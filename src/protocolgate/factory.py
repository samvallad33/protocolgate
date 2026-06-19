"""Bounty-factory orchestrator loop.

The factory walks a ``targets.yaml`` of protocols, collects a live control-plane
snapshot for each one, consults institutional memory BEFORE doing deep work (so a
previously killed lane is skipped instead of re-hunted), runs deterministic drift
comparison, and maps each target to one of four states.

Design constraints (load-bearing, do not violate):

- BRIGHT LINE: the factory NEVER auto-promotes a target to ``submission-ready``.
  Live drift plus a machine-checkable signal tops out at ``needs-PoC`` /
  needs-source-trace. Promotion to submission-ready is a human decision made
  outside this loop with a real fork PoC, scope review, and impact trace.
- Read-only. The factory reuses the read-only collector; no keys, no mainnet
  transactions, fork tests only downstream.
- Degrade gracefully. If Vestige is unavailable, closed-door read-back is
  skipped (not fatal). If RPC fails for a subject, that subject's errors
  propagate into the result instead of crashing the run.
- Dependency-free beyond the stdlib + ``pyyaml`` (already a project dependency)
  + existing ProtocolGate modules. Frozen dataclasses; ``from __future__``
  annotations; stdlib-first style to match the repo.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

import yaml

from protocolgate.collector import (
    CollectionResult,
    CollectorError,
    ContractTarget,
    MultisigTarget,
    collect_snapshot,
    targets_from_manifest,
)
from protocolgate.connectors.solodit import SoloditClient, SoloditFinding
from protocolgate.drift import DriftFinding, compare_snapshot
from protocolgate.economics import EconomicsSnapshot, ScanLedger
from protocolgate.forkpoc import ForkConfig, ForkPoCResult, verify as forkpoc_verify
from protocolgate.historical_db import HistoricalDB, HistoricalExploit
from protocolgate.manifest import ManifestError, load_manifest
from protocolgate.memory import MemoryEvidence, MemoryResult, VestigeClient
from protocolgate.reasoning import (
    ACTION_PROCEED,
    ACTION_SKIP,
    INTENT_DUPLICATE_RISK,
    INTENT_HISTORICAL_EXPLOIT,
    HistoricalRecallFn,
    LaneJudgment,
    judge_lane,
)
from protocolgate.router import BudgetDecision, order_targets, route

# Four factory states. ``submission-ready`` is intentionally present in the type
# space but is NEVER assigned by this module (see BRIGHT LINE above).
STATE_DEAD_DOOR = "dead-door"
STATE_NEEDS_CONFIG = "needs-config"
STATE_NEEDS_POC = "needs-PoC"
STATE_SUBMISSION_READY = "submission-ready"

# Markers that, when present in a recalled memory preview, prove the prospective
# lane was previously closed (or deferred behind unmet evidence) and should be
# skipped rather than re-hunted.
DEAD_DOOR_MARKERS = (
    "dead-door",
    "dead_door",
    "dead lane",
    "dead-lane",
    "dead_lane",
    "closed-door",
    "closed_door",
    "closed door",
    "reopen_if",
    "reopen-if",
    "reopen if",
)


# A collector callable matching ``collector.collect_snapshot`` so tests can
# inject a fake without network access.
CollectSnapshotFn = Callable[..., CollectionResult]
# Resolves a target's ``rpc_url`` / ``rpc_url_env`` declaration into a usable URL.
RpcResolver = Callable[["FactoryTarget"], str]
# An injectable fork-PoC verifier matching ``forkpoc.verify``'s shape so tests can
# inject a fake that returns a canned ``ForkPoCResult`` without forge/ityfuzz or
# network. CORE-1: this gates ELIGIBILITY only -- it NEVER promotes a lane state.
ForkPoCVerifier = Callable[..., ForkPoCResult]


def _empty_economics_snapshot() -> EconomicsSnapshot:
    return ScanLedger().snapshot()


class VestigeQueryClient(Protocol):
    """Structural type for the advisory memory client the factory consumes.

    The real :class:`protocolgate.memory.VestigeClient` satisfies this; tests
    inject a fake with the same two methods and no network.
    """

    def is_available(self) -> bool: ...

    def query(self, text: str) -> MemoryResult: ...


@dataclass(frozen=True)
class FactoryTarget:
    """One row of ``targets.yaml``."""

    name: str
    chain: str
    manifest: str
    rpc_url: str = ""
    rpc_url_env: str = ""
    payout: str = ""
    scope_notes: str = ""


@dataclass(frozen=True)
class LaneReadback:
    """Closed-door read-back outcome for one prospective drift lane."""

    subject: str
    kind: str
    signature: str
    queried: bool
    recalled_dead_door: bool
    evidence_refs: tuple[str, ...] = ()
    note: str = ""
    judgment: LaneJudgment | None = None
    budget_decision: BudgetDecision | None = None


@dataclass(frozen=True)
class LaneResult:
    """A single drift lane after read-back and state mapping."""

    subject: str
    kind: str
    severity: str
    message: str
    expected: str
    actual: str
    signature: str
    status: str
    skipped_dead_door: bool = False
    evidence_refs: tuple[str, ...] = ()
    reasoning_action: str = ACTION_PROCEED
    reasoning_refs: tuple[str, ...] = ()
    reasoning_summary: str = ""
    # CORE-1 fork-PoC eligibility signal. SURFACED, never load-bearing on state:
    # ``poc_proven`` True means the lane is ELIGIBLE for a human to promote to
    # submission-ready, but ``status`` stays capped at needs-PoC. Defaulted so
    # every existing construction site and test is unaffected.
    poc_status: str = ""
    poc_proven: bool = False
    poc_usd_impact: float = 0.0
    budget_decision: BudgetDecision | None = None


@dataclass(frozen=True)
class TargetResult:
    """Per-target factory output."""

    name: str
    chain: str
    manifest: str
    state: str
    block: str
    snapshot: dict[str, Any]
    findings: tuple[dict[str, Any], ...]
    lanes: tuple[LaneResult, ...]
    readbacks: tuple[LaneReadback, ...]
    errors: tuple[str, ...]
    vestige_available: bool
    skipped: bool = False
    economics: EconomicsSnapshot = field(default_factory=_empty_economics_snapshot)
    budget_decisions: tuple[BudgetDecision, ...] = ()


@dataclass(frozen=True)
class FactoryResult:
    """Top-level result of one factory run over a whole ``targets.yaml``."""

    targets_path: str
    target_count: int
    results: tuple[TargetResult, ...]
    vestige_available: bool
    errors: tuple[str, ...] = field(default_factory=tuple)
    economics: EconomicsSnapshot = field(default_factory=_empty_economics_snapshot)
    budget_queue: tuple[BudgetDecision, ...] = ()

    @property
    def states(self) -> dict[str, str]:
        return {result.name: result.state for result in self.results}


class FactoryError(RuntimeError):
    """Raised when ``targets.yaml`` itself cannot be loaded or parsed."""


def run_factory(
    targets_path: str | Path,
    *,
    write_vestige: bool = False,
    rpc_resolver: RpcResolver | None = None,
    collect: CollectSnapshotFn = collect_snapshot,
    vestige_client: VestigeQueryClient | None = None,
    block: str = "latest",
    timeout: float = 15.0,
    run_poc: bool = False,
    poc_verifier: ForkPoCVerifier = forkpoc_verify,
    poc_chain_id: int = 1,
    poc_timeout: int = 180,
    historical_recall_fn: HistoricalRecallFn | None = None,
    solodit_client: SoloditClient | None = None,
    historical_db: HistoricalDB | None = None,
    base_scan_cost: float = 1.0,
) -> FactoryResult:
    """Run the bounty-factory loop over every target in ``targets_path``.

    Parameters
    ----------
    targets_path:
        Path to the ``targets.yaml`` file.
    write_vestige:
        Reserved for the eventual write-back of factory capsules. The factory
        never writes during read-back; this flag is threaded through so callers
        and tests can assert the read/write split. (Read-back is always on when
        a Vestige client is available.)
    rpc_resolver:
        Optional callable that turns a :class:`FactoryTarget` into an RPC URL.
        Defaults to :func:`default_rpc_resolver`, which reads a direct
        ``rpc_url`` or an env var named by ``rpc_url_env``. Tests inject a fake
        resolver to avoid touching the environment.
    collect:
        The snapshot collector. Defaults to the real
        :func:`protocolgate.collector.collect_snapshot`; tests inject a fake.
    vestige_client:
        Advisory memory client for closed-door read-back. Defaults to a real
        :class:`protocolgate.memory.VestigeClient`. If it is unavailable,
        read-back is skipped (not fatal).
    """

    targets_path = Path(targets_path)
    targets = _load_targets(targets_path)
    resolver = rpc_resolver or default_rpc_resolver
    client = vestige_client if vestige_client is not None else VestigeClient()
    solodit = solodit_client if solodit_client is not None else _default_solodit_client()
    history = historical_db if historical_db is not None else _default_historical_db()

    # One health check for the whole run: if memory is down, every target's
    # read-back degrades to "not queried" without per-target connection storms.
    vestige_available = False
    if client is not None:
        try:
            vestige_available = bool(client.is_available())
        except Exception:  # noqa: BLE001 - advisory layer must never be fatal
            vestige_available = False

    results: list[TargetResult] = []
    errors: list[str] = []
    for target in targets:
        try:
            result = _run_target(
                target,
                resolver=resolver,
                collect=collect,
                client=client if vestige_available else None,
                vestige_available=vestige_available,
                block=block,
                timeout=timeout,
                run_poc=run_poc,
                poc_verifier=poc_verifier,
                poc_chain_id=poc_chain_id,
                poc_timeout=poc_timeout,
                historical_recall_fn=historical_recall_fn,
                solodit_client=solodit,
                historical_db=history,
                base_scan_cost=base_scan_cost,
            )
        except ManifestError as exc:
            errors.append(f"{target.name}: manifest error: {exc}")
            result = _error_target(target, f"manifest error: {exc}", vestige_available)
        results.append(result)

    economics = _merge_economics(result.economics for result in results)
    budget_queue = order_targets(
        decision
        for result in results
        for decision in result.budget_decisions
    )

    return FactoryResult(
        targets_path=str(targets_path),
        target_count=len(targets),
        results=tuple(results),
        vestige_available=vestige_available,
        errors=tuple(errors),
        economics=economics,
        budget_queue=budget_queue,
    )


def default_rpc_resolver(target: FactoryTarget) -> str:
    """Resolve an RPC URL from a direct value or a named environment variable.

    A direct ``rpc_url`` wins. Otherwise ``rpc_url_env`` names an environment
    variable to read. Missing/empty resolution raises so the target is recorded
    as an error rather than collecting against an empty URL.
    """

    if target.rpc_url:
        return target.rpc_url
    if target.rpc_url_env:
        value = os.environ.get(target.rpc_url_env, "")
        if value:
            return value
        raise FactoryError(
            f"rpc_url_env '{target.rpc_url_env}' is not set for target '{target.name}'"
        )
    raise FactoryError(f"target '{target.name}' has no rpc_url or rpc_url_env")


def _run_target(
    target: FactoryTarget,
    *,
    resolver: RpcResolver,
    collect: CollectSnapshotFn,
    client: VestigeQueryClient | None,
    vestige_available: bool,
    block: str,
    timeout: float,
    run_poc: bool = False,
    poc_verifier: ForkPoCVerifier = forkpoc_verify,
    poc_chain_id: int = 1,
    poc_timeout: int = 180,
    historical_recall_fn: HistoricalRecallFn | None = None,
    solodit_client: SoloditClient | None = None,
    historical_db: HistoricalDB | None = None,
    base_scan_cost: float = 1.0,
) -> TargetResult:
    """Collect, read-back, drift-compare, and map one target to a state."""

    manifest = load_manifest(Path(target.manifest))
    contracts, multisigs = targets_from_manifest(manifest)

    errors: list[str] = []

    # (c) Resolve RPC and collect the live snapshot. A resolver or collector
    # failure for this target propagates as an error, not a crash.
    try:
        rpc_url = resolver(target)
    except (FactoryError, CollectorError) as exc:
        return _error_target(target, f"rpc resolve error: {exc}", vestige_available)

    try:
        collection = collect(
            rpc_url,
            contracts,
            multisigs,
            block=block,
            timeout=timeout,
        )
    except CollectorError as exc:
        return _error_target(target, f"collector error: {exc}", vestige_available)

    snapshot = collection.snapshot
    errors.extend(collection.errors)

    # (d) Closed-door read-back BEFORE deep work. Build a signature per
    # prospective drift lane and ask memory whether it is already dead.
    prospective = _prospective_lanes(contracts, multisigs)
    readbacks = tuple(
        _read_back_lane(
            target.name,
            subject,
            kind,
            client,
            prior_usd_impact=_target_prior_usd(target),
            base_scan_cost=base_scan_cost,
            historical_recall_fn=historical_recall_fn,
            solodit_client=solodit_client,
            historical_db=historical_db,
        )
        for subject, kind in prospective
    )
    dead_signatures = {rb.signature for rb in readbacks if rb.recalled_dead_door}
    refs_by_signature = {
        rb.signature: rb.evidence_refs for rb in readbacks if rb.recalled_dead_door
    }
    judgment_by_signature = {
        rb.signature: rb.judgment for rb in readbacks if rb.judgment is not None
    }
    budget_by_signature = {
        rb.signature: rb.budget_decision
        for rb in readbacks
        if rb.budget_decision is not None
    }

    # (e) Deterministic drift comparison.
    findings = compare_snapshot(manifest, snapshot)

    # (f) Map findings to lanes/states, downgrading any lane that read-back
    # already killed.
    lanes = tuple(
        _lane_from_finding(
            target.name,
            finding,
            dead_signatures=dead_signatures,
            refs_by_signature=refs_by_signature,
            judgment_by_signature=judgment_by_signature,
            budget_by_signature=budget_by_signature,
        )
        for finding in findings
    )

    # CORE-1 (OFF BY DEFAULT): optionally fork-prove live drift lanes. This
    # ATTACHES an eligibility signal (poc_status / poc_proven) but NEVER mutates
    # ``status`` -- the bright line means a proven delta makes a lane ELIGIBLE
    # for a human to promote, not promoted. ``_target_state`` below therefore
    # still tops out at needs-PoC.
    if run_poc:
        lanes = tuple(
            _maybe_verify_lane(
                lane,
                finding,
                rpc_url=rpc_url,
                target=target,
                verifier=poc_verifier,
                chain_id=poc_chain_id,
                block=snapshot.get("block", block),
                timeout=poc_timeout,
            )
            for lane, finding in zip(lanes, findings)
        )

    state = _target_state(lanes)
    economics = _economics_for_lanes(lanes)
    budget_decisions = order_targets(
        lane.budget_decision for lane in lanes if lane.budget_decision is not None
    )

    return TargetResult(
        name=target.name,
        chain=target.chain,
        manifest=target.manifest,
        state=state,
        block=str(snapshot.get("block", block)),
        snapshot=snapshot,
        findings=tuple(_finding_dict(finding) for finding in findings),
        lanes=lanes,
        readbacks=readbacks,
        errors=tuple(errors),
        vestige_available=vestige_available,
        economics=economics,
        budget_decisions=budget_decisions,
    )


def _prospective_lanes(
    contracts: list[ContractTarget], multisigs: list[MultisigTarget]
) -> tuple[tuple[str, str], ...]:
    """Every (subject, kind) the drift engine could possibly flag for a target.

    Read-back is done up front against the full prospective set so a known dead
    lane is skipped before we spend effort, even though the drift engine only
    emits a finding when there is real drift.
    """

    lanes: list[tuple[str, str]] = []
    for contract in contracts:
        lanes.append((contract.name, "proxy_admin_drift"))
    for multisig in multisigs:
        lanes.append((multisig.name, "multisig_threshold_drift"))
    return tuple(lanes)


def lane_signature(target: str, subject: str, kind: str) -> str:
    """Canonical lane signature used for both read-back and downgrade matching."""

    return f"{target}:{subject}:{kind}"


def _read_back_lane(
    target: str,
    subject: str,
    kind: str,
    client: VestigeQueryClient | None,
    *,
    prior_usd_impact: float = 0.0,
    base_scan_cost: float = 1.0,
    historical_recall_fn: HistoricalRecallFn | None = None,
    solodit_client: SoloditClient | None = None,
    historical_db: HistoricalDB | None = None,
) -> LaneReadback:
    """Closed-door read-back for one prospective lane. Never raises."""

    signature = lane_signature(target, subject, kind)
    if client is None:
        judgment = LaneJudgment(
            signature=signature,
            action=ACTION_PROCEED,
            confidence_delta=0.0,
            intents=(),
            summary=f"{signature}: vestige unavailable; read-back skipped -> PROCEED.",
            available=False,
        )
        return LaneReadback(
            subject=subject,
            kind=kind,
            signature=signature,
            queried=False,
            recalled_dead_door=False,
            note="vestige unavailable; read-back skipped",
            judgment=judgment,
            budget_decision=route(
                judgment,
                prior_usd_impact=prior_usd_impact,
                base_scan_cost=base_scan_cost,
            ),
        )

    try:
        result = client.query(signature)
    except Exception:  # noqa: BLE001 - advisory layer must never be fatal
        judgment = LaneJudgment(
            signature=signature,
            action=ACTION_PROCEED,
            confidence_delta=0.0,
            intents=(),
            summary=f"{signature}: vestige query failed; read-back skipped -> PROCEED.",
            available=False,
        )
        return LaneReadback(
            subject=subject,
            kind=kind,
            signature=signature,
            queried=False,
            recalled_dead_door=False,
            note="vestige query failed; read-back skipped",
            judgment=judgment,
            budget_decision=route(
                judgment,
                prior_usd_impact=prior_usd_impact,
                base_scan_cost=base_scan_cost,
            ),
        )

    if not getattr(result, "available", False) or not result.evidence:
        dead_refs: tuple[str, ...] = ()
    else:
        dead_refs = tuple(
            evidence.memory_id
            for evidence in result.evidence
            if _is_dead_door_preview(evidence.preview)
        )

    recall_fn = historical_recall_fn or _historical_recall_adapter(
        solodit_client=solodit_client,
        historical_db=historical_db,
        kind=kind,
        subject=subject,
    )

    # MOAT layer: run the full four-intent cross-bounty reasoning on top of the
    # authoritative dead-door signal. judge_lane is advisory and never raises; it
    # surfaces PRIORITIZE / ARM_TEMPLATE / FLAG_DUPLICATE context and feeds the
    # budget router before any optional fork-PoC spend.
    judgment: LaneJudgment | None = None
    try:
        judgment = judge_lane(
            target,
            subject,
            kind,
            client,
            historical_recall_fn=recall_fn,
        )
    except Exception:  # noqa: BLE001 - advisory layer must never be fatal
        judgment = None
    if dead_refs:
        summary = (
            f"{signature}: direct dead-door read-back [{','.join(ref[:8] for ref in dead_refs[:3])}] "
            "-> SKIP before scan spend."
        )
        judgment = (
            replace(judgment, action=ACTION_SKIP, summary=summary)
            if judgment is not None
            else LaneJudgment(
                signature=signature,
                action=ACTION_SKIP,
                confidence_delta=-1.0,
                intents=(),
                summary=summary,
                available=True,
            )
        )
    budget = (
        route(
            judgment,
            prior_usd_impact=prior_usd_impact,
            base_scan_cost=base_scan_cost,
        )
        if judgment is not None
        else None
    )
    if dead_refs and budget is not None:
        budget = replace(budget, evidence=dead_refs)

    return LaneReadback(
        subject=subject,
        kind=kind,
        signature=signature,
        queried=True,
        recalled_dead_door=bool(dead_refs),
        evidence_refs=dead_refs,
        note="recalled prior dead-door capsule" if dead_refs else "",
        judgment=judgment,
        budget_decision=budget,
    )


def _is_dead_door_preview(preview: str) -> bool:
    lowered = (preview or "").lower()
    return any(marker in lowered for marker in DEAD_DOOR_MARKERS)


def _lane_from_finding(
    target: str,
    finding: DriftFinding,
    *,
    dead_signatures: set[str],
    refs_by_signature: dict[str, tuple[str, ...]],
    judgment_by_signature: dict[str, LaneJudgment] | None = None,
    budget_by_signature: dict[str, BudgetDecision] | None = None,
) -> LaneResult:
    kind = _kind_for_finding(finding)
    signature = lane_signature(target, finding.subject, kind)
    budget = (budget_by_signature or {}).get(signature)
    skipped = signature in dead_signatures or bool(budget and budget.is_skip)
    status = STATE_DEAD_DOOR if skipped else _live_lane_status(finding)

    judgment = (judgment_by_signature or {}).get(signature)
    reasoning_action = judgment.action if judgment is not None else ACTION_PROCEED
    reasoning_refs = judgment.evidence_refs if judgment is not None else ()
    reasoning_summary = judgment.summary if judgment is not None else ""

    return LaneResult(
        subject=finding.subject,
        kind=kind,
        severity=finding.severity,
        message=finding.message,
        expected=_stringify(finding.expected),
        actual=_stringify(finding.actual),
        signature=signature,
        status=status,
        skipped_dead_door=skipped,
        evidence_refs=refs_by_signature.get(signature, ()),
        reasoning_action=reasoning_action,
        reasoning_refs=reasoning_refs,
        reasoning_summary=reasoning_summary,
        budget_decision=budget,
    )


def _maybe_verify_lane(
    lane: LaneResult,
    finding: DriftFinding,
    *,
    rpc_url: str,
    target: FactoryTarget,
    verifier: ForkPoCVerifier,
    chain_id: int,
    block: Any,
    timeout: int,
) -> LaneResult:
    """Fork-prove ONE live drift lane and attach an eligibility signal.

    BRIGHT LINE: this returns a lane whose ``status`` is byte-for-byte the input
    lane's status. A ``proven_delta`` sets ``poc_proven=True`` (the lane is now
    ELIGIBLE for a human to promote to submission-ready), but the factory still
    does NOT promote -- ``status`` stays capped at needs-PoC and the human
    submits. Only runs for a live ``needs-PoC`` lane with an rpc_url + target
    address; otherwise the lane is returned unchanged. Never raises: a verifier
    failure leaves the lane untouched (poc_status='', poc_proven=False).
    """

    if lane.skipped_dead_door or lane.status != STATE_NEEDS_POC:
        return lane

    target_address = _lane_target_address(target, finding)
    if not rpc_url or not target_address:
        return lane

    fork_block = _fork_block(block)
    if fork_block is None:
        return lane

    fork = ForkConfig(rpc_url=rpc_url, block=fork_block, chain_id=chain_id)
    try:
        poc: ForkPoCResult = verifier(
            finding,
            fork,
            target_address,
            run=True,
            timeout=timeout,
        )
    except Exception:  # noqa: BLE001 - PoC layer must never be fatal to the loop
        return lane

    # ``is_proven`` is the hard constraint: a real, measured before != after.
    proven = bool(getattr(poc, "is_proven", lambda: False)())
    usd_impact = 0.0
    if proven and poc.delta is not None and poc.delta.usd_impact is not None:
        usd_impact = max(0.0, float(poc.delta.usd_impact))

    # SURFACE the signal; DO NOT touch ``status``. The bright line lives here.
    return replace(
        lane,
        poc_status=poc.status,
        poc_proven=proven,
        poc_usd_impact=usd_impact,
    )


def _lane_target_address(target: FactoryTarget, finding: DriftFinding) -> str:
    """Best-effort target address for a lane's fork PoC.

    Address resolution is intentionally conservative: only an explicit on-finding
    address is used. A name-only finding yields "" so we never fork-prove against
    a guessed address, and the lane is left unproven (degrade gracefully).
    """

    return getattr(finding, "address", "") or ""


def _fork_block(block: Any) -> int | None:
    """Coerce a snapshot block ('latest' / '0x123' / 291) into an int for the fork.

    ``latest`` (or any unparseable value) returns ``None`` so the PoC is skipped
    rather than pinned to a meaningless block.
    """

    if isinstance(block, int):
        return block
    text = str(block).strip().lower()
    if not text or text == "latest":
        return None
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None


def _kind_for_finding(finding: DriftFinding) -> str:
    text = f"{finding.subject} {finding.message}".lower()
    if "proxy admin" in text:
        return "proxy_admin_drift"
    if "multisig threshold" in text:
        return "multisig_threshold_drift"
    return "runtime_configuration_drift"


def _live_lane_status(finding: DriftFinding) -> str:
    """Map one live drift finding to a non-promoting lane status.

    A drifted/changed value is a machine-checkable open door -> ``needs-PoC``
    (needs a source-trace + fork PoC before any human submission). A merely
    *missing* object is more likely collector noise or topology mismatch ->
    ``needs-config``. Nothing here ever returns ``submission-ready``.
    """

    if "missing" in finding.message.lower():
        return STATE_NEEDS_CONFIG
    return STATE_NEEDS_POC


def _target_state(lanes: tuple[LaneResult, ...]) -> str:
    """Reduce per-lane statuses to one target state, honoring the bright line.

    Priority: any live needs-PoC lane wins (real drift to trace) > any
    needs-config lane > otherwise dead-door (no live drift, or every lane was
    read-back-killed). ``submission-ready`` is never produced here.
    """

    live = [lane for lane in lanes if not lane.skipped_dead_door]
    if any(lane.status == STATE_NEEDS_POC for lane in live):
        return STATE_NEEDS_POC
    if any(lane.status == STATE_NEEDS_CONFIG for lane in live):
        return STATE_NEEDS_CONFIG
    return STATE_DEAD_DOOR


# --------------------------------------------------------------------------- #
# CORE-0 economics + CORE-2 public-corpus recall helpers
# --------------------------------------------------------------------------- #


def _economics_for_lanes(lanes: tuple[LaneResult, ...]) -> EconomicsSnapshot:
    """Record the router economics for the drift lanes this target produced."""

    ledger = ScanLedger()
    for lane in lanes:
        decision = lane.budget_decision
        if decision is not None:
            ledger.record_decision(
                decision,
                finding_proven=lane.poc_proven,
                usd_impact=lane.poc_usd_impact,
            )
            continue
        if lane.skipped_dead_door:
            ledger.record_skip(lane.signature)
        else:
            ledger.record_scan(lane.signature)
            if lane.poc_proven:
                ledger.record_finding(lane.signature, lane.poc_usd_impact)
    return ledger.snapshot()


def _merge_economics(snapshots: Iterable[EconomicsSnapshot]) -> EconomicsSnapshot:
    """Merge per-target snapshots into one run-level economics snapshot."""

    rows = tuple(snapshots)
    ledger = ScanLedger(
        scans_spent=sum(snapshot.scans_spent for snapshot in rows),
        scans_skipped=sum(snapshot.scans_skipped for snapshot in rows),
        scan_cost_spent=sum(snapshot.scan_cost_spent for snapshot in rows),
        findings_proven=sum(snapshot.findings_proven for snapshot in rows),
        realized_usd_impact=sum(snapshot.realized_usd_impact for snapshot in rows),
    )
    return ledger.snapshot()


def _target_prior_usd(target: FactoryTarget) -> float:
    """Best-effort payout parser for value-weighted routing.

    ``targets.yaml`` often carries human text like ``50000``, ``$50k`` or
    ``up to 1.5M``. The router only needs an advisory prior-impact weight, so
    parsing is intentionally tolerant and falls back to zero.
    """

    text = str(target.payout or "").replace(",", "")
    match = re.search(r"(?P<num>\d+(?:\.\d+)?)\s*(?P<suffix>[kKmMbB])?", text)
    if not match:
        return 0.0
    value = float(match.group("num"))
    suffix = (match.group("suffix") or "").lower()
    if suffix == "k":
        value *= 1_000.0
    elif suffix == "m":
        value *= 1_000_000.0
    elif suffix == "b":
        value *= 1_000_000_000.0
    return max(0.0, value)


def _default_solodit_client() -> SoloditClient:
    """Construct the optional Solodit connector from env, degrading key-free."""

    api_key = (
        os.environ.get("PROTOCOLGATE_SOLODIT_API_KEY")
        or os.environ.get("SOLODIT_API_KEY")
        or os.environ.get("CYFRIN_API_KEY")
    )
    return SoloditClient(api_key=api_key)


def _default_historical_db() -> HistoricalDB:
    """Load an optional local DeFiHackLabs README/corpus path from env."""

    path = (
        os.environ.get("PROTOCOLGATE_DEFIHACKLABS_README")
        or os.environ.get("DEFIHACKLABS_README")
        or os.environ.get("DEFIHACKLABS_PATH")
    )
    return HistoricalDB.load(path)


def _historical_recall_adapter(
    *,
    solodit_client: SoloditClient | None,
    historical_db: HistoricalDB | None,
    kind: str,
    subject: str,
) -> HistoricalRecallFn:
    """Build the public-corpus recall function consumed by ``judge_lane``."""

    def recall(intent: str, query: str) -> tuple[MemoryEvidence, ...]:
        evidence: list[MemoryEvidence] = []
        if solodit_client is not None and intent in (
            INTENT_HISTORICAL_EXPLOIT,
            INTENT_DUPLICATE_RISK,
        ):
            evidence.extend(
                _solodit_evidence(
                    solodit_client.search_drift(
                        kind,
                        keywords=f"{subject} {query}",
                        limit=5,
                    ),
                    intent=intent,
                    kind=kind,
                )
            )
        if historical_db is not None and intent == INTENT_HISTORICAL_EXPLOIT:
            evidence.extend(
                _historical_db_evidence(
                    historical_db.match(query, protocol_category=kind),
                    kind=kind,
                )
            )
        return tuple(evidence)

    return recall


def _solodit_evidence(
    findings: Iterable[SoloditFinding],
    *,
    intent: str,
    kind: str,
) -> tuple[MemoryEvidence, ...]:
    out: list[MemoryEvidence] = []
    prefix = (
        "already reported duplicate risk"
        if intent == INTENT_DUPLICATE_RISK
        else "exploit prior art"
    )
    for finding in findings:
        ident = finding.id or _slug(f"{finding.protocol}-{finding.title}")
        out.append(
            MemoryEvidence(
                memory_id=f"solodit:{ident}",
                trust=_solodit_trust(finding),
                date="",
                preview=(
                    f"{prefix}: {finding.protocol} {finding.title} "
                    f"{finding.severity} {finding.summary} tags={','.join(finding.tags)} "
                    f"kind={kind}"
                ).strip(),
                role="historical",
                source="solodit",
            )
        )
    return tuple(out)


def _historical_db_evidence(
    exploits: Iterable[HistoricalExploit],
    *,
    kind: str,
) -> tuple[MemoryEvidence, ...]:
    out: list[MemoryEvidence] = []
    for exploit in list(exploits)[:5]:
        out.append(
            MemoryEvidence(
                memory_id=f"defihacklabs:{exploit.poc_path}",
                trust=0.72,
                date=exploit.date,
                preview=(
                    f"exploit prior art: {exploit.project} {exploit.tag} "
                    f"poc={exploit.poc_path} chain={exploit.chain} kind={kind} "
                    f"tags={','.join(exploit.tags)}"
                ),
                role="historical",
                source="defihacklabs",
            )
        )
    return tuple(out)


def _solodit_trust(finding: SoloditFinding) -> float:
    """Fold Solodit quality, rarity, and severity into memory trust."""

    quality = {
        "high": 0.18,
        "medium": 0.10,
        "low": 0.02,
    }.get(finding.quality.strip().lower(), 0.08)
    rarity = {
        "rare": 0.16,
        "uncommon": 0.10,
        "common": 0.02,
    }.get(finding.rarity.strip().lower(), 0.06)
    severity = {
        "critical": 0.16,
        "high": 0.12,
        "medium": 0.06,
        "low": 0.02,
    }.get(finding.severity.strip().lower(), 0.04)
    return min(0.95, 0.45 + quality + rarity + severity)


def _slug(text: str) -> str:
    slug = re.sub(r"[^0-9a-zA-Z]+", "-", text.strip().lower()).strip("-")
    return slug or "finding"


def _error_target(
    target: FactoryTarget, message: str, vestige_available: bool
) -> TargetResult:
    """Build a non-crashing result row for a target that failed to collect."""

    return TargetResult(
        name=target.name,
        chain=target.chain,
        manifest=target.manifest,
        state=STATE_DEAD_DOOR,
        block="",
        snapshot={},
        findings=(),
        lanes=(),
        readbacks=(),
        errors=(message,),
        vestige_available=vestige_available,
    )


def _load_targets(targets_path: Path) -> list[FactoryTarget]:
    try:
        raw = targets_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise FactoryError(f"targets file not found: {targets_path}") from exc

    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise FactoryError(f"invalid YAML in {targets_path}: {exc}") from exc

    if isinstance(data, dict):
        rows = data.get("targets", [])
    elif isinstance(data, list):
        rows = data
    else:
        raise FactoryError("targets file must be a list or a mapping with a 'targets' key")

    if rows is None:
        rows = []
    if not isinstance(rows, list):
        raise FactoryError("'targets' must be a list")

    targets: list[FactoryTarget] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise FactoryError(f"targets[{index}] must be a mapping")
        name = row.get("name")
        manifest = row.get("manifest")
        if not name:
            raise FactoryError(f"targets[{index}] is missing 'name'")
        if not manifest:
            raise FactoryError(f"target '{name}' is missing 'manifest'")
        targets.append(
            FactoryTarget(
                name=str(name),
                chain=str(row.get("chain", "")),
                manifest=str(manifest),
                rpc_url=str(row.get("rpc_url", "")),
                rpc_url_env=str(row.get("rpc_url_env", "")),
                payout=str(row.get("payout", "")),
                scope_notes=str(row.get("scope_notes", "")),
            )
        )
    return targets


def _finding_dict(finding: DriftFinding) -> dict[str, Any]:
    return {
        "severity": finding.severity,
        "subject": finding.subject,
        "message": finding.message,
        "expected": finding.expected,
        "actual": finding.actual,
        "address": finding.address,
    }


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    return str(value)
