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
import shutil
import subprocess
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

import yaml

from protocolgate.bounty_sim import smart_ingest_stdio
from protocolgate.capsules import (
    VerdictCapsule,
    drift_verdict_capsules,
)
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
# MOAT write-back sink. Given the verdict capsules a finished factory run
# produced, persist them so future runs compound (dead-doors skip faster,
# prior-win value-weighting strengthens). The default sink ships them through the
# SAME stdio ``smart_ingest`` transport bounty-sim uses; tests inject a recorder
# that captures the capsules WITHOUT any subprocess or network. A writer must
# NEVER raise into the loop and NEVER set a submission-ready status (it only
# records what the deterministic verdict already decided).
VestigeWriter = Callable[[tuple["VerdictCapsule", ...]], None]


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
    vestige_writer: VestigeWriter | None = None,
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
        When ``True``, the MOAT write-back is enabled: after each target is
        classified, the factory dual-writes verdict capsules back to Vestige so
        future runs compound -- dead-door capsules for skipped/no-drift lanes
        (future runs skip them before scan spend), and budget/realized-impact
        capsules for live lanes (PRIOR_WIN value-weighting strengthens). Writing
        happens AFTER read-back and state mapping; it never changes this run's
        verdict and never sets submission-ready. When ``False`` (default) the
        factory only READS, exactly as before. Degrades gracefully: a missing or
        failing writer is a no-op, never fatal.
    vestige_writer:
        Optional sink for the write-back capsules. Defaults to
        :func:`default_vestige_writer`, which ships them through the same stdio
        ``smart_ingest`` transport bounty-sim uses. Tests inject a recorder that
        captures the capsules with no subprocess or network. Ignored when
        ``write_vestige`` is ``False``.
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
    # MOAT write-back sink. Only resolved when the caller opted in; otherwise the
    # factory stays read-only and the writer is never touched.
    writer = (
        (vestige_writer if vestige_writer is not None else default_vestige_writer)
        if write_vestige
        else None
    )

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
                vestige_writer=writer,
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
    vestige_writer: VestigeWriter | None = None,
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
    economics = _economics_for_lanes(lanes, readbacks)
    budget_decisions = order_targets(
        lane.budget_decision for lane in lanes if lane.budget_decision is not None
    )

    # (g) MOAT write-back. The data moat only fills if a run COMPOUNDS: dual-write
    # dead-door capsules (so future runs skip these lanes before scan spend) and
    # live budget/realized-impact capsules (so PRIOR_WIN value-weighting grows).
    # This runs AFTER the deterministic verdict is fixed; it records what already
    # happened and never sets submission-ready. Never fatal: a writer failure is
    # swallowed (advisory layer).
    _write_back_factory_run(
        target=target,
        manifest=manifest,
        snapshot=snapshot,
        findings=findings,
        lanes=lanes,
        readbacks=readbacks,
        writer=vestige_writer,
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


def _economics_for_lanes(
    lanes: tuple[LaneResult, ...],
    readbacks: tuple[LaneReadback, ...] = (),
) -> EconomicsSnapshot:
    """Record the router economics for one target.

    Two sources feed the ledger:

    1. ``lanes`` -- the drift-derived lanes (a lane only exists when the engine
       flagged real drift). A scanned lane records spend; a read-back-killed
       drift lane records a skip.
    2. ``readbacks`` -- the FULL prospective set, including dead-door lanes that
       produced NO live drift. Those never become a ``LaneResult``, so without
       this second pass their read-back SKIP -- the highest-value skip, since we
       avoided a lane we already knew was dead -- would be dropped from
       ``compute_saved``.

    Double-counting is avoided by recording the drift lanes FIRST (which writes
    their signatures into the ledger's scanned/skipped sets) and then crediting a
    read-back SKIP only for a signature not already represented by any lane. The
    ledger's per-signature de-dup makes the skip credit idempotent.
    """

    ledger = ScanLedger()
    lane_signatures = {lane.signature for lane in lanes}
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

    # Credit read-back SKIP decisions for dead-door prospective lanes that
    # produced no live drift (so they never became a LaneResult above). A
    # no-drift PROCEED read-back is neither scanned nor skipped -- there was
    # simply nothing to flag -- so only SKIP decisions are counted.
    for readback in readbacks:
        if readback.signature in lane_signatures:
            continue
        decision = readback.budget_decision
        if decision is not None and decision.is_skip:
            ledger.record_skip(readback.signature)
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


# --------------------------------------------------------------------------- #
# MOAT write-back: a finished run COMPOUNDS into memory (GAP 1)
# --------------------------------------------------------------------------- #


def _write_back_factory_run(
    *,
    target: FactoryTarget,
    manifest: dict[str, Any],
    snapshot: dict[str, Any],
    findings: tuple[DriftFinding, ...] | list[DriftFinding],
    lanes: tuple[LaneResult, ...],
    readbacks: tuple[LaneReadback, ...],
    writer: VestigeWriter | None,
) -> tuple[VerdictCapsule, ...]:
    """Build and persist the capsules one factory run produced. Never fatal.

    Returns the capsules it built (also handy for tests) regardless of whether a
    writer is wired. When ``writer`` is ``None`` (read-only run) it builds nothing
    and returns ``()`` -- the read/write split stays clean. A writer exception is
    swallowed: the advisory moat must never break the deterministic loop.
    """

    if writer is None:
        return ()

    capsules = _factory_capsules(
        target=target,
        manifest=manifest,
        snapshot=snapshot,
        findings=tuple(findings),
        lanes=lanes,
        readbacks=readbacks,
    )
    if not capsules:
        return ()
    try:
        writer(capsules)
    except Exception:  # noqa: BLE001 - write-back is advisory; never fatal
        pass
    return capsules


def _factory_capsules(
    *,
    target: FactoryTarget,
    manifest: dict[str, Any],
    snapshot: dict[str, Any],
    findings: tuple[DriftFinding, ...],
    lanes: tuple[LaneResult, ...],
    readbacks: tuple[LaneReadback, ...],
) -> tuple[VerdictCapsule, ...]:
    """Dual-write capsule set for one classified target.

    (a) dead-door capsules for every read-back-killed prospective lane (including
        no-drift dead-door lanes that never became a ``LaneResult``) so future
        runs skip them before scan spend;
    (b) live drift capsules (reusing :func:`drift_verdict_capsules`) enriched with
        the lane's budget decision and any proven realized USD impact, so
        PRIOR_WIN value-weighting compounds run over run.

    The deterministic verdict is already fixed when this runs; nothing here ever
    produces a submission-ready signal.
    """

    capsules: list[VerdictCapsule] = []

    # (a) Dead-door capsules. A prospective lane is dead either because read-back
    # recalled a prior dead-door (``recalled_dead_door``) or because the router
    # decided SKIP. Build one capsule per dead signature, de-duplicated.
    seen_dead: set[str] = set()
    lane_by_signature = {lane.signature: lane for lane in lanes}
    for readback in readbacks:
        decision = readback.budget_decision
        is_skip = bool(decision is not None and decision.is_skip)
        if not (readback.recalled_dead_door or is_skip):
            continue
        if readback.signature in seen_dead:
            continue
        seen_dead.add(readback.signature)
        capsules.append(
            _dead_door_capsule(
                target=target,
                manifest=manifest,
                subject=readback.subject,
                kind=readback.kind,
                signature=readback.signature,
                evidence_refs=readback.evidence_refs,
                note=readback.note,
                budget=decision,
                produced_live_drift=readback.signature in lane_by_signature,
            )
        )

    # (b) Live drift capsules, enriched with budget + realized-impact memory.
    live_findings = [
        finding
        for finding, lane in zip(findings, lanes)
        if not lane.skipped_dead_door
    ]
    if live_findings:
        drift_capsules = drift_verdict_capsules(
            manifest=manifest,
            target=target.manifest,
            snapshot_target=target.name,
            snapshot=snapshot,
            findings=live_findings,
        )
        # ``drift_verdict_capsules`` preserves finding order, so zip against the
        # live lanes (same order) to attach each lane's budget + impact.
        live_lanes = [lane for lane in lanes if not lane.skipped_dead_door]
        for capsule, lane in zip(drift_capsules, live_lanes):
            capsules.append(_enrich_live_capsule(capsule, lane))

    return tuple(capsules)


def _dead_door_capsule(
    *,
    target: FactoryTarget,
    manifest: dict[str, Any],
    subject: str,
    kind: str,
    signature: str,
    evidence_refs: tuple[str, ...],
    note: str,
    budget: BudgetDecision | None,
    produced_live_drift: bool,
) -> VerdictCapsule:
    """A closed-door capsule a future run's read-back will recall and skip.

    The summary/tags/reopen_if carry the dead-door markers
    :data:`DEAD_DOOR_MARKERS` matches, so the next run's
    ``_is_dead_door_preview`` recognizes it and short-circuits the lane before
    scan spend. This is negative knowledge: it never promotes anything.
    """

    target_name = _manifest_name(manifest)
    rationale = (budget.rationale if budget is not None else "") or note
    summary = (
        f"dead-door lane {signature}: skipped before scan spend. "
        f"{rationale} reopen_if scope or live config changes."
    )
    evidence: dict[str, Any] = {
        "workflow": "factory",
        "result": "closed_door",
        "signature": signature,
        "subject": subject,
        "kind": kind,
        "prior_evidence_refs": list(evidence_refs),
        "produced_live_drift": produced_live_drift,
        "route_action": budget.action if budget is not None else "",
        "route_weight": budget.weight if budget is not None else 0.0,
    }
    return VerdictCapsule(
        capsule_id=_factory_capsule_id("factory_dead_door", target.name, signature),
        schema_version=1,
        capsule_type="protocolgate.verdict_capsule.v1",
        created_at=_now_iso(),
        producer="protocolgate",
        workflow="factory",
        source="protocolgate factory write-back",
        target=target.manifest,
        target_name=target_name,
        lane=kind,
        result="closed_door",
        status="closed_door",
        title=f"Dead-door: {subject} {kind}",
        summary=summary,
        tags=(
            "protocolgate",
            "verdict-capsule",
            "factory",
            "dead-door",
            "closed-door",
            f"lane-{kind}",
        ),
        evidence=evidence,
        blockers=(),
        missing_evidence=(),
        next_actions=(
            "Skip this lane on future runs unless reopen_if conditions are met.",
        ),
        reopen_if=(
            "scope language changes",
            "live control-plane config changes for this subject",
            "a new PoC proves direct in-scope public-actor impact",
        ),
        memory={"advisory_read_refs": list(evidence_refs), "write_status": "factory_write_back"},
        metadata={
            "advisory": True,
            "deterministic_verdict_unchanged": True,
            "submission_ready": False,
        },
    )


def _enrich_live_capsule(capsule: VerdictCapsule, lane: LaneResult) -> VerdictCapsule:
    """Attach a live lane's budget decision + realized impact to its capsule.

    The capsule's deterministic verdict is untouched; only ``evidence`` and
    ``memory`` gain the routing/impact context that lets PRIOR_WIN value-weighting
    compound. ``submission_ready`` is pinned ``False`` no matter how strong the
    proven impact is -- the bright line holds in the moat too.
    """

    decision = lane.budget_decision
    evidence = dict(capsule.evidence)
    evidence.update(
        {
            "factory_signature": lane.signature,
            "factory_status": lane.status,
            "route_action": decision.action if decision is not None else "",
            "route_weight": decision.weight if decision is not None else 0.0,
            "route_expected_value": decision.expected_value if decision is not None else 0.0,
            "poc_proven": lane.poc_proven,
            "realized_usd_impact": lane.poc_usd_impact,
            "reasoning_action": lane.reasoning_action,
        }
    )
    memory = dict(capsule.memory)
    memory["write_status"] = "factory_write_back"
    if lane.reasoning_refs:
        memory["advisory_read_refs"] = list(lane.reasoning_refs)
    metadata = dict(capsule.metadata)
    metadata["submission_ready"] = False
    return replace(
        capsule,
        source="protocolgate factory write-back",
        workflow="factory",
        evidence=evidence,
        memory=memory,
        metadata=metadata,
    )


def _factory_capsule_id(*parts: str) -> str:
    import hashlib

    raw = "\x1f".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _manifest_name(manifest: dict[str, Any]) -> str:
    project = manifest.get("project")
    if isinstance(project, dict) and project.get("name"):
        return str(project["name"])
    return "unknown target"


def _capsule_to_smart_ingest_item(capsule: VerdictCapsule) -> dict[str, Any]:
    """Render one capsule as a Vestige ``smart_ingest`` item.

    Mirrors the ``{content, node_type, source, tags}`` shape bounty-sim's
    ``_vestige_items`` produces so the moat write-back lands in the same memory
    space and is recallable by the same read-back path.
    """

    content = (
        f"ProtocolGate factory {capsule.result}: {capsule.target_name} / {capsule.lane}. "
        f"{capsule.summary} "
        f"status={capsule.status}; reopen_if={'; '.join(capsule.reopen_if[:2])}"
    )
    return {
        "content": content,
        "node_type": "event",
        "source": "protocolgate factory write-back",
        "tags": list(dict.fromkeys([*capsule.tags, "factory", "private-protocolgate"])),
    }


def default_vestige_writer(
    capsules: tuple[VerdictCapsule, ...],
    *,
    command: str = "vestige-mcp",
    timeout_seconds: int = 45,
) -> None:
    """Default MOAT sink: ship capsules through the stdio ``smart_ingest`` path.

    Reuses :func:`protocolgate.bounty_sim.smart_ingest_stdio` -- the exact same
    JSON-RPC transport bounty-sim uses -- so there is one write path, not two.
    Degrades gracefully end to end: empty capsule set, a missing ``vestige-mcp``
    binary, a subprocess failure, or a timeout are all silent no-ops. NEVER
    raises into the loop. Items are capped to stay within one batch.
    """

    if not capsules:
        return
    resolved = shutil.which(command)
    if resolved is None:
        return
    items = [_capsule_to_smart_ingest_item(capsule) for capsule in capsules][:20]
    if not items:
        return
    try:
        smart_ingest_stdio(
            items,
            command=resolved,
            timeout_seconds=timeout_seconds,
            client_name="protocolgate-factory",
        )
    except (subprocess.SubprocessError, OSError):
        return


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
