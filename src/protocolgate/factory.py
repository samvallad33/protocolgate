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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

import yaml

from protocolgate.collector import (
    CollectionResult,
    CollectorError,
    ContractTarget,
    MultisigTarget,
    collect_snapshot,
    targets_from_manifest,
)
from protocolgate.drift import DriftFinding, compare_snapshot
from protocolgate.manifest import ManifestError, load_manifest
from protocolgate.memory import MemoryResult, VestigeClient

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


@dataclass(frozen=True)
class FactoryResult:
    """Top-level result of one factory run over a whole ``targets.yaml``."""

    targets_path: str
    target_count: int
    results: tuple[TargetResult, ...]
    vestige_available: bool
    errors: tuple[str, ...] = field(default_factory=tuple)

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
            )
        except ManifestError as exc:
            errors.append(f"{target.name}: manifest error: {exc}")
            result = _error_target(target, f"manifest error: {exc}", vestige_available)
        results.append(result)

    return FactoryResult(
        targets_path=str(targets_path),
        target_count=len(targets),
        results=tuple(results),
        vestige_available=vestige_available,
        errors=tuple(errors),
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
        _read_back_lane(target.name, subject, kind, client)
        for subject, kind in prospective
    )
    dead_signatures = {rb.signature for rb in readbacks if rb.recalled_dead_door}
    refs_by_signature = {
        rb.signature: rb.evidence_refs for rb in readbacks if rb.recalled_dead_door
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
        )
        for finding in findings
    )
    state = _target_state(lanes)

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
) -> LaneReadback:
    """Closed-door read-back for one prospective lane. Never raises."""

    signature = lane_signature(target, subject, kind)
    if client is None:
        return LaneReadback(
            subject=subject,
            kind=kind,
            signature=signature,
            queried=False,
            recalled_dead_door=False,
            note="vestige unavailable; read-back skipped",
        )

    try:
        result = client.query(signature)
    except Exception:  # noqa: BLE001 - advisory layer must never be fatal
        return LaneReadback(
            subject=subject,
            kind=kind,
            signature=signature,
            queried=False,
            recalled_dead_door=False,
            note="vestige query failed; read-back skipped",
        )

    if not getattr(result, "available", False) or not result.evidence:
        return LaneReadback(
            subject=subject,
            kind=kind,
            signature=signature,
            queried=True,
            recalled_dead_door=False,
        )

    dead_refs = tuple(
        evidence.memory_id
        for evidence in result.evidence
        if _is_dead_door_preview(evidence.preview)
    )
    return LaneReadback(
        subject=subject,
        kind=kind,
        signature=signature,
        queried=True,
        recalled_dead_door=bool(dead_refs),
        evidence_refs=dead_refs,
        note="recalled prior dead-door capsule" if dead_refs else "",
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
) -> LaneResult:
    kind = _kind_for_finding(finding)
    signature = lane_signature(target, finding.subject, kind)
    skipped = signature in dead_signatures
    status = STATE_DEAD_DOOR if skipped else _live_lane_status(finding)
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
    )


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
    }


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    return str(value)
