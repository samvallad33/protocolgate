"""Vestige-backed cross-bounty invariant mining (Trace2Inv-on-memory).

This module mines reusable invariant candidates from a protocol family's
accumulated bounty memory: prior wins, dead doors, duplicate flags, and exploit
post-mortems. It is intentionally advisory. A down Vestige client, malformed
recall, or empty corpus produces an empty result instead of blocking the
deterministic engine.

The public surface has two layers:

* :func:`mine_invariants` keeps the narrow compatibility API: return candidates.
* :func:`mine_invariant_report` returns the same candidates plus reusable
  routing tags/templates that factory/router code can consume later.

Tests use the injectable query function or ``local_fallback`` corpus, so no
network or local Vestige server is required for deterministic coverage.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Callable

from protocolgate.memory import MemoryEvidence, MemoryResult
from protocolgate.reasoning import (
    DEAD_DOOR_MARKERS,
    DUPLICATE_MARKERS,
    EXPLOIT_MARKERS,
    PRIOR_WIN_MARKERS,
)

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Mirrors ``memory.DEFAULT_TRUST_FLOOR`` and ``reasoning.DEFAULT_TRUST_FLOOR``.
DEFAULT_TRUST_FLOOR = 0.45

# Single-memory support is allowed because this is an advisory candidate miner,
# not a verdict gate. Callers can raise the floor for stricter batch runs.
DEFAULT_MIN_SUPPORT = 1

# Keep the output reviewable and deterministic.
DEFAULT_MAX_CANDIDATES = 12

SIGNAL_PRIOR_WIN = "prior-win"
SIGNAL_DEAD_DOOR = "dead-door"
SIGNAL_DUPLICATE_RISK = "duplicate-risk"
SIGNAL_HISTORICAL_EXPLOIT = "historical-exploit"

ROUTE_PRIORITIZE = "prioritize"
ROUTE_SKIP = "skip"
ROUTE_FLAG = "flag"
ROUTE_ARM = "arm"

EvidenceInput = MemoryResult | Iterable[MemoryEvidence] | None
FamilyQueryFn = Callable[[str, str], EvidenceInput]


@dataclass(frozen=True)
class _InvariantRule:
    name: str
    markers: tuple[str, ...]
    implication: str
    predicate: str
    template: str
    routing_tags: tuple[str, ...]


@dataclass(frozen=True)
class _SignalRule:
    kind: str
    markers: tuple[str, ...]
    route_action: str
    tag: str


_SIGNAL_RULES: tuple[_SignalRule, ...] = (
    _SignalRule(SIGNAL_PRIOR_WIN, PRIOR_WIN_MARKERS, ROUTE_PRIORITIZE, "memory:prior-win"),
    _SignalRule(SIGNAL_DEAD_DOOR, DEAD_DOOR_MARKERS, ROUTE_SKIP, "memory:dead-door"),
    _SignalRule(SIGNAL_DUPLICATE_RISK, DUPLICATE_MARKERS, ROUTE_FLAG, "memory:duplicate-risk"),
    _SignalRule(
        SIGNAL_HISTORICAL_EXPLOIT,
        EXPLOIT_MARKERS,
        ROUTE_ARM,
        "memory:historical-exploit",
    ),
)


# Each rule maps recalled bounty history to a reusable invariant family plus the
# downstream PoC/routing template most likely to consume it.
_INVARIANT_RULES: tuple[_InvariantRule, ...] = (
    _InvariantRule(
        name="supply_conservation",
        markers=("mint", "burn", "inflate", "infinite mint", "supply", "totalsupply", "over-mint"),
        implication="total supply only changes through authorized mint/burn paths",
        predicate=(
            "totalSupply() equals the sum of accounted balances and never inflates "
            "outside an authorized mint"
        ),
        template="supply_conservation",
        routing_tags=("control-plane:accounting", "surface:mint-burn"),
    ),
    _InvariantRule(
        name="upgrade_authority",
        markers=(
            "upgrade authority",
            "unprotected upgrade",
            "proxy admin",
            "admin takeover",
            "uninitialized",
            "initializer",
            "upgradeto",
            "implementation",
        ),
        implication="only the designated admin can change the implementation",
        predicate=(
            "the proxy implementation/admin can only be changed by the configured "
            "owner and the initializer cannot be re-run"
        ),
        template="proxy_admin_drift",
        routing_tags=("control-plane:upgrade", "surface:proxy-admin"),
    ),
    _InvariantRule(
        name="access_control",
        markers=(
            "access control",
            "onlyowner",
            "missing modifier",
            "unauthorized",
            "privileged",
            "role",
            "permission",
            "auth bypass",
        ),
        implication="privileged entrypoints reject unauthorized callers",
        predicate="every privileged function reverts when called by a non-authorized address",
        template="access_control_guard",
        routing_tags=("control-plane:authority", "surface:roles"),
    ),
    _InvariantRule(
        name="solvency",
        markers=("solvency", "drain", "drained", "underwater", "bad debt", "insolvent", "reserve", "backing"),
        implication="protocol liabilities never exceed its backing assets",
        predicate=(
            "the sum of user claims never exceeds the protocol's held collateral "
            "(no insolvency)"
        ),
        template="solvency_accounting",
        routing_tags=("control-plane:accounting", "surface:collateral"),
    ),
    _InvariantRule(
        name="oracle_bounds",
        markers=("oracle", "price manipulation", "oracle manipulation", "stale price", "twap", "spot price"),
        implication="price inputs stay within validated, non-manipulable bounds",
        predicate="any price consumed from an oracle is fresh and within sane deviation bounds before use",
        template="oracle_bounds",
        routing_tags=("control-plane:oracle", "surface:price-feed"),
    ),
    _InvariantRule(
        name="timelock",
        markers=("timelock", "timelock bypass", "delay bypass", "instant execution", "governance delay"),
        implication="governance/admin actions respect the configured timelock delay",
        predicate="no privileged state change executes before its timelock delay has elapsed",
        template="timelock_delay",
        routing_tags=("control-plane:governance", "surface:timelock"),
    ),
    _InvariantRule(
        name="reentrancy",
        markers=("reentrancy", "reentrant", "callback", "checks-effects", "nonreentrant"),
        implication="external calls cannot re-enter and corrupt mid-update state",
        predicate="no external call re-enters a state-mutating path before its effects are committed",
        template="reentrancy_guard",
        routing_tags=("control-plane:execution", "surface:external-call"),
    ),
    _InvariantRule(
        name="bridge_accounting",
        markers=("bridge drain", "bridge", "cross-chain", "message replay", "double spend", "withdrawal proof"),
        implication="bridged assets are conserved across chains and proofs are single-use",
        predicate="locked source-chain value equals minted destination value and no withdrawal proof is replayed",
        template="bridge_accounting",
        routing_tags=("control-plane:bridge", "surface:cross-chain"),
    ),
    _InvariantRule(
        name="withdrawal_queue_ordering",
        markers=(
            "withdrawal queue",
            "queue ordering",
            "claim queue",
            "redemption queue",
            "fifo",
            "pending withdrawal",
            "delayed withdrawal",
        ),
        implication="withdrawal/redemption queues preserve ordering and accounting",
        predicate="queued withdrawals cannot skip earlier claims or withdraw more than their accounted share",
        template="withdrawal_queue_ordering",
        routing_tags=("control-plane:lifecycle", "surface:withdrawal-queue"),
    ),
    _InvariantRule(
        name="pause_lifecycle",
        markers=("pause", "paused", "guardian", "emergency", "circuit breaker", "unpause"),
        implication="emergency lifecycle powers are bounded to their declared role and timing",
        predicate="pause/unpause authority cannot bypass the declared guardian/governance lifecycle",
        template="pause_lifecycle",
        routing_tags=("control-plane:lifecycle", "surface:pause-guardian"),
    ),
)


# --------------------------------------------------------------------------- #
# Result dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SignalSummary:
    """Trusted memory signal supporting a mined invariant."""

    kind: str
    support: int
    source_refs: tuple[str, ...]
    trust: float
    route_action: str


@dataclass(frozen=True)
class CandidateInvariant:
    """A protocol invariant mined from recurring cross-bounty memory."""

    name: str
    predicate: str
    source_refs: tuple[str, ...]
    support: int
    trust: float
    rationale: str
    routing_tags: tuple[str, ...] = ()
    templates: tuple[str, ...] = ()
    signals: tuple[SignalSummary, ...] = ()

    @property
    def function_name(self) -> str:
        """The ``invariant_*`` Solidity function name for this candidate."""
        return f"invariant_{_sanitize_identifier(self.name)}"

    @property
    def primary_template(self) -> str:
        """Best first downstream template for this candidate."""
        return self.templates[0] if self.templates else _sanitize_identifier(self.name)


@dataclass(frozen=True)
class InvariantRouteTemplate:
    """Stable API shape for router/factory integrations."""

    name: str
    predicate: str
    routing_tags: tuple[str, ...]
    templates: tuple[str, ...]
    source_refs: tuple[str, ...]
    support: int
    trust: float


@dataclass(frozen=True)
class InvariantMiningReport:
    """Full mining result, including reusable routing hooks."""

    protocol_family: str
    query: str
    candidates: tuple[CandidateInvariant, ...]
    routing_tags: tuple[str, ...]
    templates: tuple[str, ...]
    source_refs: tuple[str, ...]
    available: bool = True
    used_fallback: bool = False


# --------------------------------------------------------------------------- #
# Query builder
# --------------------------------------------------------------------------- #


def family_history_query(protocol_family: str) -> str:
    """Build the recall query for a family's bounty history."""

    family = (protocol_family or "").strip()
    return (
        f"{family} protocol family invariant safety property bounty paid payout prior-win "
        f"submission-ready exploit post-mortem vulnerability root cause dead-door "
        f"closed-door known-issue duplicate already submitted mint burn supply solvency "
        f"upgrade authority proxy admin oracle timelock reentrancy access control bridge "
        f"withdrawal queue pause guardian"
    ).strip()


# --------------------------------------------------------------------------- #
# Mining
# --------------------------------------------------------------------------- #


def mine_invariants(
    protocol_family: str,
    client: object | None,
    *,
    query_fn: FamilyQueryFn | None = None,
    local_fallback: EvidenceInput = None,
    trust_floor: float = DEFAULT_TRUST_FLOOR,
    min_support: int = DEFAULT_MIN_SUPPORT,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> list[CandidateInvariant]:
    """Mine candidate invariants for ``protocol_family``.

    Compatibility wrapper around :func:`mine_invariant_report`; returns only the
    ranked candidate list.
    """

    report = mine_invariant_report(
        protocol_family,
        client,
        query_fn=query_fn,
        local_fallback=local_fallback,
        trust_floor=trust_floor,
        min_support=min_support,
        max_candidates=max_candidates,
    )
    return list(report.candidates)


def mine_invariant_report(
    protocol_family: str,
    client: object | None,
    *,
    query_fn: FamilyQueryFn | None = None,
    local_fallback: EvidenceInput = None,
    trust_floor: float = DEFAULT_TRUST_FLOOR,
    min_support: int = DEFAULT_MIN_SUPPORT,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> InvariantMiningReport:
    """Mine candidates plus reusable routing tags/templates.

    Vestige is used when available through ``client`` or ``query_fn``. If that
    path is unavailable and ``local_fallback`` is provided, the fallback evidence
    is mined deterministically. Every failure degrades to an empty report.
    """

    family = (protocol_family or "").strip()
    query = family_history_query(family)
    if not family:
        return _empty_report(family, query, available=False)

    result, used_fallback = _load_result(
        family=family,
        query=query,
        client=client,
        query_fn=query_fn,
        local_fallback=local_fallback,
    )
    if result is None or not getattr(result, "available", False):
        return _empty_report(family, query, available=False)

    candidates = tuple(
        _extract_candidates(
            result,
            trust_floor=trust_floor,
            min_support=max(1, min_support),
            max_candidates=max(1, max_candidates),
        )
    )
    return InvariantMiningReport(
        protocol_family=family,
        query=query,
        candidates=candidates,
        routing_tags=_ordered_unique(tag for c in candidates for tag in c.routing_tags),
        templates=_ordered_unique(template for c in candidates for template in c.templates),
        source_refs=_ordered_unique(ref for c in candidates for ref in c.source_refs),
        available=True,
        used_fallback=used_fallback,
    )


def route_template_for(inv: CandidateInvariant) -> InvariantRouteTemplate:
    """Return the stable router/factory integration payload for one candidate."""

    return InvariantRouteTemplate(
        name=inv.name,
        predicate=inv.predicate,
        routing_tags=inv.routing_tags,
        templates=inv.templates,
        source_refs=inv.source_refs,
        support=inv.support,
        trust=inv.trust,
    )


def _load_result(
    *,
    family: str,
    query: str,
    client: object | None,
    query_fn: FamilyQueryFn | None,
    local_fallback: EvidenceInput,
) -> tuple[MemoryResult | None, bool]:
    result = _try_query(family=family, query=query, client=client, query_fn=query_fn)
    if result is not None and getattr(result, "available", False):
        return result, False

    fallback = _coerce_result(local_fallback)
    if fallback is not None and fallback.available:
        return fallback, True
    return result, False


def _try_query(
    *,
    family: str,
    query: str,
    client: object | None,
    query_fn: FamilyQueryFn | None,
) -> MemoryResult | None:
    if query_fn is None:
        if client is None:
            return None
        try:
            if not bool(client.is_available()):  # type: ignore[attr-defined]
                return None
        except Exception:  # noqa: BLE001 - advisory layer must never be fatal
            return None
        runner = _default_runner(client)
    else:
        runner = query_fn

    try:
        return _coerce_result(runner(family, query))
    except Exception:  # noqa: BLE001 - mining failure is non-fatal
        return None


def _default_runner(client: object) -> FamilyQueryFn:
    """Wrap ``client.query`` into the ``(family, query) -> MemoryResult`` shape."""

    def runner(_family: str, query: str) -> MemoryResult:
        return client.query(query)  # type: ignore[attr-defined]

    return runner


def _coerce_result(raw: EvidenceInput) -> MemoryResult | None:
    if raw is None:
        return None
    if isinstance(raw, MemoryResult):
        return raw
    evidence: list[MemoryEvidence] = []
    try:
        for item in raw:
            if isinstance(item, MemoryEvidence):
                evidence.append(item)
    except TypeError:
        return None
    return MemoryResult(
        available=True,
        confidence=1.0 if evidence else 0.0,
        evidence=tuple(evidence),
    )


def _extract_candidates(
    result: MemoryResult,
    *,
    trust_floor: float,
    min_support: int,
    max_candidates: int,
) -> list[CandidateInvariant]:
    buckets: dict[str, dict[str, object]] = {}

    for index, evidence in enumerate(result.evidence or ()):
        if not isinstance(evidence, MemoryEvidence):
            continue
        if evidence.trust < trust_floor:
            continue

        text = _evidence_text(evidence)
        if not text:
            continue
        ref = evidence.memory_id or f"__noid_{index}"
        signals = _signals_for(text)

        for rule in _INVARIANT_RULES:
            if not _matches_any(text, rule.markers):
                continue
            bucket = _bucket_for(buckets, rule)
            _add_ref(bucket, ref)
            bucket["top_trust"] = max(float(bucket["top_trust"]), evidence.trust)
            _add_signals(bucket, signals, evidence, ref)

    candidates: list[CandidateInvariant] = []
    for bucket in buckets.values():
        refs = tuple(bucket["refs"])  # type: ignore[arg-type]
        support = len(refs)
        if support < min_support:
            continue

        rule = bucket["rule"]
        if not isinstance(rule, _InvariantRule):
            continue
        source_refs = tuple(ref for ref in refs if not str(ref).startswith("__noid_"))
        signals = _signal_summaries(bucket)
        routing_tags = _routing_tags(rule, signals)
        templates = _templates_for(rule)
        top_trust = round(float(bucket["top_trust"]), 4)
        candidates.append(
            CandidateInvariant(
                name=rule.name,
                predicate=rule.predicate,
                source_refs=source_refs,
                support=support,
                trust=top_trust,
                rationale=_rationale_for(rule.implication, support, top_trust, signals),
                routing_tags=routing_tags,
                templates=templates,
                signals=signals,
            )
        )

    candidates.sort(key=lambda c: (-c.support, -c.trust, c.name))
    return candidates[:max_candidates]


def _bucket_for(buckets: dict[str, dict[str, object]], rule: _InvariantRule) -> dict[str, object]:
    bucket = buckets.get(rule.name)
    if bucket is None:
        bucket = {
            "rule": rule,
            "refs": [],
            "seen": set(),
            "top_trust": 0.0,
            "signals": {},
        }
        buckets[rule.name] = bucket
    return bucket


def _add_ref(bucket: dict[str, object], ref: str) -> None:
    seen = bucket["seen"]
    refs = bucket["refs"]
    if not isinstance(seen, set) or not isinstance(refs, list):
        return
    if ref in seen:
        return
    seen.add(ref)
    refs.append(ref)


def _add_signals(
    bucket: dict[str, object],
    signals: tuple[_SignalRule, ...],
    evidence: MemoryEvidence,
    ref: str,
) -> None:
    raw = bucket.get("signals")
    if not isinstance(raw, dict):
        return
    for signal in signals:
        entry = raw.setdefault(
            signal.kind,
            {
                "rule": signal,
                "refs": [],
                "seen": set(),
                "top_trust": 0.0,
            },
        )
        if not isinstance(entry, dict):
            continue
        refs = entry.get("refs")
        seen = entry.get("seen")
        if not isinstance(refs, list) or not isinstance(seen, set):
            continue
        if ref not in seen:
            seen.add(ref)
            refs.append(ref)
        entry["top_trust"] = max(float(entry.get("top_trust") or 0.0), evidence.trust)


def _signal_summaries(bucket: dict[str, object]) -> tuple[SignalSummary, ...]:
    raw = bucket.get("signals")
    if not isinstance(raw, dict):
        return ()

    out: list[SignalSummary] = []
    for kind in (SIGNAL_DEAD_DOOR, SIGNAL_DUPLICATE_RISK, SIGNAL_HISTORICAL_EXPLOIT, SIGNAL_PRIOR_WIN):
        entry = raw.get(kind)
        if not isinstance(entry, dict):
            continue
        rule = entry.get("rule")
        refs = tuple(str(ref) for ref in entry.get("refs", ()) if not str(ref).startswith("__noid_"))
        if not isinstance(rule, _SignalRule):
            continue
        out.append(
            SignalSummary(
                kind=rule.kind,
                support=len(entry.get("refs", ())),
                source_refs=refs,
                trust=round(float(entry.get("top_trust") or 0.0), 4),
                route_action=rule.route_action,
            )
        )
    return tuple(out)


def _routing_tags(rule: _InvariantRule, signals: tuple[SignalSummary, ...]) -> tuple[str, ...]:
    tags: list[str] = [
        f"invariant:{rule.name}",
        f"template:{rule.template}",
        *rule.routing_tags,
    ]
    for summary in signals:
        signal_rule = _signal_rule(summary.kind)
        if signal_rule is None:
            continue
        tags.extend((signal_rule.tag, f"route:{signal_rule.route_action}"))
    return _ordered_unique(tags)


def _templates_for(rule: _InvariantRule) -> tuple[str, ...]:
    return (rule.template, f"foundry_invariant_{rule.name}")


def _signals_for(text: str) -> tuple[_SignalRule, ...]:
    return tuple(signal for signal in _SIGNAL_RULES if _matches_any(text, signal.markers))


def _signal_rule(kind: str) -> _SignalRule | None:
    return next((signal for signal in _SIGNAL_RULES if signal.kind == kind), None)


def _matches_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker.lower() in text for marker in markers)


def _evidence_text(evidence: MemoryEvidence) -> str:
    return " ".join(
        part
        for part in (
            evidence.preview,
            evidence.role,
            evidence.source,
        )
        if part
    ).lower()


def _rationale_for(
    implication: str,
    support: int,
    top_trust: float,
    signals: tuple[SignalSummary, ...],
) -> str:
    plural = "memory" if support == 1 else "memories"
    signal_text = ", ".join(signal.kind for signal in signals) or "general-family-history"
    return (
        f"{support} trusted {plural} (top trust {top_trust:.2f}; signals={signal_text}) "
        f"recur on: {implication} -> candidate invariant"
    )


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in values:
        value = str(raw)
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return tuple(out)


def _empty_report(protocol_family: str, query: str, *, available: bool) -> InvariantMiningReport:
    return InvariantMiningReport(
        protocol_family=protocol_family,
        query=query,
        candidates=(),
        routing_tags=(),
        templates=(),
        source_refs=(),
        available=available,
        used_fallback=False,
    )


# --------------------------------------------------------------------------- #
# Foundry rendering
# --------------------------------------------------------------------------- #


def render_foundry_invariant(inv: CandidateInvariant) -> str:
    """Emit a minimal, honest forge-std invariant test stub for ``inv``.

    The body intentionally fails with ``require(false, ...)`` until a human
    encodes the real check against live protocol state.
    """

    fn = inv.function_name
    contract = f"{_to_pascal_case(inv.name)}Invariant"
    refs = ", ".join(ref[:8] for ref in inv.source_refs[:5]) or "no-ref"
    predicate = _solidity_comment_safe(inv.predicate)
    rationale = _solidity_comment_safe(inv.rationale)
    tags = _solidity_comment_safe(", ".join(inv.routing_tags[:8]) or "none")
    templates = _solidity_comment_safe(", ".join(inv.templates[:4]) or inv.primary_template)

    return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {{Test}} from "forge-std/Test.sol";

/// @title {contract}
/// @notice Mined cross-bounty invariant candidate for a protocol family.
/// @dev Property: {predicate}
/// @dev Evidence: {inv.support} trusted memories (top trust {inv.trust:.2f}); refs [{refs}].
/// @dev Routing tags: {tags}
/// @dev Templates: {templates}
/// @dev Rationale: {rationale}
///
/// Trace2Inv-on-memory: this candidate recurred across the family's accumulated
/// Vestige bounty history. It is a STARTING POINT, not a verified property.
contract {contract} is Test {{
    // TODO: deploy/handler-register the target protocol here (setUp()).
    // function setUp() public {{ ... }}

    /// @notice {predicate}
    function {fn}() public {{
        // TODO(protocolgate): encode the real invariant check below.
        //   Property to assert: {predicate}
        //   This stub intentionally FAILS until implemented so it can never be
        //   mistaken for a verified property. Do NOT replace with a no-op or a
        //   trivially-true assertion -- assert the actual protocol state.
        require(false, "{fn}: not yet implemented (mined candidate)");
    }}
}}
"""


# --------------------------------------------------------------------------- #
# Identifier / comment helpers
# --------------------------------------------------------------------------- #


def _sanitize_identifier(name: str) -> str:
    """Lowercase snake_case identifier safe for a Solidity function suffix."""

    cleaned = re.sub(r"[^0-9a-zA-Z]+", "_", (name or "").strip().lower())
    cleaned = cleaned.strip("_")
    if not cleaned:
        return "property"
    if cleaned[0].isdigit():
        cleaned = f"p_{cleaned}"
    return cleaned


def _to_pascal_case(name: str) -> str:
    parts = [p for p in re.split(r"[^0-9a-zA-Z]+", (name or "").strip()) if p]
    if not parts:
        return "Property"
    return "".join(p[:1].upper() + p[1:] for p in parts)


def _solidity_comment_safe(text: str) -> str:
    """Collapse text so a single-line NatSpec comment cannot be escaped."""

    flat = " ".join((text or "").split())
    return flat.replace("*/", "* /").replace("//", "/ /")
