"""Cross-bounty memory reasoning layer for the ProtocolGate factory.

The factory's :mod:`protocolgate.factory` read-back answers a single yes/no
question per lane: "was this lane already closed as a dead-door?" That is a
skip-cache. This module is the MOAT: it treats Vestige as the memory an agent
uses to *reason across bounties*, not just to avoid repeats.

For one prospective drift lane it runs FOUR distinct reasoning intents, each a
focused Vestige query plus a classifier over the recalled evidence, then
synthesizes a single :class:`LaneJudgment` whose ``action`` changes what the
factory does next. The reasoning follows the active-synthesis contract:

    evidence -> implication -> action

Each recalled memory is read for *what action it changes*, weighted by trust.
Only evidence at or above ``trust_floor`` counts. The four intents are:

1. ``DEAD_DOOR``         -> ``SKIP``           (lane already killed/deferred)
2. ``PRIOR_WIN``         -> ``PRIORITIZE``     (this pattern paid before)
3. ``HISTORICAL_EXPLOIT``-> ``ARM_TEMPLATE``   (a known exploit matches topology)
4. ``DUPLICATE_RISK``    -> ``FLAG_DUPLICATE`` (this exact finding was reported)

Design constraints (load-bearing, do not violate):

- ADVISORY. This layer never gates a verdict and never raises. On any error, an
  unavailable client, or empty recall it degrades to ``PROCEED``.
- Injectable. The client and the per-intent query function are both injectable
  so tests run with no network.
- Dependency-free beyond the stdlib + existing ProtocolGate modules. Frozen
  dataclasses; ``from __future__`` annotations; stdlib-first style to match the
  repo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol

from protocolgate.memory import MemoryEvidence, MemoryResult

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Only reason over memories the memory engine itself scores as reasonably
# trusted. Mirrors ``memory.DEFAULT_TRUST_FLOOR`` so factory and reasoning agree.
DEFAULT_TRUST_FLOOR = 0.45

# Intent identifiers (also the labels rendered in a judgment summary).
INTENT_DEAD_DOOR = "DEAD_DOOR"
INTENT_PRIOR_WIN = "PRIOR_WIN"
INTENT_HISTORICAL_EXPLOIT = "HISTORICAL_EXPLOIT"
INTENT_DUPLICATE_RISK = "DUPLICATE_RISK"

# Actions a judgment can recommend, in precedence order (highest first). When
# more than one intent fires, the earliest action in this tuple wins.
ACTION_SKIP = "SKIP"
ACTION_FLAG_DUPLICATE = "FLAG_DUPLICATE"
ACTION_ARM_TEMPLATE = "ARM_TEMPLATE"
ACTION_PRIORITIZE = "PRIORITIZE"
ACTION_PROCEED = "PROCEED"

# Strict precedence: DEAD_DOOR (skip) > DUPLICATE_RISK (flag) >
# HISTORICAL_EXPLOIT (arm) > PRIOR_WIN (prioritize) > PROCEED.
ACTION_PRECEDENCE = (
    ACTION_SKIP,
    ACTION_FLAG_DUPLICATE,
    ACTION_ARM_TEMPLATE,
    ACTION_PRIORITIZE,
    ACTION_PROCEED,
)

# Confidence nudges each firing intent applies to the lane. Negative = downgrade
# (skip / duplicate), positive = upgrade (exploit armed / prior win). These are
# advisory deltas the factory may fold into its own ranking.
DELTA_DEAD_DOOR = -1.0
DELTA_DUPLICATE_RISK = -0.5
DELTA_HISTORICAL_EXPLOIT = +0.5
DELTA_PRIOR_WIN = +0.35

# Markers proving a recalled lane was previously closed or deferred. Kept in
# sync with ``factory.DEAD_DOOR_MARKERS`` so the two layers classify identically.
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
    "known-issue",
    "known issue",
    "ineligible",
    "out of scope",
    "out-of-scope",
)

# Markers proving a recalled control-plane pattern previously PAID.
PRIOR_WIN_MARKERS = (
    "paid",
    "payout",
    "bounty paid",
    "submission-ready",
    "submission ready",
    "confirmed critical",
    "confirmed high",
    "accepted",
    "rewarded",
    "triaged valid",
    "valid critical",
    "valid high",
)

# Markers proving a recalled memory describes a historical exploit / attack
# pattern that can arm a PoC template.
EXPLOIT_MARKERS = (
    "exploit",
    "hack",
    "drained",
    "drain",
    "attack",
    "upgrade authority",
    "unprotected upgrade",
    "admin takeover",
    "proxy admin",
    "uninitialized",
    "timelock bypass",
    "oracle manipulation",
    "bridge drain",
    "rug",
    "cve",
    "post-mortem",
    "postmortem",
)

# Markers proving this exact finding was already reported / submitted.
DUPLICATE_MARKERS = (
    "submitted",
    "already reported",
    "already submitted",
    "duplicate",
    "dup of",
    "previously disclosed",
    "already known",
    "known finding",
    "reported on",
    "filed report",
)


# --------------------------------------------------------------------------- #
# Injectable client / query types
# --------------------------------------------------------------------------- #


class VestigeQueryClient(Protocol):
    """Structural type for the advisory memory client this layer consumes.

    The real :class:`protocolgate.memory.VestigeClient` satisfies this; tests
    inject a fake with the same two methods and no network.
    """

    def is_available(self) -> bool: ...

    def query(self, text: str) -> MemoryResult: ...


# A callable that, given an intent name and its query string, returns a
# ``MemoryResult``. Defaults to ``client.query``; injectable so tests can map a
# scripted result per intent without a network.
IntentQueryFn = Callable[[str, str], MemoryResult]


# --------------------------------------------------------------------------- #
# Result dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class IntentResult:
    """Outcome of one reasoning intent over the recalled, trust-filtered memory."""

    intent: str
    query: str
    matched: bool
    refs: tuple[str, ...] = ()
    top_trust: float = 0.0
    rationale: str = ""

    @property
    def action(self) -> str:
        """The action this intent recommends iff it fired, else ``PROCEED``."""
        if not self.matched:
            return ACTION_PROCEED
        return _INTENT_ACTION.get(self.intent, ACTION_PROCEED)

    @property
    def delta(self) -> float:
        """This intent's confidence nudge iff it fired, else ``0.0``."""
        if not self.matched:
            return 0.0
        return _INTENT_DELTA.get(self.intent, 0.0)


@dataclass(frozen=True)
class LaneJudgment:
    """Synthesized cross-bounty judgment for one prospective drift lane.

    ``action`` is the single recommended next move (precedence-resolved when
    several intents fire). ``confidence_delta`` is the summed advisory nudge.
    ``summary`` is an explainable ``evidence -> implication -> action`` line.
    """

    signature: str
    action: str
    confidence_delta: float
    intents: tuple[IntentResult, ...]
    summary: str
    available: bool = True

    @property
    def fired_intents(self) -> tuple[IntentResult, ...]:
        return tuple(intent for intent in self.intents if intent.matched)

    @property
    def evidence_refs(self) -> tuple[str, ...]:
        """Deduplicated memory refs across every firing intent, order-preserved."""
        seen: set[str] = set()
        out: list[str] = []
        for intent in self.intents:
            if not intent.matched:
                continue
            for ref in intent.refs:
                if ref and ref not in seen:
                    seen.add(ref)
                    out.append(ref)
        return tuple(out)


# Intent -> action / delta lookups (defined after the dataclasses so the
# properties above can reference them).
_INTENT_ACTION = {
    INTENT_DEAD_DOOR: ACTION_SKIP,
    INTENT_DUPLICATE_RISK: ACTION_FLAG_DUPLICATE,
    INTENT_HISTORICAL_EXPLOIT: ACTION_ARM_TEMPLATE,
    INTENT_PRIOR_WIN: ACTION_PRIORITIZE,
}
_INTENT_DELTA = {
    INTENT_DEAD_DOOR: DELTA_DEAD_DOOR,
    INTENT_DUPLICATE_RISK: DELTA_DUPLICATE_RISK,
    INTENT_HISTORICAL_EXPLOIT: DELTA_HISTORICAL_EXPLOIT,
    INTENT_PRIOR_WIN: DELTA_PRIOR_WIN,
}


# --------------------------------------------------------------------------- #
# Query builders (exposed for tests)
# --------------------------------------------------------------------------- #


def lane_signature(target: str, subject: str, kind: str) -> str:
    """Canonical lane signature, identical to ``factory.lane_signature``."""
    return f"{target}:{subject}:{kind}"


def dead_door_query(target: str, subject: str, kind: str, finding: str = "") -> str:
    """Intent 1: was this lane/pattern already killed or deferred?"""
    sig = lane_signature(target, subject, kind)
    base = f"{sig} dead-door closed-door reopen_if known-issue ineligible out-of-scope"
    return _with_finding(base, finding)


def prior_win_query(target: str, subject: str, kind: str, finding: str = "") -> str:
    """Intent 2: did this control-plane pattern PAY on a similar protocol before?"""
    base = (
        f"{kind} paid bounty submission-ready confirmed critical high "
        f"control-plane payout accepted rewarded"
    )
    return _with_finding(base, finding)


def historical_exploit_query(
    target: str, subject: str, kind: str, finding: str = ""
) -> str:
    """Intent 3: does a known historical exploit match this topology/kind?"""
    base = (
        f"{kind} {subject} exploit hack upgrade authority proxy admin timelock "
        f"oracle bridge drain attack post-mortem"
    )
    return _with_finding(base, finding)


def duplicate_risk_query(
    target: str, subject: str, kind: str, finding: str = ""
) -> str:
    """Intent 4: has this exact finding already been reported/submitted?"""
    base = f"{target} {subject} {kind} submitted report duplicate already known disclosed"
    return _with_finding(base, finding)


# Ordered intent table: (intent name, query builder, marker tuple). Used to drive
# both the per-intent run and the precedence-respecting synthesis.
_INTENT_BUILDERS: tuple[tuple[str, Callable[[str, str, str, str], str], tuple[str, ...]], ...] = (
    (INTENT_DEAD_DOOR, dead_door_query, DEAD_DOOR_MARKERS),
    (INTENT_PRIOR_WIN, prior_win_query, PRIOR_WIN_MARKERS),
    (INTENT_HISTORICAL_EXPLOIT, historical_exploit_query, EXPLOIT_MARKERS),
    (INTENT_DUPLICATE_RISK, duplicate_risk_query, DUPLICATE_MARKERS),
)


def _with_finding(base: str, finding: str) -> str:
    finding = (finding or "").strip()
    if not finding:
        return base
    # Cap the appended finding context so the query stays compact and the client
    # truncation (1500 chars) never clips the structured marker tail.
    return f"{base} {finding[:300]}"


# --------------------------------------------------------------------------- #
# Per-intent classification
# --------------------------------------------------------------------------- #


def _matches_markers(preview: str, markers: tuple[str, ...]) -> bool:
    lowered = (preview or "").lower()
    return any(marker in lowered for marker in markers)


def _classify_intent(
    intent: str,
    query: str,
    result: MemoryResult,
    markers: tuple[str, ...],
    trust_floor: float,
) -> IntentResult:
    """Read trust-filtered recall for one intent into a (matched, refs, ...) row.

    Only evidence with ``trust >= trust_floor`` and a marker hit counts. The
    rationale is the ``evidence -> implication`` half of the contract; the action
    half is the intent's mapped action.
    """

    if result is None or not getattr(result, "available", False):
        return IntentResult(intent=intent, query=query, matched=False, rationale="no recall")

    matched_refs: list[str] = []
    top_trust = 0.0
    for evidence in result.evidence or ():
        if not isinstance(evidence, MemoryEvidence):
            continue
        if evidence.trust < trust_floor:
            continue
        if not _matches_markers(evidence.preview, markers):
            continue
        matched_refs.append(evidence.memory_id)
        if evidence.trust > top_trust:
            top_trust = evidence.trust

    if not matched_refs:
        # Distinguish "had recall but nothing trusted/matching" from "no recall".
        had_recall = bool(result.evidence)
        rationale = (
            "recall present but below trust floor or no pattern match"
            if had_recall
            else "no recall"
        )
        return IntentResult(intent=intent, query=query, matched=False, rationale=rationale)

    return IntentResult(
        intent=intent,
        query=query,
        matched=True,
        refs=tuple(matched_refs),
        top_trust=top_trust,
        rationale=_rationale_for(intent, len(matched_refs), top_trust),
    )


def _rationale_for(intent: str, count: int, top_trust: float) -> str:
    plural = "memory" if count == 1 else "memories"
    if intent == INTENT_DEAD_DOOR:
        impl = "this lane was already killed/deferred"
    elif intent == INTENT_PRIOR_WIN:
        impl = "this control-plane pattern paid before"
    elif intent == INTENT_HISTORICAL_EXPLOIT:
        impl = "a known exploit matches this topology"
    elif intent == INTENT_DUPLICATE_RISK:
        impl = "this finding looks already reported"
    else:
        impl = "relevant prior context"
    return f"{count} trusted {plural} (top trust {top_trust:.2f}) -> {impl}"


# --------------------------------------------------------------------------- #
# Top-level synthesis
# --------------------------------------------------------------------------- #


def judge_lane(
    target: str,
    subject: str,
    kind: str,
    client: VestigeQueryClient | None,
    *,
    finding: str | None = None,
    trust_floor: float = DEFAULT_TRUST_FLOOR,
    intent_query_fn: IntentQueryFn | None = None,
) -> LaneJudgment:
    """Reason across bounty memory for one lane and return a :class:`LaneJudgment`.

    Runs all four intents as distinct queries, classifies each over the recalled
    evidence (trust-filtered at ``trust_floor``), then synthesizes one action by
    precedence. NEVER raises: on an unavailable client or any error it degrades
    to a ``PROCEED`` judgment.

    Parameters
    ----------
    target, subject, kind:
        The prospective drift lane to reason about.
    client:
        Advisory memory client (real :class:`VestigeClient` or a fake). ``None``
        or unavailable -> ``PROCEED``.
    finding:
        Optional free-text finding context appended to each intent query to
        sharpen recall.
    trust_floor:
        Minimum evidence trust that counts toward a match.
    intent_query_fn:
        Injectable ``(intent, query) -> MemoryResult``. Defaults to wrapping
        ``client.query`` (which ignores the intent name). Tests use it to script
        a different result per intent without a network.
    """

    signature = lane_signature(target, subject, kind)

    if client is None:
        return _proceed(signature, "vestige client not provided", available=False)

    # One up-front availability check: a down memory engine means no reasoning,
    # not a connection storm across four intents.
    try:
        available = bool(client.is_available())
    except Exception:  # noqa: BLE001 - advisory layer must never be fatal
        available = False
    if not available:
        return _proceed(signature, "vestige unavailable; reasoning skipped", available=False)

    runner = intent_query_fn if intent_query_fn is not None else _default_runner(client)

    intents: list[IntentResult] = []
    for intent_name, builder, markers in _INTENT_BUILDERS:
        query = builder(target, subject, kind, finding or "")
        try:
            result = runner(intent_name, query)
        except Exception:  # noqa: BLE001 - one intent failing must not kill the rest
            intents.append(
                IntentResult(
                    intent=intent_name,
                    query=query,
                    matched=False,
                    rationale="intent query failed",
                )
            )
            continue
        intents.append(_classify_intent(intent_name, query, result, markers, trust_floor))

    return _synthesize(signature, tuple(intents))


def _default_runner(client: VestigeQueryClient) -> IntentQueryFn:
    """Wrap ``client.query`` into the (intent, query) -> MemoryResult shape."""

    def runner(_intent: str, query: str) -> MemoryResult:
        return client.query(query)

    return runner


def _synthesize(signature: str, intents: tuple[IntentResult, ...]) -> LaneJudgment:
    """Resolve fired intents into one precedence-ranked, explainable judgment."""

    fired = [intent for intent in intents if intent.matched]
    if not fired:
        return LaneJudgment(
            signature=signature,
            action=ACTION_PROCEED,
            confidence_delta=0.0,
            intents=intents,
            summary=(
                f"{signature}: no trusted cross-bounty evidence -> PROCEED "
                "(deterministic drift engine decides)."
            ),
            available=True,
        )

    # Precedence: the earliest action in ACTION_PRECEDENCE among fired intents.
    action = _resolve_action(fired)
    delta = sum(intent.delta for intent in fired)
    summary = _summarize(signature, action, fired)
    return LaneJudgment(
        signature=signature,
        action=action,
        confidence_delta=delta,
        intents=intents,
        summary=summary,
        available=True,
    )


def _resolve_action(fired: list[IntentResult]) -> str:
    fired_actions = {intent.action for intent in fired}
    for candidate in ACTION_PRECEDENCE:
        if candidate in fired_actions:
            return candidate
    return ACTION_PROCEED


def _summarize(signature: str, action: str, fired: list[IntentResult]) -> str:
    """Build the explainable ``evidence -> implication -> action`` summary.

    The winning intent (the one whose action was selected by precedence) leads;
    other firing intents are listed as additional context so nothing is hidden.
    """

    winner = next((intent for intent in fired if intent.action == action), fired[0])
    refs = ",".join(ref[:8] for ref in winner.refs[:3])
    head = (
        f"{signature}: {winner.intent} fired [{refs}] "
        f"trust={winner.top_trust:.2f} -> {winner.rationale} -> {action}"
    )

    others = [intent for intent in fired if intent is not winner]
    if not others:
        return head
    tail = "; also " + ", ".join(
        f"{intent.intent}({intent.action},{intent.top_trust:.2f})" for intent in others
    )
    return head + tail


def _proceed(signature: str, reason: str, *, available: bool) -> LaneJudgment:
    """A no-op PROCEED judgment used for unavailable/empty/error degradation."""

    return LaneJudgment(
        signature=signature,
        action=ACTION_PROCEED,
        confidence_delta=0.0,
        intents=(),
        summary=f"{signature}: {reason} -> PROCEED.",
        available=available,
    )
