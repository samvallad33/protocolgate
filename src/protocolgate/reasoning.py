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
from typing import Callable, Iterable, Protocol

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

# A callable that, given an intent name and its query string, returns historical
# evidence pulled from a PUBLIC corpus connector (Solodit, DeFiHackLabs, ...) and
# already mapped into the repo's ``MemoryEvidence`` shape. Defaults to ``None``
# (a pure no-op: existing callers behave identically). When supplied it is
# consulted ONLY for the two intents that reason over historical exploits and
# prior public reports, and its matches are FOLDED INTO those intents' Vestige
# evidence rather than replacing it.
#
# The connector layer (out of scope here) is responsible for trust-weighting:
# each returned ``MemoryEvidence.trust`` should already encode Solodit
# quality x rarity (e.g. a high-severity, rarely-seen finding scores near 1.0; a
# common low-severity note scores below ``DEFAULT_TRUST_FLOOR`` so it cannot
# fire an intent). ``source`` should mark provenance, e.g. ``"solodit"``.
#
# Bright line (see ``connectors``): Solodit is a public utility INPUT, never the
# moat. The moat move is to dual-write *strong* Solodit matches back into the
# private Vestige layer so it compounds. The wiring describes that ``smart_ingest``
# call shape in ``_dual_write_hint`` below; it never performs network I/O here.
HistoricalRecallFn = Callable[[str, str], "Iterable[MemoryEvidence] | MemoryResult | None"]

# Intents allowed to fold in public-corpus (Solodit) recall. Dead-door and
# prior-win reason over the PRIVATE bounty-sim layer only; mixing public corpus
# into them would dilute those private signals, so they are deliberately excluded.
_RECALL_FOLD_INTENTS = frozenset({INTENT_HISTORICAL_EXPLOIT, INTENT_DUPLICATE_RISK})


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
# Public-corpus (Solodit) fold-in
# --------------------------------------------------------------------------- #


def _coerce_recall(recall: object) -> tuple[MemoryEvidence, ...]:
    """Normalise a ``historical_recall_fn`` return value to evidence.

    Accepts ``None``, a ``MemoryResult``, or any iterable of ``MemoryEvidence``
    so the connector layer can return whichever shape is convenient. Anything
    else is treated as empty. Never raises (advisory contract).
    """

    if recall is None:
        return ()
    if isinstance(recall, MemoryResult):
        if not getattr(recall, "available", False):
            return ()
        recall = recall.evidence or ()
    out: list[MemoryEvidence] = []
    try:
        for item in recall:  # type: ignore[union-attr]
            if isinstance(item, MemoryEvidence):
                out.append(item)
    except TypeError:
        return ()
    return tuple(out)


def _merge_intent(base: IntentResult, extra: IntentResult) -> IntentResult:
    """Fold a Solodit-derived ``IntentResult`` into the Vestige one for an intent.

    Union of refs (order-preserved, Vestige first), max top trust, matched iff
    either matched. The rationale notes the Solodit contribution so the
    ``evidence -> implication`` half stays explainable.
    """

    if not extra.matched:
        return base

    seen: set[str] = set()
    refs: list[str] = []
    for ref in (*base.refs, *extra.refs):
        if ref and ref not in seen:
            seen.add(ref)
            refs.append(ref)

    top_trust = max(base.top_trust, extra.top_trust)
    count = len(refs)
    rationale = (
        f"{_rationale_for(base.intent, count, top_trust)} "
        f"(+{len(extra.refs)} solodit)"
    )
    return IntentResult(
        intent=base.intent,
        query=base.query,
        matched=True,
        refs=tuple(refs),
        top_trust=top_trust,
        rationale=rationale,
    )


def _fold_historical_recall(
    intents: list[IntentResult],
    *,
    recall_fn: HistoricalRecallFn,
    target: str,
    subject: str,
    kind: str,
    finding: str,
    trust_floor: float,
) -> list[IntentResult]:
    """Augment HISTORICAL_EXPLOIT / DUPLICATE_RISK with public-corpus recall.

    Pure-additive: the Solodit evidence is run through the SAME trust-floor and
    marker classifier as Vestige evidence (so a weak Solodit hit cannot fire an
    intent on its own), then merged into the matching intent's row. Never raises;
    a failing or empty recall leaves ``intents`` untouched.
    """

    by_intent = {INTENT_HISTORICAL_EXPLOIT: EXPLOIT_MARKERS, INTENT_DUPLICATE_RISK: DUPLICATE_MARKERS}
    out: list[IntentResult] = []
    for current in intents:
        markers = by_intent.get(current.intent)
        if markers is None or current.intent not in _RECALL_FOLD_INTENTS:
            out.append(current)
            continue
        try:
            raw = recall_fn(current.intent, current.query)
            evidence = _coerce_recall(raw)
        except Exception:  # noqa: BLE001 - advisory: recall failure is non-fatal
            out.append(current)
            continue
        if not evidence:
            out.append(current)
            continue
        solodit_result = MemoryResult(available=True, confidence=1.0, evidence=evidence)
        solodit_intent = _classify_intent(
            current.intent, current.query, solodit_result, markers, trust_floor
        )
        merged = _merge_intent(current, solodit_intent)
        if merged.matched and not current.matched:
            # A purely-Solodit match is worth dual-writing back into the private
            # layer so the moat compounds. We only describe the call; no network.
            _dual_write_hint(target, subject, kind, finding, solodit_intent)
        out.append(merged)
    return out


def _dual_write_hint(
    target: str,
    subject: str,
    kind: str,
    finding: str,
    solodit_intent: IntentResult,
) -> None:
    """Describe (do NOT perform) the moat dual-write of a strong Solodit match.

    The bright-line moat move: when a public-corpus finding clears the trust
    floor and fires an intent, mirror it into the PRIVATE Vestige layer so the
    trust-weighted memory compounds over time. The actual write belongs to the
    factory's write path (it already owns the stdio ``smart_ingest`` channel via
    ``bounty_sim``); reasoning is advisory and stays network-free. The intended
    call shape is::

        smart_ingest(
            content=(
                f"[solodit-mirror] {lane_signature(target, subject, kind)} "
                f"intent={solodit_intent.intent} "
                f"refs={','.join(solodit_intent.refs)} "
                f"trust={solodit_intent.top_trust:.2f} "
                f"finding={finding[:300]}"
            ),
            source="protocolgate:solodit-mirror",
            tags=["historical-exploit", kind, target],
        )

    This is intentionally a no-op here so reasoning never blocks on or fails from
    a write. The connector/factory layer decides when to actually emit it.
    """

    return None


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
    historical_recall_fn: HistoricalRecallFn | None = None,
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
    historical_recall_fn:
        OPTIONAL injectable ``(intent, query) -> Iterable[MemoryEvidence] |
        MemoryResult | None`` that pulls public-corpus (Solodit / DeFiHackLabs)
        matches and folds them into the HISTORICAL_EXPLOIT and DUPLICATE_RISK
        intents only. ``None`` (the default) is a pure no-op: behaviour is
        identical to before. Matches are trust-floor + marker filtered exactly
        like Vestige evidence, so a weak public hit never fires an intent on its
        own. The returned evidence is expected to be trust-weighted by Solodit
        quality x rarity in the connector layer. Strong purely-public matches are
        candidates for a dual-write back into the private Vestige layer (see
        ``_dual_write_hint``); this function never performs network I/O.
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

    # Pure-additive: when a public-corpus recall fn is supplied, fold Solodit
    # matches into the historical-exploit / duplicate-risk intents. No fn -> no-op.
    if historical_recall_fn is not None:
        intents = _fold_historical_recall(
            intents,
            recall_fn=historical_recall_fn,
            target=target,
            subject=subject,
            kind=kind,
            finding=finding or "",
            trust_floor=trust_floor,
        )

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
