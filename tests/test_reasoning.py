"""Tests for the cross-bounty memory reasoning layer.

No network: a fake client returns scripted ``MemoryResult``s, and an injectable
``intent_query_fn`` lets each of the four reasoning intents be fired in
isolation. These tests pin the four intent->action mappings, the precedence
order when several fire, trust-floor filtering, and the advisory degradation
contract (unavailable / raising client -> PROCEED, never an exception).
"""

from __future__ import annotations

import pytest

from protocolgate.memory import MemoryEvidence, MemoryResult
from protocolgate.reasoning import (
    ACTION_ARM_TEMPLATE,
    ACTION_FLAG_DUPLICATE,
    ACTION_PRIORITIZE,
    ACTION_PROCEED,
    ACTION_SKIP,
    DEFAULT_TRUST_FLOOR,
    INTENT_DEAD_DOOR,
    INTENT_DUPLICATE_RISK,
    INTENT_HISTORICAL_EXPLOIT,
    INTENT_PRIOR_WIN,
    LaneJudgment,
    dead_door_query,
    duplicate_risk_query,
    historical_exploit_query,
    judge_lane,
    lane_signature,
    prior_win_query,
)

TARGET = "Acme"
SUBJECT = "Vault"
KIND = "proxy_admin_drift"
SIG = lane_signature(TARGET, SUBJECT, KIND)


# --------------------------------------------------------------------------- #
# Fakes (no network)
# --------------------------------------------------------------------------- #


def _evidence(memory_id: str, preview: str, trust: float = 0.9) -> MemoryEvidence:
    return MemoryEvidence(
        memory_id=memory_id,
        trust=trust,
        date="2026-06-01",
        preview=preview,
        role="recommended",
        source="protocolgate private bounty-sim",
    )


def _result(*evidence: MemoryEvidence, confidence: float = 0.9) -> MemoryResult:
    return MemoryResult(
        available=True,
        confidence=confidence if evidence else 0.0,
        evidence=tuple(evidence),
    )


EMPTY = MemoryResult(available=True, confidence=0.0, evidence=())


class FakeClient:
    """Minimal available/query client; query result is overridable per call."""

    def __init__(self, available: bool = True, result: MemoryResult | None = None) -> None:
        self._available = available
        self._result = result if result is not None else EMPTY
        self.queries: list[str] = []

    def is_available(self) -> bool:
        return self._available

    def query(self, text: str) -> MemoryResult:
        self.queries.append(text)
        return self._result


def scripted_runner(by_intent: dict[str, MemoryResult]):
    """Build an intent_query_fn that returns a scripted result per intent name.

    Records every (intent, query) pair it is asked for so tests can assert all
    four intents were exercised with the right query strings.
    """

    calls: list[tuple[str, str]] = []

    def runner(intent: str, query: str) -> MemoryResult:
        calls.append((intent, query))
        return by_intent.get(intent, EMPTY)

    runner.calls = calls  # type: ignore[attr-defined]
    return runner


# --------------------------------------------------------------------------- #
# 1. Each intent fires in isolation -> its mapped action
# --------------------------------------------------------------------------- #


def test_dead_door_intent_fires_skip() -> None:
    runner = scripted_runner(
        {INTENT_DEAD_DOOR: _result(_evidence("deadcap0", "lane closed as dead-door; reopen_if scope changes"))}
    )
    judgment = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)

    assert judgment.action == ACTION_SKIP
    assert judgment.confidence_delta < 0
    assert judgment.evidence_refs == ("deadcap0",)
    fired = judgment.fired_intents
    assert [intent.intent for intent in fired] == [INTENT_DEAD_DOOR]
    assert fired[0].top_trust == pytest.approx(0.9)
    assert "DEAD_DOOR" in judgment.summary and "SKIP" in judgment.summary
    # All four intents were still queried even though only one matched.
    assert len(runner.calls) == 4  # type: ignore[attr-defined]


def test_prior_win_intent_fires_prioritize() -> None:
    runner = scripted_runner(
        {INTENT_PRIOR_WIN: _result(_evidence("wincap00", "proxy_admin_drift PAID 50k confirmed critical on similar protocol"))}
    )
    judgment = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)

    assert judgment.action == ACTION_PRIORITIZE
    assert judgment.confidence_delta > 0
    assert judgment.evidence_refs == ("wincap00",)
    assert [intent.intent for intent in judgment.fired_intents] == [INTENT_PRIOR_WIN]


def test_historical_exploit_intent_fires_arm_template() -> None:
    runner = scripted_runner(
        {INTENT_HISTORICAL_EXPLOIT: _result(_evidence("explo000", "post-mortem: unprotected upgrade authority let attacker drain proxy admin"))}
    )
    judgment = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)

    assert judgment.action == ACTION_ARM_TEMPLATE
    assert judgment.confidence_delta > 0
    assert judgment.evidence_refs == ("explo000",)
    assert [intent.intent for intent in judgment.fired_intents] == [INTENT_HISTORICAL_EXPLOIT]


def test_duplicate_risk_intent_fires_flag_duplicate() -> None:
    runner = scripted_runner(
        {INTENT_DUPLICATE_RISK: _result(_evidence("dupcap00", "this exact proxy admin finding already submitted / duplicate"))}
    )
    judgment = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)

    assert judgment.action == ACTION_FLAG_DUPLICATE
    assert judgment.confidence_delta < 0
    assert judgment.evidence_refs == ("dupcap00",)
    assert [intent.intent for intent in judgment.fired_intents] == [INTENT_DUPLICATE_RISK]


def test_no_matching_evidence_proceeds() -> None:
    # Recall exists but matches no intent's markers -> PROCEED, no fired intents.
    noise = _result(_evidence("noisecap", "unrelated note about deployment scripts and CI cache"))
    runner = scripted_runner({intent: noise for intent in (
        INTENT_DEAD_DOOR, INTENT_PRIOR_WIN, INTENT_HISTORICAL_EXPLOIT, INTENT_DUPLICATE_RISK)})
    judgment = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)

    assert judgment.action == ACTION_PROCEED
    assert judgment.confidence_delta == 0.0
    assert judgment.fired_intents == ()
    assert judgment.available is True


# --------------------------------------------------------------------------- #
# 2. Precedence when several intents fire
# --------------------------------------------------------------------------- #


def test_precedence_dead_door_beats_everything() -> None:
    runner = scripted_runner(
        {
            INTENT_DEAD_DOOR: _result(_evidence("deadcap0", "closed-door dead-door reopen_if scope changes")),
            INTENT_PRIOR_WIN: _result(_evidence("wincap00", "proxy_admin_drift PAID confirmed critical")),
            INTENT_HISTORICAL_EXPLOIT: _result(_evidence("explo000", "exploit: admin takeover drained funds")),
            INTENT_DUPLICATE_RISK: _result(_evidence("dupcap00", "already submitted duplicate")),
        }
    )
    judgment = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)

    # DEAD_DOOR (skip) wins over duplicate, exploit, prior-win.
    assert judgment.action == ACTION_SKIP
    # But all four are recorded as fired (nothing hidden).
    assert {intent.intent for intent in judgment.fired_intents} == {
        INTENT_DEAD_DOOR, INTENT_PRIOR_WIN, INTENT_HISTORICAL_EXPLOIT, INTENT_DUPLICATE_RISK
    }
    # Winner leads the summary, others surface as "also".
    assert judgment.summary.startswith(f"{SIG}: DEAD_DOOR")
    assert "also" in judgment.summary


def test_precedence_duplicate_beats_exploit_and_prior_win() -> None:
    runner = scripted_runner(
        {
            INTENT_PRIOR_WIN: _result(_evidence("wincap00", "proxy_admin_drift PAID confirmed critical")),
            INTENT_HISTORICAL_EXPLOIT: _result(_evidence("explo000", "exploit: admin takeover drained funds")),
            INTENT_DUPLICATE_RISK: _result(_evidence("dupcap00", "already submitted duplicate")),
        }
    )
    judgment = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)

    assert judgment.action == ACTION_FLAG_DUPLICATE
    assert judgment.summary.startswith(f"{SIG}: DUPLICATE_RISK")


def test_precedence_exploit_beats_prior_win() -> None:
    runner = scripted_runner(
        {
            INTENT_PRIOR_WIN: _result(_evidence("wincap00", "proxy_admin_drift PAID confirmed critical")),
            INTENT_HISTORICAL_EXPLOIT: _result(_evidence("explo000", "exploit: unprotected upgrade authority drain")),
        }
    )
    judgment = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)

    assert judgment.action == ACTION_ARM_TEMPLATE
    # Delta sums both firing intents' nudges.
    assert judgment.confidence_delta == pytest.approx(0.5 + 0.35)


# --------------------------------------------------------------------------- #
# 3. Trust-floor filtering
# --------------------------------------------------------------------------- #


def test_low_trust_evidence_is_ignored() -> None:
    # Marker matches, but trust is below the floor -> intent does NOT fire.
    runner = scripted_runner(
        {INTENT_DEAD_DOOR: _result(_evidence("weakcap0", "dead-door closed lane", trust=0.20))}
    )
    judgment = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)

    assert judgment.action == ACTION_PROCEED
    assert judgment.fired_intents == ()


def test_trust_floor_is_configurable() -> None:
    runner = scripted_runner(
        {INTENT_DEAD_DOOR: _result(_evidence("midcap00", "dead-door closed lane", trust=0.50))}
    )
    # Default floor (0.45): 0.50 counts -> SKIP.
    fires = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)
    assert fires.action == ACTION_SKIP

    # Raise the floor above the evidence trust: it no longer counts -> PROCEED.
    runner2 = scripted_runner(
        {INTENT_DEAD_DOOR: _result(_evidence("midcap00", "dead-door closed lane", trust=0.50))}
    )
    suppressed = judge_lane(
        TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner2, trust_floor=0.75
    )
    assert suppressed.action == ACTION_PROCEED


def test_only_trusted_refs_are_carried() -> None:
    # Two markers match; only the one at/above floor is carried as a ref.
    runner = scripted_runner(
        {
            INTENT_HISTORICAL_EXPLOIT: _result(
                _evidence("weak0000", "exploit drain", trust=0.30),
                _evidence("strong00", "exploit: oracle manipulation bridge drain", trust=0.88),
            )
        }
    )
    judgment = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)

    assert judgment.action == ACTION_ARM_TEMPLATE
    assert judgment.evidence_refs == ("strong00",)
    fired = judgment.fired_intents[0]
    assert fired.top_trust == pytest.approx(0.88)


# --------------------------------------------------------------------------- #
# 4. Advisory degradation: never raises
# --------------------------------------------------------------------------- #


def test_client_none_proceeds() -> None:
    judgment = judge_lane(TARGET, SUBJECT, KIND, None)
    assert judgment.action == ACTION_PROCEED
    assert judgment.available is False
    assert judgment.intents == ()
    assert judgment.signature == SIG


def test_client_unavailable_proceeds_without_querying() -> None:
    client = FakeClient(available=False)
    judgment = judge_lane(TARGET, SUBJECT, KIND, client)

    assert judgment.action == ACTION_PROCEED
    assert judgment.available is False
    # No queries issued because the up-front health check failed.
    assert client.queries == []


def test_is_available_raising_proceeds() -> None:
    class BoomAvailable(FakeClient):
        def is_available(self) -> bool:
            raise RuntimeError("health blew up")

    judgment = judge_lane(TARGET, SUBJECT, KIND, BoomAvailable())
    assert judgment.action == ACTION_PROCEED
    assert judgment.available is False


def test_query_raising_is_not_fatal() -> None:
    # The default runner (client.query) raises for every intent -> PROCEED, no crash.
    class BoomQuery(FakeClient):
        def query(self, text: str) -> MemoryResult:
            raise RuntimeError("memory blew up")

    judgment = judge_lane(TARGET, SUBJECT, KIND, BoomQuery())

    assert judgment.action == ACTION_PROCEED
    assert judgment.available is True  # client was reachable; recall just failed
    # Every intent is recorded as a non-fatal failure.
    assert len(judgment.intents) == 4
    assert all(intent.matched is False for intent in judgment.intents)
    assert all("failed" in intent.rationale for intent in judgment.intents)


def test_one_intent_raising_does_not_kill_the_rest() -> None:
    # DEAD_DOOR query raises; DUPLICATE_RISK still fires -> FLAG_DUPLICATE.
    def runner(intent: str, query: str) -> MemoryResult:
        if intent == INTENT_DEAD_DOOR:
            raise RuntimeError("dead-door intent blew up")
        if intent == INTENT_DUPLICATE_RISK:
            return _result(_evidence("dupcap00", "already submitted duplicate"))
        return EMPTY

    judgment = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)

    assert judgment.action == ACTION_FLAG_DUPLICATE
    dead = next(i for i in judgment.intents if i.intent == INTENT_DEAD_DOOR)
    assert dead.matched is False and "failed" in dead.rationale


# --------------------------------------------------------------------------- #
# 5. Query builders are exposed and well-formed
# --------------------------------------------------------------------------- #


def test_query_builders_embed_signature_and_markers() -> None:
    dd = dead_door_query(TARGET, SUBJECT, KIND)
    assert SIG in dd and "dead-door" in dd and "reopen_if" in dd

    pw = prior_win_query(TARGET, SUBJECT, KIND)
    assert KIND in pw and "paid" in pw and "control-plane" in pw

    ex = historical_exploit_query(TARGET, SUBJECT, KIND)
    assert KIND in ex and SUBJECT in ex and "exploit" in ex and "timelock" in ex

    du = duplicate_risk_query(TARGET, SUBJECT, KIND)
    assert TARGET in du and SUBJECT in du and KIND in du and "duplicate" in du


def test_finding_context_is_appended_to_queries() -> None:
    finding = "admin drifted from 0x1111 to 0x9999 critical"
    dd = dead_door_query(TARGET, SUBJECT, KIND, finding)
    assert "0x9999" in dd


def test_finding_context_reaches_the_runner() -> None:
    runner = scripted_runner({})
    judge_lane(
        TARGET, SUBJECT, KIND, FakeClient(),
        finding="threshold dropped from 5 to 1", intent_query_fn=runner,
    )
    # Every intent query carried the finding context.
    assert all("threshold dropped" in query for _intent, query in runner.calls)  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# 6. Public-corpus (Solodit) fold-in via historical_recall_fn
# --------------------------------------------------------------------------- #


def _solodit_evidence(memory_id: str, preview: str, trust: float = 0.92) -> MemoryEvidence:
    # Trust already encodes Solodit quality x rarity (done in the connector layer).
    return MemoryEvidence(
        memory_id=memory_id,
        trust=trust,
        date="2023-03-01",
        preview=preview,
        role="historical",
        source="solodit",
    )


def test_historical_recall_fn_default_none_is_a_noop() -> None:
    # No recall fn -> identical behaviour to before: only Vestige evidence counts.
    runner = scripted_runner(
        {INTENT_HISTORICAL_EXPLOIT: _result(_evidence("explo000", "post-mortem: unprotected upgrade authority drain"))}
    )
    baseline = judge_lane(TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner)

    runner2 = scripted_runner(
        {INTENT_HISTORICAL_EXPLOIT: _result(_evidence("explo000", "post-mortem: unprotected upgrade authority drain"))}
    )
    with_none = judge_lane(
        TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner2,
        historical_recall_fn=None,
    )

    assert with_none.action == baseline.action == ACTION_ARM_TEMPLATE
    assert with_none.evidence_refs == baseline.evidence_refs == ("explo000",)


def test_historical_recall_fn_adds_refs_to_historical_exploit() -> None:
    # Vestige has no exploit recall; an injected Solodit recall fires the intent.
    runner = scripted_runner({})  # every Vestige intent returns EMPTY

    def recall(intent: str, query: str) -> tuple[MemoryEvidence, ...]:
        if intent == INTENT_HISTORICAL_EXPLOIT:
            return (_solodit_evidence("solex001", "exploit: proxy admin takeover drained vault"),)
        return ()

    judgment = judge_lane(
        TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner,
        historical_recall_fn=recall,
    )

    assert judgment.action == ACTION_ARM_TEMPLATE
    assert "solex001" in judgment.evidence_refs
    fired = next(i for i in judgment.fired_intents if i.intent == INTENT_HISTORICAL_EXPLOIT)
    assert fired.top_trust == pytest.approx(0.92)
    assert "solodit" in fired.rationale


def test_historical_recall_fn_merges_with_vestige_refs() -> None:
    # Vestige already fired the intent; Solodit recall is folded in additively.
    runner = scripted_runner(
        {INTENT_HISTORICAL_EXPLOIT: _result(_evidence("explo000", "post-mortem: oracle manipulation bridge drain"))}
    )

    def recall(intent: str, query: str) -> tuple[MemoryEvidence, ...]:
        if intent == INTENT_HISTORICAL_EXPLOIT:
            return (_solodit_evidence("solex001", "exploit: admin takeover drained funds"),)
        return ()

    judgment = judge_lane(
        TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner,
        historical_recall_fn=recall,
    )

    assert judgment.action == ACTION_ARM_TEMPLATE
    # Union of Vestige + Solodit refs, Vestige first.
    assert judgment.evidence_refs == ("explo000", "solex001")


def test_historical_recall_fn_below_trust_floor_does_not_fire() -> None:
    # A weak (low quality x rarity) Solodit hit cannot fire an intent on its own.
    runner = scripted_runner({})

    def recall(intent: str, query: str) -> tuple[MemoryEvidence, ...]:
        if intent == INTENT_HISTORICAL_EXPLOIT:
            return (_solodit_evidence("weaksol0", "exploit drain", trust=0.20),)
        return ()

    judgment = judge_lane(
        TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner,
        historical_recall_fn=recall,
    )
    assert judgment.action == ACTION_PROCEED
    assert judgment.fired_intents == ()


def test_historical_recall_fn_not_folded_into_dead_door_or_prior_win() -> None:
    # Recall is consulted ONLY for HISTORICAL_EXPLOIT / DUPLICATE_RISK. Even a
    # high-trust marker-matching hit returned for other intents is ignored.
    runner = scripted_runner({})
    asked: list[str] = []

    def recall(intent: str, query: str) -> tuple[MemoryEvidence, ...]:
        asked.append(intent)
        # Return something that WOULD match dead-door/prior-win markers if folded.
        return (_solodit_evidence("solany0", "dead-door closed lane PAID confirmed critical"),)

    judgment = judge_lane(
        TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner,
        historical_recall_fn=recall,
    )

    # Only the two fold-eligible intents ever consult the recall fn.
    assert set(asked) == {INTENT_HISTORICAL_EXPLOIT, INTENT_DUPLICATE_RISK}
    # And neither dead-door (skip) nor prior-win fired from public corpus.
    assert judgment.action != ACTION_SKIP
    assert all(i.intent not in (INTENT_DEAD_DOOR, INTENT_PRIOR_WIN) for i in judgment.fired_intents)


def test_historical_recall_fn_raising_is_not_fatal() -> None:
    # A blowing-up recall fn degrades to Vestige-only; never raises.
    runner = scripted_runner(
        {INTENT_HISTORICAL_EXPLOIT: _result(_evidence("explo000", "post-mortem: unprotected upgrade authority drain"))}
    )

    def recall(intent: str, query: str):
        raise RuntimeError("solodit fetch blew up")

    judgment = judge_lane(
        TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner,
        historical_recall_fn=recall,
    )
    assert judgment.action == ACTION_ARM_TEMPLATE
    assert judgment.evidence_refs == ("explo000",)


def test_historical_recall_fn_accepts_memory_result_shape() -> None:
    # The recall fn may also return a MemoryResult (not just a bare iterable).
    runner = scripted_runner({})

    def recall(intent: str, query: str) -> MemoryResult:
        if intent == INTENT_DUPLICATE_RISK:
            return _result(_solodit_evidence("soldup0", "this exact finding already reported / duplicate disclosed"))
        return EMPTY

    judgment = judge_lane(
        TARGET, SUBJECT, KIND, FakeClient(), intent_query_fn=runner,
        historical_recall_fn=recall,
    )
    assert judgment.action == ACTION_FLAG_DUPLICATE
    assert "soldup0" in judgment.evidence_refs
