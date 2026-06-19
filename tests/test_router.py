"""Tests for the memory-as-router budget layer (``protocolgate.router``).

No network, no I/O: every test builds a :class:`LaneJudgment` directly with the
action under test and asserts the router's pure mapping to a
:class:`BudgetDecision` — weight, expected value, est scan cost — plus the
economic ordering. The moat invariant under test: SKIP weighs 0 (the scan it
saves), PRIORITIZE is value-weighted by prior USD, and ``order_targets`` spends
scans where prior evidence says the money is.
"""

from __future__ import annotations

import pytest

from protocolgate.reasoning import (
    ACTION_ARM_TEMPLATE,
    ACTION_FLAG_DUPLICATE,
    ACTION_PRIORITIZE,
    ACTION_PROCEED,
    ACTION_SKIP,
    LaneJudgment,
)
from protocolgate.router import (
    PRIORITIZE_USD_SCALE,
    ROUTE_ARM,
    ROUTE_FLAG,
    ROUTE_PRIORITIZE,
    ROUTE_PROCEED,
    ROUTE_SKIP,
    WEIGHT_ARM,
    WEIGHT_FLAG,
    WEIGHT_PRIORITIZE_BASE,
    WEIGHT_PROCEED,
    WEIGHT_SKIP,
    BudgetDecision,
    order_targets,
    route,
)


# --------------------------------------------------------------------------- #
# Builders (no network)
# --------------------------------------------------------------------------- #


def _judgment(
    action: str,
    *,
    signature: str = "Acme:Vault:proxy_admin_drift",
    refs: tuple[str, ...] = ("mem-aaaa", "mem-bbbb"),
    delta: float = 0.0,
) -> LaneJudgment:
    """Build a LaneJudgment carrying a single firing intent's refs.

    We don't go through ``judge_lane`` (that would touch the reasoning stack and
    a client); the router only reads ``signature``, ``action`` and
    ``evidence_refs``, so a hand-built judgment is the right, isolated unit.
    """

    from protocolgate.reasoning import IntentResult

    intents = (
        IntentResult(
            intent="X",
            query="q",
            matched=bool(refs),
            refs=refs,
            top_trust=0.9 if refs else 0.0,
            rationale="r",
        ),
    )
    return LaneJudgment(
        signature=signature,
        action=action,
        confidence_delta=delta,
        intents=intents,
        summary=f"{signature}: {action} summary",
        available=True,
    )


# --------------------------------------------------------------------------- #
# Per-action weight / EV mapping
# --------------------------------------------------------------------------- #


def test_skip_weighs_zero_the_cost_saving_lever():
    decision = route(_judgment(ACTION_SKIP), prior_usd_impact=10_000.0)
    assert decision.action == ROUTE_SKIP
    assert decision.weight == WEIGHT_SKIP == 0.0
    # The whole point: a skip costs no scan and yields no spend, regardless of
    # how much a *different* lane paid.
    assert decision.est_scan_cost == 0.0
    assert decision.expected_value == 0.0
    assert decision.is_skip is True
    assert decision.should_scan is False
    assert decision.scans_spent == 0
    assert decision.scans_skipped == 1


def test_flag_duplicate_near_zero_weight():
    decision = route(_judgment(ACTION_FLAG_DUPLICATE), prior_usd_impact=10_000.0)
    assert decision.action == ROUTE_FLAG
    assert decision.weight == WEIGHT_FLAG
    assert 0.0 < decision.weight < 0.2  # near zero, but not a hard dead-door
    assert decision.expected_value == pytest.approx(WEIGHT_FLAG * 10_000.0)


def test_proceed_neutral_baseline_weight_one():
    decision = route(_judgment(ACTION_PROCEED), prior_usd_impact=5_000.0)
    assert decision.action == ROUTE_PROCEED
    assert decision.weight == WEIGHT_PROCEED == 1.0
    assert decision.est_scan_cost == pytest.approx(1.0)  # base_scan_cost default
    assert decision.expected_value == pytest.approx(5_000.0)


def test_arm_template_high_weight():
    decision = route(_judgment(ACTION_ARM_TEMPLATE), prior_usd_impact=0.0)
    assert decision.action == ROUTE_ARM
    assert decision.weight == WEIGHT_ARM
    assert decision.weight > WEIGHT_PROCEED  # armed exploit outranks neutral
    # No prior USD on an arm-by-topology lane -> EV is 0 but weight is still high
    # so it still beats a neutral PROCEED on the weight tiebreak.
    assert decision.expected_value == 0.0


def test_prioritize_weight_scales_with_prior_usd():
    low = route(_judgment(ACTION_PRIORITIZE), prior_usd_impact=1_000.0)
    high = route(_judgment(ACTION_PRIORITIZE), prior_usd_impact=50_000.0)
    assert low.action == high.action == ROUTE_PRIORITIZE
    # Base + USD-scaled bonus; bigger prior win => bigger weight.
    assert low.weight == pytest.approx(
        WEIGHT_PRIORITIZE_BASE + 1_000.0 * PRIORITIZE_USD_SCALE
    )
    assert high.weight == pytest.approx(
        WEIGHT_PRIORITIZE_BASE + 50_000.0 * PRIORITIZE_USD_SCALE
    )
    assert high.weight > low.weight
    # EV is weight * prior_usd, so the high-paying lane dominates economically.
    assert high.expected_value > low.expected_value
    assert high.expected_value == pytest.approx(high.weight * 50_000.0)


def test_prioritize_with_no_prior_usd_still_at_least_base():
    decision = route(_judgment(ACTION_PRIORITIZE), prior_usd_impact=0.0)
    assert decision.weight == pytest.approx(WEIGHT_PRIORITIZE_BASE)
    assert decision.weight > WEIGHT_PROCEED  # a known prior win beats neutral
    assert decision.expected_value == 0.0


def test_negative_prior_usd_cannot_shrink_prioritize_below_base():
    # Defensive: a bad/negative prior impact must not drag a known-win lane
    # below the neutral baseline.
    decision = route(_judgment(ACTION_PRIORITIZE), prior_usd_impact=-9_999.0)
    assert decision.weight == pytest.approx(WEIGHT_PRIORITIZE_BASE)
    assert decision.expected_value == 0.0


def test_unknown_action_degrades_to_proceed():
    decision = route(_judgment("WAT_NOT_AN_ACTION"), prior_usd_impact=100.0)
    assert decision.action == ROUTE_PROCEED
    assert decision.weight == WEIGHT_PROCEED


# --------------------------------------------------------------------------- #
# est_scan_cost / base_scan_cost
# --------------------------------------------------------------------------- #


def test_est_scan_cost_scales_with_base_scan_cost():
    decision = route(_judgment(ACTION_PROCEED), base_scan_cost=4.0)
    assert decision.est_scan_cost == pytest.approx(4.0)  # weight 1 * base 4


def test_skip_costs_nothing_regardless_of_base_scan_cost():
    decision = route(_judgment(ACTION_SKIP), base_scan_cost=1_000.0)
    assert decision.est_scan_cost == 0.0
    assert decision.scans_spent == 0


def test_negative_base_scan_cost_cannot_create_negative_budget():
    decision = route(_judgment(ACTION_PROCEED), base_scan_cost=-7.0)
    assert decision.est_scan_cost == 0.0
    assert decision.should_scan is True


# --------------------------------------------------------------------------- #
# Carry-through: signature + evidence refs
# --------------------------------------------------------------------------- #


def test_decision_carries_signature_and_evidence_refs():
    j = _judgment(ACTION_ARM_TEMPLATE, signature="P:S:k", refs=("r1", "r2"))
    decision = route(j)
    assert decision.signature == "P:S:k"
    assert decision.evidence == ("r1", "r2")
    assert decision.rationale == j.summary


# --------------------------------------------------------------------------- #
# Ordering: where to spend scans first
# --------------------------------------------------------------------------- #


def test_order_targets_by_expected_value_desc():
    big_win = route(_judgment(ACTION_PRIORITIZE, signature="A:1:k"), prior_usd_impact=50_000.0)
    small_win = route(_judgment(ACTION_PRIORITIZE, signature="A:2:k"), prior_usd_impact=2_000.0)
    neutral = route(_judgment(ACTION_PROCEED, signature="A:3:k"), prior_usd_impact=100.0)
    skip = route(_judgment(ACTION_SKIP, signature="A:4:k"), prior_usd_impact=99_999.0)

    ordered = order_targets([neutral, skip, small_win, big_win])

    assert [d.signature for d in ordered] == ["A:1:k", "A:2:k", "A:3:k", "A:4:k"]
    # The highest prior-win lane is first; the skip is dead last despite a huge
    # (irrelevant) prior_usd_impact, because its weight is 0 -> EV 0.
    assert ordered[0] is big_win
    assert ordered[-1] is skip


def test_order_targets_arm_beats_neutral_on_weight_tiebreak_at_zero_ev():
    # Both have zero prior USD => EV 0; the armed lane should still come first
    # because its weight is higher.
    arm = route(_judgment(ACTION_ARM_TEMPLATE, signature="A:arm:k"), prior_usd_impact=0.0)
    neutral = route(_judgment(ACTION_PROCEED, signature="A:proc:k"), prior_usd_impact=0.0)
    ordered = order_targets([neutral, arm])
    assert ordered[0] is arm
    assert ordered[1] is neutral


def test_order_targets_keeps_dead_doors_after_zero_ev_scan_candidates():
    flagged = route(_judgment(ACTION_FLAG_DUPLICATE, signature="A:flag:k"))
    skip = route(_judgment(ACTION_SKIP, signature="A:skip:k"))

    ordered = order_targets([skip, flagged])

    assert ordered[0] is flagged
    assert ordered[1] is skip


def test_order_targets_is_pure_and_deterministic():
    decisions = [
        route(_judgment(ACTION_PROCEED, signature=f"A:{i}:k"), prior_usd_impact=float(i))
        for i in range(5)
    ]
    original = list(decisions)
    out1 = order_targets(decisions)
    out2 = order_targets(decisions)
    assert out1 == out2  # deterministic
    assert decisions == original  # input not mutated
    assert isinstance(out1, tuple)


def test_order_targets_empty_is_empty_tuple():
    assert order_targets([]) == ()


# --------------------------------------------------------------------------- #
# Moat economics: skipped scans are the saving made visible
# --------------------------------------------------------------------------- #


def test_scans_spent_aggregates_into_a_saving():
    decisions = [
        route(_judgment(ACTION_SKIP, signature="A:1:k")),
        route(_judgment(ACTION_SKIP, signature="A:2:k")),
        route(_judgment(ACTION_PRIORITIZE, signature="A:3:k"), prior_usd_impact=10_000.0),
        route(_judgment(ACTION_PROCEED, signature="A:4:k")),
    ]
    scans_spent = sum(d.scans_spent for d in decisions)
    scans_skipped = sum(1 for d in decisions if d.is_skip)
    assert scans_spent == 2
    assert scans_skipped == 2
