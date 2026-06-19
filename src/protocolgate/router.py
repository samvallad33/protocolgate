"""Memory-as-router budget decisions.

The reasoning layer answers "what should happen next?" for a lane. This module
turns that judgment into the small economic object the factory can honor before
spending a fork/PoC scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from protocolgate.reasoning import (
    ACTION_ARM_TEMPLATE,
    ACTION_FLAG_DUPLICATE,
    ACTION_PRIORITIZE,
    ACTION_PROCEED,
    ACTION_SKIP,
    LaneJudgment,
)

ROUTE_SKIP = "skip"
ROUTE_PRIORITIZE = "prioritize"
ROUTE_ARM = "arm"
ROUTE_FLAG = "flag"
ROUTE_PROCEED = "proceed"

_ACTION_TO_ROUTE = {
    ACTION_SKIP: ROUTE_SKIP,
    ACTION_PRIORITIZE: ROUTE_PRIORITIZE,
    ACTION_ARM_TEMPLATE: ROUTE_ARM,
    ACTION_FLAG_DUPLICATE: ROUTE_FLAG,
    ACTION_PROCEED: ROUTE_PROCEED,
}

WEIGHT_SKIP = 0.0
WEIGHT_FLAG = 0.05
WEIGHT_PROCEED = 1.0
WEIGHT_ARM = 2.0
WEIGHT_PRIORITIZE_BASE = 1.5
PRIORITIZE_USD_SCALE = 0.001

__all__ = [
    "BudgetDecision",
    "PRIORITIZE_USD_SCALE",
    "ROUTE_ARM",
    "ROUTE_FLAG",
    "ROUTE_PRIORITIZE",
    "ROUTE_PROCEED",
    "ROUTE_SKIP",
    "WEIGHT_ARM",
    "WEIGHT_FLAG",
    "WEIGHT_PRIORITIZE_BASE",
    "WEIGHT_PROCEED",
    "WEIGHT_SKIP",
    "order_targets",
    "route",
]


@dataclass(frozen=True)
class BudgetDecision:
    signature: str
    action: str
    weight: float
    evidence: tuple[str, ...]
    rationale: str
    est_scan_cost: float
    expected_value: float

    @property
    def is_skip(self) -> bool:
        return self.action == ROUTE_SKIP or self.weight <= 0.0

    @property
    def should_scan(self) -> bool:
        return not self.is_skip

    @property
    def scans_spent(self) -> int:
        return 0 if self.is_skip else 1

    @property
    def scans_skipped(self) -> int:
        return 1 if self.is_skip else 0


def _non_negative(value: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, number)


def _weight_for(route_action: str, *, prior_usd_impact: float) -> float:
    if route_action == ROUTE_SKIP:
        return WEIGHT_SKIP
    if route_action == ROUTE_FLAG:
        return WEIGHT_FLAG
    if route_action == ROUTE_ARM:
        return WEIGHT_ARM
    if route_action == ROUTE_PRIORITIZE:
        bonus = max(prior_usd_impact, 0.0) * PRIORITIZE_USD_SCALE
        return WEIGHT_PRIORITIZE_BASE + bonus
    return WEIGHT_PROCEED


def route(
    judgment: LaneJudgment,
    *,
    prior_usd_impact: float = 0.0,
    base_scan_cost: float = 1.0,
) -> BudgetDecision:
    route_action = _ACTION_TO_ROUTE.get(judgment.action, ROUTE_PROCEED)
    prior_value = _non_negative(prior_usd_impact)
    scan_cost = _non_negative(base_scan_cost)
    weight = _weight_for(route_action, prior_usd_impact=prior_value)
    return BudgetDecision(
        signature=judgment.signature,
        action=route_action,
        weight=weight,
        evidence=judgment.evidence_refs,
        rationale=judgment.summary,
        est_scan_cost=weight * scan_cost,
        expected_value=0.0 if route_action == ROUTE_SKIP else weight * prior_value,
    )


def order_targets(decisions: Iterable[BudgetDecision]) -> tuple[BudgetDecision, ...]:
    return tuple(
        sorted(
            decisions,
            key=lambda d: (d.is_skip, -d.expected_value, -d.weight, d.signature),
        )
    )
