from __future__ import annotations

from protocolgate.report import Violation
from protocolgate.rules_hunt import hunt_safety_control_scope_mismatch
from protocolgate.rules_support import Manifest, Rule, RuleFn


def hunt_manifest(manifest: Manifest) -> list[Violation]:
    """Run bounty-oriented invariant-hunting checks against a manifest.

    Hunt mode is intentionally separate from validate mode. `validate` answers
    "should this topology ship?" Hunt mode answers "where are the weird doors?"
    """

    disabled = set(manifest.get("policy", {}).get("disable_rules", []))
    findings = [
        finding
        for evaluator in HUNT_EVALUATORS
        for finding in evaluator(manifest)
        if finding.rule_id not in disabled
    ]

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(
        findings,
        key=lambda item: (severity_rank.get(item.severity.lower(), 99), item.rule_id, item.path),
    )


HUNT_EVALUATORS: tuple[RuleFn, ...] = (
    hunt_safety_control_scope_mismatch,
)

HUNT_RULES: tuple[Rule, ...] = (
    Rule(
        "CG039",
        "Safety-control scope must cover protected predicate scope",
        "critical",
        hunt_safety_control_scope_mismatch,
    ),
)
