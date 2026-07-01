from __future__ import annotations

from protocolgate.report import Violation
from protocolgate.rules_access import (
    reject_proxy_admin_eoa,
    require_admin_functions_timelocked,
    require_defined_security_actors,
    require_deployment_chain_guardrails,
    require_governance_floor,
    require_guardian_controls,
    require_pause_authority_separation,
    require_unpause_timelock,
    require_upgrade_safety,
    require_upgradeable_admin_timelock,
)
from protocolgate.rules_protocol import (
    require_bridge_rate_limits,
    require_decimal_precision_alignment,
    require_external_call_ordering,
    require_fee_change_bounds,
    require_multisig_thresholds,
    require_oracle_fail_closed,
    require_redemption_controls,
    require_supply_controls,
    require_treasury_splits_sum,
)
from protocolgate.rules_proposal_intent import (
    require_admin_monitor_coverage,
    require_privileged_selector_allowlist,
    require_proposal_calldata_hash_binding,
    require_proposal_expiry,
    require_proposal_metadata,
    require_safe_module_allowlist,
    require_transaction_simulation,
)
from protocolgate.rules_support import Manifest, Rule, RuleFn


def evaluate_manifest(manifest: Manifest) -> list[Violation]:
    disabled = set(manifest.get("policy", {}).get("disable_rules", []))
    findings = [
        finding
        for evaluator in EVALUATORS
        for finding in evaluator(manifest)
        if finding.rule_id not in disabled
    ]

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(
        findings,
        key=lambda item: (severity_rank.get(item.severity.lower(), 99), item.rule_id, item.path),
    )


EVALUATORS: tuple[RuleFn, ...] = (
    require_upgradeable_admin_timelock,
    reject_proxy_admin_eoa,
    require_admin_functions_timelocked,
    require_redemption_controls,
    require_decimal_precision_alignment,
    require_bridge_rate_limits,
    require_oracle_fail_closed,
    require_treasury_splits_sum,
    require_multisig_thresholds,
    require_unpause_timelock,
    require_external_call_ordering,
    require_upgrade_safety,
    require_supply_controls,
    require_deployment_chain_guardrails,
    require_pause_authority_separation,
    require_fee_change_bounds,
    require_guardian_controls,
    require_governance_floor,
    require_defined_security_actors,
    require_proposal_metadata,
    require_proposal_expiry,
    require_proposal_calldata_hash_binding,
    require_privileged_selector_allowlist,
    require_safe_module_allowlist,
    require_transaction_simulation,
    require_admin_monitor_coverage,
)

RULES: tuple[Rule, ...] = (
    Rule("CG001", "Upgradeable admin must be timelocked governance controller", "critical", require_upgradeable_admin_timelock),
    Rule("CG002", "Proxy admin must not be EOA", "critical", reject_proxy_admin_eoa),
    Rule("CG003", "Admin functions must be timelocked", "high", require_admin_functions_timelocked),
    Rule("CG004", "Redemptions require cooldown, circuit breaker, and pause", "high", require_redemption_controls),
    Rule("CG005", "Integration decimals must align", "high", require_decimal_precision_alignment),
    Rule("CG006", "Bridges require per-block rate limits", "high", require_bridge_rate_limits),
    Rule("CG007", "Oracles need bounded staleness", "medium", require_oracle_fail_closed),
    Rule("CG008", "Oracles must fail closed", "medium", require_oracle_fail_closed),
    Rule("CG009", "Treasury splits must be complete and sum to 10000 bps", "critical", require_treasury_splits_sum),
    Rule("CG010", "Multisig threshold floor", "high", require_multisig_thresholds),
    Rule("CG011", "Unpause requires timelock", "high", require_unpause_timelock),
    Rule("CG012", "External calls require CEI and nonReentrant", "high", require_external_call_ordering),
    Rule("CG013", "Storage layout checks required", "high", require_upgrade_safety),
    Rule("CG014", "Initializers must be locked", "high", require_upgrade_safety),
    Rule("CG015", "Supply controls require caps", "medium", require_supply_controls),
    Rule("CG016", "Supply controls require timelock", "high", require_supply_controls),
    Rule("CG017", "Production deployments must pin chain_id", "medium", require_deployment_chain_guardrails),
    Rule("CG018", "Production deployments must declare deployers", "medium", require_deployment_chain_guardrails),
    Rule("CG019", "Pause and upgrade authorities must be separated", "medium", require_pause_authority_separation),
    Rule("CG020", "Fee changes require max bounds", "medium", require_fee_change_bounds),
    Rule("CG021", "Fee changes require timelock", "medium", require_fee_change_bounds),
    Rule("CG022", "Upgrade guardians require timelock", "high", require_guardian_controls),
    Rule("CG023", "Pause guardians require multisig", "medium", require_guardian_controls),
    Rule("CG024", "Governance quorum floor", "medium", require_governance_floor),
    Rule("CG025", "Governance voting period floor", "medium", require_governance_floor),
    Rule("CG026", "Security actor references must resolve", "high", require_defined_security_actors),
    Rule("CG032", "Privileged proposals require signer-readable metadata", "high", require_proposal_metadata),
    Rule("CG033", "Privileged proposals must have bounded validity", "critical", require_proposal_expiry),
    Rule("CG034", "Executed calldata must match reviewed intent", "critical", require_proposal_calldata_hash_binding),
    Rule("CG035", "Privileged selectors must be allowlisted", "high", require_privileged_selector_allowlist),
    Rule("CG036", "Safe/Squads modules must be allowlisted", "high", require_safe_module_allowlist),
    Rule("CG037", "Privileged proposals require transaction simulation", "high", require_transaction_simulation),
    Rule("CG038", "High-risk admin proposals require monitor coverage", "medium", require_admin_monitor_coverage),
)
