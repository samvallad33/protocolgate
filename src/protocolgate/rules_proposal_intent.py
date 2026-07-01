from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from protocolgate.report import Violation
from protocolgate.rules_support import Manifest, as_list


DEFAULT_MAX_VALIDITY_SECONDS = 24 * 60 * 60
CALLDATA_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")

HIGH_PRIVILEGE_CATEGORIES = {
    "admin_transfer",
    "bridge_limit_change",
    "mint_cap_change",
    "oracle_change",
    "treasury_transfer",
    "upgrade",
    "withdrawal_limit_change",
}

DEFAULT_PRIVILEGED_SELECTORS = {
    "changeAdmin(address)",
    "grantRole(bytes32,address)",
    "mint(address,uint256)",
    "pause()",
    "revokeRole(bytes32,address)",
    "setBridgeLimit(uint256)",
    "setFeeBps(uint256)",
    "setOracle(address)",
    "setWithdrawalLimit(uint256)",
    "unpause()",
    "upgradeTo(address)",
    "upgradeToAndCall(address,bytes)",
}


def require_proposal_metadata(manifest: Manifest) -> Iterable[Violation]:
    config = _proposal_config(manifest)
    if not _has_proposal_intent(manifest) or config.get("require_metadata") is False:
        return

    for index, proposal in enumerate(_proposals(manifest)):
        if not _is_high_privilege(proposal, config):
            continue

        for field in ("target", "category", "selector", "intent"):
            if _has_text(proposal.get(field)):
                continue
            yield Violation(
                "CG032",
                "high",
                f"proposal {_proposal_id(proposal, index)} is missing {field}",
                _proposal_path(index, f".{field}"),
                "Require privileged proposals to include signer-readable metadata before approval.",
            )


def require_proposal_expiry(manifest: Manifest) -> Iterable[Violation]:
    config = _proposal_config(manifest)
    if not _has_proposal_intent(manifest):
        return

    max_validity = _positive_int(
        config.get("max_validity_seconds"),
        DEFAULT_MAX_VALIDITY_SECONDS,
    )

    for index, proposal in enumerate(_proposals(manifest)):
        if not _is_high_privilege(proposal, config):
            continue

        created_raw = proposal.get("created_at")
        expires_raw = proposal.get("expires_at")
        proposal_id = _proposal_id(proposal, index)

        if not _has_text(created_raw):
            yield Violation(
                "CG033",
                "critical",
                f"proposal {proposal_id} has no creation timestamp",
                _proposal_path(index, ".created_at"),
                "Declare when the privileged proposal was created so its validity window can be bounded.",
            )
            continue

        if not _has_text(expires_raw):
            yield Violation(
                "CG033",
                "critical",
                f"proposal {proposal_id} has no expiry",
                _proposal_path(index, ".expires_at"),
                "Set an explicit expiry so pre-signed privileged approvals cannot live forever.",
            )
            continue

        created = _parse_timestamp(created_raw)
        expires = _parse_timestamp(expires_raw)
        if not created:
            yield Violation(
                "CG033",
                "critical",
                f"proposal {proposal_id} has an invalid creation timestamp",
                _proposal_path(index, ".created_at"),
                "Use an RFC3339 timestamp such as 2026-05-04T00:00:00Z.",
            )
            continue

        if not expires:
            yield Violation(
                "CG033",
                "critical",
                f"proposal {proposal_id} has an invalid expiry timestamp",
                _proposal_path(index, ".expires_at"),
                "Use an RFC3339 timestamp such as 2026-05-04T00:00:00Z.",
            )
            continue

        validity_seconds = (expires - created).total_seconds()
        if validity_seconds <= 0:
            yield Violation(
                "CG033",
                "critical",
                f"proposal {proposal_id} expires before it can be safely reviewed",
                _proposal_path(index, ".expires_at"),
                "Set expires_at later than created_at for privileged proposal approvals.",
            )
            continue

        if validity_seconds > max_validity:
            yield Violation(
                "CG033",
                "critical",
                f"proposal {proposal_id} is valid for {int(validity_seconds)} seconds",
                _proposal_path(index, ".expires_at"),
                f"Limit privileged proposal validity to {max_validity} seconds or less.",
            )


def require_proposal_calldata_hash_binding(manifest: Manifest) -> Iterable[Violation]:
    config = _proposal_config(manifest)
    if (
        not _has_proposal_intent(manifest)
        or config.get("require_calldata_hash_match") is False
    ):
        return

    for index, proposal in enumerate(_proposals(manifest)):
        if not _is_high_privilege(proposal, config):
            continue

        reviewed = proposal.get("reviewed_calldata_hash")
        executed = proposal.get("execution_calldata_hash")
        proposal_id = _proposal_id(proposal, index)

        if not _valid_calldata_hash(reviewed):
            yield Violation(
                "CG034",
                "critical",
                f"proposal {proposal_id} has no valid reviewed calldata hash",
                _proposal_path(index, ".reviewed_calldata_hash"),
                "Bind signer review to a 32-byte calldata hash before signatures are collected.",
            )
            continue

        if not _valid_calldata_hash(executed):
            yield Violation(
                "CG034",
                "critical",
                f"proposal {proposal_id} has no valid execution calldata hash",
                _proposal_path(index, ".execution_calldata_hash"),
                "Bind execution to the exact calldata hash that signers reviewed.",
            )
            continue

        if str(reviewed).lower() != str(executed).lower():
            yield Violation(
                "CG034",
                "critical",
                f"proposal {proposal_id} execution calldata does not match reviewed intent",
                _proposal_path(index, ".execution_calldata_hash"),
                "Require the reviewed calldata hash and execution calldata hash to match before signing.",
            )


def require_privileged_selector_allowlist(manifest: Manifest) -> Iterable[Violation]:
    config = _proposal_config(manifest)
    if not _has_proposal_intent(manifest):
        return

    allowed = _allowed_selectors(config)
    for index, proposal in enumerate(_proposals(manifest)):
        if not _is_high_privilege(proposal, config):
            continue

        selector = proposal.get("selector")
        if not _has_text(selector):
            continue

        if str(selector) not in allowed:
            yield Violation(
                "CG035",
                "high",
                f"proposal {_proposal_id(proposal, index)} uses unapproved privileged selector {selector}",
                _proposal_path(index, ".selector"),
                "Allowlist selectors that can change upgrades, admins, bridges, oracles, supply, treasury, or emergency controls.",
            )


def require_safe_module_allowlist(manifest: Manifest) -> Iterable[Violation]:
    config = _proposal_config(manifest)
    if not _has_proposal_intent(manifest):
        return

    allowed = {str(item) for item in as_list(config.get("allowed_safe_modules"))}
    declared = {
        str(module.get("name"))
        for module in _safe_modules(config)
        if module.get("enabled") is not False and _has_text(module.get("name"))
    }
    for index, module in enumerate(_safe_modules(config)):
        if module.get("enabled") is False:
            continue

        name = module.get("name")
        if _has_text(name) and str(name) in allowed:
            continue

        yield Violation(
            "CG036",
            "high",
            f"Safe module {name or index} is not in the module allowlist",
            f"proposal_intent.safe_modules[{index}].name",
            "Declare and review every Safe or Squads module that can execute transactions outside normal signer flow.",
        )

    for proposal_index, proposal in enumerate(_proposals(manifest)):
        for field in ("module", "safe_module"):
            name = proposal.get(field)
            if not _has_text(name):
                continue

            module_name = str(name)
            if module_name in declared and module_name in allowed:
                continue

            reasons = []
            if module_name not in declared:
                reasons.append("undeclared")
            if module_name not in allowed:
                reasons.append("unapproved")

            yield Violation(
                "CG036",
                "high",
                f"proposal {_proposal_id(proposal, proposal_index)} uses {' and '.join(reasons)} Safe/Squads module {module_name}",
                _proposal_path(proposal_index, f".{field}"),
                "Declare and allowlist every Safe or Squads module used to execute privileged proposals.",
            )


def require_transaction_simulation(manifest: Manifest) -> Iterable[Violation]:
    config = _proposal_config(manifest)
    if not _has_proposal_intent(manifest) or config.get("require_simulation") is False:
        return

    for index, proposal in enumerate(_proposals(manifest)):
        if not _is_high_privilege(proposal, config):
            continue

        simulation = proposal.get("simulation") if isinstance(proposal.get("simulation"), dict) else {}
        if simulation.get("status") == "passed":
            continue

        yield Violation(
            "CG037",
            "high",
            f"proposal {_proposal_id(proposal, index)} has no passed transaction simulation",
            _proposal_path(index, ".simulation.status"),
            "Simulate privileged transactions before collecting signatures.",
        )


def require_admin_monitor_coverage(manifest: Manifest) -> Iterable[Violation]:
    config = _proposal_config(manifest)
    if not _has_proposal_intent(manifest):
        return

    monitored = {
        str(item).lower()
        for item in as_list(config.get("monitor_required_for"))
    }
    if not monitored:
        return

    for index, proposal in enumerate(_proposals(manifest)):
        category = str(proposal.get("category", "")).lower()
        if category not in monitored:
            continue

        monitor = proposal.get("monitor") if isinstance(proposal.get("monitor"), dict) else {}
        if monitor.get("enabled") is True:
            continue

        yield Violation(
            "CG038",
            "medium",
            f"proposal {_proposal_id(proposal, index)} has no monitor coverage",
            _proposal_path(index, ".monitor.enabled"),
            "Attach monitor coverage to admin, oracle, bridge, treasury, and supply-control proposals.",
        )


def _has_proposal_intent(manifest: Manifest) -> bool:
    return isinstance(manifest.get("proposal_intent"), dict) and bool(manifest["proposal_intent"])


def _proposal_config(manifest: Manifest) -> dict[str, Any]:
    config = manifest.get("proposal_intent", {})
    return config if isinstance(config, dict) else {}


def _proposals(manifest: Manifest) -> list[dict[str, Any]]:
    return _mapping_list(_proposal_config(manifest).get("proposals", []))


def _safe_modules(config: dict[str, Any]) -> list[dict[str, Any]]:
    return _mapping_list(config.get("safe_modules", []))


def _mapping_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in as_list(value) if isinstance(item, dict)]


def _is_high_privilege(proposal: dict[str, Any], config: dict[str, Any]) -> bool:
    category = str(proposal.get("category", "")).lower()
    selector = proposal.get("selector") if isinstance(proposal.get("selector"), str) else ""
    return (
        category in HIGH_PRIVILEGE_CATEGORIES
        or selector in DEFAULT_PRIVILEGED_SELECTORS
        or selector in _configured_selectors(config)
    )


def _allowed_selectors(config: dict[str, Any]) -> set[str]:
    configured = _configured_selectors(config)
    return configured or set(DEFAULT_PRIVILEGED_SELECTORS)


def _configured_selectors(config: dict[str, Any]) -> set[str]:
    return {str(item) for item in as_list(config.get("privileged_selectors"))}


def _proposal_path(index: int, suffix: str = "") -> str:
    return f"proposal_intent.proposals[{index}]{suffix}"


def _proposal_id(proposal: dict[str, Any], index: int) -> str:
    value = proposal.get("id")
    return str(value) if _has_text(value) else str(index)


def _has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_calldata_hash(value: Any) -> bool:
    return isinstance(value, str) and bool(CALLDATA_HASH_RE.fullmatch(value))


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _parse_timestamp(value: Any) -> datetime | None:
    if not _has_text(value):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
