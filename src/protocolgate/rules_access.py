from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from protocolgate.report import Violation
from protocolgate.rules_support import (
    MIN_ADMIN_TIMELOCK_SECONDS,
    Manifest,
    actor_ref,
    admin_ref,
    as_list,
    contract_path,
    function_path,
    function_timelock_delay,
    is_eoa_ref,
    is_named_actor_ref,
    is_timelocked_governance_controller,
    multisig,
    role_ref,
    valid_actor_names,
)


def require_upgradeable_admin_timelock(manifest: Manifest) -> Iterable[Violation]:
    for index, contract in enumerate(manifest["contracts"]):
        if not contract.get("upgradeable"):
            continue
        admin = admin_ref(contract)
        if not is_timelocked_governance_controller(manifest, admin):
            yield Violation(
                "CG001",
                "critical",
                f"{contract.get('name', '<unnamed>')} is upgradeable but proxy/admin control is not a 24h+ timelocked governance controller",
                contract_path(index, ".proxy.admin"),
                "Set proxy.admin to a timelock whose proposer/executor is a declared multisig or governor.",
            )


def reject_proxy_admin_eoa(manifest: Manifest) -> Iterable[Violation]:
    for index, contract in enumerate(manifest["contracts"]):
        if not contract.get("upgradeable"):
            continue
        admin = admin_ref(contract)
        if is_eoa_ref(admin):
            yield Violation(
                "CG002",
                "critical",
                f"{contract.get('name', '<unnamed>')} uses an EOA as upgrade admin",
                contract_path(index, ".proxy.admin"),
                "Move upgrade authority to a timelock controlled by a declared multisig or governor.",
            )


def require_admin_functions_timelocked(manifest: Manifest) -> Iterable[Violation]:
    for contract_index, contract in enumerate(manifest["contracts"]):
        for function_index, function in enumerate(contract.get("functions", [])):
            if not function.get("admin_only"):
                continue
            if function_timelock_delay(manifest, contract, function) < MIN_ADMIN_TIMELOCK_SECONDS:
                yield Violation(
                    "CG003",
                    "high",
                    f"{contract.get('name', '<unnamed>')}.{function.get('name', '<unnamed>')} is admin-only without a 24h+ timelock",
                    function_path(contract_index, function_index, ".timelock"),
                    "Route privileged calls through the protocol timelock.",
                )


def require_unpause_timelock(manifest: Manifest) -> Iterable[Violation]:
    for contract_index, contract in enumerate(manifest["contracts"]):
        for function_index, function in enumerate(contract.get("functions", [])):
            if str(function.get("name", "")).lower() != "unpause":
                continue
            if function_timelock_delay(manifest, contract, function) < MIN_ADMIN_TIMELOCK_SECONDS:
                yield Violation(
                    "CG011",
                    "high",
                    f"{contract.get('name', '<unnamed>')}.unpause can execute without a 24h+ timelock",
                    function_path(contract_index, function_index, ".timelock"),
                    "Allow emergency pause immediately, but require timelock governance for unpause.",
                )


def require_upgrade_safety(manifest: Manifest) -> Iterable[Violation]:
    for index, contract in enumerate(manifest["contracts"]):
        if not contract.get("upgradeable"):
            continue
        safety = contract.get("upgrade_safety", {})
        if not safety.get("storage_layout_check"):
            yield Violation(
                "CG013",
                "high",
                f"{contract.get('name', '<unnamed>')} does not prove storage layout upgrade checks are enabled",
                contract_path(index, ".upgrade_safety.storage_layout_check"),
                "Enable storage layout diff checks in CI before upgrade execution.",
            )
        if not safety.get("initializer_locked"):
            yield Violation(
                "CG014",
                "high",
                f"{contract.get('name', '<unnamed>')} does not declare locked initializers",
                contract_path(index, ".upgrade_safety.initializer_locked"),
                "Lock implementation initializers and verify initialization state in deployment scripts.",
            )


def require_deployment_chain_guardrails(manifest: Manifest) -> Iterable[Violation]:
    deployment = manifest.get("deployment", {})
    if deployment.get("environment") == "production" and not deployment.get("chain_id"):
        yield Violation(
            "CG017",
            "medium",
            "production deployment does not pin chain_id",
            "deployment.chain_id",
            "Pin chain_id in deployment scripts to prevent wrong-chain execution.",
        )
    if deployment.get("environment") == "production" and not deployment.get("allowed_deployers"):
        yield Violation(
            "CG018",
            "medium",
            "production deployment does not declare allowed deployers",
            "deployment.allowed_deployers",
            "Declare the expected deployer addresses or deployment signer controls.",
        )


def require_pause_authority_separation(manifest: Manifest) -> Iterable[Violation]:
    for index, contract in enumerate(manifest["contracts"]):
        pause_ref = role_ref(contract, "pauser")
        upgrade_ref = admin_ref(contract)
        if pause_ref and upgrade_ref and pause_ref == upgrade_ref:
            yield Violation(
                "CG019",
                "medium",
                f"{contract.get('name', '<unnamed>')} uses the same authority for pause and upgrade",
                contract_path(index, ".roles.pauser"),
                "Separate emergency pause authority from upgrade authority.",
            )


def require_guardian_controls(manifest: Manifest) -> Iterable[Violation]:
    for index, guardian in enumerate(manifest["guardians"]):
        powers = set(as_list(guardian.get("powers")))
        if "upgrade" in powers and not guardian.get("timelock"):
            yield Violation(
                "CG022",
                "high",
                f"guardian {guardian.get('name', index)} can upgrade without a timelock",
                f"guardians[{index}].timelock",
                "Emergency guardians may pause immediately, but upgrades must route through timelock governance.",
            )
        if "pause" in powers and not multisig(manifest, guardian.get("multisig")):
            yield Violation(
                "CG023",
                "medium",
                f"guardian {guardian.get('name', index)} pause authority is not multisig-backed",
                f"guardians[{index}].multisig",
                "Back emergency controls with a named multisig.",
            )


def require_governance_floor(manifest: Manifest) -> Iterable[Violation]:
    governance = manifest.get("governance") or {}
    if not governance:
        return
    if int(governance.get("quorum_bps") or 0) < 400:
        yield Violation(
            "CG024",
            "medium",
            "governance quorum is below 4%",
            "governance.quorum_bps",
            "Use quorum_bps >= 400 unless the project explicitly disables this rule.",
        )
    if int(governance.get("voting_period_seconds") or 0) < MIN_ADMIN_TIMELOCK_SECONDS:
        yield Violation(
            "CG025",
            "medium",
            "governance voting period is below 24 hours",
            "governance.voting_period_seconds",
            "Give tokenholders at least 24 hours to react to governance actions.",
        )


def require_defined_security_actors(manifest: Manifest) -> Iterable[Violation]:
    valid_actors = valid_actor_names(manifest)

    def check(ref: Any, path: str, subject: str) -> Iterable[Violation]:
        name = actor_ref(ref)
        if not is_named_actor_ref(name) or name in valid_actors:
            return
        yield Violation(
            "CG026",
            "high",
            f"{subject} references undefined security actor: {name}",
            path,
            "Define the actor in multisigs, governors, timelocks, or guardians, or use an explicit address.",
        )

    for index, contract in enumerate(manifest["contracts"]):
        proxy = contract.get("proxy", {})
        if isinstance(proxy, dict):
            yield from check(
                proxy.get("admin"),
                contract_path(index, ".proxy.admin"),
                f"contract {contract.get('name', index)}",
            )
        yield from check(contract.get("admin"), contract_path(index, ".admin"), f"contract {contract.get('name', index)}")

        for role, ref in contract.get("roles", {}).items():
            yield from check(
                ref,
                contract_path(index, f".roles.{role}"),
                f"contract {contract.get('name', index)} role {role}",
            )

        for function_index, function in enumerate(contract.get("functions", [])):
            subject = f"{contract.get('name', index)}.{function.get('name', function_index)}"
            yield from check(function.get("admin"), function_path(index, function_index, ".admin"), subject)
            yield from check(function.get("timelock"), function_path(index, function_index, ".timelock"), subject)

    for index, timelock in enumerate(manifest["timelocks"]):
        for field in ("admin", "proposer", "executor", "controller"):
            yield from check(
                timelock.get(field),
                f"timelocks[{index}].{field}",
                f"timelock {timelock.get('name', index)}",
            )

    for index, guardian in enumerate(manifest["guardians"]):
        yield from check(guardian.get("multisig"), f"guardians[{index}].multisig", f"guardian {guardian.get('name', index)}")
        yield from check(guardian.get("timelock"), f"guardians[{index}].timelock", f"guardian {guardian.get('name', index)}")

    for index, deployer in enumerate(as_list(manifest.get("deployment", {}).get("allowed_deployers"))):
        yield from check(deployer, f"deployment.allowed_deployers[{index}]", "deployment")
