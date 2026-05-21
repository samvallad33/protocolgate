from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from protocolgate.report import Violation


Manifest = dict[str, Any]
RuleFn = Callable[[Manifest], Iterable[Violation]]

MIN_ADMIN_TIMELOCK_SECONDS = 24 * 60 * 60
MAX_ORACLE_STALENESS_SECONDS = 60 * 60
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    evaluate: RuleFn


def named(items: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    return next((item for item in items if item.get("name") == name), None)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def contract_path(index: int, suffix: str = "") -> str:
    return f"contracts[{index}]{suffix}"


def function_path(contract_index: int, function_index: int, suffix: str = "") -> str:
    return f"contracts[{contract_index}].functions[{function_index}]{suffix}"


def is_eoa_ref(ref: Any) -> bool:
    if not ref:
        return False
    if isinstance(ref, dict):
        return ref.get("kind") == "eoa" or ref.get("type") == "eoa"
    if isinstance(ref, str):
        return ref.startswith("0x") and len(ref) == 42
    return False


def is_zero_address(ref: Any) -> bool:
    return isinstance(ref, str) and ref.lower() == ZERO_ADDRESS


def actor_ref(ref: Any) -> str | None:
    if isinstance(ref, dict):
        value = ref.get("name") or ref.get("ref")
        return value if isinstance(value, str) else None
    return ref if isinstance(ref, str) else None


def is_named_actor_ref(ref: Any) -> bool:
    name = actor_ref(ref)
    return bool(name) and not is_eoa_ref(name)


def valid_actor_names(manifest: Manifest) -> set[str]:
    actor_names: set[str] = set()
    for key in ("multisigs", "governors", "timelocks", "guardians"):
        actor_names.update(
            item["name"]
            for item in manifest[key]
            if isinstance(item.get("name"), str)
        )
    return actor_names


def multisig(manifest: Manifest, ref: Any) -> dict[str, Any] | None:
    name = actor_ref(ref)
    if not isinstance(name, str):
        return None
    return named(manifest["multisigs"], name)


def governor(manifest: Manifest, ref: Any) -> dict[str, Any] | None:
    name = actor_ref(ref)
    if not isinstance(name, str):
        return None
    return named(manifest["governors"], name)


def timelock(manifest: Manifest, ref: Any) -> dict[str, Any] | None:
    name = actor_ref(ref)
    if not isinstance(name, str):
        return None
    return named(manifest["timelocks"], name)


def timelock_delay(manifest: Manifest, ref: Any) -> int:
    item = timelock(manifest, ref)
    if not item:
        return 0
    return int(item.get("delay_seconds") or 0)


def is_timelocked_governance_controller(manifest: Manifest, ref: Any) -> bool:
    item = timelock(manifest, ref)
    if not item:
        return False
    if timelock_delay(manifest, ref) < MIN_ADMIN_TIMELOCK_SECONDS:
        return False

    controllers = [
        item.get("admin"),
        item.get("proposer"),
        item.get("executor"),
        item.get("controller"),
    ]
    return any(
        multisig(manifest, controller) or governor(manifest, controller)
        for controller in controllers
        if controller
    )


def role_ref(contract: dict[str, Any], role: str) -> Any:
    roles = contract.get("roles", {})
    if not isinstance(roles, dict):
        return None
    return roles.get(role)


def function_controls(function: dict[str, Any]) -> set[str]:
    controls = set(str(item) for item in as_list(function.get("controls")))
    controls.update(str(item) for item in as_list(function.get("modifiers")))
    if function.get("cooldown_seconds", 0):
        controls.add("cooldown")
    if function.get("circuit_breaker"):
        controls.add("circuit_breaker")
    if function.get("pausable"):
        controls.add("pause")
    if function.get("non_reentrant"):
        controls.add("nonReentrant")
    return controls


def is_redemption_function(function: dict[str, Any]) -> bool:
    name = str(function.get("name", "")).lower()
    category = str(function.get("category", "")).lower()
    return category == "redemption" or any(term in name for term in ("redeem", "withdraw", "exit"))


def is_privileged_supply_function(function: dict[str, Any]) -> bool:
    name = str(function.get("name", "")).lower()
    category = str(function.get("category", "")).lower()
    return category == "supply" or any(term in name for term in ("mint", "burn"))


def function_timelock_delay(
    manifest: Manifest,
    contract: dict[str, Any],
    function: dict[str, Any],
) -> int:
    refs = [
        function.get("timelock"),
        function.get("admin"),
        function.get("role"),
        role_ref(contract, "admin"),
        role_ref(contract, "owner"),
    ]
    return max((timelock_delay(manifest, ref) for ref in refs), default=0)


def admin_ref(contract: dict[str, Any]) -> Any:
    proxy = contract.get("proxy", {})
    if isinstance(proxy, dict) and proxy.get("admin") is not None:
        return proxy.get("admin")
    return contract.get("admin") or role_ref(contract, "admin") or role_ref(contract, "owner")
