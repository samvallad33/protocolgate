from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from protocolgate.report import Violation
from protocolgate.rules_support import Manifest


def hunt_safety_control_scope_mismatch(manifest: Manifest) -> Iterable[Violation]:
    """Find local safety controls that claim to protect broader predicates.

    This is the Aave V3.7 lesson as a reusable invariant:
    if a protected predicate is account-global but the guard is reserve-local,
    callers may be able to route through an unguarded local component.
    """

    predicates = {
        item.get("name"): item
        for item in manifest.get("predicates", [])
        if isinstance(item.get("name"), str)
    }

    for control_index, control in enumerate(manifest.get("safety_controls", [])):
        control_scope = _scope_kind(control.get("scope"))
        protects = control.get("protects", [])
        if not isinstance(protects, list):
            continue

        for protect_index, protected in enumerate(protects):
            if not isinstance(protected, dict):
                continue
            if _scope_mismatch_accepted(control, protected):
                continue

            predicate = predicates.get(protected.get("predicate"))
            predicate_scope = _scope_kind(protected.get("expected_scope")) or _scope_kind(
                predicate.get("scope") if predicate else None
            )
            if not control_scope or not predicate_scope or control_scope == predicate_scope:
                continue

            bypass_inputs = _bypass_inputs(control, protected)
            loss_surface = str(
                protected.get("loss_surface") or control.get("loss_surface") or ""
            ).lower()
            severity = "critical" if loss_surface in {"user_principal", "protocol_solvency"} else "high"
            predicate_name = protected.get("predicate", "<unknown predicate>")
            control_name = control.get("name", f"safety_controls[{control_index}]")
            action = protected.get("action", "<unknown action>")
            bypass_note = (
                f"; selectable bypass inputs: {', '.join(bypass_inputs)}"
                if bypass_inputs
                else ""
            )

            yield Violation(
                "CG039",
                severity,
                (
                    f"{control_name} is {control_scope}-scoped but protects "
                    f"{predicate_scope}-scoped predicate {predicate_name} for {action}"
                    f"{bypass_note}"
                ),
                f"safety_controls[{control_index}].protects[{protect_index}]",
                (
                    "Expand the safety check to every state component that contributes "
                    "to the protected predicate, or explicitly document and test the "
                    "narrower execution scope."
                ),
            )


def _scope_kind(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("kind"), str):
        return value["kind"]
    return None


def _bypass_inputs(control: dict[str, Any], protected: dict[str, Any]) -> list[str]:
    values = protected.get("bypass_selectors", control.get("bypass_selectors", []))
    if values is None:
        return []
    if not isinstance(values, list):
        values = [values]
    return [str(item) for item in values if item]


def _scope_mismatch_accepted(control: dict[str, Any], protected: dict[str, Any]) -> bool:
    return bool(
        control.get("accepted_scope_mismatch")
        or protected.get("accepted_scope_mismatch")
        or protected.get("coverage") in {"predicate", "global", "all_components"}
    )
