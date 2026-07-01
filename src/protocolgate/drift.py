from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DriftFinding:
    severity: str
    subject: str
    message: str
    expected: Any
    actual: Any


def compare_snapshot(manifest: dict[str, Any], snapshot: dict[str, Any]) -> list[DriftFinding]:
    """Compare a manifest against a collected chain-state snapshot.

    The first implementation accepts a JSON snapshot so the drift detector can be
    tested without binding the core policy gate to a specific RPC provider.
    """

    findings: list[DriftFinding] = []
    live_contracts = {
        contract.get("name"): contract
        for contract in snapshot.get("contracts", [])
        if contract.get("name")
    }

    for contract in manifest.get("contracts", []):
        name = contract.get("name")
        if not name:
            continue
        if name not in live_contracts:
            findings.append(
                DriftFinding(
                    severity="medium",
                    subject=name,
                    message="contract missing from live snapshot",
                    expected="present",
                    actual="missing",
                )
            )
            continue

        live = live_contracts[name]
        expected_admin = (contract.get("proxy") or {}).get("admin")
        actual_admin = (live.get("proxy") or {}).get("admin")
        if expected_admin and not actual_admin:
            findings.append(
                DriftFinding(
                    severity="high",
                    subject=name,
                    message="proxy admin missing from live snapshot",
                    expected=expected_admin,
                    actual=None,
                )
            )
        elif expected_admin and actual_admin != expected_admin:
            findings.append(
                DriftFinding(
                    severity="critical",
                    subject=name,
                    message="proxy admin drifted from manifest",
                    expected=expected_admin,
                    actual=actual_admin,
                )
            )

    live_multisigs = {
        multisig.get("name"): multisig
        for multisig in snapshot.get("multisigs", [])
        if multisig.get("name")
    }
    for multisig in manifest.get("multisigs", []):
        name = multisig.get("name")
        if not name:
            continue
        if name not in live_multisigs:
            findings.append(
                DriftFinding(
                    severity="medium",
                    subject=name,
                    message="multisig missing from live snapshot",
                    expected="present",
                    actual="missing",
                )
            )
            continue

        expected = multisig.get("threshold")
        actual = live_multisigs[name].get("threshold")
        if expected is not None and actual is None:
            findings.append(
                DriftFinding(
                    severity="high",
                    subject=name,
                    message="multisig threshold missing from live snapshot",
                    expected=expected,
                    actual=None,
                )
            )
        elif expected is not None and actual != expected:
            findings.append(
                DriftFinding(
                    severity="high",
                    subject=name,
                    message="multisig threshold drifted from manifest",
                    expected=expected,
                    actual=actual,
                )
            )

    return findings
