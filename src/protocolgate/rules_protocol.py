from __future__ import annotations

import re
from collections.abc import Iterable
from math import ceil

from protocolgate.report import Violation
from protocolgate.rules_support import (
    MAX_ORACLE_STALENESS_SECONDS,
    MIN_ADMIN_TIMELOCK_SECONDS,
    Manifest,
    as_list,
    contract_path,
    function_controls,
    function_path,
    function_timelock_delay,
    is_privileged_supply_function,
    is_redemption_function,
    is_zero_address,
)


def require_redemption_controls(manifest: Manifest) -> Iterable[Violation]:
    required = {"cooldown", "circuit_breaker", "pause"}
    for contract_index, contract in enumerate(manifest["contracts"]):
        for function_index, function in enumerate(contract.get("functions", [])):
            if not is_redemption_function(function):
                continue
            missing = required - function_controls(function)
            if missing:
                yield Violation(
                    "CG004",
                    "high",
                    f"{contract.get('name', '<unnamed>')}.{function.get('name', '<unnamed>')} lacks redemption controls: {', '.join(sorted(missing))}",
                    function_path(contract_index, function_index, ".controls"),
                    "Gate redemption with cooldown, circuit breaker, and emergency pause controls.",
                )


def require_decimal_precision_alignment(manifest: Manifest) -> Iterable[Violation]:
    token_decimals = {
        token.get("name"): token.get("decimals")
        for token in manifest["tokens"]
        if token.get("name") and token.get("decimals") is not None
    }
    oracle_decimals = {
        oracle.get("name"): oracle.get("decimals")
        for oracle in manifest["oracles"]
        if oracle.get("name") and oracle.get("decimals") is not None
    }

    for contract_index, contract in enumerate(manifest["contracts"]):
        for integration_index, integration in enumerate(contract.get("integrations", [])):
            actual = integration.get("decimals")
            expected = integration.get("expected_decimals")
            ref = integration.get("ref") or integration.get("name")
            if expected is None and ref in token_decimals:
                expected = token_decimals[ref]
            if expected is None and ref in oracle_decimals:
                expected = oracle_decimals[ref]
            if actual is not None and expected is not None and actual != expected:
                yield Violation(
                    "CG005",
                    "high",
                    f"{contract.get('name', '<unnamed>')} integration {ref or integration_index} has decimals={actual}, expected={expected}",
                    contract_path(contract_index, f".integrations[{integration_index}].decimals"),
                    "Normalize precision boundaries at every token, oracle, and accounting integration.",
                )


def require_bridge_rate_limits(manifest: Manifest) -> Iterable[Violation]:
    for index, bridge in enumerate(manifest["bridges"]):
        if not bridge.get("rate_limits", {}).get("per_block"):
            yield Violation(
                "CG006",
                "high",
                f"bridge {bridge.get('name', index)} does not declare a per-block rate limit",
                f"bridges[{index}].rate_limits.per_block",
                "Add a per-block bridge rate limit and enforce it in the bridge contract.",
            )

    for index, contract in enumerate(manifest["contracts"]):
        if str(contract.get("type", "")).lower() != "bridge":
            continue
        if not contract.get("rate_limits", {}).get("per_block"):
            yield Violation(
                "CG006",
                "high",
                f"bridge {contract.get('name', index)} does not declare a per-block rate limit",
                contract_path(index, ".rate_limits.per_block"),
                "Add a per-block bridge rate limit and enforce it in the bridge contract.",
            )


def require_oracle_fail_closed(manifest: Manifest) -> Iterable[Violation]:
    for index, oracle in enumerate(manifest["oracles"]):
        max_staleness = int(oracle.get("max_staleness_seconds") or 0)
        if max_staleness <= 0 or max_staleness > MAX_ORACLE_STALENESS_SECONDS:
            yield Violation(
                "CG007",
                "medium",
                f"oracle {oracle.get('name', index)} has unsafe staleness window",
                f"oracles[{index}].max_staleness_seconds",
                "Set max_staleness_seconds to 3600 or lower for production feeds.",
            )
        if oracle.get("failure_mode") != "fail_closed":
            yield Violation(
                "CG008",
                "medium",
                f"oracle {oracle.get('name', index)} does not fail closed",
                f"oracles[{index}].failure_mode",
                "Set failure_mode: fail_closed and halt dependent operations when the feed is invalid.",
            )


def require_treasury_splits_sum(manifest: Manifest) -> Iterable[Violation]:
    splits = manifest.get("treasury", {}).get("splits", [])
    if not splits:
        return

    total = 0
    for index, split in enumerate(splits):
        bps = int(split.get("bps") or 0)
        total += bps
        recipient = split.get("recipient")
        if bps < 0:
            yield Violation(
                "CG009",
                "critical",
                f"treasury split {index} has negative bps={bps}",
                f"treasury.splits[{index}].bps",
                "Treasury split basis points must be non-negative and sum exactly to 10000.",
            )
        if not recipient or is_zero_address(recipient):
            yield Violation(
                "CG009",
                "critical",
                f"treasury split {index} has an invalid recipient",
                f"treasury.splits[{index}].recipient",
                "Set every treasury split recipient to an explicit non-zero destination.",
            )

    if total != 10_000:
        yield Violation(
            "CG009",
            "critical",
            f"treasury splits sum to {total} bps, not 10000 bps",
            "treasury.splits",
            "Make treasury allocation basis points sum exactly to 10000.",
        )


def require_multisig_thresholds(manifest: Manifest) -> Iterable[Violation]:
    for index, multisig in enumerate(manifest["multisigs"]):
        signers = as_list(multisig.get("signers"))
        threshold = int(multisig.get("threshold") or 0)
        min_threshold = max(2, ceil(len(signers) / 2))
        if not signers:
            yield Violation(
                "CG010",
                "critical",
                f"multisig {multisig.get('name', index)} has no signers",
                f"multisigs[{index}].signers",
                "Define the signer set and set a threshold of at least 2.",
            )
        elif threshold < 2:
            yield Violation(
                "CG010",
                "critical",
                f"multisig {multisig.get('name', index)} threshold {threshold}/{len(signers)} is a paper multisig",
                f"multisigs[{index}].threshold",
                "Set multisig threshold to at least 2, ideally 3/5 or 5/9.",
            )
        elif threshold > len(signers):
            yield Violation(
                "CG010",
                "critical",
                f"multisig {multisig.get('name', index)} threshold {threshold}/{len(signers)} can never execute",
                f"multisigs[{index}].threshold",
                "Set threshold to a value no greater than the signer count.",
            )
        elif threshold < min_threshold:
            yield Violation(
                "CG010",
                "high",
                f"multisig {multisig.get('name', index)} threshold {threshold}/{len(signers)} is below the production floor",
                f"multisigs[{index}].threshold",
                "Use at least 2 signers and no less than half of the signer set.",
            )


def require_external_call_ordering(manifest: Manifest) -> Iterable[Violation]:
    for contract_index, contract in enumerate(manifest["contracts"]):
        for function_index, function in enumerate(contract.get("functions", [])):
            if not function.get("external_calls"):
                continue
            controls = function_controls(function)
            if not function.get("state_updates_before_external_calls") or "nonReentrant" not in controls:
                yield Violation(
                    "CG012",
                    "high",
                    f"{contract.get('name', '<unnamed>')}.{function.get('name', '<unnamed>')} has external calls without CEI + nonReentrant controls",
                    function_path(contract_index, function_index),
                    "Update state before external calls and add nonReentrant protection.",
                )


def require_supply_controls(manifest: Manifest) -> Iterable[Violation]:
    for contract_index, contract in enumerate(manifest["contracts"]):
        for function_index, function in enumerate(contract.get("functions", [])):
            if not is_privileged_supply_function(function):
                continue
            if not function.get("supply_cap"):
                yield Violation(
                    "CG015",
                    "medium",
                    f"{contract.get('name', '<unnamed>')}.{function.get('name', '<unnamed>')} has no supply cap",
                    function_path(contract_index, function_index, ".supply_cap"),
                    "Declare and enforce a hard cap or bounded mint/burn envelope.",
                )
            if function_timelock_delay(manifest, contract, function) < MIN_ADMIN_TIMELOCK_SECONDS:
                yield Violation(
                    "CG016",
                    "high",
                    f"{contract.get('name', '<unnamed>')}.{function.get('name', '<unnamed>')} supply control is not timelocked",
                    function_path(contract_index, function_index, ".timelock"),
                    "Put privileged supply changes behind the protocol timelock.",
                )


def require_fee_change_bounds(manifest: Manifest) -> Iterable[Violation]:
    for contract_index, contract in enumerate(manifest["contracts"]):
        for function_index, function in enumerate(contract.get("functions", [])):
            name = str(function.get("name", "")).lower()
            if not _is_fee_change_function(name, function.get("category")):
                continue
            if function.get("max_bps") is None:
                yield Violation(
                    "CG020",
                    "medium",
                    f"{contract.get('name', '<unnamed>')}.{function.get('name', '<unnamed>')} can change fees without max_bps",
                    function_path(contract_index, function_index, ".max_bps"),
                    "Declare a hard upper bound for fee-setting logic.",
                )
            if function_timelock_delay(manifest, contract, function) < MIN_ADMIN_TIMELOCK_SECONDS:
                yield Violation(
                    "CG021",
                    "medium",
                    f"{contract.get('name', '<unnamed>')}.{function.get('name', '<unnamed>')} fee change is not timelocked",
                    function_path(contract_index, function_index, ".timelock"),
                    "Route fee changes through the protocol timelock.",
                )


def _is_fee_change_function(name: str, category: object) -> bool:
    if str(category).lower() == "fee":
        return True
    return bool(re.search(r"fee(?!d)", name))
