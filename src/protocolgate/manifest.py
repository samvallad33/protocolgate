from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


Manifest = dict[str, Any]


class ManifestError(ValueError):
    """Raised when a manifest cannot be loaded or normalized."""


def load_manifest(path: Path) -> Manifest:
    """Load a protocolgate.yaml manifest from disk."""

    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ManifestError(f"manifest not found: {path}") from exc

    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise ManifestError(f"invalid YAML in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ManifestError("manifest root must be a mapping")

    return normalize_manifest(data)


def normalize_manifest(data: Manifest) -> Manifest:
    """Apply conservative defaults so policy code can stay simple."""

    normalized = dict(data)
    list_sections = (
        "contracts",
        "multisigs",
        "governors",
        "timelocks",
        "guardians",
        "bridges",
        "oracles",
        "tokens",
        "predicates",
        "safety_controls",
    )
    for key in list_sections:
        value = normalized.get(key, [])
        if value is None:
            value = []
        if not isinstance(value, list):
            raise ManifestError(f"{key} must be a list")
        for index, item in enumerate(value):
            if not isinstance(item, dict):
                raise ManifestError(f"{key}[{index}] must be a mapping")
        normalized[key] = value

    for key in ("deployment", "treasury", "governance", "policy", "project", "proposal_intent"):
        value = normalized.get(key, {})
        if value is None:
            value = {}
        if not isinstance(value, dict):
            raise ManifestError(f"{key} must be a mapping")
        normalized[key] = value

    for contract_index, contract in enumerate(normalized["contracts"]):
        for key in ("functions", "integrations"):
            value = contract.get(key, [])
            if value is None:
                value = []
            if not isinstance(value, list):
                raise ManifestError(f"contracts[{contract_index}].{key} must be a list")
            for item_index, item in enumerate(value):
                if not isinstance(item, dict):
                    raise ManifestError(f"contracts[{contract_index}].{key}[{item_index}] must be a mapping")
            contract[key] = value

        for key in ("proxy", "roles", "upgrade_safety", "rate_limits"):
            value = contract.get(key, {})
            if value is None:
                value = {}
            if not isinstance(value, dict):
                raise ManifestError(f"contracts[{contract_index}].{key} must be a mapping")
            contract[key] = value

    for predicate_index, predicate in enumerate(normalized["predicates"]):
        for key in ("reads", "authorizes"):
            value = predicate.get(key, [])
            if value is None:
                value = []
            if not isinstance(value, list):
                raise ManifestError(f"predicates[{predicate_index}].{key} must be a list")
            predicate[key] = value

    for control_index, control in enumerate(normalized["safety_controls"]):
        for key in ("protects", "bypass_selectors"):
            value = control.get(key, [])
            if value is None:
                value = []
            if not isinstance(value, list):
                raise ManifestError(f"safety_controls[{control_index}].{key} must be a list")
            for item_index, item in enumerate(value):
                if key == "protects" and not isinstance(item, dict):
                    raise ManifestError(f"safety_controls[{control_index}].protects[{item_index}] must be a mapping")
            control[key] = value

    treasury_splits = normalized["treasury"].get("splits", [])
    if treasury_splits is None:
        treasury_splits = []
    if not isinstance(treasury_splits, list):
        raise ManifestError("treasury.splits must be a list")
    for index, split in enumerate(treasury_splits):
        if not isinstance(split, dict):
            raise ManifestError(f"treasury.splits[{index}] must be a mapping")
    normalized["treasury"]["splits"] = treasury_splits

    proposals = normalized["proposal_intent"].get("proposals", [])
    if proposals is None:
        proposals = []
    if not isinstance(proposals, list):
        raise ManifestError("proposal_intent.proposals must be a list")
    for index, proposal in enumerate(proposals):
        if not isinstance(proposal, dict):
            raise ManifestError(f"proposal_intent.proposals[{index}] must be a mapping")
        for key in ("simulation", "monitor"):
            value = proposal.get(key, {})
            if value is None:
                value = {}
            if not isinstance(value, dict):
                raise ManifestError(f"proposal_intent.proposals[{index}].{key} must be a mapping")
            proposal[key] = value
    normalized["proposal_intent"]["proposals"] = proposals

    safe_modules = normalized["proposal_intent"].get("safe_modules", [])
    if safe_modules is None:
        safe_modules = []
    if not isinstance(safe_modules, list):
        raise ManifestError("proposal_intent.safe_modules must be a list")
    for index, module in enumerate(safe_modules):
        if not isinstance(module, dict):
            raise ManifestError(f"proposal_intent.safe_modules[{index}] must be a mapping")
    normalized["proposal_intent"]["safe_modules"] = safe_modules

    for key in ("privileged_selectors", "allowed_safe_modules", "monitor_required_for"):
        value = normalized["proposal_intent"].get(key, [])
        if value is None:
            value = []
        if not isinstance(value, list):
            raise ManifestError(f"proposal_intent.{key} must be a list")
        normalized["proposal_intent"][key] = value

    disabled_rules = normalized["policy"].get("disable_rules", [])
    if disabled_rules is None:
        disabled_rules = []
    if not isinstance(disabled_rules, list):
        raise ManifestError("policy.disable_rules must be a list")
    normalized["policy"]["disable_rules"] = disabled_rules
    return normalized


def to_opa_input(manifest: Manifest) -> str:
    """Serialize normalized manifest input for OPA."""

    return json.dumps(manifest, indent=2, sort_keys=True)
