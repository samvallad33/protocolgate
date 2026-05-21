from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from protocolgate.manifest import load_manifest
from protocolgate.rules import evaluate_manifest


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_FIXTURES = sorted((ROOT / "examples" / "public").glob("*/protocolgate.yaml"))


def test_public_fixtures_are_clean_case_studies() -> None:
    assert PUBLIC_FIXTURES

    for fixture in PUBLIC_FIXTURES:
        manifest = load_manifest(fixture)

        assert evaluate_manifest(manifest) == [], fixture


def test_public_fixture_upgrade_admin_mutation_is_blocked() -> None:
    manifest = load_manifest(ROOT / "examples" / "public" / "compound-comet-usdc" / "protocolgate.yaml")
    manifest = deepcopy(manifest)
    manifest["contracts"][0]["proxy"]["admin"] = "0x1111111111111111111111111111111111111111"

    findings = evaluate_manifest(manifest)
    rule_ids = {finding.rule_id for finding in findings}

    assert "CG001" in rule_ids
    assert "CG002" in rule_ids


def test_public_fixture_proposal_calldata_mutation_is_blocked() -> None:
    manifest = load_manifest(ROOT / "examples" / "public" / "aave-governance-v3-ethereum" / "protocolgate.yaml")
    manifest = deepcopy(manifest)
    manifest["proposal_intent"]["proposals"][0]["execution_calldata_hash"] = (
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    )

    findings = evaluate_manifest(manifest)
    rule_ids = {finding.rule_id for finding in findings}

    assert "CG034" in rule_ids
