from copy import deepcopy
from pathlib import Path

from protocolgate.drift import compare_snapshot
from protocolgate.hunt import hunt_manifest
from protocolgate.manifest import ManifestError, load_manifest
from protocolgate.rules import evaluate_manifest


ROOT = Path(__file__).resolve().parents[1]


def test_valid_manifest_passes() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.valid.yaml")

    findings = evaluate_manifest(manifest)

    assert findings == []


def test_invalid_manifest_reports_anchor_findings() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.invalid.yaml")

    findings = evaluate_manifest(manifest)
    rule_ids = {finding.rule_id for finding in findings}

    assert "CG001" in rule_ids
    assert "CG002" in rule_ids
    assert "CG004" in rule_ids
    assert "CG005" in rule_ids
    assert "CG006" in rule_ids
    assert "CG009" in rule_ids
    assert "CG010" in rule_ids
    assert "CG013" in rule_ids
    assert "CG014" in rule_ids


def test_proposal_intent_example_passes() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.proposal-intent.yaml")

    findings = evaluate_manifest(manifest)

    assert findings == []


def test_hunt_finds_safety_control_scope_mismatch() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.aave-grace-bypass.yaml")

    findings = hunt_manifest(manifest)
    finding = next(item for item in findings if item.rule_id == "CG039")

    assert finding.severity == "critical"
    assert finding.path == "safety_controls[0].protects[0]"
    assert "reserve-scoped" in finding.message
    assert "account-scoped" in finding.message
    assert "collateralAsset" in finding.message
    assert "debtAsset" in finding.message


def test_validate_does_not_run_hunt_rules() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.aave-grace-bypass.yaml")

    findings = evaluate_manifest(manifest)
    rule_ids = {finding.rule_id for finding in findings}

    assert "CG039" not in rule_ids


def test_hunt_allows_explicitly_accepted_scope_mismatch() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.aave-grace-bypass.yaml")
    manifest = deepcopy(manifest)
    manifest["safety_controls"][0]["protects"][0]["accepted_scope_mismatch"] = True

    findings = hunt_manifest(manifest)
    rule_ids = {finding.rule_id for finding in findings}

    assert "CG039" not in rule_ids


def test_invalid_manifest_reports_proposal_intent_findings() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.invalid.yaml")

    findings = evaluate_manifest(manifest)
    rule_ids = {finding.rule_id for finding in findings}

    assert "CG032" in rule_ids
    assert "CG033" in rule_ids
    assert "CG034" in rule_ids
    assert "CG035" in rule_ids
    assert "CG036" in rule_ids
    assert "CG037" in rule_ids
    assert "CG038" in rule_ids


def test_proposal_intent_calldata_binding_is_case_insensitive() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.proposal-intent.yaml")
    manifest = deepcopy(manifest)
    proposal = manifest["proposal_intent"]["proposals"][0]
    proposal["reviewed_calldata_hash"] = (
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )

    findings = evaluate_manifest(manifest)
    rule_ids = {finding.rule_id for finding in findings}

    assert "CG034" not in rule_ids


def test_proposal_intent_rejects_expired_review_window() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.proposal-intent.yaml")
    manifest = deepcopy(manifest)
    manifest["proposal_intent"]["proposals"][0]["expires_at"] = "2026-05-06T00:00:00Z"

    findings = evaluate_manifest(manifest)
    expiry = next(finding for finding in findings if finding.rule_id == "CG033")

    assert expiry.path == "proposal_intent.proposals[0].expires_at"
    assert "259200 seconds" in expiry.message


def test_proposal_intent_allows_declared_proposal_safe_module() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.proposal-intent.yaml")
    manifest = deepcopy(manifest)
    manifest["proposal_intent"]["proposals"][0]["safe_module"] = "DelayModule"

    findings = evaluate_manifest(manifest)

    assert findings == []


def test_proposal_intent_rejects_undeclared_proposal_safe_module() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.proposal-intent.yaml")
    manifest = deepcopy(manifest)
    manifest["proposal_intent"]["proposals"][0]["safe_module"] = "RawExecutionModule"

    findings = evaluate_manifest(manifest)
    module_finding = next(finding for finding in findings if finding.rule_id == "CG036")

    assert module_finding.path == "proposal_intent.proposals[0].safe_module"
    assert "undeclared and unapproved" in module_finding.message


def test_rule_disable_is_per_finding() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.invalid.yaml")
    manifest["policy"] = {"disable_rules": ["CG002"]}

    findings = evaluate_manifest(manifest)
    rule_ids = {finding.rule_id for finding in findings}

    assert "CG001" in rule_ids
    assert "CG002" not in rule_ids


def test_paper_multisig_is_critical() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.valid.yaml")
    manifest = deepcopy(manifest)
    manifest["multisigs"][0]["threshold"] = 1

    findings = evaluate_manifest(manifest)
    paper_multisig = next(finding for finding in findings if finding.rule_id == "CG010")

    assert paper_multisig.severity == "critical"
    assert "paper multisig" in paper_multisig.message


def test_treasury_bps_mismatch_is_critical() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.valid.yaml")
    manifest = deepcopy(manifest)
    manifest["treasury"]["splits"][0]["bps"] = 6000

    findings = evaluate_manifest(manifest)
    treasury = next(finding for finding in findings if finding.rule_id == "CG009")

    assert treasury.severity == "critical"
    assert "not 10000 bps" in treasury.message


def test_ghost_reference_check_catches_undefined_security_actor() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.valid.yaml")
    manifest = deepcopy(manifest)
    manifest["contracts"][0]["roles"]["admin"] = "MissingTimelock"

    findings = evaluate_manifest(manifest)
    ghost = next(finding for finding in findings if finding.rule_id == "CG026")

    assert ghost.path == "contracts[0].roles.admin"
    assert "MissingTimelock" in ghost.message


def test_guardian_controls_require_timelock_and_multisig_backing() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.valid.yaml")
    manifest = deepcopy(manifest)
    manifest["guardians"] = [
        {
            "name": "UpgradeGuardian",
            "powers": ["upgrade"],
        },
        {
            "name": "PauseGuardian",
            "powers": ["pause"],
        },
    ]

    findings = evaluate_manifest(manifest)
    rule_ids = {finding.rule_id for finding in findings}

    assert "CG022" in rule_ids
    assert "CG023" in rule_ids


def test_governance_floor_rejects_low_quorum_and_short_voting_period() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.valid.yaml")
    manifest = deepcopy(manifest)
    manifest["governance"]["quorum_bps"] = 100
    manifest["governance"]["voting_period_seconds"] = 3600

    findings = evaluate_manifest(manifest)
    rule_ids = {finding.rule_id for finding in findings}

    assert "CG024" in rule_ids
    assert "CG025" in rule_ids


def test_upgrade_admin_can_be_governor_controlled_timelock() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.valid.yaml")
    manifest = deepcopy(manifest)
    manifest["governors"].append(
        {
            "name": "ProtocolGovernor",
            "address": "0x7000000000000000000000000000000000000007",
            "kind": "governor-bravo",
            "voting_delay_seconds": 86400,
            "voting_period_seconds": 172800,
            "timelock": "GovernorTimelock",
        }
    )
    manifest["timelocks"].append(
        {
            "name": "GovernorTimelock",
            "address": "0x8000000000000000000000000000000000000008",
            "delay_seconds": 172800,
            "proposer": "ProtocolGovernor",
            "executor": "ProtocolGovernor",
        }
    )
    manifest["contracts"][0]["proxy"]["admin"] = "GovernorTimelock"
    manifest["contracts"][0]["roles"]["admin"] = "GovernorTimelock"
    manifest["contracts"][0]["roles"]["owner"] = "GovernorTimelock"

    findings = evaluate_manifest(manifest)
    rule_ids = {finding.rule_id for finding in findings}

    assert "CG001" not in rule_ids
    assert "CG002" not in rule_ids
    assert "CG026" not in rule_ids


def test_upgrade_safety_fails_closed_when_storage_check_missing() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.valid.yaml")
    manifest = deepcopy(manifest)
    del manifest["contracts"][0]["upgrade_safety"]["storage_layout_check"]

    findings = evaluate_manifest(manifest)
    upgrade_safety = next(finding for finding in findings if finding.rule_id == "CG013")

    assert upgrade_safety.path == "contracts[0].upgrade_safety.storage_layout_check"
    assert "does not prove" in upgrade_safety.message


def test_manifest_rejects_non_mapping_contract_items(tmp_path: Path) -> None:
    manifest_path = tmp_path / "protocolgate.yaml"
    manifest_path.write_text("version: 1\ncontracts: [bad]\n", encoding="utf-8")

    try:
        load_manifest(manifest_path)
    except ManifestError as exc:
        assert "contracts[0] must be a mapping" in str(exc)
    else:
        raise AssertionError("expected ManifestError")


def test_manifest_rejects_non_mapping_deployment(tmp_path: Path) -> None:
    manifest_path = tmp_path / "protocolgate.yaml"
    manifest_path.write_text("version: 1\ncontracts: []\ndeployment: []\n", encoding="utf-8")

    try:
        load_manifest(manifest_path)
    except ManifestError as exc:
        assert "deployment must be a mapping" in str(exc)
    else:
        raise AssertionError("expected ManifestError")


def test_manifest_rejects_bad_proposal_intent_shape(tmp_path: Path) -> None:
    manifest_path = tmp_path / "protocolgate.yaml"
    manifest_path.write_text(
        "version: 1\ncontracts: []\nproposal_intent:\n  proposals: [bad]\n",
        encoding="utf-8",
    )

    try:
        load_manifest(manifest_path)
    except ManifestError as exc:
        assert "proposal_intent.proposals[0] must be a mapping" in str(exc)
    else:
        raise AssertionError("expected ManifestError")


def test_manifest_normalizes_sparse_contract_and_hunt_sections(tmp_path: Path) -> None:
    manifest_path = tmp_path / "protocolgate.yaml"
    manifest_path.write_text(
        "\n".join(
            [
                "version: 1",
                "contracts:",
                "  - name: Sparse",
                "    type: vault",
                "predicates:",
                "  - name: accountHealth",
                "    scope: account",
                "safety_controls:",
                "  - name: LocalGuard",
                "    scope:",
                "      kind: reserve",
                "    protects:",
                "      - action: act",
                "        predicate: accountHealth",
            ]
        ),
        encoding="utf-8",
    )

    manifest = load_manifest(manifest_path)

    assert manifest["contracts"][0]["functions"] == []
    assert manifest["contracts"][0]["proxy"] == {}
    assert manifest["predicates"][0]["reads"] == []
    assert manifest["safety_controls"][0]["bypass_selectors"] == []


def test_drift_snapshot_detects_proxy_admin_and_threshold_changes() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.valid.yaml")
    snapshot = {
        "contracts": [
            {"name": "MonetrixVault", "proxy": {"admin": "CompromisedAdmin"}},
            {"name": "MonetrixL2Bridge"},
        ],
        "multisigs": [
            {"name": "ProtocolMultisig", "threshold": 2},
            {"name": "SecurityCouncilMultisig", "threshold": 2},
        ],
    }

    findings = compare_snapshot(manifest, snapshot)

    assert {finding.message for finding in findings} == {
        "proxy admin drifted from manifest",
        "multisig threshold drifted from manifest",
    }


def test_drift_snapshot_missing_live_data_is_a_finding() -> None:
    manifest = load_manifest(ROOT / "examples" / "protocolgate.valid.yaml")

    findings = compare_snapshot(manifest, {"contracts": [], "multisigs": []})
    messages = {finding.message for finding in findings}

    assert "contract missing from live snapshot" in messages
    assert "multisig missing from live snapshot" in messages
