from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from protocolgate.bounty_scope import analyze_bounty_reportability
from protocolgate.capsules import (
    bounty_scope_verdict_capsule,
    compile_dead_lane_constraints,
    drift_verdict_capsules,
    hunt_verdict_capsules,
    text_fingerprint,
    validate_verdict_capsules,
    write_capsules_jsonl,
)
from protocolgate.drift import compare_snapshot
from protocolgate.cli import app
from protocolgate.hunt import hunt_manifest
from protocolgate.manifest import load_manifest
from protocolgate.rules import evaluate_manifest


ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


SCOPE = """
# ExampleBridge Audit Contest

## In Scope
- Solidity smart contracts
- LayerZero OApp bridge contracts
- vault withdrawal accounting
- oracle integrations

## Out Of Scope
- centralization risks
- trusted role abuse by owner, admin, guardian, governance, or multisig
- best-practice recommendations without direct exploitability
- known issues and accepted risks

## Rewards
- Critical: loss of user funds, direct theft, or protocol insolvency up to $250,000
- High: unauthorized withdrawals or minting up to $50,000

## Requirements
- PoC required for smart-contract impacts.
- Reports must include affected commit 4a23d1f.
"""


def test_hunt_verdict_capsule_contains_invariant_detail_and_stable_id() -> None:
    manifest_path = ROOT / "examples" / "protocolgate.aave-grace-bypass.yaml"
    manifest = load_manifest(manifest_path)
    findings = hunt_manifest(manifest)

    capsules = hunt_verdict_capsules(manifest=manifest, target=str(manifest_path), findings=findings)
    repeated = hunt_verdict_capsules(manifest=manifest, target=str(manifest_path), findings=findings)

    assert len(capsules) == 1
    capsule = capsules[0]
    assert capsule.capsule_id == repeated[0].capsule_id
    assert capsule.capsule_type == "protocolgate.verdict_capsule.v1"
    assert capsule.producer == "protocolgate"
    assert capsule.workflow == "hunt"
    assert capsule.source == "hunt"
    assert capsule.target_name == "AaveV37GraceBypassFixture"
    assert capsule.lane == "global_invariant_local_gate"
    assert capsule.result == "open_door"
    assert capsule.status == "needs_source_and_poc"
    assert "open-door" in capsule.tags
    assert "severity-critical" in capsule.tags
    assert "boundary-scope" in capsule.tags
    assert capsule.metadata["advisory"] is True
    assert capsule.metadata["deterministic_verdict_unchanged"] is True
    assert capsule.memory["write_status"] == "local_only"
    assert capsule.evidence["invariant_tested"]["safety_control"] == "LiquidationGrace"
    assert capsule.evidence["invariant_tested"]["control_scope"] == "reserve"
    assert capsule.evidence["invariant_tested"]["expected_scope"] == "account"
    assert capsule.evidence["bypass_selectors"] == ("collateralAsset", "debtAsset")
    assert capsule.evidence["files_contracts"]["subjects"] == (
        "AavePool",
        "liquidationCall",
        "liquidationGracePeriodUntil",
        "LiquidationGrace",
    )
    assert capsule.evidence["role_assumptions"]["trusted_roles_required"] == "unknown_until_source_review"
    assert capsule.evidence["live_config_assumptions"]["requires_live_config"] is True
    assert capsule.evidence["poc_status"] == "missing"
    assert capsule.evidence["input_fingerprints"]["manifest"].startswith("sha256:")


def test_validate_verdict_capsule_normalizes_policy_evidence() -> None:
    manifest_path = ROOT / "examples" / "protocolgate.invalid.yaml"
    manifest = load_manifest(manifest_path)
    findings = evaluate_manifest(manifest)

    capsules = validate_verdict_capsules(manifest=manifest, target=str(manifest_path), findings=findings)

    assert capsules
    capsule = capsules[0]
    assert capsule.workflow == "validate"
    assert capsule.source == "validate"
    assert capsule.result == "open_door"
    assert capsule.status == "needs_fix_or_review"
    assert capsule.evidence["workflow"] == "validate"
    assert capsule.evidence["files_contracts"]["paths"]
    assert "role_assumptions" in capsule.evidence
    assert capsule.evidence["live_config_assumptions"]["requires_live_config"] is False
    assert capsule.evidence["poc_status"] == "not_started"


def test_drift_verdict_capsule_preserves_snapshot_context() -> None:
    manifest_path = ROOT / "examples" / "protocolgate.valid.yaml"
    snapshot_path = ROOT / "examples" / "live-state.drift.json"
    manifest = load_manifest(manifest_path)
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    findings = compare_snapshot(manifest, snapshot)

    capsules = drift_verdict_capsules(
        manifest=manifest,
        target=str(manifest_path),
        snapshot_target=str(snapshot_path),
        snapshot=snapshot,
        findings=findings,
    )

    assert capsules
    capsule = capsules[0]
    assert capsule.workflow == "drift"
    assert capsule.source == "drift"
    assert capsule.lane == "runtime_configuration_drift"
    assert capsule.status == "needs_live_config_review"
    assert "needs-live-config" in capsule.tags
    assert capsule.evidence["live_config_assumptions"]["requires_live_config"] is True
    assert capsule.evidence["input_fingerprints"]["snapshot"].startswith("sha256:")


def test_dead_lane_compiler_does_not_close_open_drift_findings() -> None:
    manifest_path = ROOT / "examples" / "protocolgate.valid.yaml"
    snapshot_path = ROOT / "examples" / "live-state.drift.json"
    manifest = load_manifest(manifest_path)
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    findings = compare_snapshot(manifest, snapshot)
    capsules = drift_verdict_capsules(
        manifest=manifest,
        target=str(manifest_path),
        snapshot_target=str(snapshot_path),
        snapshot=snapshot,
        findings=findings,
    )

    assert compile_dead_lane_constraints(capsules) == ()


def test_bounty_scope_defer_capsule_marks_evidence_gap() -> None:
    result = analyze_bounty_reportability(
        SCOPE,
        candidate_notes="Public LayerZero bridge has no rate limit and should add hardening.",
    )

    capsule = bounty_scope_verdict_capsule(
        result=result,
        scope_target="scope.md",
        candidate_target="candidate.md",
    )

    assert result.verdict == "defer"
    assert capsule.source == "bounty_scope"
    assert capsule.result == "reportability_defer"
    assert capsule.status == "needs_evidence"
    assert "needs-evidence" in capsule.tags
    assert "evidence-gap" in capsule.tags
    assert "needs-poc" in capsule.tags
    assert capsule.evidence["dead_lane_constraints"]
    assert capsule.metadata["dead_lane_compiler"] is True
    assert any("Missing rate-limit claim" in item for item in capsule.missing_evidence)
    assert "PoC or concrete reproduction exists" in capsule.reopen_if
    assert capsule.metadata["deterministic_verdict_unchanged"] is True


def test_bounty_scope_capsule_id_includes_input_fingerprints() -> None:
    first_candidate = "Anyone can perform an unauthorized withdrawal from the bridge vault. Foundry PoC shows loss."
    second_candidate = first_candidate + " Source references point to BridgeVault.withdraw."
    first = analyze_bounty_reportability(SCOPE, candidate_notes=first_candidate)
    second = analyze_bounty_reportability(SCOPE, candidate_notes=second_candidate)

    first_capsule = bounty_scope_verdict_capsule(
        result=first,
        scope_target="scope.md",
        candidate_target="candidate.md",
        scope_fingerprint=text_fingerprint(SCOPE),
        candidate_fingerprint=text_fingerprint(first_candidate),
    )
    second_capsule = bounty_scope_verdict_capsule(
        result=second,
        scope_target="scope.md",
        candidate_target="candidate.md",
        scope_fingerprint=text_fingerprint(SCOPE),
        candidate_fingerprint=text_fingerprint(second_candidate),
    )

    assert first_capsule.capsule_id != second_capsule.capsule_id
    assert first_capsule.evidence["input_fingerprints"]["scope"].startswith("sha256:")
    assert first_capsule.evidence["input_fingerprints"]["candidate"] == text_fingerprint(first_candidate)
    assert second_capsule.evidence["input_fingerprints"]["candidate"] == text_fingerprint(second_candidate)


def test_bounty_scope_kill_capsule_marks_closed_door_scope_blocked() -> None:
    result = analyze_bounty_reportability(
        SCOPE,
        candidate_notes="The owner multisig admin can remove the bridge rate limit and upgrade the proxy.",
    )

    capsule = bounty_scope_verdict_capsule(
        result=result,
        scope_target="scope.md",
        candidate_target="candidate.md",
    )

    assert result.verdict == "kill"
    assert capsule.result == "reportability_kill"
    assert capsule.status == "closed_door"
    assert "closed-door" in capsule.tags
    assert "scope-blocked" in capsule.tags
    assert capsule.evidence["dead_lane_constraints"][0]["constraint_type"] == "closed_door"
    assert any("trusted or privileged role" in item for item in capsule.blockers)
    assert "candidate no longer depends on a trusted role or excluded surface" in capsule.reopen_if


def test_dead_lane_compiler_turns_killed_capsules_into_constraints() -> None:
    result = analyze_bounty_reportability(
        SCOPE,
        candidate_notes="The owner multisig admin can remove the bridge rate limit and upgrade the proxy.",
    )
    capsule = bounty_scope_verdict_capsule(result=result, scope_target="scope.md", candidate_target="candidate.md")

    constraints = compile_dead_lane_constraints((capsule,))

    assert len(constraints) == 1
    constraint = constraints[0]
    assert constraint.source_capsule_id == capsule.capsule_id
    assert constraint.lane == "bounty_reportability"
    assert constraint.hypothesis == capsule.summary
    assert constraint.invariant_tested["verdict"] == "kill"
    assert constraint.files_contracts["scope_target"] == "scope.md"
    assert constraint.role_assumptions["public_actor_path_required"] is True
    assert constraint.poc_status == "required"
    assert constraint.evidence_grade == "scope-and-reportability"
    assert constraint.scope_severity_reason.startswith("reportability=kill")
    assert constraint.confidence == "high"
    assert "closed-door" in constraint.tags
    assert constraint.reopen_if


def test_write_capsules_jsonl_appends_and_returns_count(tmp_path: Path) -> None:
    result = analyze_bounty_reportability(
        SCOPE,
        candidate_notes="Public LayerZero bridge has no rate limit and should add hardening.",
    )
    capsule = bounty_scope_verdict_capsule(result=result, scope_target="scope.md")
    capsules_path = tmp_path / "nested" / "capsules.jsonl"

    assert write_capsules_jsonl(capsules_path, (capsule,)) == 1
    assert write_capsules_jsonl(capsules_path, (capsule,)) == 1
    assert write_capsules_jsonl(capsules_path, ()) == 0

    lines = capsules_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert all(item["schema_version"] == 1 for item in parsed)
    assert all(item["capsule_type"] == "protocolgate.verdict_capsule.v1" for item in parsed)


def test_hunt_capsules_cli_does_not_create_ledger_when_no_findings(tmp_path: Path) -> None:
    capsules_path = tmp_path / "capsules.jsonl"

    result = runner.invoke(
        app,
        [
            "hunt",
            str(ROOT / "examples" / "protocolgate.valid.yaml"),
            "--capsules",
            str(capsules_path),
        ],
    )

    assert result.exit_code == 0
    assert "PASS" in result.output
    assert not capsules_path.exists()
