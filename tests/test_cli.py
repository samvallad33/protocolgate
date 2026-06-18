import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from protocolgate.cli import app


ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def test_validate_json_output_is_machine_readable() -> None:
    result = runner.invoke(
        app,
        [
            "validate",
            str(ROOT / "examples" / "protocolgate.invalid.yaml"),
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 1
    findings = json.loads(result.output)
    assert findings[0]["rule_id"] == "CG001"


def test_validate_markdown_output_is_buyer_readable() -> None:
    result = runner.invoke(
        app,
        [
            "validate",
            str(ROOT / "examples" / "protocolgate.invalid.yaml"),
            "--output",
            "markdown",
        ],
    )

    assert result.exit_code == 1
    assert "# ProtocolGate Control-Plane Report" in result.output
    assert "**Result:** FAIL" in result.output
    assert "| Rule | Severity | Path | Finding | Recommendation |" in result.output
    assert "CG001" in result.output


def test_validate_capsules_jsonl_preserves_json_and_exit_code(tmp_path: Path) -> None:
    capsules_path = tmp_path / "capsules.jsonl"

    result = runner.invoke(
        app,
        [
            "validate",
            str(ROOT / "examples" / "protocolgate.invalid.yaml"),
            "--output",
            "json",
            "--capsules",
            str(capsules_path),
        ],
    )

    assert result.exit_code == 1
    findings = json.loads(result.output)
    assert findings[0]["rule_id"] == "CG001"

    lines = capsules_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(findings)
    capsule = json.loads(lines[0])
    assert capsule["source"] == "validate"
    assert capsule["result"] == "open_door"
    assert capsule["status"] == "needs_fix_or_review"
    assert capsule["evidence"]["workflow"] == "validate"
    assert capsule["evidence"]["poc_status"] == "not_started"


def test_validate_capsule_write_failure_preserves_json_and_exit_code(tmp_path: Path) -> None:
    capsules_path = tmp_path / "capsules-dir"
    capsules_path.mkdir()

    result = runner.invoke(
        app,
        [
            "validate",
            str(ROOT / "examples" / "protocolgate.invalid.yaml"),
            "--output",
            "json",
            "--capsules",
            str(capsules_path),
        ],
    )

    assert result.exit_code == 1
    findings = json.loads(result.stdout)
    assert findings[0]["rule_id"] == "CG001"
    assert "capsule warning" in result.stderr


def test_hunt_json_output_reports_scope_mismatch() -> None:
    result = runner.invoke(
        app,
        [
            "hunt",
            str(ROOT / "examples" / "protocolgate.aave-grace-bypass.yaml"),
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 1
    findings = json.loads(result.output)
    assert findings[0]["rule_id"] == "CG039"
    assert findings[0]["severity"] == "critical"
    assert "reserve-scoped" in findings[0]["message"]


def test_hunt_capsules_jsonl_preserves_scope_mismatch_context(tmp_path: Path) -> None:
    capsules_path = tmp_path / "capsules.jsonl"

    result = runner.invoke(
        app,
        [
            "hunt",
            str(ROOT / "examples" / "protocolgate.aave-grace-bypass.yaml"),
            "--output",
            "json",
            "--capsules",
            str(capsules_path),
        ],
    )

    assert result.exit_code == 1
    # Existing machine-readable output is not polluted by the capsule writer.
    findings = json.loads(result.output)
    assert findings[0]["rule_id"] == "CG039"

    lines = capsules_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    capsule = json.loads(lines[0])
    assert capsule["schema_version"] == 1
    assert capsule["source"] == "hunt"
    assert capsule["result"] == "open_door"
    assert capsule["status"] == "needs_source_and_poc"
    assert capsule["lane"] == "global_invariant_local_gate"
    assert "open-door" in capsule["tags"]
    assert "boundary-scope" in capsule["tags"]
    assert capsule["evidence"]["rule_id"] == "CG039"
    assert capsule["evidence"]["invariant_tested"]["safety_control"] == "LiquidationGrace"
    assert capsule["evidence"]["invariant_tested"]["predicate"] == "healthFactorBelowOne"
    assert "source line references" in capsule["missing_evidence"]


def test_hunt_capsule_write_failure_preserves_json_and_exit_code(tmp_path: Path) -> None:
    capsules_path = tmp_path / "capsules-dir"
    capsules_path.mkdir()

    result = runner.invoke(
        app,
        [
            "hunt",
            str(ROOT / "examples" / "protocolgate.aave-grace-bypass.yaml"),
            "--output",
            "json",
            "--capsules",
            str(capsules_path),
        ],
    )

    assert result.exit_code == 1
    findings = json.loads(result.stdout)
    assert findings[0]["rule_id"] == "CG039"
    assert "capsule warning" in result.stderr


def test_hunt_markdown_output_is_reportable() -> None:
    result = runner.invoke(
        app,
        [
            "hunt",
            str(ROOT / "examples" / "protocolgate.aave-grace-bypass.yaml"),
            "--output",
            "markdown",
        ],
    )

    assert result.exit_code == 1
    assert "# ProtocolGate Control-Plane Report" in result.output
    assert "CG039" in result.output
    assert "LiquidationGrace" in result.output


def test_validate_with_local_opa_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    opa = ROOT / ".tools" / "opa"
    if not opa.exists():
        pytest.skip("project-local OPA binary is not installed")

    monkeypatch.setenv("PATH", f"{opa.parent}{os.pathsep}{os.environ.get('PATH', '')}")

    valid = runner.invoke(
        app,
        [
            "validate",
            str(ROOT / "examples" / "protocolgate.proposal-intent.yaml"),
            "--engine",
            "opa",
            "--policy-dir",
            str(ROOT / "policies"),
        ],
    )

    assert valid.exit_code == 0

    invalid = runner.invoke(
        app,
        [
            "validate",
            str(ROOT / "examples" / "protocolgate.invalid.yaml"),
            "--engine",
            "opa",
            "--policy-dir",
            str(ROOT / "policies"),
            "--output",
            "json",
        ],
    )

    assert invalid.exit_code == 1
    findings = json.loads(invalid.output)
    rule_ids = {finding["rule_id"] for finding in findings}
    assert {"CG032", "CG033", "CG034", "CG035", "CG036", "CG037", "CG038"} <= rule_ids


def test_validate_help_does_not_expose_local_checkout_path() -> None:
    result = runner.invoke(app, ["validate", "--help"])

    assert result.exit_code == 0
    assert str(ROOT) not in result.output


def test_drift_json_output_is_machine_readable() -> None:
    result = runner.invoke(
        app,
        [
            "drift",
            str(ROOT / "examples" / "protocolgate.valid.yaml"),
            str(ROOT / "examples" / "live-state.drift.json"),
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 1
    findings = json.loads(result.output)
    assert findings[0]["message"] == "proxy admin drifted from manifest"


def test_drift_capsules_jsonl_preserves_json_and_exit_code(tmp_path: Path) -> None:
    capsules_path = tmp_path / "capsules.jsonl"

    result = runner.invoke(
        app,
        [
            "drift",
            str(ROOT / "examples" / "protocolgate.valid.yaml"),
            str(ROOT / "examples" / "live-state.drift.json"),
            "--output",
            "json",
            "--capsules",
            str(capsules_path),
        ],
    )

    assert result.exit_code == 1
    findings = json.loads(result.output)
    assert findings[0]["message"] == "proxy admin drifted from manifest"

    lines = capsules_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(findings)
    capsule = json.loads(lines[0])
    assert capsule["source"] == "drift"
    assert capsule["lane"] == "runtime_configuration_drift"
    assert capsule["status"] == "needs_live_config_review"
    assert capsule["evidence"]["live_config_assumptions"]["requires_live_config"] is True


def test_malformed_manifest_returns_clean_error(tmp_path: Path) -> None:
    manifest_path = tmp_path / "protocolgate.yaml"
    manifest_path.write_text("version: 1\ncontracts: [bad]\n", encoding="utf-8")

    result = runner.invoke(app, ["validate", str(manifest_path)])

    assert result.exit_code == 2
    assert "manifest error:" in result.output
    assert "Traceback" not in result.output
