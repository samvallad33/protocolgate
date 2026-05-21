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


def test_malformed_manifest_returns_clean_error(tmp_path: Path) -> None:
    manifest_path = tmp_path / "protocolgate.yaml"
    manifest_path.write_text("version: 1\ncontracts: [bad]\n", encoding="utf-8")

    result = runner.invoke(app, ["validate", str(manifest_path)])

    assert result.exit_code == 2
    assert "manifest error:" in result.output
    assert "Traceback" not in result.output
