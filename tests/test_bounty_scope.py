from __future__ import annotations

import json

from typer.testing import CliRunner

from protocolgate.bounty_scope import analyze_bounty_reportability, parse_bounty_scope
from protocolgate.cli import app


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


def test_parse_bounty_scope_extracts_reportability_fields() -> None:
    scope = parse_bounty_scope(SCOPE)

    assert scope.program_name == "ExampleBridge Audit Contest"
    assert any("LayerZero" in item for item in scope.in_scope)
    assert any("trusted role" in item for item in scope.out_of_scope)
    assert scope.poc_required is True
    assert "4a23d1f" in " ".join(scope.commits)
    assert "LayerZero/OApp path" in scope.source_signals


def test_bounty_gate_submits_public_actor_poc_with_impact() -> None:
    result = analyze_bounty_reportability(
        SCOPE,
        candidate_notes=(
            "Anyone can replay a LayerZero OApp bridge message and perform an unauthorized "
            "withdrawal from the vault. Foundry PoC on fork shows loss of user funds, with "
            "source reference lines for the replay check and accounting bypass."
        ),
    )

    assert result.verdict == "submit"
    assert result.score >= 80
    assert "LayerZero/OApp path" in result.matched_in_scope
    assert not result.blockers


def test_bounty_gate_defers_missing_rate_limit_without_exploit_path() -> None:
    result = analyze_bounty_reportability(
        SCOPE,
        candidate_notes="Public LayerZero bridge has no rate limit and should add hardening.",
    )

    assert result.verdict == "defer"
    assert any("Missing rate-limit claim" in item for item in result.missing_evidence)


def test_bounty_gate_kills_trusted_role_only_candidate() -> None:
    result = analyze_bounty_reportability(
        SCOPE,
        candidate_notes="The owner multisig admin can remove the bridge rate limit and upgrade the proxy.",
    )

    assert result.verdict == "kill"
    assert any("trusted or privileged role" in item for item in result.blockers)


def test_bounty_scope_cli_outputs_json(tmp_path) -> None:
    scope_path = tmp_path / "scope.md"
    candidate_path = tmp_path / "candidate.md"
    scope_path.write_text(SCOPE, encoding="utf-8")
    candidate_path.write_text(
        "Anyone can perform an unauthorized withdrawal from the bridge vault. "
        "Foundry PoC shows loss of user funds.",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "bounty-scope",
            str(scope_path),
            "--candidate",
            str(candidate_path),
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["verdict"] == "submit"
    assert payload["scope"]["poc_required"] is True


def test_bounty_scope_cli_writes_verdict_capsule(tmp_path) -> None:
    scope_path = tmp_path / "scope.md"
    candidate_path = tmp_path / "candidate.md"
    capsules_path = tmp_path / "capsules.jsonl"
    scope_path.write_text(SCOPE, encoding="utf-8")
    candidate_path.write_text(
        "Anyone can perform an unauthorized withdrawal from the bridge vault. "
        "Foundry PoC shows loss of user funds.",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "bounty-scope",
            str(scope_path),
            "--candidate",
            str(candidate_path),
            "--output",
            "json",
            "--capsules",
            str(capsules_path),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["verdict"] == "submit"

    lines = capsules_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    capsule = json.loads(lines[0])
    assert capsule["schema_version"] == 1
    assert capsule["source"] == "bounty_scope"
    assert capsule["result"] == "reportability_submit"
    assert capsule["status"] == "reportable_candidate"
    assert capsule["lane"] == "bounty_reportability"
    assert "validated-lane" in capsule["tags"]
    assert capsule["evidence"]["verdict"] == "submit"
    assert capsule["evidence"]["candidate_target"] == str(candidate_path)


def test_bounty_scope_capsule_write_failure_preserves_json_and_exit_code(tmp_path) -> None:
    scope_path = tmp_path / "scope.md"
    candidate_path = tmp_path / "candidate.md"
    capsules_path = tmp_path / "capsules-dir"
    capsules_path.mkdir()
    scope_path.write_text(SCOPE, encoding="utf-8")
    candidate_path.write_text(
        "Anyone can perform an unauthorized withdrawal from the bridge vault. "
        "Foundry PoC shows loss of user funds.",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "bounty-scope",
            str(scope_path),
            "--candidate",
            str(candidate_path),
            "--output",
            "json",
            "--capsules",
            str(capsules_path),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["verdict"] == "submit"
    assert "capsule warning" in result.stderr
