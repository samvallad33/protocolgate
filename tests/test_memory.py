"""Tests for the advisory institutional-memory layer.

Covers the two contractual guarantees:
1. A stubbed Vestige response is parsed into trust-filtered evidence.
2. When the server is down, --with-memory degrades gracefully: identical
   findings, identical exit code, no exceptions.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from protocolgate.cli import app
from protocolgate.memory import MemoryResult, VestigeClient, finding_query

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()

STUB_RESPONSE = {
    "confidence": 0.81,
    "recommended": {
        "memory_id": "aaaa1111-2222-3333-4444-555566667777",
        "trust_score": 0.74,
        "date": "2026-03-02T12:00:00+00:00",
        "answer_preview": "Quantstamp audit: daily fiat mint cap is 100M USD; raising it requires a new audit sign-off.",
        "source": "quantstamp-dreusd-2026-03.pdf",
    },
    "evidence": [
        {
            "id": "bbbb1111-2222-3333-4444-555566667777",
            "trust": 0.61,
            "date": "2026-06-01T09:30:00+00:00",
            "preview": "Ops decision: custodian migration freeze Jun 12-15; no supply-control changes during the window.",
            "role": "supporting",
            "source": "ops-runbook",
        },
        {
            "id": "cccc1111-2222-3333-4444-555566667777",
            "trust": 0.12,
            "date": "2026-01-10T00:00:00+00:00",
            "preview": "Low-trust stale note that must be filtered out.",
            "role": "supporting",
        },
    ],
    "contradictions": [{"pair": "x"}],
}


def test_stubbed_response_parses_into_trust_filtered_evidence() -> None:
    client = VestigeClient("http://localhost:9")
    result = client._parse(STUB_RESPONSE)

    assert result.available is True
    assert result.confidence == 0.81
    assert result.contradictions == 1
    # recommended + one supporting item above the trust floor; the 0.12 item is dropped
    assert len(result.evidence) == 2
    assert result.evidence[0].role == "recommended"
    assert result.evidence[0].source == "quantstamp-dreusd-2026-03.pdf"
    assert result.evidence[1].trust == 0.61

    line = result.evidence[0].render_line()
    assert "trust=0.74" in line
    assert "aaaa1111" in line
    assert "source=quantstamp-dreusd-2026-03.pdf" in line


def test_query_degrades_to_empty_when_server_down() -> None:
    # Port 9 (discard) is never running an HTTP server.
    client = VestigeClient("http://127.0.0.1:9", timeout=0.2)

    assert client.is_available() is False
    result = client.query("CG034 execution calldata does not match reviewed intent")
    assert result == MemoryResult(available=False, confidence=0.0, evidence=())


def test_finding_query_composes_rule_context() -> None:
    query = finding_query("CG034", "calldata mismatch", "proposal_intent.proposals[0]")
    assert query == "CG034 calldata mismatch proposal_intent.proposals[0]"


def test_with_memory_flag_degrades_gracefully_when_server_down() -> None:
    manifest = str(ROOT / "examples" / "protocolgate.invalid.yaml")

    baseline = runner.invoke(app, ["validate", manifest, "--output", "json"])
    with_memory = runner.invoke(
        app,
        [
            "validate",
            manifest,
            "--output",
            "json",
            "--with-memory",
            "--memory-url",
            "http://127.0.0.1:9",
        ],
    )

    assert with_memory.exit_code == baseline.exit_code == 1

    def extract_json(output: str) -> list:
        start = output.index("[")
        return json.loads(output[start:])

    baseline_findings = extract_json(baseline.output)
    memory_findings = extract_json(with_memory.output)

    # Verdict and findings are identical; memory never gates.
    assert [f["rule_id"] for f in memory_findings] == [f["rule_id"] for f in baseline_findings]
    assert all("institutional_evidence" not in f for f in memory_findings)
    # The CLI tells the user it is continuing without evidence (rich may wrap lines).
    flattened = " ".join(with_memory.output.split())
    assert "continuing without institutional evidence" in flattened


def test_with_memory_attaches_advisory_evidence_with_stub(monkeypatch) -> None:
    import protocolgate.cli as cli_module

    class StubClient:
        base_url = "http://stub"

        def is_available(self) -> bool:
            return True

        def query(self, text: str) -> MemoryResult:
            return VestigeClient("http://stub")._parse(STUB_RESPONSE)

    monkeypatch.setattr(cli_module, "VestigeClient", lambda url: StubClient())

    result = runner.invoke(
        app,
        [
            "validate",
            str(ROOT / "examples" / "protocolgate.invalid.yaml"),
            "--output",
            "json",
            "--with-memory",
        ],
    )

    assert result.exit_code == 1
    findings = json.loads(result.output)
    evidenced = [f for f in findings if "institutional_evidence" in f]
    assert evidenced, "expected advisory evidence blocks on findings"
    block = evidenced[0]["institutional_evidence"]
    assert block["advisory"] is True
    assert block["confidence"] == 0.81
    assert len(block["memories"]) == 2
