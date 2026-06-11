from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Iterable

from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from protocolgate.memory import MemoryResult


@dataclass(frozen=True)
class Violation:
    rule_id: str
    severity: str
    message: str
    path: str
    recommendation: str


EvidenceMap = dict[tuple[str, str], "MemoryResult"]
"""Advisory memory evidence keyed by (rule_id, path). Never affects verdicts."""


def _evidence_for(finding: Violation, evidence: EvidenceMap | None) -> "MemoryResult | None":
    if not evidence:
        return None
    return evidence.get((finding.rule_id, finding.path))


def findings_to_json(findings: Iterable[Violation], *, evidence: EvidenceMap | None = None) -> str:
    payload = []
    for finding in findings:
        item: dict = asdict(finding)
        result = _evidence_for(finding, evidence)
        if result is not None:
            item["institutional_evidence"] = {
                "advisory": True,
                "confidence": result.confidence,
                "contradictions": result.contradictions,
                "memories": [asdict(ev) for ev in result.evidence],
            }
        payload.append(item)
    return json.dumps(payload, indent=2)


def findings_to_markdown(
    findings: list[Violation],
    *,
    target: str = "deployment manifest",
    evidence: EvidenceMap | None = None,
) -> str:
    title = "# ProtocolGate Control-Plane Report"
    lines = [
        title,
        "",
        f"**Target:** `{target}`",
        "",
    ]

    if not findings:
        lines.extend(
            [
                "**Result:** PASS",
                "",
                "No policy violations detected.",
                "",
            ]
        )
        return "\n".join(lines)

    counts = _severity_counts(findings)
    lines.extend(
        [
            "**Result:** FAIL",
            "",
            "## Summary",
            "",
            f"- Critical: {counts['critical']}",
            f"- High: {counts['high']}",
            f"- Medium: {counts['medium']}",
            f"- Low: {counts['low']}",
            "",
            "## Findings",
            "",
            "| Rule | Severity | Path | Finding | Recommendation |",
            "| --- | --- | --- | --- | --- |",
        ]
    )

    for finding in findings:
        lines.append(
            "| "
            + " | ".join(
                [
                    _md(finding.rule_id),
                    _md(finding.severity),
                    f"`{_md(finding.path)}`",
                    _md(finding.message),
                    _md(finding.recommendation),
                ]
            )
            + " |"
        )

    evidenced = [
        (finding, result)
        for finding in findings
        if (result := _evidence_for(finding, evidence)) is not None and result.has_evidence
    ]
    if evidenced:
        lines.extend(
            [
                "",
                "## Institutional Evidence (advisory)",
                "",
                "Context retrieved from the local Vestige memory layer. Advisory only: "
                "it never changes a verdict. The deterministic engine above is authoritative.",
                "",
            ]
        )
        for finding, result in evidenced:
            lines.append(f"### {finding.rule_id} - `{_md(finding.path)}`")
            lines.append("")
            lines.append(f"Retrieval confidence: {result.confidence:.2f}")
            if result.contradictions:
                lines.append(f"Contradictions detected in memory: {result.contradictions}")
            lines.append("")
            for ev in result.evidence:
                lines.append(f"- {_md(ev.render_line())}")
            lines.append("")

    lines.extend(
        [
            "",
            "## Scope Note",
            "",
            "ProtocolGate validates declared deployment topology and control-plane invariants. "
            "It does not replace a full smart-contract audit, formal verification, or runtime monitoring. "
            "Institutional evidence, when present, is advisory context from a local memory layer; "
            "it is never part of the pass/fail decision.",
        ]
    )
    return "\n".join(lines)


def print_findings(
    findings: list[Violation],
    *,
    console: Console | None = None,
    evidence: EvidenceMap | None = None,
) -> None:
    console = console or Console()
    if not findings:
        console.print("[green]PASS[/green] no policy violations")
        return

    table = Table(title="ProtocolGate Policy Findings")
    table.add_column("Rule", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Path")
    table.add_column("Finding")
    table.add_column("Fix")

    for finding in findings:
        style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
        }.get(finding.severity.lower(), "")
        table.add_row(
            finding.rule_id,
            f"[{style}]{finding.severity}[/{style}]" if style else finding.severity,
            finding.path,
            finding.message,
            finding.recommendation,
        )

    console.print(table)
    _print_evidence(findings, evidence, console)


def _print_evidence(
    findings: list[Violation],
    evidence: EvidenceMap | None,
    console: Console,
) -> None:
    if not evidence:
        return

    evidenced = [
        (finding, result)
        for finding in findings
        if (result := _evidence_for(finding, evidence)) is not None and result.has_evidence
    ]
    if not evidenced:
        return

    console.print()
    console.print("[bold]Institutional Evidence (advisory)[/bold]")
    console.print(
        "[dim]Context from the local Vestige memory layer. Advisory only; "
        "the deterministic verdict above is authoritative.[/dim]"
    )
    for finding, result in evidenced:
        console.print()
        header = f"[bold]{finding.rule_id}[/bold] [dim]{finding.path}[/dim]  confidence={result.confidence:.2f}"
        if result.contradictions:
            header += f"  [yellow]contradictions={result.contradictions}[/yellow]"
        console.print(header)
        for ev in result.evidence:
            console.print(f"  [cyan]>[/cyan] {ev.render_line()}")


def _severity_counts(findings: list[Violation]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding.severity.lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
