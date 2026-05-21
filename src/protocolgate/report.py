from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Iterable

from rich.console import Console
from rich.table import Table


@dataclass(frozen=True)
class Violation:
    rule_id: str
    severity: str
    message: str
    path: str
    recommendation: str


def findings_to_json(findings: Iterable[Violation]) -> str:
    return json.dumps([asdict(finding) for finding in findings], indent=2)


def findings_to_markdown(findings: list[Violation], *, target: str = "deployment manifest") -> str:
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

    lines.extend(
        [
            "",
            "## Scope Note",
            "",
            "ProtocolGate validates declared deployment topology and control-plane invariants. "
            "It does not replace a full smart-contract audit, formal verification, or runtime monitoring.",
        ]
    )
    return "\n".join(lines)


def print_findings(findings: list[Violation], *, console: Console | None = None) -> None:
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


def _severity_counts(findings: list[Violation]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding.severity.lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
