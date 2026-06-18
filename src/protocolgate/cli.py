from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from protocolgate.bounty_scope import (
    analyze_bounty_reportability,
    bounty_reportability_to_json,
    bounty_reportability_to_markdown,
)
from protocolgate.capsules import (
    bounty_scope_verdict_capsule,
    drift_verdict_capsules,
    hunt_verdict_capsules,
    text_fingerprint,
    validate_verdict_capsules,
    write_capsules_jsonl,
)
from protocolgate.drift import compare_snapshot
from protocolgate.hunt import hunt_manifest
from protocolgate.manifest import ManifestError, load_manifest, to_opa_input
from protocolgate.memory import DEFAULT_BASE_URL, VestigeClient, finding_query
from protocolgate.opa import OpaUnavailable, evaluate_with_opa
from protocolgate.report import EvidenceMap, findings_to_json, findings_to_markdown, print_findings
from protocolgate.rules import evaluate_manifest


app = typer.Typer(
    add_completion=False,
    help="Web3 control-plane policy gate for smart-contract deployment topology.",
)
console = Console()
error_console = Console(stderr=True)


def _default_policy_dir() -> Path:
    package_policy_dir = Path(__file__).resolve().parent / "policies"
    if package_policy_dir.exists():
        return package_policy_dir
    return Path(__file__).resolve().parents[2] / "policies"


@app.command()
def validate(
    manifest: Annotated[Path, typer.Argument(help="Path to protocolgate.yaml")],
    engine: Annotated[str, typer.Option(help="Policy engine: builtin or opa")] = "builtin",
    policy_dir: Annotated[Path | None, typer.Option(help="OPA policy directory")] = None,
    output: Annotated[str, typer.Option("--output", "-o", help="Output format: table, json, or markdown")] = "table",
    with_memory: Annotated[
        bool,
        typer.Option(
            "--with-memory",
            help=(
                "Attach advisory institutional evidence from a local Vestige memory "
                "server to each finding. Advisory only: never changes the verdict "
                "or exit code."
            ),
        ),
    ] = False,
    memory_url: Annotated[
        str,
        typer.Option(help="Base URL of the local Vestige dashboard API"),
    ] = DEFAULT_BASE_URL,
    capsules: Annotated[
        Path | None,
        typer.Option(
            "--capsules",
            help=(
                "Append Bounty Composition Mode verdict capsules as JSONL. "
                "Advisory only: does not change findings or exit code."
            ),
        ),
    ] = None,
) -> None:
    """Validate a deployment manifest before deploy."""

    try:
        data = load_manifest(manifest)
        if engine == "builtin":
            findings = evaluate_manifest(data)
        elif engine == "opa":
            policy_dir = policy_dir or _default_policy_dir()
            findings = evaluate_with_opa(data, policy_dir)
        else:
            raise typer.BadParameter("engine must be builtin or opa")
    except ManifestError as exc:
        console.print(f"[red]manifest error:[/red] {exc}")
        raise typer.Exit(2) from exc
    except OpaUnavailable as exc:
        console.print(f"[red]opa error:[/red] {exc}")
        raise typer.Exit(2) from exc
    except RuntimeError as exc:
        console.print(f"[red]policy error:[/red] {exc}")
        raise typer.Exit(2) from exc

    evidence = _collect_memory_evidence(findings, memory_url) if with_memory else None

    if output == "json":
        print(findings_to_json(findings, evidence=evidence))
    elif output == "markdown":
        print(findings_to_markdown(findings, target=str(manifest), evidence=evidence))
    elif output == "table":
        print_findings(findings, console=console, evidence=evidence)
    else:
        raise typer.BadParameter("output must be table, json, or markdown")

    if capsules is not None:
        _write_capsules_best_effort(
            capsules,
            validate_verdict_capsules(manifest=data, target=str(manifest), findings=findings),
        )

    if findings:
        raise typer.Exit(1)


@app.command()
def hunt(
    manifest: Annotated[Path, typer.Argument(help="Path to protocolgate.yaml")],
    output: Annotated[str, typer.Option("--output", "-o", help="Output format: table, json, or markdown")] = "table",
    capsules: Annotated[
        Path | None,
        typer.Option(
            "--capsules",
            help=(
                "Append Bounty Composition Mode verdict capsules as JSONL. "
                "Advisory only: does not change findings or exit code."
            ),
        ),
    ] = None,
) -> None:
    """Find bounty-oriented control-plane invariant mismatch candidates."""

    try:
        data = load_manifest(manifest)
        findings = hunt_manifest(data)
    except ManifestError as exc:
        console.print(f"[red]manifest error:[/red] {exc}")
        raise typer.Exit(2) from exc

    if output == "json":
        print(findings_to_json(findings))
    elif output == "markdown":
        print(findings_to_markdown(findings, target=str(manifest)))
    elif output == "table":
        print_findings(findings, console=console)
    else:
        raise typer.BadParameter("output must be table, json, or markdown")

    if capsules is not None:
        _write_capsules_best_effort(
            capsules,
            hunt_verdict_capsules(manifest=data, target=str(manifest), findings=findings),
        )

    if findings:
        raise typer.Exit(1)


@app.command("bounty-scope")
def bounty_scope(
    scope: Annotated[Path, typer.Argument(help="Path to bounty or audit-contest scope text/Markdown")],
    candidate: Annotated[
        Path | None,
        typer.Option("--candidate", "-c", help="Optional candidate finding notes to reportability-gate"),
    ] = None,
    program_name: Annotated[str, typer.Option("--program-name", help="Optional program name override")] = "",
    output: Annotated[str, typer.Option("--output", "-o", help="Output format: markdown or json")] = "markdown",
    capsules: Annotated[
        Path | None,
        typer.Option(
            "--capsules",
            help=(
                "Append Bounty Composition Mode verdict capsules as JSONL. "
                "Advisory only: does not change the reportability verdict."
            ),
        ),
    ] = None,
) -> None:
    """Parse bounty scope and gate a candidate as submit, defer, or kill."""

    try:
        scope_text = scope.read_text(encoding="utf-8")
        candidate_text = candidate.read_text(encoding="utf-8") if candidate else ""
    except OSError as exc:
        console.print(f"[red]bounty-scope error:[/red] {exc}")
        raise typer.Exit(2) from exc

    result = analyze_bounty_reportability(
        scope_text,
        candidate_notes=candidate_text,
        program_name=program_name,
    )

    if output == "json":
        print(bounty_reportability_to_json(result))
    elif output == "markdown":
        print(bounty_reportability_to_markdown(result))
    else:
        raise typer.BadParameter("output must be markdown or json")

    if capsules is not None:
        _write_capsules_best_effort(
            capsules,
            (
                bounty_scope_verdict_capsule(
                    result=result,
                    scope_target=str(scope),
                    candidate_target=str(candidate) if candidate else "",
                    scope_fingerprint=text_fingerprint(scope_text),
                    candidate_fingerprint=text_fingerprint(candidate_text) if candidate else "",
                ),
            ),
        )


def _write_capsules_best_effort(path: Path, capsules) -> None:
    """Write local JSONL capsules without changing deterministic verdicts."""

    try:
        write_capsules_jsonl(path, capsules)
    except OSError as exc:
        error_console.print(f"[yellow]capsule warning:[/yellow] {exc}")


def _collect_memory_evidence(findings, memory_url: str) -> EvidenceMap | None:
    """Query the local memory server per finding. Advisory only; never raises."""

    client = VestigeClient(memory_url)
    if not client.is_available():
        console.print(
            "[yellow]memory:[/yellow] Vestige not reachable at "
            f"{client.base_url}; continuing without institutional evidence"
        )
        return None

    evidence: EvidenceMap = {}
    for finding in findings:
        key = (finding.rule_id, finding.path)
        if key in evidence:
            continue
        result = client.query(finding_query(finding.rule_id, finding.message, finding.path))
        if result.has_evidence:
            evidence[key] = result
    return evidence or None


@app.command("export-input")
def export_input(
    manifest: Annotated[Path, typer.Argument(help="Path to protocolgate.yaml")],
) -> None:
    """Print normalized JSON input for OPA, CI, or downstream tooling."""

    try:
        print(to_opa_input(load_manifest(manifest)))
    except ManifestError as exc:
        console.print(f"[red]manifest error:[/red] {exc}")
        raise typer.Exit(2) from exc


@app.command()
def drift(
    manifest: Annotated[Path, typer.Argument(help="Path to protocolgate.yaml")],
    snapshot: Annotated[Path, typer.Argument(help="JSON snapshot of live chain state")],
    output: Annotated[str, typer.Option("--output", "-o", help="Output format: table or json")] = "table",
    capsules: Annotated[
        Path | None,
        typer.Option(
            "--capsules",
            help=(
                "Append Bounty Composition Mode verdict capsules as JSONL. "
                "Advisory only: does not change findings or exit code."
            ),
        ),
    ] = None,
) -> None:
    """Detect runtime drift against a collected chain-state snapshot."""

    try:
        data = load_manifest(manifest)
        live = json.loads(snapshot.read_text(encoding="utf-8"))
    except ManifestError as exc:
        console.print(f"[red]manifest error:[/red] {exc}")
        raise typer.Exit(2) from exc
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[red]snapshot error:[/red] {exc}")
        raise typer.Exit(2) from exc

    findings = compare_snapshot(data, live)
    if output == "json":
        print(json.dumps([finding.__dict__ for finding in findings], indent=2))
    else:
        if not findings:
            console.print("[green]PASS[/green] no runtime drift detected")
        for finding in findings:
            console.print(
                f"[{finding.severity}] {finding.subject}: {finding.message} "
                f"(expected={finding.expected}, actual={finding.actual})"
            )

    if capsules is not None:
        _write_capsules_best_effort(
            capsules,
            drift_verdict_capsules(
                manifest=data,
                target=str(manifest),
                snapshot_target=str(snapshot),
                snapshot=live,
                findings=findings,
            ),
        )

    if findings:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
