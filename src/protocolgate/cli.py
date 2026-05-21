from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from protocolgate.drift import compare_snapshot
from protocolgate.manifest import ManifestError, load_manifest, to_opa_input
from protocolgate.opa import OpaUnavailable, evaluate_with_opa
from protocolgate.report import findings_to_json, findings_to_markdown, print_findings
from protocolgate.rules import evaluate_manifest


app = typer.Typer(
    add_completion=False,
    help="Web3 control-plane policy gate for smart-contract deployment topology.",
)
console = Console()


def _default_policy_dir() -> Path:
    package_policy_dir = Path(__file__).resolve().parent / "policies"
    if package_policy_dir.exists():
        return package_policy_dir
    return Path(__file__).resolve().parents[2] / "policies"


@app.command()
def validate(
    manifest: Annotated[Path, typer.Argument(help="Path to protocolgate.yaml")],
    engine: Annotated[str, typer.Option(help="Policy engine: builtin or opa")] = "builtin",
    policy_dir: Annotated[Path, typer.Option(help="OPA policy directory")] = _default_policy_dir(),
    output: Annotated[str, typer.Option("--output", "-o", help="Output format: table, json, or markdown")] = "table",
) -> None:
    """Validate a deployment manifest before deploy."""

    try:
        data = load_manifest(manifest)
        if engine == "builtin":
            findings = evaluate_manifest(data)
        elif engine == "opa":
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

    if output == "json":
        print(findings_to_json(findings))
    elif output == "markdown":
        print(findings_to_markdown(findings, target=str(manifest)))
    elif output == "table":
        print_findings(findings, console=console)
    else:
        raise typer.BadParameter("output must be table, json, or markdown")

    if findings:
        raise typer.Exit(1)


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

    if findings:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
