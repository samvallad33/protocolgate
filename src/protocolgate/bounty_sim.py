from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from protocolgate.capsules import VerdictCapsule, drift_verdict_capsules, write_capsules_jsonl
from protocolgate.drift import DriftFinding, compare_snapshot
from protocolgate.manifest import load_manifest


@dataclass(frozen=True)
class SimulationLane:
    index: int
    subject: str
    severity: str
    template: str
    hypothesis: str
    first_test: str
    expected: str
    actual: str
    status: str


@dataclass(frozen=True)
class FoundryRun:
    status: str
    command: tuple[str, ...]
    project_dir: str
    returncode: int | None
    stdout_tail: str
    stderr_tail: str


@dataclass(frozen=True)
class VestigeWrite:
    status: str
    command: tuple[str, ...]
    items: int
    response_tail: str
    error: str


@dataclass(frozen=True)
class BountySimulationResult:
    target_name: str
    manifest: str
    snapshot: str
    output_dir: str
    report_path: str
    summary_path: str
    capsules_path: str
    foundry_project_dir: str
    findings: tuple[dict[str, Any], ...]
    lanes: tuple[SimulationLane, ...]
    capsules_written: int
    foundry: FoundryRun
    vestige: VestigeWrite
    verdict: str
    next_actions: tuple[str, ...]


def run_bounty_simulation(
    *,
    manifest_path: Path,
    snapshot_path: Path,
    output_dir: Path | None = None,
    run_foundry: bool = True,
    write_vestige: bool = False,
    vestige_command: str = "vestige-mcp",
    timeout_seconds: int = 120,
) -> BountySimulationResult:
    """Run the private ProtocolGate drift -> capsule -> Foundry proof loop."""

    manifest = load_manifest(manifest_path)
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    target_name = _target_name(manifest)
    root = output_dir or _default_output_dir(target_name)
    root.mkdir(parents=True, exist_ok=True)

    findings = compare_snapshot(manifest, snapshot)
    capsules = drift_verdict_capsules(
        manifest=manifest,
        target=str(manifest_path),
        snapshot_target=str(snapshot_path),
        snapshot=snapshot,
        findings=findings,
    )
    capsules_path = root / "verdict-capsules.jsonl"
    capsules_written = write_capsules_jsonl(capsules_path, capsules)
    lanes = tuple(_lane_from_finding(index, finding) for index, finding in enumerate(findings))

    foundry_project_dir = root / "foundry"
    _write_foundry_project(foundry_project_dir, target_name=target_name, lanes=lanes)
    foundry = _run_foundry(foundry_project_dir, run_foundry=run_foundry, timeout_seconds=timeout_seconds)

    vestige = _write_vestige_mcp(
        capsules,
        lanes=lanes,
        enabled=write_vestige,
        command=vestige_command,
        timeout_seconds=min(timeout_seconds, 45),
    )

    verdict = _verdict(findings=findings, foundry=foundry)
    next_actions = _next_actions(verdict)
    result = BountySimulationResult(
        target_name=target_name,
        manifest=str(manifest_path),
        snapshot=str(snapshot_path),
        output_dir=str(root),
        report_path=str(root / "BOUNTY_SIMULATION_REPORT.md"),
        summary_path=str(root / "summary.json"),
        capsules_path=str(capsules_path),
        foundry_project_dir=str(foundry_project_dir),
        findings=tuple(asdict(finding) for finding in findings),
        lanes=lanes,
        capsules_written=capsules_written,
        foundry=foundry,
        vestige=vestige,
        verdict=verdict,
        next_actions=next_actions,
    )
    _write_outputs(result)
    return result


def result_to_json(result: BountySimulationResult) -> str:
    return json.dumps(asdict(result), indent=2)


def result_to_markdown(result: BountySimulationResult) -> str:
    lines = [
        "# ProtocolGate Private Bounty Simulation",
        "",
        f"**Target:** `{result.target_name}`",
        f"**Verdict:** `{result.verdict}`",
        f"**Findings:** `{len(result.findings)}`",
        f"**Foundry:** `{result.foundry.status}`",
        f"**Vestige:** `{result.vestige.status}`",
        "",
        "## What Happened",
        "",
        "ProtocolGate compared the declared control-plane manifest against the supplied runtime snapshot, converted each drift into a verdict capsule, generated a focused Foundry harness, and ran the local proof step when enabled.",
        "",
        "This proves the drift signal is machine-checkable. It does not by itself claim a bounty-ready exploit; source-level impact and scope checks are still required before submission.",
        "",
        "## Lanes",
        "",
        "| # | Severity | Subject | Template | Status | Hypothesis | First Test |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]

    if not result.lanes:
        lines.append("| - | - | - | - | pass | No runtime drift found. | None. |")
    for lane in result.lanes:
        lines.append(
            "| "
            + " | ".join(
                [
                    str(lane.index),
                    _md(lane.severity),
                    _md(lane.subject),
                    f"`{_md(lane.template)}`",
                    _md(lane.status),
                    _md(lane.hypothesis),
                    _md(lane.first_test),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            f"- Capsules: `{result.capsules_path}`",
            f"- Foundry project: `{result.foundry_project_dir}`",
            f"- JSON summary: `{result.summary_path}`",
            "",
            "## Next Actions",
            "",
        ]
    )
    for action in result.next_actions:
        lines.append(f"- {action}")

    if result.foundry.stdout_tail or result.foundry.stderr_tail:
        lines.extend(["", "## Foundry Tail", ""])
        if result.foundry.stdout_tail:
            lines.extend(["```text", result.foundry.stdout_tail, "```"])
        if result.foundry.stderr_tail:
            lines.extend(["```text", result.foundry.stderr_tail, "```"])

    return "\n".join(lines) + "\n"


def _default_output_dir(target_name: str) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    slug = _slug(target_name) or "target"
    return Path(".protocolgate") / "bounty-sim" / f"{stamp}-{slug}"


def _target_name(manifest: dict[str, Any]) -> str:
    project = manifest.get("project")
    if isinstance(project, dict) and project.get("name"):
        return str(project["name"])
    return "unknown target"


def _lane_from_finding(index: int, finding: DriftFinding) -> SimulationLane:
    template = _template_for(finding)
    return SimulationLane(
        index=index,
        subject=finding.subject,
        severity=finding.severity,
        template=template,
        hypothesis=_hypothesis_for(finding, template),
        first_test=_first_test_for(template),
        expected=str(finding.expected),
        actual=str(finding.actual),
        status="open_door_needs_source_trace",
    )


def _template_for(finding: DriftFinding) -> str:
    text = f"{finding.subject} {finding.message}".lower()
    if "proxy admin" in text:
        return "proxy_admin_drift"
    if "multisig threshold" in text:
        return "multisig_threshold_drift"
    if "missing" in text:
        return "missing_control_plane_object"
    return "runtime_configuration_drift"


def _hypothesis_for(finding: DriftFinding, template: str) -> str:
    if template == "proxy_admin_drift":
        return (
            f"{finding.subject} is governed by a different proxy admin than the manifest declares; "
            "trace whether the live admin can upgrade or redirect user-facing logic."
        )
    if template == "multisig_threshold_drift":
        return (
            f"{finding.subject} has a live threshold that differs from the declared policy; "
            "trace whether privileged execution became easier or emergency action became impossible."
        )
    if template == "missing_control_plane_object":
        return (
            f"{finding.subject} is absent from the runtime snapshot; confirm whether the manifest, "
            "deployment, or collector missed a control-plane object."
        )
    return f"{finding.subject} runtime configuration differs from the declared manifest."


def _first_test_for(template: str) -> str:
    return {
        "proxy_admin_drift": "Read proxy admin and implementation on-chain, then prove the drifted admin controls upgrade execution.",
        "multisig_threshold_drift": "Read Safe threshold/modules/guard and prove the live signer policy differs from the declared invariant.",
        "missing_control_plane_object": "Re-collect the object at a pinned block and decide whether this is collector noise or real topology drift.",
        "runtime_configuration_drift": "Pin the live config, then trace it to a source-level asset-flow or authority impact.",
    }.get(template, "Trace the drift to source-level impact.")


def _write_foundry_project(project_dir: Path, *, target_name: str, lanes: Iterable[SimulationLane]) -> None:
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "src").mkdir(exist_ok=True)
    (project_dir / "test").mkdir(exist_ok=True)
    (project_dir / "foundry.toml").write_text(
        "\n".join(
            [
                "[profile.default]",
                'src = "src"',
                'test = "test"',
                'out = "out"',
                "libs = []",
                'solc_version = "0.8.24"',
                "optimizer = true",
                "optimizer_runs = 200",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (project_dir / "src" / "ProtocolGateBountyHarness.sol").write_text(
        _harness_source(target_name=target_name, lanes=tuple(lanes)),
        encoding="utf-8",
    )
    (project_dir / "test" / "ProtocolGateBountySimulation.t.sol").write_text(
        _test_source(lanes=tuple(lanes)),
        encoding="utf-8",
    )


def _harness_source(*, target_name: str, lanes: tuple[SimulationLane, ...]) -> str:
    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity ^0.8.24;",
        "",
        "library ProtocolGateBountyHarness {",
        f"    string internal constant TARGET = {_sol_string(target_name)};",
    ]
    if not lanes:
        lines.extend(
            [
                "    function findingCount() internal pure returns (uint256) {",
                "        return 0;",
                "    }",
                "}",
                "",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            "",
            "    function findingCount() internal pure returns (uint256) {",
            f"        return {len(lanes)};",
            "    }",
            "",
        ]
    )
    for lane in lanes:
        expected_hash = _bytes32(lane.expected)
        actual_hash = _bytes32(lane.actual)
        lines.extend(
            [
                f"    function drift_{lane.index}() internal pure returns (bool) {{",
                f"        bytes32 expectedHash = {expected_hash};",
                f"        bytes32 actualHash = {actual_hash};",
                "        return expectedHash != actualHash;",
                "    }",
                "",
                f"    function template_{lane.index}() internal pure returns (string memory) {{",
                f"        return {_sol_string(lane.template)};",
                "    }",
                "",
            ]
        )
    lines.extend(["}", ""])
    return "\n".join(lines)


def _test_source(*, lanes: tuple[SimulationLane, ...]) -> str:
    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity ^0.8.24;",
        "",
        'import "../src/ProtocolGateBountyHarness.sol";',
        "",
        "contract ProtocolGateBountySimulationTest {",
        "    function test_protocolgateGeneratedAtLeastOneSignalWhenDriftExists() public pure {",
        f"        require(ProtocolGateBountyHarness.findingCount() == {len(lanes)}, \"unexpected finding count\");",
        "    }",
        "",
    ]
    if not lanes:
        lines.extend(["}", ""])
        return "\n".join(lines)

    for lane in lanes:
        lines.extend(
            [
                f"    function test_drift_{lane.index}_{_sol_identifier(lane.template)}() public pure {{",
                f"        require(ProtocolGateBountyHarness.drift_{lane.index}(), \"drift {lane.index} not reproduced\");",
                "    }",
                "",
            ]
        )
    lines.extend(
        [
            "    function test_sourceTraceStillRequiredBeforeBountySubmission() public pure {",
            "        require(ProtocolGateBountyHarness.findingCount() > 0, \"no open door\");",
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def _run_foundry(project_dir: Path, *, run_foundry: bool, timeout_seconds: int) -> FoundryRun:
    command = ("forge", "test", "-vv")
    if not run_foundry:
        return FoundryRun(
            status="skipped",
            command=command,
            project_dir=str(project_dir),
            returncode=None,
            stdout_tail="",
            stderr_tail="",
        )
    if shutil.which("forge") is None:
        return FoundryRun(
            status="forge_missing",
            command=command,
            project_dir=str(project_dir),
            returncode=None,
            stdout_tail="",
            stderr_tail="forge command not found",
        )

    try:
        completed = subprocess.run(
            command,
            cwd=project_dir,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return FoundryRun(
            status="timeout",
            command=command,
            project_dir=str(project_dir),
            returncode=None,
            stdout_tail=_tail(exc.stdout or ""),
            stderr_tail=_tail(exc.stderr or "forge test timed out"),
        )

    return FoundryRun(
        status="passed" if completed.returncode == 0 else "failed",
        command=command,
        project_dir=str(project_dir),
        returncode=completed.returncode,
        stdout_tail=_tail(completed.stdout),
        stderr_tail=_tail(completed.stderr),
    )


def _write_vestige_mcp(
    capsules: Iterable[VerdictCapsule],
    *,
    lanes: tuple[SimulationLane, ...],
    enabled: bool,
    command: str,
    timeout_seconds: int,
) -> VestigeWrite:
    items = _vestige_items(tuple(capsules), lanes=lanes)
    cmd = (command,)
    if not enabled:
        return VestigeWrite(status="skipped", command=cmd, items=len(items), response_tail="", error="")
    resolved = shutil.which(command)
    if resolved is None:
        return VestigeWrite(status="vestige_mcp_missing", command=cmd, items=len(items), response_tail="", error=f"{command} not found")
    if not items:
        return VestigeWrite(status="no_items", command=cmd, items=0, response_tail="", error="")

    payload = "\n".join(
        [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "protocolgate-bounty-sim", "version": "0.1.0"},
                    },
                }
            ),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "smart_ingest", "arguments": {"items": items, "batchMergePolicy": "smart"}},
                }
            ),
            "",
        ]
    )
    try:
        completed = subprocess.run(
            (resolved,),
            input=payload,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return VestigeWrite(
            status="timeout",
            command=cmd,
            items=len(items),
            response_tail=_tail(exc.stdout or ""),
            error=_tail(exc.stderr or "vestige-mcp timed out"),
        )

    response_tail = _tail(completed.stdout)
    error_tail = _tail(completed.stderr)
    status = "written" if completed.returncode == 0 and '"error"' not in completed.stdout else "failed"
    return VestigeWrite(
        status=status,
        command=cmd,
        items=len(items),
        response_tail=response_tail,
        error=error_tail,
    )


def _vestige_items(capsules: tuple[VerdictCapsule, ...], *, lanes: tuple[SimulationLane, ...]) -> list[dict[str, Any]]:
    lane_by_subject = {lane.subject: lane for lane in lanes}
    items = []
    for capsule in capsules:
        subject = str(capsule.evidence.get("subject") or "")
        lane = lane_by_subject.get(subject)
        content = (
            f"ProtocolGate bounty-sim {capsule.result}: {capsule.target_name} / {capsule.lane}. "
            f"{capsule.summary}. "
            f"Template={lane.template if lane else 'unknown'}; "
            f"status={capsule.status}; next={'; '.join(capsule.next_actions[:2])}"
        )
        items.append(
            {
                "content": content,
                "node_type": "event",
                "source": "protocolgate private bounty-sim",
                "tags": list(dict.fromkeys([*capsule.tags, "bounty-sim", "private-protocolgate"])),
            }
        )
    return items[:20]


def _write_outputs(result: BountySimulationResult) -> None:
    Path(result.summary_path).write_text(result_to_json(result) + "\n", encoding="utf-8")
    Path(result.report_path).write_text(result_to_markdown(result), encoding="utf-8")


def _verdict(*, findings: list[DriftFinding], foundry: FoundryRun) -> str:
    if not findings:
        return "pass_no_runtime_drift"
    if foundry.status == "passed":
        return "open_door_machine_checked_needs_source_trace"
    if foundry.status in {"skipped", "forge_missing"}:
        return "open_door_needs_foundry_run"
    return "open_door_foundry_failed_needs_debug"


def _next_actions(verdict: str) -> tuple[str, ...]:
    if verdict == "pass_no_runtime_drift":
        return (
            "Move to hunt or proposal-intent checks; this snapshot did not show drift.",
            "Save the clean snapshot as a baseline if it came from a trusted live collector.",
        )
    if verdict == "open_door_machine_checked_needs_source_trace":
        return (
            "Trace the drifted control-plane object to exact source lines.",
            "Prove whether the drift enables unauthorized upgrade, withdrawal, mint, oracle, bridge, or pause behavior.",
            "Run bounty-scope with candidate notes before drafting a report.",
            "If impact survives, replace the generated harness with a target-specific fork PoC.",
        )
    if verdict == "open_door_needs_foundry_run":
        return (
            "Run the generated Foundry project manually with forge test -vv.",
            "If it passes, continue to source-level impact tracing.",
            "If it fails, fix the generated harness before treating the lane as evidence.",
        )
    return (
        "Debug the generated Foundry harness.",
        "Do not submit until the proof path passes and impact is traced.",
    )


def _bytes32(value: str) -> str:
    import hashlib

    return "0x" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sol_string(value: str) -> str:
    return json.dumps(value)


def _sol_identifier(value: str) -> str:
    ident = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not ident or ident[0].isdigit():
        ident = f"lane_{ident}"
    return ident[:64]


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:80]


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _tail(value: str, *, lines: int = 40, chars: int = 4000) -> str:
    parts = value.splitlines()
    tailed = "\n".join(parts[-lines:])
    if len(tailed) <= chars:
        return tailed
    return tailed[-chars:]
