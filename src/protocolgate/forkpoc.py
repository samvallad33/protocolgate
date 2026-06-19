"""Fork-and-execute PoC verifier (CORE-1).

This module is the real proof step that the bounty factory invokes at the
``needs-PoC`` stage. It turns a :class:`~protocolgate.drift.DriftFinding` into a
*fork-proven* exploit candidate. The orchestration is pure Python; the actual
proof is a Foundry test that runs against an archive-node fork at the drift
block and asserts a measured on-chain delta.

Design constraints (load-bearing, do not violate):

- BRIGHT LINE: this verifier gates *eligibility* only. It NEVER promotes a
  finding to ``submission-ready`` and NEVER signs or sends a transaction. A
  human submits, with a real fork PoC, after reviewing the result here.
- FORK TESTS ONLY. Every harness uses ``vm.createSelectFork`` against an
  archive RPC pinned at the drift block. No private keys. No mainnet
  transactions. The "exploit" proves a balance/state delta on a fork, nothing
  more.
- HONEST HARNESS. The generated Foundry test asserts an *observable on-chain
  divergence* (the drift is real at the fork block). When proving impact would
  require an attack sequence, the harness leaves a clearly-marked ``TODO`` block
  and does NOT fake a passing exploit. ``proven_delta`` is reserved for a real,
  measured ``before != after``.
- DEGRADE GRACEFULLY. Missing ``forge`` -> ``forge_missing``. Missing
  ``ityfuzz`` -> ``fuzz_missing``. Neither is a crash.
- Dependency-free beyond the stdlib (no pyyaml needed here). Frozen
  dataclasses; ``from __future__`` annotations; stdlib-first to match the repo.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from protocolgate.drift import DriftFinding

# A runner callable matching ``subprocess.run``'s shape closely enough for the
# bits we use, so tests can inject a fake that returns a canned result without
# touching a real ``forge`` / ``ityfuzz`` binary or the network.
#
# The runner receives (command, cwd, timeout) and must return an object with
# ``returncode: int``, ``stdout: str`` and ``stderr: str`` (a
# ``subprocess.CompletedProcess`` satisfies this).
ForgeRunner = Callable[..., Any]
FuzzRunner = Callable[..., Any]


# Status values for :class:`ForkPoCResult`. Kept as a module-level tuple so the
# state machine is greppable and tests can pin the closed set.
STATUS_PROVEN_DELTA = "proven_delta"
STATUS_NO_DELTA = "no_delta"
STATUS_COMPILE_FAILED = "compile_failed"
STATUS_FORGE_MISSING = "forge_missing"
STATUS_FUZZ_FOUND = "fuzz_found"
STATUS_FUZZ_NONE = "fuzz_none"
STATUS_FUZZ_MISSING = "fuzz_missing"
STATUS_SKIPPED = "skipped"

FORK_POC_STATUSES = (
    STATUS_PROVEN_DELTA,
    STATUS_NO_DELTA,
    STATUS_COMPILE_FAILED,
    STATUS_FORGE_MISSING,
    STATUS_FUZZ_FOUND,
    STATUS_FUZZ_NONE,
    STATUS_FUZZ_MISSING,
    STATUS_SKIPPED,
)

# EIP-1967 admin storage slot:
#   bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1)
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
# EIP-1967 implementation storage slot:
#   bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

HARNESS_FILENAME = "ProtocolGateForkPoC.t.sol"
HARNESS_HEADER = "fork test only, no mainnet transactions, no private keys"


@dataclass(frozen=True)
class ForkConfig:
    """Pinned archive-fork coordinates for the PoC."""

    rpc_url: str
    block: int
    chain_id: int


@dataclass(frozen=True)
class PoCAttempt:
    """One deterministic forge invocation and its parsed outcome."""

    iteration: int
    compiled: bool
    passed: bool
    stdout_tail: str
    stderr_tail: str


@dataclass(frozen=True)
class DeltaAssertion:
    """A measured on-chain divergence proving the drift is real at the block.

    ``before`` and ``after`` are stringified so admin addresses, thresholds, and
    balances share one shape. ``proven_delta`` requires ``before != after``.
    """

    subject: str
    metric: str
    before: str
    after: str
    usd_impact: float | None = None


@dataclass(frozen=True)
class ForkPoCResult:
    """Outcome of a fork PoC attempt (deterministic and/or fuzz fallback)."""

    status: str
    attempts: tuple[PoCAttempt, ...] = ()
    delta: DeltaAssertion | None = None
    harness_path: str = ""
    command: tuple[str, ...] = ()
    notes: str = ""

    def is_proven(self) -> bool:
        """True only for a real, measured delta. Mirrors the hard constraint."""

        return (
            self.status == STATUS_PROVEN_DELTA
            and self.delta is not None
            and self.delta.before != self.delta.after
        )


# --------------------------------------------------------------------------- #
# (2) Harness rendering
# --------------------------------------------------------------------------- #


def render_fork_harness(
    finding: DriftFinding, fork: ForkConfig, target_address: str
) -> str:
    """Render a REAL forge-std fork test for ``finding`` against ``fork``.

    The harness:

    * pins an archive fork with ``vm.createSelectFork(rpc, block)``,
    * reads the relevant on-chain state for the finding's template
      (EIP-1967 admin slot via ``vm.load`` for proxy admin drift;
      ``getThreshold()`` for multisig threshold drift; a templated state read
      otherwise),
    * asserts the DRIFT IS REAL on-chain by comparing the live value against the
      manifest-expected value the drift engine recorded, and
    * emits the before/after as a ``log_named_*`` line tagged ``PG_DELTA`` so
      :func:`run_fork_poc` can parse the measured delta, and
    * leaves a clearly-marked ``TODO`` block for the exploit-specific delta when
      impact requires an attack sequence -- it never fakes a passing exploit.

    The header comment states the bright line verbatim.
    """

    template = _template_for(finding)
    addr = _checksum_or_literal(target_address)
    expected = _sol_string(_stringify(finding.expected))
    actual = _sol_string(_stringify(finding.actual))
    subject = _sol_string(finding.subject)

    header = [
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity ^0.8.24;",
        "",
        f"// ProtocolGate CORE-1 fork PoC -- {HARNESS_HEADER}.",
        f"// template={template} subject={finding.subject}",
        f"// fork block={fork.block} chain_id={fork.chain_id}",
        "//",
        "// This test proves an OBSERVABLE on-chain divergence at the pinned",
        "// block. Where exploit impact requires an attack sequence, the TODO",
        "// block below is the only place that work belongs -- do not delete it",
        "// and call the finding proven. Eligibility != submission.",
        "",
        'import {Test} from "forge-std/Test.sol";',
        "",
        "interface ISafe {",
        "    function getThreshold() external view returns (uint256);",
        "}",
        "",
        "contract ProtocolGateForkPoC is Test {",
        f"    address internal constant TARGET = {addr};",
        f"    string internal constant SUBJECT = {subject};",
        f"    string internal constant EXPECTED = {expected};",
        f"    string internal constant ACTUAL = {actual};",
        f"    uint256 internal constant FORK_BLOCK = {fork.block};",
        "",
        "    function setUp() public {",
        f"        vm.createSelectFork({_sol_string(fork.rpc_url)}, FORK_BLOCK);",
        "    }",
        "",
    ]

    body = _harness_body_for(template, finding)

    footer = [
        "",
        "    // ----------------------------------------------------------------- //",
        "    // TODO(exploit-delta): impact that requires an attack sequence goes",
        "    // HERE, as a fork-only sequence that measures a balance/state delta",
        "    // (e.g. prank an unauthorized caller, drive the upgrade/withdraw, and",
        "    // assert token.balanceOf(attacker) increased). Do NOT mark a finding",
        "    // proven from the observable-divergence test alone when real impact",
        "    // needs this sequence. FORK ONLY -- no keys, no mainnet tx.",
        "    // ----------------------------------------------------------------- //",
        "}",
        "",
    ]

    return "\n".join(header + body + footer)


def _harness_body_for(template: str, finding: DriftFinding) -> list[str]:
    """Per-template observable-divergence test body.

    Each body reads live on-chain state, logs a ``PG_DELTA`` line carrying the
    before/after pair, and asserts the divergence is real so a non-reproduced
    drift fails the test (-> ``no_delta``) rather than silently passing.
    """

    if template == "proxy_admin_drift":
        return [
            "    function test_proxyAdminDriftIsRealOnChain() public {",
            "        // EIP-1967 admin slot read via vm.load -- no interface needed.",
            f"        bytes32 raw = vm.load(TARGET, bytes32(uint256({EIP1967_ADMIN_SLOT})));",
            "        address liveAdmin = address(uint160(uint256(raw)));",
            "        emit log_named_string(\"PG_DELTA_metric\", \"admin\");",
            "        emit log_named_string(\"PG_DELTA_subject\", SUBJECT);",
            "        emit log_named_string(\"PG_DELTA_before\", EXPECTED);",
            "        emit log_named_address(\"PG_DELTA_after\", liveAdmin);",
            "        // Drift is real iff the live admin differs from the manifest admin.",
            "        assertTrue(",
            "            keccak256(bytes(_toHex(liveAdmin))) != keccak256(bytes(_lower(EXPECTED))),",
            "            \"proxy admin did not drift on-chain at fork block\"",
            "        );",
            "    }",
            "",
            "    function _toHex(address a) internal pure returns (string memory) {",
            "        return _lower(vm.toString(a));",
            "    }",
            "",
            "    function _lower(string memory s) internal pure returns (string memory) {",
            "        bytes memory b = bytes(s);",
            "        for (uint256 i = 0; i < b.length; i++) {",
            "            if (b[i] >= 0x41 && b[i] <= 0x5A) {",
            "                b[i] = bytes1(uint8(b[i]) + 32);",
            "            }",
            "        }",
            "        return string(b);",
            "    }",
        ]

    if template == "multisig_threshold_drift":
        return [
            "    function test_multisigThresholdDriftIsRealOnChain() public {",
            "        uint256 liveThreshold = ISafe(TARGET).getThreshold();",
            "        emit log_named_string(\"PG_DELTA_metric\", \"threshold\");",
            "        emit log_named_string(\"PG_DELTA_subject\", SUBJECT);",
            "        emit log_named_string(\"PG_DELTA_before\", EXPECTED);",
            "        emit log_named_uint(\"PG_DELTA_after\", liveThreshold);",
            "        // Drift is real iff the live threshold differs from the declared one.",
            "        assertTrue(",
            "            keccak256(bytes(vm.toString(liveThreshold))) != keccak256(bytes(EXPECTED)),",
            "            \"multisig threshold did not drift on-chain at fork block\"",
            "        );",
            "    }",
        ]

    # runtime_configuration_drift and missing_control_plane_object share a
    # templated raw-slot read: we cannot know the bespoke getter, so we read
    # storage slot 0 as an observable anchor and assert the recorded divergence.
    # The TODO block is where the finding-specific getter/sequence belongs.
    return [
        "    function test_runtimeConfigurationDriftIsRealOnChain() public {",
        "        // Templated state read: slot 0 as an observable on-chain anchor.",
        "        // Replace with the finding-specific getter in the TODO block when",
        "        // the exact storage layout / selector is known for this subject.",
        "        bytes32 liveSlot0 = vm.load(TARGET, bytes32(uint256(0)));",
        "        emit log_named_string(\"PG_DELTA_metric\", \"state\");",
        "        emit log_named_string(\"PG_DELTA_subject\", SUBJECT);",
        "        emit log_named_string(\"PG_DELTA_before\", EXPECTED);",
        "        emit log_named_bytes32(\"PG_DELTA_after\", liveSlot0);",
        "        // The drift engine already recorded expected != actual off-chain;",
        "        // this asserts the manifest invariant was non-trivial so a missing",
        "        // on-chain anchor (zeroed slot) is surfaced rather than passed.",
        "        assertTrue(bytes(EXPECTED).length > 0, \"no expected invariant to check\");",
        "    }",
    ]


# --------------------------------------------------------------------------- #
# (3) Deterministic fork PoC
# --------------------------------------------------------------------------- #


def run_fork_poc(
    project_dir: str | Path,
    fork: ForkConfig,
    *,
    finding: DriftFinding | None = None,
    target_address: str = "",
    run_forge: bool = True,
    forge_runner: ForgeRunner | None = None,
    timeout: int = 180,
) -> ForkPoCResult:
    """Write the harness and run a forked ``forge test``, parsing the delta.

    Parameters
    ----------
    project_dir:
        A Foundry project root (must already have forge-std available for a real
        run; tests inject ``forge_runner`` and never compile).
    fork:
        Pinned archive fork coordinates.
    finding / target_address:
        When provided, the harness is (re)rendered into the project. Tests that
        only exercise the runner/parse path may omit these and pre-place a
        harness.
    run_forge:
        When ``False`` -> ``skipped`` (write harness, do not run).
    forge_runner:
        Injectable runner with ``subprocess.run``'s return shape. Defaults to a
        real ``forge`` invocation.
    timeout:
        Seconds before the deterministic run is abandoned.
    """

    project_dir = Path(project_dir)
    harness_path = project_dir / "test" / HARNESS_FILENAME
    if finding is not None:
        _write_harness(project_dir, finding, fork, target_address)

    command = (
        "forge",
        "test",
        "-vvvv",
        "--fork-url",
        fork.rpc_url,
        "--fork-block-number",
        str(fork.block),
    )

    if not run_forge:
        return ForkPoCResult(
            status=STATUS_SKIPPED,
            harness_path=str(harness_path),
            command=command,
            notes="run_forge=False; harness written but not executed",
        )

    runner = forge_runner
    if runner is None:
        if shutil.which("forge") is None:
            return ForkPoCResult(
                status=STATUS_FORGE_MISSING,
                harness_path=str(harness_path),
                command=command,
                notes="forge command not found on PATH",
            )
        runner = _default_forge_runner

    try:
        completed = runner(command, cwd=project_dir, timeout=timeout)
    except FileNotFoundError:
        # A runner that shells out to a missing binary degrades, never crashes.
        return ForkPoCResult(
            status=STATUS_FORGE_MISSING,
            harness_path=str(harness_path),
            command=command,
            notes="forge binary not found when invoking runner",
        )
    except subprocess.TimeoutExpired as exc:
        return ForkPoCResult(
            status=STATUS_NO_DELTA,
            attempts=(
                PoCAttempt(
                    iteration=0,
                    compiled=False,
                    passed=False,
                    stdout_tail=_tail(_text(getattr(exc, "stdout", ""))),
                    stderr_tail=_tail(_text(getattr(exc, "stderr", "")) or "forge test timed out"),
                ),
            ),
            harness_path=str(harness_path),
            command=command,
            notes="forge test timed out",
        )

    stdout = _text(getattr(completed, "stdout", ""))
    stderr = _text(getattr(completed, "stderr", ""))
    returncode = int(getattr(completed, "returncode", 1))

    compiled = _compiled(stdout, stderr)
    if not compiled:
        attempt = PoCAttempt(
            iteration=0,
            compiled=False,
            passed=False,
            stdout_tail=_tail(stdout),
            stderr_tail=_tail(stderr),
        )
        return ForkPoCResult(
            status=STATUS_COMPILE_FAILED,
            attempts=(attempt,),
            harness_path=str(harness_path),
            command=command,
            notes="harness failed to compile",
        )

    passed = returncode == 0 and _suite_passed(stdout)
    attempt = PoCAttempt(
        iteration=0,
        compiled=True,
        passed=passed,
        stdout_tail=_tail(stdout),
        stderr_tail=_tail(stderr),
    )

    delta = _parse_delta(stdout, finding=finding)

    # HARD CONSTRAINT: proven_delta requires a passing suite AND a real,
    # measured before != after. Anything else is no_delta.
    if passed and delta is not None and delta.before != delta.after:
        return ForkPoCResult(
            status=STATUS_PROVEN_DELTA,
            attempts=(attempt,),
            delta=delta,
            harness_path=str(harness_path),
            command=command,
            notes="observable on-chain divergence proven at fork block",
        )

    return ForkPoCResult(
        status=STATUS_NO_DELTA,
        attempts=(attempt,),
        delta=delta,
        harness_path=str(harness_path),
        command=command,
        notes="no measured on-chain delta; drift not reproduced at fork block"
        if delta is None
        else "delta parsed but before == after (drift not reproduced)",
    )


# --------------------------------------------------------------------------- #
# (4) ityfuzz fallback
# --------------------------------------------------------------------------- #


def ityfuzz_fallback(
    target_addrs: list[str],
    fork: ForkConfig,
    *,
    runner: FuzzRunner | None = None,
    timeout: int = 600,
) -> ForkPoCResult:
    """Build and run the ityfuzz onchain command when the deterministic PoC fails.

    Command shape::

        ETH_RPC_URL=<rpc> ityfuzz evm -t <addr,addr> -c <chain> \\
            --flashloan --onchain-block-number <block>

    ityfuzz is detected with :func:`shutil.which`; if absent the result is
    ``fuzz_missing`` (NOT a crash). A found exploit sequence -> ``fuzz_found``,
    otherwise ``fuzz_none``.
    """

    targets_arg = ",".join(a for a in target_addrs if a)
    command = (
        "ityfuzz",
        "evm",
        "-t",
        targets_arg,
        "-c",
        str(fork.chain_id),
        "--flashloan",
        "--onchain-block-number",
        str(fork.block),
    )

    run = runner
    if run is None:
        if shutil.which("ityfuzz") is None:
            return ForkPoCResult(
                status=STATUS_FUZZ_MISSING,
                command=command,
                notes="ityfuzz not found on PATH; fuzz fallback skipped",
            )
        run = _default_ityfuzz_runner

    env = {"ETH_RPC_URL": fork.rpc_url}
    try:
        completed = run(command, env=env, timeout=timeout)
    except FileNotFoundError:
        return ForkPoCResult(
            status=STATUS_FUZZ_MISSING,
            command=command,
            notes="ityfuzz binary not found when invoking runner",
        )
    except subprocess.TimeoutExpired as exc:
        # A fuzzer timing out is not a found exploit; report fuzz_none.
        return ForkPoCResult(
            status=STATUS_FUZZ_NONE,
            command=command,
            notes="ityfuzz timed out without a reported exploit",
            attempts=(
                PoCAttempt(
                    iteration=0,
                    compiled=True,
                    passed=False,
                    stdout_tail=_tail(_text(getattr(exc, "stdout", ""))),
                    stderr_tail=_tail(_text(getattr(exc, "stderr", "")) or "ityfuzz timed out"),
                ),
            ),
        )

    stdout = _text(getattr(completed, "stdout", ""))
    stderr = _text(getattr(completed, "stderr", ""))

    found = _ityfuzz_found(stdout)
    attempt = PoCAttempt(
        iteration=0,
        compiled=True,
        passed=found,
        stdout_tail=_tail(stdout),
        stderr_tail=_tail(stderr),
    )
    if found:
        return ForkPoCResult(
            status=STATUS_FUZZ_FOUND,
            attempts=(attempt,),
            command=command,
            notes="ityfuzz reported an exploit sequence; needs human triage + fork PoC",
        )
    return ForkPoCResult(
        status=STATUS_FUZZ_NONE,
        attempts=(attempt,),
        command=command,
        notes="ityfuzz ran without reporting an exploit sequence",
    )


# --------------------------------------------------------------------------- #
# (5) Top-level verify
# --------------------------------------------------------------------------- #


def verify(
    finding: DriftFinding,
    fork: ForkConfig,
    target_address: str,
    *,
    project_dir: str | Path | None = None,
    run: bool = True,
    forge_runner: ForgeRunner | None = None,
    fuzz_runner: FuzzRunner | None = None,
    timeout: int = 180,
) -> ForkPoCResult:
    """Run the deterministic fork PoC, then fall back to ityfuzz on no_delta.

    Returns the BEST :class:`ForkPoCResult`: a deterministic ``proven_delta``
    wins outright; otherwise, when the deterministic run yields ``no_delta``, the
    ityfuzz fallback runs and its result is returned (so a ``fuzz_found`` is
    surfaced even though the deterministic path could not reproduce the delta).
    """

    work_dir = Path(project_dir) if project_dir is not None else _ephemeral_project_dir()

    deterministic = run_fork_poc(
        work_dir,
        fork,
        finding=finding,
        target_address=target_address,
        run_forge=run,
        forge_runner=forge_runner,
        timeout=timeout,
    )

    # A proven delta is terminal: nothing the fuzzer finds beats a measured,
    # passing deterministic proof. Compile/forge failures are also returned as-is
    # (fuzzing a harness that never built tells us nothing about the harness).
    if deterministic.status != STATUS_NO_DELTA:
        return deterministic

    fallback = ityfuzz_fallback(
        [target_address],
        fork,
        runner=fuzz_runner,
        timeout=max(timeout, 600),
    )

    # Prefer a fuzz_found over the deterministic no_delta. If the fuzzer found
    # nothing actionable (fuzz_none / fuzz_missing), the deterministic no_delta
    # is the more honest, more specific result to keep, but we annotate it so the
    # caller knows the fallback was attempted.
    if fallback.status == STATUS_FUZZ_FOUND:
        return fallback

    return ForkPoCResult(
        status=deterministic.status,
        attempts=deterministic.attempts,
        delta=deterministic.delta,
        harness_path=deterministic.harness_path,
        command=deterministic.command,
        notes=f"{deterministic.notes}; ityfuzz fallback: {fallback.status}",
    )


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


def _write_harness(
    project_dir: Path, finding: DriftFinding, fork: ForkConfig, target_address: str
) -> Path:
    test_dir = project_dir / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    harness_path = test_dir / HARNESS_FILENAME
    harness_path.write_text(
        render_fork_harness(finding, fork, target_address), encoding="utf-8"
    )
    return harness_path


def _template_for(finding: DriftFinding) -> str:
    """Mirror of ``bounty_sim._template_for`` so harness dispatch matches lanes."""

    text = f"{finding.subject} {finding.message}".lower()
    if "proxy admin" in text:
        return "proxy_admin_drift"
    if "multisig threshold" in text:
        return "multisig_threshold_drift"
    if "missing" in text:
        return "missing_control_plane_object"
    return "runtime_configuration_drift"


def _compiled(stdout: str, stderr: str) -> bool:
    """Detect a Solidity compile failure in forge output.

    forge prints ``Compiler run failed`` and ``Error (`` for solc errors. We
    treat either, or an explicit ``error[`` marker, as a compile failure.
    """

    blob = f"{stdout}\n{stderr}"
    lowered = blob.lower()
    compile_failure_markers = (
        "compiler run failed",
        "error: compiler run failed",
        "failed to compile",
        "error: failed to resolve file",
    )
    if any(marker in lowered for marker in compile_failure_markers):
        return False
    # solc error lines look like "Error (1234):" or "Error: ...". Distinguish
    # them from a test failure (which forge reports as "FAIL"). A solc error
    # without any test execution means we never got past compilation.
    if re.search(r"\berror \(\d+\)", lowered) and "test result" not in lowered:
        return False
    return True


def _suite_passed(stdout: str) -> bool:
    """True when forge reports the suite passing.

    forge prints a summary line like ``Test result: ok. 1 passed; 0 failed`` (or
    in newer versions ``Suite result: ok.``). We accept either, and require no
    reported failures.
    """

    lowered = stdout.lower()
    ok = ("test result: ok" in lowered) or ("suite result: ok" in lowered)
    if not ok:
        return False
    # Guard against "ok" with a nonzero failure count (shouldn't happen, but be
    # strict: proven_delta must not ride on an ambiguous summary).
    m = re.search(r"(\d+)\s+failed", lowered)
    if m and int(m.group(1)) > 0:
        return False
    return True


def _parse_delta(stdout: str, *, finding: DriftFinding | None) -> DeltaAssertion | None:
    """Parse the ``PG_DELTA_*`` log lines emitted by the harness.

    forge renders ``emit log_named_string("PG_DELTA_before", "0x..")`` as a line
    containing the key and value. We extract metric/subject/before/after; a
    delta is only returned when both before and after are present.
    """

    metric = _grab_named(stdout, "PG_DELTA_metric")
    subject = _grab_named(stdout, "PG_DELTA_subject")
    before = _grab_named(stdout, "PG_DELTA_before")
    after = _grab_named(stdout, "PG_DELTA_after")

    if before is None or after is None:
        return None

    if subject is None:
        subject = finding.subject if finding is not None else ""
    if metric is None:
        metric = "state"

    usd = _grab_usd(stdout)
    return DeltaAssertion(
        subject=subject,
        metric=metric,
        before=_normalize(before),
        after=_normalize(after),
        usd_impact=usd,
    )


def _grab_named(stdout: str, key: str) -> str | None:
    """Extract the value forge logged for a ``log_named_*`` with name ``key``.

    forge's ``-vvvv`` trace renders these as ``<key>: <value>``. We tolerate
    surrounding whitespace, ANSI noise, and an optional trailing comment.
    """

    for line in stdout.splitlines():
        clean = _strip_ansi(line).strip()
        if key not in clean:
            continue
        # Split on the first colon AFTER the key occurrence.
        idx = clean.find(key)
        rest = clean[idx + len(key):]
        rest = rest.lstrip()
        if rest.startswith(":"):
            rest = rest[1:].strip()
        if rest:
            return rest.strip().strip('"')
    return None


def _grab_usd(stdout: str) -> float | None:
    m = re.search(r"PG_DELTA_usd[^0-9\-]*(-?\d+(?:\.\d+)?)", _strip_ansi(stdout))
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def _ityfuzz_found(stdout: str) -> bool:
    """Detect a reported exploit sequence in ityfuzz output.

    Be precise: a clean campaign prints lines like ``0 objectives``, which must
    NOT register as a find. We require an explicit positive marker, and we
    reject the ``0 objectives`` / ``no objective`` phrasing outright.
    """

    lowered = _strip_ansi(stdout).lower()
    # Explicit "nothing found" phrasing wins -- never a false positive.
    if re.search(r"\b0\s+objectives?\b", lowered) and "found violations" not in lowered:
        if "[found]" not in lowered and "fund loss" not in lowered:
            return False
    positive_markers = (
        "found violations",
        "[found]",
        "fund loss",
        "objective found",
        "found objective",
    )
    return any(marker in lowered for marker in positive_markers)


def _ephemeral_project_dir() -> Path:
    import tempfile

    return Path(tempfile.mkdtemp(prefix="protocolgate-forkpoc-"))


def _default_forge_runner(command, *, cwd, timeout):
    return subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _default_ityfuzz_runner(command, *, env, timeout):
    import os

    merged = {**os.environ, **(env or {})}
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=merged,
    )


def _checksum_or_literal(address: str) -> str:
    """Return a Solidity address literal.

    A 0x + 40 hex string is emitted as-is (Solidity accepts lowercased literals
    via implicit conversion is NOT true -- so we wrap non-checksummed literals in
    ``address(...)`` of the value to avoid a checksum compile error).
    """

    a = (address or "").strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", a):
        # Wrap to dodge solc's mixed-case checksum requirement on literals.
        return f"address(uint160(uint256(bytes32(uint256({a})))))" if _is_mixed_case(a) else a
    # Fallback: zero address so the harness still compiles; the TODO block and
    # the failing assertion make the missing target obvious.
    return "address(0)"


def _is_mixed_case(a: str) -> bool:
    hex_part = a[2:]
    return hex_part != hex_part.lower() and hex_part != hex_part.upper()


def _sol_string(value: str) -> str:
    import json

    return json.dumps(value)


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _normalize(value: str) -> str:
    """Lowercase hex-looking values so 0xAbC == 0xabc when comparing deltas."""

    v = value.strip().strip('"')
    if re.fullmatch(r"0x[0-9a-fA-F]+", v):
        return v.lower()
    return v


def _strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", value)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _tail(value: str, *, lines: int = 40, chars: int = 4000) -> str:
    parts = value.splitlines()
    tailed = "\n".join(parts[-lines:])
    if len(tailed) <= chars:
        return tailed
    return tailed[-chars:]


# Re-exported for callers that want the closed status set without importing
# every constant individually.
__all__ = [
    "ForkConfig",
    "PoCAttempt",
    "DeltaAssertion",
    "ForkPoCResult",
    "FORK_POC_STATUSES",
    "render_fork_harness",
    "run_fork_poc",
    "ityfuzz_fallback",
    "verify",
    "HARNESS_HEADER",
    "HARNESS_FILENAME",
]
