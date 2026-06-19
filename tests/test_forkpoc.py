"""Tests for the fork-and-execute PoC verifier (CORE-1).

No network, no real forge, no real ityfuzz: fake ``forge_runner`` /
``fuzz_runner`` callables return canned stdout/stderr so the status machine is
verified deterministically. These tests pin the load-bearing constraints:

* ``proven_delta`` is reachable ONLY with a passing suite AND a real,
  measured ``before != after``,
* ``forge``/``ityfuzz`` absence degrades to ``forge_missing`` / ``fuzz_missing``
  rather than crashing,
* the generated harness is a real ``createSelectFork`` fork test, never a
  ``public pure`` sha256 placeholder, and carries the bright-line header.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from protocolgate.drift import DriftFinding
from protocolgate.forkpoc import (
    EIP1967_ADMIN_SLOT,
    FORK_POC_STATUSES,
    HARNESS_FILENAME,
    HARNESS_HEADER,
    STATUS_COMPILE_FAILED,
    STATUS_FORGE_MISSING,
    STATUS_FUZZ_FOUND,
    STATUS_FUZZ_MISSING,
    STATUS_FUZZ_NONE,
    STATUS_NO_DELTA,
    STATUS_PROVEN_DELTA,
    STATUS_SKIPPED,
    DeltaAssertion,
    ForkConfig,
    ForkPoCResult,
    ityfuzz_fallback,
    render_fork_harness,
    run_fork_poc,
    verify,
)


# --------------------------------------------------------------------------- #
# Fixtures / fakes (no network, no real binaries)
# --------------------------------------------------------------------------- #


FORK = ForkConfig(
    rpc_url="https://archive.example/eth",
    block=18_000_000,
    chain_id=1,
)

ADMIN_FINDING = DriftFinding(
    severity="critical",
    subject="LendingPoolProxy",
    message="proxy admin drifted from manifest",
    expected="0x1111111111111111111111111111111111111111",
    actual="0x2222222222222222222222222222222222222222",
)

THRESHOLD_FINDING = DriftFinding(
    severity="high",
    subject="TreasurySafe",
    message="multisig threshold drifted from manifest",
    expected=3,
    actual=1,
)

RUNTIME_FINDING = DriftFinding(
    severity="medium",
    subject="OracleConfig",
    message="runtime configuration differs",
    expected="paused=false",
    actual="paused=true",
)

TARGET = "0x2222222222222222222222222222222222222222"


class FakeRunner:
    """Injectable runner returning a canned CompletedProcess-like object.

    Records each invocation so tests can assert the forked command shape.
    """

    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.calls: list[dict] = []

    def __call__(self, command, **kwargs):
        self.calls.append({"command": tuple(command), **kwargs})
        return subprocess.CompletedProcess(
            args=list(command),
            returncode=self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )


# Canned forge -vvvv output for a PASSING proxy-admin divergence with a real
# delta: EXPECTED (manifest admin) != live admin logged after.
PASS_ADMIN_STDOUT = """\
Running 1 test for test/ProtocolGateForkPoC.t.sol:ProtocolGateForkPoC
[PASS] test_proxyAdminDriftIsRealOnChain() (gas: 41234)
Logs:
  PG_DELTA_metric: admin
  PG_DELTA_subject: LendingPoolProxy
  PG_DELTA_before: 0x1111111111111111111111111111111111111111
  PG_DELTA_after: 0x2222222222222222222222222222222222222222
Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 1.20s
"""

# Canned forge output for a NO-DELTA run: the drift was not reproduced, so the
# assertion FAILED and before == after in the (partial) logs.
NO_DELTA_STDOUT = """\
Running 1 test for test/ProtocolGateForkPoC.t.sol:ProtocolGateForkPoC
[FAIL. Reason: proxy admin did not drift on-chain at fork block] test_proxyAdminDriftIsRealOnChain() (gas: 39000)
Logs:
  PG_DELTA_metric: admin
  PG_DELTA_subject: LendingPoolProxy
  PG_DELTA_before: 0x1111111111111111111111111111111111111111
  PG_DELTA_after: 0x1111111111111111111111111111111111111111
Test result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 1.10s
"""

# Canned forge output for a COMPILE failure.
COMPILE_FAIL_STDERR = """\
Error: Compiler run failed:
Error (7920): Identifier not found or not unique.
 --> test/ProtocolGateForkPoC.t.sol:42:9:
"""

# Canned ityfuzz output: a found exploit sequence.
ITYFUZZ_FOUND_STDOUT = """\
[*] Starting fuzzing campaign
[+] Found violations! Objective: fund loss
[Found] exploit sequence with flashloan
"""

# Canned ityfuzz output: ran clean, nothing found.
ITYFUZZ_NONE_STDOUT = """\
[*] Starting fuzzing campaign
[*] 1_000_000 execs, 0 objectives
[*] campaign finished
"""


# --------------------------------------------------------------------------- #
# (1) Status set is the closed enum the prompt specified
# --------------------------------------------------------------------------- #


def test_status_set_is_closed_and_complete():
    assert set(FORK_POC_STATUSES) == {
        "proven_delta",
        "no_delta",
        "compile_failed",
        "forge_missing",
        "fuzz_found",
        "fuzz_none",
        "fuzz_missing",
        "skipped",
    }


# --------------------------------------------------------------------------- #
# (2) Harness rendering is a REAL fork test, not a placeholder
# --------------------------------------------------------------------------- #


def test_render_admin_harness_is_real_fork_test():
    src = render_fork_harness(ADMIN_FINDING, FORK, TARGET)
    # Bright-line header verbatim.
    assert HARNESS_HEADER in src
    # Real fork mechanics, not the bounty_sim placeholder.
    assert "vm.createSelectFork(" in src
    assert "vm.load(" in src
    assert EIP1967_ADMIN_SLOT in src
    assert f"FORK_BLOCK = {FORK.block}" in src
    # NEVER the placeholder shape.
    assert "public pure" not in src
    assert "sha256" not in src.lower()
    assert "keccak256(\"eip1967" not in src  # we use the precomputed slot
    # The honest TODO block for attack-sequence impact must be present.
    assert "TODO(exploit-delta)" in src


def test_render_threshold_harness_calls_get_threshold():
    src = render_fork_harness(THRESHOLD_FINDING, FORK, TARGET)
    assert "vm.createSelectFork(" in src
    assert "getThreshold()" in src
    assert "public pure" not in src
    assert HARNESS_HEADER in src


def test_render_runtime_harness_reads_state_and_keeps_todo():
    src = render_fork_harness(RUNTIME_FINDING, FORK, TARGET)
    assert "vm.createSelectFork(" in src
    assert "vm.load(" in src  # templated raw-slot read
    assert "TODO(exploit-delta)" in src
    assert "public pure" not in src


# --------------------------------------------------------------------------- #
# (3) Deterministic run -> status machine
# --------------------------------------------------------------------------- #


def test_run_fork_poc_proven_delta(tmp_path: Path):
    runner = FakeRunner(returncode=0, stdout=PASS_ADMIN_STDOUT)
    result = run_fork_poc(
        tmp_path,
        FORK,
        finding=ADMIN_FINDING,
        target_address=TARGET,
        forge_runner=runner,
    )
    assert result.status == STATUS_PROVEN_DELTA
    assert result.is_proven()
    assert result.delta is not None
    assert result.delta.metric == "admin"
    assert result.delta.subject == "LendingPoolProxy"
    assert result.delta.before != result.delta.after
    assert result.attempts[0].compiled is True
    assert result.attempts[0].passed is True
    # Forked command shape, pinned at the drift block.
    assert "--fork-url" in result.command
    assert "--fork-block-number" in result.command
    assert str(FORK.block) in result.command
    # Harness was actually written.
    assert (tmp_path / "test" / HARNESS_FILENAME).exists()


def test_proven_delta_requires_real_before_after(tmp_path: Path):
    """A passing suite whose logged before == after is NOT proven_delta."""

    runner = FakeRunner(returncode=0, stdout=NO_DELTA_STDOUT.replace(
        "FAILED. 0 passed; 1 failed", "ok. 1 passed; 0 failed"
    ).replace("[FAIL. Reason: proxy admin did not drift on-chain at fork block]", "[PASS]"))
    result = run_fork_poc(
        tmp_path,
        FORK,
        finding=ADMIN_FINDING,
        target_address=TARGET,
        forge_runner=runner,
    )
    # Suite "passed" but before == after, so the hard constraint forbids proven.
    assert result.status == STATUS_NO_DELTA
    assert result.is_proven() is False
    assert result.delta is not None
    assert result.delta.before == result.delta.after


def test_run_fork_poc_no_delta_on_failed_assertion(tmp_path: Path):
    runner = FakeRunner(returncode=1, stdout=NO_DELTA_STDOUT)
    result = run_fork_poc(
        tmp_path,
        FORK,
        finding=ADMIN_FINDING,
        target_address=TARGET,
        forge_runner=runner,
    )
    assert result.status == STATUS_NO_DELTA
    assert result.is_proven() is False
    assert result.attempts[0].compiled is True
    assert result.attempts[0].passed is False


def test_run_fork_poc_compile_failed(tmp_path: Path):
    runner = FakeRunner(returncode=1, stdout="", stderr=COMPILE_FAIL_STDERR)
    result = run_fork_poc(
        tmp_path,
        FORK,
        finding=ADMIN_FINDING,
        target_address=TARGET,
        forge_runner=runner,
    )
    assert result.status == STATUS_COMPILE_FAILED
    assert result.attempts[0].compiled is False
    assert result.delta is None
    assert result.is_proven() is False


def test_run_fork_poc_forge_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # No runner injected AND forge not on PATH -> forge_missing, not a crash.
    monkeypatch.setattr("protocolgate.forkpoc.shutil.which", lambda name: None)
    result = run_fork_poc(
        tmp_path,
        FORK,
        finding=ADMIN_FINDING,
        target_address=TARGET,
        forge_runner=None,
    )
    assert result.status == STATUS_FORGE_MISSING
    assert result.is_proven() is False


def test_run_fork_poc_skipped_when_not_run(tmp_path: Path):
    result = run_fork_poc(
        tmp_path,
        FORK,
        finding=ADMIN_FINDING,
        target_address=TARGET,
        run_forge=False,
    )
    assert result.status == STATUS_SKIPPED
    # Harness is still written for a human to run manually.
    assert (tmp_path / "test" / HARNESS_FILENAME).exists()


def test_run_fork_poc_timeout_is_no_delta(tmp_path: Path):
    def boom(command, **kwargs):
        raise subprocess.TimeoutExpired(cmd=list(command), timeout=1)

    result = run_fork_poc(
        tmp_path,
        FORK,
        finding=ADMIN_FINDING,
        target_address=TARGET,
        forge_runner=boom,
    )
    assert result.status == STATUS_NO_DELTA
    assert result.is_proven() is False


# --------------------------------------------------------------------------- #
# (4) ityfuzz fallback
# --------------------------------------------------------------------------- #


def test_ityfuzz_fallback_found():
    runner = FakeRunner(returncode=0, stdout=ITYFUZZ_FOUND_STDOUT)
    result = ityfuzz_fallback([TARGET], FORK, runner=runner)
    assert result.status == STATUS_FUZZ_FOUND
    # Command shape carries the fuzz flags and pinned block.
    assert "--flashloan" in result.command
    assert "--onchain-block-number" in result.command
    assert str(FORK.block) in result.command
    assert TARGET in result.command
    assert str(FORK.chain_id) in result.command
    # RPC is passed via env, never on the command line / never a key.
    assert runner.calls[0]["env"]["ETH_RPC_URL"] == FORK.rpc_url
    # A fuzz_found is NOT proven_delta -- it needs human triage + fork PoC.
    assert result.is_proven() is False


def test_ityfuzz_fallback_none():
    runner = FakeRunner(returncode=0, stdout=ITYFUZZ_NONE_STDOUT)
    result = ityfuzz_fallback([TARGET], FORK, runner=runner)
    assert result.status == STATUS_FUZZ_NONE
    assert result.is_proven() is False


def test_ityfuzz_fallback_missing(monkeypatch: pytest.MonkeyPatch):
    # No runner injected AND ityfuzz not on PATH -> fuzz_missing, not a crash.
    monkeypatch.setattr("protocolgate.forkpoc.shutil.which", lambda name: None)
    result = ityfuzz_fallback([TARGET], FORK, runner=None)
    assert result.status == STATUS_FUZZ_MISSING
    assert result.is_proven() is False


def test_ityfuzz_fallback_timeout_is_fuzz_none():
    def boom(command, **kwargs):
        raise subprocess.TimeoutExpired(cmd=list(command), timeout=1)

    result = ityfuzz_fallback([TARGET], FORK, runner=boom)
    assert result.status == STATUS_FUZZ_NONE
    assert result.is_proven() is False


# --------------------------------------------------------------------------- #
# (5) Top-level verify orchestration
# --------------------------------------------------------------------------- #


def test_verify_returns_deterministic_proven_without_fuzzing(tmp_path: Path):
    forge = FakeRunner(returncode=0, stdout=PASS_ADMIN_STDOUT)
    fuzz = FakeRunner(returncode=0, stdout=ITYFUZZ_FOUND_STDOUT)
    result = verify(
        ADMIN_FINDING,
        FORK,
        TARGET,
        project_dir=tmp_path,
        forge_runner=forge,
        fuzz_runner=fuzz,
    )
    assert result.status == STATUS_PROVEN_DELTA
    assert result.is_proven()
    # Fuzzer must NOT have been invoked once the deterministic path proved it.
    assert fuzz.calls == []


def test_verify_falls_back_to_ityfuzz_on_no_delta(tmp_path: Path):
    forge = FakeRunner(returncode=1, stdout=NO_DELTA_STDOUT)
    fuzz = FakeRunner(returncode=0, stdout=ITYFUZZ_FOUND_STDOUT)
    result = verify(
        ADMIN_FINDING,
        FORK,
        TARGET,
        project_dir=tmp_path,
        forge_runner=forge,
        fuzz_runner=fuzz,
    )
    assert result.status == STATUS_FUZZ_FOUND
    # The fuzzer WAS invoked because deterministic yielded no_delta.
    assert len(fuzz.calls) == 1


def test_verify_keeps_no_delta_when_fuzz_finds_nothing(tmp_path: Path):
    forge = FakeRunner(returncode=1, stdout=NO_DELTA_STDOUT)
    fuzz = FakeRunner(returncode=0, stdout=ITYFUZZ_NONE_STDOUT)
    result = verify(
        ADMIN_FINDING,
        FORK,
        TARGET,
        project_dir=tmp_path,
        forge_runner=forge,
        fuzz_runner=fuzz,
    )
    assert result.status == STATUS_NO_DELTA
    assert result.is_proven() is False
    # Notes record that the fallback was attempted.
    assert "ityfuzz fallback: fuzz_none" in result.notes


def test_verify_compile_failure_does_not_fuzz(tmp_path: Path):
    forge = FakeRunner(returncode=1, stdout="", stderr=COMPILE_FAIL_STDERR)
    fuzz = FakeRunner(returncode=0, stdout=ITYFUZZ_FOUND_STDOUT)
    result = verify(
        ADMIN_FINDING,
        FORK,
        TARGET,
        project_dir=tmp_path,
        forge_runner=forge,
        fuzz_runner=fuzz,
    )
    assert result.status == STATUS_COMPILE_FAILED
    # A harness that never compiled tells us nothing -- do not fuzz it.
    assert fuzz.calls == []


# --------------------------------------------------------------------------- #
# (6) Bright line: no status claims "proven" without a real delta
# --------------------------------------------------------------------------- #


def test_is_proven_is_false_for_every_non_proven_status():
    for status in FORK_POC_STATUSES:
        if status == STATUS_PROVEN_DELTA:
            continue
        result = ForkPoCResult(status=status)
        assert result.is_proven() is False, status


def test_proven_status_with_equal_delta_is_not_proven():
    """Even a hand-constructed proven_delta with before == after fails is_proven."""

    bogus = ForkPoCResult(
        status=STATUS_PROVEN_DELTA,
        delta=DeltaAssertion(subject="x", metric="admin", before="0xabc", after="0xabc"),
    )
    assert bogus.is_proven() is False
