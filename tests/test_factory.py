"""Tests for the bounty-factory orchestrator loop.

No network: a fake collector returns canned snapshots and a fake VestigeClient
returns canned read-back evidence, so the factory's read-back -> drift -> state
mapping is verified deterministically. These tests also pin the BRIGHT LINE:
the factory never auto-assigns ``submission-ready``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from protocolgate.collector import (
    CollectionResult,
    CollectorError,
    ContractTarget,
    MultisigTarget,
)
from protocolgate.factory import (
    STATE_DEAD_DOOR,
    STATE_NEEDS_CONFIG,
    STATE_NEEDS_POC,
    STATE_SUBMISSION_READY,
    FactoryTarget,
    lane_signature,
    run_factory,
)
from protocolgate.memory import MemoryEvidence, MemoryResult


# --------------------------------------------------------------------------- #
# Fakes (no network)
# --------------------------------------------------------------------------- #


class FakeCollector:
    """Returns a scripted snapshot keyed by rpc_url; records calls."""

    def __init__(self, snapshots: dict[str, dict], errors: dict[str, list[str]] | None = None,
                 raise_for: set[str] | None = None) -> None:
        self.snapshots = snapshots
        self.errors = errors or {}
        self.raise_for = raise_for or set()
        self.calls: list[str] = []

    def __call__(self, rpc_url, contracts, multisigs, *, block="latest", timeout=15.0):
        self.calls.append(rpc_url)
        if rpc_url in self.raise_for:
            raise CollectorError(f"rpc dead: {rpc_url}")
        snapshot = self.snapshots.get(rpc_url, {"block": block, "contracts": [], "multisigs": []})
        return CollectionResult(snapshot=snapshot, errors=list(self.errors.get(rpc_url, [])))


class FakeVestige:
    """Fake advisory memory client. Scripts dead-door recall by signature."""

    def __init__(self, available: bool = True, dead_signatures: set[str] | None = None) -> None:
        self._available = available
        self.dead_signatures = dead_signatures or set()
        self.queries: list[str] = []

    def is_available(self) -> bool:
        return self._available

    def query(self, text: str) -> MemoryResult:
        self.queries.append(text)
        if text in self.dead_signatures:
            evidence = MemoryEvidence(
                memory_id="deadcap0",
                trust=0.9,
                date="2026-06-01",
                preview=(
                    "ProtocolGate bounty-sim KILL: lane closed as dead-door; "
                    "reopen_if scope language changes."
                ),
                role="recommended",
                source="protocolgate private bounty-sim",
            )
            return MemoryResult(available=True, confidence=0.9, evidence=(evidence,))
        return MemoryResult(available=True, confidence=0.0, evidence=())


PROXY = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADMIN = "0x1111111111111111111111111111111111111111"
SAFE = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _write_manifest(tmp_path: Path, name: str = "AcmeProtocol") -> Path:
    manifest = tmp_path / "protocolgate.yaml"
    manifest.write_text(
        "\n".join(
            [
                "version: 1",
                "project:",
                f"  name: {name}",
                "contracts:",
                "  - name: Vault",
                f'    address: "{PROXY}"',
                "    proxy:",
                f'      admin: "{ADMIN}"',
                "multisigs:",
                "  - name: Gov",
                f'    address: "{SAFE}"',
                "    threshold: 3",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return manifest


def _write_targets(tmp_path: Path, manifest: Path, rpc_url: str = "http://rpc.local") -> Path:
    targets = tmp_path / "targets.yaml"
    targets.write_text(
        "\n".join(
            [
                "targets:",
                "  - name: Acme",
                "    chain: ethereum-mainnet",
                f"    manifest: {manifest}",
                f"    rpc_url: {rpc_url}",
                "    payout: 50000",
                "    scope_notes: control-plane drift only",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return targets


def _resolver(target: FactoryTarget) -> str:
    return target.rpc_url


# --------------------------------------------------------------------------- #
# 1. Clean target: no drift -> dead-door / pass
# --------------------------------------------------------------------------- #


def test_clean_target_is_dead_door(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)

    # Live snapshot matches the manifest exactly -> compare_snapshot finds nothing.
    clean = {
        "block": "latest",
        "contracts": [{"name": "Vault", "address": PROXY, "proxy": {"admin": ADMIN}}],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://rpc.local": clean})
    vestige = FakeVestige(available=True)

    result = run_factory(
        targets,
        rpc_resolver=_resolver,
        collect=collector,
        vestige_client=vestige,
    )

    assert result.target_count == 1
    acme = result.results[0]
    assert acme.state == STATE_DEAD_DOOR
    assert acme.findings == ()
    assert acme.lanes == ()
    assert acme.errors == ()
    # Collector and read-back both ran.
    assert collector.calls == ["http://rpc.local"]
    assert acme.vestige_available is True


# --------------------------------------------------------------------------- #
# 2. Drifted target -> needs-PoC (never submission-ready)
# --------------------------------------------------------------------------- #


def test_drifted_target_is_needs_poc_never_submission_ready(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)

    # Admin drifted to a different address -> critical proxy_admin_drift finding.
    drifted = {
        "block": "0x123",
        "contracts": [
            {"name": "Vault", "address": PROXY, "proxy": {"admin": "0x9999999999999999999999999999999999999999"}}
        ],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://rpc.local": drifted})
    vestige = FakeVestige(available=True)  # no dead-door recall

    result = run_factory(
        targets,
        rpc_resolver=_resolver,
        collect=collector,
        vestige_client=vestige,
    )

    acme = result.results[0]
    assert acme.state == STATE_NEEDS_POC
    assert acme.state != STATE_SUBMISSION_READY  # BRIGHT LINE
    assert len(acme.lanes) == 1
    lane = acme.lanes[0]
    assert lane.subject == "Vault"
    assert lane.kind == "proxy_admin_drift"
    assert lane.status == STATE_NEEDS_POC
    assert lane.skipped_dead_door is False


def test_missing_object_is_needs_config_not_poc(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)

    # Multisig absent from snapshot -> "missing" finding -> needs-config.
    snapshot = {
        "block": "latest",
        "contracts": [{"name": "Vault", "address": PROXY, "proxy": {"admin": ADMIN}}],
        "multisigs": [],  # Gov missing
    }
    collector = FakeCollector(snapshots={"http://rpc.local": snapshot})
    vestige = FakeVestige(available=True)

    result = run_factory(targets, rpc_resolver=_resolver, collect=collector, vestige_client=vestige)

    acme = result.results[0]
    assert acme.state == STATE_NEEDS_CONFIG
    assert acme.state != STATE_SUBMISSION_READY
    assert [lane.status for lane in acme.lanes] == [STATE_NEEDS_CONFIG]


# --------------------------------------------------------------------------- #
# 3. Known dead-door lane: read-back -> skipped, target downgraded
# --------------------------------------------------------------------------- #


def test_known_dead_door_lane_is_skipped(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)

    # Same critical admin drift as the needs-PoC case...
    drifted = {
        "block": "0x123",
        "contracts": [
            {"name": "Vault", "address": PROXY, "proxy": {"admin": "0x9999999999999999999999999999999999999999"}}
        ],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://rpc.local": drifted})

    # ...but memory recalls this exact lane as a prior dead-door.
    dead_sig = lane_signature("Acme", "Vault", "proxy_admin_drift")
    vestige = FakeVestige(available=True, dead_signatures={dead_sig})

    result = run_factory(
        targets,
        rpc_resolver=_resolver,
        collect=collector,
        vestige_client=vestige,
    )

    acme = result.results[0]
    # The single drift lane was read-back-killed, so no live lane remains.
    assert acme.state == STATE_DEAD_DOOR
    assert acme.state != STATE_SUBMISSION_READY
    assert len(acme.lanes) == 1
    lane = acme.lanes[0]
    assert lane.skipped_dead_door is True
    assert lane.status == STATE_DEAD_DOOR
    assert lane.evidence_refs == ("deadcap0",)
    # The read-back query used the canonical lane signature.
    assert dead_sig in vestige.queries
    # A dead-door read-back was recorded for the proxy lane.
    proxy_readback = next(rb for rb in acme.readbacks if rb.kind == "proxy_admin_drift")
    assert proxy_readback.recalled_dead_door is True


# --------------------------------------------------------------------------- #
# 4. Vestige-unavailable degradation (not fatal)
# --------------------------------------------------------------------------- #


def test_vestige_unavailable_degrades_gracefully(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)

    drifted = {
        "block": "0x123",
        "contracts": [
            {"name": "Vault", "address": PROXY, "proxy": {"admin": "0x9999999999999999999999999999999999999999"}}
        ],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://rpc.local": drifted})
    vestige = FakeVestige(available=False)

    result = run_factory(
        targets,
        rpc_resolver=_resolver,
        collect=collector,
        vestige_client=vestige,
    )

    acme = result.results[0]
    # Read-back is skipped, so the live drift still surfaces as needs-PoC.
    assert result.vestige_available is False
    assert acme.vestige_available is False
    assert acme.state == STATE_NEEDS_POC
    # No queries were issued because the health check failed up front.
    assert vestige.queries == []
    # Read-backs are recorded as "not queried".
    assert all(rb.queried is False for rb in acme.readbacks)


def test_vestige_query_failure_is_not_fatal(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)

    drifted = {
        "block": "0x123",
        "contracts": [
            {"name": "Vault", "address": PROXY, "proxy": {"admin": "0x9999999999999999999999999999999999999999"}}
        ],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://rpc.local": drifted})

    class BoomVestige(FakeVestige):
        def query(self, text: str) -> MemoryResult:
            raise RuntimeError("memory blew up")

    vestige = BoomVestige(available=True)

    result = run_factory(targets, rpc_resolver=_resolver, collect=collector, vestige_client=vestige)

    acme = result.results[0]
    assert acme.state == STATE_NEEDS_POC  # drift still surfaces
    assert all(rb.recalled_dead_door is False for rb in acme.readbacks)


# --------------------------------------------------------------------------- #
# RPC failure for a subject / target propagates, does not crash
# --------------------------------------------------------------------------- #


def test_rpc_failure_propagates_as_error_not_crash(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest, rpc_url="http://dead.rpc")
    collector = FakeCollector(snapshots={}, raise_for={"http://dead.rpc"})
    vestige = FakeVestige(available=True)

    result = run_factory(targets, rpc_resolver=_resolver, collect=collector, vestige_client=vestige)

    acme = result.results[0]
    assert acme.state == STATE_DEAD_DOOR
    assert acme.errors  # collector error captured
    assert "rpc dead" in acme.errors[0]


def test_per_subject_collector_errors_propagate(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)
    # Snapshot collected, but one subject failed and the collector logged it.
    snapshot = {
        "block": "latest",
        "contracts": [{"name": "Vault", "address": PROXY, "proxy": {"admin": ADMIN}}],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(
        snapshots={"http://rpc.local": snapshot},
        errors={"http://rpc.local": ["multisig Gov (0xbbbb...): rpc call eth_call failed"]},
    )
    vestige = FakeVestige(available=True)

    result = run_factory(targets, rpc_resolver=_resolver, collect=collector, vestige_client=vestige)

    acme = result.results[0]
    assert acme.errors and "Gov" in acme.errors[0]
    # A clean-but-noisy snapshot still maps cleanly when there is no drift.
    assert acme.state == STATE_DEAD_DOOR


# --------------------------------------------------------------------------- #
# targets.yaml parsing + rpc_url_env resolution
# --------------------------------------------------------------------------- #


def test_rpc_url_env_resolution(tmp_path: Path, monkeypatch) -> None:
    manifest = _write_manifest(tmp_path)
    targets = tmp_path / "targets.yaml"
    targets.write_text(
        "\n".join(
            [
                "targets:",
                "  - name: Acme",
                "    chain: ethereum-mainnet",
                f"    manifest: {manifest}",
                "    rpc_url_env: ACME_RPC_URL",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ACME_RPC_URL", "http://from-env.local")

    clean = {
        "block": "latest",
        "contracts": [{"name": "Vault", "address": PROXY, "proxy": {"admin": ADMIN}}],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://from-env.local": clean})
    vestige = FakeVestige(available=False)

    # Use the default resolver (reads env) by not passing rpc_resolver.
    result = run_factory(targets, collect=collector, vestige_client=vestige)

    acme = result.results[0]
    assert collector.calls == ["http://from-env.local"]
    assert acme.state == STATE_DEAD_DOOR
    assert acme.errors == ()


def test_missing_rpc_is_recorded_as_error(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    targets = tmp_path / "targets.yaml"
    targets.write_text(
        "\n".join(
            [
                "targets:",
                "  - name: Acme",
                f"    manifest: {manifest}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    collector = FakeCollector(snapshots={})
    vestige = FakeVestige(available=False)

    # Default resolver raises FactoryError -> recorded, not crashed.
    result = run_factory(targets, collect=collector, vestige_client=vestige)
    acme = result.results[0]
    assert acme.errors and "no rpc_url" in acme.errors[0]
    assert collector.calls == []  # never attempted collection
