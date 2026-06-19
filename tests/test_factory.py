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
from protocolgate.forkpoc import DeltaAssertion, ForkPoCResult, STATUS_PROVEN_DELTA
from protocolgate.memory import MemoryEvidence, MemoryResult
from protocolgate.connectors.solodit import SoloditClient
from protocolgate.historical_db import HistoricalDB, HistoricalExploit
from protocolgate.reasoning import (
    ACTION_ARM_TEMPLATE,
    ACTION_FLAG_DUPLICATE,
    INTENT_HISTORICAL_EXPLOIT,
)
from protocolgate.router import ROUTE_ARM, ROUTE_FLAG, ROUTE_SKIP


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
    assert proxy_readback.budget_decision is not None
    assert proxy_readback.budget_decision.action == ROUTE_SKIP
    assert proxy_readback.budget_decision.evidence == ("deadcap0",)
    assert result.economics.scans_skipped == 1
    assert result.economics.scans_spent == 0
    assert result.economics.compute_saved_percent == 100.0


def test_no_drift_dead_door_lane_is_credited_as_skip(tmp_path: Path) -> None:
    """GAP 2: a dead-door prospective lane with NO live drift still counts as a skip.

    The snapshot matches the manifest exactly, so the drift engine emits no
    finding and no ``LaneResult`` is ever built. Memory recalls the multisig lane
    as a prior dead-door. The read-back SKIP for that no-drift dead-door lane is
    the highest-value skip -- we avoided a lane we already knew was dead -- and
    must be credited to ``scans_skipped`` via the read-back economics pass. The
    proxy lane (no drift, no dead-door recall -> PROCEED read-back) must NOT be
    counted as either a scan or a skip.
    """

    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)

    # Snapshot matches the manifest exactly: admin == ADMIN, threshold == 3.
    # compare_snapshot emits zero findings, so there are zero drift lanes.
    clean = {
        "block": "0x123",
        "contracts": [{"name": "Vault", "address": PROXY, "proxy": {"admin": ADMIN}}],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://rpc.local": clean})

    # Memory recalls the multisig lane as a prior dead-door (no drift this run).
    dead_sig = lane_signature("Acme", "Gov", "multisig_threshold_drift")
    vestige = FakeVestige(available=True, dead_signatures={dead_sig})

    result = run_factory(
        targets,
        rpc_resolver=_resolver,
        collect=collector,
        vestige_client=vestige,
    )

    acme = result.results[0]
    # No live drift -> no lanes at all -> target is dead-door.
    assert acme.lanes == ()
    assert acme.state == STATE_DEAD_DOOR
    # The dead-door read-back SKIP for the no-drift multisig lane is credited.
    multisig_rb = next(rb for rb in acme.readbacks if rb.kind == "multisig_threshold_drift")
    assert multisig_rb.recalled_dead_door is True
    assert multisig_rb.budget_decision is not None
    assert multisig_rb.budget_decision.action == ROUTE_SKIP
    # The proxy lane had no drift and no dead-door recall -> PROCEED, not counted.
    proxy_rb = next(rb for rb in acme.readbacks if rb.kind == "proxy_admin_drift")
    assert proxy_rb.recalled_dead_door is False
    assert result.economics.scans_skipped == 1
    assert result.economics.scans_spent == 0
    assert result.economics.compute_saved_percent == 100.0


def test_factory_records_scan_spend_for_live_lane(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest, rpc_url="http://rpc.local")
    snapshot = {
        "block": "0x123",
        "contracts": [
            {"name": "Vault", "address": PROXY, "proxy": {"admin": "0x9999999999999999999999999999999999999999"}}
        ],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://rpc.local": snapshot})

    result = run_factory(
        targets,
        rpc_resolver=_resolver,
        collect=collector,
        vestige_client=FakeVestige(available=True),
        base_scan_cost=2.0,
    )

    lane = result.results[0].lanes[0]
    assert lane.budget_decision is not None
    assert lane.budget_decision.should_scan is True
    assert result.economics.scans_spent == 1
    assert result.economics.scans_skipped == 0
    assert result.economics.scan_cost_spent == 2.0
    assert result.budget_queue[0].signature == lane.signature


def test_historical_recall_reaches_lane_reasoning_and_budget(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)
    snapshot = {
        "block": "0x123",
        "contracts": [
            {"name": "Vault", "address": PROXY, "proxy": {"admin": "0x9999999999999999999999999999999999999999"}}
        ],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://rpc.local": snapshot})

    def recall(intent: str, query: str) -> tuple[MemoryEvidence, ...]:
        if intent == INTENT_HISTORICAL_EXPLOIT:
            return (
                MemoryEvidence(
                    memory_id="solodit:proxy-admin",
                    trust=0.9,
                    date="2024-01-01",
                    preview="exploit: proxy admin takeover drained funds",
                    role="historical",
                    source="solodit",
                ),
            )
        return ()

    result = run_factory(
        targets,
        rpc_resolver=_resolver,
        collect=collector,
        vestige_client=FakeVestige(available=True),
        historical_recall_fn=recall,
    )

    lane = result.results[0].lanes[0]
    assert lane.reasoning_action == ACTION_ARM_TEMPLATE
    assert "solodit:proxy-admin" in lane.reasoning_refs
    assert lane.budget_decision is not None
    assert lane.budget_decision.action == ROUTE_ARM
    assert result.budget_queue[0].action == ROUTE_ARM


def test_proven_poc_records_realized_usd_impact_without_promoting(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)
    snapshot = {
        "block": "0x123",
        "contracts": [
            {"name": "Vault", "address": PROXY, "proxy": {"admin": "0x9999999999999999999999999999999999999999"}}
        ],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://rpc.local": snapshot})
    verifier_calls: list[str] = []

    def verifier(finding, fork, target_address, **kwargs) -> ForkPoCResult:
        verifier_calls.append(target_address)
        return ForkPoCResult(
            status=STATUS_PROVEN_DELTA,
            delta=DeltaAssertion(
                subject=finding.subject,
                metric="admin",
                before=str(finding.expected),
                after=str(finding.actual),
                usd_impact=12_500.0,
            ),
        )

    result = run_factory(
        targets,
        rpc_resolver=_resolver,
        collect=collector,
        vestige_client=FakeVestige(available=True),
        run_poc=True,
        poc_verifier=verifier,
        base_scan_cost=2.0,
    )

    acme = result.results[0]
    lane = acme.lanes[0]
    assert verifier_calls == [PROXY]
    assert acme.state == STATE_NEEDS_POC
    assert acme.state != STATE_SUBMISSION_READY
    assert lane.poc_proven is True
    assert lane.poc_usd_impact == 12_500.0
    assert result.economics.findings_proven == 1
    assert result.economics.realized_usd_impact == 12_500.0
    assert result.economics.realized_usd_per_scan == 12_500.0
    assert result.economics.cost_per_finding == 2.0


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


# --------------------------------------------------------------------------- #
# GAP 3: the DEFAULT _historical_recall_adapter consumes an injected
# SoloditClient + in-memory HistoricalDB (no historical_recall_fn override).
# These pin that recall reaches a live lane's reasoning_refs + budget_decision
# through the real run_factory -> _read_back_lane -> _historical_recall_adapter
# -> judge_lane path, with zero network.
# --------------------------------------------------------------------------- #


def _fake_solodit_http_fn(url, data, headers, timeout):
    """Canned Solodit POST body. No socket is opened; SoloditClient calls this
    instead of urllib when injected via ``http_fn``. Returns one critical,
    rare, high-quality proxy-admin finding so it clears the trust floor and the
    EXPLOIT_MARKERS classifier inside ``judge_lane``."""

    return {
        "findings": [
            {
                "id": "SOLO-1",
                "title": "Proxy admin takeover",
                "severity": "critical",
                "protocol": "Acme",
                "tags": ["Access Control", "Proxy", "Admin"],
                "quality": "high",
                "rarity": "rare",
                "url": "https://solodit.cyfrin.io/issues/SOLO-1",
                "summary": "unprotected upgrade drained the proxy via admin",
            }
        ]
    }


def _euler_exploit() -> HistoricalExploit:
    """An in-memory DeFiHackLabs record whose tags overlap a proxy_admin_drift
    historical-exploit query ("proxy", "admin", "upgrade")."""

    return HistoricalExploit(
        date="2023-03-13",
        project="Euler Finance",
        tag="euler",
        poc_path="src/test/2023-03/Euler_exp.sol",
        fork_block=16_818_057,
        chain="ethereum",
        tags=("euler", "proxy", "admin", "upgrade", "flashloan"),
    )


def test_default_adapter_consumes_injected_solodit_and_historical_db(tmp_path: Path) -> None:
    """GAP 3: with NO historical_recall_fn override, the default
    _historical_recall_adapter must consume the injected SoloditClient AND the
    injected in-memory HistoricalDB, folding BOTH public-corpus hits into the
    live lane's reasoning_refs and budget_decision.

    The Solodit fold-in also fires DUPLICATE_RISK (its preview prefix always
    trips a duplicate marker), so the precedence-resolved action is
    FLAG_DUPLICATE -- the real behavior, pinned here."""

    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)
    snapshot = {
        "block": "0x123",
        "contracts": [
            {"name": "Vault", "address": PROXY, "proxy": {"admin": "0x9999999999999999999999999999999999999999"}}
        ],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://rpc.local": snapshot})

    # Real SoloditClient with an api_key (so it does not short-circuit on the
    # key-free guard) and an injected http_fn (so no socket is opened).
    solodit = SoloditClient(api_key="test-key", http_fn=_fake_solodit_http_fn)
    history = HistoricalDB(exploits=(_euler_exploit(),))

    result = run_factory(
        targets,
        rpc_resolver=_resolver,
        collect=collector,
        vestige_client=FakeVestige(available=True),  # no dead-door; pure read-back
        solodit_client=solodit,
        historical_db=history,
        # NOTE: historical_recall_fn intentionally NOT passed -> exercises the
        # default _historical_recall_adapter.
    )

    lane = result.results[0].lanes[0]

    # Both public-corpus sources reached the lane's reasoning evidence.
    assert "solodit:SOLO-1" in lane.reasoning_refs
    assert "defihacklabs:src/test/2023-03/Euler_exp.sol" in lane.reasoning_refs

    # The default adapter's hits drove the budget decision (not a bare PROCEED).
    assert lane.budget_decision is not None
    assert lane.budget_decision.action == ROUTE_FLAG
    assert result.budget_queue[0].action == ROUTE_FLAG

    # Solodit folds into HISTORICAL_EXPLOIT *and* DUPLICATE_RISK; precedence
    # resolves to FLAG_DUPLICATE. Pin the real resolved action.
    assert lane.reasoning_action == ACTION_FLAG_DUPLICATE

    # The bright line still holds: never auto-promoted.
    assert result.results[0].state == STATE_NEEDS_POC
    assert result.results[0].state != STATE_SUBMISSION_READY


def test_default_adapter_historical_db_only_arms_template(tmp_path: Path) -> None:
    """GAP 3 (isolated HISTORICAL_EXPLOIT path): when only the injected
    HistoricalDB has a match (the injected SoloditClient is key-free, so it is a
    guaranteed no-op), the default _historical_recall_adapter still feeds the
    DeFiHackLabs hit into the lane and the precedence-resolved action is the
    clean ARM_TEMPLATE -> ROUTE_ARM."""

    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)
    snapshot = {
        "block": "0x123",
        "contracts": [
            {"name": "Vault", "address": PROXY, "proxy": {"admin": "0x9999999999999999999999999999999999999999"}}
        ],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://rpc.local": snapshot})

    # Key-free SoloditClient: search() returns [] immediately (no key), no
    # network, no http_fn needed. Only the HistoricalDB can contribute.
    solodit = SoloditClient(api_key=None)
    history = HistoricalDB(exploits=(_euler_exploit(),))

    result = run_factory(
        targets,
        rpc_resolver=_resolver,
        collect=collector,
        vestige_client=FakeVestige(available=True),
        solodit_client=solodit,
        historical_db=history,
    )

    lane = result.results[0].lanes[0]

    # The DeFiHackLabs match reached the lane; no Solodit ref (key-free no-op).
    assert lane.reasoning_refs == ("defihacklabs:src/test/2023-03/Euler_exp.sol",)
    assert lane.reasoning_action == ACTION_ARM_TEMPLATE
    assert lane.budget_decision is not None
    assert lane.budget_decision.action == ROUTE_ARM
    assert result.budget_queue[0].action == ROUTE_ARM


# --------------------------------------------------------------------------- #
# GAP 1: the MOAT write-back. A finished run COMPOUNDS into memory.
#
# A finished factory run must dual-write capsules back to Vestige so future runs
# skip dead lanes and value-weight prior wins. The default writer ships them
# through the same stdio smart_ingest transport bounty-sim uses; tests inject a
# recorder so no subprocess or network is touched. The bright line holds: a
# write-back never produces a submission-ready signal.
# --------------------------------------------------------------------------- #


class RecordingWriter:
    """Captures the capsules passed to the MOAT write-back. No I/O."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def __call__(self, capsules: tuple) -> None:
        self.calls.append(capsules)

    @property
    def captured(self) -> tuple:
        return self.calls[0] if self.calls else ()


def test_write_vestige_false_never_calls_writer(tmp_path: Path) -> None:
    """Default read-only run: the write-back is inert and the writer is untouched."""

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
    writer = RecordingWriter()

    result = run_factory(
        targets,
        rpc_resolver=_resolver,
        collect=collector,
        vestige_client=FakeVestige(available=True),
        # write_vestige defaults to False; pass a writer anyway to prove it is
        # never invoked unless explicitly enabled.
        vestige_writer=writer,
    )

    # The run still classifies normally...
    assert result.results[0].state == STATE_NEEDS_POC
    # ...but the read/write split holds: nothing was written.
    assert writer.calls == []


def test_write_vestige_true_writes_dead_door_and_live_capsules(tmp_path: Path) -> None:
    """write_vestige=True dual-writes a dead-door capsule for the read-back-killed
    multisig lane AND a live capsule for the drifted proxy lane -- and never a
    submission-ready signal."""

    manifest = _write_manifest(tmp_path)
    targets = _write_targets(tmp_path, manifest)
    # Proxy admin drifts (live needs-PoC lane); the multisig lane does not drift.
    drifted = {
        "block": "0x123",
        "contracts": [
            {"name": "Vault", "address": PROXY, "proxy": {"admin": "0x9999999999999999999999999999999999999999"}}
        ],
        "multisigs": [{"name": "Gov", "address": SAFE, "threshold": 3}],
    }
    collector = FakeCollector(snapshots={"http://rpc.local": drifted})

    # Memory recalls the (no-drift) multisig lane as a prior dead-door, so a
    # dead-door capsule must be written for it even though it produced no finding.
    dead_sig = lane_signature("Acme", "Gov", "multisig_threshold_drift")
    vestige = FakeVestige(available=True, dead_signatures={dead_sig})
    writer = RecordingWriter()

    result = run_factory(
        targets,
        rpc_resolver=_resolver,
        collect=collector,
        vestige_client=vestige,
        write_vestige=True,
        vestige_writer=writer,
    )

    acme = result.results[0]
    assert acme.state == STATE_NEEDS_POC
    assert acme.state != STATE_SUBMISSION_READY  # BRIGHT LINE

    # The writer was called exactly once with this target's capsules.
    assert len(writer.calls) == 1
    capsules = writer.captured
    by_result: dict[str, list] = {}
    for capsule in capsules:
        by_result.setdefault(capsule.result, []).append(capsule)

    # (a) A dead-door capsule for the read-back-killed multisig lane.
    dead = by_result.get("closed_door", [])
    assert len(dead) == 1
    dead_cap = dead[0]
    assert dead_cap.lane == "multisig_threshold_drift"
    assert dead_cap.status == "closed_door"
    assert "dead-door" in dead_cap.tags
    # A future run's read-back must recognize this as a dead-door (marker present).
    assert any(
        marker in dead_cap.summary.lower() for marker in ("dead-door", "reopen_if")
    )

    # (b) A live capsule for the drifted proxy lane, enriched with routing memory.
    live = by_result.get("open_door", [])
    assert len(live) == 1
    live_cap = live[0]
    assert live_cap.workflow == "factory"
    assert live_cap.evidence.get("factory_signature") == lane_signature(
        "Acme", "Vault", "proxy_admin_drift"
    )
    assert live_cap.evidence.get("route_action")  # budget decision folded in

    # The bright line holds across every written capsule.
    assert all(c.status != STATE_SUBMISSION_READY for c in capsules)
    assert all(c.metadata.get("submission_ready") is False for c in capsules)
