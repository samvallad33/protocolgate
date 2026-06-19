"""Tests for the Vestige-backed cross-bounty invariant miner (CORE-0).

No network: an injected ``query_fn`` returns canned ``MemoryResult`` objects so
the mining logic is verified deterministically.
"""

from __future__ import annotations

from protocolgate.invariant_miner import (
    DEFAULT_TRUST_FLOOR,
    CandidateInvariant,
    family_history_query,
    mine_invariant_report,
    mine_invariants,
    render_foundry_invariant,
    route_template_for,
)
from protocolgate.memory import MemoryEvidence, MemoryResult


def _evidence(memory_id: str, trust: float, preview: str) -> MemoryEvidence:
    return MemoryEvidence(
        memory_id=memory_id,
        trust=trust,
        date="2026-06-19",
        preview=preview,
        role="primary",
        source="test",
    )


def _result(evidence: tuple[MemoryEvidence, ...], available: bool = True) -> MemoryResult:
    return MemoryResult(
        available=available,
        confidence=0.8,
        evidence=evidence,
        contradictions=0,
    )


def test_family_history_query_mentions_family():
    q = family_history_query("erc4626-vaults")
    assert "erc4626-vaults" in q
    assert "dead-door" in q
    assert "duplicate" in q
    assert "paid" in q


def test_mines_candidates_from_recall():
    recall = _result(
        (
            _evidence("m1", 0.7, "proxy admin must remain the governance multisig after upgrade"),
            _evidence("m2", 0.65, "proxy admin must remain the governance multisig after upgrade"),
            _evidence("m3", 0.6, "withdrawal queue ordering must be preserved across claims"),
        )
    )

    def query_fn(_family: str, _query: str) -> MemoryResult:
        return recall

    candidates = mine_invariants("vaults", None, query_fn=query_fn, min_support=1)
    assert candidates, "expected at least one mined invariant"
    assert all(isinstance(c, CandidateInvariant) for c in candidates)
    # every candidate carries the source refs it was mined from (the moat: provenance)
    assert all(c.source_refs for c in candidates)


def test_mines_signal_backed_routing_tags_and_templates():
    recall = _result(
        (
            _evidence("win", 0.9, "proxy admin drift PAID confirmed critical on similar vault"),
            _evidence("dead", 0.8, "proxy admin lane was a dead-door known-issue; reopen_if scope changes"),
            _evidence("dup", 0.75, "this exact proxy admin finding already submitted / duplicate"),
        )
    )

    def query_fn(_family: str, _query: str) -> MemoryResult:
        return recall

    report = mine_invariant_report("vaults", None, query_fn=query_fn)
    inv = next(c for c in report.candidates if c.name == "upgrade_authority")

    assert inv.support == 3
    assert inv.source_refs == ("win", "dead", "dup")
    assert "memory:prior-win" in inv.routing_tags
    assert "memory:dead-door" in inv.routing_tags
    assert "memory:duplicate-risk" in inv.routing_tags
    assert "route:prioritize" in inv.routing_tags
    assert "route:skip" in inv.routing_tags
    assert "route:flag" in inv.routing_tags
    assert "proxy_admin_drift" in inv.templates
    assert "template:proxy_admin_drift" in report.routing_tags

    payload = route_template_for(inv)
    assert payload.name == "upgrade_authority"
    assert payload.templates[0] == "proxy_admin_drift"
    assert payload.source_refs == inv.source_refs


def test_local_fallback_drives_deterministic_tests_without_client():
    fallback = (
        _evidence("oracle-win", 0.82, "oracle stale price prior win paid bounty"),
    )

    report = mine_invariant_report("oracles", None, local_fallback=fallback)

    assert report.used_fallback is True
    assert [c.name for c in report.candidates] == ["oracle_bounds"]
    assert "oracle_bounds" in report.templates


def test_trust_floor_filters_low_trust_evidence():
    recall = _result(
        (
            _evidence("low", 0.2, "some weak signal about admin drift that should be ignored"),
        )
    )

    def query_fn(_family: str, _query: str) -> MemoryResult:
        return recall

    candidates = mine_invariants(
        "vaults", None, query_fn=query_fn, trust_floor=DEFAULT_TRUST_FLOOR
    )
    assert candidates == []


def test_unavailable_recall_yields_no_candidates():
    def query_fn(_family: str, _query: str) -> MemoryResult:
        return _result((), available=False)

    assert mine_invariants("vaults", None, query_fn=query_fn) == []


def test_render_produces_solidity_with_todo_and_no_fake_pass():
    inv = CandidateInvariant(
        name="proxy_admin_stable",
        predicate="proxy admin must remain the governance multisig",
        source_refs=("m1", "m2"),
        support=2,
        trust=0.7,
        rationale="recurred across 2 prior bounties",
    )
    src = render_foundry_invariant(inv)
    assert "function" in src
    # honest harness: never a fake-passing assertion; the body is a marked TODO.
    assert "TODO" in src
    assert "m1" in src or "proxy admin" in src.lower()
