"""Tests for CORE-0 routing economics."""

from __future__ import annotations

import math

import pytest

from protocolgate.economics import EconomicsSnapshot, ScanLedger
from protocolgate.router import BudgetDecision, ROUTE_PROCEED, ROUTE_SKIP


def _decision(
    signature: str,
    *,
    action: str = ROUTE_PROCEED,
    cost: float = 1.0,
    expected_value: float = 0.0,
) -> BudgetDecision:
    is_skip = action == ROUTE_SKIP
    return BudgetDecision(
        signature=signature,
        action=action,
        weight=0.0 if is_skip else 1.0,
        evidence=("mem-1",),
        rationale=f"{signature}: {action}",
        est_scan_cost=0.0 if is_skip else cost,
        expected_value=0.0 if is_skip else expected_value,
    )


def test_empty_ledger_is_zero_division_safe():
    ledger = ScanLedger()
    snapshot = ledger.snapshot()

    assert snapshot == EconomicsSnapshot(
        scans_spent=0,
        scans_skipped=0,
        scan_cost_spent=0.0,
        findings_proven=0,
        realized_usd_impact=0.0,
        compute_saved_percent=0.0,
        roi=0.0,
        realized_usd_per_scan=0.0,
        cost_per_finding=math.inf,
    )


def test_record_decision_tracks_skip_scan_finding_and_value_metrics():
    ledger = ScanLedger()

    assert ledger.record_decision(_decision("A:dead:k", action=ROUTE_SKIP)) is True
    assert (
        ledger.record_decision(
            _decision("A:live:k", cost=2.5, expected_value=1_000.0),
            finding_proven=True,
            usd_impact=1_000.0,
        )
        is True
    )

    snapshot = ledger.snapshot()
    assert snapshot.scans_spent == 1
    assert snapshot.scans_skipped == 1
    assert snapshot.scan_cost_spent == pytest.approx(2.5)
    assert snapshot.findings_proven == 1
    assert snapshot.realized_usd_impact == pytest.approx(1_000.0)
    assert snapshot.compute_saved_percent == pytest.approx(50.0)
    assert snapshot.roi == pytest.approx(400.0)
    assert snapshot.realized_usd_per_scan == pytest.approx(1_000.0)
    assert snapshot.cost_per_finding == pytest.approx(2.5)


def test_compute_saved_percent_uses_lane_counts_not_scan_cost():
    ledger = ScanLedger()
    ledger.record_skip("A:dead-1:k")
    ledger.record_skip("A:dead-2:k")
    ledger.record_scan("A:expensive:k", cost=25.0)

    assert ledger.compute_saved_percent == pytest.approx(66.6666666667)
    assert ledger.scan_cost_spent == pytest.approx(25.0)


def test_records_dedupe_by_signature_and_clamp_negative_values():
    ledger = ScanLedger()

    assert ledger.record_skip("A:dead:k") is True
    assert ledger.record_skip("A:dead:k") is False
    assert ledger.record_scan("A:scan:k", cost=-5.0) is True
    assert ledger.record_scan("A:scan:k", cost=99.0) is False
    assert ledger.record_finding("A:scan:k", usd_impact=-10.0) is True
    assert ledger.record_finding("A:scan:k", usd_impact=10_000.0) is False

    assert ledger.scans_skipped == 1
    assert ledger.scans_spent == 1
    assert ledger.scan_cost_spent == 0.0
    assert ledger.findings_proven == 1
    assert ledger.realized_usd_impact == 0.0


def test_cost_per_finding_is_inf_until_a_finding_is_proven():
    ledger = ScanLedger()
    ledger.record_scan("A:miss:k", cost=3.0)

    assert ledger.cost_per_finding is math.inf
    assert ledger.roi == 0.0
    assert ledger.realized_usd_per_scan == 0.0


def test_to_dict_returns_snapshot_metrics():
    ledger = ScanLedger()
    ledger.record_decision(_decision("A:live:k", cost=4.0), finding_proven=True, usd_impact=20.0)

    as_dict = ledger.to_dict()

    assert as_dict["scans_spent"] == 1
    assert as_dict["scan_cost_spent"] == pytest.approx(4.0)
    assert as_dict["roi"] == pytest.approx(5.0)
    assert as_dict["realized_usd_per_scan"] == pytest.approx(20.0)
    assert as_dict["cost_per_finding"] == pytest.approx(4.0)
