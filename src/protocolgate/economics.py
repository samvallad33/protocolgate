"""CORE-0 routing economics ledger.

The router decides whether a lane should spend scan budget. The ledger records
those decisions and the realized value from proven findings so a caller can
report the economics of memory-as-router without doing any I/O here.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any

__all__ = ["EconomicsSnapshot", "ScanLedger"]


@dataclass(frozen=True)
class EconomicsSnapshot:
    """Immutable point-in-time report for one routed scan run."""

    scans_spent: int
    scans_skipped: int
    scan_cost_spent: float
    findings_proven: int
    realized_usd_impact: float
    compute_saved_percent: float
    roi: float
    realized_usd_per_scan: float
    cost_per_finding: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanLedger:
    """Mutable per-run tally for CORE-0 routing economics.

    ``scans_spent`` and ``scans_skipped`` are lane counts. ``scan_cost_spent``
    is the budget/cost denominator used for ROI and cost per finding.
    """

    scans_spent: int = 0
    scans_skipped: int = 0
    scan_cost_spent: float = 0.0
    findings_proven: int = 0
    realized_usd_impact: float = 0.0

    skipped_signatures: list[str] = field(default_factory=list)
    scanned_signatures: list[str] = field(default_factory=list)
    finding_signatures: list[str] = field(default_factory=list)

    def record_skip(self, signature: str | None = None) -> bool:
        """Record a dead-door lane skipped before spending scan budget."""

        if signature is not None and signature in self.skipped_signatures:
            return False
        self.scans_skipped += 1
        if signature is not None:
            self.skipped_signatures.append(signature)
        return True

    def record_scan(self, signature: str | None = None, cost: float = 1.0) -> bool:
        """Record one scan spent on a non-skip lane."""

        if signature is not None and signature in self.scanned_signatures:
            return False
        self.scans_spent += 1
        self.scan_cost_spent += _non_negative(cost)
        if signature is not None:
            self.scanned_signatures.append(signature)
        return True

    def record_finding(
        self, signature: str | None = None, usd_impact: float = 0.0
    ) -> bool:
        """Record a proven finding and its realized USD impact."""

        if signature is not None and signature in self.finding_signatures:
            return False
        self.findings_proven += 1
        self.realized_usd_impact += _non_negative(usd_impact)
        if signature is not None:
            self.finding_signatures.append(signature)
        return True

    def record_decision(
        self,
        decision: Any,
        *,
        finding_proven: bool = False,
        usd_impact: float = 0.0,
    ) -> bool:
        """Record a router ``BudgetDecision``-shaped object.

        The method uses duck typing to keep this module independent from the
        router module at import time. A skip counts as saved compute; any
        non-skip counts as one scan with ``decision.est_scan_cost`` as cost.
        """

        signature = getattr(decision, "signature", None)
        if getattr(decision, "is_skip", False):
            return self.record_skip(signature)

        counted = self.record_scan(
            signature, cost=getattr(decision, "est_scan_cost", 1.0)
        )
        if counted and finding_proven:
            self.record_finding(signature, usd_impact=usd_impact)
        return counted

    @property
    def candidate_lanes(self) -> int:
        return self.scans_spent + self.scans_skipped

    @property
    def compute_saved_percent(self) -> float:
        """Percent of candidate lanes skipped before scan spend."""

        if self.candidate_lanes <= 0:
            return 0.0
        return (self.scans_skipped / self.candidate_lanes) * 100.0

    @property
    def roi(self) -> float:
        """Realized USD impact per scan-cost unit spent."""

        if self.scan_cost_spent <= 0.0:
            return 0.0
        return self.realized_usd_impact / self.scan_cost_spent

    @property
    def realized_usd_per_scan(self) -> float:
        """Realized USD impact per scan count."""

        if self.scans_spent <= 0:
            return 0.0
        return self.realized_usd_impact / self.scans_spent

    @property
    def cost_per_finding(self) -> float:
        """Scan-cost units spent per proven finding."""

        if self.findings_proven <= 0:
            return math.inf
        return self.scan_cost_spent / self.findings_proven

    def snapshot(self) -> EconomicsSnapshot:
        return EconomicsSnapshot(
            scans_spent=self.scans_spent,
            scans_skipped=self.scans_skipped,
            scan_cost_spent=self.scan_cost_spent,
            findings_proven=self.findings_proven,
            realized_usd_impact=self.realized_usd_impact,
            compute_saved_percent=self.compute_saved_percent,
            roi=self.roi,
            realized_usd_per_scan=self.realized_usd_per_scan,
            cost_per_finding=self.cost_per_finding,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.snapshot().to_dict()


def _non_negative(value: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, number)
