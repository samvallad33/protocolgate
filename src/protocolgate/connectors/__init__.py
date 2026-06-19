"""External historical-findings connectors (INPUTS ONLY).

Connectors in this package fetch public audit/exploit corpora (Solodit,
DeFiHackLabs, ...) so the factory can arm templates and prioritise drift lanes.

Bright line: these sources are a public utility, never the moat. The moat is the
private trust-weighted Vestige layer that compounds as strong matches are
dual-written back. Connectors NEVER submit, NEVER hold keys, NEVER gate a
verdict, and degrade to empty (never raise) on any error.
"""

from __future__ import annotations

from protocolgate.connectors.solodit import (
    DRIFT_TAG_MAP,
    SoloditClient,
    SoloditFinding,
    tags_for_drift,
)

__all__ = [
    "DRIFT_TAG_MAP",
    "SoloditClient",
    "SoloditFinding",
    "tags_for_drift",
]
