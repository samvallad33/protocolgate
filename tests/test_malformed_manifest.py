"""Regression tests for malformed-manifest handling.

These cover two crash paths that previously escaped as uncaught tracebacks:

- non-numeric values in numeric control-plane fields (multisig threshold,
  treasury bps, oracle staleness, governance quorum/voting period, timelock
  delay) used to raise a bare ``ValueError``;
- privileged proposals mixing timezone-aware and naive timestamps used to raise
  ``TypeError: can't subtract offset-naive and offset-aware datetimes``.
"""

from datetime import timezone

import pytest

from protocolgate.manifest import ManifestError, normalize_manifest
from protocolgate.rules import evaluate_manifest
from protocolgate.rules_proposal_intent import _parse_timestamp
from protocolgate.rules_support import as_int


def test_as_int_coerces_and_defaults() -> None:
    assert as_int(None, field="x") == 0
    assert as_int("", field="x") == 0
    assert as_int(5, field="x") == 5
    assert as_int("3", field="x") == 3
    assert as_int(7, field="x", default=1) == 7


def test_as_int_rejects_non_numeric() -> None:
    with pytest.raises(ManifestError):
        as_int("not-a-number", field="multisigs[0].threshold")


def test_as_int_rejects_bool() -> None:
    # bool is an int subclass in Python; a boolean threshold is almost certainly
    # a manifest mistake, so reject it rather than silently treating it as 0/1.
    with pytest.raises(ManifestError):
        as_int(True, field="multisigs[0].threshold")


def test_non_numeric_threshold_raises_manifest_error_not_traceback() -> None:
    manifest = normalize_manifest(
        {"multisigs": [{"name": "council", "threshold": "abc", "signers": ["0x1", "0x2"]}]}
    )
    with pytest.raises(ManifestError):
        evaluate_manifest(manifest)


def test_parse_timestamp_normalizes_naive_to_utc() -> None:
    aware = _parse_timestamp("2026-05-05T00:00:00Z")
    naive = _parse_timestamp("2026-05-04T00:00:00")

    assert aware is not None and naive is not None
    assert aware.tzinfo is not None
    assert naive.tzinfo is timezone.utc
    # The subtraction that previously raised TypeError now succeeds.
    assert (aware - naive).total_seconds() == 86_400.0
