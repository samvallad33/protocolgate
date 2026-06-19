"""Tests for the Solodit (Cyfrin) historical-findings connector.

No network: a fake ``http_fn`` returns canned payloads so every path is verified
deterministically. Covers the load-bearing contract:

1. Drift types map to the correct Solodit tag sets.
2. A configured key + good payload parses into SoloditFinding rows.
3. Missing key degrades to [] WITHOUT ever calling http_fn.
4. Any http_fn error degrades to [] (never raises).
5. The TTL cache serves a hit without a second http_fn call, and expires.
"""

from __future__ import annotations

import urllib.error

import pytest

from protocolgate.connectors import solodit
from protocolgate.connectors.solodit import (
    API_KEY_HEADER,
    DRIFT_TAG_MAP,
    SoloditClient,
    SoloditFinding,
    tags_for_drift,
)


class FakeHttp:
    """Records every call and returns a scripted body (or raises)."""

    def __init__(self, body=None, raises: Exception | None = None):
        self.body = body
        self.raises = raises
        self.calls: list[dict] = []

    def __call__(self, url, data, headers, timeout):
        import json

        self.calls.append(
            {
                "url": url,
                "data": json.loads(data.decode("utf-8")),
                "headers": headers,
                "timeout": timeout,
            }
        )
        if self.raises is not None:
            raise self.raises
        return self.body


def _payload(*titles: str) -> dict:
    return {
        "findings": [
            {
                "id": f"sol-{i}",
                "title": title,
                "severity": "High",
                "protocol": "DreUSD",
                "tags": ["Access Control", "Admin"],
                "quality": "high",
                "rarity": "common",
                "url": f"https://solodit.cyfrin.io/issues/sol-{i}",
                "summary": f"summary for {title}",
            }
            for i, title in enumerate(titles)
        ]
    }


# -- 1. drift -> tag mapping -------------------------------------------------


def test_drift_tag_map_covers_all_six_drift_types():
    # The six concrete drift lanes the factory arms, plus the generic fallback.
    for drift_type in (
        "proxy_admin_drift",
        "multisig_threshold_drift",
        "oracle_config_drift",
        "timelock_drift",
        "guardian_pause_drift",
        "bridge_config_drift",
    ):
        assert drift_type in DRIFT_TAG_MAP
        assert DRIFT_TAG_MAP[drift_type], f"{drift_type} maps to an empty tag set"


def test_tags_for_drift_known_and_unknown():
    assert tags_for_drift("proxy_admin_drift") == ["Access Control", "Admin", "Proxy"]
    assert tags_for_drift("multisig_threshold_drift") == ["Quorum", "DAO", "Multisig"]
    assert tags_for_drift("oracle_config_drift") == ["Oracle", "Stale Price"]
    assert tags_for_drift("timelock_drift") == ["Timelock", "Delay"]
    # Unknown drift type falls back to a non-empty default, never [].
    assert tags_for_drift("totally_unknown_drift") == ["Access Control"]


def test_search_uses_mapped_tags_and_sends_key_header():
    http = FakeHttp(body=_payload("Admin role left unguarded"))
    client = SoloditClient(api_key="secret-key", http_fn=http)

    findings = client.search(tags_for_drift("proxy_admin_drift"), keywords="upgrade")

    assert len(findings) == 1
    assert isinstance(findings[0], SoloditFinding)
    assert findings[0].id == "sol-0"
    assert findings[0].title == "Admin role left unguarded"

    # One call, hitting the right URL, with the mapped tags + key header.
    assert len(http.calls) == 1
    call = http.calls[0]
    assert call["url"] == "https://solodit.cyfrin.io/api/v1/solodit/findings"
    assert call["data"]["tags"] == ["Access Control", "Admin", "Proxy"]
    assert call["data"]["keywords"] == "upgrade"
    assert call["headers"][API_KEY_HEADER] == "secret-key"


def test_search_drift_convenience_maps_drift_type():
    http = FakeHttp(body=_payload("Stale oracle price accepted"))
    client = SoloditClient(api_key="k", http_fn=http)

    findings = client.search_drift("oracle_config_drift")

    assert findings[0].title == "Stale oracle price accepted"
    assert http.calls[0]["data"]["tags"] == ["Oracle", "Stale Price"]


# -- 2. parsing tolerance ----------------------------------------------------


def test_parses_full_finding_fields():
    http = FakeHttp(body=_payload("Threshold lowered to 1"))
    client = SoloditClient(api_key="k", http_fn=http)

    f = client.search(["Quorum"])[0]
    assert f.severity == "High"
    assert f.protocol == "DreUSD"
    assert f.tags == ("Access Control", "Admin")
    assert f.quality == "high"
    assert f.rarity == "common"
    assert f.url == "https://solodit.cyfrin.io/issues/sol-0"
    assert f.summary == "summary for Threshold lowered to 1"


def test_parses_and_strips_tag_fields():
    http = FakeHttp(
        body={
            "findings": [
                {
                    "id": "x1",
                    "title": "tag cleanup",
                    "tags": [" Admin ", "", "Proxy"],
                }
            ]
        }
    )
    client = SoloditClient(api_key="k", http_fn=http)

    assert client.search(["Admin"])[0].tags == ("Admin", "Proxy")


def test_bare_list_envelope_is_accepted():
    http = FakeHttp(body=[{"id": "x1", "title": "bare list row"}])
    client = SoloditClient(api_key="k", http_fn=http)
    findings = client.search(["Admin"])
    assert [f.title for f in findings] == ["bare list row"]


def test_limit_is_respected():
    http = FakeHttp(body=_payload("a", "b", "c", "d"))
    client = SoloditClient(api_key="k", http_fn=http)
    findings = client.search(["Admin"], limit=2)
    assert len(findings) == 2


def test_unusable_rows_are_dropped():
    http = FakeHttp(body={"findings": ["not-a-dict", {"severity": "High"}, {"id": "ok"}]})
    client = SoloditClient(api_key="k", http_fn=http)
    findings = client.search(["Admin"])
    # The string and the id/title-less dict are dropped; only "ok" survives.
    assert [f.id for f in findings] == ["ok"]


def test_non_dict_payload_degrades_to_empty():
    http = FakeHttp(body="not json object")
    client = SoloditClient(api_key="k", http_fn=http)
    assert client.search(["Admin"]) == []


# -- 3. missing key ----------------------------------------------------------


def test_missing_key_returns_empty_without_calling_http():
    http = FakeHttp(body=_payload("should never be fetched"))
    client = SoloditClient(api_key=None, http_fn=http)

    assert client.has_key is False
    assert client.search(tags_for_drift("proxy_admin_drift")) == []
    # Bright line: no key means no network call at all.
    assert http.calls == []


def test_empty_string_key_is_treated_as_missing():
    http = FakeHttp(body=_payload("nope"))
    client = SoloditClient(api_key="", http_fn=http)
    assert client.has_key is False
    assert client.search(["Admin"]) == []
    assert http.calls == []


# -- 4. error degradation ----------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        urllib.error.URLError("down"),
        TimeoutError("slow"),
        ValueError("bad json"),
        OSError("socket"),
        RuntimeError("unexpected"),
    ],
)
def test_any_http_error_degrades_to_empty(exc):
    http = FakeHttp(raises=exc)
    client = SoloditClient(api_key="k", http_fn=http)
    # Never raises, regardless of the failure mode.
    assert client.search(["Admin"]) == []


# -- 5. TTL cache ------------------------------------------------------------


class FakeClock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t


def test_cache_hit_skips_second_http_call():
    http = FakeHttp(body=_payload("cached row"))
    clock = FakeClock(1000.0)
    client = SoloditClient(api_key="k", http_fn=http, clock=clock, cache_ttl=300.0)

    first = client.search(["Admin"], keywords="x")
    second = client.search(["Admin"], keywords="x")

    assert [f.id for f in first] == [f.id for f in second]
    # Cache hit: still exactly one network call.
    assert len(http.calls) == 1


def test_cache_normalizes_equivalent_tag_sets():
    http = FakeHttp(body=_payload("cached row"))
    client = SoloditClient(api_key="k", http_fn=http, cache_ttl=300.0)

    first = client.search(["Admin", "Proxy"], keywords=" upgrade ")
    second = client.search([" proxy ", "admin"], keywords="upgrade")

    assert [f.id for f in first] == [f.id for f in second]
    assert len(http.calls) == 1


def test_cache_expires_after_ttl():
    http = FakeHttp(body=_payload("row"))
    clock = FakeClock(0.0)
    client = SoloditClient(api_key="k", http_fn=http, clock=clock, cache_ttl=300.0)

    client.search(["Admin"])
    clock.t = 301.0  # past the TTL
    client.search(["Admin"])

    assert len(http.calls) == 2


def test_distinct_queries_are_cached_separately():
    http = FakeHttp(body=_payload("row"))
    client = SoloditClient(api_key="k", http_fn=http)

    client.search(["Admin"], keywords="a")
    client.search(["Admin"], keywords="b")  # different keywords -> different key

    assert len(http.calls) == 2
