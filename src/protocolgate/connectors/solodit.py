"""Solodit (Cyfrin) historical-findings connector.

Pulls public audit findings from Solodit so the factory can arm PoC templates
and prioritise drift lanes with prior art ("this exact misconfiguration has been
paid out before"). Solodit is an INPUT ONLY -- a public utility, never the moat.
The moat is dual-writing strong matches into Vestige so the private,
trust-weighted layer compounds over time.

Design constraints (load-bearing -- do not violate):

- Read-only. No keys are required to *run* the factory; a missing/invalid key
  simply degrades the connector to an empty result. It never blocks a scan.
- Dependency-free. stdlib ``urllib`` only, so the policy gate stays unbound to
  any HTTP library.
- Never raises. Any network error, non-200, malformed JSON, or missing key
  returns ``[]``. A connector outage must never crash a scan or masquerade as
  "no prior art" in a way that changes a verdict.
- Injectable I/O. ``http_fn`` is swappable so tests run with zero network.
- Bounded. A small in-memory TTL cache keeps repeated drift lookups cheap
  within a single factory run without persisting anything to disk.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

DEFAULT_BASE_URL = "https://solodit.cyfrin.io"
DEFAULT_TIMEOUT = 15.0
DEFAULT_LIMIT = 10
# Repeated lookups for the same drift lane inside one factory run are common;
# 5 minutes keeps them free without ever going stale within a session.
SEARCH_CACHE_TTL = 300.0
API_KEY_HEADER = "X-Cyfrin-API-Key"
SEARCH_PATH = "/api/v1/solodit/findings"

# An ``http_fn`` takes (url, data, headers, timeout) and returns the decoded JSON
# body. urllib is the default; tests inject a fake so no socket is ever opened.
HttpFn = Callable[[str, bytes, dict[str, str], float], object]


# ---------------------------------------------------------------------------
# Drift-type -> Solodit tag mapping
#
# The factory speaks in drift types (proxy_admin_drift, multisig_threshold_drift,
# ...). Solodit indexes findings by free-form tags. This map is the bridge: it
# turns "this lane is a proxy-admin drift" into "fetch Solodit's Access
# Control / Admin / Proxy corpus", which is the prior art that arms a template.
# ---------------------------------------------------------------------------
DRIFT_TAG_MAP: dict[str, tuple[str, ...]] = {
    "proxy_admin_drift": ("Access Control", "Admin", "Proxy"),
    "multisig_threshold_drift": ("Quorum", "DAO", "Multisig"),
    "oracle_config_drift": ("Oracle", "Stale Price"),
    "timelock_drift": ("Timelock", "Delay"),
    "guardian_pause_drift": ("Access Control", "Pause", "Guardian"),
    "bridge_config_drift": ("Bridge", "Cross-chain"),
    # Generic fallback lane: cast a slightly wider configuration net.
    "runtime_configuration_drift": ("Configuration", "Access Control"),
}

# A drift type we have no specific corpus for still gets a sensible default so a
# new lane never silently fetches nothing.
DEFAULT_DRIFT_TAGS: tuple[str, ...] = ("Access Control",)


def tags_for_drift(drift_type: str) -> list[str]:
    """Return the Solodit tag set to search for a given drift type.

    Unknown drift types fall back to a broad access-control net rather than an
    empty query, so a brand-new lane still surfaces prior art.
    """

    return list(DRIFT_TAG_MAP.get(drift_type, DEFAULT_DRIFT_TAGS))


@dataclass(frozen=True)
class SoloditFinding:
    """One historical Solodit finding (prior art for a drift lane)."""

    id: str
    title: str
    severity: str
    protocol: str
    tags: tuple[str, ...]
    quality: str
    rarity: str
    url: str
    summary: str


@dataclass
class _CacheEntry:
    expires_at: float
    value: list[SoloditFinding]


def _default_http_fn(
    url: str, data: bytes, headers: dict[str, str], timeout: float
) -> object:
    """urllib-backed POST. Raises on any transport/decoding failure.

    The client wraps every call in a try/except, so raising here is the
    contract: the failure is caught one level up and degraded to ``[]``.
    """

    request = urllib.request.Request(
        url, data=data, headers=headers, method="POST"
    )
    with urllib.request.urlopen(request, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class SoloditClient:
    """Thin, dependency-free client for Solodit's historical-findings API.

    Never raises: every public method degrades to an empty list on missing key,
    network error, non-dict payload, or malformed rows.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        *,
        http_fn: HttpFn | None = None,
        cache_ttl: float = SEARCH_CACHE_TTL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.api_key = api_key or None
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._http_fn = http_fn or _default_http_fn
        self._cache_ttl = cache_ttl
        self._clock = clock
        self._cache: dict[tuple, _CacheEntry] = {}

    @property
    def search_url(self) -> str:
        return f"{self.base_url}{SEARCH_PATH}"

    @property
    def has_key(self) -> bool:
        return bool(self.api_key)

    def search(
        self, tags: list[str], keywords: str = "", limit: int = DEFAULT_LIMIT
    ) -> list[SoloditFinding]:
        """Search Solodit by tag set + keywords. Never raises; degrades to [].

        Returns ``[]`` immediately when no API key is configured (the factory
        runs key-free by design) or on any error. Results are cached per
        (tags, keywords, limit) for ``cache_ttl`` seconds.
        """

        if not self.has_key:
            return []

        key = (_cache_tags(tags), keywords.strip(), int(limit))
        cached = self._cache_get(key)
        if cached is not None:
            return cached

        payload = json.dumps(
            {"tags": list(tags), "keywords": keywords, "limit": int(limit)}
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            API_KEY_HEADER: self.api_key or "",
        }

        try:
            body = self._http_fn(self.search_url, payload, headers, self.timeout)
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            return []
        except Exception:
            # A connector outage must never crash a scan. Any unexpected error
            # from an injected http_fn degrades to empty, same as a timeout.
            return []

        findings = _parse_findings(body, limit=int(limit))
        self._cache_set(key, findings)
        return findings

    def search_drift(
        self, drift_type: str, keywords: str = "", limit: int = DEFAULT_LIMIT
    ) -> list[SoloditFinding]:
        """Convenience: search the tag set mapped to a drift type."""

        return self.search(tags_for_drift(drift_type), keywords=keywords, limit=limit)

    # -- cache ------------------------------------------------------------

    def _cache_get(self, key: tuple) -> list[SoloditFinding] | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        if entry.expires_at <= self._clock():
            self._cache.pop(key, None)
            return None
        return entry.value

    def _cache_set(self, key: tuple, value: list[SoloditFinding]) -> None:
        if self._cache_ttl <= 0:
            return
        self._cache[key] = _CacheEntry(
            expires_at=self._clock() + self._cache_ttl, value=value
        )


# ---------------------------------------------------------------------------
# Parsing -- tolerant of shape drift in the upstream API.
# ---------------------------------------------------------------------------
def _parse_findings(body: object, *, limit: int) -> list[SoloditFinding]:
    """Pull a list of findings out of whatever envelope the API returns.

    Accepts either a bare list or a dict with a ``findings``/``results``/``data``
    list. Anything else degrades to ``[]`` (never raises).
    """

    rows = _extract_rows(body)
    findings: list[SoloditFinding] = []
    for raw in rows:
        if limit and len(findings) >= limit:
            break
        finding = _finding_from_row(raw)
        if finding is not None:
            findings.append(finding)
    return findings


def _extract_rows(body: object) -> list:
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in ("findings", "results", "data", "items"):
            value = body.get(key)
            if isinstance(value, list):
                return value
    return []


def _finding_from_row(raw: object) -> SoloditFinding | None:
    if not isinstance(raw, dict):
        return None
    title = str(raw.get("title") or raw.get("name") or "").strip()
    finding_id = str(raw.get("id") or raw.get("finding_id") or "").strip()
    # A row with neither an id nor a title is unusable noise.
    if not finding_id and not title:
        return None
    return SoloditFinding(
        id=finding_id,
        title=title,
        severity=str(raw.get("severity") or "").strip(),
        protocol=str(raw.get("protocol") or raw.get("project") or "").strip(),
        tags=_as_str_tuple(raw.get("tags")),
        quality=str(raw.get("quality") or "").strip(),
        rarity=str(raw.get("rarity") or "").strip(),
        url=str(raw.get("url") or raw.get("link") or "").strip(),
        summary=str(raw.get("summary") or raw.get("description") or "").strip(),
    )


def _as_str_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    if isinstance(value, str) and value.strip():
        return (value.strip(),)
    return ()


def _cache_tags(tags: list[str]) -> tuple[str, ...]:
    """Stable semantic cache key for a Solodit tag set."""

    return tuple(sorted({tag.strip().casefold() for tag in tags if tag.strip()}))
