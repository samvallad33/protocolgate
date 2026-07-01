"""Advisory institutional-memory layer for ProtocolGate.

This module is an OPTIONAL, NON-AUTHORITATIVE evidence layer. It queries a
locally running Vestige memory server and attaches institutional context (audit
findings, prior decisions, operating intent) to deterministic ProtocolGate
findings.

Design constraints (do not violate):

- The deterministic engine in ``rules.py`` is the ONLY thing that decides
  pass/fail. Memory never gates, never changes a verdict, never suppresses a
  finding.
- If Vestige is unreachable, malformed, or returns nothing, evidence simply
  degrades to empty. ProtocolGate output is unaffected.
- Evidence is labelled "advisory" everywhere it is rendered.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

DEFAULT_BASE_URL = "http://localhost:3927"
DEFAULT_TIMEOUT = 4.0
DEFAULT_DEPTH = 12
# Only surface memories the memory engine itself scores as reasonably trusted.
DEFAULT_TRUST_FLOOR = 0.45
# Keep evidence blocks reviewable: strongest few items per finding.
DEFAULT_MAX_ITEMS = 4


@dataclass(frozen=True)
class MemoryEvidence:
    """A single advisory memory item attached to a finding."""

    memory_id: str
    trust: float
    date: str
    preview: str
    role: str
    source: str = ""

    def render_line(self) -> str:
        ref = self.memory_id[:8] if self.memory_id else "????????"
        date = (self.date or "")[:10]
        suffix = f" source={self.source}" if self.source else ""
        return f"[{ref}] trust={self.trust:.2f} date={date}{suffix}: {self.preview}"


@dataclass(frozen=True)
class MemoryResult:
    """Result of an advisory memory lookup for one finding."""

    available: bool
    confidence: float
    evidence: tuple[MemoryEvidence, ...]
    contradictions: int = 0

    @property
    def has_evidence(self) -> bool:
        return bool(self.evidence)


class VestigeClient:
    """Thin, dependency-free client for the local Vestige dashboard REST API.

    Uses only the stdlib so ProtocolGate stays lightweight. The dashboard
    ``/api/deep_reference`` endpoint is the same retrieval engine used by
    Vestige's own hooks; see ``vestige/hooks/sanhedrin-local.py``.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        depth: int = DEFAULT_DEPTH,
        trust_floor: float = DEFAULT_TRUST_FLOOR,
        max_items: int = DEFAULT_MAX_ITEMS,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.depth = depth
        self.trust_floor = trust_floor
        self.max_items = max_items

    @property
    def health_url(self) -> str:
        return f"{self.base_url}/api/health"

    @property
    def deep_reference_url(self) -> str:
        return f"{self.base_url}/api/deep_reference"

    def is_available(self) -> bool:
        """Return True only if the memory server answers a health check."""
        try:
            with urllib.request.urlopen(self.health_url, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            return str(payload.get("status", "")).lower() == "healthy"
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            return False

    def query(self, text: str) -> MemoryResult:
        """Fetch advisory evidence for a finding. Never raises; degrades to empty."""
        body = json.dumps({"query": text[:1500], "depth": self.depth}).encode("utf-8")
        request = urllib.request.Request(
            self.deep_reference_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            return MemoryResult(available=False, confidence=0.0, evidence=())

        if not isinstance(data, dict):
            return MemoryResult(available=False, confidence=0.0, evidence=())

        return self._parse(data)

    def _parse(self, data: dict) -> MemoryResult:
        confidence = _safe_float(data.get("confidence"))
        items: list[MemoryEvidence] = []
        seen: set[str] = set()

        recommended = data.get("recommended")
        if isinstance(recommended, dict):
            rec = _evidence_from_recommended(recommended)
            if rec is not None and rec.trust >= self.trust_floor:
                items.append(rec)
                seen.add(rec.memory_id)

        for raw in data.get("evidence") or []:
            if len(items) >= self.max_items:
                break
            if not isinstance(raw, dict):
                continue
            ev = _evidence_from_node(raw)
            if ev is None or ev.trust < self.trust_floor or ev.memory_id in seen:
                continue
            items.append(ev)
            seen.add(ev.memory_id)

        contradictions = data.get("contradictions") or []
        return MemoryResult(
            available=True,
            confidence=confidence,
            evidence=tuple(items),
            contradictions=len(contradictions) if isinstance(contradictions, list) else 0,
        )


def finding_query(rule_id: str, message: str, path: str) -> str:
    """Build the retrieval query for a single deterministic finding."""
    return f"{rule_id} {message} {path}".strip()


def _evidence_from_node(node: dict) -> MemoryEvidence | None:
    preview = str(node.get("preview") or "").strip()
    if not preview:
        return None
    return MemoryEvidence(
        memory_id=str(node.get("id") or ""),
        trust=_safe_float(node.get("trust")),
        date=str(node.get("date") or ""),
        preview=_clip(preview, 300),
        role=str(node.get("role") or "?"),
        source=str(node.get("source") or ""),
    )


def _evidence_from_recommended(rec: dict) -> MemoryEvidence | None:
    preview = str(rec.get("answer_preview") or rec.get("preview") or "").strip()
    if not preview:
        return None
    return MemoryEvidence(
        memory_id=str(rec.get("memory_id") or rec.get("id") or ""),
        trust=_safe_float(rec.get("trust_score") or rec.get("trust")),
        date=str(rec.get("date") or ""),
        preview=_clip(preview, 400),
        role="recommended",
        source=str(rec.get("source") or ""),
    )


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _clip(text: str, limit: int) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."
