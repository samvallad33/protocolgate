"""DeFiHackLabs exploit-PoC index (an INPUT, never the moat).

This module turns the public `DeFiHackLabs
<https://github.com/SunWeb3Sec/DeFiHackLabs>`_ corpus into a small, queryable
index of historical exploit PoCs. Its single job is to *arm a PoC template*:
when the reasoning lane raises ``HISTORICAL_EXPLOIT`` -> ``ARM_TEMPLATE``, this
index supplies the closest known on-chain exploit (its Foundry PoC path and the
fork block it reproduces at) so :mod:`protocolgate.forkpoc` and
:mod:`protocolgate.bounty_sim` have a concrete seed to start from.

Design constraints (load-bearing, do not violate):

- INPUT ONLY. DeFiHackLabs is a public utility. The moat is the trust-weighted
  Vestige layer that strong matches get dual-written into, never this corpus.
  Nothing here submits, signs, or sends; it only reads and ranks.
- DEGRADE GRACEFULLY. A missing path, an empty file, or unparseable lines must
  yield an EMPTY index, never an exception. The corpus is frequently absent in
  CI and on fresh checkouts; ``load`` must be safe there.
- DETERMINISTIC + STDLIB-ONLY. Parsing uses :mod:`re` only. Ranking is a pure,
  deterministic function of tag overlap so tests pin exact order with no
  network and no extra dependencies.
- INJECTABLE I/O FOR TESTS. ``load`` reads a path, but every behavior is also
  reachable via the in-memory ``HistoricalDB(exploits=...)`` constructor and the
  ``parse_readme`` string parser, so tests never touch the filesystem network.

The real corpus README groups entries by month and links a Foundry PoC, e.g.::

    ### 20230313 Euler Finance - Flashloan & Donate Attack
    - Lost: ~197M USD
    - [Euler.sol](https://github.com/.../src/test/2023-03/Euler_exp.sol)

    - 2023-03-13 [Euler] - [PoC](src/test/2023-03/Euler_exp.sol)

Different snapshots of the corpus format the index line slightly differently, so
the parser is intentionally tolerant: it pulls a date, a project name, and a
``.sol`` PoC path from each line, derives tags from the project + nearby words,
and skips anything it cannot anchor to a PoC path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# --------------------------------------------------------------------------- #
# Record
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class HistoricalExploit:
    """One reproducible historical exploit from the DeFiHackLabs corpus.

    ``tags`` is the searchable vocabulary for :meth:`HistoricalDB.match`: it
    always includes a normalized project token and any attack-pattern keywords
    recovered from the source line (e.g. ``"flashloan"``, ``"reentrancy"``).
    """

    date: str
    project: str
    tag: str
    poc_path: str
    fork_block: int | None = None
    chain: str = "ethereum"
    tags: tuple[str, ...] = ()

    def matches(self, query_tokens: Iterable[str]) -> int:
        """Number of distinct query tokens that overlap this exploit's tags."""

        wanted = {t for t in (_norm(q) for q in query_tokens) if t}
        if not wanted:
            return 0
        return len(wanted & set(self.tags))


# --------------------------------------------------------------------------- #
# Index
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class HistoricalDB:
    """An in-memory, queryable index of :class:`HistoricalExploit` records."""

    exploits: tuple[HistoricalExploit, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        # Accept any iterable (list/tuple/generator) from callers and tests and
        # freeze it. Frozen dataclass => set via object.__setattr__.
        object.__setattr__(self, "exploits", tuple(self.exploits))

    # -- construction ------------------------------------------------------- #

    @classmethod
    def load(cls, path: str | Path | None) -> "HistoricalDB":
        """Build an index from a DeFiHackLabs README file OR a directory.

        Degrades to an EMPTY index for any of: ``None`` path, missing path,
        unreadable file, empty content, or a directory with no recognizable
        README. Never raises.
        """

        if path is None:
            return cls()

        p = Path(path)
        text = _read_corpus_text(p)
        if not text:
            return cls()
        return cls.parse(text)

    @classmethod
    def parse(cls, readme_text: str) -> "HistoricalDB":
        """Build an index from raw README text. Never raises."""

        return cls(parse_readme(readme_text))

    # -- query -------------------------------------------------------------- #

    def match(
        self, tag: str, protocol_category: str = ""
    ) -> list[HistoricalExploit]:
        """Return exploits ranked by tag overlap (best first).

        ``tag`` and the optional ``protocol_category`` are tokenized and unioned
        into the query vocabulary, so callers can pass an attack family
        (``"proxy admin"``), a protocol kind (``"lending"``), or both. Exploits
        with zero overlap are excluded. Ties break deterministically by most
        recent date, then project name, so the order is stable for tests.
        """

        tokens = _query_tokens(tag, protocol_category)
        if not tokens:
            return []

        scored = [
            (ex.matches(tokens), ex)
            for ex in self.exploits
        ]
        hits = [(score, ex) for score, ex in scored if score > 0]
        hits.sort(key=lambda se: (-se[0], _date_key(se[1].date), se[1].project))
        return [ex for _, ex in hits]

    def __len__(self) -> int:
        return len(self.exploits)

    def __iter__(self):
        return iter(self.exploits)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


# A ``.sol`` PoC path anchors a usable entry. Without it we cannot arm a
# template, so a line that has no such path is skipped.
_POC_PATH_RE = re.compile(r"(?P<path>(?:[\w./-]*?src/test/[\w./-]+?\.sol))")
# Fallback: any .sol path under a year/month dir or a bare *_exp.sol file.
_ANY_SOL_RE = re.compile(r"(?P<path>[\w./-]*?\.sol)")
# A leading ISO-ish date on the index line: 2023-03-13, 2023-03, or 20230313.
_DATE_RE = re.compile(r"(?P<date>\d{4}-\d{2}(?:-\d{2})?|\d{8})")
# Project name in brackets: ``[Euler]`` or ``[Euler Finance]``.
_BRACKET_PROJECT_RE = re.compile(r"\[(?P<project>[^\]\[]+?)\]")
# Heading form: ``### 20230313 Euler Finance - Flashloan & Donate Attack``.
_HEADING_RE = re.compile(
    r"^#{2,4}\s+(?P<date>\d{8}|\d{4}-\d{2}(?:-\d{2})?)\s+(?P<project>.+?)"
    r"(?:\s+[-–]\s+(?P<desc>.+))?$"
)
# An explicit fork block annotation some snapshots carry: ``block: 16818057``.
_BLOCK_RE = re.compile(r"(?:fork[\s_-]?block|block)\s*[:=]\s*(?P<block>\d{4,})", re.I)
# Chain hint inside parentheses or after a chain: marker.
_CHAIN_RE = re.compile(
    r"\b(?P<chain>ethereum|eth|mainnet|bsc|bnb|polygon|matic|arbitrum|"
    r"optimism|avalanche|avax|fantom|ftm|base|gnosis)\b",
    re.I,
)

# Known attack-pattern keywords; recovered from the line text and added to tags
# so semantic-ish queries ("flashloan reentrancy") rank without an embedding.
_ATTACK_KEYWORDS = (
    "flashloan", "flash loan", "reentrancy", "reentrant", "oracle",
    "price manipulation", "manipulation", "access control", "access-control",
    "unprotected", "uninitialized", "proxy", "admin", "upgrade", "delegatecall",
    "donation", "donate", "rounding", "precision", "slippage", "approval",
    "signature", "replay", "timelock", "bridge", "rug", "drain", "overflow",
    "underflow", "logic", "lending", "amm", "vault", "staking",
)

# Chain aliases collapsed to a canonical name.
_CHAIN_ALIASES = {
    "eth": "ethereum", "mainnet": "ethereum", "bnb": "bsc",
    "matic": "polygon", "avax": "avalanche", "ftm": "fantom",
}


# --------------------------------------------------------------------------- #
# Parsing helpers (the layer the journal truncated; rebuilt to spec)
# --------------------------------------------------------------------------- #


def _normalize_date(raw: str) -> str:
    """Normalize 20230313 / 2023-03 / 2023-03-13 to a dashed form."""
    raw = raw.strip()
    if re.fullmatch(r"\d{8}", raw):
        return f"{raw[0:4]}-{raw[4:6]}-{raw[6:8]}"
    return raw


def _canonical_chain(raw: str) -> str:
    low = raw.lower()
    return _CHAIN_ALIASES.get(low, low)


def _recover_tags(project: str, text: str) -> tuple[str, ...]:
    """Project tokens + attack keywords found in the line text, de-duped."""
    tags: list[str] = []
    for tok in re.split(r"[^a-z0-9]+", project.lower()):
        if tok and tok not in tags:
            tags.append(tok)
    low = text.lower()
    for kw in _ATTACK_KEYWORDS:
        if kw in low:
            norm = kw.replace(" ", "").replace("-", "")
            if norm not in tags:
                tags.append(norm)
    return tuple(tags)


def _strip_to_repo_path(path: str) -> str:
    """Collapse a full GitHub URL to its repo-relative ``src/test/...`` path."""
    m = re.search(r"(src/test/[\w./-]+?\.sol)", path)
    return m.group(1) if m else path


def _poc_path_from_line(line: str) -> str | None:
    """Best PoC path on a line, preferring an explicit ``src/test/...`` anchor."""
    m = _POC_PATH_RE.search(line)
    if m:
        return _strip_to_repo_path(m.group("path"))
    # Fallback: any *_exp.sol path; reject prose .sol mentions (interface names).
    m = _ANY_SOL_RE.search(line)
    if m and "_exp.sol" in m.group("path"):
        return _strip_to_repo_path(m.group("path"))
    return None


def parse_readme(readme_text: str) -> tuple[HistoricalExploit, ...]:
    """Parse DeFiHackLabs README text into exploit records, de-duped by PoC path.

    Tolerant of both the ``### <date> <project> - <desc>`` heading form and the
    ``- <date> [Project] - <desc> - [PoC](path)`` index-line form. A line with no
    ``.sol`` PoC/test anchor is skipped (prose interface mentions never become
    entries). Never raises.
    """
    if not readme_text or not readme_text.strip():
        return ()

    by_path: dict[str, HistoricalExploit] = {}
    pending_heading: dict | None = None

    for raw_line in readme_text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue

        heading = _HEADING_RE.match(line.strip())
        if heading:
            # A heading sets context; its PoC path may be on the same or a
            # following bullet line.
            project = heading.group("project").strip()
            desc = heading.group("desc") or ""
            chain_m = _CHAIN_RE.search(line)
            pending_heading = {
                "date": _normalize_date(heading.group("date")),
                "project": project,
                "text": f"{project} {desc} {line}",
                "chain": _canonical_chain(chain_m.group("chain")) if chain_m else "ethereum",
            }
            # A heading may also carry its PoC on the same line.
            path = _poc_path_from_line(line)
            if path:
                _add_entry(by_path, pending_heading, line, path)
                pending_heading = None
            continue

        path = _poc_path_from_line(line)
        if not path:
            # A bullet under a pending heading (e.g. ``- block: 16818057``)
            # carries context (block, chain) even with no PoC path: accumulate
            # it so the heading's record recovers it when the PoC line arrives.
            if pending_heading is not None:
                pending_heading["text"] += " " + line
            continue

        # A PoC line completing a PENDING HEADING: the heading is authoritative
        # for project/date/chain (the bullet's link text, e.g. "Euler.sol", must
        # NOT override "Euler Finance"). The accumulated heading text supplies the
        # block. Chain prefers an explicit hint already captured on the heading.
        if pending_heading is not None:
            ctx = dict(pending_heading)
            ctx["text"] += " " + line
            _add_entry(by_path, ctx, ctx["text"], path)
            pending_heading = None
            continue

        # Standalone index-line form: ``- 2023-03-13 [Euler] - ... - [PoC](path)``.
        date_m = _DATE_RE.search(line)
        bracket_m = _BRACKET_PROJECT_RE.search(line)
        project = bracket_m.group("project").strip() if bracket_m else "unknown"
        date = _normalize_date(date_m.group("date")) if date_m else ""
        chain_m = _CHAIN_RE.search(line)
        chain = _canonical_chain(chain_m.group("chain")) if chain_m else "ethereum"
        ctx = {"date": date, "project": project, "text": f"{project} {line}", "chain": chain}
        _add_entry(by_path, ctx, line, path)

    return tuple(by_path.values())


def _add_entry(by_path: dict, ctx: dict, line: str, path: str) -> None:
    """Insert/merge one record keyed by PoC path (dedup heading+index lines)."""
    block_m = _BLOCK_RE.search(line) or _BLOCK_RE.search(ctx.get("text", ""))
    fork_block = int(block_m.group("block")) if block_m else None
    tags = _recover_tags(ctx["project"], ctx.get("text", "") + " " + line)

    existing = by_path.get(path)
    if existing is None:
        by_path[path] = HistoricalExploit(
            date=ctx["date"],
            project=ctx["project"],
            tag=ctx["project"].lower(),
            poc_path=path,
            fork_block=fork_block,
            chain=ctx.get("chain", "ethereum"),
            tags=tags,
        )
        return

    # Merge: prefer a fuller date, a recovered block, a non-default chain, and
    # the union of tags. Heading + index line for the same PoC collapse to one.
    merged_tags = tuple(dict.fromkeys(existing.tags + tags))
    by_path[path] = HistoricalExploit(
        date=existing.date if len(existing.date) >= len(ctx["date"]) else ctx["date"],
        project=existing.project if len(existing.project) >= len(ctx["project"]) else ctx["project"],
        tag=existing.tag,
        poc_path=path,
        fork_block=existing.fork_block if existing.fork_block is not None else fork_block,
        chain=existing.chain if existing.chain != "ethereum" else ctx.get("chain", "ethereum"),
        tags=merged_tags,
    )


def _tokenize(text: str) -> set[str]:
    """Lowercase alnum tokens for tag-overlap matching."""
    return {t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if t}


def _query_tokens(*parts: str) -> set[str]:
    """Tokens plus collapsed attack phrases for matching recovered tags."""
    tokens: set[str] = set()
    for text in parts:
        if not text:
            continue
        tokens.update(_tokenize(text))
        collapsed = _norm(text)
        if collapsed:
            tokens.add(collapsed)
        low = text.lower()
        for kw in _ATTACK_KEYWORDS:
            if kw in low:
                tokens.add(_norm(kw))
    return tokens


def _date_key(date: str) -> str:
    """Sort key that puts the most recent date first (negated lexicographic)."""
    # Dashed ISO dates sort lexicographically; invert for descending order.
    return "".join(chr(255 - ord(c)) for c in date)


def _read_corpus_text(path: Path) -> str:
    """Read a README file or a directory's README. Empty string on any failure."""
    try:
        if path.is_dir():
            for name in ("README.md", "Readme.md", "readme.md"):
                candidate = path / name
                if candidate.exists():
                    return candidate.read_text(encoding="utf-8", errors="ignore")
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, ValueError):
        return ""


def _norm(token: str) -> str:
    """Normalize one token to its alnum-collapsed lowercase form for matching."""
    return re.sub(r"[^a-z0-9]+", "", (token or "").lower())
