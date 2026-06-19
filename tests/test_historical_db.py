"""Tests for the DeFiHackLabs historical exploit-PoC index.

No filesystem network: every behavior is exercised via the in-memory
constructor, the string parser, and a single ``tmp_path`` round-trip that proves
``load`` reads a real file and that a missing path degrades to empty.
"""

from __future__ import annotations

from pathlib import Path

from protocolgate.historical_db import (
    HistoricalDB,
    HistoricalExploit,
    parse_readme,
)


# A tiny but realistic slice of the DeFiHackLabs README, covering both the
# heading form and the index-line form, plus a fork-block and a chain hint.
SAMPLE_README = """\
# DeFiHackLabs

On-chain reproduce of DeFi exploits. Public utility only.

### 20230313 Euler Finance - Flashloan & Donate Attack
- Lost: ~197M USD
- block: 16818057
- [Euler.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-03/Euler_exp.sol)

### 20220824 XSURGE - Reentrancy (bsc)
- [XSURGE.sol](src/test/2022-08/XSURGE_exp.sol)

## Index

- 2023-03-13 [Euler] - [PoC](src/test/2023-03/Euler_exp.sol)
- 2021-04-19 [Uranium Finance] - flashloan rounding bug - [PoC](src/test/2021-04/Uranium_exp.sol)
- 2022-10-11 [Mango Markets] - oracle price manipulation - [PoC](src/test/2022-10/Mango_exp.sol)

A prose line mentioning IERC20.sol that must NOT become an entry.
"""


# --------------------------------------------------------------------------- #
# In-memory construction
# --------------------------------------------------------------------------- #


def _ex(project, tags, date="2023-01-01", path=None, block=None, chain="ethereum"):
    return HistoricalExploit(
        date=date,
        project=project,
        tag=project.lower(),
        poc_path=path or f"src/test/{project}_exp.sol",
        fork_block=block,
        chain=chain,
        tags=tuple(tags),
    )


def test_in_memory_constructor_accepts_iterable_and_freezes():
    db = HistoricalDB(
        exploits=[
            _ex("Euler", ("euler", "flashloan", "donation")),
            _ex("Mango", ("mango", "oracle", "manipulation")),
        ]
    )
    assert len(db) == 2
    assert isinstance(db.exploits, tuple)
    # Iteration yields the records.
    assert {e.project for e in db} == {"Euler", "Mango"}


def test_match_ranks_by_tag_overlap():
    db = HistoricalDB(
        exploits=[
            _ex("Euler", ("euler", "flashloan", "donation"), date="2023-03-13"),
            _ex("Harvest", ("harvest", "flashloan", "oracle"), date="2020-10-26"),
            _ex("Mango", ("mango", "oracle", "manipulation"), date="2022-10-11"),
        ]
    )
    # "flashloan oracle" overlaps Harvest by 2, Euler by 1, Mango by 1.
    ranked = db.match("flashloan oracle")
    assert [e.project for e in ranked] == ["Harvest", "Euler", "Mango"]


def test_match_tie_breaks_by_recency_then_project():
    db = HistoricalDB(
        exploits=[
            _ex("Beta", ("beta", "oracle"), date="2021-01-01"),
            _ex("Alpha", ("alpha", "oracle"), date="2023-01-01"),
            _ex("Gamma", ("gamma", "oracle"), date="2023-01-01"),
        ]
    )
    ranked = db.match("oracle")
    # All score 1: newest first (Alpha/Gamma 2023 before Beta 2021), then project.
    assert [e.project for e in ranked] == ["Alpha", "Gamma", "Beta"]


def test_match_protocol_category_widens_query():
    db = HistoricalDB(
        exploits=[
            _ex("Euler", ("euler", "flashloan", "lending")),
            _ex("XSURGE", ("xsurge", "reentrancy")),
        ]
    )
    # Tag alone misses Euler; category "lending" pulls it in.
    assert db.match("flashloan", protocol_category="lending")[0].project == "Euler"


def test_match_collapsed_attack_phrase_tags():
    db = HistoricalDB(
        exploits=[
            _ex("ProxyBug", ("proxybug", "accesscontrol", "proxy")),
            _ex("Euler", ("euler", "flashloan")),
        ]
    )

    assert db.match("access control")[0].project == "ProxyBug"
    assert db.match("flash loan")[0].project == "Euler"


def test_match_empty_query_and_no_overlap_return_empty():
    db = HistoricalDB(exploits=[_ex("Euler", ("euler", "flashloan"))])
    assert db.match("") == []
    assert db.match("   ") == []
    assert db.match("nonexistent-attack-family") == []


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def test_parse_sample_readme_extracts_entries():
    exploits = parse_readme(SAMPLE_README)
    by_path = {e.poc_path: e for e in exploits}

    # Each distinct PoC path becomes exactly one entry (heading + index line for
    # Euler collapse to one record keyed by path).
    assert "src/test/2023-03/Euler_exp.sol" in by_path
    assert "src/test/2022-08/XSURGE_exp.sol" in by_path
    assert "src/test/2021-04/Uranium_exp.sol" in by_path
    assert "src/test/2022-10/Mango_exp.sol" in by_path

    # The prose IERC20.sol line is rejected (no PoC/test anchor).
    assert not any("IERC20" in e.poc_path for e in exploits)


def test_parse_normalizes_dates_and_recovers_block_and_chain():
    by_path = {e.poc_path: e for e in parse_readme(SAMPLE_README)}

    euler = by_path["src/test/2023-03/Euler_exp.sol"]
    assert euler.date == "2023-03-13"  # 20230313 normalized
    assert euler.fork_block == 16818057  # recovered from "block: 16818057"
    assert "flashloan" in euler.tags
    assert "donation" in euler.tags or "donate" in euler.tags
    # Heading project "Euler Finance" -> joined normalized tag, but the split
    # "euler" token stays searchable in tags.
    assert euler.project == "Euler Finance"
    assert "euler" in euler.tags

    xsurge = by_path["src/test/2022-08/XSURGE_exp.sol"]
    assert xsurge.date == "2022-08-24"
    assert xsurge.chain == "bsc"  # chain hint "(bsc)" recovered
    assert "reentrancy" in xsurge.tags


def test_parse_strips_url_prefix_to_repo_relative_path():
    by_path = {e.poc_path: e for e in parse_readme(SAMPLE_README)}
    # The Euler heading linked a full GitHub URL; it must collapse to src/test/.
    assert by_path["src/test/2023-03/Euler_exp.sol"].poc_path.startswith("src/test/")


def test_parse_match_roundtrip_by_tag():
    db = HistoricalDB.parse(SAMPLE_README)
    # "oracle manipulation" should surface Mango first.
    ranked = db.match("oracle manipulation")
    assert ranked
    assert ranked[0].project.lower().startswith("mango")


def test_parse_empty_and_whitespace_yield_no_entries():
    assert parse_readme("") == ()
    assert parse_readme("   \n\n  ") == ()
    assert len(HistoricalDB.parse("# Just a title\nno entries here")) == 0


# --------------------------------------------------------------------------- #
# load(): file round-trip + graceful degradation (never raises)
# --------------------------------------------------------------------------- #


def test_load_reads_file(tmp_path: Path):
    readme = tmp_path / "README.md"
    readme.write_text(SAMPLE_README, encoding="utf-8")

    db = HistoricalDB.load(readme)
    assert len(db) == 4
    assert db.match("flashloan")  # corpus loaded and queryable


def test_load_reads_directory_readme(tmp_path: Path):
    (tmp_path / "README.md").write_text(SAMPLE_README, encoding="utf-8")
    db = HistoricalDB.load(tmp_path)  # directory, not file
    assert len(db) == 4


def test_load_missing_path_degrades_to_empty():
    db = HistoricalDB.load("/no/such/defihacklabs/README.md")
    assert len(db) == 0
    assert db.match("flashloan") == []  # safe to query an empty index


def test_load_none_path_degrades_to_empty():
    assert len(HistoricalDB.load(None)) == 0


def test_load_empty_file_degrades_to_empty(tmp_path: Path):
    empty = tmp_path / "README.md"
    empty.write_text("", encoding="utf-8")
    assert len(HistoricalDB.load(empty)) == 0


def test_load_directory_without_readme_degrades_to_empty(tmp_path: Path):
    (tmp_path / "notes.txt").write_text("nothing useful", encoding="utf-8")
    assert len(HistoricalDB.load(tmp_path)) == 0
