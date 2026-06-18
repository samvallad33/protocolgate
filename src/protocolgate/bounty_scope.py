from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class BountyScope:
    program_name: str
    in_scope: tuple[str, ...]
    out_of_scope: tuple[str, ...]
    trusted_role_exclusions: tuple[str, ...]
    centralization_exclusions: tuple[str, ...]
    known_issue_exclusions: tuple[str, ...]
    rewards: tuple[str, ...]
    commits: tuple[str, ...]
    poc_required: bool
    source_signals: tuple[str, ...]


@dataclass(frozen=True)
class BountyReportability:
    program_name: str
    verdict: str
    score: int
    confidence: str
    executive_summary: str
    matched_in_scope: tuple[str, ...]
    positive_signals: tuple[str, ...]
    blockers: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    next_actions: tuple[str, ...]
    scope: BountyScope


CONTROL_PLANE_TERMS: tuple[tuple[str, str], ...] = (
    ("bridge", "bridge/cross-chain path"),
    ("cross-chain", "bridge/cross-chain path"),
    ("layerzero", "LayerZero/OApp path"),
    ("oapp", "LayerZero/OApp path"),
    ("dvn", "DVN/message verification"),
    ("oracle", "oracle dependency"),
    ("proxy", "proxy/admin upgrade path"),
    ("upgrade", "proxy/admin upgrade path"),
    ("admin", "admin authority"),
    ("governance", "governance/timelock path"),
    ("timelock", "governance/timelock path"),
    ("multisig", "multisig authority"),
    ("safe", "Safe/module authority"),
    ("module", "Safe/module authority"),
    ("guardian", "guardian/emergency authority"),
    ("pause", "pause/emergency authority"),
    ("rate limit", "rate-limit boundary"),
    ("ratelimit", "rate-limit boundary"),
    ("vault", "vault/accounting path"),
    ("withdraw", "withdrawal path"),
    ("mint", "mint/burn path"),
    ("burn", "mint/burn path"),
    ("liquidation", "liquidation/solvency path"),
)

IMPACT_TERMS: tuple[tuple[str, str], ...] = (
    ("drain", "direct asset drain"),
    ("steal", "direct asset theft"),
    ("loss of funds", "loss-of-funds impact"),
    ("loss of user funds", "loss-of-funds impact"),
    ("loss of principal", "loss-of-principal impact"),
    ("insolvency", "protocol solvency impact"),
    ("bad debt", "protocol solvency impact"),
    ("unauthorized", "unauthorized action"),
    ("bypass", "security-control bypass"),
    ("replay", "message replay path"),
    ("mint", "unauthorized mint/burn impact"),
    ("withdraw", "unauthorized withdrawal impact"),
    ("oracle manipulation", "oracle manipulation impact"),
    ("liquidation", "liquidation impact"),
)

EVIDENCE_TERMS: tuple[tuple[str, str], ...] = (
    ("poc", "PoC evidence"),
    ("proof of concept", "PoC evidence"),
    ("foundry", "Foundry reproducer"),
    ("forge test", "Foundry reproducer"),
    ("reproducer", "reproducer"),
    ("fork", "fork-state evidence"),
    ("transaction", "transaction evidence"),
    ("call trace", "call-trace evidence"),
    ("source reference", "source references"),
    ("line", "source references"),
)

PUBLIC_ACTOR_TERMS = (
    "anyone",
    "public",
    "permissionless",
    "attacker",
    "untrusted",
    "without permission",
    "arbitrary user",
    "external caller",
)

TRUSTED_ROLE_TERMS = (
    "trusted role",
    "owner",
    "onlyowner",
    "admin",
    "governance",
    "multisig",
    "guardian",
    "operator",
    "keeper",
    "authorized",
)

THEORY_TERMS = (
    "best practice",
    "theoretical",
    "recommendation",
    "informational",
    "hardening",
    "missing rate limit",
    "no rate limit",
    "without rate limit",
)

SECTION_ALIASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("out_scope", ("out of scope", "out-of-scope", "not in scope", "exclusions")),
    ("trusted", ("trusted role", "trusted roles", "privileged role", "privileged roles")),
    ("centralization", ("centralization", "centralisation")),
    ("known", ("known issue", "known issues", "accepted risk", "acknowledged")),
    ("reward", ("reward", "rewards", "payout", "payouts", "severity")),
    ("commit", ("commit", "commits", "tag", "version", "hash")),
    ("poc", ("poc", "proof of concept", "reproducible", "reproduction", "requirements")),
    ("in_scope", ("in scope", "in-scope", "assets in scope", "smart contracts in scope")),
)


def analyze_bounty_reportability(
    scope_text: str,
    *,
    candidate_notes: str = "",
    program_name: str = "",
) -> BountyReportability:
    """Extract bounty scope and decide whether a candidate is reportable.

    The gate is intentionally conservative. It is designed to stop weak bounty
    submissions before they waste triage time or damage buyer confidence.
    """

    scope = parse_bounty_scope(scope_text, program_name=program_name)
    candidate = candidate_notes.strip()
    if not candidate:
        return BountyReportability(
            program_name=scope.program_name,
            verdict="defer",
            score=35,
            confidence="medium",
            executive_summary="Scope parsed. Add candidate notes before deciding whether to submit.",
            matched_in_scope=tuple(),
            positive_signals=tuple(),
            blockers=tuple(),
            missing_evidence=("candidate exploit notes", "source-to-sink path", "PoC or concrete reproduction plan"),
            next_actions=(
                "Paste the candidate finding summary.",
                "Include the public actor, affected contracts, impact, and reproduction evidence.",
                "Run the gate again before drafting a report.",
            ),
            scope=scope,
        )

    text = candidate.lower()
    scope_text_lower = scope_text.lower()
    scope_domains = _domain_signals(scope_text_lower)
    candidate_domains = _domain_signals(text)
    matched_in_scope = _ordered_intersection(candidate_domains, scope_domains)
    if not matched_in_scope and any("smart contract" in item.lower() for item in scope.in_scope):
        if any(word in text for word in ("contract", "solidity", "function", "vault", "bridge", "oracle")):
            matched_in_scope = ("smart-contract scope",)

    positives = list(candidate_domains)
    positives.extend(_impact_signals(text))
    positives.extend(_evidence_signals(text))
    positives = list(dict.fromkeys(positives))

    blockers: list[str] = []
    missing: list[str] = []
    next_actions: list[str] = []

    out_scope_matches = _matched_exclusion_lines(text, scope.out_of_scope)
    if out_scope_matches:
        blockers.append("Candidate appears to match out-of-scope language: " + "; ".join(out_scope_matches[:3]))

    if _trusted_role_excluded(scope) and _candidate_depends_on_trusted_role(text):
        blockers.append("Candidate appears to depend on a trusted or privileged role, which the scope excludes.")

    centralization_matches = _matched_exclusion_lines(text, scope.centralization_exclusions)
    if centralization_matches:
        blockers.append("Candidate looks like a centralization-risk report, which the scope excludes.")

    known_matches = _matched_exclusion_lines(text, scope.known_issue_exclusions)
    if known_matches or any(term in text for term in ("known issue", "known risk", "accepted risk", "documented")):
        blockers.append("Candidate may be a known, accepted, or documented issue.")

    if scope.poc_required and not _has_evidence(text):
        missing.append("Program appears to require a PoC, but candidate notes do not show one.")

    if not matched_in_scope:
        missing.append("No clear in-scope asset, repo, impact, or control-plane surface matched.")

    if not _impact_signals(text):
        missing.append("No concrete in-scope impact is stated.")

    if not _public_actor_path(text):
        missing.append("Public/untrusted actor path is not explicit.")

    if _rate_limit_only_claim(text):
        missing.append("Missing rate-limit claim needs an exploit path: value moved, minted, withdrawn, replayed, or accounting broken.")

    if _theory_only_claim(text):
        missing.append("Candidate reads like hardening or best-practice feedback unless tied to exploitable impact.")

    score = _score_candidate(
        matched_in_scope=matched_in_scope,
        positives=positives,
        blockers=blockers,
        missing=missing,
        scope=scope,
        candidate_text=text,
    )
    verdict = _verdict(score, blockers, missing)
    confidence = _confidence(score, blockers, missing)
    summary = _summary(verdict, score, blockers, missing)

    if verdict == "submit":
        next_actions.extend(
            [
                "Draft the private report with exact scope references, source lines, and PoC steps.",
                "Lead with the exploit path and impact, not the control-plane label.",
                "Add false-positive kill checks: trusted-role dependency, known issue, and out-of-scope exclusions.",
            ]
        )
    elif verdict == "defer":
        next_actions.extend(
            [
                "Do not submit yet.",
                "Build the missing source-to-sink proof and a minimal reproduction.",
                "Ask whether the issue survives trusted-role, known-issue, and centralization exclusions.",
            ]
        )
    else:
        next_actions.extend(
            [
                "Do not submit this as a bounty report.",
                "Use it as buyer-facing bounty-readiness noise if it is still educational.",
                "Move to a candidate with public actor, direct impact, and PoC evidence.",
            ]
        )

    return BountyReportability(
        program_name=scope.program_name,
        verdict=verdict,
        score=score,
        confidence=confidence,
        executive_summary=summary,
        matched_in_scope=tuple(matched_in_scope),
        positive_signals=tuple(positives),
        blockers=tuple(dict.fromkeys(blockers)),
        missing_evidence=tuple(dict.fromkeys(missing)),
        next_actions=tuple(next_actions),
        scope=scope,
    )


def parse_bounty_scope(scope_text: str, *, program_name: str = "") -> BountyScope:
    """Parse a pasted bounty or audit-contest scope into reportability fields."""

    sections: dict[str, list[str]] = {
        "in_scope": [],
        "out_scope": [],
        "trusted": [],
        "centralization": [],
        "known": [],
        "reward": [],
        "commit": [],
        "poc": [],
    }
    current: str | None = None
    lines = scope_text.splitlines()

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        is_bullet = line.startswith(("-", "*"))
        header = None if is_bullet and ":" not in line else _section_header(line)
        if header is not None:
            current = header
            remainder = _header_remainder(line)
            if remainder:
                sections[current].append(remainder)
            continue
        if current is not None and _is_content_line(line):
            sections[current].append(_clean_line(line))

        lowered = line.lower()
        if "$" in line or "reward" in lowered or "payout" in lowered:
            sections["reward"].append(_clean_line(line))
        if "commit" in lowered or re.search(r"\b[0-9a-f]{7,64}\b", lowered):
            sections["commit"].append(_clean_line(line))
        if "centralization" in lowered or "centralisation" in lowered:
            sections["centralization"].append(_clean_line(line))
        if "trusted role" in lowered or "privileged role" in lowered:
            sections["trusted"].append(_clean_line(line))
        if "known issue" in lowered or "accepted risk" in lowered or "acknowledged" in lowered:
            sections["known"].append(_clean_line(line))

    poc_required = any(
        phrase in scope_text.lower()
        for phrase in (
            "poc required",
            "proof of concept required",
            "must include a poc",
            "must include proof of concept",
            "must include reproducible",
            "reproducible poc",
        )
    )

    source_signal_basis = " ".join(
        sections["in_scope"] + sections["reward"] + sections["poc"] + sections["commit"]
    )
    source_signals = list(_domain_signals(source_signal_basis.lower()))
    if poc_required:
        source_signals.append("PoC required")
    if sections["trusted"] or "trusted roles are out of scope" in scope_text.lower():
        source_signals.append("trusted-role exclusion")
    if sections["centralization"]:
        source_signals.append("centralization exclusion")

    inferred_name = program_name.strip() or _infer_program_name(scope_text)
    return BountyScope(
        program_name=inferred_name or "unknown program",
        in_scope=_dedupe(sections["in_scope"]),
        out_of_scope=_dedupe(sections["out_scope"]),
        trusted_role_exclusions=_dedupe(sections["trusted"]),
        centralization_exclusions=_dedupe(sections["centralization"]),
        known_issue_exclusions=_dedupe(sections["known"]),
        rewards=_dedupe(sections["reward"]),
        commits=_dedupe(sections["commit"]),
        poc_required=poc_required,
        source_signals=tuple(dict.fromkeys(source_signals)),
    )


def bounty_reportability_to_json(result: BountyReportability) -> str:
    return json.dumps(asdict(result), indent=2)


def bounty_reportability_to_markdown(result: BountyReportability) -> str:
    lines = [
        "# ProtocolGate Bounty Scope Gate",
        "",
        f"**Program:** {result.program_name}",
        f"**Verdict:** {result.verdict.upper()}",
        f"**Score:** {result.score}/100",
        f"**Confidence:** {result.confidence}",
        "",
        "## Executive Summary",
        "",
        result.executive_summary,
        "",
        "## Scope Signals",
        "",
        _bullet_block("Matched In Scope", result.matched_in_scope),
        _bullet_block("Scope Source Signals", result.scope.source_signals),
        _bullet_block("Rewards / Severity Signals", result.scope.rewards),
        _bullet_block("Commits / Versions", result.scope.commits),
        f"- **PoC Required:** {'yes' if result.scope.poc_required else 'not detected'}",
        "",
        "## Reportability Gate",
        "",
        _bullet_block("Positive Signals", result.positive_signals),
        _bullet_block("Blockers", result.blockers),
        _bullet_block("Missing Evidence", result.missing_evidence),
        "",
        "## Next Actions",
        "",
        _bullet_block("Actions", result.next_actions),
        "",
        "## Extracted Scope",
        "",
        _bullet_block("In Scope", result.scope.in_scope),
        _bullet_block("Out Of Scope", result.scope.out_of_scope),
        _bullet_block("Trusted-Role Exclusions", result.scope.trusted_role_exclusions),
        _bullet_block("Centralization Exclusions", result.scope.centralization_exclusions),
        _bullet_block("Known-Issue Exclusions", result.scope.known_issue_exclusions),
        "",
        "## Scope Note",
        "",
        "This is a reportability filter, not a vulnerability verdict. Submit only when the "
        "candidate has an in-scope asset, public actor path, concrete impact, reproduction "
        "evidence, and no scope exclusion blocker.",
    ]
    return "\n".join(lines)


def _section_header(line: str) -> str | None:
    lowered = _clean_header(line)
    if len(lowered) > 120:
        return None
    for key, aliases in SECTION_ALIASES:
        if any(alias in lowered for alias in aliases):
            return key
    return None


def _clean_header(line: str) -> str:
    value = line.strip().lower()
    value = re.sub(r"^#{1,6}\s*", "", value)
    value = re.sub(r"^[*-]\s*", "", value)
    return value.strip(" :")


def _header_remainder(line: str) -> str:
    if ":" not in line:
        return ""
    remainder = line.split(":", 1)[1].strip()
    return _clean_line(remainder) if remainder else ""


def _is_content_line(line: str) -> bool:
    if line.startswith(("#", "##", "###")):
        return False
    if _section_header(line) is not None and not line.startswith(("-", "*")):
        return False
    return True


def _clean_line(line: str) -> str:
    return re.sub(r"^\s*[-*]\s*", "", line).strip()


def _dedupe(items: Iterable[str]) -> tuple[str, ...]:
    cleaned = [_clean_line(item) for item in items if _clean_line(item)]
    return tuple(dict.fromkeys(cleaned))


def _infer_program_name(scope_text: str) -> str:
    for line in scope_text.splitlines()[:10]:
        cleaned = _clean_line(line).strip("# ")
        if cleaned and len(cleaned) <= 80 and not _section_header(cleaned):
            return cleaned
    return ""


def _domain_signals(text: str) -> list[str]:
    return list(dict.fromkeys(label for needle, label in CONTROL_PLANE_TERMS if needle in text))


def _impact_signals(text: str) -> list[str]:
    return list(dict.fromkeys(label for needle, label in IMPACT_TERMS if needle in text))


def _evidence_signals(text: str) -> list[str]:
    return list(dict.fromkeys(label for needle, label in EVIDENCE_TERMS if needle in text))


def _ordered_intersection(left: Iterable[str], right: Iterable[str]) -> tuple[str, ...]:
    right_set = set(right)
    return tuple(item for item in left if item in right_set)


def _matched_exclusion_lines(candidate_text: str, lines: Iterable[str]) -> list[str]:
    matches: list[str] = []
    for line in lines:
        lowered = line.lower()
        if not lowered:
            continue
        if any(term in candidate_text and term in lowered for term in TRUSTED_ROLE_TERMS + THEORY_TERMS):
            matches.append(line)
            continue
        for token in _meaningful_tokens(lowered):
            if token in candidate_text:
                matches.append(line)
                break
    return list(dict.fromkeys(matches))


def _meaningful_tokens(text: str) -> list[str]:
    raw = re.findall(r"[a-z0-9][a-z0-9_-]{4,}", text)
    stop = {"scope", "issues", "issue", "impact", "reports", "report", "known", "smart", "contract"}
    return [token for token in raw if token not in stop]


def _trusted_role_excluded(scope: BountyScope) -> bool:
    text = " ".join(
        scope.trusted_role_exclusions
        + scope.centralization_exclusions
        + scope.out_of_scope
        + scope.known_issue_exclusions
    ).lower()
    return any(
        phrase in text
        for phrase in (
            "trusted role",
            "privileged role",
            "centralization",
            "admin key",
            "governance attack",
            "compromised",
        )
    )


def _candidate_depends_on_trusted_role(text: str) -> bool:
    if _public_actor_path(text):
        return False
    return any(term in text.replace(" ", "") for term in ("onlyowner",)) or any(term in text for term in TRUSTED_ROLE_TERMS)


def _public_actor_path(text: str) -> bool:
    return any(term in text for term in PUBLIC_ACTOR_TERMS) or "unauthorized" in text


def _has_evidence(text: str) -> bool:
    return bool(_evidence_signals(text))


def _rate_limit_only_claim(text: str) -> bool:
    if not any(phrase in text for phrase in ("missing rate limit", "no rate limit", "without rate limit")):
        return False
    return not any(
        term in text
        for term in (
            "drain",
            "loss",
            "replay",
            "mint",
            "withdraw",
            "insolvency",
            "bad debt",
            "bypass",
            "steal",
        )
    )


def _theory_only_claim(text: str) -> bool:
    if any(term in text for term in ("poc", "foundry", "reproducer", "drain", "loss", "unauthorized")):
        return False
    return any(term in text for term in THEORY_TERMS)


def _score_candidate(
    *,
    matched_in_scope: Iterable[str],
    positives: Iterable[str],
    blockers: Iterable[str],
    missing: Iterable[str],
    scope: BountyScope,
    candidate_text: str,
) -> int:
    score = 45
    if list(matched_in_scope):
        score += 15
    if _impact_signals(candidate_text):
        score += 20
    if _has_evidence(candidate_text):
        score += 15
    if _public_actor_path(candidate_text):
        score += 10
    if scope.rewards and any(signal in candidate_text for signal in ("critical", "high", "loss", "funds", "drain")):
        score += 5
    if any("PoC" in signal or "reproducer" in signal for signal in positives):
        score += 5

    score -= 30 * len(list(blockers))
    score -= 10 * len(list(missing))
    if scope.poc_required and not _has_evidence(candidate_text):
        score -= 10
    return max(0, min(100, score))


def _verdict(score: int, blockers: list[str], missing: list[str]) -> str:
    if blockers and score < 85:
        return "kill"
    if score >= 80 and not blockers and len(missing) <= 1:
        return "submit"
    return "defer"


def _confidence(score: int, blockers: list[str], missing: list[str]) -> str:
    if blockers or score >= 85:
        return "high"
    if len(missing) <= 2:
        return "medium"
    return "low"


def _summary(verdict: str, score: int, blockers: list[str], missing: list[str]) -> str:
    if verdict == "submit":
        return (
            f"Candidate looks reportable with score {score}/100. It has enough scope, "
            "impact, actor-path, and evidence signal to draft a private report."
        )
    if verdict == "kill":
        return (
            f"Kill this candidate for bounty submission. The dominant issue is scope risk: "
            f"{blockers[0] if blockers else 'hard exclusion detected'}"
        )
    return (
        f"Defer submission. Score is {score}/100 and the missing proof is: "
        + ("; ".join(missing[:3]) if missing else "stronger reproduction evidence")
        + "."
    )


def _bullet_block(title: str, items: Iterable[str]) -> str:
    values = list(items)
    lines = [f"### {title}"]
    if not values:
        lines.append("- None detected")
    else:
        lines.extend(f"- {item}" for item in values)
    return "\n".join(lines)
