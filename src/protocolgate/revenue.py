from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable, Literal


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PIPELINE_PATH = PROJECT_ROOT / ".protocolgate" / "client_pipeline.jsonl"

BUYER_SIGNALS: tuple[tuple[str, int, str], ...] = (
    ("audit", 5, "near-term audit"),
    ("bounty", 5, "near-term bounty"),
    ("immunefi", 5, "public bounty surface"),
    ("cantina", 5, "audit competition surface"),
    ("codehawks", 5, "audit competition surface"),
    ("hackenproof", 5, "audit or bounty surface"),
    ("upgrade", 4, "privileged upgrade event"),
    ("governance", 4, "governance/control-plane event"),
    ("proposal", 4, "privileged proposal event"),
    ("cross-chain", 4, "cross-chain expansion"),
    ("bridge", 4, "bridge control-plane risk"),
    ("layerzero", 4, "LayerZero/OApp control-plane risk"),
    ("oapp", 4, "OApp control-plane risk"),
    ("dvn", 4, "DVN or message verification risk"),
    ("oracle", 3, "oracle dependency"),
    ("rwa", 3, "RWA control-plane sensitivity"),
    ("stablecoin", 3, "stablecoin mint/redeem sensitivity"),
    ("vault", 3, "vault authority risk"),
    ("lending", 3, "lending market authority risk"),
    ("restaking", 3, "restaking authority risk"),
    ("safe", 3, "Safe signer/module boundary"),
    ("multisig", 3, "multisig authority"),
    ("timelock", 3, "timelock authority"),
    ("proxy admin", 3, "proxy admin upgrade authority"),
    ("guardian", 3, "guardian/emergency authority"),
    ("founder", 3, "buyer or sponsor role"),
    ("cto", 3, "buyer or sponsor role"),
    ("protocol lead", 3, "buyer or sponsor role"),
    ("security lead", 3, "security owner role"),
)

NEGATIVE_SIGNALS: tuple[tuple[str, int, str], ...] = (
    ("no deployed", -4, "no deployed addresses or launch plan"),
    ("pure nft", -3, "weak control-plane fit"),
    ("meme", -3, "weak control-plane fit"),
    ("price", -2, "market discourse, not buyer pain"),
    ("airdrop", -2, "growth discourse, not buyer pain"),
)

STAGES = (
    "identified",
    "touched",
    "replied",
    "call_booked",
    "pain_confirmed",
    "offer_sent",
    "paid_pilot_proposed",
    "closed",
    "dead",
)


@dataclass(frozen=True)
class LeadScore:
    score: int
    priority: str
    matched_signals: tuple[str, ...]
    negative_signals: tuple[str, ...]
    buyer_hypothesis: str
    recommended_offer: str
    hard_ask: str
    next_action: str


@dataclass(frozen=True)
class PipelineEvent:
    timestamp: str
    lead_name: str
    organization: str
    stage: str
    persona: str
    score: int
    priority: str
    next_action: str
    notes: str


def score_lead(notes: str, persona: str = "founder") -> LeadScore:
    """Score a pasted Web3 lead profile for ProtocolGate buyer fit."""

    text = f"{persona} {notes}".lower()
    score = 0
    positives: list[str] = []
    negatives: list[str] = []

    for needle, points, label in BUYER_SIGNALS:
        if needle in text:
            score += points
            positives.append(label)

    for needle, points, label in NEGATIVE_SIGNALS:
        if needle in text:
            score += points
            negatives.append(label)

    if score >= 12:
        priority = "A"
        offer = "48-hour Control-Plane Triage at USD 1.5k-3k"
        hard_ask = "Ask for a 15-minute call and propose a paid 48-hour triage."
    elif score >= 7:
        priority = "B"
        offer = "Audit/Bounty Readiness Review at USD 5k-10k if urgency is confirmed"
        hard_ask = "Ask who owns audit or bounty readiness and request a routing intro."
    else:
        priority = "C"
        offer = "No paid offer yet"
        hard_ask = "Ask one technical qualifying question before spending more time."

    hypothesis = _buyer_hypothesis(positives, negatives)
    next_action = _next_action(priority, positives)

    return LeadScore(
        score=score,
        priority=priority,
        matched_signals=tuple(dict.fromkeys(positives)),
        negative_signals=tuple(dict.fromkeys(negatives)),
        buyer_hypothesis=hypothesis,
        recommended_offer=offer,
        hard_ask=hard_ask,
        next_action=next_action,
    )


def daily_briefing() -> dict:
    """Return the daily ProtocolGate client-acquisition operating plan."""

    return {
        "goal": "Close at least one paid ProtocolGate B2B contract during the active sprint.",
        "positioning": "Audit and bounty readiness for Web3 control-plane security.",
        "one_liner": "Audits check code. ProtocolGate checks who can change the code.",
        "minimum_day": [
            "Review 20 high-fit buyer profiles.",
            "Send 10 direct buyer DMs.",
            "Send 5 auditor/platform/researcher DMs.",
            "Leave 5 useful public comments.",
            "Make 2 hard conversion asks.",
            "Follow up with every warm reply.",
        ],
        "aggressive_day": [
            "Review 50 high-fit buyer profiles.",
            "Send 25 buyer DMs.",
            "Send 10 partner/auditor/researcher DMs.",
            "Leave 12 useful public comments.",
            "Make 5 hard conversion asks.",
            "Ask one person for a paid pilot.",
        ],
        "search_queries": [
            "DeFi audit readiness",
            "bug bounty DeFi protocol",
            "LayerZero OApp security",
            "bridge security protocol",
            "oracle security DeFi",
            "Safe multisig timelock",
            "governance proposal calldata",
            "protocol security engineer DeFi",
        ],
        "hard_asks": [
            "Would a 48-hour control-plane triage be useful before your audit or bounty?",
            "Who owns audit and bounty readiness on your team?",
            "Can I send the one-page ProtocolGate offer?",
            "Would you pay for a short review if it produced a findings report and triage memo?",
        ],
    }


def generate_outreach(
    *,
    lead_name: str,
    organization: str,
    persona: str,
    lead_notes: str,
    stage: str = "cold",
    tone: Literal["direct", "technical", "founder"] = "direct",
) -> dict:
    """Generate non-spam ProtocolGate outreach from concrete lead notes."""

    score = score_lead(lead_notes, persona)
    custom_trigger = _custom_trigger(lead_notes)
    if not custom_trigger:
        return {
            "refusal": True,
            "reason": "No concrete trigger found. Add one real detail: audit, bounty, launch, upgrade, bridge, oracle, Safe, timelock, governance, or recent post.",
            "score": asdict(score),
        }

    opener = f"Hey {lead_name}," if lead_name else "Hey,"
    if tone == "technical":
        angle = (
            "I am working on ProtocolGate, a Web3 control-plane policy gate for "
            "audit and bounty readiness."
        )
    elif tone == "founder":
        angle = (
            "I am helping Web3 teams catch control-plane risk before it becomes "
            "audit friction or bounty triage noise."
        )
    else:
        angle = (
            "I am building ProtocolGate, a Web3 control-plane readiness review "
            "for teams preparing for audit, upgrade, launch, or bounty."
        )

    message = "\n\n".join(
        [
            opener,
            f"I noticed {organization or 'your team'} is relevant because {custom_trigger}.",
            angle,
            (
                "It maps who can upgrade, pause, bridge, govern, change oracle settings, "
                "move treasury funds, or sign privileged proposals, then returns an "
                "audit-style findings report plus bounty-readiness notes."
            ),
            score.hard_ask,
        ]
    )

    return {
        "refusal": False,
        "priority": score.priority,
        "score": score.score,
        "message": message,
        "custom_trigger": custom_trigger,
        "asset_to_send": select_asset(persona=persona, stage=stage, score=score.score),
        "next_action": score.next_action,
    }


def build_offer(*, urgency: str, lead_notes: str, budget_hint: str = "") -> dict:
    """Build a price-anchored ProtocolGate offer from urgency and buyer context."""

    text = f"{urgency} {lead_notes} {budget_hint}".lower()
    lead = score_lead(text)
    if any(word in text for word in ("immunefi", "cantina", "bounty", "competition", "cross-chain", "bridge")):
        package = "Pre-Bounty Hardening Sprint"
        price = "USD 12k-25k"
        scope = "1-2 week deep review before public researcher pressure."
    elif lead.score >= 12 or any(word in text for word in ("audit", "upgrade", "launch")):
        package = "Audit And Bounty Readiness Review"
        price = "USD 5k-10k"
        scope = "Production-like control-plane manifest, findings report, and readiness memo."
    else:
        package = "48-Hour Control-Plane Triage"
        price = "USD 1.5k-3k"
        scope = "One protocol, upgrade, vault, market, or bridge path."

    return {
        "package": package,
        "price": price,
        "scope": scope,
        "deliverables": [
            "authority map",
            "control-plane findings",
            "bounty-readiness notes",
            "remediation order",
            "walkthrough call",
        ],
        "close": (
            f"I can make this a fixed-scope {package} for {price}. "
            "If the first pass is useful, we can expand from there."
        ),
    }


def content_angles(theme: str = "bounty_readiness") -> dict:
    """Return high-signal daily content angles for ProtocolGate promotion."""

    library = {
        "bounty_readiness": [
            "Opening a bounty is not readiness. Readiness means knowing which admin, bridge, oracle, and signing paths researchers will attack first.",
            "A scary bridge exposure is not always a bug. The question is whether the exploit path survives peer checks, replay bounds, ownership, caps, and accounting.",
            "Bounty triage gets expensive when control-plane assumptions are scattered across docs and Safe transactions.",
        ],
        "audit_readiness": [
            "Audits check code. ProtocolGate checks who can change the code after the audit.",
            "The audit PDF should not be the only place where proxy-admin and timelock assumptions live.",
            "A pre-audit control-plane map gives auditors the authority model before they have to reconstruct it manually.",
        ],
        "founder": [
            "A protocol can look secure and still be one bad admin path away from crisis.",
            "Before mainnet, founders should know exactly who can upgrade, pause, mint, bridge, and change oracle settings.",
            "The best time to clean up authority risk is before researchers turn it into a public report.",
        ],
    }
    return {
        "theme": theme,
        "posts": library.get(theme, library["bounty_readiness"]),
        "comment_formula": "specific risk -> why it matters -> one ProtocolGate-style question",
    }


def control_plane_hypothesis(*, organization: str, lead_notes: str) -> dict:
    """Build a founder-readable control-plane hypothesis for a target protocol."""

    text = lead_notes.lower()
    surfaces = _surfaces_from_text(text)
    if not surfaces:
        surfaces = ["admin authority", "upgrade path", "signer workflow"]

    proof_questions = []
    if "bridge/OApp path" in surfaces:
        proof_questions.extend(
            [
                "Which endpoint, peer, DVN, executor, delegate, replay, cap, and rate-limit assumptions bound the path?",
                "Can a public bridge path mint, withdraw, or move value without burning or locking caller-owned value?",
            ]
        )
    if "oracle dependency" in surfaces:
        proof_questions.append("What happens when oracle data is stale, missing, manipulated, or decimals-mismatched?")
    if "proxy/admin upgrade path" in surfaces:
        proof_questions.append("Who controls proxy admins, and is upgrade execution delayed by timelocked governance?")
    if "Safe/multisig execution" in surfaces:
        proof_questions.append("Are Safe modules, guards, signer thresholds, and owner rotations documented and bounded?")
    if "privileged proposal flow" in surfaces:
        proof_questions.append("Does reviewed intent match exact calldata, selector, simulation, expiry, and monitor coverage?")

    return {
        "organization": organization,
        "hypothesis": (
            f"{organization or 'This protocol'} likely has buyer pain around "
            + ", ".join(surfaces)
            + "."
        ),
        "likely_surfaces": surfaces,
        "proof_questions": proof_questions or ["Which privileged path can change production behavior, and what evidence bounds it?"],
        "buyer_reason": "This is worth a ProtocolGate conversation if an audit, bounty, launch, upgrade, or cross-chain event is near.",
        "caveat": "This is a sales/research hypothesis, not a vulnerability claim.",
    }


def forecast_bounty_noise(*, lead_notes: str) -> dict:
    """Predict bounty reports a protocol may receive and how to triage them."""

    text = lead_notes.lower()
    lanes = []
    def add(name: str, status: str, evidence: str) -> None:
        lanes.append({"lane": name, "triage_default": status, "evidence_needed": evidence})

    if any(word in text for word in ("bridge", "layerzero", "oapp", "cross-chain", "dvn")):
        add(
            "Bridge missing rate limit / peer / replay / delegate claim",
            "needs evidence",
            "peer config, replay protection, DVN threshold, burn/lock accounting, caps, rate limits, owner/delegate authority",
        )
    if any(word in text for word in ("proxy", "upgrade", "upgradeable", "admin")):
        add(
            "Proxy admin or upgrade authority claim",
            "likely valid if no timelock or multisig evidence",
            "proxy admin owner, timelock delay, multisig threshold, upgrade simulation, storage-layout check",
        )
    if any(word in text for word in ("safe", "multisig", "module", "guard")):
        add(
            "Safe module or weak signer-threshold claim",
            "needs evidence",
            "module inventory, guard config, threshold, owner set, emergency path, signer rotation policy",
        )
    if "oracle" in text:
        add(
            "Oracle staleness/fail-open/decimal claim",
            "likely valid if fail-closed behavior is absent",
            "feed address, heartbeat, decimals normalization, stale-data behavior, fallback behavior",
        )
    if any(word in text for word in ("mint", "burn", "stablecoin", "rwa", "vault", "withdrawal")):
        add(
            "Mint/burn/withdrawal cap claim",
            "needs evidence",
            "caps, roles, rate limits, pause authority, redemption cooldown, accounting invariant",
        )

    if not lanes:
        add(
            "Generic admin/control-plane claim",
            "too vague",
            "specific privileged function, owner path, blast radius, delay, and exploit path",
        )

    return {
        "summary": "Likely bounty noise forecast. Use this before public researcher pressure.",
        "lanes": lanes,
        "protocolgate_angle": "Pre-triage these lanes privately, then document what is real, missing, expected, or bounded.",
    }


def lint_outreach(text: str) -> dict:
    """Score outreach for spam, overclaiming, and missing personalization."""

    lower = text.lower()
    flags: list[str] = []
    spam_score = 0
    if "dear sir" in lower or "i hope this message finds you well" in lower:
        spam_score += 20
        flags.append("generic opener")
    if "replaces audits" in lower or "prevent every exploit" in lower or "guarantee" in lower:
        spam_score += 40
        flags.append("overclaim")
    if "audit" not in lower and "bounty" not in lower and "upgrade" not in lower and "bridge" not in lower and "oracle" not in lower:
        spam_score += 25
        flags.append("no ProtocolGate trigger")
    if "?" not in text:
        spam_score += 15
        flags.append("no direct ask")
    if len(text) > 1_000:
        spam_score += 10
        flags.append("too long")

    if spam_score <= 20:
        verdict = "sendable after human review"
    elif spam_score <= 50:
        verdict = "rewrite before sending"
    else:
        verdict = "do not send"

    return {
        "spam_score": min(spam_score, 100),
        "verdict": verdict,
        "flags": flags,
        "required_fix": "Add one concrete trigger and one hard ask; remove any audit-replacement or exploit-prevention claim.",
    }


def mini_report(*, organization: str, persona: str, lead_notes: str) -> dict:
    """Generate a one-page ProtocolGate buyer packet for a qualified lead."""

    score = score_lead(lead_notes, persona)
    hypothesis = control_plane_hypothesis(organization=organization, lead_notes=lead_notes)
    forecast = forecast_bounty_noise(lead_notes=lead_notes)
    offer = build_offer(urgency="qualified lead", lead_notes=lead_notes)
    return {
        "title": f"ProtocolGate Fit Brief: {organization}",
        "one_liner": "Audits check code. ProtocolGate checks who can change the code.",
        "priority": score.priority,
        "why_now": score.buyer_hypothesis,
        "control_plane_hypothesis": hypothesis,
        "likely_bounty_noise": forecast["lanes"][:5],
        "proposed_review": offer,
        "cta": "Would a fixed-scope 48-hour control-plane triage be useful before your next audit, bounty, upgrade, or cross-chain deployment?",
        "caveat": "This is a fit brief and hypothesis, not a vulnerability report.",
    }


def prepare_call(*, organization: str, persona: str, lead_notes: str, meeting_context: str = "") -> dict:
    """Prepare a 15-minute founder/CTO/security lead call."""

    score = score_lead(f"{lead_notes} {meeting_context}", persona)
    offer = build_offer(urgency=meeting_context or "discovery call", lead_notes=lead_notes)
    return {
        "objective": "Confirm a near-term audit, bounty, upgrade, launch, or cross-chain event and close a paid first pass.",
        "opening": "I am not here to replace your audit. I want to map the authority layer around the audit before it becomes bounty noise or upgrade risk.",
        "qualifying_questions": [
            "What audit, bounty, launch, upgrade, or cross-chain event is coming up?",
            "Which contracts are upgradeable?",
            "Who controls proxy admins?",
            "Which multisigs, timelocks, Safe modules, guardians, bridges, or oracle admins matter?",
            "What would public researchers probably flag first?",
            "Who approves a small fixed-scope security readiness review?",
        ],
        "listen_for": list(score.matched_signals),
        "recommended_offer": offer,
        "close": offer["close"],
    }


def signal_queries(segment: str = "direct_buyer", goal: str = "audit_bounty_readiness") -> dict:
    """Return manual web/LinkedIn search queries for ProtocolGate lead discovery."""

    query_bank = {
        "direct_buyer": [
            '"DeFi founder" "audit"',
            '"CTO" "smart contract audit"',
            '"protocol lead" "bug bounty"',
            '"mainnet launch" "DeFi protocol"',
        ],
        "cross_chain": [
            '"LayerZero OApp" "security"',
            '"cross-chain deployment" "DeFi"',
            '"bridge security" "protocol engineer"',
            '"DVN" "LayerZero" "security"',
        ],
        "rwa_stablecoin": [
            '"RWA protocol" "audit"',
            '"stablecoin protocol" "bug bounty"',
            '"mint burn" "governance" "DeFi"',
            '"vault protocol" "audit"',
        ],
        "platform": [
            '"Immunefi" "triage"',
            '"Cantina" "competition"',
            '"HackenProof" "audit contest"',
            '"CodeHawks" "First Flight"',
        ],
    }
    return {
        "segment": segment,
        "goal": goal,
        "queries": query_bank.get(segment, query_bank["direct_buyer"]),
        "rule": "Use these manually. Do not scrape or automate LinkedIn. Every outbound needs one real trigger and human approval.",
    }


def select_asset(*, persona: str, stage: str, score: int) -> str:
    """Pick the best ProtocolGate asset to send next."""

    persona_text = persona.lower()
    stage_text = stage.lower()
    if "founder" in persona_text or "cto" in persona_text:
        return "docs/CONTROL_PLANE_REVIEW_OFFER.md"
    if "auditor" in persona_text or "researcher" in persona_text:
        return "docs/SAMPLE_CONTROL_PLANE_REPORT.md"
    if "platform" in persona_text or "bounty" in persona_text:
        return "PROTOCOLGATE_OUTREACH.md"
    if "reply" in stage_text or score >= 12:
        return "docs/CONTROL_PLANE_REVIEW_OFFER.md"
    return "README.md"


def log_interaction(
    *,
    lead_name: str,
    organization: str,
    stage: str,
    persona: str,
    notes: str,
    next_action: str,
    pipeline_path: Path = DEFAULT_PIPELINE_PATH,
) -> PipelineEvent:
    """Append a local pipeline event for daily follow-up discipline."""

    if stage not in STAGES:
        raise ValueError(f"stage must be one of: {', '.join(STAGES)}")
    score = score_lead(notes, persona)
    event = PipelineEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        lead_name=lead_name,
        organization=organization,
        stage=stage,
        persona=persona,
        score=score.score,
        priority=score.priority,
        next_action=next_action or score.next_action,
        notes=notes,
    )
    pipeline_path.parent.mkdir(parents=True, exist_ok=True)
    with pipeline_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(event), sort_keys=True) + "\n")
    return event


def pipeline_summary(pipeline_path: Path = DEFAULT_PIPELINE_PATH) -> dict:
    """Summarize local ProtocolGate pipeline events."""

    events = _read_events(pipeline_path)
    stage_counts = {stage: 0 for stage in STAGES}
    priority_counts = {"A": 0, "B": 0, "C": 0}
    for event in events:
        stage_counts[event.stage] = stage_counts.get(event.stage, 0) + 1
        priority_counts[event.priority] = priority_counts.get(event.priority, 0) + 1

    followups = [
        asdict(event)
        for event in events[-20:]
        if event.stage in {"replied", "call_booked", "pain_confirmed", "offer_sent", "paid_pilot_proposed"}
    ]
    return {
        "pipeline_path": _display_path(pipeline_path),
        "total_events": len(events),
        "stage_counts": stage_counts,
        "priority_counts": priority_counts,
        "hot_followups": followups[-10:],
    }


def war_room(
    *,
    lead_name: str,
    organization: str,
    persona: str,
    lead_notes: str,
    stage: str = "cold",
) -> dict:
    """One-shot workflow: score a lead, choose angle, write outreach, and propose the close."""

    score = score_lead(lead_notes, persona)
    outreach = generate_outreach(
        lead_name=lead_name,
        organization=organization,
        persona=persona,
        lead_notes=lead_notes,
        stage=stage,
    )
    offer = build_offer(urgency=stage, lead_notes=lead_notes)
    return {
        "lead": {"name": lead_name, "organization": organization, "persona": persona},
        "score": asdict(score),
        "outreach": outreach,
        "offer": offer,
        "objections": objection_responses(),
        "same_day_move": _same_day_move(score),
    }


def objection_responses() -> dict[str, str]:
    """Founder/CTO objection responses that keep ProtocolGate claims precise."""

    return {
        "we_already_have_audits": "Good. ProtocolGate is audit-adjacent: it turns admin, bridge, oracle, proposal, and drift assumptions into an artifact that survives after the audit.",
        "we_already_have_a_bounty": "That makes this more urgent. A bounty invites researchers to attack the control plane. ProtocolGate helps triage what is real, missing, bounded, or noisy before reports arrive.",
        "is_this_a_scanner": "No. It is a control-plane readiness layer: authority map, policy findings, bounty notes, and remediation order.",
        "can_you_prove_we_are_safe": "No serious review should claim that. ProtocolGate proves a narrower useful thing: the declared authority model satisfies checks and high-risk exposures have evidence.",
    }


def _surfaces_from_text(text: str) -> list[str]:
    surfaces: list[str] = []
    if any(word in text for word in ("bridge", "layerzero", "oapp", "cross-chain", "dvn")):
        surfaces.append("bridge/OApp path")
    if "oracle" in text:
        surfaces.append("oracle dependency")
    if any(word in text for word in ("proxy", "upgrade", "upgradeable", "admin")):
        surfaces.append("proxy/admin upgrade path")
    if any(word in text for word in ("safe", "multisig", "module", "guard")):
        surfaces.append("Safe/multisig execution")
    if any(word in text for word in ("proposal", "governance", "timelock")):
        surfaces.append("privileged proposal flow")
    if any(word in text for word in ("mint", "burn", "withdraw", "stablecoin", "rwa", "vault", "lending")):
        surfaces.append("mint/burn/withdrawal controls")
    return surfaces


def _read_events(pipeline_path: Path) -> list[PipelineEvent]:
    if not pipeline_path.exists():
        return []
    events: list[PipelineEvent] = []
    for line in pipeline_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            events.append(PipelineEvent(**payload))
        except (json.JSONDecodeError, TypeError):
            continue
    return events


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return path.name


def _buyer_hypothesis(positives: Iterable[str], negatives: Iterable[str]) -> str:
    positive_list = list(dict.fromkeys(positives))
    negative_list = list(dict.fromkeys(negatives))
    if positive_list:
        return "Likely pain: " + "; ".join(positive_list[:5]) + "."
    if negative_list:
        return "Weak fit until a real audit, bounty, upgrade, bridge, oracle, or admin trigger appears."
    return "Unknown fit. Need one concrete trigger before outreach."


def _next_action(priority: str, positives: list[str]) -> str:
    if priority == "A":
        return "Send custom DM today and ask for a paid 48-hour triage."
    if priority == "B":
        return "Ask one qualifying question and route toward the security owner."
    return "Do not pitch yet; find a stronger trigger or move on."


def _custom_trigger(notes: str) -> str:
    text = notes.strip()
    if len(text) < 30:
        return ""
    score = score_lead(text)
    if not score.matched_signals:
        return ""
    return score.matched_signals[0]


def _same_day_move(score: LeadScore) -> str:
    if score.priority == "A":
        return "Send the DM, then log the lead as touched with a 48-hour follow-up."
    if score.priority == "B":
        return "Ask for the person who owns audit/bounty readiness; do not send a deck yet."
    return "Skip unless you can find a stronger trigger from a recent post, bounty, audit, or launch."
