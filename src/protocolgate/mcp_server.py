from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from protocolgate.bounty_scope import analyze_bounty_reportability
from protocolgate.revenue import (
    PROJECT_ROOT,
    build_offer,
    content_angles,
    control_plane_hypothesis,
    daily_briefing,
    forecast_bounty_noise,
    generate_outreach,
    lint_outreach,
    log_interaction,
    mini_report,
    objection_responses,
    pipeline_summary,
    prepare_call,
    score_lead,
    select_asset,
    signal_queries,
    war_room,
)


CHARACTER_LIMIT = 25_000

mcp = FastMCP("protocolgate_mcp")


class ResponseFormat(str, Enum):
    MARKDOWN = "markdown"
    JSON = "json"


class LeadScoreInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    lead_notes: str = Field(
        ...,
        description="Pasted notes from a founder/CTO/security lead profile, post, protocol page, bounty page, or audit announcement.",
        min_length=10,
        max_length=8_000,
    )
    persona: str = Field(default="founder", description="Buyer persona, e.g. founder, CTO, protocol security lead, auditor.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class OutreachInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    lead_name: str = Field(default="", description="Person's first name if known.")
    organization: str = Field(default="", description="Protocol, company, DAO, or platform name.")
    persona: str = Field(default="founder", description="Buyer persona.")
    lead_notes: str = Field(..., description="Concrete trigger notes. Must include real audit/bounty/upgrade/bridge/oracle/admin context.", min_length=10, max_length=8_000)
    stage: str = Field(default="cold", description="cold, connected, replied, call_booked, offer_sent, follow_up.")
    tone: str = Field(default="direct", description="direct, technical, or founder.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class OfferInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    urgency: str = Field(..., description="Near-term event, e.g. audit, bounty, upgrade, launch, cross-chain deployment.", min_length=3, max_length=1_000)
    lead_notes: str = Field(..., description="Buyer/protocol context.", min_length=10, max_length=8_000)
    budget_hint: str = Field(default="", description="Optional budget signal or pricing objection.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class LogInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    lead_name: str = Field(default="", description="Person's name.")
    organization: str = Field(default="", description="Protocol/company/DAO.")
    stage: str = Field(..., description="Pipeline stage: identified, touched, replied, call_booked, pain_confirmed, offer_sent, paid_pilot_proposed, closed, dead.")
    persona: str = Field(default="founder", description="Buyer persona.")
    notes: str = Field(..., description="Interaction notes and buyer trigger.", min_length=3, max_length=8_000)
    next_action: str = Field(default="", description="Next follow-up action.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class PipelineInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class ContentInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    theme: str = Field(default="bounty_readiness", description="bounty_readiness, audit_readiness, or founder.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class TextInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    text: str = Field(..., description="Text to lint or analyze.", min_length=3, max_length=8_000)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class BountyGateInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    scope_text: str = Field(
        ...,
        description="Pasted bounty, audit-contest, or Immunefi/Cantina/HackenProof scope text.",
        min_length=20,
        max_length=20_000,
    )
    candidate_notes: str = Field(
        default="",
        description="Candidate finding notes: actor, path, impact, PoC, scope references, and kill checks.",
        max_length=12_000,
    )
    program_name: str = Field(default="", description="Optional program or competition name.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class HypothesisInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    organization: str = Field(default="", description="Protocol, company, or DAO name.")
    lead_notes: str = Field(..., description="Target context, docs, posts, launch/audit/bounty notes, or protocol summary.", min_length=10, max_length=8_000)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class MiniReportInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    organization: str = Field(..., description="Protocol, company, or DAO name.", min_length=1, max_length=200)
    persona: str = Field(default="founder", description="Buyer persona.")
    lead_notes: str = Field(..., description="Target context with concrete audit/bounty/upgrade/control-plane signals.", min_length=10, max_length=8_000)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class CallPrepInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    organization: str = Field(..., description="Protocol, company, or DAO name.", min_length=1, max_length=200)
    persona: str = Field(default="founder", description="Buyer persona.")
    lead_notes: str = Field(..., description="Target context with concrete signals.", min_length=10, max_length=8_000)
    meeting_context: str = Field(default="", description="Reply context, scheduled call notes, objection, or buyer ask.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class SignalQueryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    segment: str = Field(default="direct_buyer", description="direct_buyer, cross_chain, rwa_stablecoin, or platform.")
    goal: str = Field(default="audit_bounty_readiness", description="Current search goal.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class AssetInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    persona: str = Field(default="founder", description="Buyer persona.")
    stage: str = Field(default="cold", description="Conversation stage.")
    score: int = Field(default=0, ge=0, le=100, description="Lead score if known.")


class WarRoomInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    lead_name: str = Field(default="", description="Person's first name if known.")
    organization: str = Field(default="", description="Protocol, company, DAO, or platform.")
    persona: str = Field(default="founder", description="Buyer persona.")
    lead_notes: str = Field(..., description="Concrete buyer trigger notes from public profile, site, bounty, audit, or post.", min_length=10, max_length=8_000)
    stage: str = Field(default="cold", description="cold, connected, replied, call_booked, offer_sent, follow_up.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


@mcp.tool(
    name="protocolgate_daily_briefing",
    annotations={"title": "ProtocolGate Daily Client Briefing", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_daily_briefing(response_format: ResponseFormat = ResponseFormat.MARKDOWN) -> str:
    """Return the daily ProtocolGate client-acquisition operating plan.

    Use this first each day to focus on buyer outreach, hard asks, search
    queries, and the current one-line ProtocolGate positioning.
    """

    return _format(daily_briefing(), response_format)


@mcp.tool(
    name="protocolgate_score_lead",
    annotations={"title": "Score ProtocolGate Lead", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_score_lead(params: LeadScoreInput) -> str:
    """Score a Web3 lead for ProtocolGate buyer fit from pasted notes.

    This is the anti-random-DM gate. Use it before outreach to decide whether a
    founder, CTO, security lead, auditor, or platform contact has real audit,
    bounty, upgrade, bridge, oracle, governance, Safe, or proxy-admin urgency.
    """

    return _format(score_lead(params.lead_notes, params.persona).__dict__, params.response_format)


@mcp.tool(
    name="protocolgate_generate_outreach",
    annotations={"title": "Generate ProtocolGate Outreach", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_generate_outreach(params: OutreachInput) -> str:
    """Generate a custom ProtocolGate DM, comment, or follow-up.

    The tool refuses generic spam. It needs a concrete public trigger such as an
    audit, bounty, upgrade, bridge/OApp launch, oracle dependency, governance
    proposal, Safe/multisig/timelock, or bounty platform context.
    """

    payload = generate_outreach(
        lead_name=params.lead_name,
        organization=params.organization,
        persona=params.persona,
        lead_notes=params.lead_notes,
        stage=params.stage,
        tone=params.tone,  # type: ignore[arg-type]
    )
    return _format(payload, params.response_format)


@mcp.tool(
    name="protocolgate_war_room",
    annotations={"title": "ProtocolGate Lead War Room", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_war_room(params: WarRoomInput) -> str:
    """Run the full ProtocolGate lead workflow in one call.

    Scores the lead, extracts the buyer hypothesis, generates non-spam
    outreach, picks the asset to send, builds the likely offer, includes
    objection responses, and recommends the same-day move.
    """

    payload = war_room(
        lead_name=params.lead_name,
        organization=params.organization,
        persona=params.persona,
        lead_notes=params.lead_notes,
        stage=params.stage,
    )
    return _format(payload, params.response_format)


@mcp.tool(
    name="protocolgate_build_offer",
    annotations={"title": "Build ProtocolGate Offer", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_build_offer(params: OfferInput) -> str:
    """Build a price-anchored ProtocolGate offer for a qualified buyer.

    Use after a reply or discovery call. It chooses between 48-hour triage,
    Audit/Bounty Readiness Review, and Pre-Bounty Hardening Sprint based on
    urgency and buyer context.
    """

    payload = build_offer(urgency=params.urgency, lead_notes=params.lead_notes, budget_hint=params.budget_hint)
    return _format(payload, params.response_format)


@mcp.tool(
    name="protocolgate_log_interaction",
    annotations={"title": "Log ProtocolGate Pipeline Interaction", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
)
async def protocolgate_log_interaction(params: LogInput) -> str:
    """Append a local ProtocolGate pipeline event.

    Writes to `.protocolgate/client_pipeline.jsonl` inside the ProtocolGate
    repo. Use after touching a lead, receiving a reply, booking a call, sending
    an offer, proposing a paid pilot, or closing/dead-ending a conversation.
    """

    event = log_interaction(
        lead_name=params.lead_name,
        organization=params.organization,
        stage=params.stage,
        persona=params.persona,
        notes=params.notes,
        next_action=params.next_action,
    )
    return _format(event.__dict__, params.response_format)


@mcp.tool(
    name="protocolgate_pipeline_summary",
    annotations={"title": "ProtocolGate Pipeline Summary", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_pipeline_summary(params: PipelineInput) -> str:
    """Summarize the local ProtocolGate client pipeline and hot follow-ups."""

    return _format(pipeline_summary(), params.response_format)


@mcp.tool(
    name="protocolgate_content_angles",
    annotations={"title": "ProtocolGate Content Angles", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_content_angles(params: ContentInput) -> str:
    """Return daily LinkedIn/X content angles for ProtocolGate promotion."""

    return _format(content_angles(params.theme), params.response_format)


@mcp.tool(
    name="protocolgate_signal_queries",
    annotations={"title": "ProtocolGate Signal Queries", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_signal_queries(params: SignalQueryInput) -> str:
    """Return manual search queries for finding high-fit ProtocolGate leads.

    This tool does not scrape. It gives manual search strings for buyer segments
    such as direct buyers, cross-chain teams, RWA/stablecoin teams, and audit or
    bounty platforms.
    """

    return _format(signal_queries(params.segment, params.goal), params.response_format)


@mcp.tool(
    name="protocolgate_control_plane_hypothesis",
    annotations={"title": "Build Control-Plane Hypothesis", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_control_plane_hypothesis(params: HypothesisInput) -> str:
    """Build a founder-readable control-plane hypothesis for a target protocol.

    Use when an operator has public notes about a target and needs a credible reason to
    reach out. The output is explicitly a hypothesis, not a vulnerability claim.
    """

    return _format(
        control_plane_hypothesis(organization=params.organization, lead_notes=params.lead_notes),
        params.response_format,
    )


@mcp.tool(
    name="protocolgate_forecast_bounty_noise",
    annotations={"title": "Forecast Bounty Noise", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_forecast_bounty_noise(params: HypothesisInput) -> str:
    """Forecast likely bounty reports and triage evidence for a target protocol.

    This is the Veda/SonicUSD lesson packaged as a workflow: scary-looking
    exposures are separated into likely valid, likely noisy, and needs-evidence
    lanes before public researcher pressure arrives.
    """

    return _format(forecast_bounty_noise(lead_notes=params.lead_notes), params.response_format)


@mcp.tool(
    name="protocolgate_bounty_reportability_gate",
    annotations={"title": "Bounty Reportability Gate", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_bounty_reportability_gate(params: BountyGateInput) -> str:
    """Parse bounty scope and decide whether a candidate should be submitted.

    This is the anti-noise gate for active hunts. It extracts in-scope and
    out-of-scope signals, trusted-role and centralization exclusions, PoC
    requirements, rewards, and commit/version references, then returns
    submit/defer/kill with missing evidence.
    """

    result = analyze_bounty_reportability(
        params.scope_text,
        candidate_notes=params.candidate_notes,
        program_name=params.program_name,
    )
    return _format(asdict(result), params.response_format)


@mcp.tool(
    name="protocolgate_lint_outreach",
    annotations={"title": "Lint ProtocolGate Outreach", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_lint_outreach(params: TextInput) -> str:
    """Check outreach for spam risk, weak personalization, and overclaims."""

    return _format(lint_outreach(params.text), params.response_format)


@mcp.tool(
    name="protocolgate_generate_mini_report",
    annotations={"title": "Generate ProtocolGate Mini Report", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_generate_mini_report(params: MiniReportInput) -> str:
    """Generate a one-page buyer fit brief for a high-fit ProtocolGate target."""

    return _format(
        mini_report(organization=params.organization, persona=params.persona, lead_notes=params.lead_notes),
        params.response_format,
    )


@mcp.tool(
    name="protocolgate_prepare_call",
    annotations={"title": "Prepare ProtocolGate Founder Call", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_prepare_call(params: CallPrepInput) -> str:
    """Prepare a 15-minute founder/CTO/security-lead call and close path."""

    return _format(
        prepare_call(
            organization=params.organization,
            persona=params.persona,
            lead_notes=params.lead_notes,
            meeting_context=params.meeting_context,
        ),
        params.response_format,
    )


@mcp.tool(
    name="protocolgate_select_asset",
    annotations={"title": "Select ProtocolGate Asset", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_select_asset(params: AssetInput) -> str:
    """Pick the best ProtocolGate asset to send based on persona and stage."""

    return select_asset(persona=params.persona, stage=params.stage, score=params.score)


@mcp.tool(
    name="protocolgate_objection_responses",
    annotations={"title": "ProtocolGate Objection Responses", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def protocolgate_objection_responses(response_format: ResponseFormat = ResponseFormat.MARKDOWN) -> str:
    """Return precise responses to common founder/CTO objections."""

    return _format(objection_responses(), response_format)


@mcp.resource("protocolgate://offer")
async def protocolgate_offer_resource() -> str:
    """Read the current ProtocolGate paid review offer."""

    return _read_text(PROJECT_ROOT / "docs" / "CONTROL_PLANE_REVIEW_OFFER.md")


@mcp.resource("protocolgate://sample-report")
async def protocolgate_sample_report_resource() -> str:
    """Read the current buyer-facing sample control-plane report."""

    return _read_text(PROJECT_ROOT / "docs" / "SAMPLE_CONTROL_PLANE_REPORT.md")


@mcp.resource("protocolgate://outreach")
async def protocolgate_outreach_resource() -> str:
    """Read the current ProtocolGate B2B contract-hunt playbook."""

    return _read_text(PROJECT_ROOT / "PROTOCOLGATE_OUTREACH.md")


@mcp.prompt("protocolgate_daily_war_room")
def protocolgate_daily_war_room_prompt() -> str:
    """Prompt for running a daily ProtocolGate client-acquisition session."""

    return (
        "Run ProtocolGate daily war room. Start with protocolgate_daily_briefing, "
        "then review yesterday's protocolgate_pipeline_summary, identify hot follow-ups, "
        "generate outreach only for leads with concrete audit/bounty/upgrade/bridge/oracle triggers, "
        "and end by logging next actions."
    )


@mcp.prompt("protocolgate_founder_close")
def protocolgate_founder_close_prompt() -> str:
    """Prompt for converting a founder reply into a paid ProtocolGate pilot."""

    return (
        "Given a founder/CTO reply, use protocolgate_score_lead, protocolgate_build_offer, "
        "and protocolgate_generate_outreach to move toward a 48-hour paid control-plane triage. "
        "Stay precise: ProtocolGate complements audits and does not promise exploit prevention."
    )


@mcp.prompt("protocolgate_bounty_noise_forecast")
def protocolgate_bounty_noise_forecast_prompt() -> str:
    """Prompt for turning a target protocol into a bounty-readiness angle."""

    return (
        "Use protocolgate_control_plane_hypothesis and protocolgate_forecast_bounty_noise "
        "on the target notes. Separate real exploit-path candidates from scary-looking but "
        "bounded exposures. Then generate a mini report and a non-spam founder DM."
    )


@mcp.prompt("protocolgate_competition_triage")
def protocolgate_competition_triage_prompt() -> str:
    """Prompt for running a bounty-scope gate before report writing."""

    return (
        "Paste the current bounty or audit competition scope into "
        "protocolgate_bounty_reportability_gate with candidate notes. Do not draft "
        "a submission until the gate returns submit or the missing evidence list has "
        "been resolved. Kill trusted-role-only, known-issue, centralization, and "
        "no-exploit-path candidates quickly."
    )


def _read_text(path: Path) -> str:
    try:
        return _truncate(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return (
            f"Error: could not read {_display_path(path)}: {exc.strerror or exc}. "
            "Check that the ProtocolGate repo assets exist."
        )


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return path.name


def _format(payload: object, response_format: ResponseFormat) -> str:
    if response_format == ResponseFormat.JSON:
        return _truncate(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return _truncate(_markdown(payload))


def _markdown(payload: object, level: int = 1) -> str:
    if isinstance(payload, dict):
        lines: list[str] = []
        for key, value in payload.items():
            title = str(key).replace("_", " ").title()
            if isinstance(value, (dict, list, tuple)):
                lines.append(f"{'#' * min(level + 1, 6)} {title}")
                lines.append(_markdown(value, level + 1))
            else:
                lines.append(f"- **{title}:** {value}")
        return "\n".join(lines)
    if isinstance(payload, (list, tuple)):
        return "\n".join(f"- {item}" for item in payload)
    return str(payload)


def _truncate(text: str) -> str:
    if len(text) <= CHARACTER_LIMIT:
        return text
    return (
        text[:CHARACTER_LIMIT]
        + "\n\n[truncated: narrow the request or use JSON output to inspect specific fields]"
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
