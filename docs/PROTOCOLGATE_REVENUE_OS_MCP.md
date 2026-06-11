# ProtocolGate Revenue OS MCP

ProtocolGate Revenue OS is a local MCP server for daily B2B contract outreach.

It is not a CRM, scraper, or auto-DM bot. It is a Web3 security GTM cockpit:

> Find teams with control-plane pain, turn that pain into a founder-readable
> reason to talk, draft non-spam outreach, remember follow-ups, and push toward
> a paid ProtocolGate review.

## Why It Exists

The 2026 market supports this wedge:

- audit and bounty marketplaces still have active payout supply
- full smart-contract audits are expensive enough to anchor paid readiness work
- access control, multisig, proxy/admin, bridge, oracle, and upgrade failures
  remain high-impact risk classes
- bounty triage is noisy when teams do not have control-plane evidence ready
- founders and CTOs understand deadline-driven pain: audit, bounty, upgrade,
  launch, bridge expansion, governance proposal

ProtocolGate's daily job is to convert those signals into conversations.

## What Makes It Different

Most sales tools start with a person and ask, "How do we pitch them?"

ProtocolGate Revenue OS starts with a control-plane trigger:

- new bounty
- audit contest
- bridge/OApp launch
- oracle migration
- proxy-admin transfer
- governance proposal
- Safe module or signer change
- new market/vault/asset
- stablecoin mint/redeem controls

Then it asks:

1. Is this a real ProtocolGate buyer?
2. What control-plane surface is likely painful?
3. What would researchers probably report?
4. What evidence would kill or validate the scary path?
5. What is the smallest paid offer to propose?
6. What should the operator say without sounding generic?

## Tools

### Daily Control

- `protocolgate_daily_briefing` - daily quotas, hard asks, search queries
- `protocolgate_pipeline_summary` - local follow-up and pipeline summary
- `protocolgate_log_interaction` - append one local pipeline event

### Lead Qualification

- `protocolgate_signal_queries` - manual search queries by buyer segment
- `protocolgate_score_lead` - A/B/C lead score from pasted notes
- `protocolgate_war_room` - one-call lead score, outreach, offer, objections
- `protocolgate_select_asset` - pick the right asset for persona/stage

### Unique Security GTM Workflows

- `protocolgate_control_plane_hypothesis` - founder-readable hypothesis, not a
  vulnerability claim
- `protocolgate_forecast_bounty_noise` - likely bounty reports and evidence
  needed
- `protocolgate_generate_mini_report` - one-page buyer fit brief
- `protocolgate_prepare_call` - 15-minute call agenda and close path

### Outreach Guardrails

- `protocolgate_generate_outreach` - custom DM/email/comment draft
- `protocolgate_lint_outreach` - spam and overclaim linting
- `protocolgate_build_offer` - price-anchored package selection
- `protocolgate_objection_responses` - precise founder/CTO objection replies
- `protocolgate_content_angles` - daily LinkedIn/X post angles

## Resources

- `protocolgate://offer`
- `protocolgate://sample-report`
- `protocolgate://outreach`

## Prompts

- `protocolgate_daily_war_room`
- `protocolgate_founder_close`
- `protocolgate_bounty_noise_forecast`

## Local Storage

Pipeline events are stored at:

```text
.protocolgate/client_pipeline.jsonl
```

This is intentionally simple for v1. It keeps the server useful immediately
without building a full CRM.

## Guardrails

- Do not scrape LinkedIn.
- Do not auto-send DMs, emails, or posts.
- Do not call a hypothesis a vulnerability.
- Do not claim ProtocolGate replaces audits.
- Do not claim ProtocolGate prevents every exploit.
- Do not pitch without a concrete trigger.
- Every outbound message needs human review.

## Daily Flow

1. Run `protocolgate_daily_briefing`.
2. Use `protocolgate_signal_queries` to find candidates manually.
3. Paste notes into `protocolgate_score_lead`.
4. For A/B leads, run `protocolgate_war_room`.
5. Lint the draft with `protocolgate_lint_outreach`.
6. Send manually if the message is specific and accurate.
7. Log the touch with `protocolgate_log_interaction`.
8. Use `protocolgate_pipeline_summary` before ending the day.

## Install

From the ProtocolGate repo:

```bash
uv run protocolgate-mcp
```

Configure the MCP client to run that command from:

```text
<protocolgate repo path>
```

The server uses stdio transport by default.
