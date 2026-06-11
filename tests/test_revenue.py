from __future__ import annotations

from pathlib import Path

from protocolgate.revenue import (
    build_offer,
    control_plane_hypothesis,
    forecast_bounty_noise,
    generate_outreach,
    lint_outreach,
    log_interaction,
    mini_report,
    pipeline_summary,
    prepare_call,
    score_lead,
    signal_queries,
    war_room,
)


def test_score_lead_prioritizes_audit_bounty_bridge_context() -> None:
    score = score_lead(
        "Founder of a DeFi stablecoin protocol preparing an Immunefi bounty, "
        "LayerZero OApp bridge launch, Safe multisig, proxy admin migration, and oracle upgrade.",
        persona="founder",
    )

    assert score.priority == "A"
    assert score.score >= 12
    assert "near-term bounty" in score.matched_signals
    assert "bridge control-plane risk" in score.matched_signals


def test_generate_outreach_refuses_generic_notes() -> None:
    result = generate_outreach(
        lead_name="Nia",
        organization="Example",
        persona="founder",
        lead_notes="works in crypto",
    )

    assert result["refusal"] is True
    assert "No concrete trigger" in result["reason"]


def test_generate_outreach_uses_concrete_trigger() -> None:
    result = generate_outreach(
        lead_name="Ari",
        organization="BridgeVault",
        persona="CTO",
        lead_notes="CTO announced a cross-chain LayerZero OApp deployment and new Immunefi bounty for a DeFi vault.",
        tone="founder",
    )

    assert result["refusal"] is False
    assert "BridgeVault" in result["message"]
    assert "control-plane" in result["message"]
    assert result["priority"] == "A"


def test_build_offer_escalates_for_public_bounty() -> None:
    offer = build_offer(
        urgency="Opening Immunefi bounty next month",
        lead_notes="Upgradeable lending protocol with bridge and oracle dependencies.",
    )

    assert offer["package"] == "Pre-Bounty Hardening Sprint"
    assert offer["price"] == "USD 12k-25k"


def test_pipeline_log_and_summary(tmp_path: Path) -> None:
    path = tmp_path / "pipeline.jsonl"
    event = log_interaction(
        lead_name="Dana",
        organization="VaultDAO",
        stage="replied",
        persona="founder",
        notes="Founder replied about upcoming audit and bounty for a vault protocol.",
        next_action="Send offer page.",
        pipeline_path=path,
    )
    summary = pipeline_summary(path)

    assert event.priority == "A"
    assert summary["total_events"] == 1
    assert summary["stage_counts"]["replied"] == 1
    assert summary["hot_followups"][0]["organization"] == "VaultDAO"


def test_war_room_returns_full_sales_packet() -> None:
    packet = war_room(
        lead_name="Mina",
        organization="OracleBridge",
        persona="protocol security lead",
        lead_notes="Security lead posting about oracle migration, governance proposal, Safe multisig, and bridge limits before audit.",
    )

    assert packet["score"]["priority"] == "A"
    assert "outreach" in packet
    assert "offer" in packet
    assert "objections" in packet


def test_control_plane_hypothesis_is_not_a_vulnerability_claim() -> None:
    result = control_plane_hypothesis(
        organization="SonicVault",
        lead_notes="LayerZero OApp bridge, Safe multisig, oracle migration, and proxy admin upgrade before bounty.",
    )

    assert "bridge/OApp path" in result["likely_surfaces"]
    assert "not a vulnerability claim" in result["caveat"]


def test_forecast_bounty_noise_lists_evidence_needed() -> None:
    result = forecast_bounty_noise(
        lead_notes="Upgradeable stablecoin vault with LayerZero bridge, oracle dependency, Safe modules, and mint caps."
    )

    lanes = result["lanes"]
    assert any("Bridge" in lane["lane"] for lane in lanes)
    assert all("evidence_needed" in lane for lane in lanes)


def test_lint_outreach_flags_overclaim() -> None:
    result = lint_outreach("I guarantee ProtocolGate replaces audits and will prevent every exploit.")

    assert result["verdict"] == "do not send"
    assert "overclaim" in result["flags"]


def test_mini_report_and_call_prep_include_close() -> None:
    notes = "Founder preparing Immunefi bounty for RWA stablecoin bridge with Safe multisig and oracle upgrade."
    report = mini_report(organization="RWABridge", persona="founder", lead_notes=notes)
    call = prepare_call(organization="RWABridge", persona="founder", lead_notes=notes)

    assert report["priority"] == "A"
    assert "cta" in report
    assert "close" in call


def test_signal_queries_are_manual_not_scraping() -> None:
    result = signal_queries("cross_chain")

    assert result["queries"]
    assert "Do not scrape" in result["rule"]
