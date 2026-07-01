from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from protocolgate.bounty_scope import BountyReportability
from protocolgate.drift import DriftFinding
from protocolgate.report import Violation
from protocolgate.rules_support import Manifest


CAPSULE_SCHEMA_VERSION = 1
CAPSULE_TYPE = "protocolgate.verdict_capsule.v1"


@dataclass(frozen=True)
class VerdictCapsule:
    """Structured memory handoff for bounty composition workflows.

    Capsules are advisory records. They preserve what a deterministic
    ProtocolGate workflow found or killed so a memory layer can later compose
    cross-target attack lanes without changing current verdicts.
    """

    capsule_id: str
    schema_version: int
    capsule_type: str
    created_at: str
    producer: str
    workflow: str
    source: str
    target: str
    target_name: str
    lane: str
    result: str
    status: str
    title: str
    summary: str
    tags: tuple[str, ...]
    evidence: dict[str, Any]
    blockers: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    next_actions: tuple[str, ...]
    reopen_if: tuple[str, ...]
    memory: dict[str, Any]
    metadata: dict[str, Any]


@dataclass(frozen=True)
class DeadLaneConstraint:
    """Reusable negative-knowledge record compiled from killed capsules."""

    constraint_id: str
    source_capsule_id: str
    target: str
    target_name: str
    lane: str
    hypothesis: str
    reason: str
    invariant_tested: Any
    files_contracts: Any
    role_assumptions: Any
    live_config_assumptions: Any
    poc_status: str
    evidence_grade: str
    tests_run: tuple[str, ...]
    scope_severity_reason: str
    blockers: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    reopen_if: tuple[str, ...]
    tags: tuple[str, ...]
    confidence: str
    related_invariant_family: str


def validate_verdict_capsules(
    *,
    manifest: Manifest,
    target: str,
    findings: Iterable[Violation],
) -> tuple[VerdictCapsule, ...]:
    """Convert normal policy findings into JSONL-ready verdict capsules."""

    target_name = _target_name_from_manifest(manifest)
    manifest_fingerprint = value_fingerprint(manifest)
    capsules: list[VerdictCapsule] = []
    for finding in findings:
        lane = _lane_for_policy_rule(finding.rule_id)
        evidence = _normalized_evidence(
            workflow="validate",
            result="open_door",
            invariant_tested={
                "rule_id": finding.rule_id,
                "policy_path": finding.path,
                "message": finding.message,
                "recommendation": finding.recommendation,
            },
            files_contracts=_files_contracts_for_path(manifest, finding.path),
            role_assumptions=_role_assumptions_for_rule(finding.rule_id),
            live_config_assumptions={
                "requires_live_config": False,
                "note": "validate checks declared topology, not live chain state",
            },
            poc_status="not_started",
            input_fingerprints={"manifest": manifest_fingerprint},
            grade="manifest-policy-failure",
        )
        capsules.append(
            VerdictCapsule(
                capsule_id=_capsule_id("validate", target, manifest_fingerprint, finding.rule_id, finding.path, finding.message),
                schema_version=CAPSULE_SCHEMA_VERSION,
                capsule_type=CAPSULE_TYPE,
                created_at=_now_iso(),
                producer="protocolgate",
                workflow="validate",
                source="validate",
                target=target,
                target_name=target_name,
                lane=lane,
                result="open_door",
                status="needs_fix_or_review",
                title=f"{finding.rule_id}: {_title_from_message(finding.message)}",
                summary=finding.message,
                tags=_policy_tags("validate", finding, lane),
                evidence=evidence,
                blockers=(),
                missing_evidence=(
                    "source line references if this becomes a bounty candidate",
                    "PoC or concrete execution trace if impact is claimed",
                    "live configuration proof if production drift is relevant",
                ),
                next_actions=(
                    "Fix the declared topology or document why the invariant is intentionally accepted.",
                    "If bounty-hunting, trace the rule to source and build the smallest reproducible impact path.",
                ),
                reopen_if=(),
                memory={"advisory_read_refs": (), "write_status": "local_only"},
                metadata={"advisory": True, "deterministic_verdict_unchanged": True},
            )
        )
    return tuple(capsules)


def hunt_verdict_capsules(
    *,
    manifest: Manifest,
    target: str,
    findings: Iterable[Violation],
) -> tuple[VerdictCapsule, ...]:
    """Convert hunt findings into JSONL-ready verdict capsules."""

    target_name = _target_name_from_manifest(manifest)
    manifest_fingerprint = value_fingerprint(manifest)
    capsules: list[VerdictCapsule] = []
    for finding in findings:
        detail = _hunt_detail(manifest, finding)
        lane = _lane_for_rule(finding.rule_id)
        tags = _hunt_tags(finding, detail)
        missing = (
            "source line references",
            "PoC or concrete execution trace",
            "live configuration proof before submission",
            "duplicate and scope review",
        )
        next_actions = (
            "Trace the modeled invariant into source code.",
            "Build a minimal PoC or fork-state reproduction.",
            "Run bounty-scope before writing a report.",
        )
        reopen_if = (
            "source review proves the protected action is publicly reachable",
            "PoC demonstrates direct value movement or protection bypass",
            "program scope treats this impact category as reportable",
        )
        evidence = _normalized_evidence(
            workflow="hunt",
            result="open_door",
            invariant_tested=detail.get("invariant_tested", {"rule_id": finding.rule_id, "policy_path": finding.path}),
            files_contracts=_files_contracts_for_path(manifest, finding.path, detail=detail),
            role_assumptions={
                "trusted_roles_required": "unknown_until_source_review",
                "attacker": "public actor must be proven before submission",
            },
            live_config_assumptions={
                "requires_live_config": True,
                "note": "hunt findings are candidates until source and production config are checked",
            },
            poc_status="missing",
            input_fingerprints={"manifest": manifest_fingerprint},
            grade="manifest-modeled",
            extra={
                "rule_id": finding.rule_id,
                "severity_hypothesis": finding.severity,
                "path": finding.path,
                "recommendation": finding.recommendation,
                **{key: value for key, value in detail.items() if key != "invariant_tested"},
            },
        )
        capsule = VerdictCapsule(
            capsule_id=_capsule_id("hunt", target, manifest_fingerprint, finding.rule_id, finding.path, finding.message),
            schema_version=CAPSULE_SCHEMA_VERSION,
            capsule_type=CAPSULE_TYPE,
            created_at=_now_iso(),
            producer="protocolgate",
            workflow="hunt",
            source="hunt",
            target=target,
            target_name=target_name,
            lane=lane,
            result="open_door",
            status="needs_source_and_poc",
            title=f"{finding.rule_id}: {_title_from_message(finding.message)}",
            summary=finding.message,
            tags=tags,
            evidence=evidence,
            blockers=(),
            missing_evidence=missing,
            next_actions=next_actions,
            reopen_if=reopen_if,
            memory={"advisory_read_refs": (), "write_status": "local_only"},
            metadata={"advisory": True, "deterministic_verdict_unchanged": True},
        )
        capsules.append(capsule)
    return tuple(capsules)


def drift_verdict_capsules(
    *,
    manifest: Manifest,
    target: str,
    snapshot_target: str,
    snapshot: dict[str, Any],
    findings: Iterable[DriftFinding],
) -> tuple[VerdictCapsule, ...]:
    """Convert runtime drift findings into composition-ready capsules."""

    target_name = _target_name_from_manifest(manifest)
    manifest_fingerprint = value_fingerprint(manifest)
    snapshot_fingerprint = value_fingerprint(snapshot)
    capsules: list[VerdictCapsule] = []
    for finding in findings:
        lane = "runtime_configuration_drift"
        evidence = _normalized_evidence(
            workflow="drift",
            result="open_door",
            invariant_tested={
                "subject": finding.subject,
                "message": finding.message,
                "expected": finding.expected,
                "actual": finding.actual,
            },
            files_contracts={"subjects": (finding.subject,), "paths": ()},
            role_assumptions={
                "trusted_roles_required": "unknown_until_trace_review",
                "operator_path": "live state differs from declared control-plane model",
            },
            live_config_assumptions={
                "requires_live_config": True,
                "snapshot_target": snapshot_target,
                "snapshot_fingerprint": snapshot_fingerprint,
            },
            poc_status="snapshot_evidence_only",
            input_fingerprints={"manifest": manifest_fingerprint, "snapshot": snapshot_fingerprint},
            grade="snapshot-drift",
            extra={
                "severity_hypothesis": finding.severity,
                "subject": finding.subject,
                "expected": finding.expected,
                "actual": finding.actual,
            },
        )
        capsules.append(
            VerdictCapsule(
                capsule_id=_capsule_id(
                    "drift",
                    target,
                    snapshot_target,
                    manifest_fingerprint,
                    snapshot_fingerprint,
                    finding.subject,
                    finding.message,
                ),
                schema_version=CAPSULE_SCHEMA_VERSION,
                capsule_type=CAPSULE_TYPE,
                created_at=_now_iso(),
                producer="protocolgate",
                workflow="drift",
                source="drift",
                target=target,
                target_name=target_name,
                lane=lane,
                result="open_door",
                status="needs_live_config_review",
                title=f"Drift: {_title_from_message(finding.message)}",
                summary=f"{finding.subject}: {finding.message}",
                tags=_drift_tags(finding),
                evidence=evidence,
                blockers=(),
                missing_evidence=(
                    "on-chain transaction or block reference for the drift",
                    "source-level impact trace from drifted config to exploitable behavior",
                    "scope review if submitting as a bounty candidate",
                ),
                next_actions=(
                    "Confirm the snapshot source and block height.",
                    "Trace the drifted object into source-level authority or asset-flow impact.",
                    "Run bounty-scope before writing a bounty report.",
                ),
                reopen_if=(),
                memory={"advisory_read_refs": (), "write_status": "local_only"},
                metadata={"advisory": True, "deterministic_verdict_unchanged": True},
            )
        )
    return tuple(capsules)


def bounty_scope_verdict_capsule(
    *,
    result: BountyReportability,
    scope_target: str,
    candidate_target: str = "",
    scope_fingerprint: str = "",
    candidate_fingerprint: str = "",
) -> VerdictCapsule:
    """Convert a bounty-scope decision into one composition-ready capsule."""

    tags = _bounty_tags(result)
    status = {
        "submit": "reportable_candidate",
        "defer": "needs_evidence",
        "kill": "closed_door",
    }.get(result.verdict, "unknown")
    evidence = _normalized_evidence(
        workflow="bounty-scope",
        result=f"reportability_{result.verdict}",
        invariant_tested={
            "program_name": result.program_name,
            "verdict": result.verdict,
            "score": result.score,
            "confidence": result.confidence,
        },
        files_contracts={"scope_target": scope_target, "candidate_target": candidate_target},
        role_assumptions={
            "trusted_role_blockers": tuple(item for item in result.blockers if "trusted" in item.lower() or "privileged" in item.lower()),
            "public_actor_path_required": True,
        },
        live_config_assumptions={
            "requires_live_config": any("live" in item.lower() for item in result.missing_evidence + result.next_actions),
        },
        poc_status="required" if result.scope.poc_required else "program_dependent",
        input_fingerprints=_input_fingerprints(
            scope_fingerprint=scope_fingerprint,
            candidate_fingerprint=candidate_fingerprint,
        ),
        grade="scope-and-reportability",
        extra={
            "verdict": result.verdict,
            "score": result.score,
            "confidence": result.confidence,
            "matched_in_scope": result.matched_in_scope,
            "positive_signals": result.positive_signals,
            "scope_source_signals": result.scope.source_signals,
            "poc_required": result.scope.poc_required,
            "candidate_target": candidate_target,
        },
    )
    dead_constraints = _dead_lane_constraints_for_bounty_result(result)
    if dead_constraints:
        evidence["dead_lane_constraints"] = dead_constraints
    title = f"Bounty Scope Gate: {result.verdict.upper()} {result.score}/100"
    return VerdictCapsule(
        capsule_id=_capsule_id(
            "bounty_scope",
            scope_target,
            candidate_target,
            result.program_name,
            scope_fingerprint,
            candidate_fingerprint,
            result.verdict,
            str(result.score),
        ),
        schema_version=CAPSULE_SCHEMA_VERSION,
        capsule_type=CAPSULE_TYPE,
        created_at=_now_iso(),
        producer="protocolgate",
        workflow="bounty-scope",
        source="bounty_scope",
        target=scope_target,
        target_name=result.program_name,
        lane="bounty_reportability",
        result=f"reportability_{result.verdict}",
        status=status,
        title=title,
        summary=result.executive_summary,
        tags=tags,
        evidence=evidence,
        blockers=result.blockers,
        missing_evidence=result.missing_evidence,
        next_actions=result.next_actions,
        reopen_if=_bounty_reopen_if(result),
        memory={"advisory_read_refs": (), "write_status": "local_only"},
        metadata={
            "advisory": True,
            "deterministic_verdict_unchanged": True,
            "dead_lane_compiler": bool(dead_constraints),
        },
    )


def compile_dead_lane_constraints(capsules: Iterable[VerdictCapsule]) -> tuple[DeadLaneConstraint, ...]:
    """Compile closed or weak lanes into reusable future-hunt constraints."""

    constraints: list[DeadLaneConstraint] = []
    for capsule in capsules:
        if not _is_dead_lane(capsule):
            continue
        reason = _dead_lane_reason(capsule)
        constraint = DeadLaneConstraint(
            constraint_id=_capsule_id("dead_lane", capsule.capsule_id, capsule.lane, reason),
            source_capsule_id=capsule.capsule_id,
            target=capsule.target,
            target_name=capsule.target_name,
            lane=capsule.lane,
            hypothesis=capsule.summary or capsule.title,
            reason=reason,
            invariant_tested=capsule.evidence.get("invariant_tested", {}),
            files_contracts=capsule.evidence.get("files_contracts", {}),
            role_assumptions=capsule.evidence.get("role_assumptions", {}),
            live_config_assumptions=capsule.evidence.get("live_config_assumptions", {}),
            poc_status=str(capsule.evidence.get("poc_status", "")),
            evidence_grade=str(capsule.evidence.get("grade", "")),
            tests_run=_tuple_from_evidence(capsule.evidence.get("tests_run")),
            scope_severity_reason=_scope_severity_reason(capsule),
            blockers=capsule.blockers,
            missing_evidence=capsule.missing_evidence,
            reopen_if=capsule.reopen_if,
            tags=tuple(tag for tag in capsule.tags if tag in _NEGATIVE_KNOWLEDGE_TAGS),
            confidence=_dead_lane_confidence(capsule),
            related_invariant_family=capsule.lane,
        )
        constraints.append(constraint)
    return tuple(constraints)


def capsules_to_jsonl(capsules: Iterable[VerdictCapsule]) -> str:
    """Render capsules as JSONL."""

    lines = [json.dumps(asdict(capsule), sort_keys=True) for capsule in capsules]
    return "\n".join(lines) + ("\n" if lines else "")


def write_capsules_jsonl(path: Path, capsules: Iterable[VerdictCapsule]) -> int:
    """Append capsules to a JSONL ledger and return the number written."""

    items = tuple(capsules)
    if not items:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(capsules_to_jsonl(items))
    return len(items)


def value_fingerprint(value: Any) -> str:
    """Return a stable content fingerprint without storing raw input text."""

    encoded = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return _sha256_fingerprint(encoded)


def text_fingerprint(text: str) -> str:
    """Return a stable fingerprint for user-provided text."""

    return _sha256_fingerprint(text)


def _target_name_from_manifest(manifest: Manifest) -> str:
    project = manifest.get("project")
    if isinstance(project, dict) and project.get("name"):
        return str(project["name"])
    return "unknown target"


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _input_fingerprints(*, scope_fingerprint: str, candidate_fingerprint: str) -> dict[str, str]:
    fingerprints = {"scope": scope_fingerprint}
    if candidate_fingerprint:
        fingerprints["candidate"] = candidate_fingerprint
    return {key: value for key, value in fingerprints.items() if value}


def _normalized_evidence(
    *,
    workflow: str,
    result: str,
    invariant_tested: dict[str, Any],
    files_contracts: Any,
    role_assumptions: dict[str, Any],
    live_config_assumptions: dict[str, Any],
    poc_status: str,
    input_fingerprints: dict[str, str],
    grade: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = {
        "workflow": workflow,
        "result": result,
        "invariant_tested": invariant_tested,
        "files_contracts": files_contracts,
        "role_assumptions": role_assumptions,
        "live_config_assumptions": live_config_assumptions,
        "poc_status": poc_status,
        "input_fingerprints": input_fingerprints,
        "grade": grade,
    }
    if extra:
        evidence.update(extra)
    return evidence


def _hunt_detail(manifest: Manifest, finding: Violation) -> dict[str, Any]:
    detail: dict[str, Any] = {}
    match = re.fullmatch(r"safety_controls\[(\d+)\]\.protects\[(\d+)\]", finding.path)
    if not match:
        return detail

    control_index = int(match.group(1))
    protect_index = int(match.group(2))
    controls = manifest.get("safety_controls", [])
    if not isinstance(controls, list) or control_index >= len(controls):
        return detail
    control = controls[control_index]
    if not isinstance(control, dict):
        return detail
    protects = control.get("protects", [])
    protected = protects[protect_index] if isinstance(protects, list) and protect_index < len(protects) else {}
    if not isinstance(protected, dict):
        protected = {}

    detail["invariant_tested"] = {
        "safety_control": control.get("name"),
        "contract": control.get("contract"),
        "state_variable": control.get("state_variable"),
        "control_scope": _scope_kind(control.get("scope")),
        "protected_action": protected.get("action"),
        "predicate": protected.get("predicate"),
        "expected_scope": _scope_kind(protected.get("expected_scope")),
        "loss_surface": protected.get("loss_surface") or control.get("loss_surface"),
    }
    bypass = protected.get("bypass_selectors", control.get("bypass_selectors", ()))
    detail["bypass_selectors"] = tuple(str(item) for item in bypass) if isinstance(bypass, list) else tuple()
    detail["boundary_crossed"] = _boundary_tags(
        " ".join(str(value) for value in [finding.message, control.get("name"), protected.get("predicate")])
    )
    return detail


def _files_contracts_for_path(manifest: Manifest, path: str, *, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    subjects: list[str] = []
    if detail:
        invariant = detail.get("invariant_tested")
        if isinstance(invariant, dict):
            for key in ("contract", "protected_action", "state_variable"):
                value = invariant.get(key)
                if value:
                    subjects.append(str(value))

    match = re.match(r"(contracts|multisigs|timelocks|oracles|bridges|treasury|safety_controls|proposal_intent)\[(\d+)\]", path)
    if match:
        collection, index_raw = match.groups()
        index = int(index_raw)
        items = manifest.get(collection, [])
        if isinstance(items, list) and index < len(items) and isinstance(items[index], dict):
            item = items[index]
            for key in ("name", "contract", "target", "asset", "address"):
                if item.get(key):
                    subjects.append(str(item[key]))

    return {"subjects": tuple(dict.fromkeys(subjects)), "paths": (path,)}


def _role_assumptions_for_rule(rule_id: str) -> dict[str, Any]:
    if rule_id in {"CG032", "CG033", "CG034", "CG035", "CG036", "CG037", "CG038"}:
        return {
            "trusted_roles_required": "privileged_proposal_signer_or_executor_context",
            "note": "proposal-intent findings inspect whether privileged execution is reviewable and bounded",
        }
    if rule_id in {"CG001", "CG002", "CG003", "CG011", "CG016", "CG022", "CG026"}:
        return {
            "trusted_roles_required": "admin_or_governance_control_plane_context",
            "note": "validate finding is a topology/control-plane weakness, not proof of public exploitability",
        }
    return {
        "trusted_roles_required": "unknown",
        "note": "role assumptions require source and scope review before bounty submission",
    }


def _lane_for_policy_rule(rule_id: str) -> str:
    if rule_id in {"CG032", "CG033", "CG034", "CG035", "CG036", "CG037", "CG038"}:
        return "proposal_intent_gate"
    if rule_id in {"CG001", "CG002", "CG003", "CG011", "CG013", "CG014", "CG016", "CG022", "CG026"}:
        return "upgrade_admin_control_plane"
    if rule_id in {"CG004", "CG005", "CG006", "CG007", "CG008", "CG012", "CG015", "CG020", "CG021"}:
        return "asset_flow_operational_control"
    return "control_plane_policy_gate"


def _policy_tags(workflow: str, finding: Violation, lane: str) -> tuple[str, ...]:
    tags = ["protocolgate", "verdict-capsule", workflow, "open-door", lane, f"rule-{finding.rule_id.lower()}"]
    severity = finding.severity.lower()
    if severity:
        tags.append(f"severity-{severity}")
    for boundary in _boundary_tags(" ".join((finding.message, finding.path, finding.recommendation, lane))):
        tags.append(f"boundary-{boundary}")
    return tuple(dict.fromkeys(tags))


def _drift_tags(finding: DriftFinding) -> tuple[str, ...]:
    tags = [
        "protocolgate",
        "verdict-capsule",
        "drift",
        "open-door",
        "runtime-configuration-drift",
        f"severity-{finding.severity.lower()}",
        "needs-live-config",
    ]
    for boundary in _boundary_tags(" ".join((finding.subject, finding.message))):
        tags.append(f"boundary-{boundary}")
    return tuple(dict.fromkeys(tags))


def _scope_kind(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and value.get("kind"):
        return str(value["kind"])
    return ""


def _lane_for_rule(rule_id: str) -> str:
    return {
        "CG039": "global_invariant_local_gate",
    }.get(rule_id, "control_plane_hunt")


def _hunt_tags(finding: Violation, detail: dict[str, Any]) -> tuple[str, ...]:
    tags = ["protocolgate", "verdict-capsule", "hunt", "open-door", _lane_for_rule(finding.rule_id)]
    severity = finding.severity.lower()
    if severity:
        tags.append(f"severity-{severity}")
    for boundary in detail.get("boundary_crossed", ()):
        tags.append(f"boundary-{boundary}")
    return tuple(dict.fromkeys(tags))


def _bounty_tags(result: BountyReportability) -> tuple[str, ...]:
    tags = ["protocolgate", "verdict-capsule", "bounty-scope", f"verdict-{result.verdict}"]
    if result.verdict == "submit":
        tags.append("validated-lane")
    elif result.verdict == "defer":
        tags.extend(("needs-evidence", "evidence-gap"))
    elif result.verdict == "kill":
        tags.append("closed-door")
    if result.blockers:
        tags.append("scope-blocked")
    if any("PoC" in item or "poc" in item.lower() for item in result.missing_evidence):
        tags.append("needs-poc")
    return tuple(dict.fromkeys(tags))


def _dead_lane_constraints_for_bounty_result(result: BountyReportability) -> tuple[dict[str, Any], ...]:
    if result.verdict not in {"kill", "defer"}:
        return ()
    reason_items = result.blockers if result.blockers else result.missing_evidence
    if not reason_items:
        reason_items = (result.executive_summary,)
    return tuple(
        {
            "reason": item,
            "verdict": result.verdict,
            "program_name": result.program_name,
            "reopen_if": _bounty_reopen_if(result),
            "constraint_type": "closed_door" if result.verdict == "kill" else "evidence_gap",
        }
        for item in reason_items
    )


def _bounty_reopen_if(result: BountyReportability) -> tuple[str, ...]:
    if result.verdict == "kill":
        return (
            "scope language changes",
            "candidate no longer depends on a trusted role or excluded surface",
            "new PoC proves direct in-scope public-actor impact",
        )
    if result.verdict == "defer":
        return (
            "missing source-to-sink proof is produced",
            "PoC or concrete reproduction exists",
            "public actor path and impact are explicit",
        )
    return ()


_NEGATIVE_KNOWLEDGE_TAGS = frozenset(
    {
        "closed-door",
        "weak-impact",
        "duplicate-risk",
        "trusted-role-only",
        "needs-live-config",
        "needs-poc",
        "scope-blocked",
        "needs-evidence",
        "evidence-gap",
    }
)


def _is_dead_lane(capsule: VerdictCapsule) -> bool:
    tags = set(capsule.tags)
    if capsule.result.endswith("_kill") or capsule.status == "closed_door" or "closed-door" in tags:
        return True
    if capsule.result.endswith("_defer") or capsule.status == "needs_evidence" or "evidence-gap" in tags:
        return True
    return bool({"weak-impact", "duplicate-risk", "trusted-role-only", "scope-blocked"} & tags)


def _dead_lane_reason(capsule: VerdictCapsule) -> str:
    if capsule.blockers:
        return capsule.blockers[0]
    if capsule.missing_evidence:
        return capsule.missing_evidence[0]
    return capsule.summary


def _dead_lane_confidence(capsule: VerdictCapsule) -> str:
    if capsule.status == "closed_door" or capsule.result.endswith("_kill"):
        return "high"
    if "duplicate-risk" in capsule.tags or "scope-blocked" in capsule.tags:
        return "medium"
    return "low"


def _scope_severity_reason(capsule: VerdictCapsule) -> str:
    verdict = capsule.evidence.get("verdict")
    score = capsule.evidence.get("score")
    confidence = capsule.evidence.get("confidence")
    if verdict:
        parts = [f"reportability={verdict}"]
        if score is not None:
            parts.append(f"score={score}")
        if confidence:
            parts.append(f"confidence={confidence}")
        return ", ".join(parts)

    severity = capsule.evidence.get("severity_hypothesis")
    if severity:
        return f"severity_hypothesis={severity}"

    return f"result={capsule.result}, status={capsule.status}"


def _tuple_from_evidence(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return (str(value),)


def _boundary_tags(text: str) -> tuple[str, ...]:
    lowered = text.lower()
    matches = []
    for needle, tag in (
        ("oracle", "oracle"),
        ("settlement", "settlement"),
        ("withdraw", "queue"),
        ("queue", "queue"),
        ("keeper", "keeper"),
        ("upgrade", "upgrade"),
        ("pause", "pause"),
        ("grace", "time"),
        ("timelock", "time"),
        ("chain", "chain"),
        ("bridge", "chain"),
        ("role", "role"),
        ("account", "scope"),
        ("reserve", "scope"),
        ("global", "scope"),
        ("local", "scope"),
        ("accounting", "accounting"),
    ):
        if needle in lowered:
            matches.append(tag)
    return tuple(dict.fromkeys(matches))


def _title_from_message(message: str) -> str:
    value = message.strip()
    if len(value) <= 96:
        return value
    return value[:93].rstrip() + "..."


def _capsule_id(*parts: str) -> str:
    raw = "\x1f".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _sha256_fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]
