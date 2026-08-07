#!/usr/bin/env python3
"""Authoritative FSM-lite policy for Zhulong Audit State Protocol R2.

This module deliberately validates workflow-record consistency only.  It does
not inspect candidates, verifier verdicts, Docker evidence, dispositions,
bundles, recording archives, or finalization artifacts.  Those facts remain
owned by their existing validators and producer gates.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


TRANSITION_POLICY_VERSION = 1

STAGES = (
    "intake",
    "recon",
    "candidate_generation",
    "triage",
    "verification",
    "severity_escalation",
    "variant_discovery",
    "packaging",
    "finalization",
    "recording",
)
STATUSES = ("running", "paused", "blocked", "completed")
TRANSITION_KINDS = (
    "start",
    "observe",
    "advance",
    "pause",
    "block",
    "resume",
    "skip",
    "return",
    "reopen",
    "complete",
)

# These five fields form one atomic policy metadata set.  Their absence means
# a pre-P9.3 R2 record; a partial set is never silently interpreted.
POLICY_EVENT_FIELDS = (
    "from_stage",
    "transition_kind",
    "transition_policy_version",
    "blocker",
    "resume_step",
)

# This is the only stage-edge source of truth.  It intentionally leaves many
# plausible paths unavailable until a concrete product need establishes them.
FORWARD_STAGE_EDGES: dict[str, frozenset[str]] = {
    "intake": frozenset({"recon"}),
    "recon": frozenset({"candidate_generation"}),
    "candidate_generation": frozenset({"triage"}),
    "triage": frozenset({"verification"}),
    "verification": frozenset({"severity_escalation", "variant_discovery", "packaging", "finalization"}),
    "severity_escalation": frozenset({"variant_discovery", "packaging", "finalization"}),
    "variant_discovery": frozenset({"packaging", "finalization"}),
    "packaging": frozenset({"finalization"}),
    "finalization": frozenset({"recording"}),
    "recording": frozenset(),
}

# A return is intentionally narrower than "any earlier stage".  In
# particular, candidate discovery can route a candidate back to independent
# verification, and a finalization gate can return unresolved work to the
# relevant verification/packaging stage without claiming any promotion.
RETURN_STAGE_EDGES: dict[str, frozenset[str]] = {
    "intake": frozenset(),
    "recon": frozenset(),
    "candidate_generation": frozenset({"recon"}),
    "triage": frozenset({"recon", "candidate_generation"}),
    "verification": frozenset({"recon", "candidate_generation", "triage"}),
    "severity_escalation": frozenset({"verification"}),
    "variant_discovery": frozenset({"verification"}),
    "packaging": frozenset({"verification", "severity_escalation", "variant_discovery"}),
    "finalization": frozenset({"verification", "severity_escalation", "variant_discovery", "packaging"}),
    "recording": frozenset({"finalization", "packaging"}),
}

# A conditional stage may be completed as not applicable.  Mandatory
# verification, packaging, and finalization are deliberately absent: a state
# event cannot skip their independent artifact gates.
OPTIONAL_STAGES = frozenset({"severity_escalation", "variant_discovery", "recording"})

ENHANCED_REASON_CODES: dict[str, frozenset[str]] = {
    "resume": frozenset(
        {
            "prerequisite_missing",
            "policy_or_safety_block",
            "verification_blocked",
            "external_dependency",
            "manual_review_required",
            "recovery_requested",
            "operator_request",
        }
    ),
    "skip": frozenset({"not_applicable", "scope_change"}),
    "return": frozenset(
        {
            "validation_failed",
            "prerequisite_missing",
            "verification_blocked",
            "scope_change",
            "manual_review_required",
            "recovery_requested",
        }
    ),
    "reopen": frozenset({"validation_failed", "recovery_requested", "scope_change", "manual_review_required", "operator_request"}),
}


class TransitionPolicyError(Exception):
    """Stable policy rejection that callers can expose without parsing prose."""

    def __init__(self, code: str, message: str, *, event_index: int | None = None) -> None:
        self.code = code
        self.message = message
        self.event_index = event_index
        super().__init__(message)


@dataclass(frozen=True)
class TransitionState:
    stage: str | None = None
    status: str | None = None
    blocker: str | None = None
    resume_step: str | None = None


def _fail(code: str, message: str) -> None:
    raise TransitionPolicyError(code, message)


def _nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _nullable_context(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    if not _nonempty_text(value):
        _fail("INVALID_TRANSITION_CONTEXT", f"{field} must be null or a non-empty string")
    if len(value) > 2048:
        _fail("INVALID_TRANSITION_CONTEXT", f"{field} exceeds the maximum length of 2048")
    return value


def validate_transition_metadata(event: dict[str, Any]) -> str:
    """Validate optional P9.3 metadata without rewriting legacy R2 events."""
    present = {field for field in POLICY_EVENT_FIELDS if field in event}
    if not present:
        return "pre_policy_r2"
    missing = [field for field in POLICY_EVENT_FIELDS if field not in event]
    if missing:
        _fail(
            "TRANSITION_METADATA_INCOMPLETE",
            "P9.3 transition metadata must be present as one complete set; missing " + ", ".join(missing),
        )

    version = event["transition_policy_version"]
    if type(version) is not int or version != TRANSITION_POLICY_VERSION:
        _fail(
            "TRANSITION_POLICY_VERSION_UNSUPPORTED",
            f"transition_policy_version must be {TRANSITION_POLICY_VERSION}",
        )
    from_stage = event["from_stage"]
    if from_stage is not None and from_stage not in STAGES:
        _fail("INVALID_FROM_STAGE", "from_stage must be null or a canonical Zhulong stage")
    transition_kind = event["transition_kind"]
    if transition_kind not in TRANSITION_KINDS:
        _fail("INVALID_TRANSITION_KIND", "transition_kind is not recognized by the authoritative policy")
    _nullable_context(event["blocker"], field="blocker")
    _nullable_context(event["resume_step"], field="resume_step")
    return "transition_policy_v1"


def _validate_context_for_target(event: dict[str, Any]) -> None:
    target_status = str(event["to_status"])
    blocker = event["blocker"]
    resume_step = event["resume_step"]
    if target_status in {"paused", "blocked"}:
        if not _nonempty_text(blocker):
            _fail("TRANSITION_BLOCKER_REQUIRED", f"{target_status} transition requires a non-empty blocker")
        if not _nonempty_text(resume_step):
            _fail("TRANSITION_RESUME_STEP_REQUIRED", f"{target_status} transition requires a non-empty resume_step")
    elif blocker is not None or resume_step is not None:
        _fail("TRANSITION_STALE_BLOCKER_FIELDS", f"{target_status} transition requires blocker and resume_step to be null")


def _validate_enhanced_material(event: dict[str, Any], transition_kind: str) -> None:
    if transition_kind not in ENHANCED_REASON_CODES:
        return
    if event.get("reason_code") not in ENHANCED_REASON_CODES[transition_kind]:
        _fail(
            "TRANSITION_REASON_CODE_INVALID",
            f"{transition_kind} requires a documented non-default reason_code",
        )
    details = event.get("details")
    if not isinstance(details, dict) or not _nonempty_text(details.get("reason_detail")):
        _fail("TRANSITION_REASON_DETAIL_REQUIRED", f"{transition_kind} requires details.reason_detail")
    subjects = event.get("subjects")
    if not isinstance(subjects, list) or not subjects:
        _fail("TRANSITION_SUBJECT_REQUIRED", f"{transition_kind} requires at least one subject")
    evidence_refs = event.get("evidence_refs")
    if not isinstance(evidence_refs, list) or not evidence_refs:
        _fail("TRANSITION_EVIDENCE_REQUIRED", f"{transition_kind} requires at least one evidence_ref")
    next_actions = event.get("next_actions")
    if not isinstance(next_actions, list) or not next_actions:
        _fail("TRANSITION_NEXT_ACTION_REQUIRED", f"{transition_kind} requires at least one next_action")


def _validate_source(current: TransitionState, event: dict[str, Any]) -> None:
    recorded_from_stage = event.get("from_stage")
    recorded_from_status = event.get("from_status")
    if current.stage is None:
        if recorded_from_stage is not None:
            _fail("SOURCE_STAGE_MISMATCH", "the first transition must record from_stage=null")
        if recorded_from_status is not None:
            _fail("SOURCE_STATUS_MISMATCH", "the first transition must record from_status=null")
        return
    if recorded_from_stage != current.stage:
        _fail("SOURCE_STAGE_MISMATCH", "from_stage does not match the locked current stage")
    if recorded_from_status != current.status:
        _fail("SOURCE_STATUS_MISMATCH", "from_status does not match the locked current status")


def _validate_observation_context(current: TransitionState, event: dict[str, Any]) -> None:
    if current.status not in {"paused", "blocked"}:
        return
    if current.blocker is not None and event["blocker"] != current.blocker:
        _fail("TRANSITION_BLOCKER_CONTEXT_MISMATCH", "observe must not replace an existing blocker")
    if current.resume_step is not None and event["resume_step"] != current.resume_step:
        _fail("TRANSITION_BLOCKER_CONTEXT_MISMATCH", "observe must not replace an existing resume_step")


def validate_transition(current: TransitionState, event: dict[str, Any]) -> TransitionState:
    """Validate one policy-bearing event against the locked current state."""
    if validate_transition_metadata(event) != "transition_policy_v1":
        _fail("TRANSITION_METADATA_REQUIRED", "new R2 writes require complete P9.3 transition metadata")

    kind = str(event["transition_kind"])
    target_stage = str(event["stage"])
    target_status = str(event["to_status"])
    _validate_source(current, event)
    _validate_context_for_target(event)
    _validate_enhanced_material(event, kind)

    if current.stage is None:
        if kind != "start":
            _fail("START_REQUIRED", "the first R2 event must use transition_kind=start")
        if target_stage != "intake":
            _fail("START_STAGE_INVALID", "the first R2 event must start intake")
        if target_status != "running":
            _fail("START_STATUS_INVALID", "the first R2 event must start intake as running")
        return TransitionState(target_stage, target_status, event["blocker"], event["resume_step"])

    if kind == "start":
        _fail("START_NOT_INITIAL", "transition_kind=start is only valid for the first R2 event")
    if kind == "observe":
        if target_stage != current.stage or target_status != current.status:
            _fail("OBSERVE_STATE_CHANGED", "observe must not change stage or status")
        _validate_observation_context(current, event)
    elif kind == "pause":
        if not (target_stage == current.stage and current.status == "running" and target_status == "paused"):
            _fail("PAUSE_TRANSITION_INVALID", "pause only permits running -> paused within one stage")
    elif kind == "block":
        if not (target_stage == current.stage and current.status == "running" and target_status == "blocked"):
            _fail("BLOCK_TRANSITION_INVALID", "block only permits running -> blocked within one stage")
    elif kind == "resume":
        if not (
            target_stage == current.stage
            and current.status in {"paused", "blocked"}
            and target_status == "running"
        ):
            _fail("RESUME_TRANSITION_INVALID", "resume only permits paused/blocked -> running within one stage")
    elif kind == "reopen":
        if not (target_stage == current.stage and current.status == "completed" and target_status == "running"):
            _fail("REOPEN_TRANSITION_INVALID", "reopen only permits completed -> running within one stage")
    elif kind == "complete":
        if not (target_stage == current.stage and current.status == "running" and target_status == "completed"):
            _fail("COMPLETE_TRANSITION_INVALID", "complete only permits running -> completed within one stage")
    elif kind == "advance":
        if current.status not in {"running", "completed"} or target_status != "running":
            _fail("ADVANCE_TRANSITION_INVALID", "advance requires a running/completed source and a running target")
        if target_stage == current.stage or target_stage not in FORWARD_STAGE_EDGES.get(current.stage, frozenset()):
            _fail("ADVANCE_STAGE_EDGE_INVALID", "advance is not an allowed forward stage relationship")
        if current.stage == "finalization" and target_stage == "recording" and current.status != "completed":
            _fail(
                "RECORDING_REQUIRES_FINALIZATION",
                "recording may advance only from a completed finalization stage",
            )
    elif kind == "skip":
        if target_stage not in OPTIONAL_STAGES or target_status != "completed":
            _fail("SKIP_TRANSITION_INVALID", "skip may complete only a documented optional stage")
        if target_stage == current.stage:
            if current.status not in {"running", "paused", "blocked"}:
                _fail("SKIP_TRANSITION_INVALID", "same-stage skip requires running, paused, or blocked work")
        elif current.status not in {"running", "completed"} or target_stage not in FORWARD_STAGE_EDGES.get(current.stage, frozenset()):
            _fail("SKIP_STAGE_EDGE_INVALID", "skip is not an allowed optional forward stage relationship")
        if current.stage == "finalization" and target_stage == "recording" and current.status != "completed":
            _fail(
                "RECORDING_REQUIRES_FINALIZATION",
                "recording may be skipped only after a completed finalization stage",
            )
    elif kind == "return":
        if current.status != "running" or target_status != "running":
            _fail("RETURN_TRANSITION_INVALID", "return requires a running source and a running target")
        if target_stage not in RETURN_STAGE_EDGES.get(current.stage, frozenset()):
            _fail("RETURN_STAGE_EDGE_INVALID", "return is not an allowed evidence-correction relationship")
    else:  # pragma: no cover - metadata validation above keeps this defensive branch unreachable.
        _fail("INVALID_TRANSITION_KIND", "transition_kind is not recognized by the authoritative policy")

    return TransitionState(target_stage, target_status, event["blocker"], event["resume_step"])


def validate_transition_sequence(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Validate a contiguous P9.3 suffix while preserving an R2 legacy prefix.

    Pre-policy R2 records remain shape-valid evidence of prior workflow history,
    but are never relabelled as transition-validated.  The first policy event is
    checked against the last materialized stage/status represented by that
    accepted prefix.
    """
    current = TransitionState()
    pre_policy_count = 0
    policy_event_count = 0
    policy_started = False

    for event_index, event in enumerate(events, start=1):
        try:
            classification = validate_transition_metadata(event)
            if classification == "pre_policy_r2":
                if policy_started:
                    _fail(
                        "PRE_POLICY_R2_AFTER_POLICY",
                        "pre-policy R2 records may appear only as a journal prefix",
                    )
                pre_policy_count += 1
                current = TransitionState(
                    str(event.get("stage") or "") or None,
                    str(event.get("to_status") or "") or None,
                    None,
                    None,
                )
                continue
            policy_started = True
            current = validate_transition(current, event)
            policy_event_count += 1
        except TransitionPolicyError as exc:
            if exc.event_index is None:
                exc.event_index = event_index
            raise

    if policy_event_count == 0:
        classification = "pre_policy_r2" if pre_policy_count else "no_r2_events"
    elif pre_policy_count:
        classification = "pre_policy_r2_prefix_then_transition_policy_v1"
    else:
        classification = "transition_policy_v1"
    return {
        "classification": classification,
        "pre_policy_r2_count": pre_policy_count,
        "transition_policy_event_count": policy_event_count,
        "current_state": current,
    }
