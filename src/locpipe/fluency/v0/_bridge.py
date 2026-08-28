from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from locpipe.content.v0 import FrozenScopeV0
from locpipe.contracts.v0 import (
    ContractViolation,
    ErrorCode,
    canonical_json_bytes,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
)
from locpipe.editorial.v0 import (
    EditorialCandidateSetV0,
    EditorialJobV0,
    EditorialPacketV0,
    EditorialPolicyV0,
    EditorialSubmissionReceiptV0,
)
from locpipe.kernel.v0.config import ResolvedConfigV0
from locpipe.kernel.v0.context import ProjectContextV0
from locpipe.translation.v0 import (
    ProviderBudgetV0,
    TranslationJobV0,
    TranslationPacketV0,
    TranslationTargetSetV0,
)
from locpipe.validation.v0 import (
    ContentValidationJobV0,
    ContentValidationPacketV0,
    ContentValidatorV0,
)
from locpipe.validation.v0._packet import (
    _build_content_validation_job_from_authority_v0,
    _validate_candidate_authority,
)

from ._acceptance import accept_fluency_submission_v0
from ._models import (
    FluencyCorrectionTerminalStatusV0,
    FluencyDecisionStatusV0,
    FluencyDecisionV0,
    FluencyReviewJobV0,
    FluencyReviewPacketV0,
    FluencyReviewPlanV0,
    FluencyStateV0,
    FluencyTargetProjectionV0,
)
from ._packet import build_fluency_review_job_v0
from ._serialization import parse_fluency_correction_terminal_v0
from ._terminal import bind_fluency_correction_terminal_v0


_PROJECTION_PATH = "fluency/validation-authority.json"
_PROJECTION_CONTRACT = "locpipe.fluency.validation-authority-projection/v0"
_AUTHORITY_ROOT_CONTRACT = "locpipe.fluency.validation-complete-authority/v0"
_INITIAL_KIND = "INITIAL_STATE"
_CORRECTION_KIND = "CORRECTION_TERMINAL"
_INITIAL_ROLES = (
    "base_candidate_authority",
    "decision",
    "raw_submission",
    "review_budget",
    "review_job",
    "review_packet",
    "review_plan",
    "state",
    "submission_receipt",
    "target_projection",
)
_CORRECTION_ROLES = ("correction_chain", "correction_terminal")


def _canonical_sha(value: object) -> str:
    if not hasattr(value, "as_dict"):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency validation authority model is invalid")
    return raw_sha256(canonical_json_bytes(value.as_dict()))


def _require_canonical_equal(expected: object, supplied: object, label: str) -> None:
    if expected != supplied or _canonical_sha(expected) != _canonical_sha(supplied):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, f"Fluency validation {label} drift")


def _closed_authority_root_v0(
    provenance_kind: str,
    role_hashes: Mapping[str, str],
) -> str:
    expected = _INITIAL_ROLES if provenance_kind == _INITIAL_KIND else _CORRECTION_ROLES
    roles = tuple(sorted(role_hashes))
    if roles != expected or any(not isinstance(role_hashes[role], str) or len(role_hashes[role]) != 64 for role in roles):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency validation authority role set drift")
    return semantic_sha256({
        "contract": _AUTHORITY_ROOT_CONTRACT,
        "provenance_kind": provenance_kind,
        "roles": [{"role": role, "sha256": role_hashes[role]} for role in roles],
    })


def _projection_bytes_v0(
    provenance_kind: str,
    candidate_sha256: str,
    candidate_authority_sha256: str,
    fluency_authority_sha256: str,
    outcome: str,
    unresolved_ids: tuple[str, ...],
) -> bytes:
    if provenance_kind not in {_INITIAL_KIND, _CORRECTION_KIND}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency validation provenance kind is invalid")
    if unresolved_ids:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency validation requires resolved terminal authority")
    return canonical_json_bytes({
        "contract": _PROJECTION_CONTRACT,
        "provenance_kind": provenance_kind,
        "candidate_sha256": candidate_sha256,
        "candidate_authority_sha256": candidate_authority_sha256,
        "fluency_authority_sha256": fluency_authority_sha256,
        "outcome": outcome,
        "unresolved_ids": [],
    })


def _candidate_authority_v0(
    candidate: EditorialCandidateSetV0,
    candidate_evidence: tuple[tuple[str, bytes], ...],
    editorial_job: EditorialJobV0 | None,
    editorial_packet: EditorialPacketV0 | None,
    editorial_policy: EditorialPolicyV0 | None,
) -> tuple[str, str]:
    if not isinstance(candidate, EditorialCandidateSetV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency validation candidate is invalid")
    authority_sha256, _round, _max_rounds, _available = _validate_candidate_authority(
        candidate,
        candidate_evidence,
        editorial_job,
        editorial_packet,
        editorial_policy,
    )
    return raw_sha256(canonical_json_bytes(candidate.as_dict())), authority_sha256


def _normalize_initial_validation_authority_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    candidate: EditorialCandidateSetV0,
    candidate_sha256: str,
    candidate_authority_sha256: str,
    projection: FluencyTargetProjectionV0,
    budget: ProviderBudgetV0,
    plan: FluencyReviewPlanV0,
    job: FluencyReviewJobV0,
    packet: FluencyReviewPacketV0,
    receipt_bytes: bytes,
    raw_output: bytes,
    decision: FluencyDecisionV0,
    state: FluencyStateV0,
) -> bytes:
    if not all(isinstance(value, selected) for value, selected in (
        (projection, FluencyTargetProjectionV0),
        (budget, ProviderBudgetV0),
        (plan, FluencyReviewPlanV0),
        (job, FluencyReviewJobV0),
        (packet, FluencyReviewPacketV0),
        (decision, FluencyDecisionV0),
        (state, FluencyStateV0),
    )) or not isinstance(receipt_bytes, bytes) or not isinstance(raw_output, bytes):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency initial validation authority is invalid")
    if plan.round_index != 0 or plan.parent_terminal_sha256 is not None:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency initial validation authority must be round zero")
    rebuilt_plan, rebuilt_job, rebuilt_packet = build_fluency_review_job_v0(
        context,
        resolved,
        candidate,
        projection,
        candidate_authority_sha256=candidate_authority_sha256,
        requested_ids=plan.requested_ids,
        budget=budget,
        round_index=0,
        max_correction_rounds=plan.max_correction_rounds,
        parent_terminal_sha256=None,
    )
    for expected, supplied, label in (
        (rebuilt_plan, plan, "initial plan"),
        (rebuilt_job, job, "initial job"),
        (rebuilt_packet, packet, "initial packet"),
    ):
        _require_canonical_equal(expected, supplied, label)
    rebuilt_decision, rebuilt_state = accept_fluency_submission_v0(
        rebuilt_plan,
        rebuilt_job,
        rebuilt_packet,
        receipt_bytes,
        raw_output,
    )
    _require_canonical_equal(rebuilt_decision, decision, "initial decision")
    _require_canonical_equal(rebuilt_state, state, "initial state")
    if (
        rebuilt_plan.candidate_sha256 != candidate_sha256
        or rebuilt_plan.candidate_authority_sha256 != candidate_authority_sha256
        or rebuilt_decision.status is not FluencyDecisionStatusV0.FLUENCY_VERIFIED
        or rebuilt_state.status is not FluencyDecisionStatusV0.FLUENCY_VERIFIED
        or rebuilt_decision.correction_ids
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency initial validation authority is not verified")
    root = _closed_authority_root_v0(_INITIAL_KIND, {
        "base_candidate_authority": candidate_authority_sha256,
        "decision": _canonical_sha(rebuilt_decision),
        "raw_submission": raw_sha256(raw_output),
        "review_budget": _canonical_sha(budget),
        "review_job": _canonical_sha(rebuilt_job),
        "review_packet": _canonical_sha(rebuilt_packet),
        "review_plan": _canonical_sha(rebuilt_plan),
        "state": _canonical_sha(rebuilt_state),
        "submission_receipt": raw_sha256(receipt_bytes),
        "target_projection": _canonical_sha(projection),
    })
    return _projection_bytes_v0(
        _INITIAL_KIND,
        candidate_sha256,
        candidate_authority_sha256,
        root,
        rebuilt_state.status.value,
        (),
    )


def _normalize_correction_validation_authority_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    candidate_sha256: str,
    candidate_authority_sha256: str,
    terminal_bytes: bytes,
    trigger_bytes: bytes,
    adjudication_bytes: bytes,
    accuracy_job: EditorialJobV0,
    accuracy_packet: EditorialPacketV0,
    accuracy_policy: EditorialPolicyV0,
    accuracy_parent_candidate: EditorialCandidateSetV0,
    accuracy_receipt: EditorialSubmissionReceiptV0,
    accuracy_raw_output: bytes,
    accuracy_terminal_artifacts: tuple[tuple[str, bytes], ...],
    resulting_candidate_evidence: tuple[tuple[str, bytes], ...],
    *,
    recheck_projection: FluencyTargetProjectionV0 | None,
    recheck_budget: ProviderBudgetV0 | None,
    recheck_plan: FluencyReviewPlanV0 | None,
    recheck_job: FluencyReviewJobV0 | None,
    recheck_packet: FluencyReviewPacketV0 | None,
    recheck_receipt_bytes: bytes | None,
    recheck_raw_output: bytes | None,
    recheck_decision: FluencyDecisionV0 | None,
    recheck_state: FluencyStateV0 | None,
) -> bytes:
    if not isinstance(terminal_bytes, bytes):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction terminal bytes are invalid")
    parsed_terminal = parse_fluency_correction_terminal_v0(terminal_bytes)
    rebuilt_terminal = bind_fluency_correction_terminal_v0(
        context,
        resolved,
        trigger_bytes,
        adjudication_bytes,
        accuracy_job,
        accuracy_packet,
        accuracy_policy,
        accuracy_parent_candidate,
        accuracy_receipt,
        accuracy_raw_output,
        accuracy_terminal_artifacts,
        resulting_candidate_evidence,
        recheck_projection=recheck_projection,
        recheck_budget=recheck_budget,
        recheck_plan=recheck_plan,
        recheck_job=recheck_job,
        recheck_packet=recheck_packet,
        recheck_receipt_bytes=recheck_receipt_bytes,
        recheck_raw_output=recheck_raw_output,
        recheck_decision=recheck_decision,
        recheck_state=recheck_state,
    )
    if (
        parsed_terminal != rebuilt_terminal
        or canonical_json_bytes(rebuilt_terminal.as_dict()) != terminal_bytes
        or rebuilt_terminal.status not in {
            FluencyCorrectionTerminalStatusV0.FLUENCY_VERIFIED_WITH_DISMISSALS,
            FluencyCorrectionTerminalStatusV0.FLUENCY_VERIFIED,
        }
        or rebuilt_terminal.unresolved_ids
        or rebuilt_terminal.candidate_sha256 != candidate_sha256
        or rebuilt_terminal.candidate_authority_sha256 != candidate_authority_sha256
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction validation terminal drift")
    root = _closed_authority_root_v0(_CORRECTION_KIND, {
        "correction_chain": rebuilt_terminal.correction_chain_sha256,
        "correction_terminal": rebuilt_terminal.digest,
    })
    return _projection_bytes_v0(
        _CORRECTION_KIND,
        candidate_sha256,
        candidate_authority_sha256,
        root,
        rebuilt_terminal.status.value,
        rebuilt_terminal.unresolved_ids,
    )


def build_fluency_content_validation_job_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    scope: FrozenScopeV0,
    translation_job: TranslationJobV0,
    translation_packet: TranslationPacketV0,
    translation_decision_bytes: bytes,
    translation_state_bytes: bytes,
    target_set: TranslationTargetSetV0,
    candidate: EditorialCandidateSetV0,
    validator: ContentValidatorV0,
    *,
    source_lock_bytes: bytes,
    reconciliation_bytes: bytes,
    scope_bytes: bytes,
    scope_lock_bytes: bytes,
    segments_bytes: bytes,
    candidate_evidence: tuple[tuple[str, bytes], ...],
    editorial_job: EditorialJobV0 | None = None,
    editorial_packet: EditorialPacketV0 | None = None,
    editorial_policy: EditorialPolicyV0 | None = None,
    provenance_kind: Literal["INITIAL_STATE", "CORRECTION_TERMINAL"],
    initial_projection: FluencyTargetProjectionV0 | None = None,
    initial_budget: ProviderBudgetV0 | None = None,
    initial_plan: FluencyReviewPlanV0 | None = None,
    initial_job: FluencyReviewJobV0 | None = None,
    initial_packet: FluencyReviewPacketV0 | None = None,
    initial_receipt_bytes: bytes | None = None,
    initial_raw_output: bytes | None = None,
    initial_decision: FluencyDecisionV0 | None = None,
    initial_state: FluencyStateV0 | None = None,
    correction_terminal_bytes: bytes | None = None,
    correction_trigger_bytes: bytes | None = None,
    correction_adjudication_bytes: bytes | None = None,
    correction_accuracy_job: EditorialJobV0 | None = None,
    correction_accuracy_packet: EditorialPacketV0 | None = None,
    correction_accuracy_policy: EditorialPolicyV0 | None = None,
    correction_accuracy_parent_candidate: EditorialCandidateSetV0 | None = None,
    correction_accuracy_receipt: EditorialSubmissionReceiptV0 | None = None,
    correction_accuracy_raw_output: bytes | None = None,
    correction_accuracy_terminal_artifacts: tuple[tuple[str, bytes], ...] | None = None,
    correction_recheck_projection: FluencyTargetProjectionV0 | None = None,
    correction_recheck_budget: ProviderBudgetV0 | None = None,
    correction_recheck_plan: FluencyReviewPlanV0 | None = None,
    correction_recheck_job: FluencyReviewJobV0 | None = None,
    correction_recheck_packet: FluencyReviewPacketV0 | None = None,
    correction_recheck_receipt_bytes: bytes | None = None,
    correction_recheck_raw_output: bytes | None = None,
    correction_recheck_decision: FluencyDecisionV0 | None = None,
    correction_recheck_state: FluencyStateV0 | None = None,
) -> tuple[ContentValidationJobV0, ContentValidationPacketV0, tuple[tuple[str, bytes], ...]]:
    initial_values = (
        initial_projection,
        initial_budget,
        initial_plan,
        initial_job,
        initial_packet,
        initial_receipt_bytes,
        initial_raw_output,
        initial_decision,
        initial_state,
    )
    correction_required = (
        correction_terminal_bytes,
        correction_trigger_bytes,
        correction_adjudication_bytes,
        correction_accuracy_job,
        correction_accuracy_packet,
        correction_accuracy_policy,
        correction_accuracy_parent_candidate,
        correction_accuracy_receipt,
        correction_accuracy_raw_output,
        correction_accuracy_terminal_artifacts,
    )
    correction_recheck = (
        correction_recheck_projection,
        correction_recheck_budget,
        correction_recheck_plan,
        correction_recheck_job,
        correction_recheck_packet,
        correction_recheck_receipt_bytes,
        correction_recheck_raw_output,
        correction_recheck_decision,
        correction_recheck_state,
    )
    if provenance_kind == _INITIAL_KIND:
        if not all(value is not None for value in initial_values) or any(
            value is not None for value in (*correction_required, *correction_recheck)
        ):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency initial validation provenance group is incomplete or mixed")
    elif provenance_kind == _CORRECTION_KIND:
        if any(value is not None for value in initial_values) or not all(
            value is not None for value in correction_required
        ) or (any(value is not None for value in correction_recheck) and not all(
            value is not None for value in correction_recheck
        )):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction validation provenance group is incomplete or mixed")
    else:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency validation provenance kind is invalid")

    candidate_sha256, candidate_authority_sha256 = _candidate_authority_v0(
        candidate,
        candidate_evidence,
        editorial_job,
        editorial_packet,
        editorial_policy,
    )
    if provenance_kind == _INITIAL_KIND:
        projection_bytes = _normalize_initial_validation_authority_v0(
            context,
            resolved,
            candidate,
            candidate_sha256,
            candidate_authority_sha256,
            initial_projection,
            initial_budget,
            initial_plan,
            initial_job,
            initial_packet,
            initial_receipt_bytes,
            initial_raw_output,
            initial_decision,
            initial_state,
        )
    else:
        projection_bytes = _normalize_correction_validation_authority_v0(
            context,
            resolved,
            candidate_sha256,
            candidate_authority_sha256,
            correction_terminal_bytes,
            correction_trigger_bytes,
            correction_adjudication_bytes,
            correction_accuracy_job,
            correction_accuracy_packet,
            correction_accuracy_policy,
            correction_accuracy_parent_candidate,
            correction_accuracy_receipt,
            correction_accuracy_raw_output,
            correction_accuracy_terminal_artifacts,
            candidate_evidence,
            recheck_projection=correction_recheck_projection,
            recheck_budget=correction_recheck_budget,
            recheck_plan=correction_recheck_plan,
            recheck_job=correction_recheck_job,
            recheck_packet=correction_recheck_packet,
            recheck_receipt_bytes=correction_recheck_receipt_bytes,
            recheck_raw_output=correction_recheck_raw_output,
            recheck_decision=correction_recheck_decision,
            recheck_state=correction_recheck_state,
        )

    job, packet, authority = _build_content_validation_job_from_authority_v0(
        context,
        resolved,
        scope,
        translation_job,
        translation_packet,
        translation_decision_bytes,
        translation_state_bytes,
        target_set,
        candidate,
        validator,
        source_lock_bytes=source_lock_bytes,
        reconciliation_bytes=reconciliation_bytes,
        scope_bytes=scope_bytes,
        scope_lock_bytes=scope_lock_bytes,
        segments_bytes=segments_bytes,
        candidate_evidence=candidate_evidence,
        editorial_job=editorial_job,
        editorial_packet=editorial_packet,
        editorial_policy=editorial_policy,
        supplemental_authority=((_PROJECTION_PATH, projection_bytes),),
    )
    supplemental = tuple((path, payload) for path, payload in authority if path == _PROJECTION_PATH)
    projection = parse_canonical_json(projection_bytes)
    if (
        supplemental != ((_PROJECTION_PATH, projection_bytes),)
        or job.candidate_sha256 != projection["candidate_sha256"]
        or job.candidate_authority_sha256 != projection["candidate_authority_sha256"]
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency validation job does not bind normalized authority")
    return job, packet, authority
