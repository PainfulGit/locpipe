from __future__ import annotations

import posixpath
from collections.abc import Mapping

from locpipe.contracts.v0 import (
    ContractViolation,
    ErrorCode,
    canonical_json_bytes,
    raw_sha256,
)
from locpipe.editorial.v0 import (
    EditorialCandidateSetV0,
    EditorialJobV0,
    EditorialPacketV0,
    EditorialPolicyV0,
    EditorialSubmissionReceiptV0,
    editorial_job_root_v0,
    editorial_terminal_artifacts_v0,
    parse_editorial_candidate_v0,
)
from locpipe.kernel.v0.config import ResolvedConfigV0, validate_context_config_binding
from locpipe.kernel.v0.context import ProjectContextV0
from locpipe.translation.v0 import ProviderBudgetV0
from locpipe.validation.v0._packet import _validate_candidate_authority

from ._acceptance import accept_fluency_submission_v0
from ._correction import accept_fluency_adjudication_v0, build_fluency_recheck_job_v0
from ._models import (
    FluencyAdjudicationStatusV0,
    FluencyCorrectionTerminalStatusV0,
    FluencyCorrectionTerminalV0,
    FluencyDecisionStatusV0,
    FluencyDecisionV0,
    FluencyReviewJobV0,
    FluencyReviewPacketV0,
    FluencyReviewPlanV0,
    FluencyStateV0,
    FluencyTargetProjectionV0,
)
from ._serialization import (
    parse_fluency_adjudication_v0,
    parse_fluency_correction_terminal_v0,
    parse_fluency_correction_trigger_v0,
)


_CORRECTION_CHAIN_CONTRACT = "locpipe.fluency.correction-terminal-authority-projection/v0"
_COMMON_CORRECTION_ROLES = (
    "accuracy_job",
    "accuracy_packet",
    "accuracy_parent_authority",
    "accuracy_policy",
    "accuracy_raw_output",
    "accuracy_receipt",
    "accuracy_terminal_projection",
    "adjudication",
    "resulting_candidate_authority",
    "trigger",
)
_RECHECK_ROLES = (
    "recheck_budget",
    "recheck_decision",
    "recheck_job",
    "recheck_packet",
    "recheck_plan",
    "recheck_raw_output",
    "recheck_receipt",
    "recheck_state",
    "target_projection",
)


def _artifact_projection_sha256(
    contract: str,
    artifacts: tuple[tuple[str, bytes], ...],
) -> str:
    rows = tuple(artifacts)
    paths = tuple(path for path, _payload in rows)
    if (
        any(not isinstance(path, str) or not path or not isinstance(payload, bytes) for path, payload in rows)
        or paths != tuple(sorted(paths))
        or len(paths) != len(set(paths))
    ):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency correction terminal artifact projection is invalid")
    return raw_sha256(canonical_json_bytes({
        "contract": contract,
        "artifacts": [
            {"path": path, "sha256": raw_sha256(payload)}
            for path, payload in rows
        ],
    }))


def _closed_correction_chain_root_v0(
    role_set: str,
    role_hashes: Mapping[str, str],
) -> str:
    if role_set == "dismissals":
        expected_roles = _COMMON_CORRECTION_ROLES
    elif role_set == "recheck":
        expected_roles = tuple(sorted((*_COMMON_CORRECTION_ROLES, *_RECHECK_ROLES)))
    else:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction terminal role set is invalid")
    if set(role_hashes) != set(expected_roles) or len(role_hashes) != len(expected_roles):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction terminal role inventory drift")
    for value in role_hashes.values():
        if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction terminal role digest is invalid")
    return raw_sha256(canonical_json_bytes({
        "contract": _CORRECTION_CHAIN_CONTRACT,
        "role_set": role_set,
        "roles": [
            {"role": role, "sha256": role_hashes[role]}
            for role in expected_roles
        ],
    }))


def _resulting_candidate_authority_v0(
    resolved: ResolvedConfigV0,
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
):
    trigger = parse_fluency_correction_trigger_v0(trigger_bytes)
    adjudication = parse_fluency_adjudication_v0(adjudication_bytes)
    expected_terminal = editorial_terminal_artifacts_v0(
        accuracy_job,
        accuracy_packet,
        accuracy_policy,
        accuracy_parent_candidate,
        accuracy_receipt,
        accuracy_raw_output,
    )
    rebuilt_adjudication = accept_fluency_adjudication_v0(
        resolved=resolved,
        trigger_bytes=trigger_bytes,
        job=accuracy_job,
        packet=accuracy_packet,
        policy=accuracy_policy,
        parent_candidate=accuracy_parent_candidate,
        receipt=accuracy_receipt,
        raw_output=accuracy_raw_output,
        terminal_artifacts=accuracy_terminal_artifacts,
    )
    if rebuilt_adjudication != adjudication:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction terminal adjudication drift")
    terminal = dict(expected_terminal)
    candidate_path = posixpath.join(editorial_job_root_v0(accuracy_job), "candidate_set.json")
    candidate_bytes = terminal[candidate_path]
    resulting_candidate = parse_editorial_candidate_v0(candidate_bytes)
    candidate_authority_sha256, editorial_round, max_editorial_rounds, available = _validate_candidate_authority(
        resulting_candidate,
        resulting_candidate_evidence,
        accuracy_job,
        accuracy_packet,
        accuracy_policy,
    )
    if (
        not available
        or raw_sha256(candidate_bytes) != adjudication.resulting_candidate_sha256
        or editorial_round != accuracy_job.round_index
        or max_editorial_rounds != accuracy_policy.max_rework_rounds
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction terminal candidate authority drift")
    return trigger, adjudication, expected_terminal, resulting_candidate, candidate_authority_sha256


def bind_fluency_correction_terminal_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
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
    recheck_projection: FluencyTargetProjectionV0 | None = None,
    recheck_budget: ProviderBudgetV0 | None = None,
    recheck_plan: FluencyReviewPlanV0 | None = None,
    recheck_job: FluencyReviewJobV0 | None = None,
    recheck_packet: FluencyReviewPacketV0 | None = None,
    recheck_receipt_bytes: bytes | None = None,
    recheck_raw_output: bytes | None = None,
    recheck_decision: FluencyDecisionV0 | None = None,
    recheck_state: FluencyStateV0 | None = None,
) -> FluencyCorrectionTerminalV0:
    """Bind exact correction-only terminal authority without performing I/O."""
    if not all(isinstance(value, selected) for value, selected in (
        (context, ProjectContextV0),
        (resolved, ResolvedConfigV0),
        (accuracy_job, EditorialJobV0),
        (accuracy_packet, EditorialPacketV0),
        (accuracy_policy, EditorialPolicyV0),
        (accuracy_parent_candidate, EditorialCandidateSetV0),
        (accuracy_receipt, EditorialSubmissionReceiptV0),
    )) or not all(isinstance(value, bytes) for value in (
        trigger_bytes, adjudication_bytes, accuracy_raw_output,
    )):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction terminal inputs are invalid")
    validate_context_config_binding(context, resolved)

    trigger, adjudication, expected_accuracy_terminal, resulting_candidate, candidate_authority_sha256 = (
        _resulting_candidate_authority_v0(
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
        )
    )

    parent_authority_sha256 = raw_sha256(canonical_json_bytes({
        "contract": "locpipe.fluency.accuracy-parent-authority/v0",
        "candidate_sha256": raw_sha256(canonical_json_bytes(accuracy_parent_candidate.as_dict())),
        "candidate_authority_sha256": trigger.candidate_authority_sha256,
    }))
    common_roles = {
        "trigger": raw_sha256(trigger_bytes),
        "adjudication": raw_sha256(adjudication_bytes),
        "accuracy_job": raw_sha256(canonical_json_bytes(accuracy_job.as_dict())),
        "accuracy_packet": raw_sha256(canonical_json_bytes(accuracy_packet.as_dict())),
        "accuracy_policy": raw_sha256(canonical_json_bytes(accuracy_policy.as_dict())),
        "accuracy_parent_authority": parent_authority_sha256,
        "accuracy_receipt": raw_sha256(canonical_json_bytes(accuracy_receipt.as_dict())),
        "accuracy_raw_output": raw_sha256(accuracy_raw_output),
        "accuracy_terminal_projection": _artifact_projection_sha256(
            "locpipe.fluency.accuracy-terminal-projection/v0",
            expected_accuracy_terminal,
        ),
        "resulting_candidate_authority": candidate_authority_sha256,
    }
    recheck_inputs = (
        recheck_projection,
        recheck_budget,
        recheck_plan,
        recheck_job,
        recheck_packet,
        recheck_receipt_bytes,
        recheck_raw_output,
        recheck_decision,
        recheck_state,
    )
    candidate_sha256 = raw_sha256(canonical_json_bytes(resulting_candidate.as_dict()))

    if adjudication.status is FluencyAdjudicationStatusV0.DISMISSALS_ONLY:
        if any(value is not None for value in recheck_inputs):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency dismissal terminal forbids recheck authority")
        terminal = FluencyCorrectionTerminalV0(
            FluencyCorrectionTerminalStatusV0.FLUENCY_VERIFIED_WITH_DISMISSALS,
            candidate_sha256,
            candidate_authority_sha256,
            _closed_correction_chain_root_v0("dismissals", common_roles),
            trigger.current_fluency_round,
            trigger.max_fluency_correction_rounds,
            (),
        )
    else:
        if not all(value is not None for value in recheck_inputs):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction terminal requires complete recheck authority")
        if not all(isinstance(value, selected) for value, selected in (
            (recheck_projection, FluencyTargetProjectionV0),
            (recheck_budget, ProviderBudgetV0),
            (recheck_plan, FluencyReviewPlanV0),
            (recheck_job, FluencyReviewJobV0),
            (recheck_packet, FluencyReviewPacketV0),
            (recheck_decision, FluencyDecisionV0),
            (recheck_state, FluencyStateV0),
        )) or not isinstance(recheck_receipt_bytes, bytes) or not isinstance(recheck_raw_output, bytes):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency recheck terminal inputs are invalid")
        rebuilt_plan, rebuilt_job, rebuilt_packet = build_fluency_recheck_job_v0(
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
            recheck_projection,
            budget=recheck_budget,
        )
        if (rebuilt_plan, rebuilt_job, rebuilt_packet) != (recheck_plan, recheck_job, recheck_packet):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction terminal recheck construction drift")
        rebuilt_decision, rebuilt_state = accept_fluency_submission_v0(
            recheck_plan,
            recheck_job,
            recheck_packet,
            recheck_receipt_bytes,
            recheck_raw_output,
        )
        if (rebuilt_decision, rebuilt_state) != (recheck_decision, recheck_state):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction terminal recheck acceptance drift")
        if (
            recheck_plan.round_index != trigger.current_fluency_round + 1
            or recheck_plan.max_correction_rounds != trigger.max_fluency_correction_rounds
            or recheck_plan.parent_terminal_sha256 != adjudication.digest
            or recheck_plan.candidate_sha256 != candidate_sha256
            or recheck_plan.candidate_authority_sha256 != candidate_authority_sha256
        ):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction terminal recheck policy drift")
        if rebuilt_decision.status is FluencyDecisionStatusV0.FLUENCY_VERIFIED:
            terminal_status = FluencyCorrectionTerminalStatusV0.FLUENCY_VERIFIED
            unresolved_ids: tuple[str, ...] = ()
        elif recheck_plan.round_index == recheck_plan.max_correction_rounds:
            terminal_status = FluencyCorrectionTerminalStatusV0.REWORK_EXHAUSTED
            unresolved_ids = rebuilt_decision.correction_ids
        else:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency recheck findings remain non-terminal")
        role_hashes = dict(common_roles)
        role_hashes.update({
            "target_projection": raw_sha256(canonical_json_bytes(recheck_projection.as_dict())),
            "recheck_budget": raw_sha256(canonical_json_bytes(recheck_budget.as_dict())),
            "recheck_plan": raw_sha256(canonical_json_bytes(recheck_plan.as_dict())),
            "recheck_job": raw_sha256(canonical_json_bytes(recheck_job.as_dict())),
            "recheck_packet": raw_sha256(canonical_json_bytes(recheck_packet.as_dict())),
            "recheck_receipt": raw_sha256(recheck_receipt_bytes),
            "recheck_raw_output": raw_sha256(recheck_raw_output),
            "recheck_decision": raw_sha256(canonical_json_bytes(rebuilt_decision.as_dict())),
            "recheck_state": raw_sha256(canonical_json_bytes(rebuilt_state.as_dict())),
        })
        terminal = FluencyCorrectionTerminalV0(
            terminal_status,
            candidate_sha256,
            candidate_authority_sha256,
            _closed_correction_chain_root_v0("recheck", role_hashes),
            recheck_plan.round_index,
            recheck_plan.max_correction_rounds,
            unresolved_ids,
        )

    terminal_bytes = canonical_json_bytes(terminal.as_dict())
    if parse_fluency_correction_terminal_v0(terminal_bytes) != terminal:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction terminal serialization drift")
    return terminal
