from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import posixpath

from locpipe.content.v0 import ScopeRoleV0
from locpipe.contracts.v0 import (
    ArtifactDeclarationV0,
    BranchIdentity,
    Capability,
    ContractViolation,
    ErrorCode,
    ErrorRecord,
    ImplementationRefV0,
    OperationContextV0,
    OperationHandlerV0,
    OperationRequestV0,
    canonical_json_bytes,
    display_id,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
)
from locpipe.editorial.v0 import (
    OUTPUT_CONTRACT_SHA256,
    ROLE_CONTRACT_SHA256,
    EditorialCandidateSetV0,
    EditorialJobStatusV0,
    EditorialJobV0,
    EditorialPacketRowV0,
    EditorialPacketV0,
    EditorialPolicyV0,
    EditorialSubmissionReceiptV0,
    editorial_acceptance_output_declarations_v0,
    editorial_bindings_from_config_v0,
    editorial_job_root_v0,
    editorial_submission_archive_artifacts_v0,
    editorial_submission_digest_v0,
    editorial_terminal_artifacts_v0,
    prepared_editorial_artifacts_v0,
    received_editorial_artifacts_v0,
)
from locpipe.editorial.v0._models import candidate_raw_sha
from locpipe.editorial.v0._packet import _validate_translation_authority
from locpipe.kernel.v0.config import ResolvedConfigV0, validate_context_config_binding
from locpipe.kernel.v0.context import ProjectContextV0
from locpipe.translation.v0 import (
    ProviderBudgetV0,
    TranslationJobV0,
    TranslationPacketV0,
    TranslationTargetSetV0,
    translation_job_root_v0,
)

from ._models import ContentValidationJobV0, ContentValidationPacketV0, ContentValidationStatusV0
from ._packet import _validate_candidate_authority, validation_job_root_v0


def _projection_sha(rows: tuple[tuple[str, bytes], ...]) -> str:
    ordered = tuple(sorted((path, bytes(payload)) for path, payload in rows))
    if len({path for path, _payload in ordered}) != len(ordered):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Validation editorial evidence paths collide")
    return semantic_sha256([{"path": path, "sha256": raw_sha256(payload)} for path, payload in ordered])


def _validation_trigger(
    validation_job: ContentValidationJobV0,
    parent: EditorialCandidateSetV0,
    parent_evidence: tuple[tuple[str, bytes], ...],
    report_bytes: bytes,
    state_bytes: bytes,
    rework_bytes: bytes,
) -> tuple[dict[str, object], tuple[str, ...], int]:
    report = parse_canonical_json(report_bytes)
    state = parse_canonical_json(state_bytes)
    rework = parse_canonical_json(rework_bytes)
    if any(canonical_json_bytes(value) != payload for value, payload in (
        (report, report_bytes), (state, state_bytes), (rework, rework_bytes),
    )):
        raise ContractViolation(ErrorCode.CANONICALIZATION_ERROR, "Validation rework evidence is not canonical")
    blocking = tuple(sorted({
        row["stable_id"] for row in report.get("findings", ())
        if isinstance(row, Mapping) and row.get("severity") == "ERROR"
    }))
    requested = tuple(rework.get("requested_ids", ()))
    next_round = rework.get("next_round")
    if (
        report.get("contract") != "locpipe.validation.report/v0"
        or report.get("job_id") != validation_job.job_id
        or report.get("candidate_sha256") != validation_job.candidate_sha256
        or state.get("contract") != "locpipe.validation.state/v0"
        or state.get("job_id") != validation_job.job_id
        or state.get("status") != ContentValidationStatusV0.REWORK_REQUIRED.value
        or state.get("candidate_sha256") != validation_job.candidate_sha256
        or state.get("report_sha256") != raw_sha256(report_bytes)
        or state.get("rework_request_sha256") != raw_sha256(rework_bytes)
        or rework.get("contract") != "locpipe.validation.rework-request/v0"
        or rework.get("job_id") != validation_job.job_id
        or rework.get("status") != ContentValidationStatusV0.REWORK_REQUIRED.value
        or rework.get("candidate_sha256") != validation_job.candidate_sha256
        or rework.get("report_sha256") != raw_sha256(report_bytes)
        or not blocking
        or requested != blocking
        or next_round != validation_job.editorial_round_index + 1
        or next_round > validation_job.max_rework_rounds
        or candidate_raw_sha(parent) != validation_job.candidate_sha256
        or _projection_sha(parent_evidence) != validation_job.candidate_authority_sha256
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation-origin editorial trigger drift")
    trigger = {
        "contract": "locpipe.validation.editorial-trigger/v0",
        "validation_job_id": validation_job.job_id,
        "validation_report_sha256": raw_sha256(report_bytes),
        "validation_state_sha256": raw_sha256(state_bytes),
        "validation_rework_sha256": raw_sha256(rework_bytes),
        "parent_candidate_sha256": validation_job.candidate_sha256,
        "parent_evidence_sha256": validation_job.candidate_authority_sha256,
        "requested_ids": list(requested),
        "previous_round": validation_job.editorial_round_index,
        "next_round": next_round,
    }
    return trigger, requested, next_round


def validation_editorial_trigger_path_v0(validation_job: ContentValidationJobV0) -> str:
    return posixpath.join(validation_job_root_v0(validation_job), "editorial-trigger.json")


def build_validation_editorial_rework_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    translation_job: TranslationJobV0,
    translation_packet: TranslationPacketV0,
    translation_decision_bytes: bytes,
    translation_state_bytes: bytes,
    target_set: TranslationTargetSetV0,
    policy: EditorialPolicyV0,
    parent_candidate: EditorialCandidateSetV0,
    parent_evidence: tuple[tuple[str, bytes], ...],
    parent_editorial_job: EditorialJobV0,
    parent_editorial_packet: EditorialPacketV0,
    validation_job: ContentValidationJobV0,
    validation_packet: ContentValidationPacketV0,
    validation_report_bytes: bytes,
    validation_state_bytes: bytes,
    validation_rework_bytes: bytes,
    *,
    budget: ProviderBudgetV0,
) -> tuple[EditorialJobV0, EditorialPacketV0, bytes]:
    validate_context_config_binding(context, resolved)
    bindings = editorial_bindings_from_config_v0(resolved)
    if bindings is None:
        raise ContractViolation(ErrorCode.CAPABILITY_MISSING, "Validation rework requires accuracy_editor bindings")
    module, provider = bindings
    _validate_translation_authority(
        translation_job, translation_packet, translation_decision_bytes, target_set, translation_state_bytes,
    )
    if (
        context.context_digest != validation_job.context_digest
        or validation_job.content_config_digest != resolved.content_config_digest
        or validation_job.target_locale != translation_job.target_locale
        or validation_job.scope_sha256 != translation_job.scope_sha256
        or validation_job.source_lock_sha256 != translation_job.source_lock_sha256
        or validation_job.reconciliation_sha256 != translation_job.reconciliation_sha256
        or raw_sha256(canonical_json_bytes(validation_packet.as_dict())) != validation_job.packet_sha256
        or parent_editorial_job.round_index != validation_job.editorial_round_index
        or parent_editorial_job.target_locale != validation_job.target_locale
        or parent_editorial_packet.target_locale != validation_job.target_locale
        or policy.digest != parent_editorial_job.policy_sha256
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation/editorial authority differs from translation context")
    authority_sha, round_index, max_rounds, available = _validate_candidate_authority(
        parent_candidate, parent_evidence, parent_editorial_job, parent_editorial_packet, policy,
    )
    if (
        not available
        or authority_sha != validation_job.candidate_authority_sha256
        or round_index != validation_job.editorial_round_index
        or max_rounds != validation_job.max_rework_rounds
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation parent editorial authority drift")
    trigger, requested, next_round = _validation_trigger(
        validation_job, parent_candidate, parent_evidence,
        validation_report_bytes, validation_state_bytes, validation_rework_bytes,
    )
    targets = {}
    for payload in parent_candidate._target_bytes:
        identity = BranchIdentity.from_dict(parse_canonical_json(payload)["data"]["identity"])
        targets[(identity.logical_id, identity.selector_path)] = payload
    packet_rows = []
    for row in translation_packet.rows:
        target = targets.get((row.identity.logical_id, row.identity.selector_path)) if row.role is ScopeRoleV0.OWNED else None
        packet_rows.append(EditorialPacketRowV0(
            row.identity, row.role, row.source_revision_sha, row.content_type,
            row._payload_bytes, row._constraints_bytes, target,
        ))
    packet = EditorialPacketV0(
        translation_job.target_locale,
        next_round,
        requested,
        tuple(sorted(packet_rows, key=lambda row: row.stable_id)),
        translation_packet._relation_bytes,
    )
    trigger_bytes = canonical_json_bytes(trigger)
    packet_sha = raw_sha256(canonical_json_bytes(packet.as_dict()))
    identity = {
        "context_digest": context.context_digest,
        "translation_job_id": translation_job.job_id,
        "translation_decision_sha256": raw_sha256(translation_decision_bytes),
        "translation_state_sha256": raw_sha256(translation_state_bytes),
        "base_target_set_sha256": parent_candidate.base_target_set_sha256,
        "parent_candidate_sha256": candidate_raw_sha(parent_candidate),
        "validation_trigger_sha256": raw_sha256(trigger_bytes),
        "scope_sha256": translation_job.scope_sha256,
        "source_lock_sha256": translation_job.source_lock_sha256,
        "reconciliation_sha256": translation_job.reconciliation_sha256,
        "content_config_digest": resolved.content_config_digest,
        "effective_snapshot_sha256": resolved.effective_snapshot_sha256,
        "module": {"capability": module.capability.value, "module_id": module.module_id, "version": module.version, "digest": module.digest},
        "provider": provider.as_dict(),
        "target_locale": translation_job.target_locale,
        "packet_sha256": packet_sha,
        "policy_sha256": policy.digest,
        "role_contract_sha256": ROLE_CONTRACT_SHA256,
        "output_contract_sha256": OUTPUT_CONTRACT_SHA256,
        "budget": budget.as_dict(),
        "round_index": next_round,
        "max_invocations": 1,
    }
    job_id = "editorial-" + semantic_sha256({"kind": "validation-origin-job", **identity})[:32]
    invocation_id = "invocation-" + semantic_sha256({"job_id": job_id, "provider": provider.as_dict(), "round": next_round})[:32]
    job = EditorialJobV0(
        job_id, invocation_id, context.context_digest, translation_job.job_id,
        raw_sha256(translation_decision_bytes), raw_sha256(translation_state_bytes),
        parent_candidate.base_target_set_sha256, candidate_raw_sha(parent_candidate),
        raw_sha256(trigger_bytes), translation_job.scope_sha256, translation_job.source_lock_sha256,
        translation_job.reconciliation_sha256, resolved.content_config_digest, resolved.effective_snapshot_sha256,
        module, provider, translation_job.target_locale, packet_sha, policy.digest,
        ROLE_CONTRACT_SHA256, OUTPUT_CONTRACT_SHA256, budget, next_round,
    )
    return job, packet, trigger_bytes


def validation_editorial_acceptance_inputs_v0(
    translation_job: TranslationJobV0,
    translation_packet: TranslationPacketV0,
    translation_decision_bytes: bytes,
    translation_state_bytes: bytes,
    target_set: TranslationTargetSetV0,
    job: EditorialJobV0,
    packet: EditorialPacketV0,
    policy: EditorialPolicyV0,
    parent_candidate: EditorialCandidateSetV0,
    parent_evidence: tuple[tuple[str, bytes], ...],
    validation_job: ContentValidationJobV0,
    validation_packet: ContentValidationPacketV0,
    validation_report_bytes: bytes,
    validation_state_bytes: bytes,
    validation_rework_bytes: bytes,
    trigger_bytes: bytes,
    receipt: EditorialSubmissionReceiptV0,
    raw_output: bytes,
) -> tuple[tuple[str, bytes], ...]:
    rows: dict[str, bytes] = {}

    def add(path: str, payload: bytes) -> None:
        value = bytes(payload)
        if path in rows and rows[path] != value:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, f"Validation editorial input path collision: {path}")
        rows[path] = value

    translation_root = translation_job_root_v0(translation_job)
    for name, payload in {
        "job.json": canonical_json_bytes(translation_job.as_dict()),
        "packet.json": canonical_json_bytes(translation_packet.as_dict()),
        "decision.json": translation_decision_bytes,
        "state.json": translation_state_bytes,
        "target_set.json": canonical_json_bytes(target_set.as_dict()),
    }.items():
        add(posixpath.join(translation_root, name), payload)
    for path, payload in parent_evidence:
        add(path, payload)
    for path, payload in prepared_editorial_artifacts_v0(job, packet, policy, parent_candidate):
        if path.rsplit("/", 1)[-1] != "state.json":
            add(path, payload)
    for path, payload in received_editorial_artifacts_v0(job, receipt):
        add(path, payload)
    for path, payload in editorial_submission_archive_artifacts_v0(job, raw_output, receipt):
        add(path, payload)
    validation_root = validation_job_root_v0(validation_job)
    for name, payload in {
        "job.json": canonical_json_bytes(validation_job.as_dict()),
        "packet.json": canonical_json_bytes(validation_packet.as_dict()),
        "report.json": validation_report_bytes,
        "state.json": validation_state_bytes,
        "rework_request.json": validation_rework_bytes,
        "editorial-trigger.json": trigger_bytes,
    }.items():
        add(posixpath.join(validation_root, name), payload)
    return tuple(sorted(rows.items()))


def bind_validation_editorial_acceptance_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    translation_job: TranslationJobV0,
    translation_packet: TranslationPacketV0,
    translation_decision_bytes: bytes,
    translation_state_bytes: bytes,
    target_set: TranslationTargetSetV0,
    policy: EditorialPolicyV0,
    parent_candidate: EditorialCandidateSetV0,
    parent_evidence: tuple[tuple[str, bytes], ...],
    parent_editorial_job: EditorialJobV0,
    parent_editorial_packet: EditorialPacketV0,
    validation_job: ContentValidationJobV0,
    validation_packet: ContentValidationPacketV0,
    validation_report_bytes: bytes,
    validation_state_bytes: bytes,
    validation_rework_bytes: bytes,
    expected_job: EditorialJobV0,
    expected_packet: EditorialPacketV0,
    trigger_bytes: bytes,
    receipt: EditorialSubmissionReceiptV0,
    raw_output: bytes,
) -> tuple[ImplementationRefV0, OperationHandlerV0]:
    rebuilt = build_validation_editorial_rework_v0(
        context, resolved, translation_job, translation_packet, translation_decision_bytes,
        translation_state_bytes, target_set, policy, parent_candidate, parent_evidence,
        parent_editorial_job, parent_editorial_packet, validation_job, validation_packet,
        validation_report_bytes, validation_state_bytes, validation_rework_bytes,
        budget=expected_job.budget,
    )
    if rebuilt != (expected_job, expected_packet, trigger_bytes):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation editorial bridge rebuild drift")
    expected_inputs = validation_editorial_acceptance_inputs_v0(
        translation_job, translation_packet, translation_decision_bytes, translation_state_bytes,
        target_set, expected_job, expected_packet, policy, parent_candidate, parent_evidence,
        validation_job, validation_packet, validation_report_bytes, validation_state_bytes,
        validation_rework_bytes, trigger_bytes, receipt, raw_output,
    )
    implementation = ImplementationRefV0(
        "module", expected_job.module.module_id, expected_job.module.version,
        expected_job.module.digest, Capability.EDITORIAL_REVIEW,
    )

    def handler(request: OperationRequestV0, operation_context: OperationContextV0) -> ErrorRecord | None:
        try:
            if request.capability is not Capability.EDITORIAL_REVIEW:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation editorial handler received wrong capability")
            if request.declared_outputs != editorial_acceptance_output_declarations_v0(expected_job):
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Validation editorial output contract drift")
            if tuple(row.path for row in request.inputs) != tuple(path for path, _payload in expected_inputs):
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Validation editorial input contract drift")
            for relative, payload in expected_inputs:
                if (operation_context.input_root / Path(*relative.split("/"))).read_bytes() != payload:
                    raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation editorial input authority drift")
            if editorial_submission_digest_v0(receipt) != parse_canonical_json(
                dict(expected_inputs)[posixpath.join(editorial_job_root_v0(expected_job), "state.json")]
            ).get("selected_submission_sha256"):
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation editorial submission selection drift")
            rebuilt_job, rebuilt_packet, rebuilt_trigger = build_validation_editorial_rework_v0(
                context, resolved, translation_job, translation_packet, translation_decision_bytes,
                translation_state_bytes, target_set, policy, parent_candidate, parent_evidence,
                parent_editorial_job, parent_editorial_packet, validation_job, validation_packet,
                validation_report_bytes, validation_state_bytes, validation_rework_bytes,
                budget=expected_job.budget,
            )
            if (rebuilt_job, rebuilt_packet, rebuilt_trigger) != (expected_job, expected_packet, trigger_bytes):
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation editorial runtime rebuild drift")
            for relative, payload in editorial_terminal_artifacts_v0(
                expected_job, expected_packet, policy, parent_candidate, receipt, raw_output,
            ):
                output = operation_context.staging_root / Path(*relative.split("/"))
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(payload)
            return None
        except ContractViolation as error:
            return error.as_record()

    return implementation, handler
