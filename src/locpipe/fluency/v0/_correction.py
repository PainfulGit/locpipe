from __future__ import annotations

import posixpath

from locpipe.content.v0 import ScopeRoleV0
from locpipe.contracts.v0 import (
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
)
from locpipe.editorial.v0 import (
    EditorialCandidateSetV0,
    EditorialJobV0,
    EditorialPacketV0,
    EditorialPolicyV0,
    EditorialSubmissionReceiptV0,
    editorial_submission_archive_artifacts_v0,
    prepared_editorial_artifacts_v0,
    received_editorial_artifacts_v0,
)
from locpipe.editorial.v0._acceptance import _execute_triggered_editorial_acceptance_v0
from locpipe.editorial.v0._models import candidate_raw_sha
from locpipe.editorial.v0._packet import (
    _build_triggered_editorial_job_v0,
    _validate_translation_authority,
)
from locpipe.kernel.v0.config import ResolvedConfigV0, validate_context_config_binding
from locpipe.kernel.v0.context import ProjectContextV0
from locpipe.translation.v0 import (
    ProviderBudgetV0,
    TranslationJobV0,
    TranslationPacketV0,
    TranslationTargetSetV0,
    translation_job_root_v0,
)
from locpipe.validation.v0._packet import _validate_candidate_authority

from ._acceptance import accept_fluency_submission_v0
from ._models import (
    FluencyCorrectionTriggerEntryV0,
    FluencyCorrectionTriggerV0,
    FluencyDecisionStatusV0,
    FluencyDecisionV0,
    FluencyReviewJobV0,
    FluencyReviewPacketV0,
    FluencyReviewPlanV0,
    FluencyStateV0,
)
from ._packet import fluency_bindings_from_config_v0
from ._serialization import parse_fluency_correction_trigger_v0


def _candidate_targets(candidate: EditorialCandidateSetV0) -> dict[str, bytes]:
    targets: dict[str, bytes] = {}
    for payload in candidate._target_bytes:
        envelope = parse_canonical_json(payload)
        identity = BranchIdentity.from_dict(envelope["data"]["identity"])
        stable_id = display_id(identity)
        if stable_id in targets:
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency correction candidate target identity collides")
        targets[stable_id] = payload
    return targets


def _source_rows_by_selector(translation_packet: TranslationPacketV0):
    rows = {}
    for row in translation_packet.rows:
        if row.role is not ScopeRoleV0.OWNED:
            continue
        key = (row.identity.logical_id, row.identity.selector_path)
        if key in rows:
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency correction source selector is ambiguous")
        rows[key] = row
    return rows


def build_fluency_editorial_correction_v0(
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
    fluency_plan: FluencyReviewPlanV0,
    fluency_job: FluencyReviewJobV0,
    fluency_packet: FluencyReviewPacketV0,
    fluency_receipt_bytes: bytes,
    fluency_raw_output: bytes,
    fluency_decision: FluencyDecisionV0,
    fluency_state: FluencyStateV0,
    *,
    budget: ProviderBudgetV0,
) -> tuple[EditorialJobV0, EditorialPacketV0, bytes]:
    """Build a source-aware accuracy job from accepted target-only findings."""
    if not all(isinstance(value, selected) for value, selected in (
        (context, ProjectContextV0),
        (resolved, ResolvedConfigV0),
        (translation_job, TranslationJobV0),
        (translation_packet, TranslationPacketV0),
        (target_set, TranslationTargetSetV0),
        (policy, EditorialPolicyV0),
        (parent_candidate, EditorialCandidateSetV0),
        (parent_editorial_job, EditorialJobV0),
        (parent_editorial_packet, EditorialPacketV0),
        (fluency_plan, FluencyReviewPlanV0),
        (fluency_job, FluencyReviewJobV0),
        (fluency_packet, FluencyReviewPacketV0),
        (fluency_decision, FluencyDecisionV0),
        (fluency_state, FluencyStateV0),
        (budget, ProviderBudgetV0),
    )):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction inputs are invalid")
    validate_context_config_binding(context, resolved)
    _validate_translation_authority(
        translation_job,
        translation_packet,
        translation_decision_bytes,
        target_set,
        translation_state_bytes,
    )
    module, accuracy_provider, fluency_provider = fluency_bindings_from_config_v0(resolved)
    if (
        context.context_digest != fluency_plan.context_digest
        or resolved.content_config_digest != fluency_plan.content_config_digest
        or resolved.effective_snapshot_sha256 != fluency_plan.effective_snapshot_sha256
        or module != fluency_plan.module
        or accuracy_provider != fluency_plan.accuracy_provider
        or fluency_provider != fluency_plan.fluency_provider
        or fluency_job.module != module
        or fluency_job.provider != fluency_provider
        or parent_candidate.target_locale != fluency_plan.target_locale
        or translation_job.target_locale != fluency_plan.target_locale
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction config or provider authority drift")

    rebuilt_decision, rebuilt_state = accept_fluency_submission_v0(
        fluency_plan,
        fluency_job,
        fluency_packet,
        fluency_receipt_bytes,
        fluency_raw_output,
    )
    if rebuilt_decision != fluency_decision or rebuilt_state != fluency_state:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction accepted decision or state drift")
    if (
        fluency_decision.status is not FluencyDecisionStatusV0.CORRECTION_REQUIRED
        or fluency_state.status is not FluencyDecisionStatusV0.CORRECTION_REQUIRED
        or not fluency_decision.correction_ids
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction requires accepted findings")
    if fluency_plan.round_index >= fluency_plan.max_correction_rounds:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction round is exhausted")

    authority_sha, parent_round, max_rounds, available = _validate_candidate_authority(
        parent_candidate,
        parent_evidence,
        parent_editorial_job,
        parent_editorial_packet,
        policy,
    )
    if (
        not available
        or candidate_raw_sha(parent_candidate) != fluency_plan.candidate_sha256
        or authority_sha != fluency_plan.candidate_authority_sha256
        or parent_round != parent_editorial_job.round_index
        or max_rounds != policy.max_rework_rounds
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction parent candidate authority drift")
    next_round = parent_round + 1
    if next_round > policy.max_rework_rounds:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction editorial round is exhausted")

    targets = _candidate_targets(parent_candidate)
    packet_targets = {row.stable_id: row for row in fluency_packet.rows}
    if len(packet_targets) != len(fluency_packet.rows):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency correction packet target identity collides")
    for stable_id, row in packet_targets.items():
        if stable_id not in targets or targets[stable_id] != row._target_bytes:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction packet differs from candidate")
    decision_entries = {row.stable_id: row for row in fluency_decision.entries}
    if len(decision_entries) != len(fluency_decision.entries):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency correction decision identity collides")
    source_rows = _source_rows_by_selector(translation_packet)
    entries = []
    for target_id in fluency_decision.correction_ids:
        packet_row = packet_targets.get(target_id)
        decision_entry = decision_entries.get(target_id)
        if packet_row is None or packet_row.role != "REVIEW" or decision_entry is None or not decision_entry.findings:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction target is absent from reviewed findings")
        target = parse_canonical_json(packet_row._target_bytes)
        target_identity = BranchIdentity.from_dict(target["data"]["identity"])
        key = (target_identity.logical_id, target_identity.selector_path)
        source_row = source_rows.get(key)
        if source_row is None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction target has no exact source identity")
        if target["data"].get("content_type") != source_row.content_type:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction target/source content type drift")
        entries.append(FluencyCorrectionTriggerEntryV0(
            target_id,
            raw_sha256(packet_row._target_bytes),
            source_row.identity,
            source_row.source_revision_sha,
            source_row.content_type,
            decision_entry.findings,
        ))
    trigger = FluencyCorrectionTriggerV0(
        fluency_plan.digest,
        raw_sha256(canonical_json_bytes(fluency_job.as_dict())),
        raw_sha256(canonical_json_bytes(fluency_packet.as_dict())),
        fluency_plan.candidate_sha256,
        fluency_plan.candidate_authority_sha256,
        fluency_plan.content_config_digest,
        fluency_plan.effective_snapshot_sha256,
        accuracy_provider.config_digest,
        fluency_provider.config_digest,
        fluency_decision.raw_output_sha256,
        fluency_decision.submission_sha256,
        fluency_decision.digest,
        raw_sha256(canonical_json_bytes(fluency_state.as_dict())),
        fluency_plan.round_index,
        fluency_plan.max_correction_rounds,
        parent_round,
        next_round,
        policy.digest,
        tuple(sorted(entries, key=lambda row: row.target_stable_id)),
    )
    trigger_bytes = canonical_json_bytes(trigger.as_dict())
    if parse_fluency_correction_trigger_v0(trigger_bytes) != trigger:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction trigger serialization drift")
    job, packet = _build_triggered_editorial_job_v0(
        context,
        resolved,
        translation_job,
        translation_packet,
        translation_decision_bytes,
        translation_state_bytes,
        parent_candidate,
        policy,
        module,
        accuracy_provider,
        requested_ids=trigger.requested_source_ids,
        round_index=next_round,
        trigger_bytes=trigger_bytes,
        origin_domain="fluency",
        budget=budget,
    )
    return job, packet, trigger_bytes


def fluency_correction_trigger_path_v0(trigger: FluencyCorrectionTriggerV0) -> str:
    if not isinstance(trigger, FluencyCorrectionTriggerV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction trigger is invalid")
    return posixpath.join("fl", "c", trigger.digest[:20], "trigger.json")


def fluency_accuracy_provider_inputs_v0(
    resolved: ResolvedConfigV0,
    job: EditorialJobV0,
    packet: EditorialPacketV0,
    policy: EditorialPolicyV0,
    parent_candidate: EditorialCandidateSetV0,
    trigger_bytes: bytes,
) -> tuple[tuple[str, bytes], ...]:
    """Compose exact declared inputs for a future source-aware accuracy invocation."""
    trigger = parse_fluency_correction_trigger_v0(trigger_bytes)
    module, accuracy_provider, fluency_provider = fluency_bindings_from_config_v0(resolved)
    if (
        job.module != module
        or job.provider != accuracy_provider
        or trigger.accuracy_provider_config_digest != accuracy_provider.config_digest
        or trigger.fluency_provider_config_digest != fluency_provider.config_digest
        or trigger.content_config_digest != resolved.content_config_digest
        or trigger.effective_snapshot_sha256 != resolved.effective_snapshot_sha256
        or raw_sha256(trigger_bytes) != job.parent_decision_sha256
        or raw_sha256(canonical_json_bytes(packet.as_dict())) != job.packet_sha256
        or packet.requested_ids != trigger.requested_source_ids
        or policy.digest != trigger.editorial_policy_sha256
        or job.policy_sha256 != policy.digest
        or job.parent_candidate_sha256 != trigger.candidate_sha256
        or raw_sha256(canonical_json_bytes(parent_candidate.as_dict())) != trigger.candidate_sha256
        or job.round_index != trigger.next_editorial_round
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency accuracy provider input authority drift")
    rows = dict(prepared_editorial_artifacts_v0(job, packet, policy, parent_candidate))
    trigger_path = fluency_correction_trigger_path_v0(trigger)
    if trigger_path in rows:
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency accuracy provider input paths collide")
    rows[trigger_path] = bytes(trigger_bytes)
    return tuple(sorted(rows.items()))


def fluency_accuracy_acceptance_inputs_v0(
    resolved: ResolvedConfigV0,
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
    fluency_plan: FluencyReviewPlanV0,
    fluency_job: FluencyReviewJobV0,
    fluency_packet: FluencyReviewPacketV0,
    fluency_receipt_bytes: bytes,
    fluency_raw_output: bytes,
    fluency_decision: FluencyDecisionV0,
    fluency_state: FluencyStateV0,
    trigger_bytes: bytes,
    receipt: EditorialSubmissionReceiptV0,
    raw_output: bytes,
) -> tuple[tuple[str, bytes], ...]:
    rebuilt_decision, rebuilt_state = accept_fluency_submission_v0(
        fluency_plan, fluency_job, fluency_packet, fluency_receipt_bytes, fluency_raw_output,
    )
    if rebuilt_decision != fluency_decision or rebuilt_state != fluency_state:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency accuracy accepted review authority drift")
    trigger = parse_fluency_correction_trigger_v0(trigger_bytes)
    rows: dict[str, bytes] = {}

    def add(path: str, payload: bytes) -> None:
        value = bytes(payload)
        if path in rows and rows[path] != value:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, f"Fluency accuracy input path collision: {path}")
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
    for path, payload in fluency_accuracy_provider_inputs_v0(
        resolved, job, packet, policy, parent_candidate, trigger_bytes,
    ):
        if path.rsplit("/", 1)[-1] != "state.json":
            add(path, payload)
    for path, payload in received_editorial_artifacts_v0(job, receipt):
        add(path, payload)
    for path, payload in editorial_submission_archive_artifacts_v0(job, raw_output, receipt):
        add(path, payload)
    root = posixpath.dirname(fluency_correction_trigger_path_v0(trigger))
    for name, payload in {
        "review-plan.json": canonical_json_bytes(fluency_plan.as_dict()),
        "review-job.json": canonical_json_bytes(fluency_job.as_dict()),
        "review-packet.json": canonical_json_bytes(fluency_packet.as_dict()),
        "review-receipt.json": fluency_receipt_bytes,
        "review-output.json": fluency_raw_output,
        "review-decision.json": canonical_json_bytes(fluency_decision.as_dict()),
        "review-state.json": canonical_json_bytes(fluency_state.as_dict()),
        "trigger.json": trigger_bytes,
    }.items():
        add(posixpath.join(root, name), payload)
    return tuple(sorted(rows.items()))


def bind_fluency_accuracy_acceptance_v0(
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
    fluency_plan: FluencyReviewPlanV0,
    fluency_job: FluencyReviewJobV0,
    fluency_packet: FluencyReviewPacketV0,
    fluency_receipt_bytes: bytes,
    fluency_raw_output: bytes,
    fluency_decision: FluencyDecisionV0,
    fluency_state: FluencyStateV0,
    expected_job: EditorialJobV0,
    expected_packet: EditorialPacketV0,
    trigger_bytes: bytes,
    receipt: EditorialSubmissionReceiptV0,
    raw_output: bytes,
) -> tuple[ImplementationRefV0, OperationHandlerV0]:
    rebuilt = build_fluency_editorial_correction_v0(
        context, resolved, translation_job, translation_packet, translation_decision_bytes,
        translation_state_bytes, target_set, policy, parent_candidate, parent_evidence,
        parent_editorial_job, parent_editorial_packet, fluency_plan, fluency_job, fluency_packet,
        fluency_receipt_bytes, fluency_raw_output, fluency_decision, fluency_state,
        budget=expected_job.budget,
    )
    if rebuilt != (expected_job, expected_packet, trigger_bytes):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency accuracy bridge rebuild drift")
    expected_inputs = fluency_accuracy_acceptance_inputs_v0(
        resolved, translation_job, translation_packet, translation_decision_bytes, translation_state_bytes,
        target_set, expected_job, expected_packet, policy, parent_candidate, parent_evidence,
        fluency_plan, fluency_job, fluency_packet, fluency_receipt_bytes, fluency_raw_output,
        fluency_decision, fluency_state, trigger_bytes, receipt, raw_output,
    )
    implementation = ImplementationRefV0(
        "module", expected_job.module.module_id, expected_job.module.version,
        expected_job.module.digest, Capability.EDITORIAL_REVIEW,
    )

    def handler(request: OperationRequestV0, operation_context: OperationContextV0) -> ErrorRecord | None:
        try:
            rebuilt_authority = build_fluency_editorial_correction_v0(
                context, resolved, translation_job, translation_packet, translation_decision_bytes,
                translation_state_bytes, target_set, policy, parent_candidate, parent_evidence,
                parent_editorial_job, parent_editorial_packet, fluency_plan, fluency_job, fluency_packet,
                fluency_receipt_bytes, fluency_raw_output, fluency_decision, fluency_state,
                budget=expected_job.budget,
            )
        except ContractViolation as error:
            return error.as_record()
        return _execute_triggered_editorial_acceptance_v0(
            request,
            operation_context,
            origin_domain="fluency",
            expected_job=expected_job,
            expected_packet=expected_packet,
            expected_policy=policy,
            expected_parent=parent_candidate,
            expected_inputs=expected_inputs,
            receipt=receipt,
            raw_output=raw_output,
            rebuilt_authority=rebuilt_authority,
            expected_trigger_bytes=trigger_bytes,
        )

    return implementation, handler
