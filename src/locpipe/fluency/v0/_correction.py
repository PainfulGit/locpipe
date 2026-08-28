from __future__ import annotations

import posixpath
from collections.abc import Mapping

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
    EditorialActionV0,
    EditorialCandidateSetV0,
    EditorialJobStatusV0,
    EditorialJobV0,
    EditorialPacketV0,
    EditorialPolicyV0,
    EditorialSubmissionReceiptV0,
    editorial_job_root_v0,
    editorial_submission_archive_artifacts_v0,
    editorial_terminal_artifacts_v0,
    parse_editorial_candidate_v0,
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
    FluencyAdjudicationEntryV0,
    FluencyAdjudicationStatusV0,
    FluencyAdjudicationV0,
    FluencyCorrectionTriggerEntryV0,
    FluencyCorrectionTriggerV0,
    FluencyDecisionStatusV0,
    FluencyDecisionV0,
    FluencyReviewJobV0,
    FluencyReviewPacketV0,
    FluencyReviewPlanV0,
    FluencyStateV0,
    FluencyTargetProjectionV0,
)
from ._packet import build_fluency_review_job_v0, fluency_bindings_from_config_v0
from ._serialization import parse_fluency_adjudication_v0, parse_fluency_correction_trigger_v0


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
    parent_adjudication_bytes: bytes | None = None,
    parent_trigger_bytes: bytes | None = None,
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
    if fluency_plan.round_index == 0:
        if parent_adjudication_bytes is not None or parent_trigger_bytes is not None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Initial fluency correction cannot have parent authority")
    else:
        if not isinstance(parent_adjudication_bytes, bytes) or not isinstance(parent_trigger_bytes, bytes):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Later fluency correction requires parent trigger and adjudication")
        parent_trigger = parse_fluency_correction_trigger_v0(parent_trigger_bytes)
        parent_adjudication = parse_fluency_adjudication_v0(parent_adjudication_bytes)
        if (
            raw_sha256(parent_trigger_bytes) != parent_adjudication.trigger_sha256
            or parent_adjudication.status is not FluencyAdjudicationStatusV0.CORRECTIONS_READY_FOR_RECHECK
            or raw_sha256(parent_adjudication_bytes) != fluency_plan.parent_terminal_sha256
            or parent_adjudication.resulting_candidate_sha256 != fluency_plan.candidate_sha256
            or fluency_plan.requested_ids != parent_adjudication.corrected_ids
            or fluency_plan.round_index != parent_trigger.current_fluency_round + 1
            or fluency_plan.max_correction_rounds != parent_trigger.max_fluency_correction_rounds
        ):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction parent authority drift")
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


def _canonical_terminal_tuple(values: tuple[tuple[str, bytes], ...]) -> tuple[tuple[str, bytes], ...]:
    try:
        rows = tuple((path, bytes(payload)) for path, payload in values)
    except (TypeError, ValueError) as error:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency adjudication terminal artifacts are invalid") from error
    paths = tuple(path for path, _payload in rows)
    if (
        any(not isinstance(path, str) or not path for path in paths)
        or paths != tuple(sorted(paths))
        or len(paths) != len(set(paths))
    ):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency adjudication terminal paths must be unique and sorted")
    return rows


def _canonical_mapping_artifact(payload: bytes, name: str) -> Mapping[str, object]:
    value = parse_canonical_json(payload)
    if canonical_json_bytes(value) != payload or not isinstance(value, Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} is not canonical")
    return value


def accept_fluency_adjudication_v0(
    resolved: ResolvedConfigV0,
    trigger_bytes: bytes,
    job: EditorialJobV0,
    packet: EditorialPacketV0,
    policy: EditorialPolicyV0,
    parent_candidate: EditorialCandidateSetV0,
    receipt: EditorialSubmissionReceiptV0,
    raw_output: bytes,
    terminal_artifacts: tuple[tuple[str, bytes], ...],
) -> FluencyAdjudicationV0:
    """Narrow exact existing editorial terminal evidence into fluency adjudication."""
    if not all(isinstance(value, selected) for value, selected in (
        (resolved, ResolvedConfigV0),
        (job, EditorialJobV0),
        (packet, EditorialPacketV0),
        (policy, EditorialPolicyV0),
        (parent_candidate, EditorialCandidateSetV0),
        (receipt, EditorialSubmissionReceiptV0),
    )) or not isinstance(trigger_bytes, bytes) or not isinstance(raw_output, bytes):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency adjudication inputs are invalid")

    trigger = parse_fluency_correction_trigger_v0(trigger_bytes)
    fluency_accuracy_provider_inputs_v0(
        resolved, job, packet, policy, parent_candidate, trigger_bytes,
    )
    expected_receipt = EditorialSubmissionReceiptV0(
        job.job_id,
        job.invocation_id,
        job.provider,
        receipt.provider_request_id,
        job.packet_sha256,
        job.output_contract_sha256,
        raw_sha256(raw_output),
    )
    if receipt != expected_receipt:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency adjudication receipt or raw output drift")

    expected_terminal = editorial_terminal_artifacts_v0(
        job, packet, policy, parent_candidate, receipt, raw_output,
    )
    supplied_terminal = _canonical_terminal_tuple(terminal_artifacts)
    if supplied_terminal != expected_terminal:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency adjudication terminal artifact drift")
    terminal = dict(expected_terminal)
    root = editorial_job_root_v0(job)
    decision_bytes = terminal[posixpath.join(root, "decision_set.json")]
    overlay_bytes = terminal[posixpath.join(root, "overlay.json")]
    candidate_bytes = terminal[posixpath.join(root, "candidate_set.json")]
    state_bytes = terminal[posixpath.join(root, "state.json")]
    decision = _canonical_mapping_artifact(decision_bytes, "Fluency adjudication decision set")
    overlay = _canonical_mapping_artifact(overlay_bytes, "Fluency adjudication overlay")
    state = _canonical_mapping_artifact(state_bytes, "Fluency adjudication editorial state")
    resulting_candidate = parse_editorial_candidate_v0(candidate_bytes)
    if (
        decision.get("status") != EditorialJobStatusV0.ACCEPTED.value
        or state.get("status") != EditorialJobStatusV0.ACCEPTED.value
        or decision.get("job_id") != job.job_id
        or overlay.get("job_id") != job.job_id
        or resulting_candidate.job_id != job.job_id
        or state.get("job_id") != job.job_id
        or state.get("invocation_id") != job.invocation_id
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency adjudication requires exact accepted editorial terminal evidence")

    decision_rows = decision.get("decisions")
    overlay_rows = overlay.get("entries")
    if not isinstance(decision_rows, list) or not isinstance(overlay_rows, list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency adjudication editorial rows are invalid")

    trigger_by_source = {entry.source_stable_id: entry for entry in trigger.entries}
    if len(trigger_by_source) != len(trigger.entries):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency adjudication source mapping collides")
    decisions: dict[str, Mapping[str, object]] = {}
    for row in decision_rows:
        if not isinstance(row, Mapping):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency adjudication decision row is invalid")
        try:
            source_id = display_id(BranchIdentity.from_dict(row["identity"]))
        except (KeyError, TypeError) as error:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency adjudication decision identity is invalid") from error
        if source_id in decisions:
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency adjudication decision identity collides")
        decisions[source_id] = row
    if tuple(sorted(decisions)) != trigger.requested_source_ids:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency adjudication decision coverage drift")

    overlays: dict[str, Mapping[str, object]] = {}
    for row in overlay_rows:
        if not isinstance(row, Mapping):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency adjudication overlay row is invalid")
        try:
            source_id = display_id(BranchIdentity.from_dict(row["source_identity"]))
        except (KeyError, TypeError) as error:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency adjudication overlay identity is invalid") from error
        if source_id in overlays:
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency adjudication overlay identity collides")
        overlays[source_id] = row

    parent_targets = _candidate_targets(parent_candidate)
    resulting_targets = _candidate_targets(resulting_candidate)
    if set(parent_targets) != set(resulting_targets):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency adjudication candidate identity set drift")
    changed_target_ids = tuple(sorted(
        target_id for target_id in parent_targets
        if parent_targets[target_id] != resulting_targets[target_id]
    ))

    entries = []
    keep_ids = []
    corrected_ids = []
    correct_source_ids = []
    for trigger_entry in trigger.entries:
        source_id = trigger_entry.source_stable_id
        target_id = trigger_entry.target_stable_id
        decision_row = decisions[source_id]
        try:
            action = EditorialActionV0(decision_row["action"])
            reason_code = decision_row["reason_code"]
        except (KeyError, TypeError, ValueError) as error:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency adjudication decision value is invalid") from error
        if not isinstance(reason_code, str) or not reason_code:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency adjudication decision reason is invalid")
        if target_id not in parent_targets or raw_sha256(parent_targets[target_id]) != trigger_entry.target_sha256:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency adjudication trigger target drift")
        finding_set_sha = raw_sha256(canonical_json_bytes([
            finding.as_dict() for finding in trigger_entry.findings
        ]))
        overlay_entry_sha = None
        if action is EditorialActionV0.KEEP:
            if decision_row.get("replacement_sha256") is not None or source_id in overlays or parent_targets[target_id] != resulting_targets[target_id]:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency KEEP adjudication target or overlay drift")
            keep_ids.append(target_id)
        elif action is EditorialActionV0.CORRECT:
            overlay_row = overlays.get(source_id)
            if decision_row.get("replacement_sha256") is None or overlay_row is None or parent_targets[target_id] == resulting_targets[target_id]:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency CORRECT adjudication target or overlay drift")
            overlay_entry_sha = raw_sha256(canonical_json_bytes(overlay_row))
            corrected_ids.append(target_id)
            correct_source_ids.append(source_id)
        else:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency adjudication forbids editorial rework")
        entries.append(FluencyAdjudicationEntryV0(
            target_id,
            source_id,
            finding_set_sha,
            action,
            reason_code,
            overlay_entry_sha,
        ))

    if tuple(sorted(overlays)) != tuple(sorted(correct_source_ids)):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency adjudication overlay set drift")
    mapped_overlay_targets = tuple(sorted(trigger_by_source[source_id].target_stable_id for source_id in overlays))
    corrected = tuple(sorted(corrected_ids))
    if corrected != mapped_overlay_targets or corrected != changed_target_ids:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency adjudication corrected target set drift")
    keep = tuple(sorted(keep_ids))
    status = (
        FluencyAdjudicationStatusV0.CORRECTIONS_READY_FOR_RECHECK
        if corrected
        else FluencyAdjudicationStatusV0.DISMISSALS_ONLY
    )
    adjudication = FluencyAdjudicationV0(
        raw_sha256(trigger_bytes),
        raw_sha256(canonical_json_bytes(job.as_dict())),
        raw_sha256(canonical_json_bytes(packet.as_dict())),
        raw_sha256(canonical_json_bytes(receipt.as_dict())),
        raw_sha256(raw_output),
        raw_sha256(decision_bytes),
        raw_sha256(overlay_bytes),
        raw_sha256(candidate_bytes),
        raw_sha256(state_bytes),
        tuple(entries),
        keep,
        corrected,
        status,
    )
    adjudication_bytes = canonical_json_bytes(adjudication.as_dict())
    if parse_fluency_adjudication_v0(adjudication_bytes) != adjudication:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency adjudication serialization drift")
    return adjudication


def build_fluency_recheck_job_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    trigger_bytes: bytes,
    adjudication_bytes: bytes,
    accuracy_job: EditorialJobV0,
    accuracy_packet: EditorialPacketV0,
    policy: EditorialPolicyV0,
    parent_candidate: EditorialCandidateSetV0,
    receipt: EditorialSubmissionReceiptV0,
    raw_output: bytes,
    terminal_artifacts: tuple[tuple[str, bytes], ...],
    candidate_evidence: tuple[tuple[str, bytes], ...],
    projection: FluencyTargetProjectionV0,
    *,
    budget: ProviderBudgetV0,
) -> tuple[FluencyReviewPlanV0, FluencyReviewJobV0, FluencyReviewPacketV0]:
    """Build an exact corrected-ID target-only recheck from accepted accuracy evidence."""
    if not all(isinstance(value, selected) for value, selected in (
        (context, ProjectContextV0),
        (resolved, ResolvedConfigV0),
        (accuracy_job, EditorialJobV0),
        (accuracy_packet, EditorialPacketV0),
        (policy, EditorialPolicyV0),
        (parent_candidate, EditorialCandidateSetV0),
        (receipt, EditorialSubmissionReceiptV0),
        (projection, FluencyTargetProjectionV0),
        (budget, ProviderBudgetV0),
    )) or not isinstance(trigger_bytes, bytes) or not isinstance(adjudication_bytes, bytes) or not isinstance(raw_output, bytes):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency recheck inputs are invalid")

    trigger = parse_fluency_correction_trigger_v0(trigger_bytes)
    adjudication = parse_fluency_adjudication_v0(adjudication_bytes)
    rebuilt_adjudication = accept_fluency_adjudication_v0(
        resolved,
        trigger_bytes,
        accuracy_job,
        accuracy_packet,
        policy,
        parent_candidate,
        receipt,
        raw_output,
        terminal_artifacts,
    )
    if rebuilt_adjudication != adjudication:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency recheck adjudication drift")
    if (
        adjudication.status is not FluencyAdjudicationStatusV0.CORRECTIONS_READY_FOR_RECHECK
        or not adjudication.corrected_ids
        or adjudication.trigger_sha256 != raw_sha256(trigger_bytes)
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency recheck requires accepted corrections")

    terminal = dict(editorial_terminal_artifacts_v0(
        accuracy_job,
        accuracy_packet,
        policy,
        parent_candidate,
        receipt,
        raw_output,
    ))
    candidate_path = posixpath.join(editorial_job_root_v0(accuracy_job), "candidate_set.json")
    resulting_candidate_bytes = terminal[candidate_path]
    resulting_candidate = parse_editorial_candidate_v0(resulting_candidate_bytes)
    candidate_authority_sha, editorial_round, max_editorial_rounds, available = _validate_candidate_authority(
        resulting_candidate,
        candidate_evidence,
        accuracy_job,
        accuracy_packet,
        policy,
    )
    if (
        not available
        or raw_sha256(resulting_candidate_bytes) != adjudication.resulting_candidate_sha256
        or editorial_round != accuracy_job.round_index
        or max_editorial_rounds != policy.max_rework_rounds
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency recheck candidate authority drift")

    next_round = trigger.current_fluency_round + 1
    if next_round > trigger.max_fluency_correction_rounds:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency recheck round is exhausted")
    return build_fluency_review_job_v0(
        context,
        resolved,
        resulting_candidate,
        projection,
        candidate_authority_sha256=candidate_authority_sha,
        requested_ids=adjudication.corrected_ids,
        budget=budget,
        round_index=next_round,
        max_correction_rounds=trigger.max_fluency_correction_rounds,
        parent_terminal_sha256=adjudication.digest,
    )
