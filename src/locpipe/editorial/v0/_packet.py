from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from locpipe.content.v0 import ScopeRoleV0
from locpipe.contracts.v0 import (
    BranchIdentity,
    Capability,
    ContractViolation,
    ErrorCode,
    ModuleDescriptorV0,
    canonical_json_bytes,
    display_id,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
)
from locpipe.kernel.v0.config import ResolvedConfigV0, validate_context_config_binding
from locpipe.kernel.v0.context import ProjectContextV0
from locpipe.translation.v0 import (
    ProviderBindingV0,
    ProviderBudgetV0,
    TranslationJobV0,
    TranslationJobStatusV0,
    TranslationPacketV0,
    TranslationStateV0,
    TranslationTargetSetV0,
)

from ._models import (
    EditorialCandidateSetV0,
    EditorialJobV0,
    EditorialPacketRowV0,
    EditorialPacketV0,
    EditorialPolicyV0,
    EditorialJobStatusV0,
    candidate_raw_sha,
    target_bytes_by_id,
)
from ._serialization import parse_editorial_state_v0


ROLE_CONTRACT_SHA256 = semantic_sha256({
    "contract": "locpipe.editorial.role/accuracy-editor/v0",
    "role": "accuracy_editor",
    "actions": ["KEEP", "CORRECT", "REWORK_REQUIRED"],
    "raw_outputs_immutable": True,
})
OUTPUT_CONTRACT_SHA256 = semantic_sha256({
    "contract": "locpipe.editorial.provider-output/v0",
    "coverage": "exact_requested_ids",
    "corrections": "target_branch_overlay_only",
})


def editorial_bindings_from_config_v0(
    resolved: ResolvedConfigV0,
) -> tuple[ModuleDescriptorV0, ProviderBindingV0] | None:
    if not isinstance(resolved, ResolvedConfigV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Resolved config is invalid")
    raw_modules = resolved.get_value("module_bindings")
    module_rows = [row for row in raw_modules if isinstance(row, Mapping) and row.get("capability") == Capability.EDITORIAL_REVIEW.value]
    raw_providers = resolved.get_value("provider_bindings")
    provider_rows = [row for row in raw_providers if isinstance(row, Mapping) and row.get("role") == "accuracy_editor"]
    if not module_rows and not provider_rows:
        return None
    if len(module_rows) != 1 or len(provider_rows) != 1:
        raise ContractViolation(ErrorCode.CAPABILITY_MISSING, "Editorial module/provider binding is missing or ambiguous")
    module_row = module_rows[0]
    provider_row = provider_rows[0]
    if set(module_row) != {"capability", "module_id", "version", "digest"} or set(provider_row) != {"role", "provider_id", "version", "config_digest"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial binding fields are invalid")
    return (
        ModuleDescriptorV0(Capability.EDITORIAL_REVIEW, module_row["module_id"], module_row["version"], module_row["digest"]),
        ProviderBindingV0(provider_row["role"], provider_row["provider_id"], provider_row["version"], provider_row["config_digest"]),
    )


def _target_key(envelope: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    identity = BranchIdentity.from_dict(envelope["data"]["identity"])
    return identity.logical_id, identity.selector_path


def _validate_translation_authority(
    translation_job: TranslationJobV0,
    translation_packet: TranslationPacketV0,
    translation_decision_bytes: bytes,
    target_set: TranslationTargetSetV0,
    translation_state_bytes: bytes,
) -> None:
    if raw_sha256(canonical_json_bytes(translation_packet.as_dict())) != translation_job.packet_sha256:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Editorial input translation packet drift")
    decision = parse_canonical_json(translation_decision_bytes)
    if canonical_json_bytes(decision) != translation_decision_bytes or decision.get("contract") != "locpipe.translation.decision/v0":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation decision is invalid")
    if decision.get("status") != "ACCEPTED" or decision.get("job_id") != translation_job.job_id or decision.get("invocation_id") != translation_job.invocation_id:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial review requires accepted translation decision")
    if target_set.job_id != translation_job.job_id or target_set.invocation_id != translation_job.invocation_id or target_set.target_locale != translation_job.target_locale:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation target set differs from job")
    if decision.get("target_count") != len(target_set._target_bytes):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation decision/target count drift")
    state_value = parse_canonical_json(translation_state_bytes)
    if canonical_json_bytes(state_value) != translation_state_bytes:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation terminal state is not canonical")
    expected_state = TranslationStateV0(
        translation_job.job_id, translation_job.invocation_id, TranslationJobStatusV0.ACCEPTED,
        decision.get("submission_sha256"), raw_sha256(translation_decision_bytes),
        raw_sha256(canonical_json_bytes(target_set.as_dict())),
    )
    if state_value != expected_state.as_dict():
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation terminal state does not bind decision/targets")
    owned = {
        (row.identity.logical_id, row.identity.selector_path)
        for row in translation_packet.rows if row.role is ScopeRoleV0.OWNED
    }
    targets = {
        _target_key(parse_canonical_json(payload))
        for payload in target_set._target_bytes
    }
    if targets != owned or len(targets) != len(target_set._target_bytes):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation target set does not exactly cover owned packet")


def base_candidate_from_translation_v0(
    translation_job: TranslationJobV0,
    target_set: TranslationTargetSetV0,
    *,
    ready: bool = False,
    disposition: str = "PENDING_EDITORIAL",
) -> EditorialCandidateSetV0:
    target_set_bytes = canonical_json_bytes(target_set.as_dict())
    target_ids = tuple(
        display_id(BranchIdentity.from_dict(parse_canonical_json(row)["data"]["identity"]))
        for row in target_set._target_bytes
    )
    job_id = "editorial-base-" + semantic_sha256({
        "translation_job_id": translation_job.job_id,
        "target_set_sha256": raw_sha256(target_set_bytes),
        "disposition": disposition,
    })[:32]
    return EditorialCandidateSetV0(
        job_id,
        target_set.target_locale,
        ready,
        disposition,
        raw_sha256(target_set_bytes),
        None,
        (),
        () if ready else target_ids,
        target_set._target_bytes,
    )


def build_editorial_bypass_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    translation_job: TranslationJobV0,
    translation_packet: TranslationPacketV0,
    translation_decision_bytes: bytes,
    target_set: TranslationTargetSetV0,
    translation_state_bytes: bytes,
) -> EditorialCandidateSetV0:
    validate_context_config_binding(context, resolved)
    if context.context_digest != translation_job.context_digest:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation job belongs to another context")
    if translation_job.content_config_digest != resolved.content_config_digest or translation_job.effective_snapshot_sha256 != resolved.effective_snapshot_sha256:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial bypass config differs from translation authority")
    if editorial_bindings_from_config_v0(resolved) is not None:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Configured editorial review cannot be bypassed")
    _validate_translation_authority(
        translation_job, translation_packet, translation_decision_bytes, target_set, translation_state_bytes,
    )
    return base_candidate_from_translation_v0(translation_job, target_set, ready=True, disposition="BYPASSED_BY_CONFIG")


def _validate_parent_rework(
    parent: EditorialCandidateSetV0,
    policy: EditorialPolicyV0,
    round_index: int,
    parent_state_bytes: bytes,
    parent_decision_bytes: bytes,
    parent_rework_request_bytes: bytes,
) -> str:
    state = parse_editorial_state_v0(parent_state_bytes)
    decision = parse_canonical_json(parent_decision_bytes)
    rework = parse_canonical_json(parent_rework_request_bytes)
    if canonical_json_bytes(decision) != parent_decision_bytes or canonical_json_bytes(rework) != parent_rework_request_bytes:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial parent evidence is not canonical")
    decision_sha = raw_sha256(parent_decision_bytes)
    decision_fields = {"contract", "job_id", "submission_sha256", "status", "reason_code", "decisions"}
    rework_fields = {
        "contract", "job_id", "disposition", "candidate_sha256", "parent_decision_sha256",
        "policy_sha256", "next_round", "requested_ids",
    }
    if not isinstance(decision, Mapping) or set(decision) != decision_fields or not isinstance(decision.get("decisions"), list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial parent decision fields are invalid")
    if not isinstance(rework, Mapping) or set(rework) != rework_fields or not isinstance(rework.get("requested_ids"), list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial parent rework fields are invalid")
    decision_ids = []
    rework_ids = []
    try:
        for row in decision["decisions"]:
            if not isinstance(row, Mapping) or set(row) != {"identity", "action", "reason_code", "replacement_sha256"}:
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial parent decision entry is invalid")
            identity = BranchIdentity.from_dict(row["identity"])
            stable_id = display_id(identity)
            decision_ids.append(stable_id)
            if row["action"] == "REWORK_REQUIRED":
                rework_ids.append(stable_id)
            elif row["action"] not in {"KEEP", "CORRECT"}:
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial parent decision action is invalid")
            if not isinstance(row["reason_code"], str) or not row["reason_code"]:
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial parent decision reason is invalid")
            replacement = row["replacement_sha256"]
            if (row["action"] == "CORRECT") != (isinstance(replacement, str) and len(replacement) == 64):
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial parent replacement binding is invalid")
    except (KeyError, TypeError) as error:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial parent decision is invalid") from error
    if decision_ids != sorted(decision_ids) or len(decision_ids) != len(set(decision_ids)):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Editorial parent decisions are not canonical")
    if tuple(rework_ids) != parent.unresolved_ids:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial parent unresolved decisions drift")
    if (
        state.status is not EditorialJobStatusV0.REWORK_REQUIRED
        or state.job_id != parent.job_id
        or state.candidate_sha256 != candidate_raw_sha(parent)
        or state.decision_set_sha256 != decision_sha
        or not parent.overlay_sha256s
        or state.overlay_sha256 != parent.overlay_sha256s[-1]
        or state.rework_request_sha256 != raw_sha256(parent_rework_request_bytes)
        or decision.get("contract") != "locpipe.editorial.decision-set/v0"
        or decision.get("job_id") != parent.job_id
        or decision.get("submission_sha256") != state.selected_submission_sha256
        or decision.get("status") != EditorialJobStatusV0.REWORK_REQUIRED.value
        or rework.get("contract") != "locpipe.editorial.rework-request/v0"
        or rework.get("job_id") != parent.job_id
        or rework.get("disposition") != EditorialJobStatusV0.REWORK_REQUIRED.value
        or rework.get("candidate_sha256") != candidate_raw_sha(parent)
        or rework.get("parent_decision_sha256") != decision_sha
        or rework.get("policy_sha256") != policy.digest
        or rework.get("next_round") != round_index
        or tuple(rework.get("requested_ids", ())) != parent.unresolved_ids
        or parent.disposition != EditorialJobStatusV0.REWORK_REQUIRED.value
        or round_index != len(parent.overlay_sha256s)
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial rework parent evidence drift")
    return decision_sha


def _candidate_targets_by_logical(candidate: EditorialCandidateSetV0) -> dict[tuple[tuple[str, ...], tuple[str, ...]], bytes]:
    result = {}
    for payload in candidate._target_bytes:
        envelope = parse_canonical_json(payload)
        key = _target_key(envelope)
        if key in result:
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Editorial candidate logical target collision")
        result[key] = payload
    return result


def _build_triggered_editorial_job_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    translation_job: TranslationJobV0,
    translation_packet: TranslationPacketV0,
    translation_decision_bytes: bytes,
    translation_state_bytes: bytes,
    parent_candidate: EditorialCandidateSetV0,
    policy: EditorialPolicyV0,
    module: ModuleDescriptorV0,
    provider: ProviderBindingV0,
    *,
    requested_ids: tuple[str, ...],
    round_index: int,
    trigger_bytes: bytes,
    origin_domain: str,
    budget: ProviderBudgetV0,
) -> tuple[EditorialJobV0, EditorialPacketV0]:
    """Build an exact-ID editorial job after origin-specific authority validation."""
    origins = {
        "validation": ("validation-origin-job", "validation_trigger_sha256"),
        "fluency": ("fluency-origin-job", "fluency_trigger_sha256"),
    }
    if origin_domain not in origins:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Triggered editorial origin domain is invalid")
    if not all(isinstance(value, selected) for value, selected in (
        (context, ProjectContextV0),
        (resolved, ResolvedConfigV0),
        (translation_job, TranslationJobV0),
        (translation_packet, TranslationPacketV0),
        (parent_candidate, EditorialCandidateSetV0),
        (policy, EditorialPolicyV0),
        (module, ModuleDescriptorV0),
        (provider, ProviderBindingV0),
        (budget, ProviderBudgetV0),
    )):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Triggered editorial inputs are invalid")
    trigger = parse_canonical_json(trigger_bytes)
    if canonical_json_bytes(trigger) != trigger_bytes:
        raise ContractViolation(ErrorCode.CANONICALIZATION_ERROR, "Triggered editorial evidence is not canonical")
    requested = tuple(requested_ids)
    if (
        not requested
        or requested != tuple(sorted(requested))
        or len(requested) != len(set(requested))
        or any(not isinstance(value, str) or not value for value in requested)
    ):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Triggered editorial requested IDs must be non-empty, unique and sorted")
    if (
        not isinstance(round_index, int)
        or isinstance(round_index, bool)
        or round_index < 1
        or round_index > policy.max_rework_rounds
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Triggered editorial round exceeds policy")
    if (
        context.context_digest != translation_job.context_digest
        or translation_job.content_config_digest != resolved.content_config_digest
        or translation_job.effective_snapshot_sha256 != resolved.effective_snapshot_sha256
        or parent_candidate.target_locale != translation_job.target_locale
        or not parent_candidate.ready
        or parent_candidate.unresolved_ids
        or module.capability is not Capability.EDITORIAL_REVIEW
        or provider.role != "accuracy_editor"
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Triggered editorial authority differs from translation context")

    targets = _candidate_targets_by_logical(parent_candidate)
    owned_keys = {
        (row.identity.logical_id, row.identity.selector_path)
        for row in translation_packet.rows if row.role is ScopeRoleV0.OWNED
    }
    owned_ids = {
        row.stable_id for row in translation_packet.rows if row.role is ScopeRoleV0.OWNED
    }
    if set(targets) != owned_keys or not set(requested).issubset(owned_ids):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Triggered editorial target coverage drift")
    packet_rows = tuple(sorted((
        EditorialPacketRowV0(
            row.identity,
            row.role,
            row.source_revision_sha,
            row.content_type,
            row._payload_bytes,
            row._constraints_bytes,
            targets.get((row.identity.logical_id, row.identity.selector_path))
            if row.role is ScopeRoleV0.OWNED else None,
        )
        for row in translation_packet.rows
    ), key=lambda row: row.stable_id))
    packet = EditorialPacketV0(
        translation_job.target_locale,
        round_index,
        requested,
        packet_rows,
        translation_packet._relation_bytes,
    )
    packet_sha = raw_sha256(canonical_json_bytes(packet.as_dict()))
    job_kind, trigger_field = origins[origin_domain]
    identity = {
        "context_digest": context.context_digest,
        "translation_job_id": translation_job.job_id,
        "translation_decision_sha256": raw_sha256(translation_decision_bytes),
        "translation_state_sha256": raw_sha256(translation_state_bytes),
        "base_target_set_sha256": parent_candidate.base_target_set_sha256,
        "parent_candidate_sha256": candidate_raw_sha(parent_candidate),
        trigger_field: raw_sha256(trigger_bytes),
        "scope_sha256": translation_job.scope_sha256,
        "source_lock_sha256": translation_job.source_lock_sha256,
        "reconciliation_sha256": translation_job.reconciliation_sha256,
        "content_config_digest": resolved.content_config_digest,
        "effective_snapshot_sha256": resolved.effective_snapshot_sha256,
        "module": {
            "capability": module.capability.value,
            "module_id": module.module_id,
            "version": module.version,
            "digest": module.digest,
        },
        "provider": provider.as_dict(),
        "target_locale": translation_job.target_locale,
        "packet_sha256": packet_sha,
        "policy_sha256": policy.digest,
        "role_contract_sha256": ROLE_CONTRACT_SHA256,
        "output_contract_sha256": OUTPUT_CONTRACT_SHA256,
        "budget": budget.as_dict(),
        "round_index": round_index,
        "max_invocations": 1,
    }
    job_id = "editorial-" + semantic_sha256({"kind": job_kind, **identity})[:32]
    invocation_id = "invocation-" + semantic_sha256({
        "job_id": job_id,
        "provider": provider.as_dict(),
        "round": round_index,
    })[:32]
    job = EditorialJobV0(
        job_id,
        invocation_id,
        context.context_digest,
        translation_job.job_id,
        raw_sha256(translation_decision_bytes),
        raw_sha256(translation_state_bytes),
        parent_candidate.base_target_set_sha256,
        candidate_raw_sha(parent_candidate),
        raw_sha256(trigger_bytes),
        translation_job.scope_sha256,
        translation_job.source_lock_sha256,
        translation_job.reconciliation_sha256,
        resolved.content_config_digest,
        resolved.effective_snapshot_sha256,
        module,
        provider,
        translation_job.target_locale,
        packet_sha,
        policy.digest,
        ROLE_CONTRACT_SHA256,
        OUTPUT_CONTRACT_SHA256,
        budget,
        round_index,
    )
    return job, packet


def build_editorial_job_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    translation_job: TranslationJobV0,
    translation_packet: TranslationPacketV0,
    translation_decision_bytes: bytes,
    target_set: TranslationTargetSetV0,
    translation_state_bytes: bytes,
    policy: EditorialPolicyV0,
    *,
    budget: ProviderBudgetV0,
    parent_candidate: EditorialCandidateSetV0 | None = None,
    parent_state_bytes: bytes | None = None,
    parent_decision_bytes: bytes | None = None,
    parent_rework_request_bytes: bytes | None = None,
    requested_ids: tuple[str, ...] | None = None,
    round_index: int = 0,
) -> tuple[EditorialJobV0, EditorialPacketV0, EditorialCandidateSetV0]:
    if not all(isinstance(row, selected) for row, selected in (
        (context, ProjectContextV0), (resolved, ResolvedConfigV0), (translation_job, TranslationJobV0),
        (translation_packet, TranslationPacketV0), (target_set, TranslationTargetSetV0),
        (policy, EditorialPolicyV0), (budget, ProviderBudgetV0),
    )):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial job inputs are invalid")
    validate_context_config_binding(context, resolved)
    if context.context_digest != translation_job.context_digest or translation_job.content_config_digest != resolved.content_config_digest or translation_job.effective_snapshot_sha256 != resolved.effective_snapshot_sha256:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial context/config differs from translation authority")
    bindings = editorial_bindings_from_config_v0(resolved)
    if bindings is None:
        raise ContractViolation(ErrorCode.CAPABILITY_MISSING, "Editorial review is not configured")
    module, provider = bindings
    _validate_translation_authority(translation_job, translation_packet, translation_decision_bytes, target_set, translation_state_bytes)
    if policy.max_rework_rounds < round_index:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial rework round exceeds policy")
    base = base_candidate_from_translation_v0(translation_job, target_set)
    current = parent_candidate or base
    if current.base_target_set_sha256 != base.base_target_set_sha256 or current.target_locale != target_set.target_locale:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial parent candidate differs from translation base")
    if set(_candidate_targets_by_logical(current)) != set(_candidate_targets_by_logical(base)):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial parent candidate target coverage drift")
    if round_index == 0 and any(value is not None for value in (parent_candidate, parent_state_bytes, parent_decision_bytes, parent_rework_request_bytes)):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Initial editorial job cannot use parent candidate")
    if round_index > 0 and any(value is None for value in (parent_candidate, parent_state_bytes, parent_decision_bytes, parent_rework_request_bytes)):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial rework requires complete parent terminal evidence")
    parent_decision_sha256 = None
    if round_index > 0:
        assert parent_candidate is not None and parent_state_bytes is not None and parent_decision_bytes is not None and parent_rework_request_bytes is not None
        parent_decision_sha256 = _validate_parent_rework(
            parent_candidate, policy, round_index, parent_state_bytes, parent_decision_bytes, parent_rework_request_bytes,
        )
    targets = _candidate_targets_by_logical(current)
    packet_rows = []
    owned_ids = []
    for row in translation_packet.rows:
        target = targets.get((row.identity.logical_id, row.identity.selector_path)) if row.role is ScopeRoleV0.OWNED else None
        packet_rows.append(EditorialPacketRowV0(
            row.identity, row.role, row.source_revision_sha, row.content_type,
            row._payload_bytes, row._constraints_bytes, target,
        ))
        if row.role is ScopeRoleV0.OWNED:
            owned_ids.append(row.stable_id)
    requested = tuple(sorted(owned_ids if requested_ids is None else requested_ids))
    if round_index == 0 and set(requested) != set(owned_ids):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Initial editorial review must cover every owned ID")
    if round_index > 0 and tuple(sorted(current.unresolved_ids)) != requested:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial rework IDs differ from unresolved candidate")
    packet = EditorialPacketV0(target_set.target_locale, round_index, requested, tuple(sorted(packet_rows, key=lambda row: row.stable_id)), translation_packet._relation_bytes)
    packet_bytes = canonical_json_bytes(packet.as_dict())
    identity = {
        "context_digest": context.context_digest, "translation_job_id": translation_job.job_id,
        "translation_decision_sha256": raw_sha256(translation_decision_bytes),
        "translation_state_sha256": raw_sha256(translation_state_bytes),
        "base_target_set_sha256": base.base_target_set_sha256, "parent_candidate_sha256": candidate_raw_sha(current),
        "parent_decision_sha256": parent_decision_sha256, "scope_sha256": translation_job.scope_sha256,
        "source_lock_sha256": translation_job.source_lock_sha256, "reconciliation_sha256": translation_job.reconciliation_sha256,
        "content_config_digest": resolved.content_config_digest, "effective_snapshot_sha256": resolved.effective_snapshot_sha256,
        "module": {"capability": module.capability.value, "module_id": module.module_id, "version": module.version, "digest": module.digest},
        "provider": provider.as_dict(), "target_locale": target_set.target_locale, "packet_sha256": raw_sha256(packet_bytes),
        "policy_sha256": policy.digest, "role_contract_sha256": ROLE_CONTRACT_SHA256,
        "output_contract_sha256": OUTPUT_CONTRACT_SHA256, "budget": budget.as_dict(),
        "round_index": round_index, "max_invocations": 1,
    }
    job_id = "editorial-" + semantic_sha256({"kind": "job", **identity})[:32]
    invocation_id = "invocation-" + semantic_sha256({"job_id": job_id, "provider": provider.as_dict(), "round": round_index})[:32]
    return EditorialJobV0(
        job_id, invocation_id, context.context_digest, translation_job.job_id,
        raw_sha256(translation_decision_bytes), raw_sha256(translation_state_bytes),
        base.base_target_set_sha256, candidate_raw_sha(current),
        parent_decision_sha256, translation_job.scope_sha256, translation_job.source_lock_sha256,
        translation_job.reconciliation_sha256, resolved.content_config_digest, resolved.effective_snapshot_sha256,
        module, provider, target_set.target_locale, raw_sha256(packet_bytes), policy.digest,
        ROLE_CONTRACT_SHA256, OUTPUT_CONTRACT_SHA256, budget, round_index,
    ), packet, current
