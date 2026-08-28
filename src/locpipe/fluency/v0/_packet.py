from __future__ import annotations

from collections.abc import Mapping

from locpipe.contracts.v0 import (
    ContractViolation,
    ErrorCode,
    ModuleDescriptorV0,
    canonical_json_bytes,
    raw_sha256,
    semantic_sha256,
)
from locpipe.editorial.v0 import EditorialCandidateSetV0, editorial_bindings_from_config_v0
from locpipe.kernel.v0.config import ResolvedConfigV0, validate_context_config_binding
from locpipe.kernel.v0.context import ProjectContextV0
from locpipe.translation.v0 import ProviderBindingV0, ProviderBudgetV0

from ._models import (
    FluencyReviewJobV0,
    FluencyReviewPacketRowV0,
    FluencyReviewPacketV0,
    FluencyReviewPlanV0,
    FluencyTargetProjectionV0,
    candidate_raw_sha,
)
from ._serialization import canonical_target_v0


ACCURACY_ROLE_CONTRACT_SHA256 = semantic_sha256({
    "contract": "locpipe.fluency.role/accuracy-editor-bridge/v0",
    "role": "accuracy_editor",
    "writes": "existing_editorial_target_overlay_only",
})
FLUENCY_ROLE_CONTRACT_SHA256 = semantic_sha256({
    "contract": "locpipe.fluency.role/fluency-editor/v0",
    "role": "fluency_editor",
    "reads": "target_side_packet_only",
    "writes": "findings_only",
    "replacement_targets": False,
})
OUTPUT_CONTRACT_SHA256 = semantic_sha256({
    "contract": "locpipe.fluency.provider-output/v0",
    "coverage": "exact_requested_ids",
    "replacement_targets": "forbidden",
})


def _provider_from_row(row: Mapping[str, object], expected_role: str) -> ProviderBindingV0:
    if set(row) != {"role", "provider_id", "version", "config_digest"} or row.get("role") != expected_role:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{expected_role} provider binding fields are invalid")
    return ProviderBindingV0(row["role"], row["provider_id"], row["version"], row["config_digest"])


def fluency_bindings_from_config_v0(
    resolved: ResolvedConfigV0,
) -> tuple[ModuleDescriptorV0, ProviderBindingV0, ProviderBindingV0]:
    if not isinstance(resolved, ResolvedConfigV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Resolved config is invalid")
    editorial = editorial_bindings_from_config_v0(resolved)
    if editorial is None:
        raise ContractViolation(ErrorCode.CAPABILITY_MISSING, "Fluency module/provider binding is missing or ambiguous")
    module, accuracy_provider = editorial
    providers = resolved.get_value("provider_bindings")
    fluency_rows = [row for row in providers if isinstance(row, Mapping) and row.get("role") == "fluency_editor"]
    if len(fluency_rows) != 1:
        raise ContractViolation(ErrorCode.CAPABILITY_MISSING, "Fluency module/provider binding is missing or ambiguous")
    return (
        module,
        accuracy_provider,
        _provider_from_row(fluency_rows[0], "fluency_editor"),
    )


def build_fluency_review_job_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    candidate: EditorialCandidateSetV0,
    projection: FluencyTargetProjectionV0,
    *,
    candidate_authority_sha256: str,
    requested_ids: tuple[str, ...],
    budget: ProviderBudgetV0,
    round_index: int = 0,
    max_correction_rounds: int = 1,
    parent_terminal_sha256: str | None = None,
) -> tuple[FluencyReviewPlanV0, FluencyReviewJobV0, FluencyReviewPacketV0]:
    """Build from a trusted project projection and declared candidate authority.

    The authority SHA is identity-bearing in Slice 1A. Its underlying evidence
    chain is validated by the fluency-owned validation bridge planned for 1D.
    """
    if not isinstance(context, ProjectContextV0) or not isinstance(resolved, ResolvedConfigV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency context or config is invalid")
    if context.config_snapshot_sha256 != resolved.config_snapshot_sha256:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency context config drift")
    validate_context_config_binding(context, resolved)
    if not isinstance(candidate, EditorialCandidateSetV0) or not candidate.ready or candidate.unresolved_ids:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency review requires a ready editorial candidate")
    if not isinstance(projection, FluencyTargetProjectionV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency target projection is invalid")
    if not isinstance(budget, ProviderBudgetV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency provider budget is invalid")
    candidate_sha = candidate_raw_sha(candidate)
    if projection.candidate_sha256 != candidate_sha or projection.target_locale != candidate.target_locale:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency projection candidate drift")
    requested = tuple(requested_ids)
    review_ids = tuple(row.stable_id for row in projection.rows if row.role == "REVIEW")
    if requested != review_ids:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency requested IDs differ from projection review rows")
    target_by_id = {
        canonical_target_v0(canonical_json_bytes(envelope), candidate.target_locale)[0]: canonical_json_bytes(envelope)
        for envelope in candidate.as_dict()["targets"]
    }
    if any(row.stable_id not in target_by_id for row in projection.rows):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency projection target is absent from candidate")
    packet_rows = tuple(
        FluencyReviewPacketRowV0(
            row.stable_id,
            row.role,
            row.profile_ids,
            row.group_ids,
            row.relation_ids,
            row._guidance_bytes,
            target_by_id[row.stable_id],
        )
        for row in projection.rows
    )
    packet = FluencyReviewPacketV0(
        candidate.target_locale,
        candidate_sha,
        projection.digest,
        requested,
        packet_rows,
    )
    module, accuracy_provider, fluency_provider = fluency_bindings_from_config_v0(resolved)
    plan = FluencyReviewPlanV0(
        context.context_digest,
        candidate_sha,
        candidate_authority_sha256,
        projection.digest,
        resolved.content_config_digest,
        resolved.effective_snapshot_sha256,
        module,
        accuracy_provider,
        fluency_provider,
        candidate.target_locale,
        requested,
        ACCURACY_ROLE_CONTRACT_SHA256,
        FLUENCY_ROLE_CONTRACT_SHA256,
        OUTPUT_CONTRACT_SHA256,
        round_index,
        max_correction_rounds,
        parent_terminal_sha256,
    )
    packet_sha = raw_sha256(canonical_json_bytes(packet.as_dict()))
    identity = {
        "plan_sha256": plan.digest,
        "packet_sha256": packet_sha,
        "module": {
            "capability": module.capability.value,
            "module_id": module.module_id,
            "version": module.version,
            "digest": module.digest,
        },
        "provider": fluency_provider.as_dict(),
        "role_contract_sha256": FLUENCY_ROLE_CONTRACT_SHA256,
        "output_contract_sha256": OUTPUT_CONTRACT_SHA256,
        "budget": budget.as_dict(),
        "attempt": 1,
        "max_invocations": 1,
    }
    job_id = "fluency-" + semantic_sha256({"kind": "job", **identity})[:32]
    invocation_id = "invocation-" + semantic_sha256({
        "job_id": job_id,
        "attempt": 1,
        "provider": fluency_provider.as_dict(),
    })[:32]
    return (
        plan,
        FluencyReviewJobV0(
            job_id,
            invocation_id,
            plan.digest,
            packet_sha,
            module,
            fluency_provider,
            FLUENCY_ROLE_CONTRACT_SHA256,
            OUTPUT_CONTRACT_SHA256,
            budget,
        ),
        packet,
    )
