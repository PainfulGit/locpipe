from __future__ import annotations

from collections.abc import Mapping

from locpipe.contracts.v0 import (
    ContractViolation,
    ErrorCode,
    canonical_json_bytes,
    raw_sha256,
)
from locpipe.translation.v0 import ProviderBindingV0

from ._models import (
    FluencyDecisionEntryV0,
    FluencyDecisionStatusV0,
    FluencyDecisionV0,
    FluencyFindingCategoryV0,
    FluencyFindingV0,
    FluencyReviewJobV0,
    FluencyReviewOutcomeV0,
    FluencyReviewPacketV0,
    FluencyReviewPlanV0,
    FluencyStateV0,
    FluencySubmissionReceiptV0,
)
from ._serialization import (
    canonical_fluency_provider_output_v0,
    canonical_fluency_submission_receipt_v0,
)
from ._packet import (
    ACCURACY_ROLE_CONTRACT_SHA256,
    FLUENCY_ROLE_CONTRACT_SHA256,
    OUTPUT_CONTRACT_SHA256,
)


def _provider(value: object) -> ProviderBindingV0:
    if not isinstance(value, Mapping) or set(value) != {"role", "provider_id", "version", "config_digest"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency provider binding fields are invalid")
    return ProviderBindingV0(
        value["role"], value["provider_id"], value["version"], value["config_digest"],
    )


def _validate_authority(
    plan: FluencyReviewPlanV0,
    job: FluencyReviewJobV0,
    packet: FluencyReviewPacketV0,
) -> None:
    if not isinstance(plan, FluencyReviewPlanV0) or not isinstance(job, FluencyReviewJobV0) or not isinstance(packet, FluencyReviewPacketV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency acceptance authority is invalid")
    packet_sha = raw_sha256(canonical_json_bytes(packet.as_dict()))
    if job.plan_sha256 != plan.digest or job.packet_sha256 != packet_sha:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency job plan or packet drift")
    if (
        job.module != plan.module
        or job.provider != plan.fluency_provider
        or plan.accuracy_role_contract_sha256 != ACCURACY_ROLE_CONTRACT_SHA256
        or plan.fluency_role_contract_sha256 != FLUENCY_ROLE_CONTRACT_SHA256
        or plan.output_contract_sha256 != OUTPUT_CONTRACT_SHA256
        or job.role_contract_sha256 != plan.fluency_role_contract_sha256
        or job.output_contract_sha256 != plan.output_contract_sha256
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency job provider or contract drift")
    if (
        packet.candidate_sha256 != plan.candidate_sha256
        or packet.projection_sha256 != plan.projection_sha256
        or packet.requested_ids != plan.requested_ids
        or packet.target_locale != plan.target_locale
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency packet authority drift")


def _parse_output(
    raw_output: bytes,
    plan: FluencyReviewPlanV0,
    job: FluencyReviewJobV0,
    packet: FluencyReviewPacketV0,
) -> tuple[FluencyDecisionEntryV0, ...]:
    value = canonical_fluency_provider_output_v0(raw_output)
    provider = _provider(value["provider"])
    if (
        value["job_id"] != job.job_id
        or value["invocation_id"] != job.invocation_id
        or value["plan_sha256"] != plan.digest
        or value["packet_sha256"] != job.packet_sha256
        or provider != job.provider
        or value["output_contract_sha256"] != job.output_contract_sha256
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency provider output is stale or foreign")
    entries: list[FluencyDecisionEntryV0] = []
    try:
        for review in value["reviews"]:
            outcome = FluencyReviewOutcomeV0(review["outcome"])
            findings = tuple(
                FluencyFindingV0(
                    FluencyFindingCategoryV0(finding["category"]),
                    finding["diagnostic_note"],
                )
                for finding in review["findings"]
            )
            entries.append(FluencyDecisionEntryV0(review["stable_id"], outcome, findings))
    except (TypeError, ValueError) as error:
        if isinstance(error, ContractViolation):
            raise
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency provider review value is invalid") from error
    parsed = tuple(entries)
    keys = tuple(row.stable_id for row in parsed)
    if keys != plan.requested_ids or keys != packet.requested_ids:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency provider coverage differs from requested IDs")
    return parsed


def bind_fluency_submission_receipt_v0(
    plan: FluencyReviewPlanV0,
    job: FluencyReviewJobV0,
    packet: FluencyReviewPacketV0,
    raw_output: bytes,
    *,
    provider_request_id: str,
) -> FluencySubmissionReceiptV0:
    """Derive checked-side receipt authority from expected inputs and raw bytes."""
    _validate_authority(plan, job, packet)
    _parse_output(raw_output, plan, job, packet)
    return FluencySubmissionReceiptV0(
        job.job_id,
        job.invocation_id,
        job.provider,
        provider_request_id,
        plan.digest,
        job.packet_sha256,
        job.role_contract_sha256,
        job.output_contract_sha256,
        raw_sha256(raw_output),
    )


def fluency_submission_digest_v0(receipt: FluencySubmissionReceiptV0) -> str:
    if not isinstance(receipt, FluencySubmissionReceiptV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency submission receipt is invalid")
    return raw_sha256(canonical_json_bytes(receipt.as_dict()))


def _parse_receipt(payload: bytes) -> FluencySubmissionReceiptV0:
    value = canonical_fluency_submission_receipt_v0(payload)
    return FluencySubmissionReceiptV0(
        value["job_id"],
        value["invocation_id"],
        _provider(value["provider"]),
        value["provider_request_id"],
        value["plan_sha256"],
        value["packet_sha256"],
        value["role_contract_sha256"],
        value["output_contract_sha256"],
        value["raw_output_sha256"],
    )


def accept_fluency_submission_v0(
    plan: FluencyReviewPlanV0,
    job: FluencyReviewJobV0,
    packet: FluencyReviewPacketV0,
    receipt_bytes: bytes,
    raw_output: bytes,
) -> tuple[FluencyDecisionV0, FluencyStateV0]:
    """Pure strict acceptance; creates no correction, validation or filesystem artifact."""
    _validate_authority(plan, job, packet)
    receipt = _parse_receipt(receipt_bytes)
    expected = bind_fluency_submission_receipt_v0(
        plan,
        job,
        packet,
        raw_output,
        provider_request_id=receipt.provider_request_id,
    )
    if receipt != expected or canonical_json_bytes(receipt.as_dict()) != receipt_bytes:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency submission receipt is forged or drifted")
    entries = _parse_output(raw_output, plan, job, packet)
    correction_ids = tuple(row.stable_id for row in entries if row.findings)
    status = (
        FluencyDecisionStatusV0.CORRECTION_REQUIRED
        if correction_ids
        else FluencyDecisionStatusV0.FLUENCY_VERIFIED
    )
    raw_output_sha = raw_sha256(raw_output)
    submission_sha = fluency_submission_digest_v0(receipt)
    decision = FluencyDecisionV0(
        job.job_id,
        job.invocation_id,
        plan.digest,
        job.packet_sha256,
        plan.candidate_sha256,
        plan.content_config_digest,
        job.provider.config_digest,
        raw_output_sha,
        submission_sha,
        status,
        entries,
        correction_ids,
    )
    state = FluencyStateV0(
        job.job_id,
        job.invocation_id,
        plan.digest,
        job.packet_sha256,
        plan.candidate_sha256,
        plan.content_config_digest,
        job.provider.config_digest,
        raw_output_sha,
        submission_sha,
        decision.digest,
        status,
    )
    return decision, state
