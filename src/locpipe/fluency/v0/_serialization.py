from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from locpipe.contracts.v0 import (
    BranchIdentity,
    ContractViolation,
    ErrorCode,
    canonical_json_bytes,
    canonical_value_bytes,
    display_id,
    parse_canonical_json,
    raw_sha256,
    strict_loads,
    validate_envelope,
)
from locpipe.contracts.v0.profiles import SHA256_RE


GUIDANCE_ORIGINS = frozenset({"target_policy", "target_profile"})
GUIDANCE_KINDS = frozenset({"layout", "style", "terminology", "voice"})


def _canonical_mapping(payload: bytes, fields: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(payload, bytes):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be canonical bytes")
    value = parse_canonical_json(payload)
    if canonical_json_bytes(value) != payload:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} is not canonical")
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} fields are invalid")
    return value


def canonical_fluency_provider_output_v0(payload: bytes) -> Mapping[str, Any]:
    value = _canonical_mapping(payload, {
        "contract", "job_id", "invocation_id", "plan_sha256", "packet_sha256",
        "provider", "output_contract_sha256", "reviews",
    }, "Fluency provider output")
    if value["contract"] != "locpipe.fluency.provider-output/v0":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency provider output contract is invalid")
    provider = value["provider"]
    if not isinstance(provider, Mapping) or set(provider) != {"role", "provider_id", "version", "config_digest"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency provider binding fields are invalid")
    reviews = value["reviews"]
    if not isinstance(reviews, list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency provider reviews must be a list")
    for review in reviews:
        if not isinstance(review, Mapping) or set(review) != {"stable_id", "outcome", "findings"}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency provider review fields are invalid")
        findings = review["findings"]
        if not isinstance(findings, list):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency provider findings must be a list")
        for finding in findings:
            if not isinstance(finding, Mapping) or set(finding) != {"category", "diagnostic_note"}:
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency provider finding fields are invalid")
    return value


def canonical_fluency_submission_receipt_v0(payload: bytes) -> Mapping[str, Any]:
    value = _canonical_mapping(payload, {
        "contract", "job_id", "invocation_id", "provider", "provider_request_id",
        "plan_sha256", "packet_sha256", "role_contract_sha256",
        "output_contract_sha256", "raw_output_sha256",
    }, "Fluency submission receipt")
    if value["contract"] != "locpipe.fluency.submission-receipt/v0":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency submission receipt contract is invalid")
    provider = value["provider"]
    if not isinstance(provider, Mapping) or set(provider) != {"role", "provider_id", "version", "config_digest"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency receipt provider fields are invalid")
    return value


def parse_fluency_correction_trigger_v0(payload: bytes):
    value = _canonical_mapping(payload, {
        "contract", "plan_sha256", "fluency_job_sha256", "fluency_packet_sha256",
        "candidate_sha256", "candidate_authority_sha256", "content_config_digest",
        "effective_snapshot_sha256", "accuracy_provider_config_digest",
        "fluency_provider_config_digest", "raw_output_sha256", "submission_sha256",
        "decision_sha256", "state_sha256", "current_fluency_round",
        "max_fluency_correction_rounds", "parent_editorial_round", "next_editorial_round",
        "editorial_policy_sha256", "entries",
    }, "Fluency correction trigger")
    if value["contract"] != "locpipe.fluency.correction-trigger/v0":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction trigger contract is invalid")
    entries = value["entries"]
    if not isinstance(entries, list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction trigger entries must be a list")
    from ._models import (
        FluencyCorrectionTriggerEntryV0,
        FluencyCorrectionTriggerV0,
        FluencyFindingCategoryV0,
        FluencyFindingV0,
    )

    parsed_entries = []
    try:
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != {
                "target_stable_id", "target_sha256", "source_identity",
                "source_revision_sha256", "content_type", "findings",
            }:
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction trigger entry fields are invalid")
            findings = entry["findings"]
            if not isinstance(findings, list):
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction trigger findings must be a list")
            parsed_findings = []
            for finding in findings:
                if not isinstance(finding, Mapping) or set(finding) != {"category", "diagnostic_note"}:
                    raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction trigger finding fields are invalid")
                parsed_findings.append(FluencyFindingV0(
                    FluencyFindingCategoryV0(finding["category"]),
                    finding["diagnostic_note"],
                ))
            parsed_entries.append(FluencyCorrectionTriggerEntryV0(
                entry["target_stable_id"],
                entry["target_sha256"],
                BranchIdentity.from_dict(entry["source_identity"]),
                entry["source_revision_sha256"],
                entry["content_type"],
                tuple(parsed_findings),
            ))
        trigger = FluencyCorrectionTriggerV0(
            value["plan_sha256"],
            value["fluency_job_sha256"],
            value["fluency_packet_sha256"],
            value["candidate_sha256"],
            value["candidate_authority_sha256"],
            value["content_config_digest"],
            value["effective_snapshot_sha256"],
            value["accuracy_provider_config_digest"],
            value["fluency_provider_config_digest"],
            value["raw_output_sha256"],
            value["submission_sha256"],
            value["decision_sha256"],
            value["state_sha256"],
            value["current_fluency_round"],
            value["max_fluency_correction_rounds"],
            value["parent_editorial_round"],
            value["next_editorial_round"],
            value["editorial_policy_sha256"],
            tuple(parsed_entries),
        )
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, ContractViolation):
            raise
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction trigger value is invalid") from error
    if canonical_json_bytes(trigger.as_dict()) != payload:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction trigger projection drift")
    return trigger


def canonical_target_v0(payload: bytes, target_locale: str | None) -> tuple[str, Mapping[str, Any]]:
    if not isinstance(payload, bytes):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency target must be canonical bytes")
    envelope = parse_canonical_json(payload)
    if canonical_json_bytes(envelope) != payload:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency target is not canonical")
    validate_envelope(envelope)
    if envelope.get("kind") != "target_branch" or not isinstance(envelope.get("data"), Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency target must be target_branch")
    identity = BranchIdentity.from_dict(envelope["data"]["identity"])
    if target_locale is not None and identity.locale != target_locale:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency target locale drift")
    return display_id(identity), envelope


def canonical_guidance_block_v0(payload: bytes) -> Mapping[str, Any]:
    if not isinstance(payload, bytes):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency guidance must be canonical bytes")
    value = strict_loads(payload)
    if canonical_value_bytes(value) != payload or not isinstance(value, Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency guidance is not canonical")
    if set(value) != {"guidance_kind", "origin", "payload", "payload_sha256"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency guidance fields are invalid")
    if value["origin"] not in GUIDANCE_ORIGINS:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency guidance origin is not target-side")
    if value["guidance_kind"] not in GUIDANCE_KINDS:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency guidance kind is invalid")
    if not isinstance(value["payload_sha256"], str) or SHA256_RE.fullmatch(value["payload_sha256"]) is None:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency guidance payload SHA is invalid")
    if raw_sha256(canonical_value_bytes(value["payload"])) != value["payload_sha256"]:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Fluency guidance payload SHA drift")
    return value
