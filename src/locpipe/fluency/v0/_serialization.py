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
