from __future__ import annotations

from collections.abc import Mapping

from locpipe.contracts.v0 import ContractViolation, ErrorCode, canonical_json_bytes, parse_canonical_json
from locpipe.translation.v0 import ProviderBindingV0

from ._evidence import EditorialStateV0, EditorialSubmissionReceiptV0
from ._models import EditorialCandidateSetV0, EditorialJobStatusV0


def _object(payload: bytes, fields: set[str], name: str) -> Mapping[str, object]:
    value = parse_canonical_json(payload)
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} fields are invalid")
    return value


def parse_editorial_submission_receipt_v0(payload: bytes) -> EditorialSubmissionReceiptV0:
    value = _object(payload, {
        "contract", "job_id", "invocation_id", "provider", "provider_request_id",
        "packet_sha256", "output_contract_sha256", "raw_output_sha256",
    }, "Editorial submission receipt")
    if value["contract"] != "locpipe.editorial.submission-receipt/v0" or not isinstance(value["provider"], Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial submission receipt contract is invalid")
    provider = value["provider"]
    if set(provider) != {"role", "provider_id", "version", "config_digest"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial submission provider fields are invalid")
    return EditorialSubmissionReceiptV0(
        value["job_id"], value["invocation_id"],
        ProviderBindingV0(provider["role"], provider["provider_id"], provider["version"], provider["config_digest"]),
        value["provider_request_id"], value["packet_sha256"], value["output_contract_sha256"], value["raw_output_sha256"],
    )


def parse_editorial_state_v0(payload: bytes) -> EditorialStateV0:
    value = _object(payload, {
        "contract", "job_id", "invocation_id", "status", "selected_submission_sha256",
        "decision_set_sha256", "overlay_sha256", "candidate_sha256", "rework_request_sha256",
    }, "Editorial state")
    if value["contract"] != "locpipe.editorial.state/v0":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial state contract is invalid")
    try:
        status = EditorialJobStatusV0(value["status"])
    except (TypeError, ValueError) as error:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial state status is invalid") from error
    return EditorialStateV0(
        value["job_id"], value["invocation_id"], status, value["selected_submission_sha256"],
        value["decision_set_sha256"], value["overlay_sha256"], value["candidate_sha256"], value["rework_request_sha256"],
    )


def parse_editorial_candidate_v0(payload: bytes) -> EditorialCandidateSetV0:
    value = _object(payload, {
        "contract", "job_id", "target_locale", "ready", "disposition", "base_target_set_sha256",
        "parent_candidate_sha256", "overlay_sha256s", "unresolved_ids", "targets",
    }, "Editorial candidate")
    if value["contract"] != "locpipe.editorial.candidate-set/v0" or not isinstance(value["targets"], list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial candidate contract is invalid")
    return EditorialCandidateSetV0(
        value["job_id"], value["target_locale"], value["ready"], value["disposition"],
        value["base_target_set_sha256"], value["parent_candidate_sha256"], tuple(value["overlay_sha256s"]),
        tuple(value["unresolved_ids"]), tuple(canonical_json_bytes(row) for row in value["targets"]),
    )
