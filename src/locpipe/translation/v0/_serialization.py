from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from locpipe.content.v0 import (
    ReconciliationEventV0,
    ReconciliationStateV0,
    SourceReconciliationV0,
    TargetValidityStateV0,
    TargetValidityV0,
)
from locpipe.contracts.v0 import BranchIdentity, ContractViolation, ErrorCode, parse_canonical_json

from ._models import (
    ProviderBindingV0,
    ProviderBudgetV0,
    ProviderSubmissionReceiptV0,
    TranslationJobStatusV0,
    TranslationJobV0,
    TranslationStateV0,
)


def _mapping(payload: bytes, fields: set[str], name: str) -> Mapping[str, Any]:
    value = parse_canonical_json(payload)
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} fields are invalid")
    return value


def _provider(value: object) -> ProviderBindingV0:
    if not isinstance(value, Mapping) or set(value) != {"role", "provider_id", "version", "config_digest"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Provider binding fields are invalid")
    return ProviderBindingV0(value["role"], value["provider_id"], value["version"], value["config_digest"])


def parse_translation_job_v0(payload: bytes) -> TranslationJobV0:
    value = _mapping(payload, {
        "contract", "job_id", "invocation_id", "context_digest", "scope_sha256",
        "source_lock_sha256", "reconciliation_sha256", "content_config_digest",
        "effective_snapshot_sha256", "provider", "target_locale", "packet_sha256",
        "role_contract_sha256", "output_contract_sha256", "budget", "attempt",
        "max_invocations",
    }, "Translation job")
    if value["contract"] != "locpipe.translation.job/v0":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation job contract is invalid")
    budget = value["budget"]
    if not isinstance(budget, Mapping) or set(budget) != {"max_seconds", "max_tokens"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Provider budget fields are invalid")
    return TranslationJobV0(
        value["job_id"], value["invocation_id"], value["context_digest"], value["scope_sha256"],
        value["source_lock_sha256"], value["reconciliation_sha256"], value["content_config_digest"],
        value["effective_snapshot_sha256"], _provider(value["provider"]), value["target_locale"],
        value["packet_sha256"], value["role_contract_sha256"], value["output_contract_sha256"],
        ProviderBudgetV0(budget["max_seconds"], budget["max_tokens"]), value["attempt"], value["max_invocations"],
    )


def parse_submission_receipt_v0(payload: bytes) -> ProviderSubmissionReceiptV0:
    value = _mapping(payload, {
        "contract", "job_id", "invocation_id", "provider", "provider_request_id",
        "packet_sha256", "output_contract_sha256", "raw_output_sha256",
    }, "Provider submission receipt")
    if value["contract"] != "locpipe.translation.submission-receipt/v0":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Submission receipt contract is invalid")
    return ProviderSubmissionReceiptV0(
        value["job_id"], value["invocation_id"], _provider(value["provider"]),
        value["provider_request_id"], value["packet_sha256"], value["output_contract_sha256"],
        value["raw_output_sha256"],
    )


def parse_translation_state_v0(payload: bytes) -> TranslationStateV0:
    value = _mapping(payload, {
        "contract", "job_id", "invocation_id", "status", "selected_submission_sha256",
        "decision_sha256", "target_set_sha256",
    }, "Translation state")
    if value["contract"] != "locpipe.translation.state/v0":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation state contract is invalid")
    try:
        status = TranslationJobStatusV0(value["status"])
    except (TypeError, ValueError) as error:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation state status is invalid") from error
    return TranslationStateV0(
        value["job_id"], value["invocation_id"], status, value["selected_submission_sha256"],
        value["decision_sha256"], value["target_set_sha256"],
    )


def parse_reconciliation_v0(payload: bytes) -> SourceReconciliationV0:
    value = _mapping(payload, {
        "contract", "previous_corpus_digest", "current_corpus_digest", "events", "tombstones",
        "target_validity", "summary",
    }, "Source reconciliation")
    if value["contract"] != "locpipe.content.reconciliation/v0":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source reconciliation contract is invalid")
    if not isinstance(value["events"], list) or not isinstance(value["tombstones"], list) or not isinstance(value["target_validity"], list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source reconciliation collections are invalid")
    events = []
    for row in value["events"]:
        if not isinstance(row, Mapping) or set(row) != {"state", "old_ids", "new_ids"}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Reconciliation event is invalid")
        try:
            state = ReconciliationStateV0(row["state"])
        except (TypeError, ValueError) as error:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Reconciliation event state is invalid") from error
        events.append(ReconciliationEventV0(state, tuple(row["old_ids"]), tuple(row["new_ids"])))
    validity = []
    for row in value["target_validity"]:
        if not isinstance(row, Mapping) or set(row) != {"target_id", "state", "invalid_source_ids"}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target validity row is invalid")
        try:
            state = TargetValidityStateV0(row["state"])
        except (TypeError, ValueError) as error:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target validity state is invalid") from error
        validity.append(TargetValidityV0(row["target_id"], state, tuple(row["invalid_source_ids"])))
    parsed = SourceReconciliationV0(
        value["previous_corpus_digest"], value["current_corpus_digest"], tuple(events),
        tuple(value["tombstones"]), tuple(validity),
    )
    if parsed.as_dict() != dict(value):
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Reconciliation summary or ordering drift")
    return parsed
