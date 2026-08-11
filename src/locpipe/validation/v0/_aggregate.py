from __future__ import annotations

from collections.abc import Mapping

from locpipe.content.v0 import FrozenScopeV0
from locpipe.contracts.v0 import ContractViolation, ErrorCode, canonical_json_bytes, raw_sha256
from locpipe.kernel.v0.transactions import PublicationGroupReceiptV0
from locpipe.kernel.v0.context import ProjectContextV0
from locpipe.kernel.v0.transactions import SyntheticTransactionStoreV0

from ._handler import content_locale_receipt_v0
from ._models import ContentLocaleReceiptV0, ContentValidationJobV0, ContentVerificationSetV0


def finalize_content_verified_v0(
    scope: FrozenScopeV0,
    locale_receipts: tuple[ContentLocaleReceiptV0, ...],
    *,
    validation_evidence: tuple[
        tuple[
            ContentValidationJobV0, bytes, bytes, bytes, Mapping[str, object],
            PublicationGroupReceiptV0, SyntheticTransactionStoreV0, ProjectContextV0,
        ], ...
    ],
) -> tuple[ContentVerificationSetV0, bytes]:
    rows = tuple(sorted(locale_receipts, key=lambda row: row.target_locale))
    if tuple(row.target_locale for row in rows) != scope.target_locales:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Locale receipts do not exactly cover frozen target locales")
    if not rows:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Content verification requires locale receipts")
    rebuilt = tuple(sorted(
        (
            content_locale_receipt_v0(
                job, report_bytes, state_bytes, rework_bytes,
                store=store,
                context=context,
                operation_result=operation_result,
                validation_publication_receipt=publication_receipt,
            )
            for job, report_bytes, state_bytes, rework_bytes, operation_result, publication_receipt, store, context
            in validation_evidence
        ),
        key=lambda row: row.target_locale,
    ))
    if rebuilt != rows or len(rebuilt) != len(validation_evidence):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Locale receipts lack exact verified validation evidence")
    first = rows[0]
    expected = (
        first.context_digest,
        first.config_snapshot_sha256,
        first.content_config_digest,
        first.scope_sha256,
        first.source_lock_sha256,
        first.reconciliation_sha256,
    )
    if first.scope_sha256 != raw_sha256(canonical_json_bytes(scope.scope_dict())):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Locale receipt scope differs from frozen scope")
    for row in rows:
        actual = (
            row.context_digest,
            row.config_snapshot_sha256,
            row.content_config_digest,
            row.scope_sha256,
            row.source_lock_sha256,
            row.reconciliation_sha256,
        )
        if actual != expected:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Locale receipt authority drift")
    verification = ContentVerificationSetV0(*expected, rows)
    verification_bytes = canonical_json_bytes(verification.as_dict())
    state = canonical_json_bytes({
        "contract": "locpipe.validation.content-state/v0",
        "context_digest": first.context_digest,
        "scope_sha256": first.scope_sha256,
        "verification_set_sha256": raw_sha256(verification_bytes),
        "state": "CONTENT_VERIFIED",
    })
    return verification, state
