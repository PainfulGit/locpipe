from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from locpipe.contracts.v0 import ContractViolation, ErrorCategory, ErrorCode

from ._context_models import ProjectContextV0
from ._context_transaction_storage import (
    bind_context_transaction,
    context_transaction_store,
    validate_context_transaction_binding,
)
from ._transaction_group_models import (
    GroupRecoveryPlanV0,
    PublicationGroupReceiptV0,
    PublicationGroupSpecV0,
)
from ._transaction_group_publish import publish_verified_group, rollback_publication_group
from ._transaction_group_storage import inspect_group_recovery, _validate_group_terminal_for_release
from ._transaction_lease import release_write_lease
from ._transaction_models import (
    PublicationReceiptV0,
    PublicationSpecV0,
    RecoveryDispositionV0,
    RecoveryPlanV0,
    TransactionErrorCode,
    TransactionStateV0,
    TransactionViolation,
    WriteLeaseV0,
    _utc_now,
)
from ._transaction_publish import publish_verified_file, rollback_publication
from ._transaction_storage import (
    SyntheticTransactionStoreV0,
    _read_object,
    _validate_journal,
    inspect_recovery,
)


def _binding_mismatch(detail: str) -> ContractViolation:
    return ContractViolation(
        ErrorCode.BINDING_MISMATCH,
        detail,
        category=ErrorCategory.CONFIGURATION,
    )


def _validate_owner(
    context: ProjectContextV0,
    operation_id: str,
    lease: WriteLeaseV0,
) -> None:
    if not isinstance(lease, WriteLeaseV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid context publication lease")
    if lease.namespace != context.namespace or lease.operation_id != operation_id:
        raise _binding_mismatch("Lease belongs to a different project context operation")


def create_context_staging(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    operation_id: str,
) -> Path:
    return bind_context_transaction(store, context, operation_id).create_staging(operation_id)


def _validate_parent_transaction_terminal(
    store: SyntheticTransactionStoreV0,
    lease: WriteLeaseV0,
) -> None:
    transaction_dir = store.transaction_dir(lease.operation_id)
    if not transaction_dir.exists():
        return
    journal = _read_object(transaction_dir / "journal.json", "transaction journal")
    if journal.get("transaction_kind") == "raw_file_group_v0":
        _validate_group_terminal_for_release(store, lease, journal)
        return
    plan = inspect_recovery(store, lease.operation_id)
    if plan.disposition is not RecoveryDispositionV0.NO_ACTION or plan.journal_state not in {
        TransactionStateV0.VERIFIED,
        TransactionStateV0.ROLLED_BACK,
    }:
        raise TransactionViolation(
            TransactionErrorCode.RECOVERY_REQUIRED,
            "Cannot release context lease with incomplete parent transaction",
        )
    _validate_journal(journal, lease.operation_id)
    if (
        journal["namespace"] != lease.namespace.as_dict()
        or journal["namespace_token"] != lease.namespace_token
        or journal["owner_token"] != lease.owner_token
        or journal["fencing_epoch"] != lease.fencing_epoch
    ):
        raise TransactionViolation(
            TransactionErrorCode.FENCE_STALE,
            "Lease does not own terminal parent transaction",
        )


def release_context_write_lease(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    lease: WriteLeaseV0,
) -> None:
    if not isinstance(lease, WriteLeaseV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid context publication lease")
    _validate_owner(context, lease.operation_id, lease)
    _validate_parent_transaction_terminal(store, lease)
    initial_view = context_transaction_store(store, context)
    binding = initial_view.transactions / f"{lease.operation_id}.context.json"
    view = validate_context_transaction_binding(
        store,
        context,
        lease.operation_id,
        required=binding.exists() or initial_view.transaction_dir(lease.operation_id).exists(),
    )
    release_write_lease(view, lease)


def publish_context_file(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    spec: PublicationSpecV0,
    lease: WriteLeaseV0,
    *,
    clock: Callable[[], str] = _utc_now,
    _failure_hook: Callable[[str], None] | None = None,
) -> PublicationReceiptV0:
    if not isinstance(spec, PublicationSpecV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid context publication spec")
    if spec.namespace != context.namespace:
        raise _binding_mismatch("Publication spec belongs to a different project context")
    _validate_owner(context, spec.operation_id, lease)
    view = validate_context_transaction_binding(store, context, spec.operation_id, required=True)
    return publish_verified_file(
        view,
        spec,
        lease,
        view.staging / spec.operation_id,
        clock=clock,
        _failure_hook=_failure_hook,
    )


def inspect_context_file_recovery(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    operation_id: str,
) -> RecoveryPlanV0:
    return inspect_recovery(
        validate_context_transaction_binding(store, context, operation_id, required=True),
        operation_id,
    )


def rollback_context_file(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    plan: RecoveryPlanV0,
    lease: WriteLeaseV0,
    *,
    clock: Callable[[], str] = _utc_now,
    _failure_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    if not isinstance(plan, RecoveryPlanV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid context recovery plan")
    _validate_owner(context, plan.operation_id, lease)
    return rollback_publication(
        validate_context_transaction_binding(store, context, plan.operation_id, required=True),
        plan,
        lease,
        clock=clock,
        _failure_hook=_failure_hook,
    )


def publish_context_group(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    spec: PublicationGroupSpecV0,
    lease: WriteLeaseV0,
    *,
    clock: Callable[[], str] = _utc_now,
    _failure_hook: Callable[[str], None] | None = None,
) -> PublicationGroupReceiptV0:
    if not isinstance(spec, PublicationGroupSpecV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid context group spec")
    if spec.namespace != context.namespace:
        raise _binding_mismatch("Group spec belongs to a different project context")
    _validate_owner(context, spec.operation_id, lease)
    view = validate_context_transaction_binding(store, context, spec.operation_id, required=True)
    return publish_verified_group(
        view,
        spec,
        lease,
        view.staging / spec.operation_id,
        clock=clock,
        _failure_hook=_failure_hook,
    )


def inspect_context_group_recovery(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    operation_id: str,
) -> GroupRecoveryPlanV0:
    return inspect_group_recovery(
        validate_context_transaction_binding(store, context, operation_id, required=True),
        operation_id,
    )


def rollback_context_group(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    plan: GroupRecoveryPlanV0,
    lease: WriteLeaseV0,
    *,
    clock: Callable[[], str] = _utc_now,
    _failure_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    if not isinstance(plan, GroupRecoveryPlanV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid context group recovery plan")
    _validate_owner(context, plan.operation_id, lease)
    return rollback_publication_group(
        validate_context_transaction_binding(store, context, plan.operation_id, required=True),
        plan,
        lease,
        clock=clock,
        _failure_hook=_failure_hook,
    )
