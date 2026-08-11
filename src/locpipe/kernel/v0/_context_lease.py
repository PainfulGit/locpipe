from __future__ import annotations

import secrets
from collections.abc import Callable

from locpipe.contracts.v0 import ContractViolation, ErrorCode

from ._context_models import ProjectContextV0
from ._context_storage import resolve_project_paths
from ._transaction_lease import acquire_write_lease, release_write_lease
from ._transaction_models import WriteLeaseV0, _utc_now
from ._transaction_storage import SyntheticTransactionStoreV0


def acquire_context_write_lease(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    operation_id: str,
    *,
    owner_token_factory: Callable[[], str] = lambda: secrets.token_hex(16),
    clock: Callable[[], str] = _utc_now,
) -> WriteLeaseV0:
    resolve_project_paths(store, context)
    return acquire_write_lease(
        store,
        context.namespace,
        operation_id,
        owner_token_factory=owner_token_factory,
        clock=clock,
    )


def release_context_write_lease(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    lease: WriteLeaseV0,
) -> None:
    resolve_project_paths(store, context)
    if not isinstance(lease, WriteLeaseV0) or lease.namespace != context.namespace:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Lease belongs to a different project context")
    release_write_lease(store, lease)
