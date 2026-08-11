from __future__ import annotations

import os
from pathlib import Path

from locpipe.contracts.v0 import ContractViolation, ErrorCategory, ErrorCode
from locpipe.contracts.v0.artifacts import has_reparse_component

from ._context_models import ProjectContextV0, ProjectPathsV0
from ._context_storage import resolve_project_paths
from ._transaction_models import NamespaceV0
from ._transaction_storage import (
    SyntheticTransactionStoreV0,
    _assert_store_layout,
    _canonical_document,
    _read_object,
)


def _binding_mismatch(detail: str) -> ContractViolation:
    return ContractViolation(
        ErrorCode.BINDING_MISMATCH,
        detail,
        category=ErrorCategory.CONFIGURATION,
    )


class _ContextTransactionStoreV0(SyntheticTransactionStoreV0):
    """Private path view that reuses the existing transaction implementation."""

    def __init__(
        self,
        parent: SyntheticTransactionStoreV0,
        context: ProjectContextV0,
        paths: ProjectPathsV0,
    ) -> None:
        self.root = parent.root
        self.targets = paths.outputs_root
        self.staging = paths.staging_root
        self.transactions = paths.transactions_root
        self.locks = parent.locks
        self.epochs = parent.epochs
        self._context = context
        _assert_store_layout(self)

    def target_root(self, namespace: NamespaceV0, *, create: bool = False) -> Path:
        if not isinstance(namespace, NamespaceV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid target namespace")
        if namespace != self._context.namespace:
            raise _binding_mismatch("Publication namespace belongs to a different project context")
        _assert_store_layout(self)
        if (
            not self.targets.is_dir()
            or self.targets.is_symlink()
            or has_reparse_component(self.root, self.targets)
        ):
            raise ContractViolation(ErrorCode.PATH_ESCAPE, "Unsafe project context output root")
        return self.targets


def context_transaction_store(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
) -> _ContextTransactionStoreV0:
    if not isinstance(store, SyntheticTransactionStoreV0) or not isinstance(context, ProjectContextV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid project context binding")
    paths = resolve_project_paths(store, context)
    return _ContextTransactionStoreV0(store, context, paths)


def _binding_path(view: _ContextTransactionStoreV0, operation_id: str) -> Path:
    view.transaction_dir(operation_id)
    return view.transactions / f"{operation_id}.context.json"


def _binding_payload(context: ProjectContextV0, operation_id: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "context_transaction_binding_v0",
        "operation_id": operation_id,
        "namespace": context.namespace.as_dict(),
        "namespace_token": context.namespace.token,
        "context_digest": context.context_digest,
    }


def _validate_binding_file(
    view: _ContextTransactionStoreV0,
    context: ProjectContextV0,
    operation_id: str,
    path: Path,
) -> None:
    if (
        not path.is_file()
        or path.is_symlink()
        or has_reparse_component(view.root, path)
    ):
        raise _binding_mismatch("Context transaction binding is missing or unsafe")
    try:
        value = _read_object(path, "context transaction binding")
    except Exception as error:
        raise _binding_mismatch("Context transaction binding is malformed") from error
    if value != _binding_payload(context, operation_id):
        raise _binding_mismatch("Context transaction binding drift")


def bind_context_transaction(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    operation_id: str,
) -> _ContextTransactionStoreV0:
    view = context_transaction_store(store, context)
    path = _binding_path(view, operation_id)
    payload = _canonical_document(_binding_payload(context, operation_id))
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        _validate_binding_file(view, context, operation_id, path)
        return view
    try:
        remaining = memoryview(payload)
        while remaining:
            remaining = remaining[os.write(descriptor, remaining) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _validate_binding_file(view, context, operation_id, path)
    return view


def validate_context_transaction_binding(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    operation_id: str,
    *,
    required: bool,
) -> _ContextTransactionStoreV0:
    view = context_transaction_store(store, context)
    path = _binding_path(view, operation_id)
    transaction_exists = view.transaction_dir(operation_id).exists()
    if not path.exists():
        if required or transaction_exists:
            raise _binding_mismatch("Context transaction binding is missing")
        return view
    _validate_binding_file(view, context, operation_id, path)
    return view
