from __future__ import annotations

import os
import secrets
from collections.abc import Callable
from pathlib import Path

from locpipe.contracts.v0 import ContractViolation, ErrorCode
from locpipe.contracts.v0.artifacts import has_reparse_component

from ._transaction_models import (
    NamespaceV0,
    OPERATION_RE,
    RecoveryDispositionV0,
    TransactionErrorCode,
    TransactionStateV0,
    TransactionViolation,
    WriteLeaseV0,
    _utc_now,
)
from ._transaction_storage import (
    SyntheticTransactionStoreV0,
    _assert_store_layout,
    _atomic_write,
    _canonical_document,
    _exact_keys,
    _read_object,
    _validate_journal,
    inspect_recovery,
)

def _lease_paths(store: SyntheticTransactionStoreV0, namespace: NamespaceV0) -> tuple[Path, Path]:
    return (
        store.locks / f"{namespace.token}.json",
        store.epochs / f"{namespace.token}.txt",
    )


def acquire_write_lease(
    store: SyntheticTransactionStoreV0,
    namespace: NamespaceV0,
    operation_id: str,
    *,
    owner_token_factory: Callable[[], str] = lambda: secrets.token_hex(16),
    clock: Callable[[], str] = _utc_now,
) -> WriteLeaseV0:
    if not isinstance(store, SyntheticTransactionStoreV0) or not isinstance(namespace, NamespaceV0):
        raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Invalid lease store or namespace")
    if not isinstance(operation_id, str) or not OPERATION_RE.fullmatch(operation_id):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid operation ID")
    _assert_store_layout(store)
    lock_path, epoch_path = _lease_paths(store, namespace)
    wrote_lock = False
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as error:
        raise TransactionViolation(TransactionErrorCode.WRITER_LOCKED, "Namespace already has a writer") from error
    try:
        epoch = 1
        if epoch_path.exists():
            try:
                epoch = int(epoch_path.read_text(encoding="ascii")) + 1
            except (OSError, ValueError) as error:
                raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Fencing epoch is corrupt") from error
        _atomic_write(epoch_path, f"{epoch}\n".encode("ascii"))
        lease = WriteLeaseV0(namespace, namespace.token, owner_token_factory(), operation_id, epoch)
        record = {**lease.as_dict(), "acquired_at": clock(), "schema_version": 1}
        os.write(descriptor, _canonical_document(record))
        os.fsync(descriptor)
        wrote_lock = True
        return lease
    except Exception:
        if not wrote_lock:
            try:
                lock_path.unlink()
            except OSError:
                pass
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _assert_current_lease(store: SyntheticTransactionStoreV0, lease: WriteLeaseV0) -> None:
    _assert_store_layout(store)
    lock_path, epoch_path = _lease_paths(store, lease.namespace)
    if (
        not lock_path.is_file()
        or lock_path.is_symlink()
        or has_reparse_component(store.root, lock_path)
        or not epoch_path.is_file()
        or epoch_path.is_symlink()
        or has_reparse_component(store.root, epoch_path)
    ):
        raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Writer lease is missing")
    record = _read_object(lock_path, "writer lease")
    _exact_keys(
        record,
        {"namespace", "namespace_token", "owner_token", "operation_id", "fencing_epoch", "acquired_at", "schema_version"},
        set(),
        "writer lease",
    )
    if record.get("schema_version") != 1 or not isinstance(record.get("acquired_at"), str):
        raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Writer lease record is malformed")
    expected = lease.as_dict()
    if any(record.get(key) != value for key, value in expected.items()):
        raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Writer lease owner or namespace changed")
    try:
        epoch = int(epoch_path.read_text(encoding="ascii"))
    except (OSError, ValueError) as error:
        raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Fencing epoch is corrupt") from error
    if epoch != lease.fencing_epoch:
        raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Writer fencing epoch is stale")


def release_write_lease(store: SyntheticTransactionStoreV0, lease: WriteLeaseV0) -> None:
    _assert_current_lease(store, lease)
    transaction_dir = store.transaction_dir(lease.operation_id)
    if transaction_dir.exists():
        journal = _read_object(transaction_dir / "journal.json", "transaction journal")
        if journal.get("transaction_kind") == "raw_file_group_v0":
            from ._transaction_group_storage import _validate_group_terminal_for_release

            _validate_group_terminal_for_release(store, lease, journal)
        else:
            plan = inspect_recovery(store, lease.operation_id)
            if plan.disposition is not RecoveryDispositionV0.NO_ACTION or plan.journal_state not in {
                TransactionStateV0.VERIFIED,
                TransactionStateV0.ROLLED_BACK,
            }:
                raise TransactionViolation(TransactionErrorCode.RECOVERY_REQUIRED, "Cannot release lease with incomplete transaction")
            _validate_journal(journal, lease.operation_id)
            if (
                journal["namespace"] != lease.namespace.as_dict()
                or journal["namespace_token"] != lease.namespace_token
                or journal["owner_token"] != lease.owner_token
                or journal["fencing_epoch"] != lease.fencing_epoch
            ):
                raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Lease does not own terminal transaction")
    lock_path, _ = _lease_paths(store, lease.namespace)
    lock_path.unlink()
