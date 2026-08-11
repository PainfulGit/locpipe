from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from locpipe.contracts.v0 import (
    ArtifactHashV0,
    ContractViolation,
    ErrorCategory,
    ErrorCode,
    validate_envelope,
)
from locpipe.contracts.v0.artifacts import (
    has_reparse_component,
    resolve_artifact_root,
    resolve_existing_artifact,
)

from .hashing import sha256_file
from ._transaction_lease import _assert_current_lease
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
from ._transaction_storage import (
    SyntheticTransactionStoreV0,
    _atomic_write,
    _canonical_document,
    _contract_sha,
    _journal_matches_publication,
    _journal_transition,
    _read_object,
    _safe_target,
    _validate_journal,
    _validate_receipt_against_journal,
    inspect_recovery,
)

def _validate_safe_retry(
    store: SyntheticTransactionStoreV0,
    spec: PublicationSpecV0,
    lease: WriteLeaseV0,
    transaction_dir: Path,
    journal: Mapping[str, Any],
) -> None:
    if not _journal_matches_publication(journal, spec, lease):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Safe-retry publication binding drift")
    target = _safe_target(store, spec.namespace, spec.target_path, create_parents=False)
    current_sha = sha256_file(target) if target.exists() else None
    if current_sha != spec.expected_preimage_sha256:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Safe-retry target changed")
    allowed = {"journal.json"}
    if journal["preimage_exists"]:
        allowed.add("preimage.bin")
    actual = {path.name for path in transaction_dir.iterdir()}
    if actual != allowed:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Safe-retry transaction files drift")
    preimage_path = transaction_dir / "preimage.bin"
    if journal["preimage_exists"] and (
        not preimage_path.is_file()
        or preimage_path.is_symlink()
        or sha256_file(preimage_path) != journal["preimage_sha256"]
    ):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Safe-retry preimage drift")
    _assert_current_lease(store, lease)
    staged_publish = target.with_name(f".{target.name}.{lease.owner_token}.staged")
    if staged_publish.exists():
        if (
            not staged_publish.is_file()
            or staged_publish.is_symlink()
            or has_reparse_component(store.target_root(spec.namespace), staged_publish)
        ):
            raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Safe-retry staged sibling drift")
        staged_publish.unlink()


def _load_verified_receipt(
    store: SyntheticTransactionStoreV0,
    spec: PublicationSpecV0,
    lease: WriteLeaseV0,
    journal: dict[str, Any],
) -> PublicationReceiptV0:
    _validate_journal(journal, spec.operation_id)
    if not _journal_matches_publication(journal, spec, lease):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Verified journal binding drift")
    receipt_path = store.transaction_dir(spec.operation_id) / "receipt.json"
    if (
        journal.get("state") != TransactionStateV0.VERIFIED.value
        or not receipt_path.is_file()
        or receipt_path.is_symlink()
        or has_reparse_component(store.root, receipt_path)
    ):
        raise TransactionViolation(TransactionErrorCode.RECOVERY_REQUIRED, "Existing transaction is incomplete")
    envelope = _read_object(receipt_path, "publication receipt")
    expected_contract = _contract_sha(spec, lease)
    if journal.get("publication_contract_sha256") != expected_contract:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Publication contract drift")
    if sha256_file(receipt_path) != journal.get("receipt_sha256"):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Publication receipt drift")
    validate_envelope(envelope, artifact_root=store.target_root(spec.namespace))
    data = envelope["data"]
    if data.get("contract_sha256") != expected_contract or data.get("operation") != spec.operation_id:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Publication receipt identity drift")
    outputs = data.get("outputs")
    if not isinstance(outputs, list) or len(outputs) != 1 or not isinstance(outputs[0], dict):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Publication receipt output drift")
    try:
        output = ArtifactHashV0.from_dict(outputs[0])
    except ContractViolation as error:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Publication receipt output drift") from error
    if output != ArtifactHashV0(spec.target_path, "raw", spec.staged_artifact.sha256):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Publication receipt target drift")
    return PublicationReceiptV0(spec.operation_id, expected_contract, output)


def _validate_single_staged_artifact(root: Path, artifact: Path) -> None:
    expected: set[str] = {artifact.relative_to(root).as_posix()}
    current = artifact.parent
    while current != root:
        expected.add(current.relative_to(root).as_posix())
        current = current.parent
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink() or has_reparse_component(root, path):
            raise ContractViolation(ErrorCode.PATH_ESCAPE, "Staging tree contains a link or reparse point")
        actual.add(path.relative_to(root).as_posix())
    if actual != expected:
        raise ContractViolation(
            ErrorCode.OUTPUT_CONTRACT_VIOLATION,
            "Slice 02 staging must contain exactly one raw file and its parent directories",
        )


def publish_verified_file(
    store: SyntheticTransactionStoreV0,
    spec: PublicationSpecV0,
    lease: WriteLeaseV0,
    staging_root: Path,
    *,
    clock: Callable[[], str] = _utc_now,
    _failure_hook: Callable[[str], None] | None = None,
) -> PublicationReceiptV0:
    if not isinstance(store, SyntheticTransactionStoreV0):
        raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Invalid synthetic store")
    if not isinstance(spec, PublicationSpecV0) or not isinstance(lease, WriteLeaseV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid publication spec or lease")
    if spec.namespace != lease.namespace or spec.operation_id != lease.operation_id:
        raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Lease does not own publication")
    _assert_current_lease(store, lease)
    resolved_staging = resolve_artifact_root(staging_root)
    try:
        resolved_staging.relative_to(store.staging)
    except ValueError as error:
        raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Staging root is outside store") from error
    staged_path = resolve_existing_artifact(resolved_staging, spec.staged_artifact.path)
    _validate_single_staged_artifact(resolved_staging, staged_path)
    if sha256_file(staged_path) != spec.staged_artifact.sha256:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Staged artifact SHA drift", category=ErrorCategory.INTEGRITY)

    transaction_dir = store.transaction_dir(spec.operation_id)
    journal_path = transaction_dir / "journal.json"
    resumed_journal: dict[str, Any] | None = None
    if transaction_dir.exists():
        if (
            not transaction_dir.is_dir()
            or transaction_dir.is_symlink()
            or has_reparse_component(store.root, transaction_dir)
            or not journal_path.is_file()
            or journal_path.is_symlink()
            or has_reparse_component(store.root, journal_path)
        ):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Transaction directory is incomplete")
        journal = _read_object(journal_path, "transaction journal")
        state = _validate_journal(journal, spec.operation_id)
        if state is TransactionStateV0.VERIFIED:
            return _load_verified_receipt(store, spec, lease, journal)
        plan = inspect_recovery(store, spec.operation_id)
        if plan.disposition is RecoveryDispositionV0.SAFE_RETRY:
            _validate_safe_retry(store, spec, lease, transaction_dir, journal)
            resumed_journal = journal
        elif plan.disposition is RecoveryDispositionV0.UNKNOWN:
            raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Existing transaction evidence drift")
        else:
            raise TransactionViolation(TransactionErrorCode.RECOVERY_REQUIRED, "Existing transaction requires recovery")

    target = _safe_target(store, spec.namespace, spec.target_path, create_parents=True)
    if resumed_journal is None:
        preimage_exists = target.exists()
        preimage_sha = sha256_file(target) if preimage_exists else None
        if preimage_sha != spec.expected_preimage_sha256:
            raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Target preimage differs from publication spec")
        transaction_dir.mkdir()
        if preimage_exists:
            _atomic_write(transaction_dir / "preimage.bin", target.read_bytes())
            if sha256_file(transaction_dir / "preimage.bin") != preimage_sha:
                raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Preimage copy drift")

        contract_sha = _contract_sha(spec, lease)
        prepared_at = clock()
        journal = {
            "schema_version": 1,
            "operation_id": spec.operation_id,
            "namespace": spec.namespace.as_dict(),
            "namespace_token": lease.namespace_token,
            "owner_token": lease.owner_token,
            "fencing_epoch": lease.fencing_epoch,
            "target_path": spec.target_path,
            "preimage_exists": preimage_exists,
            "preimage_sha256": preimage_sha,
            "expected_postimage_sha256": spec.staged_artifact.sha256,
            "publication_contract_sha256": contract_sha,
            "receipt_sha256": None,
            "state": TransactionStateV0.PREPARED.value,
            "transitions": [{"state": TransactionStateV0.PREPARED.value, "at": prepared_at}],
        }
        _atomic_write(journal_path, _canonical_document(journal))
        if _failure_hook:
            _failure_hook("AFTER_PREPARED")
    else:
        journal = resumed_journal
        contract_sha = journal["publication_contract_sha256"]
    state = TransactionStateV0(journal["state"])
    if state is TransactionStateV0.PREPARED:
        journal = _journal_transition(journal_path, journal, TransactionStateV0.APPLYING, clock)
        if _failure_hook:
            _failure_hook("AFTER_APPLYING")
    elif state is not TransactionStateV0.APPLYING:
        raise TransactionViolation(TransactionErrorCode.RECOVERY_REQUIRED, "Safe retry state changed")

    staged_publish = target.with_name(f".{target.name}.{lease.owner_token}.staged")
    try:
        with staged_path.open("rb") as source, staged_publish.open("xb") as destination:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        if sha256_file(staged_publish) != spec.staged_artifact.sha256:
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "Staged publish copy drift")
        if _failure_hook:
            _failure_hook("AFTER_STAGED_FSYNC")
        _assert_current_lease(store, lease)
        current_target = _safe_target(store, spec.namespace, spec.target_path, create_parents=False)
        current_sha = sha256_file(current_target) if current_target.exists() else None
        if current_sha != spec.expected_preimage_sha256:
            raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Target changed before atomic replace")
        os.replace(staged_publish, target)
        with target.open("r+b") as stream:
            os.fsync(stream.fileno())
        if _failure_hook:
            _failure_hook("AFTER_REPLACE_BEFORE_APPLIED")
    finally:
        if staged_publish.exists():
            staged_publish.unlink()
    if sha256_file(target) != spec.staged_artifact.sha256:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Published target SHA drift")
    journal = _journal_transition(journal_path, journal, TransactionStateV0.APPLIED, clock)
    if _failure_hook:
        _failure_hook("AFTER_APPLIED")

    receipt = PublicationReceiptV0(
        spec.operation_id,
        contract_sha,
        ArtifactHashV0(spec.target_path, "raw", spec.staged_artifact.sha256),
    )
    envelope = receipt.as_envelope()
    validate_envelope(envelope, artifact_root=store.target_root(spec.namespace))
    receipt_path = transaction_dir / "receipt.json"
    _atomic_write(receipt_path, _canonical_document(envelope))
    receipt_sha = sha256_file(receipt_path)
    journal = dict(journal)
    journal["receipt_sha256"] = receipt_sha
    _atomic_write(journal_path, _canonical_document(journal))
    if _failure_hook:
        _failure_hook("AFTER_RECEIPT_BEFORE_VERIFIED")
    _assert_current_lease(store, lease)
    if sha256_file(target) != spec.staged_artifact.sha256:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Target changed before verification")
    _validate_receipt_against_journal(store, spec.operation_id, transaction_dir, journal)
    journal = _journal_transition(journal_path, journal, TransactionStateV0.VERIFIED, clock)
    if _failure_hook:
        _failure_hook("AFTER_VERIFIED")
    return receipt


def rollback_publication(
    store: SyntheticTransactionStoreV0,
    plan: RecoveryPlanV0,
    lease: WriteLeaseV0,
    *,
    clock: Callable[[], str] = _utc_now,
    _failure_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    if not isinstance(plan, RecoveryPlanV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid recovery plan")
    current_plan = inspect_recovery(store, plan.operation_id)
    if plan != current_plan:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Recovery evidence changed")
    if current_plan.disposition is not RecoveryDispositionV0.ROLLBACK_REQUIRED:
        raise TransactionViolation(TransactionErrorCode.RECOVERY_REQUIRED, "Recovery plan does not permit rollback")
    if plan.operation_id != lease.operation_id:
        raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Lease does not own rollback")
    _assert_current_lease(store, lease)
    transaction_dir = store.transaction_dir(plan.operation_id)
    journal_path = transaction_dir / "journal.json"
    journal = _read_object(journal_path, "transaction journal")
    current = _validate_journal(journal, plan.operation_id)
    if (
        journal["namespace"] != lease.namespace.as_dict()
        or journal["namespace_token"] != lease.namespace_token
        or journal["owner_token"] != lease.owner_token
        or journal["fencing_epoch"] != lease.fencing_epoch
    ):
        raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Lease does not own transaction journal")
    if current not in {
        TransactionStateV0.PREPARED,
        TransactionStateV0.APPLYING,
        TransactionStateV0.APPLIED,
        TransactionStateV0.ROLLBACK_REQUIRED,
    }:
        raise TransactionViolation(TransactionErrorCode.RECOVERY_REQUIRED, "Journal state cannot roll back")
    if current is not TransactionStateV0.ROLLBACK_REQUIRED:
        journal = _journal_transition(journal_path, journal, TransactionStateV0.ROLLBACK_REQUIRED, clock)
    target = _safe_target(store, lease.namespace, journal["target_path"], create_parents=False)
    expected_preimage = journal["preimage_sha256"] if journal["preimage_exists"] else None
    current_target_sha = sha256_file(target) if target.exists() else None
    if current_target_sha not in {expected_preimage, journal["expected_postimage_sha256"]}:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Rollback target changed")
    if current_target_sha == expected_preimage:
        restored_sha = expected_preimage
    elif journal["preimage_exists"]:
        preimage = transaction_dir / "preimage.bin"
        if (
            not preimage.is_file()
            or preimage.is_symlink()
            or has_reparse_component(store.root, preimage)
            or sha256_file(preimage) != journal["preimage_sha256"]
        ):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Recoverable preimage drift")
        rollback_staged = target.with_name(f".{target.name}.{lease.owner_token}.rollback")
        _atomic_write(rollback_staged, preimage.read_bytes())
        _assert_current_lease(store, lease)
        os.replace(rollback_staged, target)
        with target.open("r+b") as stream:
            os.fsync(stream.fileno())
        restored_sha: str | None = sha256_file(target)
    else:
        if target.exists():
            _assert_current_lease(store, lease)
            target.unlink()
        restored_sha = None
    if restored_sha != journal["preimage_sha256"]:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Rollback did not restore exact preimage")
    if _failure_hook:
        _failure_hook("AFTER_ROLLBACK_TARGET")

    receipt_path = transaction_dir / "receipt.json"
    if receipt_path.exists() and (
        not receipt_path.is_file()
        or receipt_path.is_symlink()
        or has_reparse_component(store.root, receipt_path)
    ):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Unsafe receipt during rollback")
    existing_receipt_sha = sha256_file(receipt_path) if receipt_path.is_file() else None
    if journal.get("receipt_sha256") is not None and existing_receipt_sha != journal.get("receipt_sha256"):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Receipt changed during rollback")
    supersession: dict[str, object] = {
        "schema_version": 1,
        "operation_id": plan.operation_id,
        "status": "SUPERSEDED_BY_ROLLBACK",
        "original_receipt_sha256": existing_receipt_sha,
        "restored_sha256": restored_sha,
        "fencing_epoch": lease.fencing_epoch,
    }
    if existing_receipt_sha:
        _atomic_write(transaction_dir / "receipt.superseded.json", _canonical_document(supersession))
    if _failure_hook:
        _failure_hook("AFTER_ROLLBACK_SUPERSESSION")
    journal = dict(journal)
    journal["restored_sha256"] = restored_sha
    journal["supersession_receipt_sha256"] = (
        sha256_file(transaction_dir / "receipt.superseded.json")
        if (transaction_dir / "receipt.superseded.json").exists()
        else None
    )
    _atomic_write(journal_path, _canonical_document(journal))
    if _failure_hook:
        _failure_hook("AFTER_ROLLBACK_EVIDENCE")
    _journal_transition(journal_path, journal, TransactionStateV0.ROLLED_BACK, clock)
    return supersession
