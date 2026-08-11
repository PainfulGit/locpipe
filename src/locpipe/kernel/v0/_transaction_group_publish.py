from __future__ import annotations

import os
import secrets
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from locpipe.contracts.v0 import ArtifactHashV0, ContractViolation, ErrorCategory, ErrorCode, validate_envelope
from locpipe.contracts.v0.artifacts import has_reparse_component, resolve_artifact_root, resolve_existing_artifact

from .hashing import sha256_file
from ._transaction_group_models import (
    GroupRecoveryPlanV0,
    PublicationEntryV0,
    PublicationGroupReceiptV0,
    PublicationGroupSpecV0,
)
from ._transaction_group_storage import (
    GROUP_TRANSACTION_KIND,
    _current_target_rows,
    _group_contract_sha,
    _group_entries_from_journal,
    _group_journal_matches,
    _postimage_rows,
    _preimage_rows,
    _read_group_journal_candidate,
    _target_set_sha,
    _validate_group_journal,
    _validate_group_receipt,
    inspect_group_recovery,
)
from ._transaction_lease import _assert_current_lease
from ._transaction_models import (
    RecoveryDispositionV0,
    TransactionErrorCode,
    TransactionStateV0,
    TransactionViolation,
    WriteLeaseV0,
    _utc_now,
    transition_state,
)
from ._transaction_storage import (
    SyntheticTransactionStoreV0,
    _atomic_write,
    _canonical_document,
    _journal_transition,
    _read_object,
    _safe_target,
)


def _validate_group_staging(root: Path, entries: Sequence[PublicationEntryV0]) -> list[Path]:
    artifacts = [resolve_existing_artifact(root, entry.staged_artifact.path) for entry in entries]
    expected: set[str] = set()
    for artifact in artifacts:
        expected.add(artifact.relative_to(root).as_posix())
        current = artifact.parent
        while current != root:
            expected.add(current.relative_to(root).as_posix())
            current = current.parent
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink() or has_reparse_component(root, path):
            raise ContractViolation(ErrorCode.PATH_ESCAPE, "Group staging contains a link or reparse point")
        actual.add(path.relative_to(root).as_posix())
    if actual != expected:
        raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Group staging must contain exactly declared files")
    for artifact, entry in zip(artifacts, entries):
        if sha256_file(artifact) != entry.staged_artifact.sha256:
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "Group staged artifact SHA drift", category=ErrorCategory.INTEGRITY)
    return artifacts


def _staged_sibling(target: Path, lease: WriteLeaseV0, index: int) -> Path:
    return target.with_name(f".{target.name}.{lease.owner_token}.{index:04d}.staged")


def _rollback_sibling(target: Path, lease: WriteLeaseV0, index: int) -> Path:
    return target.with_name(f".{target.name}.{lease.owner_token}.{index:04d}.rollback")


def _group_atomic_write(
    path: Path, payload: bytes, failure_hook: Callable[[str], None] | None, label: str
) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if failure_hook:
            failure_hook(f"AFTER_ATOMIC_TEMP_FSYNC:{label}")
        os.replace(temporary, path)
        with path.open("r+b") as stream:
            os.fsync(stream.fileno())
    finally:
        if temporary.exists():
            temporary.unlink()


def _group_journal_transition(
    path: Path, journal: dict[str, Any], target: TransactionStateV0, clock: Callable[[], str],
    failure_hook: Callable[[str], None] | None, label: str,
) -> dict[str, Any]:
    transition_state(TransactionStateV0(journal["state"]), target)
    updated = dict(journal)
    updated["state"] = target.value
    updated["transitions"] = [*journal["transitions"], {"state": target.value, "at": clock()}]
    _group_atomic_write(path, _canonical_document(updated), failure_hook, label)
    return updated


def _validate_group_safe_retry(
    store: SyntheticTransactionStoreV0,
    spec: PublicationGroupSpecV0,
    lease: WriteLeaseV0,
    transaction_dir: Path,
    journal: Mapping[str, Any],
    journal_source: Path,
    journal_temporaries: Sequence[Path],
) -> None:
    if not _group_journal_matches(journal, spec, lease):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Safe-retry group binding drift")
    if _current_target_rows(store, spec.namespace, spec.entries) != _preimage_rows(spec.entries):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Safe-retry group targets changed")
    journal_path = transaction_dir / "journal.json"
    expected_files = {"preimages", *(path.name for path in journal_temporaries)}
    if journal_path.exists():
        expected_files.add("journal.json")
    if {path.name for path in transaction_dir.iterdir()} != expected_files:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Safe-retry group files drift")
    preimages = transaction_dir / "preimages"
    if not preimages.is_dir() or preimages.is_symlink() or has_reparse_component(store.root, preimages):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Safe-retry preimage directory drift")
    expected_snapshots = {
        f"{index:04d}.bin"
        for index, entry in enumerate(spec.entries)
        if entry.expected_preimage_sha256 is not None
    }
    if {path.name for path in preimages.iterdir()} != expected_snapshots:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Safe-retry preimage set drift")
    for index, entry in enumerate(spec.entries):
        if entry.expected_preimage_sha256 is None:
            continue
        snapshot = preimages / f"{index:04d}.bin"
        if (
            not snapshot.is_file()
            or snapshot.is_symlink()
            or has_reparse_component(store.root, snapshot)
            or sha256_file(snapshot) != entry.expected_preimage_sha256
        ):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Safe-retry group preimage drift")
    _assert_current_lease(store, lease)
    if journal_source != journal_path:
        os.replace(journal_source, journal_path)
        with journal_path.open("r+b") as stream:
            os.fsync(stream.fileno())
    for temporary in journal_temporaries:
        if temporary.exists():
            _assert_current_lease(store, lease)
            temporary.unlink()
    for index, entry in enumerate(spec.entries):
        target = _safe_target(store, spec.namespace, entry.staged_artifact.path, create_parents=False)
        sibling = _staged_sibling(target, lease, index)
        if sibling.exists():
            if not sibling.is_file() or sibling.is_symlink() or has_reparse_component(store.root, sibling):
                raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Safe-retry staged sibling drift")
            sibling.unlink()


def _load_verified_group_receipt(
    store: SyntheticTransactionStoreV0,
    spec: PublicationGroupSpecV0,
    lease: WriteLeaseV0,
    journal: dict[str, Any],
) -> PublicationGroupReceiptV0:
    _validate_group_journal(journal, spec.operation_id)
    if not _group_journal_matches(journal, spec, lease):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Verified group binding drift")
    if journal.get("state") != TransactionStateV0.VERIFIED.value:
        raise TransactionViolation(TransactionErrorCode.RECOVERY_REQUIRED, "Existing group is incomplete")
    transaction_dir = store.transaction_dir(spec.operation_id)
    _validate_group_receipt(store, spec.operation_id, transaction_dir, journal)
    if _current_target_rows(store, spec.namespace, spec.entries) != _postimage_rows(spec.entries):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Verified group targets drift")
    return PublicationGroupReceiptV0(
        spec.operation_id,
        _group_contract_sha(spec, lease),
        tuple(entry.staged_artifact for entry in spec.entries),
    )


def publish_verified_group(
    store: SyntheticTransactionStoreV0,
    spec: PublicationGroupSpecV0,
    lease: WriteLeaseV0,
    staging_root: Path,
    *,
    clock: Callable[[], str] = _utc_now,
    _failure_hook: Callable[[str], None] | None = None,
) -> PublicationGroupReceiptV0:
    if not isinstance(store, SyntheticTransactionStoreV0):
        raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Invalid synthetic store")
    if not isinstance(spec, PublicationGroupSpecV0) or not isinstance(lease, WriteLeaseV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group spec or lease")
    if spec.namespace != lease.namespace or spec.operation_id != lease.operation_id:
        raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Lease does not own group publication")
    _assert_current_lease(store, lease)
    resolved_staging = resolve_artifact_root(staging_root)
    try:
        resolved_staging.relative_to(store.staging)
    except ValueError as error:
        raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Group staging is outside store") from error
    staged_paths = _validate_group_staging(resolved_staging, spec.entries)

    transaction_dir = store.transaction_dir(spec.operation_id)
    journal_path = transaction_dir / "journal.json"
    resumed_journal: dict[str, Any] | None = None
    if transaction_dir.exists():
        if (
            not transaction_dir.is_dir()
            or transaction_dir.is_symlink()
            or has_reparse_component(store.root, transaction_dir)
        ):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group transaction directory is incomplete")
        journal, journal_source, journal_temporaries = _read_group_journal_candidate(store, spec.operation_id)
        state = _validate_group_journal(journal, spec.operation_id)
        if state is TransactionStateV0.VERIFIED:
            return _load_verified_group_receipt(store, spec, lease, journal)
        plan = inspect_group_recovery(store, spec.operation_id)
        if plan.disposition is RecoveryDispositionV0.SAFE_RETRY:
            _validate_group_safe_retry(
                store,
                spec,
                lease,
                transaction_dir,
                journal,
                journal_source,
                journal_temporaries,
            )
            resumed_journal = journal
        elif plan.disposition is RecoveryDispositionV0.UNKNOWN:
            raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Existing group evidence drift")
        else:
            raise TransactionViolation(TransactionErrorCode.RECOVERY_REQUIRED, "Existing group requires recovery")

    targets = [
        _safe_target(store, spec.namespace, entry.staged_artifact.path, create_parents=True)
        for entry in spec.entries
    ]
    if resumed_journal is None:
        current = _current_target_rows(store, spec.namespace, spec.entries)
        if current != _preimage_rows(spec.entries):
            raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group preimages differ from spec")
        transaction_dir.mkdir()
        preimages = transaction_dir / "preimages"
        preimages.mkdir()
        artifact_rows: list[dict[str, object]] = []
        for index, (entry, target) in enumerate(zip(spec.entries, targets)):
            snapshot_relative = f"preimages/{index:04d}.bin" if target.exists() else None
            if target.exists():
                snapshot = transaction_dir / snapshot_relative  # type: ignore[arg-type]
                _atomic_write(snapshot, target.read_bytes())
                if sha256_file(snapshot) != entry.expected_preimage_sha256:
                    raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group preimage copy drift")
            artifact_rows.append({
                "path": entry.staged_artifact.path,
                "preimage_exists": target.exists(),
                "preimage_sha256": entry.expected_preimage_sha256,
                "expected_postimage_sha256": entry.staged_artifact.sha256,
                "preimage_snapshot": snapshot_relative,
            })
        contract_sha = _group_contract_sha(spec, lease)
        prepared_at = clock()
        journal = {
            "schema_version": 1,
            "transaction_kind": GROUP_TRANSACTION_KIND,
            "operation_id": spec.operation_id,
            "namespace": spec.namespace.as_dict(),
            "namespace_token": lease.namespace_token,
            "owner_token": lease.owner_token,
            "fencing_epoch": lease.fencing_epoch,
            "artifacts": artifact_rows,
            "publication_contract_sha256": contract_sha,
            "receipt_sha256": None,
            "state": TransactionStateV0.PREPARED.value,
            "transitions": [{"state": TransactionStateV0.PREPARED.value, "at": prepared_at}],
        }
        _group_atomic_write(
            journal_path,
            _canonical_document(journal),
            _failure_hook,
            "GROUP_PREPARED_JOURNAL",
        )
        if _failure_hook:
            _failure_hook("AFTER_GROUP_PREPARED")
    else:
        journal = resumed_journal
        contract_sha = journal["publication_contract_sha256"]
    state = TransactionStateV0(journal["state"])
    if state is TransactionStateV0.PREPARED:
        journal = _group_journal_transition(
            journal_path,
            journal,
            TransactionStateV0.APPLYING,
            clock,
            _failure_hook,
            "GROUP_APPLYING_JOURNAL",
        )
        if _failure_hook:
            _failure_hook("AFTER_GROUP_APPLYING")
    elif state is not TransactionStateV0.APPLYING:
        raise TransactionViolation(TransactionErrorCode.RECOVERY_REQUIRED, "Safe-retry group state changed")

    for index, (entry, staged_path, target) in enumerate(zip(spec.entries, staged_paths, targets)):
        sibling = _staged_sibling(target, lease, index)
        try:
            with staged_path.open("rb") as source, sibling.open("xb") as destination:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            if sha256_file(sibling) != entry.staged_artifact.sha256:
                raise ContractViolation(ErrorCode.HASH_MISMATCH, "Group staged publish copy drift")
            if _failure_hook:
                _failure_hook(f"AFTER_GROUP_ARTIFACT_STAGED:{index + 1:04d}")
            _assert_current_lease(store, lease)
            expected = [
                {"path": candidate.staged_artifact.path, "sha256": (
                    candidate.staged_artifact.sha256 if candidate_index < index
                    else candidate.expected_preimage_sha256
                )}
                for candidate_index, candidate in enumerate(spec.entries)
            ]
            if _current_target_rows(store, spec.namespace, spec.entries) != expected:
                raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group changed before atomic replace")
            os.replace(sibling, target)
            with target.open("r+b") as stream:
                os.fsync(stream.fileno())
            if _failure_hook:
                _failure_hook(f"AFTER_GROUP_ARTIFACT_REPLACED:{index + 1:04d}")
        finally:
            if sibling.exists():
                sibling.unlink()
    if _current_target_rows(store, spec.namespace, spec.entries) != _postimage_rows(spec.entries):
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Published group target SHA drift")
    journal = _journal_transition(journal_path, journal, TransactionStateV0.APPLIED, clock)
    if _failure_hook:
        _failure_hook("AFTER_GROUP_APPLIED")

    receipt = PublicationGroupReceiptV0(
        spec.operation_id,
        contract_sha,
        tuple(entry.staged_artifact for entry in spec.entries),
    )
    envelope = receipt.as_envelope()
    validate_envelope(envelope, artifact_root=store.target_root(spec.namespace))
    receipt_path = transaction_dir / "receipt.json"
    _atomic_write(receipt_path, _canonical_document(envelope))
    if _failure_hook:
        _failure_hook("AFTER_GROUP_RECEIPT_WRITE")
    journal = dict(journal)
    journal["receipt_sha256"] = sha256_file(receipt_path)
    _atomic_write(journal_path, _canonical_document(journal))
    if _failure_hook:
        _failure_hook("AFTER_GROUP_RECEIPT_BEFORE_VERIFIED")
    _assert_current_lease(store, lease)
    if _current_target_rows(store, spec.namespace, spec.entries) != _postimage_rows(spec.entries):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group changed before verification")
    _validate_group_receipt(store, spec.operation_id, transaction_dir, journal)
    _journal_transition(journal_path, journal, TransactionStateV0.VERIFIED, clock)
    if _failure_hook:
        _failure_hook("AFTER_GROUP_VERIFIED")
    return receipt


def rollback_publication_group(
    store: SyntheticTransactionStoreV0,
    plan: GroupRecoveryPlanV0,
    lease: WriteLeaseV0,
    *,
    clock: Callable[[], str] = _utc_now,
    _failure_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    if not isinstance(plan, GroupRecoveryPlanV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group recovery plan")
    current_plan = inspect_group_recovery(store, plan.operation_id)
    if plan != current_plan:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group recovery evidence changed")
    if current_plan.disposition is not RecoveryDispositionV0.ROLLBACK_REQUIRED:
        raise TransactionViolation(TransactionErrorCode.RECOVERY_REQUIRED, "Group plan does not permit rollback")
    if plan.operation_id != lease.operation_id:
        raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Lease does not own group rollback")
    _assert_current_lease(store, lease)
    transaction_dir = store.transaction_dir(plan.operation_id)
    journal_path = transaction_dir / "journal.json"
    journal = _read_object(journal_path, "group transaction journal")
    state = _validate_group_journal(journal, plan.operation_id)
    if (
        journal["namespace"] != lease.namespace.as_dict()
        or journal["namespace_token"] != lease.namespace_token
        or journal["owner_token"] != lease.owner_token
        or journal["fencing_epoch"] != lease.fencing_epoch
    ):
        raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Lease does not own group journal")
    if state not in {
        TransactionStateV0.PREPARED,
        TransactionStateV0.APPLYING,
        TransactionStateV0.APPLIED,
        TransactionStateV0.ROLLBACK_REQUIRED,
    }:
        raise TransactionViolation(TransactionErrorCode.RECOVERY_REQUIRED, "Group journal cannot roll back")
    if state is not TransactionStateV0.ROLLBACK_REQUIRED:
        journal = _journal_transition(journal_path, journal, TransactionStateV0.ROLLBACK_REQUIRED, clock)
    entries = _group_entries_from_journal(journal)
    current = _current_target_rows(store, lease.namespace, entries)
    if any(
        row["sha256"] not in {entry.expected_preimage_sha256, entry.staged_artifact.sha256}
        for row, entry in zip(current, entries)
    ):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group rollback target changed")

    for index, entry in enumerate(entries):
        target = _safe_target(store, lease.namespace, entry.staged_artifact.path, create_parents=False)
        sibling = _staged_sibling(target, lease, index)
        if sibling.exists():
            if not sibling.is_file() or sibling.is_symlink() or has_reparse_component(store.root, sibling):
                raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Unsafe staged sibling during rollback")
            _assert_current_lease(store, lease)
            sibling.unlink()

    for index in reversed(range(len(entries))):
        entry = entries[index]
        target = _safe_target(store, lease.namespace, entry.staged_artifact.path, create_parents=False)
        current_sha = sha256_file(target) if target.exists() else None
        if current_sha == entry.staged_artifact.sha256:
            if entry.expected_preimage_sha256 is None:
                _assert_current_lease(store, lease)
                target.unlink()
            else:
                snapshot = transaction_dir / "preimages" / f"{index:04d}.bin"
                if (
                    not snapshot.is_file()
                    or snapshot.is_symlink()
                    or has_reparse_component(store.root, snapshot)
                    or sha256_file(snapshot) != entry.expected_preimage_sha256
                ):
                    raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group rollback preimage drift")
                sibling = _rollback_sibling(target, lease, index)
                _atomic_write(sibling, snapshot.read_bytes())
                _assert_current_lease(store, lease)
                os.replace(sibling, target)
                with target.open("r+b") as stream:
                    os.fsync(stream.fileno())
        elif current_sha != entry.expected_preimage_sha256:
            raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group rollback target drift")
        if _failure_hook:
            _failure_hook(f"AFTER_GROUP_ROLLBACK_ARTIFACT:{index + 1:04d}")
    restored = _current_target_rows(store, lease.namespace, entries)
    if restored != _preimage_rows(entries):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group rollback did not restore preimages")
    restored_set_sha = _target_set_sha(restored)
    if _failure_hook:
        _failure_hook("AFTER_GROUP_ROLLBACK_TARGETS")

    receipt_path = transaction_dir / "receipt.json"
    if receipt_path.exists() and (
        not receipt_path.is_file() or receipt_path.is_symlink() or has_reparse_component(store.root, receipt_path)
    ):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Unsafe group receipt during rollback")
    receipt_sha = sha256_file(receipt_path) if receipt_path.is_file() else None
    if journal.get("receipt_sha256") is not None and receipt_sha != journal.get("receipt_sha256"):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group receipt changed during rollback")
    supersession: dict[str, object] = {
        "schema_version": 1,
        "transaction_kind": GROUP_TRANSACTION_KIND,
        "operation_id": plan.operation_id,
        "status": "SUPERSEDED_BY_ROLLBACK",
        "original_receipt_sha256": receipt_sha,
        "restored_set_sha256": restored_set_sha,
        "fencing_epoch": lease.fencing_epoch,
    }
    if receipt_sha:
        _atomic_write(transaction_dir / "receipt.superseded.json", _canonical_document(supersession))
    if _failure_hook:
        _failure_hook("AFTER_GROUP_ROLLBACK_SUPERSESSION")
    journal = dict(journal)
    journal["restored_set_sha256"] = restored_set_sha
    journal["supersession_receipt_sha256"] = (
        sha256_file(transaction_dir / "receipt.superseded.json")
        if (transaction_dir / "receipt.superseded.json").exists()
        else None
    )
    _atomic_write(journal_path, _canonical_document(journal))
    if _failure_hook:
        _failure_hook("AFTER_GROUP_ROLLBACK_EVIDENCE")
    _journal_transition(journal_path, journal, TransactionStateV0.ROLLED_BACK, clock)
    return supersession
