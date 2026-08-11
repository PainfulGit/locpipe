from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from locpipe.contracts.v0 import ArtifactHashV0, ContractViolation, semantic_sha256, validate_envelope
from locpipe.contracts.v0.artifacts import has_reparse_component, validate_relative_posix_path

from .hashing import sha256_file
from ._transaction_group_models import (
    GroupRecoveryPlanV0,
    PublicationEntryV0,
    PublicationGroupReceiptV0,
    PublicationGroupSpecV0,
)
from ._transaction_models import (
    NamespaceV0,
    RecoveryDispositionV0,
    TransactionErrorCode,
    TransactionStateV0,
    TransactionViolation,
    WriteLeaseV0,
    _valid_sha,
    transition_state,
)
from ._transaction_storage import (
    SyntheticTransactionStoreV0,
    _assert_store_layout,
    _exact_keys,
    _read_object,
    _safe_target,
)


GROUP_TRANSACTION_KIND = "raw_file_group_v0"
_GROUP_JOURNAL_REQUIRED = {
    "schema_version",
    "transaction_kind",
    "operation_id",
    "namespace",
    "namespace_token",
    "owner_token",
    "fencing_epoch",
    "artifacts",
    "publication_contract_sha256",
    "receipt_sha256",
    "state",
    "transitions",
}
_GROUP_JOURNAL_OPTIONAL = {"restored_set_sha256", "supersession_receipt_sha256"}
_GROUP_ARTIFACT_KEYS = {
    "path",
    "preimage_exists",
    "preimage_sha256",
    "expected_postimage_sha256",
    "preimage_snapshot",
}


def _atomic_temporary_paths(store: SyntheticTransactionStoreV0, path: Path) -> tuple[Path, ...]:
    prefix = f".{path.name}."
    candidates: list[Path] = []
    for candidate in path.parent.iterdir():
        name = candidate.name
        if not name.startswith(prefix) or not name.endswith(".tmp"):
            continue
        token = name[len(prefix) : -4]
        if not re.fullmatch(r"[0-9a-f]{16}", token):
            continue
        if (
            not candidate.is_file()
            or candidate.is_symlink()
            or has_reparse_component(store.root, candidate)
        ):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Unsafe atomic temporary file")
        candidates.append(candidate)
    return tuple(sorted(candidates, key=lambda candidate: candidate.name))


def _group_contract_sha(spec: PublicationGroupSpecV0, lease: WriteLeaseV0) -> str:
    return semantic_sha256({"publication_group_spec": spec.as_dict(), "write_lease": lease.as_dict()})


def _namespace_from_journal(journal: Mapping[str, Any]) -> NamespaceV0:
    value = journal["namespace"]
    if not isinstance(value, dict):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group namespace is malformed")
    _exact_keys(value, {"workspace_id", "project_id", "release_id"}, set(), "group namespace")
    try:
        return NamespaceV0(value["workspace_id"], value["project_id"], value["release_id"])
    except (ContractViolation, TypeError) as error:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group namespace is malformed") from error


def _group_entries_from_journal(journal: Mapping[str, Any]) -> tuple[PublicationEntryV0, ...]:
    rows = journal["artifacts"]
    if not isinstance(rows, list) or not 2 <= len(rows) <= 64:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group artifacts are malformed")
    entries: list[PublicationEntryV0] = []
    paths: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group artifact is malformed")
        _exact_keys(row, _GROUP_ARTIFACT_KEYS, set(), "group artifact")
        path = row["path"]
        validate_relative_posix_path(path)
        preimage_exists = row["preimage_exists"]
        preimage_sha = row["preimage_sha256"]
        postimage_sha = row["expected_postimage_sha256"]
        snapshot = row["preimage_snapshot"]
        if not isinstance(preimage_exists, bool) or preimage_exists != (preimage_sha is not None):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group preimage evidence conflicts")
        if not _valid_sha(preimage_sha, optional=True) or not _valid_sha(postimage_sha):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group artifact SHA is malformed")
        expected_snapshot = f"preimages/{index:04d}.bin" if preimage_exists else None
        if snapshot != expected_snapshot:
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group preimage snapshot binding drift")
        try:
            entries.append(PublicationEntryV0(ArtifactHashV0(path, "raw", postimage_sha), preimage_sha))
        except ContractViolation as error:
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group artifact contract drift") from error
        paths.append(path)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group artifact ordering drift")
    for index, left in enumerate(paths):
        if any(right.startswith(left + "/") for right in paths[index + 1 :]):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group artifact path overlap")
    return tuple(entries)


def _group_contract_sha_from_journal(journal: Mapping[str, Any]) -> str:
    namespace = _namespace_from_journal(journal)
    lease = WriteLeaseV0(
        namespace,
        journal["namespace_token"],
        journal["owner_token"],
        journal["operation_id"],
        journal["fencing_epoch"],
    )
    spec = PublicationGroupSpecV0(namespace, journal["operation_id"], _group_entries_from_journal(journal))
    return _group_contract_sha(spec, lease)


def _validate_group_journal(journal: Mapping[str, Any], operation_id: str) -> TransactionStateV0:
    _exact_keys(journal, _GROUP_JOURNAL_REQUIRED, _GROUP_JOURNAL_OPTIONAL, "group transaction journal")
    if (
        journal["schema_version"] != 1
        or journal["transaction_kind"] != GROUP_TRANSACTION_KIND
        or journal["operation_id"] != operation_id
    ):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group journal identity drift")
    namespace = _namespace_from_journal(journal)
    if journal["namespace_token"] != namespace.token:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group namespace token drift")
    try:
        WriteLeaseV0(
            namespace,
            journal["namespace_token"],
            journal["owner_token"],
            journal["operation_id"],
            journal["fencing_epoch"],
        )
    except (ContractViolation, TransactionViolation, TypeError) as error:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group lease evidence is malformed") from error
    _group_entries_from_journal(journal)
    for key in ("receipt_sha256", "restored_set_sha256", "supersession_receipt_sha256"):
        if key in journal and not _valid_sha(journal[key], optional=True):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, f"Group journal {key} is malformed")
    if not _valid_sha(journal["publication_contract_sha256"]):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group contract SHA is malformed")
    try:
        state = TransactionStateV0(journal["state"])
    except (TypeError, ValueError) as error:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Unknown group journal state") from error
    transitions = journal["transitions"]
    if not isinstance(transitions, list) or not transitions:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group transitions are malformed")
    previous: TransactionStateV0 | None = None
    for index, row in enumerate(transitions):
        if not isinstance(row, dict):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group transition is malformed")
        _exact_keys(row, {"state", "at"}, set(), "group transition")
        if not isinstance(row["at"], str) or not row["at"]:
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group transition time is malformed")
        try:
            current = TransactionStateV0(row["state"])
        except (TypeError, ValueError) as error:
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group transition state is unknown") from error
        if index == 0:
            if current is not TransactionStateV0.PREPARED:
                raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group journal must begin PREPARED")
        else:
            transition_state(previous, current)  # type: ignore[arg-type]
        previous = current
    if previous is not state:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group state does not match transitions")
    if state is TransactionStateV0.VERIFIED and journal["receipt_sha256"] is None:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Verified group lacks receipt SHA")
    if state is TransactionStateV0.ROLLED_BACK and "restored_set_sha256" not in journal:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Rolled-back group lacks restoration evidence")
    if journal["publication_contract_sha256"] != _group_contract_sha_from_journal(journal):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group publication contract drift")
    return state


def _group_journal_matches(
    journal: Mapping[str, Any], spec: PublicationGroupSpecV0, lease: WriteLeaseV0
) -> bool:
    return (
        journal.get("operation_id") == spec.operation_id
        and journal.get("namespace") == spec.namespace.as_dict()
        and journal.get("namespace_token") == lease.namespace_token
        and journal.get("owner_token") == lease.owner_token
        and journal.get("fencing_epoch") == lease.fencing_epoch
        and journal.get("publication_contract_sha256") == _group_contract_sha(spec, lease)
        and [entry.as_dict() for entry in _group_entries_from_journal(journal)]
        == [entry.as_dict() for entry in spec.entries]
    )


def _read_group_journal_candidate(
    store: SyntheticTransactionStoreV0,
    operation_id: str,
) -> tuple[dict[str, Any], Path, tuple[Path, ...]]:
    transaction_dir = store.transaction_dir(operation_id)
    journal_path = transaction_dir / "journal.json"
    temporary_paths = _atomic_temporary_paths(store, journal_path)
    if journal_path.exists():
        if (
            not journal_path.is_file()
            or journal_path.is_symlink()
            or has_reparse_component(store.root, journal_path)
        ):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Unsafe group journal")
        return _read_object(journal_path, "group transaction journal"), journal_path, temporary_paths
    if not temporary_paths:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Group journal is missing")
    payloads = {candidate.read_bytes() for candidate in temporary_paths}
    if len(payloads) != 1:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Atomic group journal candidates conflict")
    source = temporary_paths[0]
    return _read_object(source, "group transaction journal candidate"), source, temporary_paths


def _current_target_rows(
    store: SyntheticTransactionStoreV0,
    namespace: NamespaceV0,
    entries: Sequence[PublicationEntryV0],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for entry in entries:
        target = _safe_target(store, namespace, entry.staged_artifact.path, create_parents=False)
        rows.append({
            "path": entry.staged_artifact.path,
            "sha256": sha256_file(target) if target.exists() else None,
        })
    return rows


def _target_set_sha(rows: Sequence[Mapping[str, object]]) -> str:
    return semantic_sha256(list(rows))


def _preimage_rows(entries: Sequence[PublicationEntryV0]) -> list[dict[str, object]]:
    return [
        {"path": entry.staged_artifact.path, "sha256": entry.expected_preimage_sha256}
        for entry in entries
    ]


def _postimage_rows(entries: Sequence[PublicationEntryV0]) -> list[dict[str, object]]:
    return [
        {"path": entry.staged_artifact.path, "sha256": entry.staged_artifact.sha256}
        for entry in entries
    ]


def _validate_group_receipt(
    store: SyntheticTransactionStoreV0,
    operation_id: str,
    transaction_dir: Path,
    journal: Mapping[str, Any],
) -> None:
    namespace = _namespace_from_journal(journal)
    entries = _group_entries_from_journal(journal)
    receipt_path = transaction_dir / "receipt.json"
    if (
        not receipt_path.is_file()
        or receipt_path.is_symlink()
        or has_reparse_component(store.root, receipt_path)
        or sha256_file(receipt_path) != journal.get("receipt_sha256")
    ):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group receipt drift")
    envelope = _read_object(receipt_path, "group publication receipt")
    validate_envelope(envelope, artifact_root=store.target_root(namespace))
    data = envelope.get("data")
    if not isinstance(data, dict) or data.get("operation") != operation_id:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group receipt identity drift")
    if data.get("contract_sha256") != journal.get("publication_contract_sha256"):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group receipt contract drift")
    outputs = data.get("outputs")
    if not isinstance(outputs, list):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group receipt outputs drift")
    try:
        parsed = tuple(ArtifactHashV0.from_dict(row) for row in outputs)
        expected = tuple(entry.staged_artifact for entry in entries)
        PublicationGroupReceiptV0(operation_id, journal["publication_contract_sha256"], parsed)
    except (ContractViolation, TypeError) as error:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group receipt outputs drift") from error
    if parsed != expected:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Group receipt target binding drift")


def inspect_group_recovery(store: SyntheticTransactionStoreV0, operation_id: str) -> GroupRecoveryPlanV0:
    _assert_store_layout(store)
    transaction_dir = store.transaction_dir(operation_id)
    if not transaction_dir.exists():
        return GroupRecoveryPlanV0(operation_id, RecoveryDispositionV0.NO_ACTION, None, None, "No transaction")
    try:
        if transaction_dir.is_symlink() or has_reparse_component(store.root, transaction_dir):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Unsafe group transaction directory")
        journal, _, _ = _read_group_journal_candidate(store, operation_id)
        state = _validate_group_journal(journal, operation_id)
        namespace = _namespace_from_journal(journal)
        entries = _group_entries_from_journal(journal)
        current = _current_target_rows(store, namespace, entries)
        current_sha = _target_set_sha(current)
        preimages = _preimage_rows(entries)
        postimages = _postimage_rows(entries)
        if state is TransactionStateV0.VERIFIED:
            if current == postimages:
                _validate_group_receipt(store, operation_id, transaction_dir, journal)
                return GroupRecoveryPlanV0(operation_id, RecoveryDispositionV0.NO_ACTION, state, current_sha, "Verified")
            return GroupRecoveryPlanV0(operation_id, RecoveryDispositionV0.UNKNOWN, state, current_sha, "Verified group drift")
        if state is TransactionStateV0.ROLLED_BACK:
            supersession_path = transaction_dir / "receipt.superseded.json"
            supersession_sha = journal.get("supersession_receipt_sha256")
            receipt_path = transaction_dir / "receipt.json"
            receipt_exists = receipt_path.is_file()
            supersession_valid = (
                supersession_sha is None and not supersession_path.exists() and not receipt_exists
            )
            if isinstance(supersession_sha, str):
                if (
                    not receipt_exists
                    or receipt_path.is_symlink()
                    or has_reparse_component(store.root, receipt_path)
                    or not supersession_path.is_file()
                    or supersession_path.is_symlink()
                    or has_reparse_component(store.root, supersession_path)
                    or sha256_file(supersession_path) != supersession_sha
                ):
                    supersession_valid = False
                else:
                    supersession = _read_object(supersession_path, "group rollback supersession")
                    _exact_keys(
                        supersession,
                        {
                            "schema_version",
                            "transaction_kind",
                            "operation_id",
                            "status",
                            "original_receipt_sha256",
                            "restored_set_sha256",
                            "fencing_epoch",
                        },
                        set(),
                        "group rollback supersession",
                    )
                    supersession_valid = (
                        supersession["schema_version"] == 1
                        and supersession["transaction_kind"] == GROUP_TRANSACTION_KIND
                        and supersession["operation_id"] == operation_id
                        and supersession["status"] == "SUPERSEDED_BY_ROLLBACK"
                        and supersession["original_receipt_sha256"] == sha256_file(receipt_path)
                        and supersession["restored_set_sha256"] == current_sha
                        and supersession["fencing_epoch"] == journal["fencing_epoch"]
                    )
            disposition = (
                RecoveryDispositionV0.NO_ACTION
                if current == preimages
                and journal.get("restored_set_sha256") == current_sha
                and supersession_valid
                else RecoveryDispositionV0.UNKNOWN
            )
            return GroupRecoveryPlanV0(operation_id, disposition, state, current_sha, "Group rollback terminal state")
        if state is TransactionStateV0.UNKNOWN:
            return GroupRecoveryPlanV0(operation_id, RecoveryDispositionV0.UNKNOWN, state, current_sha, "Unknown terminal state")
        allowed = all(
            row["sha256"] in {entry.expected_preimage_sha256, entry.staged_artifact.sha256}
            for row, entry in zip(current, entries)
        )
        if not allowed:
            return GroupRecoveryPlanV0(operation_id, RecoveryDispositionV0.UNKNOWN, state, current_sha, "Group target bytes are unknown")
        if state is TransactionStateV0.ROLLBACK_REQUIRED:
            return GroupRecoveryPlanV0(
                operation_id, RecoveryDispositionV0.ROLLBACK_REQUIRED, state, current_sha, "Group rollback is incomplete"
            )
        if current == preimages and state in {TransactionStateV0.PREPARED, TransactionStateV0.APPLYING}:
            return GroupRecoveryPlanV0(operation_id, RecoveryDispositionV0.SAFE_RETRY, state, current_sha, "Group is at preimage")
        if state is TransactionStateV0.APPLIED and current != postimages:
            return GroupRecoveryPlanV0(operation_id, RecoveryDispositionV0.UNKNOWN, state, current_sha, "Applied group is mixed")
        return GroupRecoveryPlanV0(
            operation_id, RecoveryDispositionV0.ROLLBACK_REQUIRED, state, current_sha, "Group contains postimages"
        )
    except (KeyError, TypeError, ValueError, OSError, ContractViolation, TransactionViolation):
        return GroupRecoveryPlanV0(operation_id, RecoveryDispositionV0.UNKNOWN, None, None, "Group journal is corrupt")


def _validate_group_terminal_for_release(
    store: SyntheticTransactionStoreV0,
    lease: WriteLeaseV0,
    journal: Mapping[str, Any],
) -> None:
    state = _validate_group_journal(journal, lease.operation_id)
    plan = inspect_group_recovery(store, lease.operation_id)
    if plan.disposition is not RecoveryDispositionV0.NO_ACTION or state not in {
        TransactionStateV0.VERIFIED,
        TransactionStateV0.ROLLED_BACK,
    }:
        raise TransactionViolation(TransactionErrorCode.RECOVERY_REQUIRED, "Cannot release lease with incomplete group")
    if (
        journal["namespace"] != lease.namespace.as_dict()
        or journal["namespace_token"] != lease.namespace_token
        or journal["owner_token"] != lease.owner_token
        or journal["fencing_epoch"] != lease.fencing_epoch
    ):
        raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Lease does not own terminal group")
