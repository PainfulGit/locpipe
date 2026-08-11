from __future__ import annotations

import os
import re
import secrets
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from locpipe.contracts.v0 import (
    ArtifactHashV0,
    ContractViolation,
    ErrorCode,
    canonical_value_bytes,
    semantic_sha256,
    strict_loads,
    validate_envelope,
)
from locpipe.contracts.v0.artifacts import (
    has_reparse_component,
    has_reparse_in_path,
    resolve_artifact_root,
    validate_relative_posix_path,
)

from .hashing import sha256_file
from ._transaction_models import (
    NamespaceV0,
    OPERATION_RE,
    PublicationSpecV0,
    RecoveryDispositionV0,
    RecoveryPlanV0,
    TransactionErrorCode,
    TransactionStateV0,
    TransactionViolation,
    WriteLeaseV0,
    _valid_sha,
    transition_state,
)

STORE_MARKER = ".locpipe-synthetic-v0.json"
STORE_KIND = "locpipe_synthetic_transaction_store"

def _canonical_document(value: Mapping[str, Any]) -> bytes:
    return canonical_value_bytes(dict(value)) + b"\n"


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        with path.open("r+b") as stream:
            os.fsync(stream.fileno())
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_object(path: Path, name: str) -> dict[str, Any]:
    try:
        value = strict_loads(path.read_bytes())
    except (OSError, ValueError) as error:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, f"Cannot read {name}") from error
    if not isinstance(value, dict):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, f"{name} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], required: set[str], optional: set[str], name: str) -> None:
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing or unknown:
        raise TransactionViolation(
            TransactionErrorCode.JOURNAL_CORRUPT,
            f"{name} fields invalid; missing={sorted(missing)}, unknown={sorted(unknown)}",
        )


class SyntheticTransactionStoreV0:
    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Store root must be a Path")
        try:
            self.root = root.resolve(strict=True)
        except OSError as error:
            raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Store root is missing") from error
        if not self.root.is_dir() or has_reparse_in_path(root):
            raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Unsafe store root")
        marker = self.root / STORE_MARKER
        if not marker.is_file() or marker.is_symlink():
            raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Synthetic marker is missing")
        value = _read_object(marker, "synthetic marker")
        if value != {"kind": STORE_KIND, "schema_version": 1}:
            raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Synthetic marker is invalid")
        self.targets = self.root / "targets"
        self.staging = self.root / "staging"
        self.locks = self.root / "locks"
        self.epochs = self.root / "epochs"
        self.transactions = self.root / "transactions"
        for directory in (self.targets, self.staging, self.locks, self.epochs, self.transactions):
            if not directory.is_dir() or directory.is_symlink() or has_reparse_component(self.root, directory):
                raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Synthetic store layout drift")

    @classmethod
    def create(cls, root: Path) -> "SyntheticTransactionStoreV0":
        resolved = resolve_artifact_root(root, require_empty=True)
        _atomic_write(resolved / STORE_MARKER, _canonical_document({"kind": STORE_KIND, "schema_version": 1}))
        for name in ("targets", "staging", "locks", "epochs", "transactions"):
            (resolved / name).mkdir()
        return cls(resolved)

    def create_staging(self, operation_id: str) -> Path:
        if not isinstance(operation_id, str) or not OPERATION_RE.fullmatch(operation_id):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid operation ID")
        path = self.staging / operation_id
        path.mkdir()
        return resolve_artifact_root(path, require_empty=True)

    def transaction_dir(self, operation_id: str) -> Path:
        if not isinstance(operation_id, str) or not OPERATION_RE.fullmatch(operation_id):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid operation ID")
        return self.transactions / operation_id

    def target_root(self, namespace: NamespaceV0, *, create: bool = False) -> Path:
        if not isinstance(namespace, NamespaceV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid target namespace")
        _assert_store_layout(self)
        root = self.targets / namespace.token
        if root.exists():
            if not root.is_dir() or root.is_symlink() or has_reparse_component(self.root, root):
                raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Namespace target root drift")
        elif create:
            root.mkdir()
        return root


def _assert_store_layout(store: SyntheticTransactionStoreV0) -> None:
    if not isinstance(store, SyntheticTransactionStoreV0):
        raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Invalid synthetic store")
    marker = store.root / STORE_MARKER
    if marker.is_symlink() or not marker.is_file() or has_reparse_component(store.root, marker):
        raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Synthetic marker drift")
    if _read_object(marker, "synthetic marker") != {"kind": STORE_KIND, "schema_version": 1}:
        raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Synthetic marker drift")
    for directory in (store.targets, store.staging, store.locks, store.epochs, store.transactions):
        if not directory.is_dir() or directory.is_symlink() or has_reparse_component(store.root, directory):
            raise TransactionViolation(TransactionErrorCode.SYNTHETIC_STORE_REQUIRED, "Synthetic store layout drift")


def _safe_target(
    store: SyntheticTransactionStoreV0,
    namespace: NamespaceV0,
    relative_path: str,
    *,
    create_parents: bool,
) -> Path:
    _assert_store_layout(store)
    safe = validate_relative_posix_path(relative_path)
    target_root = store.target_root(namespace, create=create_parents)
    target = target_root / Path(*safe.split("/"))
    current = target_root
    for part in target.relative_to(target_root).parts[:-1]:
        current = current / part
        if current.exists():
            if not current.is_dir() or current.is_symlink() or has_reparse_component(target_root, current):
                raise ContractViolation(ErrorCode.PATH_ESCAPE, f"Unsafe target parent: {safe}")
        elif create_parents:
            current.mkdir()
        else:
            break
    if target.exists() and (not target.is_file() or target.is_symlink() or has_reparse_component(target_root, target)):
        raise ContractViolation(ErrorCode.PATH_ESCAPE, f"Unsafe target artifact: {safe}")
    return target


def _journal_transition(
    path: Path,
    journal: dict[str, Any],
    target: TransactionStateV0,
    clock: Callable[[], str],
) -> dict[str, Any]:
    current = TransactionStateV0(journal["state"])
    transition_state(current, target)
    updated = dict(journal)
    updated["state"] = target.value
    transitions = list(updated["transitions"])
    transitions.append({"state": target.value, "at": clock()})
    updated["transitions"] = transitions
    _atomic_write(path, _canonical_document(updated))
    return updated


_JOURNAL_REQUIRED = {
    "schema_version",
    "operation_id",
    "namespace",
    "namespace_token",
    "owner_token",
    "fencing_epoch",
    "target_path",
    "preimage_exists",
    "preimage_sha256",
    "expected_postimage_sha256",
    "publication_contract_sha256",
    "receipt_sha256",
    "state",
    "transitions",
}
_JOURNAL_OPTIONAL = {"restored_sha256", "supersession_receipt_sha256"}


def _validate_journal(journal: Mapping[str, Any], operation_id: str) -> TransactionStateV0:
    _exact_keys(journal, _JOURNAL_REQUIRED, _JOURNAL_OPTIONAL, "transaction journal")
    if journal["schema_version"] != 1 or journal["operation_id"] != operation_id:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal identity drift")
    namespace_value = journal["namespace"]
    if not isinstance(namespace_value, dict):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal namespace is malformed")
    _exact_keys(namespace_value, {"workspace_id", "project_id", "release_id"}, set(), "journal namespace")
    try:
        namespace = NamespaceV0(
            namespace_value["workspace_id"],
            namespace_value["project_id"],
            namespace_value["release_id"],
        )
    except (ContractViolation, TypeError) as error:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal namespace is malformed") from error
    if journal["namespace_token"] != namespace.token:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal namespace token drift")
    if not isinstance(journal["owner_token"], str) or re.fullmatch(r"[0-9a-f]{32}", journal["owner_token"]) is None:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal owner token is malformed")
    if (
        not isinstance(journal["fencing_epoch"], int)
        or isinstance(journal["fencing_epoch"], bool)
        or journal["fencing_epoch"] <= 0
    ):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal fencing epoch is malformed")
    validate_relative_posix_path(journal["target_path"])
    if not isinstance(journal["preimage_exists"], bool):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal preimage flag is malformed")
    if journal["preimage_exists"] != (journal["preimage_sha256"] is not None):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal preimage evidence conflicts")
    for key in ("preimage_sha256", "receipt_sha256", "restored_sha256", "supersession_receipt_sha256"):
        if key in journal and not _valid_sha(journal[key], optional=True):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, f"Journal {key} is malformed")
    for key in ("expected_postimage_sha256", "publication_contract_sha256"):
        if not _valid_sha(journal[key]):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, f"Journal {key} is malformed")
    try:
        state = TransactionStateV0(journal["state"])
    except (TypeError, ValueError) as error:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Unknown journal state") from error
    transitions = journal["transitions"]
    if not isinstance(transitions, list) or not transitions:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal transitions are malformed")
    previous: TransactionStateV0 | None = None
    for index, row in enumerate(transitions):
        if not isinstance(row, dict):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal transition is malformed")
        _exact_keys(row, {"state", "at"}, set(), "journal transition")
        if not isinstance(row["at"], str) or not row["at"]:
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal transition time is malformed")
        try:
            current = TransactionStateV0(row["state"])
        except (TypeError, ValueError) as error:
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal transition state is unknown") from error
        if index == 0:
            if current is not TransactionStateV0.PREPARED:
                raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal must begin PREPARED")
        else:
            transition_state(previous, current)  # type: ignore[arg-type]
        previous = current
    if previous is not state:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal state does not match transitions")
    if state is TransactionStateV0.VERIFIED and journal["receipt_sha256"] is None:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Verified journal lacks receipt SHA")
    if state is TransactionStateV0.ROLLED_BACK and "restored_sha256" not in journal:
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Rolled-back journal lacks restoration evidence")
    if journal["publication_contract_sha256"] != _contract_sha_from_journal(journal):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Journal publication contract drift")
    return state


def _contract_sha(spec: PublicationSpecV0, lease: WriteLeaseV0) -> str:
    return semantic_sha256({"publication_spec": spec.as_dict(), "write_lease": lease.as_dict()})


def _contract_sha_from_journal(journal: Mapping[str, Any]) -> str:
    namespace_value = journal["namespace"]
    namespace = NamespaceV0(
        namespace_value["workspace_id"],
        namespace_value["project_id"],
        namespace_value["release_id"],
    )
    lease = WriteLeaseV0(
        namespace,
        journal["namespace_token"],
        journal["owner_token"],
        journal["operation_id"],
        journal["fencing_epoch"],
    )
    spec = PublicationSpecV0(
        namespace,
        journal["operation_id"],
        journal["target_path"],
        ArtifactHashV0(journal["target_path"], "raw", journal["expected_postimage_sha256"]),
        journal["preimage_sha256"],
    )
    return _contract_sha(spec, lease)


def _journal_matches_publication(
    journal: Mapping[str, Any], spec: PublicationSpecV0, lease: WriteLeaseV0
) -> bool:
    return (
        journal.get("operation_id") == spec.operation_id
        and journal.get("namespace") == spec.namespace.as_dict()
        and journal.get("namespace_token") == lease.namespace_token
        and journal.get("owner_token") == lease.owner_token
        and journal.get("fencing_epoch") == lease.fencing_epoch
        and journal.get("target_path") == spec.target_path
        and journal.get("preimage_sha256") == spec.expected_preimage_sha256
        and journal.get("expected_postimage_sha256") == spec.staged_artifact.sha256
        and journal.get("publication_contract_sha256") == _contract_sha(spec, lease)
    )


def _validate_receipt_against_journal(
    store: SyntheticTransactionStoreV0,
    operation_id: str,
    transaction_dir: Path,
    journal: Mapping[str, Any],
) -> None:
    namespace_value = journal["namespace"]
    namespace = NamespaceV0(
        namespace_value["workspace_id"],
        namespace_value["project_id"],
        namespace_value["release_id"],
    )
    receipt_path = transaction_dir / "receipt.json"
    if (
        not receipt_path.is_file()
        or receipt_path.is_symlink()
        or has_reparse_component(store.root, receipt_path)
        or sha256_file(receipt_path) != journal.get("receipt_sha256")
    ):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Publication receipt drift")
    envelope = _read_object(receipt_path, "publication receipt")
    validate_envelope(envelope, artifact_root=store.target_root(namespace))
    data = envelope.get("data")
    if not isinstance(data, dict):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Publication receipt data drift")
    outputs = data.get("outputs")
    if not isinstance(outputs, list) or len(outputs) != 1 or not isinstance(outputs[0], dict):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Publication receipt output drift")
    try:
        output = ArtifactHashV0.from_dict(outputs[0])
    except ContractViolation as error:
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Publication receipt output drift") from error
    if (
        data.get("operation") != operation_id
        or data.get("contract_sha256") != journal.get("publication_contract_sha256")
        or output.path != journal.get("target_path")
        or output.hash_domain != "raw"
        or output.sha256 != journal.get("expected_postimage_sha256")
    ):
        raise TransactionViolation(TransactionErrorCode.TRANSACTION_DRIFT, "Publication receipt binding drift")


def inspect_recovery(store: SyntheticTransactionStoreV0, operation_id: str) -> RecoveryPlanV0:
    _assert_store_layout(store)
    transaction_dir = store.transaction_dir(operation_id)
    journal_path = transaction_dir / "journal.json"
    if not transaction_dir.exists():
        return RecoveryPlanV0(operation_id, RecoveryDispositionV0.NO_ACTION, None, None, "No transaction")
    if (
        not journal_path.is_file()
        or journal_path.is_symlink()
        or has_reparse_component(store.root, journal_path)
    ):
        return RecoveryPlanV0(operation_id, RecoveryDispositionV0.UNKNOWN, None, None, "Journal is missing")
    try:
        if transaction_dir.is_symlink() or has_reparse_component(store.root, transaction_dir):
            raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Unsafe transaction directory")
        journal = _read_object(journal_path, "transaction journal")
        state = _validate_journal(journal, operation_id)
        namespace_value = journal["namespace"]
        namespace = NamespaceV0(
            namespace_value["workspace_id"],
            namespace_value["project_id"],
            namespace_value["release_id"],
        )
        target = _safe_target(store, namespace, journal["target_path"], create_parents=False)
        target_sha = sha256_file(target) if target.exists() else None
        preimage_sha = journal.get("preimage_sha256")
        postimage_sha = journal.get("expected_postimage_sha256")
        if state is TransactionStateV0.VERIFIED:
            if target_sha == postimage_sha:
                _validate_receipt_against_journal(store, operation_id, transaction_dir, journal)
                return RecoveryPlanV0(operation_id, RecoveryDispositionV0.NO_ACTION, state, target_sha, "Verified")
            return RecoveryPlanV0(operation_id, RecoveryDispositionV0.UNKNOWN, state, target_sha, "Verified evidence drift")
        if state is TransactionStateV0.ROLLED_BACK:
            expected = preimage_sha if journal.get("preimage_exists") else None
            supersession_path = transaction_dir / "receipt.superseded.json"
            supersession_sha = journal.get("supersession_receipt_sha256")
            receipt_exists = (transaction_dir / "receipt.json").is_file()
            supersession_valid = (
                supersession_sha is None
                and not supersession_path.exists()
                and not receipt_exists
            ) or (
                isinstance(supersession_sha, str)
                and supersession_path.is_file()
                and not supersession_path.is_symlink()
                and sha256_file(supersession_path) == supersession_sha
            )
            disposition = (
                RecoveryDispositionV0.NO_ACTION
                if target_sha == expected and supersession_valid
                else RecoveryDispositionV0.UNKNOWN
            )
            return RecoveryPlanV0(operation_id, disposition, state, target_sha, "Rollback terminal state")
        if state is TransactionStateV0.UNKNOWN:
            return RecoveryPlanV0(operation_id, RecoveryDispositionV0.UNKNOWN, state, target_sha, "Unknown terminal state")
        expected_preimage = preimage_sha if journal.get("preimage_exists") else None
        if state is TransactionStateV0.ROLLBACK_REQUIRED:
            if target_sha in {expected_preimage, postimage_sha}:
                return RecoveryPlanV0(
                    operation_id,
                    RecoveryDispositionV0.ROLLBACK_REQUIRED,
                    state,
                    target_sha,
                    "Rollback is incomplete",
                )
            return RecoveryPlanV0(operation_id, RecoveryDispositionV0.UNKNOWN, state, target_sha, "Rollback target drift")
        if target_sha == expected_preimage and state in {TransactionStateV0.PREPARED, TransactionStateV0.APPLYING}:
            return RecoveryPlanV0(operation_id, RecoveryDispositionV0.SAFE_RETRY, state, target_sha, "Target is preimage")
        if target_sha == postimage_sha:
            return RecoveryPlanV0(
                operation_id, RecoveryDispositionV0.ROLLBACK_REQUIRED, state, target_sha, "Postimage exists without verification"
            )
        return RecoveryPlanV0(operation_id, RecoveryDispositionV0.UNKNOWN, state, target_sha, "Target bytes are unknown")
    except (KeyError, TypeError, ValueError, OSError, ContractViolation, TransactionViolation):
        return RecoveryPlanV0(operation_id, RecoveryDispositionV0.UNKNOWN, None, None, "Journal is corrupt")
