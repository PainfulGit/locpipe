from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from locpipe.contracts.v0 import (
    ArtifactHashV0,
    CONTRACT_VERSION,
    ContractViolation,
    ErrorCode,
    canonical_value_bytes,
)
from locpipe.contracts.v0.artifacts import validate_relative_posix_path
from locpipe.contracts.v0.profiles import SHA256_RE

from .hashing import sha256_bytes

OPERATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_NAMESPACE_PART_LENGTH = 128

class TransactionStateV0(str, Enum):
    PREPARED = "PREPARED"
    APPLYING = "APPLYING"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"
    ROLLED_BACK = "ROLLED_BACK"
    UNKNOWN = "UNKNOWN"


class TransactionErrorCode(str, Enum):
    WRITER_LOCKED = "WRITER_LOCKED"
    FENCE_STALE = "FENCE_STALE"
    TRANSACTION_DRIFT = "TRANSACTION_DRIFT"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    JOURNAL_CORRUPT = "JOURNAL_CORRUPT"
    SYNTHETIC_STORE_REQUIRED = "SYNTHETIC_STORE_REQUIRED"


class TransactionViolation(RuntimeError):
    def __init__(self, code: TransactionErrorCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")


class RecoveryDispositionV0(str, Enum):
    NO_ACTION = "NO_ACTION"
    SAFE_RETRY = "SAFE_RETRY"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"
    UNKNOWN = "UNKNOWN"


ALLOWED_TRANSITIONS = {
    TransactionStateV0.PREPARED: {
        TransactionStateV0.APPLYING,
        TransactionStateV0.ROLLBACK_REQUIRED,
        TransactionStateV0.UNKNOWN,
    },
    TransactionStateV0.APPLYING: {
        TransactionStateV0.APPLIED,
        TransactionStateV0.ROLLBACK_REQUIRED,
        TransactionStateV0.UNKNOWN,
    },
    TransactionStateV0.APPLIED: {
        TransactionStateV0.VERIFIED,
        TransactionStateV0.ROLLBACK_REQUIRED,
        TransactionStateV0.UNKNOWN,
    },
    TransactionStateV0.ROLLBACK_REQUIRED: {TransactionStateV0.ROLLED_BACK},
    TransactionStateV0.VERIFIED: set(),
    TransactionStateV0.ROLLED_BACK: set(),
    TransactionStateV0.UNKNOWN: set(),
}


def transition_state(current: TransactionStateV0, target: TransactionStateV0) -> TransactionStateV0:
    if not isinstance(current, TransactionStateV0) or not isinstance(target, TransactionStateV0):
        raise TransactionViolation(TransactionErrorCode.JOURNAL_CORRUPT, "Unknown transaction state")
    if target not in ALLOWED_TRANSITIONS[current]:
        raise TransactionViolation(
            TransactionErrorCode.JOURNAL_CORRUPT,
            f"Illegal transaction transition: {current.value} -> {target.value}",
        )
    return target


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _valid_sha(value: object, *, optional: bool = False) -> bool:
    return (optional and value is None) or (isinstance(value, str) and SHA256_RE.fullmatch(value) is not None)


@dataclass(frozen=True)
class NamespaceV0:
    workspace_id: str
    project_id: str
    release_id: str

    def __post_init__(self) -> None:
        for name, value in (
            ("workspace_id", self.workspace_id),
            ("project_id", self.project_id),
            ("release_id", self.release_id),
        ):
            if (
                not isinstance(value, str)
                or not value
                or len(value) > MAX_NAMESPACE_PART_LENGTH
                or "\x00" in value
            ):
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Invalid namespace {name}")

    def as_dict(self) -> dict[str, str]:
        return {
            "workspace_id": self.workspace_id,
            "project_id": self.project_id,
            "release_id": self.release_id,
        }

    @property
    def token(self) -> str:
        return "ns-v0-" + sha256_bytes(canonical_value_bytes(self.as_dict()))


@dataclass(frozen=True)
class WriteLeaseV0:
    namespace: NamespaceV0
    namespace_token: str
    owner_token: str
    operation_id: str
    fencing_epoch: int

    def __post_init__(self) -> None:
        if self.namespace_token != self.namespace.token:
            raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Namespace token mismatch")
        if not isinstance(self.owner_token, str) or not re.fullmatch(r"[0-9a-f]{32}", self.owner_token):
            raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Invalid owner token")
        if not isinstance(self.operation_id, str) or not OPERATION_RE.fullmatch(self.operation_id):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid operation ID")
        if not isinstance(self.fencing_epoch, int) or isinstance(self.fencing_epoch, bool) or self.fencing_epoch <= 0:
            raise TransactionViolation(TransactionErrorCode.FENCE_STALE, "Invalid fencing epoch")

    def as_dict(self) -> dict[str, object]:
        return {
            "namespace": self.namespace.as_dict(),
            "namespace_token": self.namespace_token,
            "owner_token": self.owner_token,
            "operation_id": self.operation_id,
            "fencing_epoch": self.fencing_epoch,
        }


@dataclass(frozen=True)
class PublicationSpecV0:
    namespace: NamespaceV0
    operation_id: str
    target_path: str
    staged_artifact: ArtifactHashV0
    expected_preimage_sha256: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Publication namespace is invalid")
        if not isinstance(self.operation_id, str) or not OPERATION_RE.fullmatch(self.operation_id):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid operation ID")
        validate_relative_posix_path(self.target_path)
        if not isinstance(self.staged_artifact, ArtifactHashV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Staged artifact is invalid")
        if self.staged_artifact.hash_domain != "raw" or self.staged_artifact.path != self.target_path:
            raise ContractViolation(
                ErrorCode.OUTPUT_CONTRACT_VIOLATION,
                "Slice 02 supports one raw staged artifact matching target_path",
            )
        if self.expected_preimage_sha256 is not None and (
            not isinstance(self.expected_preimage_sha256, str)
            or not SHA256_RE.fullmatch(self.expected_preimage_sha256)
        ):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid expected preimage SHA")

    def as_dict(self) -> dict[str, object]:
        return {
            "namespace": self.namespace.as_dict(),
            "operation_id": self.operation_id,
            "target_path": self.target_path,
            "staged_artifact": self.staged_artifact.as_dict(),
            "expected_preimage_sha256": self.expected_preimage_sha256,
        }


@dataclass(frozen=True)
class PublicationReceiptV0:
    operation_id: str
    contract_sha256: str
    target: ArtifactHashV0

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, str) or not OPERATION_RE.fullmatch(self.operation_id):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid receipt operation ID")
        if not _valid_sha(self.contract_sha256) or not isinstance(self.target, ArtifactHashV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid publication receipt")

    def as_envelope(self) -> dict[str, object]:
        return {
            "schema_id": "urn:locpipe:contracts:v0:receipt",
            "schema_version": CONTRACT_VERSION,
            "kind": "receipt",
            "data": {
                "operation": self.operation_id,
                "inputs": [],
                "outputs": [self.target.as_dict()],
                "contract_sha256": self.contract_sha256,
                "status": "PASS",
            },
        }


@dataclass(frozen=True)
class RecoveryPlanV0:
    operation_id: str
    disposition: RecoveryDispositionV0
    journal_state: TransactionStateV0 | None
    target_sha256: str | None
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, str) or not OPERATION_RE.fullmatch(self.operation_id):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid recovery operation ID")
        if not isinstance(self.disposition, RecoveryDispositionV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid recovery disposition")
        if self.journal_state is not None and not isinstance(self.journal_state, TransactionStateV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid recovery journal state")
        if not _valid_sha(self.target_sha256, optional=True) or not isinstance(self.detail, str):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid recovery evidence")
