from __future__ import annotations

from dataclasses import dataclass

from locpipe.contracts.v0 import ArtifactHashV0, CONTRACT_VERSION, ContractViolation, ErrorCode
from locpipe.contracts.v0.artifacts import validate_relative_posix_path
from locpipe.contracts.v0.profiles import SHA256_RE

from ._transaction_models import (
    NamespaceV0,
    OPERATION_RE,
    RecoveryDispositionV0,
    TransactionStateV0,
)


MAX_GROUP_ENTRIES = 64


@dataclass(frozen=True)
class PublicationEntryV0:
    staged_artifact: ArtifactHashV0
    expected_preimage_sha256: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.staged_artifact, ArtifactHashV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Group staged artifact is invalid")
        validate_relative_posix_path(self.staged_artifact.path)
        if self.staged_artifact.hash_domain != "raw":
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Group entries must use raw hashes")
        if self.expected_preimage_sha256 is not None and (
            not isinstance(self.expected_preimage_sha256, str)
            or SHA256_RE.fullmatch(self.expected_preimage_sha256) is None
        ):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group preimage SHA")
        if self.expected_preimage_sha256 == self.staged_artifact.sha256:
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Group entries cannot be byte-identical no-ops")

    def as_dict(self) -> dict[str, object]:
        return {
            "staged_artifact": self.staged_artifact.as_dict(),
            "expected_preimage_sha256": self.expected_preimage_sha256,
        }


@dataclass(frozen=True)
class PublicationGroupSpecV0:
    namespace: NamespaceV0
    operation_id: str
    entries: tuple[PublicationEntryV0, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Group namespace is invalid")
        if not isinstance(self.operation_id, str) or OPERATION_RE.fullmatch(self.operation_id) is None:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid operation ID")
        if not isinstance(self.entries, tuple) or not 2 <= len(self.entries) <= MAX_GROUP_ENTRIES:
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Group must contain 2 to 64 entries")
        if any(not isinstance(entry, PublicationEntryV0) for entry in self.entries):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group entry")
        paths = [entry.staged_artifact.path for entry in self.entries]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Group paths must be sorted and unique")
        for index, left in enumerate(paths):
            if any(right.startswith(left + "/") for right in paths[index + 1 :]):
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Group paths cannot overlap")

    def as_dict(self) -> dict[str, object]:
        return {
            "namespace": self.namespace.as_dict(),
            "operation_id": self.operation_id,
            "entries": [entry.as_dict() for entry in self.entries],
        }


@dataclass(frozen=True)
class PublicationGroupReceiptV0:
    operation_id: str
    contract_sha256: str
    targets: tuple[ArtifactHashV0, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, str) or OPERATION_RE.fullmatch(self.operation_id) is None:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group receipt operation ID")
        if not isinstance(self.contract_sha256, str) or SHA256_RE.fullmatch(self.contract_sha256) is None:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group receipt contract SHA")
        if not isinstance(self.targets, tuple) or len(self.targets) < 2:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group receipt targets")
        if any(not isinstance(target, ArtifactHashV0) or target.hash_domain != "raw" for target in self.targets):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group receipt target")
        paths = [target.path for target in self.targets]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Group receipt targets must be sorted and unique")

    def as_envelope(self) -> dict[str, object]:
        return {
            "schema_id": "urn:locpipe:contracts:v0:receipt",
            "schema_version": CONTRACT_VERSION,
            "kind": "receipt",
            "data": {
                "operation": self.operation_id,
                "inputs": [],
                "outputs": [target.as_dict() for target in self.targets],
                "contract_sha256": self.contract_sha256,
                "status": "PASS",
            },
        }


@dataclass(frozen=True)
class GroupRecoveryPlanV0:
    operation_id: str
    disposition: RecoveryDispositionV0
    journal_state: TransactionStateV0 | None
    target_set_sha256: str | None
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, str) or OPERATION_RE.fullmatch(self.operation_id) is None:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group recovery operation ID")
        if not isinstance(self.disposition, RecoveryDispositionV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group recovery disposition")
        if self.journal_state is not None and not isinstance(self.journal_state, TransactionStateV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group recovery journal state")
        if self.target_set_sha256 is not None and (
            not isinstance(self.target_set_sha256, str) or SHA256_RE.fullmatch(self.target_set_sha256) is None
        ):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group recovery target-set SHA")
        if not isinstance(self.detail, str):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid group recovery detail")
