from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from locpipe.contracts.v0 import ContractViolation, ErrorCode, WorkflowProfile, semantic_sha256
from locpipe.contracts.v0.profiles import SHA256_RE

from ._transaction_models import NamespaceV0


@dataclass(frozen=True)
class ProjectContextV0:
    namespace: NamespaceV0
    workflow_profile: WorkflowProfile
    config_snapshot_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Project context namespace is invalid")
        try:
            profile = WorkflowProfile(self.workflow_profile)
        except (TypeError, ValueError) as error:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Project context profile is invalid") from error
        if not isinstance(self.config_snapshot_sha256, str) or not SHA256_RE.fullmatch(
            self.config_snapshot_sha256
        ):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Project context config SHA is invalid")
        object.__setattr__(self, "workflow_profile", profile)

    def as_dict(self) -> dict[str, object]:
        return {
            "namespace": self.namespace.as_dict(),
            "workflow_profile": self.workflow_profile.value,
            "config_snapshot_sha256": self.config_snapshot_sha256,
        }

    @property
    def context_digest(self) -> str:
        return semantic_sha256(self.as_dict())


@dataclass(frozen=True)
class ProjectPathsV0:
    namespace_root: Path
    state_root: Path
    cache_root: Path
    staging_root: Path
    transactions_root: Path
    receipts_root: Path
    outputs_root: Path

    def __post_init__(self) -> None:
        fields = (
            self.namespace_root,
            self.state_root,
            self.cache_root,
            self.staging_root,
            self.transactions_root,
            self.receipts_root,
            self.outputs_root,
        )
        if any(not isinstance(path, Path) or not path.is_absolute() for path in fields):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Project paths must be absolute pathlib paths")
        children = fields[1:]
        if any(path.parent != self.namespace_root for path in children) or len(set(children)) != len(children):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Project paths must be unique namespace children")
