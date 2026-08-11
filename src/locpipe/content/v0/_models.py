from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from locpipe.contracts.v0 import (
    BranchIdentity,
    ContractViolation,
    ErrorCode,
    display_id,
)
from locpipe.contracts.v0.profiles import SHA256_RE


def _sha(value: str, name: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be lowercase SHA-256")
    return value


def _nonempty(value: str, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be non-empty")
    return value


def _identities(values: tuple[BranchIdentity, ...], name: str) -> tuple[BranchIdentity, ...]:
    rows = tuple(values)
    if any(not isinstance(row, BranchIdentity) for row in rows):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} contains an invalid identity")
    keys = tuple(display_id(row) for row in rows)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, f"{name} must be unique and sorted")
    return rows


class ReconciliationStateV0(str, Enum):
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    MOVED = "MOVED"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    SPLIT = "SPLIT"
    MERGED = "MERGED"
    SUPERSEDES = "SUPERSEDES"


class TargetValidityStateV0(str, Enum):
    VALID = "VALID"
    STALE_SOURCE = "STALE_SOURCE"
    REMOVED_SOURCE = "REMOVED_SOURCE"


class ScopeRoleV0(str, Enum):
    OWNED = "OWNED"
    CONTEXT = "CONTEXT"


@dataclass(frozen=True)
class SourceSegmentV0:
    identity: BranchIdentity
    content_type: str
    source_revision_sha: str
    locator_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.identity, BranchIdentity):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source segment identity is invalid")
        _nonempty(self.content_type, "content_type")
        _sha(self.source_revision_sha, "source_revision_sha")
        _sha(self.locator_sha256, "locator_sha256")

    @property
    def stable_id(self) -> str:
        return display_id(self.identity)


@dataclass(frozen=True)
class SourceLockV0:
    config_snapshot_sha256: str
    adapter_id: str
    adapter_version: str
    adapter_digest: str
    snapshot_sha256: str
    segments_sha256: str
    relations_sha256: str | None
    source_locale: str
    source_version: str
    branch_ids: tuple[str, ...]
    corpus_digest: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.config_snapshot_sha256, "config_snapshot_sha256"),
            (self.adapter_digest, "adapter_digest"),
            (self.snapshot_sha256, "snapshot_sha256"),
            (self.segments_sha256, "segments_sha256"),
            (self.corpus_digest, "corpus_digest"),
        ):
            _sha(value, name)
        if self.relations_sha256 is not None:
            _sha(self.relations_sha256, "relations_sha256")
        _nonempty(self.adapter_id, "adapter_id")
        _nonempty(self.adapter_version, "adapter_version")
        _nonempty(self.source_locale, "source_locale")
        _nonempty(self.source_version, "source_version")
        if self.branch_ids != tuple(sorted(self.branch_ids)) or len(self.branch_ids) != len(set(self.branch_ids)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Source lock branch IDs must be unique and sorted")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.content.source-lock/v0",
            "config_snapshot_sha256": self.config_snapshot_sha256,
            "adapter": {
                "adapter_id": self.adapter_id,
                "version": self.adapter_version,
                "digest": self.adapter_digest,
            },
            "snapshot_sha256": self.snapshot_sha256,
            "segments_sha256": self.segments_sha256,
            "relations_sha256": self.relations_sha256,
            "source_locale": self.source_locale,
            "source_version": self.source_version,
            "branch_ids": list(self.branch_ids),
            "corpus_digest": self.corpus_digest,
        }


@dataclass(frozen=True)
class SourceDependencyV0:
    identity: BranchIdentity
    source_revision_sha: str

    def __post_init__(self) -> None:
        if not isinstance(self.identity, BranchIdentity):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source dependency identity is invalid")
        _sha(self.source_revision_sha, "source_revision_sha")

    def as_dict(self) -> dict[str, Any]:
        return {"identity": self.identity.as_dict(), "source_revision_sha": self.source_revision_sha}


@dataclass(frozen=True)
class TargetBindingV0:
    target_identity: BranchIdentity
    target_payload_sha256: str
    source_dependencies: tuple[SourceDependencyV0, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.target_identity, BranchIdentity):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target identity is invalid")
        _sha(self.target_payload_sha256, "target_payload_sha256")
        rows = tuple(self.source_dependencies)
        if any(not isinstance(row, SourceDependencyV0) for row in rows):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target dependencies are invalid")
        keys = tuple(display_id(row.identity) for row in rows)
        if not rows or keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Target dependencies must be non-empty, unique and sorted")
        object.__setattr__(self, "source_dependencies", rows)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_identity": self.target_identity.as_dict(),
            "target_payload_sha256": self.target_payload_sha256,
            "source_dependencies": [row.as_dict() for row in self.source_dependencies],
        }


@dataclass(frozen=True)
class LineageDirectiveV0:
    state: ReconciliationStateV0
    old_ids: tuple[BranchIdentity, ...]
    new_ids: tuple[BranchIdentity, ...]

    def __post_init__(self) -> None:
        if self.state not in {
            ReconciliationStateV0.SPLIT,
            ReconciliationStateV0.MERGED,
            ReconciliationStateV0.SUPERSEDES,
        }:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Lineage directive has an invalid state")
        object.__setattr__(self, "old_ids", _identities(self.old_ids, "Lineage old IDs"))
        object.__setattr__(self, "new_ids", _identities(self.new_ids, "Lineage new IDs"))
        if not self.old_ids or not self.new_ids:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Lineage directive sides must be non-empty")
        if self.state is ReconciliationStateV0.SPLIT and not (len(self.old_ids) == 1 and len(self.new_ids) >= 2):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "SPLIT requires one old and at least two new IDs")
        if self.state is ReconciliationStateV0.MERGED and not (len(self.old_ids) >= 2 and len(self.new_ids) == 1):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "MERGED requires at least two old and one new ID")

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "old_ids": [row.as_dict() for row in self.old_ids],
            "new_ids": [row.as_dict() for row in self.new_ids],
        }


@dataclass(frozen=True)
class ScopeEntryV0:
    identity: BranchIdentity
    role: ScopeRoleV0

    def __post_init__(self) -> None:
        if not isinstance(self.identity, BranchIdentity) or not isinstance(self.role, ScopeRoleV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Scope entry is invalid")

    def as_dict(self) -> dict[str, Any]:
        return {"identity": self.identity.as_dict(), "role": self.role.value}


@dataclass(frozen=True)
class FrozenScopeV0:
    entries: tuple[ScopeEntryV0, ...]
    target_locales: tuple[str, ...]
    source_corpus_digest: str
    source_lock_sha256: str
    reconciliation_digest: str
    config_snapshot_sha256: str
    scope_sha256: str

    def __post_init__(self) -> None:
        rows = tuple(self.entries)
        if any(not isinstance(row, ScopeEntryV0) for row in rows):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Frozen scope entries are invalid")
        keys = tuple(display_id(row.identity) for row in rows)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Frozen scope entries must be unique and sorted")
        object.__setattr__(self, "entries", rows)
        locales = tuple(self.target_locales)
        if not locales or locales != tuple(sorted(locales)) or len(locales) != len(set(locales)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Target locales must be non-empty, unique and sorted")
        if any(not isinstance(value, str) or not value for value in locales):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target locale is invalid")
        object.__setattr__(self, "target_locales", locales)
        _sha(self.source_corpus_digest, "source_corpus_digest")
        _sha(self.source_lock_sha256, "source_lock_sha256")
        _sha(self.reconciliation_digest, "reconciliation_digest")
        _sha(self.config_snapshot_sha256, "config_snapshot_sha256")
        _sha(self.scope_sha256, "scope_sha256")

    def scope_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.content.scope/v0",
            "entries": [row.as_dict() for row in self.entries],
            "target_locales": list(self.target_locales),
        }

    def lock_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.content.scope-lock/v0",
            "scope_sha256": self.scope_sha256,
            "source_corpus_digest": self.source_corpus_digest,
            "source_lock_sha256": self.source_lock_sha256,
            "reconciliation_digest": self.reconciliation_digest,
            "config_snapshot_sha256": self.config_snapshot_sha256,
            "target_locales": list(self.target_locales),
        }
