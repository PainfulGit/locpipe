from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from locpipe.contracts.v0 import (
    ArtifactDeclarationV0,
    ArtifactHashV0,
    ContractViolation,
    ErrorCode,
)
from locpipe.contracts.v0.artifacts import (
    HashVerifier,
    artifact_sha256,
    resolve_artifact_root,
    resolve_existing_artifact,
)
from locpipe.contracts.v0.profiles import SHA256_RE

from .hashing import sha256_file


NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _sorted_unique(values: Sequence[str], name: str) -> tuple[str, ...]:
    normalized = tuple(values)
    if any(not isinstance(value, str) or not value for value in normalized):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must contain non-empty strings")
    if normalized != tuple(sorted(normalized)) or len(normalized) != len(set(normalized)):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, f"{name} must be unique and sorted")
    return normalized


def _artifact_rows(
    rows: Sequence[ArtifactHashV0], name: str,
) -> tuple[ArtifactHashV0, ...]:
    result = tuple(rows)
    if any(not isinstance(row, ArtifactHashV0) for row in result):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must contain artifact hashes")
    paths = tuple(row.path for row in result)
    _sorted_unique(paths, name)
    return result


@dataclass(frozen=True)
class StateRefV0:
    owner: str
    state: str

    def __post_init__(self) -> None:
        if not isinstance(self.owner, str) or not NAME_RE.fullmatch(self.owner):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid state owner")
        if not isinstance(self.state, str) or not NAME_RE.fullmatch(self.state):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid lifecycle state")

    def as_dict(self) -> dict[str, str]:
        return {"owner": self.owner, "state": self.state}


@dataclass(frozen=True)
class OverlayBindingV0:
    raw_path: str
    raw_sha256: str
    overlay_path: str
    overlay_sha256: str
    stable_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        ArtifactHashV0(self.raw_path, "raw", self.raw_sha256)
        ArtifactHashV0(self.overlay_path, "raw", self.overlay_sha256)
        object.__setattr__(
            self, "stable_ids", _sorted_unique(self.stable_ids, "Overlay stable IDs")
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "raw_path": self.raw_path,
            "raw_sha256": self.raw_sha256,
            "overlay_path": self.overlay_path,
            "overlay_sha256": self.overlay_sha256,
            "stable_ids": list(self.stable_ids),
        }


@dataclass(frozen=True)
class EvidenceProjectionV0:
    frozen_scope_ids: tuple[str, ...]
    scope_sha256: str
    locked_outputs: tuple[ArtifactHashV0, ...]
    raw_outputs: tuple[ArtifactHashV0, ...]
    overlay_bindings: tuple[OverlayBindingV0, ...]
    lifecycle: StateRefV0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "frozen_scope_ids",
            _sorted_unique(self.frozen_scope_ids, "Frozen scope IDs"),
        )
        if not isinstance(self.scope_sha256, str) or not SHA256_RE.fullmatch(self.scope_sha256):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "scope_sha256 must be lowercase SHA-256")
        object.__setattr__(
            self, "locked_outputs", _artifact_rows(self.locked_outputs, "Locked output paths")
        )
        object.__setattr__(
            self, "raw_outputs", _artifact_rows(self.raw_outputs, "Raw output paths")
        )
        if any(not isinstance(row, OverlayBindingV0) for row in self.overlay_bindings):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Overlay bindings are invalid")
        if not isinstance(self.lifecycle, StateRefV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Lifecycle reference is invalid")
        bindings = tuple(self.overlay_bindings)
        overlay_paths = tuple(row.overlay_path for row in bindings)
        _sorted_unique(overlay_paths, "Overlay paths")
        object.__setattr__(self, "overlay_bindings", bindings)

    def as_dict(self) -> dict[str, object]:
        return {
            "frozen_scope_ids": list(self.frozen_scope_ids),
            "scope_sha256": self.scope_sha256,
            "locked_outputs": [row.as_dict() for row in self.locked_outputs],
            "raw_outputs": [row.as_dict() for row in self.raw_outputs],
            "overlay_bindings": [row.as_dict() for row in self.overlay_bindings],
            "lifecycle": self.lifecycle.as_dict(),
        }


@dataclass(frozen=True)
class ParityMismatchV0:
    code: str
    expected: object
    actual: object


@dataclass(frozen=True)
class ParityReportV0:
    mismatches: tuple[ParityMismatchV0, ...]

    @property
    def passed(self) -> bool:
        return not self.mismatches


def snapshot_artifacts(
    artifact_root: Path,
    declarations: Sequence[ArtifactDeclarationV0],
    *,
    hash_verifiers: Mapping[str, HashVerifier] | None = None,
) -> tuple[ArtifactHashV0, ...]:
    if not isinstance(artifact_root, Path):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "artifact_root must be a pathlib.Path")
    root = resolve_artifact_root(artifact_root)
    ordered = tuple(declarations)
    if any(not isinstance(row, ArtifactDeclarationV0) for row in ordered):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Artifact declarations are invalid")
    paths = tuple(row.path for row in ordered)
    _sorted_unique(paths, "Artifact declaration paths")
    result: list[ArtifactHashV0] = []
    for declaration in ordered:
        path = resolve_existing_artifact(root, declaration.path)
        digest = (
            sha256_file(path)
            if declaration.hash_domain == "raw"
            else artifact_sha256(path, declaration.hash_domain, hash_verifiers=hash_verifiers)
        )
        result.append(ArtifactHashV0(declaration.path, declaration.hash_domain, digest))
    return tuple(result)


def compare_evidence(
    expected: EvidenceProjectionV0,
    actual: EvidenceProjectionV0,
) -> ParityReportV0:
    fields = (
        ("SCOPE_IDS_DRIFT", expected.frozen_scope_ids, actual.frozen_scope_ids),
        ("SCOPE_SHA_DRIFT", expected.scope_sha256, actual.scope_sha256),
        ("LOCKED_OUTPUT_DRIFT", expected.locked_outputs, actual.locked_outputs),
        ("RAW_OUTPUT_DRIFT", expected.raw_outputs, actual.raw_outputs),
        ("OVERLAY_BINDING_DRIFT", expected.overlay_bindings, actual.overlay_bindings),
        ("STATE_DRIFT", expected.lifecycle, actual.lifecycle),
    )
    mismatches = tuple(
        ParityMismatchV0(code, left, right)
        for code, left, right in fields
        if left != right
    )
    return ParityReportV0(mismatches)
