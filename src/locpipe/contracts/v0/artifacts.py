from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Mapping
from pathlib import Path

from .errors import ContractViolation, ErrorCategory, ErrorCode


HashVerifier = Callable[[Path], str]


def validate_relative_posix_path(value: object) -> str:
    parts = value.split("/") if isinstance(value, str) else []
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or value.startswith("/")
        or (len(value) >= 2 and value[1] == ":")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ContractViolation(ErrorCode.PATH_ESCAPE, f"Invalid relative POSIX path {value!r}")
    return value


def has_reparse_component(root: Path, target: Path) -> bool:
    current = root
    try:
        relative = target.relative_to(root)
    except ValueError:
        return True
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
        try:
            attributes = getattr(os.lstat(current), "st_file_attributes", 0)
        except OSError:
            return True
        if attributes & getattr(os.stat_result, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            return True
    return False


def has_reparse_in_path(path: Path) -> bool:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            return True
        try:
            attributes = getattr(os.lstat(current), "st_file_attributes", 0)
        except OSError:
            return True
        if attributes & getattr(os.stat_result, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            return True
    return False


def resolve_artifact_root(root: Path, *, require_empty: bool = False) -> Path:
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise ContractViolation(ErrorCode.PATH_ESCAPE, f"Artifact root does not exist: {root}") from error
    if not resolved.is_dir() or has_reparse_in_path(root):
        raise ContractViolation(ErrorCode.PATH_ESCAPE, f"Artifact root is not a safe directory: {root}")
    if require_empty and any(resolved.iterdir()):
        raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Staging root must be empty")
    return resolved


def resolve_existing_artifact(root: Path, relative_path: str) -> Path:
    safe_path = validate_relative_posix_path(relative_path)
    candidate = root / Path(*safe_path.split("/"))
    try:
        resolved = candidate.resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError:
            physical_root = resolved
            for _ in safe_path.split("/"):
                physical_root = physical_root.parent
            if not os.path.samefile(physical_root, root):
                raise
    except (OSError, ValueError) as error:
        raise ContractViolation(
            ErrorCode.PATH_ESCAPE,
            f"Artifact is missing or escapes root: {safe_path}",
            category=ErrorCategory.INTEGRITY,
        ) from error
    if has_reparse_in_path(candidate) or has_reparse_component(root, candidate):
        raise ContractViolation(
            ErrorCode.PATH_ESCAPE,
            f"Artifact crosses a symlink or reparse point: {safe_path}",
            category=ErrorCategory.INTEGRITY,
        )
    return resolved


def artifact_sha256(
    path: Path,
    hash_domain: str,
    *,
    hash_verifiers: Mapping[str, HashVerifier] | None = None,
) -> str:
    if hash_domain == "raw":
        if not path.is_file():
            raise ContractViolation(ErrorCode.HASH_MISMATCH, f"Raw artifact is not a file: {path.name}")
        return hashlib.sha256(path.read_bytes()).hexdigest()
    verifier = dict(hash_verifiers or {}).get(hash_domain)
    if not callable(verifier):
        raise ContractViolation(
            ErrorCode.MALFORMED_ARTIFACT,
            f"No fail-closed verifier registered for {hash_domain}",
        )
    actual = verifier(path)
    if not isinstance(actual, str) or len(actual) != 64:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Verifier returned invalid SHA for {path.name}")
    return actual


def verify_artifact_hashes(
    rows: tuple[object, ...] | list[object],
    *,
    artifact_root: Path,
    hash_verifiers: Mapping[str, HashVerifier] | None = None,
) -> int:
    root = resolve_artifact_root(artifact_root)
    checked = 0
    for row in rows:
        path = resolve_existing_artifact(root, getattr(row, "path"))
        actual = artifact_sha256(path, getattr(row, "hash_domain"), hash_verifiers=hash_verifiers)
        if actual != getattr(row, "sha256"):
            raise ContractViolation(
                ErrorCode.HASH_MISMATCH,
                f"Artifact SHA mismatch for {getattr(row, 'path')}",
                category=ErrorCategory.INTEGRITY,
            )
        checked += 1
    return checked
