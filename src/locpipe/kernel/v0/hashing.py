from __future__ import annotations

import hashlib
from pathlib import Path

from locpipe.contracts.v0 import ContractViolation, ErrorCategory, ErrorCode


DEFAULT_CHUNK_SIZE = 1024 * 1024


def sha256_bytes(payload: bytes) -> str:
    if not isinstance(payload, bytes):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "SHA payload must be bytes")
    return hashlib.sha256(payload).hexdigest()


def sha256_text_utf8(value: str) -> str:
    if not isinstance(value, str):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "SHA text must be a string")
    return sha256_bytes(value.encode("utf-8"))


def sha256_file(path: Path, *, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    if not isinstance(path, Path):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "SHA path must be a pathlib.Path")
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size <= 0:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "chunk_size must be a positive integer")
    if not path.is_file():
        raise ContractViolation(
            ErrorCode.HASH_MISMATCH,
            f"Artifact is not a regular file: {path}",
            category=ErrorCategory.INTEGRITY,
            artifact=str(path),
        )
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(chunk_size), b""):
                digest.update(chunk)
    except OSError as error:
        raise ContractViolation(
            ErrorCode.HASH_MISMATCH,
            f"Cannot hash artifact: {path}",
            category=ErrorCategory.INTEGRITY,
            artifact=str(path),
        ) from error
    return digest.hexdigest()
