"""Private deterministic persistence for process-local prepared source authority."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
import importlib.metadata
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import tomllib
from typing import Any

from locpipe.contracts.v0 import (
    BranchIdentity,
    ContractViolation,
    ErrorCode,
    canonical_json_bytes,
    canonical_value_bytes,
    display_id,
    parse_canonical_json,
    parse_canonical_jsonl,
    raw_sha256,
    source_revision_sha,
    strict_loads,
    validate_envelope,
    validate_relation_set,
)
from locpipe.contracts.v0.artifacts import (
    resolve_artifact_root,
    resolve_existing_artifact,
    validate_relative_posix_path,
)
from locpipe.contracts.v0.profiles import SHA256_RE

from ._corpus import LoadedSourceCorpusV0, _prepared_relation, parse_source_lock_v0
from ._models import ReconciliationStateV0, SourceSegmentV0, TargetValidityStateV0
from ._prepared import (
    PreparedSourceAuthorityV0,
    PreparedSourceRelationV0,
    PreparedSourceSegmentV0,
    _bind_prepared_source_authority_v0,
    _prepared_source_parts_v0,
)
from ._reconciliation import ReconciliationEventV0, SourceReconciliationV0, TargetValidityV0


_MANIFEST_CONTRACT = "locpipe.content.prepared-source-cache-manifest/v0"
_RECEIPT_CONTRACT = "locpipe.content.prepared-source-cache-receipt/v0"
_SEGMENT_CONTRACT = "locpipe.content.prepared-source-segment-cache/v0"
_RELATION_CONTRACT = "locpipe.content.prepared-source-relation-cache/v0"
_SCHEMA_VERSION = "0.1.0"
_SHARD_TARGET_BYTES = 8 * 1024 * 1024
_SHARD_NAME_RE = re.compile(r"(?:segments|relations)/[0-9]{6}\.jsonl")
_ROLES = frozenset({
    "SOURCE_LOCK",
    "RECONCILIATION",
    "RAW_SEGMENTS",
    "RAW_RELATIONS",
    "PREPARED_SEGMENTS",
    "PREPARED_RELATIONS",
})


def _malformed(detail: str) -> ContractViolation:
    return ContractViolation(ErrorCode.MALFORMED_ARTIFACT, detail)


def _binding(detail: str) -> ContractViolation:
    return ContractViolation(ErrorCode.BINDING_MISMATCH, detail)


def _hash_mismatch(detail: str) -> ContractViolation:
    return ContractViolation(ErrorCode.HASH_MISMATCH, detail)


def _sha(value: object, detail: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise _malformed(detail)
    return value


def _text(value: object, detail: str) -> str:
    if type(value) is not str or not value:
        raise _malformed(detail)
    return value


def _count(value: object, detail: str) -> int:
    if type(value) is not int or value < 0:
        raise _malformed(detail)
    return value


def _exact_mapping(value: object, fields: frozenset[str], detail: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _malformed(detail)
    return value


def _runtime_package_version() -> str:
    source_authority = Path(__file__).resolve().parents[4] / "pyproject.toml"
    if source_authority.is_file():
        try:
            value = tomllib.loads(source_authority.read_text(encoding="utf-8"))["project"]["version"]
        except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
            raise _binding("Prepared cache package version authority is unavailable") from error
        return _text(value, "Prepared cache package version authority is invalid")
    try:
        return importlib.metadata.version("locpipe")
    except importlib.metadata.PackageNotFoundError as error:
        raise _binding("Prepared cache package version authority is unavailable") from error


@dataclass(frozen=True, slots=True)
class PreparedSourceCacheReceiptV0:
    cache_id: str
    manifest_sha256: str
    locpipe_version: str
    producer_distribution_sha256: str
    adapter_id: str
    adapter_version: str
    adapter_digest: str
    config_snapshot_sha256: str
    source_lock_sha256: str
    reconciliation_sha256: str
    corpus_digest: str
    snapshot_sha256: str
    segments_sha256: str
    relations_sha256: str | None
    segment_count: int
    relation_count: int
    file_count: int
    total_bytes: int

    def __post_init__(self) -> None:
        for name in (
            "cache_id",
            "manifest_sha256",
            "producer_distribution_sha256",
            "adapter_digest",
            "config_snapshot_sha256",
            "source_lock_sha256",
            "reconciliation_sha256",
            "corpus_digest",
            "snapshot_sha256",
            "segments_sha256",
        ):
            _sha(getattr(self, name), f"Prepared cache receipt {name} is invalid")
        if self.relations_sha256 is not None:
            _sha(self.relations_sha256, "Prepared cache receipt relations SHA is invalid")
        for name in ("locpipe_version", "adapter_id", "adapter_version"):
            _text(getattr(self, name), f"Prepared cache receipt {name} is invalid")
        for name in ("segment_count", "relation_count", "file_count", "total_bytes"):
            _count(getattr(self, name), f"Prepared cache receipt {name} is invalid")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": _RECEIPT_CONTRACT,
            "cache_id": self.cache_id,
            "manifest_sha256": self.manifest_sha256,
            "locpipe_version": self.locpipe_version,
            "producer_distribution_sha256": self.producer_distribution_sha256,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "adapter_digest": self.adapter_digest,
            "config_snapshot_sha256": self.config_snapshot_sha256,
            "source_lock_sha256": self.source_lock_sha256,
            "reconciliation_sha256": self.reconciliation_sha256,
            "corpus_digest": self.corpus_digest,
            "snapshot_sha256": self.snapshot_sha256,
            "segments_sha256": self.segments_sha256,
            "relations_sha256": self.relations_sha256,
            "segment_count": self.segment_count,
            "relation_count": self.relation_count,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.as_dict())

    @classmethod
    def from_bytes(cls, payload: bytes) -> PreparedSourceCacheReceiptV0:
        if type(payload) is not bytes:
            raise _malformed("Prepared cache receipt payload has the wrong type")
        try:
            value = parse_canonical_json(payload)
        except ContractViolation as error:
            raise _malformed("Prepared cache receipt is not canonical") from error
        row = _exact_mapping(
            value,
            frozenset({
                "contract", "cache_id", "manifest_sha256", "locpipe_version",
                "producer_distribution_sha256", "adapter_id", "adapter_version",
                "adapter_digest", "config_snapshot_sha256", "source_lock_sha256",
                "reconciliation_sha256", "corpus_digest", "snapshot_sha256",
                "segments_sha256", "relations_sha256", "segment_count",
                "relation_count", "file_count", "total_bytes",
            }),
            "Prepared cache receipt fields are invalid",
        )
        if row["contract"] != _RECEIPT_CONTRACT:
            raise ContractViolation(ErrorCode.SCHEMA_UNKNOWN, "Prepared cache receipt contract is unknown")
        receipt = cls(
            cache_id=row["cache_id"],
            manifest_sha256=row["manifest_sha256"],
            locpipe_version=row["locpipe_version"],
            producer_distribution_sha256=row["producer_distribution_sha256"],
            adapter_id=row["adapter_id"],
            adapter_version=row["adapter_version"],
            adapter_digest=row["adapter_digest"],
            config_snapshot_sha256=row["config_snapshot_sha256"],
            source_lock_sha256=row["source_lock_sha256"],
            reconciliation_sha256=row["reconciliation_sha256"],
            corpus_digest=row["corpus_digest"],
            snapshot_sha256=row["snapshot_sha256"],
            segments_sha256=row["segments_sha256"],
            relations_sha256=row["relations_sha256"],
            segment_count=row["segment_count"],
            relation_count=row["relation_count"],
            file_count=row["file_count"],
            total_bytes=row["total_bytes"],
        )
        if receipt.canonical_bytes() != payload:
            raise _malformed("Prepared cache receipt bytes are not canonical")
        return receipt


def _segment_record(row: PreparedSourceSegmentV0) -> dict[str, Any]:
    return {
        "contract": _SEGMENT_CONTRACT,
        "identity": row.identity.as_dict(),
        "content_type": row.content_type,
        "source_revision_sha": row.source_revision_sha,
        "locator_sha256": row.locator_sha256,
        "payload": strict_loads(row.payload_bytes),
        "constraints": strict_loads(row.constraints_bytes),
    }


def _relation_record(row: PreparedSourceRelationV0) -> dict[str, Any]:
    return {
        "contract": _RELATION_CONTRACT,
        "digest": row.digest,
        "relation_type": row.relation_type,
        "envelope": parse_canonical_json(row.envelope_bytes),
        "branch_ids": list(row.branch_ids),
        "logical_ids": [list(value) for value in row.logical_ids],
    }


def _inventory_row(role: str, path: str, payload: bytes | bytearray, record_count: int) -> dict[str, Any]:
    return {
        "role": role,
        "path": path,
        "byte_length": len(payload),
        "record_count": record_count,
        "sha256": raw_sha256(payload),
    }


def _validate_authority(authority: PreparedSourceAuthorityV0) -> PreparedSourceAuthorityV0:
    prepared = _prepared_source_parts_v0(authority)
    lock = prepared.corpus.lock
    if canonical_json_bytes(lock.as_dict()) != prepared.source_lock_bytes:
        raise _hash_mismatch("Prepared cache source lock bytes differ from authority")
    if canonical_json_bytes(prepared.reconciliation.as_dict()) != prepared.reconciliation_bytes:
        raise _hash_mismatch("Prepared cache reconciliation bytes differ from authority")
    if prepared.reconciliation.current_corpus_digest != lock.corpus_digest:
        raise _binding("Prepared cache reconciliation differs from authority")
    if raw_sha256(prepared.segments_bytes) != lock.segments_sha256:
        raise _hash_mismatch("Prepared cache segment bytes differ from authority")
    if (prepared.relations_bytes is None) != (lock.relations_sha256 is None):
        raise _binding("Prepared cache relation absence differs from authority")
    if prepared.relations_bytes is not None and raw_sha256(prepared.relations_bytes) != lock.relations_sha256:
        raise _hash_mismatch("Prepared cache relation bytes differ from authority")
    if tuple(row.stable_id for row in prepared.segments) != lock.branch_ids:
        raise _hash_mismatch("Prepared cache rows differ from authority")
    return prepared


def _manifest_value(
    prepared: PreparedSourceAuthorityV0,
    producer_distribution_sha256: str,
    inventory: list[dict[str, Any]],
    segment_aggregate: str,
    relation_aggregate: str,
) -> dict[str, Any]:
    lock = prepared.corpus.lock
    manifest: dict[str, Any] = {
        "contract": _MANIFEST_CONTRACT,
        "schema_version": _SCHEMA_VERSION,
        "producer": {
            "locpipe_version": _runtime_package_version(),
            "distribution_sha256": producer_distribution_sha256,
        },
        "source": {
            "adapter_id": lock.adapter_id,
            "adapter_version": lock.adapter_version,
            "adapter_digest": lock.adapter_digest,
            "config_snapshot_sha256": lock.config_snapshot_sha256,
            "source_lock_sha256": raw_sha256(prepared.source_lock_bytes),
            "reconciliation_sha256": raw_sha256(prepared.reconciliation_bytes),
            "corpus_digest": lock.corpus_digest,
            "snapshot_sha256": lock.snapshot_sha256,
            "segments_sha256": lock.segments_sha256,
            "relations_sha256": lock.relations_sha256,
            "source_locale": lock.source_locale,
            "source_version": lock.source_version,
        },
        "format": {
            "encoding": "UTF-8",
            "record_framing": "RFC8785_JSON_LF",
            "prepared_shard_target_bytes": _SHARD_TARGET_BYTES,
            "shard_name_digits": 6,
            "indexes": "REBUILD_ON_LOAD",
        },
        "counts": {"segments": len(prepared.segments), "relations": len(prepared.relations)},
        "aggregates": {
            "prepared_segments_sha256": segment_aggregate,
            "prepared_relations_sha256": relation_aggregate,
        },
        "files": inventory,
    }
    cache_id = raw_sha256(canonical_json_bytes(manifest))
    return {**manifest, "cache_id": cache_id}


def _write_exclusive(path: Path, payload: bytes | bytearray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _stage_shards(
    staging: Path,
    records: Iterable[bytes],
    *,
    family: str,
    role: str,
) -> tuple[list[dict[str, Any]], str]:
    inventory: list[dict[str, Any]] = []
    aggregate = hashlib.sha256()
    buffer = bytearray()
    record_count = 0
    shard_number = 0

    def close() -> None:
        nonlocal buffer, record_count, shard_number
        if not buffer:
            return
        relative_path = f"prepared/{family}/{shard_number:06d}.jsonl"
        payload = buffer
        _write_exclusive(staging / Path(*relative_path.split("/")), payload)
        inventory.append(_inventory_row(role, relative_path, payload, record_count))
        buffer = bytearray()
        record_count = 0
        shard_number += 1

    for record in records:
        aggregate.update(record)
        if buffer and len(buffer) + len(record) > _SHARD_TARGET_BYTES:
            close()
        buffer.extend(record)
        record_count += 1
    close()
    return inventory, aggregate.hexdigest()


def _stage_cache(
    parent: Path,
    prepared: PreparedSourceAuthorityV0,
) -> tuple[Path, list[dict[str, Any]], str, str]:
    staging: Path | None = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=".locpipe-cache-staging-", dir=parent))
        fixed = (
            ("RECONCILIATION", "authority/reconciliation.json", prepared.reconciliation_bytes, 1),
            ("SOURCE_LOCK", "authority/source-lock.json", prepared.source_lock_bytes, 1),
            ("RAW_SEGMENTS", "raw/segments.jsonl", prepared.segments_bytes, len(prepared.segments)),
        )
        inventory: list[dict[str, Any]] = []
        for role, relative_path, payload, record_count in fixed:
            _write_exclusive(staging / Path(*relative_path.split("/")), payload)
            inventory.append(_inventory_row(role, relative_path, payload, record_count))
        if prepared.relations_bytes is not None:
            relative_path = "raw/relations.jsonl"
            _write_exclusive(staging / Path(*relative_path.split("/")), prepared.relations_bytes)
            inventory.append(
                _inventory_row("RAW_RELATIONS", relative_path, prepared.relations_bytes, len(prepared.relations))
            )
        segment_rows, segment_aggregate = _stage_shards(
            staging,
            (canonical_json_bytes(_segment_record(row)) for row in prepared.segments),
            family="segments",
            role="PREPARED_SEGMENTS",
        )
        relation_rows, relation_aggregate = _stage_shards(
            staging,
            (canonical_json_bytes(_relation_record(row)) for row in prepared.relations),
            family="relations",
            role="PREPARED_RELATIONS",
        )
        inventory.extend(segment_rows)
        inventory.extend(relation_rows)
        inventory.sort(key=lambda row: row["path"])
        return staging, inventory, segment_aggregate, relation_aggregate
    except ContractViolation:
        _cleanup_owned((staging,), parent)
        raise
    except (OSError, ValueError) as error:
        _cleanup_owned((staging,), parent)
        raise ContractViolation(
            ErrorCode.OUTPUT_CONTRACT_VIOLATION,
            "Prepared cache staging failed",
        ) from error


def _flush_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_cleanup(path: Path | None, parent: Path) -> None:
    if path is None:
        return
    try:
        status = os.lstat(path)
    except FileNotFoundError:
        return
    if path.parent.resolve(strict=True) != parent:
        raise OSError("Prepared cache cleanup target is outside the owned parent")
    if stat.S_ISLNK(status.st_mode) or getattr(status, "st_file_attributes", 0) & getattr(
        stat,
        "FILE_ATTRIBUTE_REPARSE_POINT",
        0,
    ):
        raise OSError("Prepared cache cleanup target is a reparse entry")
    shutil.rmtree(path)


def _cleanup_owned(paths: Iterable[Path | None], parent: Path) -> None:
    failed = False
    for path in paths:
        try:
            _safe_cleanup(path, parent)
        except OSError:
            failed = True
    if failed:
        raise ContractViolation(
            ErrorCode.OUTPUT_CONTRACT_VIOLATION,
            "Prepared cache owned-output cleanup failed",
        )


def _read_regular(root: Path, relative_path: str) -> bytes:
    path = resolve_existing_artifact(root, relative_path)
    status = os.lstat(path)
    if not stat.S_ISREG(status.st_mode) or getattr(status, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        raise ContractViolation(ErrorCode.PATH_ESCAPE, "Prepared cache artifact is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (status.st_dev, status.st_ino):
            raise ContractViolation(ErrorCode.PATH_ESCAPE, "Prepared cache artifact identity changed")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def _copy_declared_exclusive(
    staging: Path,
    final: Path,
    row: Mapping[str, Any],
) -> None:
    source_path = resolve_existing_artifact(staging, row["path"])
    source_status = os.lstat(source_path)
    if (
        not stat.S_ISREG(source_status.st_mode)
        or getattr(source_status, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    ):
        raise ContractViolation(ErrorCode.PATH_ESCAPE, "Prepared cache staging artifact is not regular")
    source_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_descriptor = os.open(source_path, source_flags)
    target_path = final / Path(*row["path"].split("/"))
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    target_descriptor: int | None = None
    try:
        opened = os.fstat(source_descriptor)
        if (opened.st_dev, opened.st_ino) != (source_status.st_dev, source_status.st_ino):
            raise ContractViolation(ErrorCode.PATH_ESCAPE, "Prepared cache staging identity changed")
        target_descriptor = os.open(target_path, target_flags, 0o600)
        digest = hashlib.sha256()
        byte_length = 0
        record_count = 0
        with (
            os.fdopen(source_descriptor, "rb", closefd=False) as source_stream,
            os.fdopen(target_descriptor, "wb", closefd=False) as target_stream,
        ):
            while True:
                chunk = source_stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                byte_length += len(chunk)
                record_count += chunk.count(b"\n")
                target_stream.write(chunk)
            if (
                byte_length != row["byte_length"]
                or record_count != row["record_count"]
                or digest.hexdigest() != row["sha256"]
            ):
                raise _hash_mismatch("Prepared cache staging verification failed")
            target_stream.flush()
            os.fsync(target_stream.fileno())
    finally:
        os.close(source_descriptor)
        if target_descriptor is not None:
            os.close(target_descriptor)


def _publish(
    parent: Path,
    staging: Path,
    manifest: Mapping[str, Any],
) -> tuple[Path, bytes]:
    final: Path | None = None
    try:
        final = parent / manifest["cache_id"]
        try:
            os.mkdir(final, 0o700)
        except FileExistsError as error:
            final = None
            raise ContractViolation(
                ErrorCode.OUTPUT_CONTRACT_VIOLATION,
                "Prepared cache destination already exists",
            ) from error
        for row in manifest["files"]:
            _copy_declared_exclusive(staging, final, row)
        manifest_bytes = canonical_json_bytes(dict(manifest))
        _write_exclusive(final / "manifest.json", manifest_bytes)
        for directory in sorted(
            {final, parent, *(path.parent for path in final.rglob("*") if path.is_file())},
            key=lambda value: len(value.parts),
            reverse=True,
        ):
            _flush_directory(directory)
        _cleanup_owned((staging,), parent)
        staging = None
        return final, manifest_bytes
    except ContractViolation:
        _cleanup_owned((staging, final), parent)
        raise
    except (OSError, ValueError) as error:
        _cleanup_owned((staging, final), parent)
        raise ContractViolation(
            ErrorCode.OUTPUT_CONTRACT_VIOLATION,
            "Prepared cache publication failed",
        ) from error


def _parse_manifest(payload: bytes) -> Mapping[str, Any]:
    try:
        value = parse_canonical_json(payload)
    except ContractViolation as error:
        raise _malformed("Prepared cache manifest is not canonical") from error
    manifest = _exact_mapping(value, frozenset({
        "contract", "schema_version", "cache_id", "producer", "source", "format",
        "counts", "aggregates", "files",
    }), "Prepared cache manifest fields are invalid")
    if manifest["contract"] != _MANIFEST_CONTRACT:
        raise ContractViolation(ErrorCode.SCHEMA_UNKNOWN, "Prepared cache manifest contract is unknown")
    if manifest["schema_version"] != _SCHEMA_VERSION:
        raise ContractViolation(
            ErrorCode.SCHEMA_VERSION_UNSUPPORTED,
            "Prepared cache manifest schema version is unsupported",
        )
    _sha(manifest["cache_id"], "Prepared cache identity is invalid")
    producer = _exact_mapping(
        manifest["producer"],
        frozenset({"locpipe_version", "distribution_sha256"}),
        "Prepared cache producer fields are invalid",
    )
    _text(producer["locpipe_version"], "Prepared cache producer version is invalid")
    _sha(producer["distribution_sha256"], "Prepared cache producer distribution SHA is invalid")
    source = _exact_mapping(manifest["source"], frozenset({
        "adapter_id", "adapter_version", "adapter_digest", "config_snapshot_sha256",
        "source_lock_sha256", "reconciliation_sha256", "corpus_digest", "snapshot_sha256",
        "segments_sha256", "relations_sha256", "source_locale", "source_version",
    }), "Prepared cache source fields are invalid")
    for field in ("adapter_id", "adapter_version", "source_locale", "source_version"):
        _text(source[field], f"Prepared cache source {field} is invalid")
    for field in (
        "adapter_digest", "config_snapshot_sha256", "source_lock_sha256",
        "reconciliation_sha256", "corpus_digest", "snapshot_sha256", "segments_sha256",
    ):
        _sha(source[field], f"Prepared cache source {field} is invalid")
    if source["relations_sha256"] is not None:
        _sha(source["relations_sha256"], "Prepared cache source relations SHA is invalid")
    format_value = _exact_mapping(manifest["format"], frozenset({
        "encoding", "record_framing", "prepared_shard_target_bytes", "shard_name_digits", "indexes",
    }), "Prepared cache format fields are invalid")
    if dict(format_value) != {
        "encoding": "UTF-8",
        "record_framing": "RFC8785_JSON_LF",
        "prepared_shard_target_bytes": _SHARD_TARGET_BYTES,
        "shard_name_digits": 6,
        "indexes": "REBUILD_ON_LOAD",
    }:
        raise _malformed("Prepared cache format is invalid")
    counts = _exact_mapping(manifest["counts"], frozenset({"segments", "relations"}), "Prepared cache counts are invalid")
    segment_count = _count(counts["segments"], "Prepared cache segment count is invalid")
    relation_count = _count(counts["relations"], "Prepared cache relation count is invalid")
    aggregates = _exact_mapping(
        manifest["aggregates"],
        frozenset({"prepared_segments_sha256", "prepared_relations_sha256"}),
        "Prepared cache aggregates are invalid",
    )
    _sha(aggregates["prepared_segments_sha256"], "Prepared cache segment aggregate is invalid")
    _sha(aggregates["prepared_relations_sha256"], "Prepared cache relation aggregate is invalid")
    if not isinstance(manifest["files"], list):
        raise _malformed("Prepared cache file inventory is invalid")
    paths: list[str] = []
    roles: list[str] = []
    prepared_counts = {"PREPARED_SEGMENTS": 0, "PREPARED_RELATIONS": 0}
    for raw_row in manifest["files"]:
        row = _exact_mapping(raw_row, frozenset({"role", "path", "byte_length", "record_count", "sha256"}), "Prepared cache inventory row is invalid")
        role = _text(row["role"], "Prepared cache inventory role is invalid")
        if role not in _ROLES:
            raise _malformed("Prepared cache inventory role is invalid")
        path = validate_relative_posix_path(row["path"])
        _count(row["byte_length"], "Prepared cache inventory byte length is invalid")
        record_count = _count(row["record_count"], "Prepared cache inventory record count is invalid")
        _sha(row["sha256"], "Prepared cache inventory SHA is invalid")
        paths.append(path)
        roles.append(role)
        if role in prepared_counts:
            prepared_counts[role] += record_count
    if paths != sorted(paths) or len(paths) != len(set(paths)) or len({path.casefold() for path in paths}) != len(paths):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Prepared cache inventory paths are not sorted and unique")
    fixed = {
        "SOURCE_LOCK": "authority/source-lock.json",
        "RECONCILIATION": "authority/reconciliation.json",
        "RAW_SEGMENTS": "raw/segments.jsonl",
    }
    for role, path in fixed.items():
        if [(candidate_role, candidate_path) for candidate_role, candidate_path in zip(roles, paths) if candidate_role == role] != [(role, path)]:
            raise _malformed("Prepared cache fixed inventory is invalid")
    raw_relations = [path for role, path in zip(roles, paths) if role == "RAW_RELATIONS"]
    if raw_relations != ([] if source["relations_sha256"] is None else ["raw/relations.jsonl"]):
        raise _malformed("Prepared cache relation absence is invalid")
    for family, role, expected_count in (
        ("segments", "PREPARED_SEGMENTS", segment_count),
        ("relations", "PREPARED_RELATIONS", relation_count),
    ):
        shard_paths = [path for candidate_role, path in zip(roles, paths) if candidate_role == role]
        expected_paths = [f"prepared/{family}/{index:06d}.jsonl" for index in range(len(shard_paths))]
        if shard_paths != expected_paths or any(_SHARD_NAME_RE.fullmatch(path.removeprefix("prepared/")) is None for path in shard_paths):
            raise _malformed("Prepared cache shard names are invalid")
        if prepared_counts[role] != expected_count or bool(shard_paths) != bool(expected_count):
            raise _malformed("Prepared cache shard counts are invalid")
    projection = dict(manifest)
    del projection["cache_id"]
    if raw_sha256(canonical_json_bytes(projection)) != manifest["cache_id"]:
        raise _hash_mismatch("Prepared cache identity differs from manifest")
    return manifest


def _receipt(manifest: Mapping[str, Any], manifest_bytes: bytes) -> PreparedSourceCacheReceiptV0:
    producer = manifest["producer"]
    source = manifest["source"]
    counts = manifest["counts"]
    files = manifest["files"]
    return PreparedSourceCacheReceiptV0(
        manifest["cache_id"],
        raw_sha256(manifest_bytes),
        producer["locpipe_version"],
        producer["distribution_sha256"],
        source["adapter_id"],
        source["adapter_version"],
        source["adapter_digest"],
        source["config_snapshot_sha256"],
        source["source_lock_sha256"],
        source["reconciliation_sha256"],
        source["corpus_digest"],
        source["snapshot_sha256"],
        source["segments_sha256"],
        source["relations_sha256"],
        counts["segments"],
        counts["relations"],
        len(files) + 1,
        len(manifest_bytes) + sum(row["byte_length"] for row in files),
    )


def _validate_tree(root: Path, manifest: Mapping[str, Any]) -> None:
    expected_files = {row["path"] for row in manifest["files"]} | {"manifest.json"}
    expected_dirs = {str(Path(path).parent).replace("\\", "/") for path in expected_files if "/" in path}
    expected_dirs |= {
        str(parent).replace("\\", "/")
        for path in tuple(expected_dirs)
        for parent in Path(path).parents
        if str(parent) != "."
    }
    actual_files: set[str] = set()
    actual_dirs: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        status = os.lstat(path)
        if path.is_symlink() or getattr(status, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ContractViolation(ErrorCode.PATH_ESCAPE, "Prepared cache inventory crosses a reparse point")
        if stat.S_ISDIR(status.st_mode):
            actual_dirs.add(relative)
        elif stat.S_ISREG(status.st_mode):
            actual_files.add(relative)
        else:
            raise ContractViolation(ErrorCode.PATH_ESCAPE, "Prepared cache inventory contains a non-regular entry")
    if actual_files != expected_files or actual_dirs != expected_dirs:
        raise _malformed("Prepared cache inventory is incomplete or unexpected")


def _read_and_validate_inventory(
    cache_root: Path,
    expected: PreparedSourceCacheReceiptV0,
    *,
    verify_payloads: bool,
) -> tuple[Path, Mapping[str, Any], bytes]:
    if type(expected) is not PreparedSourceCacheReceiptV0:
        raise _malformed("Prepared cache expectation has the wrong type")
    root = resolve_artifact_root(cache_root)
    try:
        manifest_status = os.lstat(root / "manifest.json")
    except FileNotFoundError as error:
        raise _malformed("Prepared cache manifest is missing") from error
    except OSError as error:
        raise ContractViolation(ErrorCode.PATH_ESCAPE, "Prepared cache manifest is inaccessible") from error
    if (
        not stat.S_ISREG(manifest_status.st_mode)
        or getattr(manifest_status, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    ):
        raise ContractViolation(ErrorCode.PATH_ESCAPE, "Prepared cache manifest is not a regular file")
    manifest_bytes = _read_regular(root, "manifest.json")
    if raw_sha256(manifest_bytes) != expected.manifest_sha256:
        raise _binding("Prepared cache manifest differs from expected receipt")
    manifest = _parse_manifest(manifest_bytes)
    if root.name != manifest["cache_id"]:
        raise _binding("Prepared cache directory name differs from identity")
    if manifest["producer"]["locpipe_version"] != _runtime_package_version():
        raise _binding("Prepared cache package version differs from runtime")
    if _receipt(manifest, manifest_bytes) != expected:
        raise _binding("Prepared cache manifest differs from expected receipt")
    _validate_tree(root, manifest)
    if verify_payloads:
        for row in manifest["files"]:
            _declared_payload(root, row)
    return root, manifest, manifest_bytes


def _declared_payload(root: Path, row: Mapping[str, Any]) -> bytes:
    payload = _read_regular(root, row["path"])
    if len(payload) != row["byte_length"] or raw_sha256(payload) != row["sha256"]:
        raise _hash_mismatch("Prepared cache file bytes differ from manifest")
    if payload.count(b"\n") != row["record_count"]:
        raise _malformed("Prepared cache record framing differs from manifest")
    return payload


def _parse_reconciliation(
    payload: bytes,
    *,
    current_branch_ids: tuple[str, ...],
) -> SourceReconciliationV0:
    try:
        value = parse_canonical_json(payload)
    except ContractViolation as error:
        raise _malformed("Prepared cache reconciliation is not canonical") from error
    raw = _exact_mapping(value, frozenset({
        "contract", "previous_corpus_digest", "current_corpus_digest", "events",
        "tombstones", "target_validity", "summary",
    }), "Prepared cache reconciliation fields are invalid")
    if raw["contract"] != "locpipe.content.reconciliation/v0":
        raise _malformed("Prepared cache reconciliation contract is invalid")
    previous = raw["previous_corpus_digest"]
    if previous is not None:
        _sha(previous, "Prepared cache previous corpus digest is invalid")
    _sha(raw["current_corpus_digest"], "Prepared cache current corpus digest is invalid")
    if not isinstance(raw["events"], list) or not isinstance(raw["tombstones"], list) or not isinstance(raw["target_validity"], list):
        raise _malformed("Prepared cache reconciliation collections are invalid")
    events: list[ReconciliationEventV0] = []
    event_keys: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = []
    seen_old: set[str] = set()
    seen_new: set[str] = set()
    for value in raw["events"]:
        row = _exact_mapping(value, frozenset({"state", "old_ids", "new_ids"}), "Prepared cache reconciliation event is invalid")
        try:
            state = ReconciliationStateV0(row["state"])
        except (TypeError, ValueError) as error:
            raise _malformed("Prepared cache reconciliation state is invalid") from error
        if not isinstance(row["old_ids"], list) or not isinstance(row["new_ids"], list):
            raise _malformed("Prepared cache reconciliation event IDs are invalid")
        old_ids = tuple(_text(value, "Prepared cache reconciliation event ID is invalid") for value in row["old_ids"])
        new_ids = tuple(_text(value, "Prepared cache reconciliation event ID is invalid") for value in row["new_ids"])
        if old_ids != tuple(sorted(set(old_ids))) or new_ids != tuple(sorted(set(new_ids))):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Prepared cache reconciliation event IDs are not sorted and unique")
        valid_sides = (
            state in {
                ReconciliationStateV0.UNCHANGED,
                ReconciliationStateV0.CHANGED,
                ReconciliationStateV0.MOVED,
            }
            and len(old_ids) == 1
            and old_ids == new_ids
        ) or (
            state is ReconciliationStateV0.ADDED
            and not old_ids
            and len(new_ids) == 1
        ) or (
            state is ReconciliationStateV0.REMOVED
            and len(old_ids) == 1
            and not new_ids
        ) or (
            state is ReconciliationStateV0.SPLIT
            and len(old_ids) == 1
            and len(new_ids) >= 2
        ) or (
            state is ReconciliationStateV0.MERGED
            and len(old_ids) >= 2
            and len(new_ids) == 1
        ) or (
            state is ReconciliationStateV0.SUPERSEDES
            and bool(old_ids)
            and bool(new_ids)
        )
        if not valid_sides:
            raise _malformed("Prepared cache reconciliation event sides are invalid")
        if seen_old.intersection(old_ids) or seen_new.intersection(new_ids):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Prepared cache reconciliation events overlap")
        seen_old.update(old_ids)
        seen_new.update(new_ids)
        event_keys.append((state.value, old_ids, new_ids))
        events.append(ReconciliationEventV0(state, old_ids, new_ids))
    if event_keys != sorted(set(event_keys)):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Prepared cache reconciliation events are not sorted and unique")
    tombstones = tuple(_text(value, "Prepared cache tombstone is invalid") for value in raw["tombstones"])
    if tombstones != tuple(sorted(set(tombstones))):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Prepared cache tombstones are not sorted and unique")
    expected_tombstones = tuple(sorted(
        stable_id
        for event in events
        if event.state in {
            ReconciliationStateV0.REMOVED,
            ReconciliationStateV0.SPLIT,
            ReconciliationStateV0.MERGED,
            ReconciliationStateV0.SUPERSEDES,
        }
        for stable_id in event.old_ids
    ))
    if tombstones != expected_tombstones:
        raise _binding("Prepared cache reconciliation tombstones differ from events")
    if tuple(sorted(seen_new)) != current_branch_ids:
        raise _binding("Prepared cache reconciliation events differ from current source IDs")
    if previous is None and (
        tombstones
        or any(event.state is not ReconciliationStateV0.ADDED for event in events)
    ):
        raise _binding("Prepared cache initial reconciliation contains historical events")
    targets: list[TargetValidityV0] = []
    target_ids: list[str] = []
    for value in raw["target_validity"]:
        row = _exact_mapping(value, frozenset({"target_id", "state", "invalid_source_ids"}), "Prepared cache target validity is invalid")
        try:
            state = TargetValidityStateV0(row["state"])
        except (TypeError, ValueError) as error:
            raise _malformed("Prepared cache target validity state is invalid") from error
        if not isinstance(row["invalid_source_ids"], list):
            raise _malformed("Prepared cache target validity IDs are invalid")
        invalid = tuple(_text(item, "Prepared cache target validity ID is invalid") for item in row["invalid_source_ids"])
        if invalid != tuple(sorted(set(invalid))):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Prepared cache target validity IDs are not sorted and unique")
        if (state is TargetValidityStateV0.VALID) != (not invalid):
            raise _malformed("Prepared cache target validity state and invalid IDs disagree")
        target_id = _text(row["target_id"], "Prepared cache target ID is invalid")
        target_ids.append(target_id)
        targets.append(TargetValidityV0(target_id, state, invalid))
    if target_ids != sorted(set(target_ids)):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Prepared cache target validity rows are not sorted and unique")
    reconciliation = SourceReconciliationV0(previous, raw["current_corpus_digest"], tuple(events), tombstones, tuple(targets))
    if canonical_json_bytes(reconciliation.as_dict()) != payload:
        raise _hash_mismatch("Prepared cache reconciliation summary or order is invalid")
    return reconciliation


def _prepared_segment_from_value(value: Mapping[str, Any]) -> tuple[SourceSegmentV0, PreparedSourceSegmentV0]:
    row = _exact_mapping(value, frozenset({
        "contract", "identity", "content_type", "source_revision_sha", "locator_sha256", "payload", "constraints",
    }), "Prepared cache segment fields are invalid")
    if row["contract"] != _SEGMENT_CONTRACT or not isinstance(row["identity"], Mapping) or not isinstance(row["constraints"], Mapping):
        raise _malformed("Prepared cache segment contract is invalid")
    identity = BranchIdentity.from_dict(row["identity"])
    content_type = _text(row["content_type"], "Prepared cache segment content type is invalid")
    revision = _sha(row["source_revision_sha"], "Prepared cache segment revision is invalid")
    locator = _sha(row["locator_sha256"], "Prepared cache segment locator is invalid")
    if source_revision_sha(
        identity=identity,
        content_type=content_type,
        payload=row["payload"],
        constraints=row["constraints"],
    ) != revision:
        raise _hash_mismatch("Prepared cache segment revision differs from content")
    prepared = PreparedSourceSegmentV0(
        identity,
        content_type,
        revision,
        locator,
        canonical_value_bytes(row["payload"]),
        canonical_value_bytes(row["constraints"]),
        row["payload"] if type(row["payload"]) is str else None,
    )
    return SourceSegmentV0(identity, content_type, revision, locator), prepared


def _parse_prepared_rows(
    root: Path,
    manifest: Mapping[str, Any],
    lock: object,
) -> tuple[tuple[SourceSegmentV0, ...], tuple[PreparedSourceSegmentV0, ...], tuple[Mapping[str, Any], ...], tuple[PreparedSourceRelationV0, ...]]:
    segments: list[SourceSegmentV0] = []
    prepared_segments: list[PreparedSourceSegmentV0] = []
    segment_hash = hashlib.sha256()
    relation_envelopes: list[Mapping[str, Any]] = []
    prepared_relations: list[PreparedSourceRelationV0] = []
    relation_hash = hashlib.sha256()
    last_relation_digest: str | None = None
    for row in manifest["files"]:
        if row["role"] not in {"PREPARED_SEGMENTS", "PREPARED_RELATIONS"}:
            continue
        payload = _declared_payload(root, row)
        try:
            values = parse_canonical_jsonl(
                payload,
                sort_key=(
                    (lambda value: display_id(BranchIdentity.from_dict(value["identity"])))
                    if row["role"] == "PREPARED_SEGMENTS"
                    else (lambda value: value["digest"])
                ),
            )
        except (ContractViolation, KeyError, TypeError) as error:
            raise _malformed("Prepared cache shard is invalid") from error
        if row["role"] == "PREPARED_SEGMENTS":
            segment_hash.update(payload)
            for value in values:
                source, prepared = _prepared_segment_from_value(value)
                segments.append(source)
                prepared_segments.append(prepared)
        else:
            relation_hash.update(payload)
            for value in values:
                raw = _exact_mapping(value, frozenset({
                    "contract", "digest", "relation_type", "envelope", "branch_ids", "logical_ids",
                }), "Prepared cache relation fields are invalid")
                if raw["contract"] != _RELATION_CONTRACT or not isinstance(raw["envelope"], Mapping):
                    raise _malformed("Prepared cache relation contract is invalid")
                if not isinstance(raw["branch_ids"], list) or not isinstance(raw["logical_ids"], list):
                    raise _malformed("Prepared cache relation projections are invalid")
                digest = _sha(raw["digest"], "Prepared cache relation digest is invalid")
                if last_relation_digest is not None and digest <= last_relation_digest:
                    if digest == last_relation_digest:
                        raise ContractViolation(
                            ErrorCode.DUPLICATE_IDENTITY,
                            "Prepared cache relation digests are duplicated across shards",
                        )
                    raise _hash_mismatch("Prepared cache relation digest order crosses shard boundary")
                last_relation_digest = digest
                validate_envelope(raw["envelope"])
                expected = _prepared_relation(raw["envelope"])
                branch_ids = tuple(raw["branch_ids"])
                logical_ids = tuple(tuple(value) if isinstance(value, list) else () for value in raw["logical_ids"])
                if (
                    digest != expected.digest
                    or raw["relation_type"] != expected.relation_type
                    or branch_ids != expected.branch_ids
                    or logical_ids != expected.logical_ids
                ):
                    raise _hash_mismatch("Prepared cache relation projection differs from envelope")
                relation_envelopes.append(raw["envelope"])
                prepared_relations.append(expected)
    if tuple(row.stable_id for row in segments) != lock.branch_ids:
        raise _hash_mismatch("Prepared cache segment order differs from source lock")
    if segment_hash.hexdigest() != manifest["aggregates"]["prepared_segments_sha256"]:
        raise _hash_mismatch("Prepared cache segment aggregate differs from manifest")
    if relation_hash.hexdigest() != manifest["aggregates"]["prepared_relations_sha256"]:
        raise _hash_mismatch("Prepared cache relation aggregate differs from manifest")
    validate_relation_set(
        relation_envelopes,
        branch_identities=[row.identity for row in segments],
        locales={lock.source_locale},
    )
    return tuple(segments), tuple(prepared_segments), tuple(relation_envelopes), tuple(prepared_relations)


def build_prepared_source_cache_v0(
    authority: PreparedSourceAuthorityV0,
    destination_parent: Path,
    *,
    producer_distribution_sha256: str,
) -> PreparedSourceCacheReceiptV0:
    prepared = _validate_authority(authority)
    distribution_sha = _sha(
        producer_distribution_sha256,
        "Prepared cache producer distribution SHA is invalid",
    )
    parent = resolve_artifact_root(destination_parent)
    staging, inventory, segment_aggregate, relation_aggregate = _stage_cache(parent, prepared)
    try:
        manifest = _manifest_value(
            prepared,
            distribution_sha,
            inventory,
            segment_aggregate,
            relation_aggregate,
        )
        cache_root, manifest_bytes = _publish(parent, staging, manifest)
    except ContractViolation:
        _cleanup_owned((staging,), parent)
        raise
    except (OSError, ValueError) as error:
        _cleanup_owned((staging,), parent)
        raise ContractViolation(
            ErrorCode.OUTPUT_CONTRACT_VIOLATION,
            "Prepared cache publication failed",
        ) from error
    receipt = _receipt(manifest, manifest_bytes)
    try:
        _read_and_validate_inventory(cache_root, receipt, verify_payloads=True)
    except ContractViolation:
        _cleanup_owned((cache_root,), parent)
        raise
    except OSError as error:
        _cleanup_owned((cache_root,), parent)
        raise ContractViolation(
            ErrorCode.OUTPUT_CONTRACT_VIOLATION,
            "Prepared cache final verification failed",
        ) from error
    return receipt


def load_prepared_source_authority_v0(
    cache_root: Path,
    *,
    expected: PreparedSourceCacheReceiptV0,
) -> PreparedSourceAuthorityV0:
    root, manifest, _manifest_bytes = _read_and_validate_inventory(
        cache_root,
        expected,
        verify_payloads=False,
    )
    by_role = {row["role"]: row for row in manifest["files"] if row["role"] not in {"PREPARED_SEGMENTS", "PREPARED_RELATIONS"}}
    source_lock_bytes = _declared_payload(root, by_role["SOURCE_LOCK"])
    reconciliation_bytes = _declared_payload(root, by_role["RECONCILIATION"])
    segments_bytes = _declared_payload(root, by_role["RAW_SEGMENTS"])
    relation_row = next((row for row in manifest["files"] if row["role"] == "RAW_RELATIONS"), None)
    relations_bytes = None if relation_row is None else _declared_payload(root, relation_row)
    lock = parse_source_lock_v0(source_lock_bytes)
    source = manifest["source"]
    if (
        raw_sha256(source_lock_bytes) != source["source_lock_sha256"]
        or raw_sha256(segments_bytes) != lock.segments_sha256
        or (None if relations_bytes is None else raw_sha256(relations_bytes)) != lock.relations_sha256
        or lock.adapter_id != source["adapter_id"]
        or lock.adapter_version != source["adapter_version"]
        or lock.adapter_digest != source["adapter_digest"]
        or lock.config_snapshot_sha256 != source["config_snapshot_sha256"]
        or lock.corpus_digest != source["corpus_digest"]
        or lock.snapshot_sha256 != source["snapshot_sha256"]
        or lock.segments_sha256 != source["segments_sha256"]
        or lock.relations_sha256 != source["relations_sha256"]
        or lock.source_locale != source["source_locale"]
        or lock.source_version != source["source_version"]
    ):
        raise _binding("Prepared cache source authority differs from manifest")
    reconciliation = _parse_reconciliation(
        reconciliation_bytes,
        current_branch_ids=lock.branch_ids,
    )
    if (
        raw_sha256(reconciliation_bytes) != source["reconciliation_sha256"]
        or reconciliation.current_corpus_digest != lock.corpus_digest
    ):
        raise _binding("Prepared cache reconciliation differs from source authority")
    segments, prepared_segments, relation_envelopes, prepared_relations = _parse_prepared_rows(
        root,
        manifest,
        lock,
    )
    corpus = LoadedSourceCorpusV0(lock, segments, relation_envelopes)
    return _bind_prepared_source_authority_v0(
        corpus,
        reconciliation,
        source_lock_bytes=source_lock_bytes,
        reconciliation_bytes=reconciliation_bytes,
        segments_bytes=segments_bytes,
        relations_bytes=relations_bytes,
        segments=prepared_segments,
        relations=prepared_relations,
    )
