from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from locpipe.contracts.v0 import (
    AdapterDescriptorV0,
    BranchIdentity,
    Capability,
    ContractViolation,
    ErrorCode,
    canonical_json_bytes,
    display_id,
    parse_canonical_json,
    parse_canonical_jsonl,
    raw_sha256,
    semantic_sha256,
    source_revision_sha,
    validate_envelope,
    validate_relation_set,
)
from locpipe.contracts.v0.artifacts import resolve_existing_artifact

from ._models import SourceLockV0, SourceSegmentV0


@dataclass(frozen=True)
class LoadedSourceCorpusV0:
    lock: SourceLockV0
    segments: tuple[SourceSegmentV0, ...]
    relation_envelopes: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.lock, SourceLockV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Loaded corpus lock is invalid")
        rows = tuple(self.segments)
        if any(not isinstance(row, SourceSegmentV0) for row in rows):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Loaded corpus segments are invalid")
        if tuple(row.stable_id for row in rows) != self.lock.branch_ids:
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "Loaded corpus segments differ from source lock")
        if {row.identity.locale for row in rows} != {self.lock.source_locale}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Loaded corpus locale differs from source lock")
        object.__setattr__(self, "segments", rows)
        object.__setattr__(self, "relation_envelopes", tuple(self.relation_envelopes))


def parse_source_lock_v0(payload: bytes) -> SourceLockV0:
    value = parse_canonical_json(payload)
    if not isinstance(value, Mapping) or set(value) != {
        "contract", "config_snapshot_sha256", "adapter", "snapshot_sha256",
        "segments_sha256", "relations_sha256", "source_locale",
        "source_version", "branch_ids", "corpus_digest",
    }:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source lock fields are invalid")
    if value["contract"] != "locpipe.content.source-lock/v0":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source lock contract is invalid")
    adapter = value["adapter"]
    if not isinstance(adapter, Mapping) or set(adapter) != {"adapter_id", "version", "digest"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source lock adapter pin is invalid")
    if not isinstance(value["branch_ids"], list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source lock branch IDs are invalid")
    lock = SourceLockV0(
        value["config_snapshot_sha256"],
        adapter["adapter_id"],
        adapter["version"],
        adapter["digest"],
        value["snapshot_sha256"],
        value["segments_sha256"],
        value["relations_sha256"],
        value["source_locale"],
        value["source_version"],
        tuple(value["branch_ids"]),
        value["corpus_digest"],
    )
    projection = {
        "snapshot_sha256": lock.snapshot_sha256,
        "segments_sha256": lock.segments_sha256,
        "relations_sha256": lock.relations_sha256,
        "config_snapshot_sha256": lock.config_snapshot_sha256,
    }
    if semantic_sha256(projection) != lock.corpus_digest:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Source lock corpus digest is invalid")
    return lock


def validate_source_lock_v0(payload: bytes, corpus: LoadedSourceCorpusV0) -> SourceLockV0:
    lock = parse_source_lock_v0(payload)
    if canonical_json_bytes(lock.as_dict()) != payload or lock != corpus.lock:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Published source lock differs from corpus artifacts")
    return lock


def _descriptor_from_snapshot(root: Path, snapshot_path: str) -> AdapterDescriptorV0:
    snapshot = parse_canonical_json(resolve_existing_artifact(root, snapshot_path).read_bytes())
    if not isinstance(snapshot, Mapping) or not isinstance(snapshot.get("data"), Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source snapshot adapter pin is missing")
    adapter = snapshot["data"].get("adapter")
    if not isinstance(adapter, Mapping) or set(adapter) != {"adapter_id", "version", "digest", "capabilities"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source snapshot adapter pin is invalid")
    if not isinstance(adapter["capabilities"], list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source snapshot capabilities are invalid")
    try:
        capabilities = tuple(Capability(value) for value in adapter["capabilities"])
    except ValueError as error:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source snapshot capability is invalid") from error
    return AdapterDescriptorV0(adapter["adapter_id"], adapter["version"], adapter["digest"], capabilities)


def _identity(envelope: Mapping[str, Any]) -> BranchIdentity:
    if envelope.get("kind") != "source_branch" or not isinstance(envelope.get("data"), Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Corpus contains a non-source segment")
    data = envelope["data"]
    if not isinstance(data.get("identity"), Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source identity is missing")
    return BranchIdentity.from_dict(data["identity"])


def load_source_corpus_v0(
    root: Path,
    *,
    snapshot_path: str,
    segments_path: str,
    relations_path: str | None,
    descriptor: AdapterDescriptorV0,
    config_snapshot_sha256: str,
) -> LoadedSourceCorpusV0:
    snapshot_bytes = resolve_existing_artifact(root, snapshot_path).read_bytes()
    segments_bytes = resolve_existing_artifact(root, segments_path).read_bytes()
    relations_bytes = None if relations_path is None else resolve_existing_artifact(root, relations_path).read_bytes()
    snapshot = parse_canonical_json(snapshot_bytes)
    if not isinstance(snapshot, Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source snapshot must be an object")
    validate_envelope(snapshot)
    if snapshot.get("kind") != "source_snapshot":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source snapshot has the wrong kind")
    envelopes = parse_canonical_jsonl(segments_bytes, sort_key=lambda row: display_id(_identity(row)))
    segments: list[SourceSegmentV0] = []
    identities: list[BranchIdentity] = []
    for envelope in envelopes:
        validate_envelope(envelope)
        identity = _identity(envelope)
        data = envelope["data"]
        expected_revision = source_revision_sha(
            identity=identity,
            content_type=data["content_type"],
            payload=data["payload"],
            constraints=data["constraints"],
        )
        if data["source_revision_sha"] != expected_revision:
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "Source revision differs from segment content")
        identities.append(identity)
        segments.append(
            SourceSegmentV0(
                identity,
                data["content_type"],
                data["source_revision_sha"],
                semantic_sha256(data["locator"]),
            )
        )
    branch_ids = tuple(display_id(row) for row in identities)
    data = snapshot["data"]
    expected_adapter = {
        "adapter_id": descriptor.adapter_id,
        "version": descriptor.version,
        "digest": descriptor.digest,
        "capabilities": [capability.value for capability in descriptor.capabilities],
    }
    if data["adapter"] != expected_adapter:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Source snapshot adapter pin drift")
    if tuple(data["branch_ids"]) != branch_ids:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Source snapshot branch IDs differ from segments")
    if {row.locale for row in identities} != {data["source_locale"]}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source locale differs from segments")
    relations: tuple[Mapping[str, Any], ...] = ()
    if relations_bytes is not None:
        parsed = parse_canonical_jsonl(relations_bytes, sort_key=lambda row: semantic_sha256(row))
        validate_relation_set(parsed, branch_identities=identities, locales={data["source_locale"]})
        relations = tuple(parsed)
    projection = {
        "snapshot_sha256": raw_sha256(snapshot_bytes),
        "segments_sha256": raw_sha256(segments_bytes),
        "relations_sha256": None if relations_bytes is None else raw_sha256(relations_bytes),
        "config_snapshot_sha256": config_snapshot_sha256,
    }
    lock = SourceLockV0(
        config_snapshot_sha256,
        descriptor.adapter_id,
        descriptor.version,
        descriptor.digest,
        projection["snapshot_sha256"],
        projection["segments_sha256"],
        projection["relations_sha256"],
        data["source_locale"],
        data["source_version"],
        branch_ids,
        semantic_sha256(projection),
    )
    return LoadedSourceCorpusV0(lock, tuple(segments), relations)


def load_accepted_source_corpus_v0(
    root: Path,
    *,
    snapshot_path: str,
    segments_path: str,
    relations_path: str | None,
    source_lock_path: str,
    descriptor: AdapterDescriptorV0 | None = None,
    expected_config_snapshot_sha256: str | None = None,
) -> LoadedSourceCorpusV0:
    lock_bytes = resolve_existing_artifact(root, source_lock_path).read_bytes()
    lock = parse_source_lock_v0(lock_bytes)
    effective_descriptor = descriptor or _descriptor_from_snapshot(root, snapshot_path)
    if expected_config_snapshot_sha256 is not None and lock.config_snapshot_sha256 != expected_config_snapshot_sha256:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Source lock config snapshot differs from expected context")
    corpus = load_source_corpus_v0(
        root,
        snapshot_path=snapshot_path,
        segments_path=segments_path,
        relations_path=relations_path,
        descriptor=effective_descriptor,
        config_snapshot_sha256=lock.config_snapshot_sha256,
    )
    validate_source_lock_v0(lock_bytes, corpus)
    return corpus
