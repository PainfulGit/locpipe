from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from locpipe.contracts.v0 import (
    AdapterDescriptorV0,
    ArtifactDeclarationV0,
    BranchIdentity,
    Capability,
    ContractViolation,
    ErrorCode,
    OperationRequestV0,
    display_id,
    parse_canonical_json,
    parse_canonical_jsonl,
    semantic_sha256,
    validate_envelope,
    validate_relation_set,
)
from locpipe.contracts.v0.artifacts import resolve_existing_artifact
from locpipe.contracts.v0.artifacts import has_reparse_component, resolve_artifact_root

from ._models import AdapterCorpusSummaryV0


SOURCE_SNAPSHOT = "source_snapshot.json"
SEGMENTS = "segments.jsonl"
RELATIONS = "relations.jsonl"


def _descriptor_data(descriptor: AdapterDescriptorV0) -> dict[str, Any]:
    return {
        "adapter_id": descriptor.adapter_id,
        "version": descriptor.version,
        "digest": descriptor.digest,
        "capabilities": [capability.value for capability in descriptor.capabilities],
    }


def adapter_output_declarations_v0(*, include_relations: bool = False) -> tuple[ArtifactDeclarationV0, ...]:
    paths = [SOURCE_SNAPSHOT, SEGMENTS]
    if include_relations:
        paths.append(RELATIONS)
    return tuple(ArtifactDeclarationV0(path, "raw") for path in sorted(paths))


def _validate_staging_shape(staging_root: Path, expected_paths: tuple[str, ...]) -> Path:
    root = resolve_artifact_root(staging_root)
    actual: list[str] = []
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root).as_posix()
        if candidate.is_symlink() or has_reparse_component(root, candidate):
            raise ContractViolation(ErrorCode.PATH_ESCAPE, f"Adapter output crosses a link or reparse point: {relative}")
        if not candidate.is_file():
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, f"Adapter output is not a regular file: {relative}")
        actual.append(relative)
    if tuple(sorted(actual)) != expected_paths:
        raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Adapter staging entries differ from declared corpus outputs")
    return root


def _segment_identity(envelope: Mapping[str, Any]) -> BranchIdentity:
    if envelope.get("kind") != "source_branch":
        raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Adapter segments must contain only source_branch records")
    data = envelope.get("data")
    if not isinstance(data, Mapping) or not isinstance(data.get("identity"), Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Segment identity is missing")
    return BranchIdentity.from_dict(data["identity"])


def validate_adapter_corpus_v0(
    request: OperationRequestV0,
    staging_root: Path,
    descriptor: AdapterDescriptorV0,
) -> AdapterCorpusSummaryV0:
    if request.capability is not Capability.EXTRACT_IMPORT:
        raise ContractViolation(ErrorCode.CAPABILITY_FORBIDDEN, "Adapter corpus validation requires extract_import")
    if len(request.inputs) != 1 or request.inputs[0].hash_domain not in {"raw", "directory_manifest"}:
        raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "extract_import requires exactly one raw source input")
    include_relations = any(row.path == RELATIONS for row in request.declared_outputs)
    expected = adapter_output_declarations_v0(include_relations=include_relations)
    if request.declared_outputs != expected:
        raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Adapter output declarations differ from the corpus contract")
    expected_paths = tuple(row.path for row in expected)
    staging_root = _validate_staging_shape(staging_root, expected_paths)

    snapshot_path = resolve_existing_artifact(staging_root, SOURCE_SNAPSHOT)
    segments_path = resolve_existing_artifact(staging_root, SEGMENTS)
    snapshot = parse_canonical_json(snapshot_path.read_bytes())
    if not isinstance(snapshot, Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source snapshot must be an object")
    validate_envelope(snapshot)
    if snapshot.get("kind") != "source_snapshot":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "source_snapshot.json has the wrong kind")

    segments = parse_canonical_jsonl(
        segments_path.read_bytes(),
        sort_key=lambda row: display_id(_segment_identity(row)),
    )
    identities: list[BranchIdentity] = []
    for segment in segments:
        validate_envelope(segment)
        identities.append(_segment_identity(segment))
    branch_ids = tuple(display_id(identity) for identity in identities)
    if len(branch_ids) != len(set(branch_ids)):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Adapter segment stable IDs must be unique")

    data = snapshot["data"]
    if data["adapter"] != _descriptor_data(descriptor):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Source snapshot adapter pin differs from the bound descriptor")
    source = request.inputs[0]
    if data["source_raw_sha256"] != source.sha256:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Source snapshot SHA differs from the declared source input")
    if tuple(data["branch_ids"]) != branch_ids:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Source snapshot branch_ids differ from segments")
    locales = {identity.locale for identity in identities}
    if locales != {data["source_locale"]}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source snapshot locale differs from segments")

    relation_count = 0
    if include_relations:
        relation_path = resolve_existing_artifact(staging_root, RELATIONS)
        relations = parse_canonical_jsonl(
            relation_path.read_bytes(),
            sort_key=lambda row: semantic_sha256(row),
        )
        relation_count = validate_relation_set(
            relations,
            branch_identities=identities,
            locales=locales,
        )

    return AdapterCorpusSummaryV0(
        source_input_path=source.path,
        source_raw_sha256=source.sha256,
        source_locale=data["source_locale"],
        source_version=data["source_version"],
        snapshot_id=data["snapshot_id"],
        branch_ids=branch_ids,
        segment_count=len(segments),
        relation_count=relation_count,
        output_paths=tuple(row.path for row in request.declared_outputs),
    )
