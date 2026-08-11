from __future__ import annotations

import hashlib
import shutil
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from locpipe.adapters.v0 import (
    ReadOnlyAdapterV0,
    adapter_output_declarations_v0,
    bind_read_only_adapter_v0,
    validate_adapter_corpus_v0,
)
from locpipe.contracts.v0 import (
    ArtifactHashV0,
    Capability,
    ContractViolation,
    ErrorCode,
    OperationRequestV0,
    canonical_json_bytes,
    execute_bound_operation,
    semantic_sha256,
    strict_loads,
)

from .common import descriptor_data, directory_manifest_sha256


MANIFEST_FIELDS = {
    "schema_version", "fixture_id", "classification", "provenance", "adapter",
    "input", "outputs", "expected",
}


def _fail(detail: str) -> ContractViolation:
    return ContractViolation(ErrorCode.MALFORMED_ARTIFACT, detail)


def load_fixture_manifest_v0(payload: bytes) -> Mapping[str, Any]:
    value = strict_loads(payload)
    if not isinstance(value, Mapping) or set(value) != MANIFEST_FIELDS:
        raise _fail("Invalid conformance fixture manifest fields")
    if value["schema_version"] != 1 or value["classification"] != "PUBLIC_SYNTHETIC":
        raise _fail("Unsupported conformance fixture manifest")
    provenance = value["provenance"]
    if not isinstance(provenance, Mapping) or provenance != {
        "contains_game_text": False,
        "spdx_license": "Apache-2.0",
    }:
        raise _fail("Invalid public fixture provenance")
    adapter = value["adapter"]
    if not isinstance(adapter, Mapping) or set(adapter) != {"adapter_id", "version", "digest", "capabilities"}:
        raise _fail("Invalid fixture adapter pin")
    source = value["input"]
    if not isinstance(source, Mapping) or set(source) != {"fixture_path", "operation_path", "hash_domain", "sha256"}:
        raise _fail("Invalid fixture input declaration")
    outputs = value["outputs"]
    if not isinstance(outputs, list) or not outputs:
        raise _fail("Fixture outputs must be non-empty")
    paths = []
    for output in outputs:
        if not isinstance(output, Mapping) or set(output) != {"path", "sha256"}:
            raise _fail("Invalid fixture output declaration")
        paths.append(output["path"])
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise _fail("Fixture outputs must be unique and sorted")
    expected = value["expected"]
    if not isinstance(expected, Mapping) or set(expected) != {"segment_count", "relation_count"}:
        raise _fail("Invalid fixture expected counts")
    return value


def _binding(descriptor) -> dict[str, object]:
    return {
        "schema_id": "urn:locpipe:contracts:v0:binding",
        "schema_version": "0.1.0-draft.2",
        "kind": "binding_set",
        "data": {"adapter": descriptor_data(descriptor), "modules": []},
    }


def _copy_input(source: Path, destination: Path, *, reverse_creation: bool) -> None:
    if source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
        return
    destination.mkdir(parents=True)
    files = [path for path in source.rglob("*") if path.is_file()]
    for path in sorted(files, reverse=reverse_creation):
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())


def run_public_fixture_v0(
    fixture_root: Path,
    adapter: ReadOnlyAdapterV0,
    *,
    reverse_creation: bool = False,
) -> dict[str, object]:
    manifest = load_fixture_manifest_v0((fixture_root / "manifest.json").read_bytes())
    if descriptor_data(adapter.descriptor) != manifest["adapter"]:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fixture adapter pin differs from implementation")
    source_spec = manifest["input"]
    fixture_source = fixture_root / source_spec["fixture_path"]
    with tempfile.TemporaryDirectory(prefix="locpipe-public-conformance-") as temporary:
        root = Path(temporary)
        inputs = root / "inputs"
        staging = root / "staging"
        publication = root / "publication"
        receipts = root / "receipts"
        lifecycle = root / "lifecycle"
        for path in (inputs, staging, publication, receipts, lifecycle):
            path.mkdir()
        operation_source = inputs / Path(*source_spec["operation_path"].split("/"))
        _copy_input(fixture_source, operation_source, reverse_creation=reverse_creation)
        actual_input_sha = (
            hashlib.sha256(operation_source.read_bytes()).hexdigest()
            if source_spec["hash_domain"] == "raw"
            else directory_manifest_sha256(operation_source)
        )
        if actual_input_sha != source_spec["sha256"]:
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "Public fixture input SHA drift")
        binding = _binding(adapter.descriptor)
        include_relations = any(row["path"] == "relations.jsonl" for row in manifest["outputs"])
        request = OperationRequestV0(
            f"conformance.{manifest['fixture_id']}",
            Capability.EXTRACT_IMPORT,
            semantic_sha256(binding),
            (ArtifactHashV0(
                source_spec["operation_path"], source_spec["hash_domain"], actual_input_sha,
            ),),
            adapter_output_declarations_v0(include_relations=include_relations),
        )
        implementation, handler = bind_read_only_adapter_v0(adapter)
        result = execute_bound_operation(
            request.as_envelope(),
            binding,
            handlers={implementation: handler},
            input_root=inputs,
            staging_root=staging,
            hash_verifiers={"directory_manifest": directory_manifest_sha256},
        )
        if result["data"]["status"] != "PASS":
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Public conformance adapter returned FAIL")
        expected_hashes = {row["path"]: row["sha256"] for row in manifest["outputs"]}
        actual_hashes = {}
        for name in sorted(expected_hashes):
            actual = (staging / name).read_bytes()
            golden = (fixture_root / "golden" / name).read_bytes()
            if actual != golden:
                raise ContractViolation(ErrorCode.HASH_MISMATCH, f"Golden output drift: {name}")
            actual_hashes[name] = hashlib.sha256(actual).hexdigest()
        if actual_hashes != expected_hashes:
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "Fixture output SHA drift")
        summary = validate_adapter_corpus_v0(request, staging, adapter.descriptor)
        if (summary.segment_count, summary.relation_count) != (
            manifest["expected"]["segment_count"], manifest["expected"]["relation_count"],
        ):
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "Fixture corpus count drift")
        if any(any(path.iterdir()) for path in (publication, receipts, lifecycle)):
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Conformance adapter mutated lifecycle domains")
        return {
            "fixture_id": manifest["fixture_id"],
            "result_sha256": hashlib.sha256(canonical_json_bytes(result)).hexdigest(),
            "input_sha256": actual_input_sha,
            "output_hashes": actual_hashes,
            "segment_count": summary.segment_count,
            "relation_count": summary.relation_count,
            "published": False,
            "receipts_created": False,
            "lifecycle_changed": False,
        }
