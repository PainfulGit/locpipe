from __future__ import annotations

import json

from locpipe.adapters.v0 import AdapterExtractContextV0, AdapterMapContextV0, AdapterProbeContextV0
from locpipe.contracts.v0 import (
    AdapterDescriptorV0,
    BranchIdentity,
    Capability,
    ErrorCategory,
    ErrorCode,
    ErrorRecord,
    SelectorStep,
    canonical_json_bytes,
    canonical_jsonl_bytes,
    display_id,
    semantic_sha256,
)

from .common import directory_manifest_sha256, relation_envelope, snapshot_envelope, source_envelope


class SyntheticStructuredAdapterV0:
    descriptor = AdapterDescriptorV0(
        "synthetic.structured.v0",
        "0.1.0",
        "2" * 64,
        (Capability.EXTRACT_IMPORT,),
    )

    def probe(self, context: AdapterProbeContextV0) -> ErrorRecord | None:
        bundle = context.input_root / "source_bundle"
        if not bundle.is_dir() or sorted(path.name for path in bundle.iterdir()) != ["message.json", "metadata.json"]:
            return ErrorRecord(ErrorCode.OUTPUT_CONTRACT_VIOLATION, ErrorCategory.CONTENT, None, False, (), "structured fixture input differs")
        return None

    def extract(self, context: AdapterExtractContextV0) -> ErrorRecord | None:
        bundle = context.input_root / "source_bundle"
        message = json.loads((bundle / "message.json").read_text(encoding="utf-8"))
        metadata = json.loads((bundle / "metadata.json").read_text(encoding="utf-8"))
        if set(message) != {"message_id", "tones"} or set(metadata) != {"revision", "source_locale"}:
            return ErrorRecord(ErrorCode.MALFORMED_ARTIFACT, ErrorCategory.CONTENT, None, False, (), "structured fixture schema differs")
        (context.work_root / "normalized.json").write_bytes(canonical_json_bytes({"message": message, "metadata": metadata}))
        (context.work_root / "source.sha256").write_text(directory_manifest_sha256(bundle), encoding="ascii")
        return None

    def map(self, context: AdapterMapContextV0) -> ErrorRecord | None:
        normalized = json.loads((context.work_root / "normalized.json").read_text(encoding="utf-8"))
        message = normalized["message"]
        metadata = normalized["metadata"]
        identities = []
        segments = []
        for tone in message["tones"]:
            for count in tone["counts"]:
                identity = BranchIdentity(
                    ("synthetic", "structured", message["message_id"]),
                    metadata["source_locale"],
                    (
                        SelectorStep("tone", "select", tone["value"]),
                        SelectorStep("count", "plural", count["value"]),
                    ),
                )
                identities.append(identity)
                segments.append(source_envelope(
                    identity,
                    count["text"],
                    locator={"resource": "message.json", "tone": tone["value"], "count": count["value"]},
                    constraints={"placeholder": "{count}"},
                ))
        relations = [relation_envelope("VARIANT_OF", identity) for identity in identities]
        source_sha = (context.work_root / "source.sha256").read_text(encoding="ascii")
        (context.staging_root / "segments.jsonl").write_bytes(
            canonical_jsonl_bytes(segments, sort_key=lambda row: display_id(BranchIdentity.from_dict(row["data"]["identity"])))
        )
        (context.staging_root / "relations.jsonl").write_bytes(
            canonical_jsonl_bytes(relations, sort_key=lambda row: semantic_sha256(row))
        )
        (context.staging_root / "source_snapshot.json").write_bytes(
            canonical_json_bytes(snapshot_envelope(
                self.descriptor,
                source_sha,
                metadata["revision"],
                tuple(identities),
                snapshot_id="synthetic-structured-snapshot",
            ))
        )
        return None
