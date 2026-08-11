from __future__ import annotations

import csv
import hashlib
import io

from locpipe.adapters.v0 import AdapterExtractContextV0, AdapterMapContextV0, AdapterProbeContextV0
from locpipe.contracts.v0 import (
    AdapterDescriptorV0,
    BranchIdentity,
    Capability,
    ErrorCategory,
    ErrorCode,
    ErrorRecord,
    canonical_json_bytes,
    canonical_jsonl_bytes,
    display_id,
)

from .common import snapshot_envelope, source_envelope


class SyntheticFlatAdapterV0:
    descriptor = AdapterDescriptorV0(
        "synthetic.flat.v0",
        "0.1.0",
        "1" * 64,
        (Capability.EXTRACT_IMPORT,),
    )

    def probe(self, context: AdapterProbeContextV0) -> ErrorRecord | None:
        if sorted(path.name for path in context.input_root.iterdir()) != ["flat.csv"]:
            return ErrorRecord(ErrorCode.OUTPUT_CONTRACT_VIOLATION, ErrorCategory.CONTENT, None, False, (), "flat fixture input differs")
        return None

    def extract(self, context: AdapterExtractContextV0) -> ErrorRecord | None:
        payload = (context.input_root / "flat.csv").read_bytes()
        rows = list(csv.DictReader(io.StringIO(payload.decode("utf-8"), newline="")))
        if len(rows) != 3 or any(set(row) != {"key", "text", "context"} for row in rows):
            return ErrorRecord(ErrorCode.MALFORMED_ARTIFACT, ErrorCategory.CONTENT, "flat.csv", False, (), "flat fixture rows differ")
        (context.work_root / "rows.json").write_bytes(canonical_json_bytes(rows))
        (context.work_root / "source.sha256").write_text(hashlib.sha256(payload).hexdigest(), encoding="ascii")
        return None

    def map(self, context: AdapterMapContextV0) -> ErrorRecord | None:
        import json

        rows = json.loads((context.work_root / "rows.json").read_text(encoding="utf-8"))
        identities = tuple(BranchIdentity(("synthetic", "flat", row["key"]), "en") for row in rows)
        segments = [
            source_envelope(
                identity,
                row["text"],
                locator={"resource": "flat.csv", "key": row["key"]},
                constraints={"context": row["context"]},
            )
            for identity, row in zip(identities, rows, strict=True)
        ]
        source_sha = (context.work_root / "source.sha256").read_text(encoding="ascii")
        (context.staging_root / "segments.jsonl").write_bytes(
            canonical_jsonl_bytes(segments, sort_key=lambda row: display_id(BranchIdentity.from_dict(row["data"]["identity"])))
        )
        (context.staging_root / "source_snapshot.json").write_bytes(
            canonical_json_bytes(snapshot_envelope(
                self.descriptor,
                source_sha,
                "flat-demo-1",
                identities,
                snapshot_id="synthetic-flat-snapshot",
            ))
        )
        return None
