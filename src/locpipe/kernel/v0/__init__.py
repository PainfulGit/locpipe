"""Read-only Phase 2 kernel surface.

The v0 kernel can hash and compare evidence, but it cannot publish artifacts or
mutate lifecycle state.
"""

from .evidence import (
    EvidenceProjectionV0,
    OverlayBindingV0,
    ParityMismatchV0,
    ParityReportV0,
    StateRefV0,
    compare_evidence,
    snapshot_artifacts,
)
from .hashing import sha256_bytes, sha256_file, sha256_text_utf8

__all__ = [
    "EvidenceProjectionV0",
    "OverlayBindingV0",
    "ParityMismatchV0",
    "ParityReportV0",
    "StateRefV0",
    "compare_evidence",
    "sha256_bytes",
    "sha256_file",
    "sha256_text_utf8",
    "snapshot_artifacts",
]

