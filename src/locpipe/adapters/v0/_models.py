from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AdapterProbeContextV0:
    input_root: Path


@dataclass(frozen=True)
class AdapterExtractContextV0:
    input_root: Path
    work_root: Path


@dataclass(frozen=True)
class AdapterMapContextV0:
    work_root: Path
    staging_root: Path


@dataclass(frozen=True)
class AdapterCorpusSummaryV0:
    source_input_path: str
    source_raw_sha256: str
    source_locale: str
    source_version: str
    snapshot_id: str
    branch_ids: tuple[str, ...]
    segment_count: int
    relation_count: int
    output_paths: tuple[str, ...]
