from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from locpipe.contracts.v0.artifacts import validate_relative_posix_path


WINDOWS_ABSOLUTE = re.compile(rb"(?<![A-Za-z0-9+.-])[A-Za-z]:[\\/](?![\\/])")
UNC_ABSOLUTE = re.compile(rb"(?<![\\/])\\\\(?![?.])[A-Za-z0-9._$ -]+\\[A-Za-z0-9._$ -]+")
WINDOWS_DEVICE_ABSOLUTE = re.compile(
    rb"(?<![\\/])\\\\[?.]\\[^\\/\r\n]+(?:\\[^\\/\r\n]+)*"
)
POSIX_ABSOLUTE = re.compile(
    rb"(?<![A-Za-z0-9+.:/#\-])/(?!/)[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~ -]+)*"
)


def _contains_absolute_path(payload: bytes) -> bool:
    return any(
        pattern.search(payload)
        for pattern in (WINDOWS_ABSOLUTE, UNC_ABSOLUTE, WINDOWS_DEVICE_ABSOLUTE, POSIX_ABSOLUTE)
    )


def scan_public_export_v0(
    root: Path,
    public_paths: Iterable[str],
    *,
    private_prefixes: tuple[str, ...],
    forbidden_tokens: tuple[bytes, ...] = (),
    forbidden_payloads: tuple[bytes, ...] = (),
) -> dict[str, object]:
    paths = tuple(sorted(public_paths))
    if not paths or len(paths) != len(set(paths)):
        raise ValueError("Public export paths must be non-empty, unique and sorted")
    scanned = 0
    for relative in paths:
        validate_relative_posix_path(relative)
        if any(relative == prefix or relative.startswith(prefix + "/") for prefix in private_prefixes):
            raise ValueError("Private path entered public export set")
        path = root / Path(*relative.split("/"))
        if not path.is_file():
            raise ValueError("Public export manifest references a missing file")
        payload = path.read_bytes()
        if _contains_absolute_path(payload) or any(token in payload for token in forbidden_tokens):
            raise ValueError("Public export contains a private path or canonical Citizen dependency")
        if any(value and value in payload for value in forbidden_payloads):
            raise ValueError("Public export contains a private corpus payload")
        scanned += 1
    return {"files": scanned, "private_paths": 0, "private_payloads": 0, "absolute_paths": 0}
