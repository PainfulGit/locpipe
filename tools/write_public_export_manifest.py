from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

if __package__:
    from .check_public_boundary import (
        MANIFEST,
        ROOT,
        _canonical_public_path,
        _manifest_bytes,
    )
else:
    from check_public_boundary import (  # type: ignore[no-redef]
        MANIFEST,
        ROOT,
        _canonical_public_path,
        _manifest_bytes,
    )


def _git_z_rows(args: tuple[str, ...], *, root: Path) -> tuple[str, ...]:
    payload = subprocess.check_output(("git", *args, "-z"), cwd=root)
    return tuple(row.decode("utf-8") for row in payload.split(b"\0") if row)


def _require_index_generation_state(*, root: Path = ROOT) -> tuple[str, ...]:
    if _git_z_rows(("diff", "--name-only"), root=root):
        raise SystemExit("unstaged tracked changes reject manifest generation")
    if _git_z_rows(("ls-files", "--others", "--exclude-standard"), root=root):
        raise SystemExit("untracked files reject manifest generation")
    if _git_z_rows(("ls-files", "--unmerged"), root=root):
        raise SystemExit("unmerged index entries reject manifest generation")
    staged = tuple(sorted(_git_z_rows(("diff", "--cached", "--name-only"), root=root)))
    if not staged:
        raise SystemExit("staged public changes are required for manifest generation")
    if MANIFEST.name in staged:
        raise SystemExit("manifest must not be staged before generation")
    for path in staged:
        _canonical_public_path(path)
    return staged


def _index_paths(*, root: Path = ROOT) -> tuple[str, ...]:
    paths = tuple(sorted(_git_z_rows(("ls-files",), root=root)))
    if len(paths) != len(set(paths)):
        raise SystemExit("duplicate index paths reject manifest generation")
    for path in paths:
        _canonical_public_path(path)
    return paths


def _index_manifest_rows(
    paths: tuple[str, ...],
    read_blob: Callable[[str], bytes],
    *,
    manifest_name: str = MANIFEST.name,
) -> tuple[dict[str, object], ...]:
    canonical_paths = tuple(_canonical_public_path(path) for path in paths)
    if canonical_paths != tuple(sorted(canonical_paths)) or len(canonical_paths) != len(set(canonical_paths)):
        raise SystemExit("index paths are not sorted and unique")
    rows: list[dict[str, object]] = []
    for path in canonical_paths:
        if path == manifest_name:
            continue
        payload = read_blob(path)
        rows.append(
            {
                "path": path,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    return tuple(rows)


def _write_public_export_manifest(*, root: Path = ROOT) -> bytes:
    _require_index_generation_state(root=root)
    paths = _index_paths(root=root)
    rows = _index_manifest_rows(
        paths,
        lambda path: subprocess.check_output(("git", "show", f":{path}"), cwd=root),
    )
    payload = _manifest_bytes(rows)
    destination = root / MANIFEST.name
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=root,
            prefix=f".{MANIFEST.name}.",
            suffix=".pending",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return payload


def main() -> int:
    payload = _write_public_export_manifest()
    print(f"wrote {MANIFEST.name}: {len(payload)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
