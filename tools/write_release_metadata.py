from __future__ import annotations

import hashlib
import json
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _project_version(root: Path = ROOT) -> str:
    value = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = value.get("project")
    version = project.get("version") if isinstance(project, dict) else None
    if not isinstance(version, str) or not version:
        raise SystemExit("pyproject.toml project.version is malformed")
    return version


def _write_release_metadata(root: Path, *, project_root: Path = ROOT) -> None:
    artifacts = sorted(path for path in root.iterdir() if path.is_file() and path.name not in {"SHA256SUMS", "gate-receipt.json"})
    sums = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in artifacts)
    (root / "SHA256SUMS").write_text(sums, encoding="utf-8", newline="\n")
    receipt = {
        "contract": "locpipe.release-gate/v0",
        "package_version": _project_version(project_root),
        "contract_version": "0.1.0-draft.2",
        "artifacts": [{"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in artifacts],
        "status": "VERIFIED",
    }
    (root / "gate-receipt.json").write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: write_release_metadata.py <dist>")
    root = Path(sys.argv[1]).resolve()
    _write_release_metadata(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
