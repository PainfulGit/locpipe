from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
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


def _expected_artifact_names(root: Path = ROOT) -> list[str]:
    version = _project_version(root)
    return [f"locpipe-{version}-py3-none-any.whl", f"locpipe-{version}.tar.gz"]


def _build(output: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = "1704067200"
    subprocess.run(
        (sys.executable, "-m", "build", "--no-isolation", "--outdir", str(output), str(ROOT)),
        check=True,
        env=env,
    )
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(output.iterdir())}


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        first = _build(root / "first")
        second = _build(root / "second")
    if first != second or sorted(first) != _expected_artifact_names():
        raise SystemExit("package build is not byte-reproducible")
    print(json.dumps({"status": "PASS", "artifacts": first}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
