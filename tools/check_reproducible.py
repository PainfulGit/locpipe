from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


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
    if first != second or sorted(first) != ["locpipe-0.1.0b1-py3-none-any.whl", "locpipe-0.1.0b1.tar.gz"]:
        raise SystemExit("package build is not byte-reproducible")
    print(json.dumps({"status": "PASS", "artifacts": first}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
