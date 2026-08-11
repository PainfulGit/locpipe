from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: write_release_metadata.py <dist>")
    root = Path(sys.argv[1]).resolve()
    artifacts = sorted(path for path in root.iterdir() if path.is_file() and path.name not in {"SHA256SUMS", "gate-receipt.json"})
    sums = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in artifacts)
    (root / "SHA256SUMS").write_text(sums, encoding="utf-8", newline="\n")
    receipt = {
        "contract": "locpipe.release-gate/v0",
        "package_version": "0.1.0b1",
        "contract_version": "0.1.0-draft.2",
        "artifacts": [{"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in artifacts],
        "status": "VERIFIED",
    }
    (root / "gate-receipt.json").write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
