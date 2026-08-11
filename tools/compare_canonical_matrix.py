from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: compare_canonical_matrix.py <matrix-root>")
    files = sorted(Path(sys.argv[1]).rglob("*.json"))
    if len(files) != 6:
        raise SystemExit(f"expected 6 canonical matrices, got {len(files)}")
    payloads = [json.loads(path.read_text(encoding="utf-8")) for path in files]
    baseline = payloads[0]
    if any(payload != baseline for payload in payloads[1:]):
        raise SystemExit("canonical matrix differs across supported environments")
    print(json.dumps({"status": "PASS", "matrices": len(files), "semantic_sha256": baseline["semantic_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
