from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INCLUDED = (
    "src/locpipe/contracts/v0/schemas",
    "src/locpipe/contracts/v0/fixtures",
    "src/locpipe/resources",
    "tests/conformance/adapter_v0/fixtures",
)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: write_canonical_matrix.py <output>")
    rows = []
    for relative in INCLUDED:
        for path in sorted(
            (ROOT / relative).rglob("*"),
            key=lambda value: value.relative_to(ROOT).as_posix().encode("utf-8"),
        ):
            if path.is_file():
                rows.append({"path": path.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    payload = {
        "contract_version": "0.1.0-draft.2",
        "files": rows,
        "semantic_sha256": hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    }
    output = Path(sys.argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": "PASS", "python": platform.python_version(), "platform": sys.platform, "semantic_sha256": payload["semantic_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
