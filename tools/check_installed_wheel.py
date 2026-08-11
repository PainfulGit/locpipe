from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_installed_wheel.py <wheel>")
    wheel = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        subprocess.run((sys.executable, "-m", "venv", str(root / "venv")), check=True)
        python = root / "venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        subprocess.run((str(python), "-m", "pip", "install", "--disable-pip-version-check", str(wheel)), check=True)
        completed = subprocess.run((str(python), "-m", "locpipe.demo"), check=True, capture_output=True, text=True, cwd=root)
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        if payload.get("terminal_state") != "CONTENT_VERIFIED" or payload.get("demo") != "PASS":
            raise SystemExit("installed wheel demo did not reach CONTENT_VERIFIED")
    print(json.dumps({"status": "PASS", "wheel": wheel.name, "terminal_state": "CONTENT_VERIFIED"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
