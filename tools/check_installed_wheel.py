from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def _run_installed_demo(python: Path, *, root: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            (str(python), "-I", "-m", "locpipe.demo"),
            check=True,
            capture_output=True,
            text=True,
            cwd=root,
        )
    except subprocess.CalledProcessError as error:
        stdout = error.stdout if error.stdout is not None else ""
        stderr = error.stderr if error.stderr is not None else ""
        stdout_separator = "" if not stdout or stdout.endswith("\n") else "\n"
        raise SystemExit(
            "installed wheel demo failed with exit code "
            f"{error.returncode}\n"
            "--- installed demo stdout ---\n"
            f"{stdout}{stdout_separator}"
            "--- installed demo stderr ---\n"
            f"{stderr}"
        ) from None


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_installed_wheel.py <wheel>")
    wheel = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        subprocess.run((sys.executable, "-m", "venv", str(root / "venv")), check=True)
        python = root / "venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        subprocess.run((
            str(python), "-m", "pip", "install", "--disable-pip-version-check",
            "--no-index", "--find-links", str(wheel.parent), str(wheel),
        ), check=True)
        origin_check = subprocess.run((
            str(python), "-I", "-c",
            "import json,locpipe,pathlib;print(json.dumps({'origin':str(pathlib.Path(locpipe.__file__).resolve())}))",
        ), check=True, capture_output=True, text=True, cwd=root)
        origin = Path(json.loads(origin_check.stdout.strip().splitlines()[-1])["origin"]).resolve()
        if not origin.is_relative_to((root / "venv").resolve()):
            raise SystemExit("installed wheel import escaped the temporary environment")
        completed = _run_installed_demo(python, root=root)
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        if (
            payload.get("terminal_state") != "CONTENT_VERIFIED"
            or payload.get("demo") != "PASS"
            or payload.get("fluency_lifecycles") != 2
            or payload.get("fluency_provenance_paths") != ["CORRECTION_TERMINAL", "INITIAL_STATE"]
        ):
            raise SystemExit("installed wheel demo did not prove both fluency validation paths")
    print(json.dumps({"status": "PASS", "wheel": wheel.name, "terminal_state": "CONTENT_VERIFIED"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
