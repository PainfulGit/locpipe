from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


_PREPARED_PROBE = r"""
import copy
import json
import shutil
import tempfile
from pathlib import Path

from locpipe._demo_support.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0
from locpipe._demo_support.test_content_validation_v0 import validation_fixture
from locpipe._demo_support.test_translation_packet_v0 import FIXTURES, build_fixture
from locpipe.content.v0 import (
    PreparedSourceAuthorityV0,
    PreparedSourceRelationV0,
    PreparedSourceSegmentV0,
    frozen_scope_artifacts_v0,
    prepare_accepted_source_authority_v0,
    rebind_prepared_source_authority_v0,
)
from locpipe.contracts.v0 import WorkflowProfile, canonical_json_bytes
from locpipe.kernel.v0.context import ProjectContextV0
from locpipe.kernel.v0.transactions import NamespaceV0
from locpipe.translation.v0 import ProviderBudgetV0, build_translation_job_prepared_v0
from locpipe.validation.v0 import build_content_validation_job_prepared_v0

public_symbols = (
    PreparedSourceAuthorityV0,
    PreparedSourceRelationV0,
    PreparedSourceSegmentV0,
    prepare_accepted_source_authority_v0,
    rebind_prepared_source_authority_v0,
    build_translation_job_prepared_v0,
    build_content_validation_job_prepared_v0,
)
if not all(callable(value) for value in public_symbols):
    raise SystemExit("prepared public API is incomplete")

adapter = SyntheticStructuredAdapterV0()
resolved, corpus, scope, canonical_job, canonical_packet = build_fixture("structured", adapter)
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    golden = FIXTURES / "structured" / "golden"
    for name in ("source_snapshot.json", "segments.jsonl", "relations.jsonl"):
        shutil.copyfile(golden / name, root / name)
    (root / "source_lock.json").write_bytes(canonical_json_bytes(corpus.lock.as_dict()))
    authority = prepare_accepted_source_authority_v0(
        root,
        snapshot_path="source_snapshot.json",
        segments_path="segments.jsonl",
        relations_path="relations.jsonl",
        source_lock_path="source_lock.json",
        descriptor=adapter.descriptor,
        expected_config_snapshot_sha256=resolved.config_snapshot_sha256,
    )
    context = ProjectContextV0(
        NamespaceV0("workspace", "fixture", "release"),
        WorkflowProfile.CONTENT_ONLY,
        resolved.config_snapshot_sha256,
    )
    artifacts = dict(frozen_scope_artifacts_v0(scope))
    prepared_job, prepared_packet = build_translation_job_prepared_v0(
        context,
        resolved,
        authority,
        scope,
        scope_bytes=artifacts["scope/scope.json"],
        scope_lock_bytes=artifacts["scope/scope_lock.json"],
        target_locale="uk",
        budget=ProviderBudgetV0(None, None),
    )
    if (prepared_job, prepared_packet) != (canonical_job, canonical_packet):
        raise SystemExit("prepared translation differs from canonical translation")
    rebound = rebind_prepared_source_authority_v0(authority, config_snapshot_sha256="f" * 64)
    if authority.segments is not rebound.segments or authority.relations is not rebound.relations:
        raise SystemExit("prepared rebind did not preserve row identity")
    try:
        copy.copy(authority)
    except TypeError:
        pass
    else:
        raise SystemExit("prepared authority copy did not fail closed")

    validation = validation_fixture()
    validation_authority = dict(validation["authority"])
    validation_root = root / "validation"
    validation_root.mkdir()
    flat_golden = FIXTURES / "flat" / "golden"
    for name in ("source_snapshot.json", "segments.jsonl"):
        shutil.copyfile(flat_golden / name, validation_root / name)
    (validation_root / "source_lock.json").write_bytes(
        validation_authority["source/source_lock.json"]
    )
    prepared_validation_authority = prepare_accepted_source_authority_v0(
        validation_root,
        snapshot_path="source_snapshot.json",
        segments_path="segments.jsonl",
        relations_path=None,
        source_lock_path="source_lock.json",
        descriptor=validation["adapter"].descriptor,
        expected_config_snapshot_sha256=validation["resolved"].config_snapshot_sha256,
    )
    prepared_validation = build_content_validation_job_prepared_v0(
        validation["context"],
        validation["resolved"],
        prepared_validation_authority,
        validation["scope"],
        validation["translation_job"],
        validation["translation_packet"],
        validation["translation_decision_bytes"],
        validation["translation_state_bytes"],
        validation["translation_target_set"],
        validation["candidate"],
        validation["validator"],
        scope_bytes=validation_authority["scope/scope.json"],
        scope_lock_bytes=validation_authority["scope/scope_lock.json"],
        candidate_evidence=validation["candidate_evidence"],
        editorial_job=validation["editorial_job"],
        editorial_packet=validation["editorial_packet"],
        editorial_policy=validation["editorial_policy"],
    )
    if prepared_validation != (
        validation["job"],
        validation["packet"],
        validation["authority"],
    ):
        raise SystemExit("prepared validation differs from canonical validation")

print(json.dumps({
    "prepared_api": "PASS",
    "rows": len(authority.segments),
    "validation_api": "PASS",
}, sort_keys=True))
"""


def _run_isolated(
    python: Path,
    *arguments: str,
    root: Path,
    label: str,
) -> subprocess.CompletedProcess[str]:
    command = (str(python), "-I", *arguments)
    try:
        return subprocess.run(
            command,
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
            f"installed wheel {label} failed with exit code "
            f"{error.returncode}\n"
            f"--- installed {label} stdout ---\n"
            f"{stdout}{stdout_separator}"
            f"--- installed {label} stderr ---\n"
            f"{stderr}"
        ) from None


def _run_installed_demo(python: Path, *, root: Path) -> subprocess.CompletedProcess[str]:
    return _run_isolated(python, "-m", "locpipe.demo", root=root, label="demo")


def _run_installed_prepared_probe(python: Path, *, root: Path) -> subprocess.CompletedProcess[str]:
    return _run_isolated(python, "-c", _PREPARED_PROBE, root=root, label="prepared probe")


def _expected_wheel_version(wheel: Path) -> str:
    prefix = "locpipe-"
    suffix = "-py3-none-any.whl"
    if not wheel.name.startswith(prefix) or not wheel.name.endswith(suffix):
        raise SystemExit("installed wheel filename is not the expected locpipe wheel")
    version = wheel.name[len(prefix):-len(suffix)]
    if not version:
        raise SystemExit("installed wheel version is missing")
    return version


def _install_command(python: Path, wheel: Path, runtime_wheelhouse: Path) -> tuple[str, ...]:
    return (
        str(python), "-m", "pip", "install", "--disable-pip-version-check",
        "--no-index", "--find-links", str(runtime_wheelhouse), str(wheel),
    )


def _validate_installed_authority(
    installed: dict[str, object],
    *,
    venv_root: Path,
    expected_version: str,
) -> None:
    for name in ("locpipe_origin", "rfc8785_origin"):
        value = installed.get(name)
        if not isinstance(value, str) or not Path(value).resolve().is_relative_to(venv_root.resolve()):
            raise SystemExit("installed wheel import escaped the temporary environment")
    if installed.get("version") != expected_version or installed.get("requires") != ["rfc8785==0.1.4"]:
        raise SystemExit("installed wheel metadata differs from release authority")


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: check_installed_wheel.py <wheel> <runtime-wheelhouse>")
    wheel = Path(sys.argv[1]).resolve()
    runtime_wheelhouse = Path(sys.argv[2]).resolve()
    if not wheel.is_file() or not runtime_wheelhouse.is_dir():
        raise SystemExit("installed wheel or runtime wheelhouse is missing")
    expected_version = _expected_wheel_version(wheel)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        subprocess.run((sys.executable, "-m", "venv", str(root / "venv")), check=True)
        python = root / "venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        subprocess.run(_install_command(python, wheel, runtime_wheelhouse), check=True)
        origin_check = subprocess.run((
            str(python), "-I", "-c",
            "import importlib.metadata,json,locpipe,pathlib,rfc8785;"
            "print(json.dumps({'locpipe_origin':str(pathlib.Path(locpipe.__file__).resolve()),"
            "'rfc8785_origin':str(pathlib.Path(rfc8785.__file__).resolve()),"
            "'requires':importlib.metadata.requires('locpipe'),"
            "'version':importlib.metadata.version('locpipe')}))",
        ), check=True, capture_output=True, text=True, cwd=root)
        installed = json.loads(origin_check.stdout.strip().splitlines()[-1])
        _validate_installed_authority(
            installed,
            venv_root=root / "venv",
            expected_version=expected_version,
        )
        completed = _run_installed_demo(python, root=root)
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        if (
            payload.get("terminal_state") != "CONTENT_VERIFIED"
            or payload.get("demo") != "PASS"
            or payload.get("fluency_lifecycles") != 2
            or payload.get("fluency_provenance_paths") != ["CORRECTION_TERMINAL", "INITIAL_STATE"]
        ):
            raise SystemExit("installed wheel demo did not prove both fluency validation paths")
        prepared = _run_installed_prepared_probe(python, root=root)
        prepared_payload = json.loads(prepared.stdout.strip().splitlines()[-1])
        if (
            prepared_payload.get("prepared_api") != "PASS"
            or prepared_payload.get("validation_api") != "PASS"
            or prepared_payload.get("rows", 0) < 1
        ):
            raise SystemExit("installed wheel prepared API proof failed")
    print(json.dumps({
        "prepared_api": "PASS",
        "status": "PASS",
        "terminal_state": "CONTENT_VERIFIED",
        "validation_api": "PASS",
        "wheel": wheel.name,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
