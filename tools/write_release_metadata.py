from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import re
import sys
import tomllib
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
_WIRE_CONTRACT_VERSION = "0.1.0-draft.2"
_RELEASE_GATE_CONTRACT = "locpipe.release-gate/v0"
_SBOM_IDENTITY_CONTRACT = "locpipe.release-sbom-identity/v0"
# RFC 9562 defines this standard namespace; the canonical release identity below
# is the complete name passed to UUIDv5.
_SBOM_UUID_NAMESPACE = uuid.NAMESPACE_URL
_DERIVED_RELEASE_NAMES = frozenset({"sbom.cdx.json", "SHA256SUMS", "gate-receipt.json"})
_SOURCE_DATE_EPOCH_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\Z")


def _project_identity(root: Path = ROOT) -> tuple[str, str]:
    value = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = value.get("project")
    name = project.get("name") if isinstance(project, dict) else None
    version = project.get("version") if isinstance(project, dict) else None
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise SystemExit("pyproject.toml project identity is malformed")
    return name, version


def _project_version(root: Path = ROOT) -> str:
    return _project_identity(root)[1]


def _release_epoch() -> tuple[int, str]:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if not isinstance(raw, str) or _SOURCE_DATE_EPOCH_PATTERN.fullmatch(raw) is None:
        raise SystemExit("SOURCE_DATE_EPOCH must be a canonical nonnegative integer")
    epoch = int(raw)
    try:
        timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError) as exc:
        raise SystemExit("SOURCE_DATE_EPOCH is outside the supported UTC range") from exc
    return epoch, timestamp


def _artifact_authority(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "name": path.name,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _release_inputs(
    root: Path,
    *,
    package_name: str,
    package_version: str,
) -> list[dict[str, object]]:
    expected = {
        f"{package_name}-{package_version}-py3-none-any.whl",
        f"{package_name}-{package_version}.tar.gz",
    }
    paths = sorted(
        path for path in root.iterdir() if path.is_file() and path.name not in _DERIVED_RELEASE_NAMES
    )
    if {path.name for path in paths} != expected:
        raise SystemExit("release input artifact inventory is not the exact wheel and sdist")
    return [_artifact_authority(path) for path in paths]


def _canonical_sbom_bytes(
    sbom_bytes: bytes,
    *,
    package_name: str,
    package_version: str,
    artifact_authority: list[dict[str, object]],
    epoch: int,
    timestamp: str,
) -> bytes:
    try:
        sbom = json.loads(sbom_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("sbom.cdx.json is not valid UTF-8 JSON") from exc
    if (
        not isinstance(sbom, dict)
        or sbom.get("bomFormat") != "CycloneDX"
        or sbom.get("specVersion") != "1.6"
    ):
        raise SystemExit("sbom.cdx.json is not CycloneDX 1.6")
    components = sbom.get("components")
    if not isinstance(components, list) or len(components) != 1:
        raise SystemExit("sbom.cdx.json must contain exactly one runtime component")
    component = components[0]
    if not isinstance(component, dict) or (
        component.get("type"),
        component.get("name"),
        component.get("version"),
        component.get("purl"),
    ) != ("library", "rfc8785", "0.1.4", "pkg:pypi/rfc8785@0.1.4"):
        raise SystemExit("sbom.cdx.json runtime component authority is invalid")
    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict):
        raise SystemExit("sbom.cdx.json metadata is malformed")

    identity = {
        "artifacts": artifact_authority,
        "contract": _SBOM_IDENTITY_CONTRACT,
        "package": {"name": package_name, "version": package_version},
        "source_date_epoch": epoch,
        "wire_contract_version": _WIRE_CONTRACT_VERSION,
    }
    canonical_name = json.dumps(
        identity,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    sbom["serialNumber"] = f"urn:uuid:{uuid.uuid5(_SBOM_UUID_NAMESPACE, canonical_name)}"
    metadata["timestamp"] = timestamp
    return (
        json.dumps(sbom, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _write_release_metadata(root: Path, *, project_root: Path = ROOT) -> None:
    epoch, timestamp = _release_epoch()
    package_name, package_version = _project_identity(project_root)
    artifact_authority = _release_inputs(
        root,
        package_name=package_name,
        package_version=package_version,
    )
    sbom_path = root / "sbom.cdx.json"
    if not sbom_path.is_file():
        raise SystemExit("sbom.cdx.json is missing")
    canonical_sbom = _canonical_sbom_bytes(
        sbom_path.read_bytes(),
        package_name=package_name,
        package_version=package_version,
        artifact_authority=artifact_authority,
        epoch=epoch,
        timestamp=timestamp,
    )
    release_artifacts = sorted(
        [*artifact_authority, {
            "name": sbom_path.name,
            "size": len(canonical_sbom),
            "sha256": hashlib.sha256(canonical_sbom).hexdigest(),
        }],
        key=lambda row: str(row["name"]),
    )
    sums = "".join(f'{row["sha256"]}  {row["name"]}\n' for row in release_artifacts).encode("utf-8")
    receipt = {
        "contract": _RELEASE_GATE_CONTRACT,
        "package_version": package_version,
        "contract_version": _WIRE_CONTRACT_VERSION,
        "artifacts": [
            {"name": str(row["name"]), "sha256": str(row["sha256"])}
            for row in release_artifacts
        ],
        "status": "VERIFIED",
    }
    receipt_bytes = (
        json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")

    sbom_path.write_bytes(canonical_sbom)
    (root / "SHA256SUMS").write_bytes(sums)
    (root / "gate-receipt.json").write_bytes(receipt_bytes)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: write_release_metadata.py <dist>")
    root = Path(sys.argv[1]).resolve()
    _write_release_metadata(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
