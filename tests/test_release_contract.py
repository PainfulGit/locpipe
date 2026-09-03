from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import tomllib
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from tools.check_reproducible import _expected_artifact_names, _project_version as reproducible_project_version
from tools.write_release_metadata import _project_version as metadata_project_version, _write_release_metadata


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_VERSION = "0.2.0b6"
CONTRACT_VERSION = "0.1.0-draft.2"
RELEASE_TAG = "v0.2.0-beta.6"
SOURCE_DATE_EPOCH = "1704067200"
DERIVED_NAMES = ("sbom.cdx.json", "SHA256SUMS", "gate-receipt.json")


def _synthetic_sbom_bytes(
    *,
    timestamp: str,
    serial_number: str,
    component_type: str = "library",
) -> bytes:
    payload = {
        "bomFormat": "CycloneDX",
        "components": [{
            "name": "rfc8785",
            "purl": "pkg:pypi/rfc8785@0.1.4",
            "type": component_type,
            "version": "0.1.4",
        }],
        "metadata": {"timestamp": timestamp},
        "serialNumber": serial_number,
        "specVersion": "1.6",
        "version": 1,
    }
    return (json.dumps(payload, indent=2) + "\n").encode("utf-8")


def _write_release_inputs(
    root: Path,
    *,
    wheel_bytes: bytes = b"synthetic wheel bytes",
    timestamp: str = "2099-12-31T23:59:59+00:00",
    serial_number: str = "urn:uuid:00000000-0000-4000-8000-000000000000",
    component_type: str = "library",
    creation_order: tuple[str, ...] = (
        "locpipe-0.2.0b6-py3-none-any.whl",
        "locpipe-0.2.0b6.tar.gz",
        "sbom.cdx.json",
    ),
) -> None:
    payloads = {
        "locpipe-0.2.0b6-py3-none-any.whl": wheel_bytes,
        "locpipe-0.2.0b6.tar.gz": b"synthetic sdist bytes",
        "sbom.cdx.json": _synthetic_sbom_bytes(
            timestamp=timestamp,
            serial_number=serial_number,
            component_type=component_type,
        ),
    }
    if len(creation_order) != len(payloads) or set(creation_order) != set(payloads):
        raise AssertionError("synthetic creation order is incomplete")
    for name in creation_order:
        (root / name).write_bytes(payloads[name])


def _generated_bytes(root: Path) -> tuple[bytes, bytes, bytes]:
    return tuple((root / name).read_bytes() for name in DERIVED_NAMES)


class ReleaseContractTests(unittest.TestCase):
    def test_pyproject_is_the_package_version_authority(self) -> None:
        value = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(value["project"]["version"], PACKAGE_VERSION)
        self.assertEqual(reproducible_project_version(), PACKAGE_VERSION)
        self.assertEqual(metadata_project_version(), PACKAGE_VERSION)
        for path in sorted((ROOT / "src").rglob("*.py")):
            self.assertNotIn(PACKAGE_VERSION.encode("utf-8"), path.read_bytes(), path.as_posix())

    def test_reproducibility_artifact_names_derive_from_pyproject(self) -> None:
        self.assertEqual(
            _expected_artifact_names(),
            [
                "locpipe-0.2.0b6-py3-none-any.whl",
                "locpipe-0.2.0b6.tar.gz",
            ],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "locpipe"\nversion = "9.8.7b6"\n',
                encoding="utf-8",
            )
            self.assertEqual(
                _expected_artifact_names(root),
                ["locpipe-9.8.7b6-py3-none-any.whl", "locpipe-9.8.7b6.tar.gz"],
            )

    def test_release_metadata_derives_package_version_and_preserves_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dist = Path(directory)
            _write_release_inputs(dist)
            with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}):
                _write_release_metadata(dist)
            receipt = json.loads((dist / "gate-receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["package_version"], PACKAGE_VERSION)
            self.assertEqual(receipt["contract_version"], CONTRACT_VERSION)
            self.assertEqual(receipt["contract"], "locpipe.release-gate/v0")
            self.assertEqual(
                [row["name"] for row in receipt["artifacts"]],
                [
                    "locpipe-0.2.0b6-py3-none-any.whl",
                    "locpipe-0.2.0b6.tar.gz",
                    "sbom.cdx.json",
                ],
            )

    def test_release_metadata_is_identical_across_roots_and_ignores_stale_outputs(self) -> None:
        with (
            tempfile.TemporaryDirectory() as first_directory,
            tempfile.TemporaryDirectory() as second_directory,
        ):
            first = Path(first_directory)
            second = Path(second_directory)
            _write_release_inputs(first)
            _write_release_inputs(
                second,
                creation_order=(
                    "sbom.cdx.json",
                    "locpipe-0.2.0b6.tar.gz",
                    "locpipe-0.2.0b6-py3-none-any.whl",
                ),
            )
            for name in (
                "locpipe-0.2.0b6-py3-none-any.whl",
                "locpipe-0.2.0b6.tar.gz",
                "sbom.cdx.json",
            ):
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            for root, marker in ((first, b"first stale output"), (second, b"second stale output")):
                (root / "SHA256SUMS").write_bytes(marker)
                (root / "gate-receipt.json").write_bytes(marker)
            manifest_before = (ROOT / "PUBLIC_EXPORT_MANIFEST.json").read_bytes()
            with (
                patch.dict(os.environ, {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}),
                patch.object(uuid, "uuid4", side_effect=AssertionError("random UUID used")),
            ):
                _write_release_metadata(first)
                _write_release_metadata(second)
            self.assertEqual(_generated_bytes(first), _generated_bytes(second))
            self.assertEqual(manifest_before, (ROOT / "PUBLIC_EXPORT_MANIFEST.json").read_bytes())

            sbom = json.loads((first / "sbom.cdx.json").read_bytes())
            self.assertEqual(sbom["metadata"]["timestamp"], "2024-01-01T00:00:00Z")
            self.assertRegex(
                sbom["serialNumber"],
                re.compile(
                    r"\Aurn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-"
                    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
                ),
            )
            uuid.UUID(sbom["serialNumber"].removeprefix("urn:uuid:"))
            product_authority = []
            for name in sorted((
                "locpipe-0.2.0b6-py3-none-any.whl",
                "locpipe-0.2.0b6.tar.gz",
            )):
                payload = (first / name).read_bytes()
                product_authority.append({
                    "name": name,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                })
            documented_identity = {
                "artifacts": product_authority,
                "contract": "locpipe.release-sbom-identity/v0",
                "package": {"name": "locpipe", "version": PACKAGE_VERSION},
                "source_date_epoch": int(SOURCE_DATE_EPOCH),
                "wire_contract_version": CONTRACT_VERSION,
            }
            canonical_name = json.dumps(
                documented_identity,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            self.assertEqual(
                sbom["serialNumber"],
                f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, canonical_name)}",
            )
            combined = b"".join(_generated_bytes(first))
            self.assertNotIn(str(first).encode("utf-8"), combined)
            self.assertNotIn(str(second).encode("utf-8"), combined)
            self.assertNotIn(Path.home().name.encode("utf-8"), combined)

            components = sbom["components"]
            self.assertEqual(len(components), 1)
            self.assertEqual(
                (components[0]["name"], components[0]["version"], components[0]["purl"]),
                ("rfc8785", "0.1.4", "pkg:pypi/rfc8785@0.1.4"),
            )

    def test_release_metadata_requires_canonical_nonnegative_epoch_before_output(self) -> None:
        invalid_values = (None, "", "-1", "+1", "1.0", " 1", "01", "true")
        for value in invalid_values:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _write_release_inputs(root)
                original_sbom = (root / "sbom.cdx.json").read_bytes()
                environment = {} if value is None else {"SOURCE_DATE_EPOCH": value}
                with patch.dict(os.environ, environment, clear=True):
                    with self.assertRaises(SystemExit):
                        _write_release_metadata(root)
                self.assertEqual((root / "sbom.cdx.json").read_bytes(), original_sbom)
                self.assertFalse((root / "SHA256SUMS").exists())
                self.assertFalse((root / "gate-receipt.json").exists())

    def test_release_metadata_rejects_non_library_runtime_component_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_release_inputs(root, component_type="application")
            original_sbom = (root / "sbom.cdx.json").read_bytes()
            with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}):
                with self.assertRaises(SystemExit):
                    _write_release_metadata(root)
            self.assertEqual((root / "sbom.cdx.json").read_bytes(), original_sbom)
            self.assertFalse((root / "SHA256SUMS").exists())
            self.assertFalse((root / "gate-receipt.json").exists())

    def test_epoch_and_product_authority_change_every_dependent_metadata_artifact(self) -> None:
        outputs = []
        rows = (
            (SOURCE_DATE_EPOCH, b"synthetic wheel bytes"),
            (str(int(SOURCE_DATE_EPOCH) + 1), b"synthetic wheel bytes"),
            (SOURCE_DATE_EPOCH, b"changed synthetic wheel bytes"),
        )
        for epoch, wheel_bytes in rows:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _write_release_inputs(root, wheel_bytes=wheel_bytes)
                with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": epoch}):
                    _write_release_metadata(root)
                outputs.append(_generated_bytes(root))
        for index in range(len(DERIVED_NAMES)):
            self.assertEqual(len({row[index] for row in outputs}), len(outputs))
        serial_numbers = [json.loads(row[0])["serialNumber"] for row in outputs]
        self.assertEqual(len(set(serial_numbers)), len(outputs))

        receipt = json.loads(outputs[0][2])
        sums = outputs[0][1].decode("utf-8").splitlines()
        self.assertEqual(
            [line.split("  ", 1)[1] for line in sums],
            [row["name"] for row in receipt["artifacts"]],
        )
        for line, row in zip(sums, receipt["artifacts"]):
            digest, name = line.split("  ", 1)
            self.assertEqual(name, row["name"])
            self.assertEqual(digest, row["sha256"])

    def test_ci_selects_one_wheel_and_keeps_offline_runtime_authority(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        package_job = workflow.split("\n  package:\n", 1)[1]
        self.assertIn(
            '    runs-on: ubuntu-24.04\n    env:\n      SOURCE_DATE_EPOCH: "1704067200"\n    steps:\n',
            package_job,
        )
        self.assertEqual(workflow.count('SOURCE_DATE_EPOCH: "1704067200"'), 1)
        self.assertNotIn(
            "python -m build --no-isolation --outdir dist\n        env:",
            package_job,
        )
        self.assertIn('wheels = sorted(Path("dist").glob("locpipe-*.whl"))', workflow)
        self.assertIn("if len(wheels) != 1:", workflow)
        self.assertIn('steps.built_wheel.outputs.path', workflow)
        self.assertIn(
            "--require-hashes --only-binary=:all: -r requirements-runtime.lock --dest runtime-wheelhouse",
            workflow,
        )
        self.assertNotIn("requirements-runtime.lock --dest dist", workflow)
        self.assertIn(
            'tools/check_installed_wheel.py "${{ steps.built_wheel.outputs.path }}" runtime-wheelhouse',
            workflow,
        )
        self.assertIn("name: locpipe-release-candidate", workflow)
        self.assertNotIn("dist/locpipe-0.1.0b1-py3-none-any.whl", workflow)

    def test_release_docs_keep_successor_identity_and_history_intact(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        policy = (ROOT / "docs" / "RELEASE_POLICY.md").read_text(encoding="utf-8")
        normalized_readme = " ".join(readme.split())
        normalized_policy = " ".join(policy.split())
        for payload in (readme, changelog, policy):
            self.assertIn(PACKAGE_VERSION, payload)
            self.assertIn(RELEASE_TAG, payload)
        self.assertIn("`0.2.0b1` prerelease remains the published fluency baseline", normalized_readme)
        self.assertIn("`0.2.0b2` prerelease remains immutable", normalized_readme)
        self.assertIn("`0.2.0b3` prerelease remains immutable", normalized_readme)
        self.assertIn("`0.2.0b4` prerelease remains immutable", normalized_readme)
        self.assertIn("`0.2.0b5` prerelease remains immutable", normalized_readme)
        self.assertIn("## 0.2.0b5", changelog)
        self.assertIn("## 0.2.0b4", changelog)
        self.assertIn("## 0.2.0b3", changelog)
        self.assertIn("## 0.2.0b2", changelog)
        self.assertIn("## 0.2.0b1", changelog)
        self.assertIn("does not itself authorize a tag, upload or external publication", normalized_policy)
        self.assertIn("`rebind_source_authority_v0`", changelog)
        self.assertIn("`prepare_accepted_source_authority_v0`", changelog)
        self.assertIn("`build_translation_job_prepared_v0`", changelog)
        self.assertIn("`build_content_validation_job_prepared_v0`", changelog)
        self.assertIn("`build_fluency_content_validation_job_prepared_v0`", changelog)
        self.assertIn("`build_prepared_source_cache_v0`", changelog)
        self.assertIn("`freeze_scope_prepared_v0`", changelog)
        self.assertIn("`translation_terminal_artifacts_v0`", changelog)
        self.assertIn("## 0.1.0b1", changelog)
        self.assertIn("historical `0.1.0b1` wheel", normalized_readme)
        self.assertIn(CONTRACT_VERSION, policy)
        self.assertIn("`rfc8785==0.1.4`", policy)


if __name__ == "__main__":
    unittest.main()
