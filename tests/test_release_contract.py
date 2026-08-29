from __future__ import annotations

import json
import tempfile
import tomllib
import unittest
from pathlib import Path

from tools.check_reproducible import _expected_artifact_names, _project_version as reproducible_project_version
from tools.write_release_metadata import _project_version as metadata_project_version, _write_release_metadata


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_VERSION = "0.2.0b1"
CONTRACT_VERSION = "0.1.0-draft.2"


class ReleaseContractTests(unittest.TestCase):
    def test_pyproject_is_the_package_version_authority(self) -> None:
        value = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(value["project"]["version"], PACKAGE_VERSION)
        self.assertEqual(reproducible_project_version(), PACKAGE_VERSION)
        self.assertEqual(metadata_project_version(), PACKAGE_VERSION)
        for path in sorted((ROOT / "src").rglob("*")):
            if path.is_file():
                self.assertNotIn(PACKAGE_VERSION.encode("utf-8"), path.read_bytes(), path.as_posix())

    def test_reproducibility_artifact_names_derive_from_pyproject(self) -> None:
        self.assertEqual(
            _expected_artifact_names(),
            [
                "locpipe-0.2.0b1-py3-none-any.whl",
                "locpipe-0.2.0b1.tar.gz",
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
            artifact = dist / "locpipe-0.2.0b1-py3-none-any.whl"
            artifact.write_bytes(b"synthetic wheel bytes")
            _write_release_metadata(dist)
            receipt = json.loads((dist / "gate-receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["package_version"], PACKAGE_VERSION)
            self.assertEqual(receipt["contract_version"], CONTRACT_VERSION)
            self.assertEqual(receipt["contract"], "locpipe.release-gate/v0")
            self.assertEqual([row["name"] for row in receipt["artifacts"]], [artifact.name])

    def test_ci_selects_one_wheel_and_keeps_offline_runtime_authority(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('wheels = sorted(Path("dist").glob("locpipe-*.whl"))', workflow)
        self.assertIn("if len(wheels) != 1:", workflow)
        self.assertIn('steps.built_wheel.outputs.path', workflow)
        self.assertIn("--require-hashes --only-binary=:all: -r requirements-runtime.lock --dest dist", workflow)
        self.assertIn("name: locpipe-release-candidate", workflow)
        self.assertNotIn("dist/locpipe-0.1.0b1-py3-none-any.whl", workflow)

    def test_release_docs_keep_candidate_unpublished_and_history_intact(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        policy = (ROOT / "docs" / "RELEASE_POLICY.md").read_text(encoding="utf-8")
        for payload in (readme, changelog, policy):
            self.assertIn(PACKAGE_VERSION, payload)
        self.assertIn("has not been tagged, uploaded or externally published", readme)
        self.assertIn("No external tag, release asset or package publication is implied", changelog)
        self.assertIn("does not authorize a tag, upload or external", policy)
        self.assertIn("## 0.1.0b1", changelog)
        self.assertIn("historical `0.1.0b1` wheel", readme)
        self.assertIn(CONTRACT_VERSION, policy)


if __name__ == "__main__":
    unittest.main()
