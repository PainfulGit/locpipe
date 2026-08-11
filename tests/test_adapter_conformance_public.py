from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.contracts.v0 import (  # noqa: E402
    AdapterDescriptorV0,
    Capability,
    ContractViolation,
    ErrorCode,
    canonical_json_bytes,
    canonical_jsonl_bytes,
    semantic_sha256,
)
from tests.conformance.adapter_v0.boundary import scan_public_export_v0  # noqa: E402
from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402
from tests.conformance.adapter_v0.runner import (  # noqa: E402
    load_fixture_manifest_v0,
    run_public_fixture_v0,
)
from tests.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0  # noqa: E402


FIXTURES = ROOT / "tests/conformance/adapter_v0/fixtures"
PUBLIC_SUPPORT = ROOT / "tests/conformance/adapter_v0"


class AdapterConformancePublicTests(unittest.TestCase):
    def copied_fixture(self, name: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        target = Path(directory.name) / name
        shutil.copytree(FIXTURES / name, target)
        return target

    def test_flat_and_structured_match_golden_and_repeat_deterministically(self) -> None:
        cases = (
            ("flat", SyntheticFlatAdapterV0(), 3, 0),
            ("structured", SyntheticStructuredAdapterV0(), 6, 6),
        )
        for name, adapter, segments, relations in cases:
            first = run_public_fixture_v0(FIXTURES / name, adapter)
            second = run_public_fixture_v0(FIXTURES / name, type(adapter)(), reverse_creation=True)
            self.assertEqual(first, second)
            self.assertEqual((segments, relations), (first["segment_count"], first["relation_count"]))
            self.assertFalse(first["published"])
            self.assertFalse(first["receipts_created"])
            self.assertFalse(first["lifecycle_changed"])

    def test_input_golden_descriptor_and_manifest_drift_fail_closed(self) -> None:
        fixture = self.copied_fixture("flat")
        (fixture / "input/flat.csv").write_bytes((fixture / "input/flat.csv").read_bytes() + b"drift")
        with self.assertRaisesRegex(ContractViolation, ErrorCode.HASH_MISMATCH.value):
            run_public_fixture_v0(fixture, SyntheticFlatAdapterV0())

        fixture = self.copied_fixture("flat")
        (fixture / "golden/segments.jsonl").write_bytes(b"drift\n")
        with self.assertRaisesRegex(ContractViolation, ErrorCode.HASH_MISMATCH.value):
            run_public_fixture_v0(fixture, SyntheticFlatAdapterV0())

        fixture = self.copied_fixture("flat")
        adapter = SyntheticFlatAdapterV0()
        adapter.descriptor = AdapterDescriptorV0("synthetic.flat.v0", "0.1.0", "9" * 64, (Capability.EXTRACT_IMPORT,))
        with self.assertRaisesRegex(ContractViolation, ErrorCode.BINDING_MISMATCH.value):
            run_public_fixture_v0(fixture, adapter)

        manifest = json.loads((FIXTURES / "flat/manifest.json").read_text(encoding="utf-8"))
        manifest["unknown"] = True
        with self.assertRaisesRegex(ContractViolation, ErrorCode.MALFORMED_ARTIFACT.value):
            load_fixture_manifest_v0(canonical_json_bytes(manifest))

    def test_extra_output_and_dangling_relation_fail_closed(self) -> None:
        class ExtraFlat(SyntheticFlatAdapterV0):
            def map(self, context):
                outcome = super().map(context)
                if outcome is None:
                    (context.staging_root / "extra.txt").write_bytes(b"extra")
                return outcome

        with self.assertRaisesRegex(ContractViolation, ErrorCode.OUTPUT_CONTRACT_VIOLATION.value):
            run_public_fixture_v0(FIXTURES / "flat", ExtraFlat())

        class DanglingStructured(SyntheticStructuredAdapterV0):
            def map(self, context):
                outcome = super().map(context)
                if outcome is not None:
                    return outcome
                path = context.staging_root / "relations.jsonl"
                rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
                rows[0]["data"]["to_ref"] = {"kind": "logical_message", "logical_id": ["missing"]}
                path.write_bytes(canonical_jsonl_bytes(rows, sort_key=lambda row: semantic_sha256(row)))
                return None

        with self.assertRaisesRegex(ContractViolation, ErrorCode.OUTPUT_CONTRACT_VIOLATION.value):
            run_public_fixture_v0(FIXTURES / "structured", DanglingStructured())

    def test_public_export_scan_rejects_private_paths_and_local_paths(self) -> None:
        public = sorted(
            path.relative_to(ROOT).as_posix()
            for path in PUBLIC_SUPPORT.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        )
        result = scan_public_export_v0(
            ROOT,
            public,
            private_prefixes=("private/forbidden",),
            forbidden_tokens=(
                b"story_merged.csv", b"ui_merged.csv", b"drive_merged.csv", b"shared/choice_map.csv",
            ),
        )
        self.assertGreater(result["files"], 10)
        with self.assertRaisesRegex(ValueError, "Private path"):
            scan_public_export_v0(
                ROOT,
                public + ["private/forbidden/adapter/manifest.json"],
                private_prefixes=("private/forbidden",),
            )

    def test_public_export_scan_rejects_unc_and_posix_absolute_paths(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        public = root / "public.txt"

        for payload in (
            b"UNC=" + bytes((92, 92)) + b"server" + bytes((92,)) + b"share" + bytes((92,)) + b"secret.csv\n",
            b"EXTENDED_UNC=" + bytes((92, 92)) + b"?" + bytes((92,)) + b"UNC" + bytes((92,)) + b"server" + bytes((92,)) + b"share" + bytes((92,)) + b"secret.csv\n",
            b"DEVICE_DISK=" + bytes((92, 92)) + b"." + bytes((92,)) + b"PhysicalDrive0\n",
            b"POSIX=" + b"/" + b"home/user/private.csv\n",
            b"POSIX_ONE=" + b"/" + b"private\n",
        ):
            public.write_bytes(payload)
            with self.assertRaisesRegex(ValueError, "private path"):
                scan_public_export_v0(root, ("public.txt",), private_prefixes=("private",))

        public.write_bytes(b"URL=https://example.invalid/public/file.csv\nURN=urn:example:path/value\n")
        self.assertEqual(
            1,
            scan_public_export_v0(root, ("public.txt",), private_prefixes=("private",))["files"],
        )

    def test_public_suite_runs_from_export_tree_without_private_root(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        export = Path(directory.name)
        shutil.copytree(ROOT / "src", export / "src", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(ROOT / "tests/conformance", export / "tests/conformance", ignore=shutil.ignore_patterns("__pycache__"))
        command = (
            "from pathlib import Path; "
            "from tests.conformance.adapter_v0.runner import run_public_fixture_v0; "
            "from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0; "
            "from tests.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0; "
            "r=Path('tests/conformance/adapter_v0/fixtures'); "
            "assert run_public_fixture_v0(r/'flat',SyntheticFlatAdapterV0())['segment_count']==3; "
            "assert run_public_fixture_v0(r/'structured',SyntheticStructuredAdapterV0())['relation_count']==6"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(("src", "src", "."))
        completed = subprocess.run(
            [sys.executable, "-B", "-c", command],
            cwd=export,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)


if __name__ == "__main__":
    unittest.main()
