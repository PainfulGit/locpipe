from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.check_public_boundary import (
    MANIFEST_CLASSIFICATION,
    MANIFEST_SCHEMA_VERSION,
    _manifest_bytes,
    _manifest_tree_sha256,
    _scan_commit_metadata,
    _strict_json_loads,
    _tracked_files,
    _validate_commit_metadata,
    _validate_manifest,
    _validate_manifest_value,
)
from tools.write_public_export_manifest import _index_manifest_rows, _write_public_export_manifest


def _row(path: str, payload: bytes) -> dict[str, object]:
    return {
        "path": path,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def _manifest_value(rows: list[dict[str, object]]) -> dict[str, object]:
    return json.loads(_manifest_bytes(rows).decode("utf-8"))


def _run_git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(("git", *args), cwd=root)


class PublicBoundaryMetadataTests(unittest.TestCase):
    def test_current_history_uses_only_approved_noreply_identity(self) -> None:
        self.assertGreater(_scan_commit_metadata(), 0)

    def test_personal_or_unapproved_identity_is_rejected(self) -> None:
        with self.assertRaisesRegex(SystemExit, "unapproved author identity"):
            _validate_commit_metadata((
                ("a" * 40, "Contributor", "name@example.com", "PainfulGit", "258659461+PainfulGit@users.noreply.github.com"),
            ))
        with self.assertRaisesRegex(SystemExit, "unapproved committer identity"):
            _validate_commit_metadata((
                ("b" * 40, "PainfulGit", "258659461+PainfulGit@users.noreply.github.com", "Contributor", "name@example.com"),
            ))


class PublicManifestContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payloads = {"a.txt": b"alpha\n", "b.json": b"{}\n"}
        self.rows = [_row(path, payload) for path, payload in sorted(self.payloads.items())]
        self.paths = ("PUBLIC_EXPORT_MANIFEST.json", *tuple(sorted(self.payloads)))

    def validate(self, value: object) -> None:
        _validate_manifest_value(value, self.paths, self.payloads.__getitem__)

    def test_tree_formula_and_manifest_bytes_are_canonical_and_deterministic(self) -> None:
        self.assertEqual(
            _manifest_tree_sha256(self.rows),
            "4038067c23a809a943c74561ff342bb9bba40f548355b75e99ff290d595d633a",
        )
        first = _manifest_bytes(self.rows)
        second = _manifest_bytes(tuple(dict(row) for row in self.rows))
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        self.assertEqual(first.count(b"\n"), 1)
        self.assertNotIn(b": ", first)
        self.assertNotIn(b", ", first)
        value = json.loads(first.decode("utf-8"))
        self.assertEqual(value["classification"], MANIFEST_CLASSIFICATION)
        self.assertEqual(value["schema_version"], MANIFEST_SCHEMA_VERSION)
        self.validate(value)

    def test_top_level_contract_and_tree_drift_fail_closed(self) -> None:
        value = _manifest_value(self.rows)
        cases: list[tuple[str, object, str]] = [
            ("unknown", {**value, "extra": 1}, "top-level shape"),
            ("missing", {key: item for key, item in value.items() if key != "classification"}, "top-level shape"),
            ("classification", {**value, "classification": "PRIVATE"}, "classification"),
            ("schema", {**value, "schema_version": 2}, "schema version"),
            ("schema-bool", {**value, "schema_version": True}, "schema version"),
            ("tree-type", {**value, "tree_sha256": 1}, "tree sha256"),
            ("tree-drift", {**value, "tree_sha256": "0" * 64}, "tree sha256 drift"),
        ]
        for name, candidate, message in cases:
            with self.subTest(name=name), self.assertRaisesRegex(SystemExit, message):
                self.validate(candidate)
        with self.assertRaisesRegex(SystemExit, "manifest is malformed"):
            _strict_json_loads(b'{"classification":"PUBLIC_EXPORT","classification":"PRIVATE"}')
        with self.assertRaisesRegex(SystemExit, "manifest is malformed"):
            _strict_json_loads(b'{"files":[{"path":"a","path":"b"}]}')

    def test_row_shape_type_order_and_safe_paths_fail_closed(self) -> None:
        value = _manifest_value(self.rows)
        row_cases: list[tuple[str, list[dict[str, object]], str]] = [
            ("unknown-field", [{**self.rows[0], "extra": 1}, self.rows[1]], "row is malformed"),
            ("missing-field", [{"path": "a.txt", "sha256": self.rows[0]["sha256"]}, self.rows[1]], "row is malformed"),
            ("sha-type", [{**self.rows[0], "sha256": 1}, self.rows[1]], "sha256 is malformed"),
            ("sha-format", [{**self.rows[0], "sha256": "A" * 64}, self.rows[1]], "sha256 is malformed"),
            ("size-type", [{**self.rows[0], "size": True}, self.rows[1]], "size is malformed"),
            ("size-negative", [{**self.rows[0], "size": -1}, self.rows[1]], "size is malformed"),
            ("unsorted", [self.rows[1], self.rows[0]], "sorted and unique"),
            ("duplicate", [self.rows[0], self.rows[0]], "sorted and unique"),
        ]
        unsafe_paths = (
            "../escape.json", "/absolute.json", "C:" + "/drive.json", "x\\y.json",
            "x//y.json", "x/../a.txt", "./a.txt", "line\nbreak.json",
        )
        for unsafe in unsafe_paths:
            row_cases.append((unsafe, [{**self.rows[0], "path": unsafe}, self.rows[1]], "unsafe public export path"))
        for name, rows, message in row_cases:
            candidate = {**value, "files": rows}
            with self.subTest(name=name), self.assertRaisesRegex(SystemExit, message):
                self.validate(candidate)

    def test_stale_row_and_path_set_fail_closed(self) -> None:
        value = _manifest_value(self.rows)
        stale = [{**self.rows[0], "size": self.rows[0]["size"] + 1}, self.rows[1]]
        with self.assertRaisesRegex(SystemExit, "manifest hash drift"):
            self.validate({**value, "files": stale, "tree_sha256": _manifest_tree_sha256(stale)})
        with self.assertRaisesRegex(SystemExit, "path set drift"):
            _validate_manifest_value(_manifest_value([self.rows[0]]), self.paths, self.payloads.__getitem__)

    def test_index_rows_are_sorted_deterministic_and_self_excluding(self) -> None:
        paths = ("PUBLIC_EXPORT_MANIFEST.json", "a.txt", "b.json")
        expected = tuple(self.rows)
        self.assertEqual(_index_manifest_rows(paths, self.payloads.__getitem__), expected)
        self.assertEqual(_index_manifest_rows(paths, self.payloads.__getitem__), expected)
        with self.assertRaisesRegex(SystemExit, "sorted and unique"):
            _index_manifest_rows(("b.json", "a.txt"), self.payloads.__getitem__)
        with self.assertRaisesRegex(SystemExit, "sorted and unique"):
            _index_manifest_rows(("a.txt", "a.txt"), self.payloads.__getitem__)

    def test_writer_rejects_ambiguity_and_round_trips_committed_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _run_git(root, "init", "--quiet")
            _run_git(root, "config", "user.name", "Public Boundary Test")
            _run_git(root, "config", "user.email", "public-boundary@example.invalid")
            _run_git(root, "config", "core.autocrlf", "false")
            (root / "a.txt").write_bytes(b"old\n")
            (root / "PUBLIC_EXPORT_MANIFEST.json").write_text("{}\n", encoding="utf-8")
            _run_git(root, "add", "--", "a.txt", "PUBLIC_EXPORT_MANIFEST.json")
            _run_git(root, "commit", "--quiet", "-m", "base")

            (root / "a.txt").write_bytes(b"staged\n")
            with self.assertRaisesRegex(SystemExit, "unstaged tracked changes"):
                _write_public_export_manifest(root=root)
            _run_git(root, "add", "--", "a.txt")
            (root / "unrelated.tmp").write_bytes(b"untracked\n")
            with self.assertRaisesRegex(SystemExit, "untracked files"):
                _write_public_export_manifest(root=root)
            (root / "unrelated.tmp").unlink()

            first = _write_public_export_manifest(root=root)
            self.assertEqual(first, (root / "PUBLIC_EXPORT_MANIFEST.json").read_bytes())
            self.assertEqual(
                _run_git(root, "diff", "--name-only").decode().splitlines(),
                ["PUBLIC_EXPORT_MANIFEST.json"],
            )
            self.assertEqual(_run_git(root, "ls-files", "--others", "--exclude-standard"), b"")
            value = json.loads(first.decode("utf-8"))
            self.assertEqual(value["files"], [_row("a.txt", b"staged\n")])

            _run_git(root, "add", "--", "PUBLIC_EXPORT_MANIFEST.json")
            _run_git(root, "commit", "--quiet", "-m", "manifest contract")
            _validate_manifest(_tracked_files(root=root), root=root)

    def test_writer_rejects_manifest_prestaged_or_empty_index_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _run_git(root, "init", "--quiet")
            _run_git(root, "config", "user.name", "Public Boundary Test")
            _run_git(root, "config", "user.email", "public-boundary@example.invalid")
            _run_git(root, "config", "core.autocrlf", "false")
            (root / "PUBLIC_EXPORT_MANIFEST.json").write_text("{}\n", encoding="utf-8")
            _run_git(root, "add", "--", "PUBLIC_EXPORT_MANIFEST.json")
            _run_git(root, "commit", "--quiet", "-m", "base")
            with self.assertRaisesRegex(SystemExit, "staged public changes"):
                _write_public_export_manifest(root=root)
            (root / "PUBLIC_EXPORT_MANIFEST.json").write_text('{"changed":true}\n', encoding="utf-8")
            _run_git(root, "add", "--", "PUBLIC_EXPORT_MANIFEST.json")
            with self.assertRaisesRegex(SystemExit, "manifest must not be staged"):
                _write_public_export_manifest(root=root)


if __name__ == "__main__":
    unittest.main()
