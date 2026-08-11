from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from locpipe.contracts.v0 import ContractViolation, ErrorCode, WorkflowProfile  # noqa: E402
from locpipe.kernel.v0.context import (  # noqa: E402
    ProjectContextV0,
    acquire_context_write_lease,
    initialize_project_context,
    release_context_write_lease,
    resolve_project_paths,
)
from locpipe.kernel.v0.transactions import (  # noqa: E402
    NamespaceV0,
    SyntheticTransactionStoreV0,
    TransactionErrorCode,
    TransactionViolation,
)


OWNER = "c" * 32
OTHER_OWNER = "d" * 32


class ProjectContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_store(self, name: str = "store") -> SyntheticTransactionStoreV0:
        root = self.base / name
        root.mkdir()
        return SyntheticTransactionStoreV0.create(root)

    def make_context(
        self,
        *,
        workspace: str = "fixture-workspace",
        project: str = "fixture-project",
        release: str = "fixture-release",
        profile: WorkflowProfile = WorkflowProfile.CONTENT_ONLY,
        config_sha: str = "a" * 64,
    ) -> ProjectContextV0:
        return ProjectContextV0(
            NamespaceV0(workspace, project, release),
            profile,
            config_sha,
        )

    def test_context_identity_is_immutable_and_location_independent(self) -> None:
        context = self.make_context()
        self.assertEqual(
            "ba8ba418ce8907e75712645d372262e923687cd7c0d4b0274719b3e86f9b8e67",
            context.context_digest,
        )
        self.assertNotIn(str(self.base), json.dumps(context.as_dict()))
        with self.assertRaises(ContractViolation):
            self.make_context(config_sha="A" * 64)

    def test_initialize_and_read_only_resolve_have_exact_layout(self) -> None:
        store = self.make_store()
        context = self.make_context()
        with self.assertRaises(ContractViolation):
            resolve_project_paths(store, context)
        self.assertFalse((store.root / "contexts").exists())

        paths = initialize_project_context(store, context)
        self.assertEqual(
            {"cache", "context.json", "outputs", "receipts", "staging", "state", "transactions"},
            {path.name for path in paths.namespace_root.iterdir()},
        )
        self.assertEqual(paths, resolve_project_paths(store, context))
        marker = json.loads((paths.namespace_root / "context.json").read_text(encoding="utf-8"))
        self.assertEqual(context.context_digest, marker["context_digest"])
        self.assertNotIn(str(store.root), json.dumps(marker))

    def test_initialization_is_idempotent_and_allows_domain_files(self) -> None:
        store = self.make_store()
        context = self.make_context()
        paths = initialize_project_context(store, context)
        domain_file = paths.state_root / "state.json"
        domain_file.write_text("{}\n", encoding="utf-8")
        marker = paths.namespace_root / "context.json"
        before = (marker.read_bytes(), marker.stat().st_mtime_ns, domain_file.read_bytes())
        self.assertEqual(paths, initialize_project_context(store, context))
        after = (marker.read_bytes(), marker.stat().st_mtime_ns, domain_file.read_bytes())
        self.assertEqual(before, after)

    def test_projects_and_releases_have_disjoint_roots(self) -> None:
        store = self.make_store()
        contexts = (
            self.make_context(project="project-a", release="same-release"),
            self.make_context(project="project-b", release="same-release"),
            self.make_context(project="project-a", release="other-release"),
        )
        paths = [initialize_project_context(store, context) for context in contexts]
        roots = [row.namespace_root for row in paths]
        self.assertEqual(3, len(set(roots)))
        for field in ("state_root", "cache_root", "staging_root", "transactions_root", "outputs_root"):
            self.assertEqual(3, len({getattr(row, field) for row in paths}))

    def test_same_namespace_profile_or_config_drift_is_blocked(self) -> None:
        store = self.make_store()
        context = self.make_context()
        initialize_project_context(store, context)
        variants = (
            self.make_context(profile=WorkflowProfile.ARTIFACT_BUILD),
            self.make_context(config_sha="b" * 64),
        )
        for variant in variants:
            with self.subTest(variant=variant.as_dict()):
                with self.assertRaises(ContractViolation) as caught:
                    initialize_project_context(store, variant)
                self.assertEqual(ErrorCode.BINDING_MISMATCH, caught.exception.record.code)

    def test_known_partial_initialization_is_resumable_after_real_exit(self) -> None:
        worker = ROOT / "tests" / "phase3_context_worker.py"
        boundaries = tuple(
            f"AFTER_CONTEXT_DIRECTORY:{name}"
            for name in ("cache", "outputs", "receipts", "staging", "state", "transactions")
        ) + ("AFTER_CONTEXT_MARKER",)
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary):
                store = self.make_store(f"crash-{index}")
                completed = subprocess.run(
                    [sys.executable, str(worker), "init-crash", str(store.root), boundary],
                    cwd=ROOT,
                    check=False,
                    timeout=15,
                )
                self.assertEqual(81, completed.returncode)
                paths = initialize_project_context(store, self.make_context(
                    workspace="workspace", project="project", release="release"
                ))
                self.assertEqual(paths, resolve_project_paths(store, self.make_context(
                    workspace="workspace", project="project", release="release"
                )))

    def test_unknown_entry_and_marker_drift_fail_closed(self) -> None:
        store = self.make_store()
        context = self.make_context()
        contexts = store.root / "contexts"
        namespace_root = contexts / context.namespace.token
        namespace_root.mkdir(parents=True)
        (namespace_root / "unexpected.bin").write_bytes(b"x")
        with self.assertRaises(ContractViolation) as unknown:
            initialize_project_context(store, context)
        self.assertEqual(ErrorCode.BINDING_MISMATCH, unknown.exception.record.code)

        store = self.make_store("marker-drift")
        paths = initialize_project_context(store, context)
        marker = paths.namespace_root / "context.json"
        value = json.loads(marker.read_text(encoding="utf-8"))
        value["context_digest"] = "0" * 64
        marker.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(ContractViolation) as drift:
            resolve_project_paths(store, context)
        self.assertEqual(ErrorCode.BINDING_MISMATCH, drift.exception.record.code)

    def test_unbound_partial_context_cannot_claim_domain_files(self) -> None:
        store = self.make_store()
        context = self.make_context()
        state = store.root / "contexts" / context.namespace.token / "state"
        state.mkdir(parents=True)
        (state / "foreign.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaises(ContractViolation) as caught:
            initialize_project_context(store, context)
        self.assertEqual(ErrorCode.BINDING_MISMATCH, caught.exception.record.code)
        self.assertFalse((state.parent / "context.json").exists())

    def test_concurrent_conflicting_contexts_never_overwrite_marker(self) -> None:
        store = self.make_store()
        first = self.make_context(config_sha="a" * 64)
        second = self.make_context(config_sha="b" * 64)
        barrier = threading.Barrier(2)
        results: list[tuple[str, str]] = []

        def initialize(selected: ProjectContextV0) -> None:
            def synchronize(point: str) -> None:
                if point == "AFTER_CONTEXT_DIRECTORY:transactions":
                    barrier.wait(timeout=5)

            try:
                initialize_project_context(store, selected, _failure_hook=synchronize)
                results.append(("PASS", selected.context_digest))
            except ContractViolation as error:
                results.append((error.record.code.value, selected.context_digest))

        threads = [threading.Thread(target=initialize, args=(selected,)) for selected in (first, second)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(1, sum(status == "PASS" for status, _ in results))
        self.assertEqual(1, sum(status == ErrorCode.BINDING_MISMATCH.value for status, _ in results))
        winner = next(digest for status, digest in results if status == "PASS")
        marker = json.loads(
            (store.root / "contexts" / first.namespace.token / "context.json").read_text(encoding="utf-8")
        )
        self.assertEqual(winner, marker["context_digest"])

    def test_symlinked_context_directory_fails_closed(self) -> None:
        store = self.make_store()
        context = self.make_context()
        paths = initialize_project_context(store, context)
        paths.state_root.rmdir()
        external = self.base / "external"
        external.mkdir()
        try:
            os.symlink(external, paths.state_root, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"local symlink creation unavailable: {error}")
        with self.assertRaises(ContractViolation) as caught:
            resolve_project_paths(store, context)
        self.assertEqual(ErrorCode.PATH_ESCAPE, caught.exception.record.code)

    def test_context_lease_is_exclusive_and_context_bound(self) -> None:
        store = self.make_store()
        first = self.make_context(project="first")
        second = self.make_context(project="second")
        initialize_project_context(store, first)
        initialize_project_context(store, second)
        lease = acquire_context_write_lease(
            store, first, "op-first", owner_token_factory=lambda: OWNER
        )
        with self.assertRaises(TransactionViolation) as locked:
            acquire_context_write_lease(
                store, first, "op-other", owner_token_factory=lambda: OTHER_OWNER
            )
        self.assertEqual(TransactionErrorCode.WRITER_LOCKED, locked.exception.code)
        other = acquire_context_write_lease(
            store, second, "op-second", owner_token_factory=lambda: OTHER_OWNER
        )
        with self.assertRaises(ContractViolation) as wrong:
            release_context_write_lease(store, second, lease)
        self.assertEqual(ErrorCode.BINDING_MISMATCH, wrong.exception.record.code)
        release_context_write_lease(store, first, lease)
        release_context_write_lease(store, second, other)

    def test_context_lease_fencing_and_no_auto_steal(self) -> None:
        store = self.make_store()
        context = self.make_context()
        initialize_project_context(store, context)
        lease = acquire_context_write_lease(
            store, context, "op", owner_token_factory=lambda: OWNER
        )
        epoch = store.epochs / f"{context.namespace.token}.txt"
        epoch.write_text("2\n", encoding="ascii")
        with self.assertRaises(TransactionViolation) as stale:
            release_context_write_lease(store, context, lease)
        self.assertEqual(TransactionErrorCode.FENCE_STALE, stale.exception.code)
        with self.assertRaises(TransactionViolation) as locked:
            acquire_context_write_lease(
                store, context, "other", owner_token_factory=lambda: OTHER_OWNER
            )
        self.assertEqual(TransactionErrorCode.WRITER_LOCKED, locked.exception.code)

    def test_two_processes_cannot_hold_same_context(self) -> None:
        store = self.make_store()
        context = self.make_context(workspace="workspace", project="project", release="release")
        initialize_project_context(store, context)
        ready = self.base / "ready"
        release = self.base / "release"
        worker = ROOT / "tests" / "phase3_context_worker.py"
        process = subprocess.Popen(
            [sys.executable, str(worker), "hold", str(store.root), str(ready), str(release)],
            cwd=ROOT,
        )
        try:
            deadline = time.monotonic() + 10
            while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists(), "context worker did not acquire lease")
            with self.assertRaises(TransactionViolation) as locked:
                acquire_context_write_lease(
                    store, context, "other", owner_token_factory=lambda: OTHER_OWNER
                )
            self.assertEqual(TransactionErrorCode.WRITER_LOCKED, locked.exception.code)
        finally:
            release.write_text("release", encoding="ascii")
            process.wait(timeout=10)
        self.assertEqual(0, process.returncode)


if __name__ == "__main__":
    unittest.main()
