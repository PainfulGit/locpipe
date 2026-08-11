from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from locpipe.contracts.v0 import ArtifactHashV0, ContractViolation, WorkflowProfile  # noqa: E402
from locpipe.kernel.v0.context import (  # noqa: E402
    ProjectContextV0,
    acquire_context_write_lease,
    initialize_project_context,
)
from locpipe.kernel.v0.context_transactions import (  # noqa: E402
    create_context_staging,
    inspect_context_file_recovery,
    inspect_context_group_recovery,
    publish_context_file,
    publish_context_group,
    release_context_write_lease,
    rollback_context_file,
    rollback_context_group,
)
from locpipe.kernel.v0.transactions import (  # noqa: E402
    NamespaceV0,
    PublicationEntryV0,
    PublicationGroupSpecV0,
    PublicationSpecV0,
    RecoveryDispositionV0,
    SyntheticTransactionStoreV0,
    TransactionErrorCode,
    TransactionStateV0,
    TransactionViolation,
    WriteLeaseV0,
    publish_verified_file,
)


OWNER = "7" * 32


def raw_sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class InjectedCrash(RuntimeError):
    pass


class ContextTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name) / "store"
        root.mkdir()
        self.store = SyntheticTransactionStoreV0.create(root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def context(self, project: str = "project", release: str = "release", sha: str = "a" * 64) -> ProjectContextV0:
        return ProjectContextV0(
            NamespaceV0("workspace", project, release),
            WorkflowProfile.CONTENT_ONLY,
            sha,
        )

    def file_fixture(
        self,
        context: ProjectContextV0,
        operation: str = "publish-file",
        payload: bytes = b"new payload\n",
        preimage: bytes | None = None,
    ):
        paths = initialize_project_context(self.store, context)
        if preimage is not None:
            target = paths.outputs_root / "nested" / "result.bin"
            target.parent.mkdir()
            target.write_bytes(preimage)
        lease = acquire_context_write_lease(
            self.store, context, operation, owner_token_factory=lambda: OWNER
        )
        staging = create_context_staging(self.store, context, operation)
        artifact = staging / "nested" / "result.bin"
        artifact.parent.mkdir()
        artifact.write_bytes(payload)
        spec = PublicationSpecV0(
            context.namespace,
            operation,
            "nested/result.bin",
            ArtifactHashV0("nested/result.bin", "raw", raw_sha(payload)),
            raw_sha(preimage) if preimage is not None else None,
        )
        return paths, lease, spec

    def group_fixture(self, context: ProjectContextV0, operation: str = "publish-group"):
        paths = initialize_project_context(self.store, context)
        old = b"old-a\n"
        (paths.outputs_root / "a.bin").write_bytes(old)
        lease = acquire_context_write_lease(
            self.store, context, operation, owner_token_factory=lambda: OWNER
        )
        staging = create_context_staging(self.store, context, operation)
        payloads = {"a.bin": b"new-a\n", "nested/b.bin": b"new-b\n"}
        entries = []
        for name, payload in payloads.items():
            artifact = staging / Path(*name.split("/"))
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(payload)
            entries.append(PublicationEntryV0(
                ArtifactHashV0(name, "raw", raw_sha(payload)),
                raw_sha(old) if name == "a.bin" else None,
            ))
        return paths, lease, PublicationGroupSpecV0(context.namespace, operation, tuple(entries)), payloads

    def assert_global_transaction_domains_empty(self) -> None:
        self.assertEqual([], list(self.store.targets.iterdir()))
        self.assertEqual([], list(self.store.staging.iterdir()))
        self.assertEqual([], list(self.store.transactions.iterdir()))

    def test_single_publication_is_context_local_idempotent_and_releasable(self) -> None:
        context = self.context()
        paths, lease, spec = self.file_fixture(context)
        receipt = publish_context_file(self.store, context, spec, lease)
        self.assertEqual(b"new payload\n", (paths.outputs_root / "nested/result.bin").read_bytes())
        self.assertTrue((paths.transactions_root / spec.operation_id / "journal.json").is_file())
        self.assertTrue((paths.transactions_root / spec.operation_id / "receipt.json").is_file())
        self.assertEqual([], list(paths.receipts_root.iterdir()))
        self.assertEqual(receipt, publish_context_file(self.store, context, spec, lease))
        self.assert_global_transaction_domains_empty()
        release_context_write_lease(self.store, context, lease)

    def test_group_publication_is_context_local_and_releasable(self) -> None:
        context = self.context()
        paths, lease, spec, payloads = self.group_fixture(context)
        receipt = publish_context_group(self.store, context, spec, lease)
        self.assertEqual(tuple(payloads), tuple(target.path for target in receipt.targets))
        for name, payload in payloads.items():
            self.assertEqual(payload, (paths.outputs_root / Path(*name.split("/"))).read_bytes())
        self.assertEqual(TransactionStateV0.VERIFIED, inspect_context_group_recovery(
            self.store, context, spec.operation_id
        ).journal_state)
        self.assert_global_transaction_domains_empty()
        release_context_write_lease(self.store, context, lease)

    def test_projects_and_releases_publish_identical_paths_without_collision(self) -> None:
        contexts = (
            self.context("project-a", "same-release"),
            self.context("project-b", "same-release"),
            self.context("project-a", "other-release"),
        )
        roots = []
        for index, context in enumerate(contexts):
            paths, lease, spec = self.file_fixture(
                context, operation=f"publish-{index}", payload=f"payload-{index}".encode()
            )
            publish_context_file(self.store, context, spec, lease)
            roots.append(paths.outputs_root)
        self.assertEqual(3, len(set(roots)))
        for index, root in enumerate(roots):
            self.assertEqual(f"payload-{index}".encode(), (root / "nested/result.bin").read_bytes())

    def test_wrong_context_spec_lease_and_marker_fail_closed(self) -> None:
        selected = self.context("selected")
        other = self.context("other")
        paths, lease, spec = self.file_fixture(selected)
        initialize_project_context(self.store, other)
        with self.assertRaises(ContractViolation):
            publish_context_file(self.store, other, spec, lease)
        self.assertFalse((paths.outputs_root / "nested/result.bin").exists())

        marker = paths.namespace_root / "context.json"
        payload = json.loads(marker.read_text(encoding="utf-8"))
        payload["context"]["config_snapshot_sha256"] = "b" * 64
        marker.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(ContractViolation):
            publish_context_file(self.store, selected, spec, lease)
        self.assertFalse((paths.outputs_root / "nested/result.bin").exists())

    def test_verified_output_cannot_be_reclaimed_by_replaced_context_marker(self) -> None:
        original = self.context(sha="a" * 64)
        paths, lease, spec = self.file_fixture(original)
        publish_context_file(self.store, original, spec, lease)
        replacement = self.context(sha="b" * 64)
        marker = paths.namespace_root / "context.json"
        payload = json.loads(marker.read_text(encoding="utf-8"))
        payload["context"] = replacement.as_dict()
        payload["context_digest"] = replacement.context_digest
        marker.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(ContractViolation):
            inspect_context_file_recovery(self.store, replacement, spec.operation_id)

    def test_extra_staged_file_fails_before_target_change(self) -> None:
        context = self.context()
        paths, lease, spec = self.file_fixture(context)
        (paths.staging_root / spec.operation_id / "extra.bin").write_bytes(b"extra")
        with self.assertRaises(ContractViolation):
            publish_context_file(self.store, context, spec, lease)
        self.assertFalse((paths.outputs_root / "nested/result.bin").exists())

    def test_incomplete_single_blocks_release_then_rolls_back_exactly(self) -> None:
        context = self.context()
        paths, lease, spec = self.file_fixture(context, preimage=b"old payload\n")

        def fail(point: str) -> None:
            if point == "AFTER_APPLIED":
                raise InjectedCrash(point)

        with self.assertRaises(InjectedCrash):
            publish_context_file(self.store, context, spec, lease, _failure_hook=fail)
        with self.assertRaises(TransactionViolation) as caught:
            release_context_write_lease(self.store, context, lease)
        self.assertEqual(TransactionErrorCode.RECOVERY_REQUIRED, caught.exception.code)
        plan = inspect_context_file_recovery(self.store, context, spec.operation_id)
        self.assertEqual(RecoveryDispositionV0.ROLLBACK_REQUIRED, plan.disposition)
        rollback_context_file(self.store, context, plan, lease)
        self.assertEqual(b"old payload\n", (paths.outputs_root / "nested/result.bin").read_bytes())
        release_context_write_lease(self.store, context, lease)

    def test_incomplete_group_blocks_release_then_rolls_back_exactly(self) -> None:
        context = self.context()
        paths, lease, spec, _ = self.group_fixture(context)

        def fail(point: str) -> None:
            if point == "AFTER_GROUP_ARTIFACT_REPLACED:0001":
                raise InjectedCrash(point)

        with self.assertRaises(InjectedCrash):
            publish_context_group(self.store, context, spec, lease, _failure_hook=fail)
        with self.assertRaises(TransactionViolation):
            release_context_write_lease(self.store, context, lease)
        plan = inspect_context_group_recovery(self.store, context, spec.operation_id)
        self.assertEqual(RecoveryDispositionV0.ROLLBACK_REQUIRED, plan.disposition)
        rollback_context_group(self.store, context, plan, lease)
        self.assertEqual(b"old-a\n", (paths.outputs_root / "a.bin").read_bytes())
        self.assertFalse((paths.outputs_root / "nested/b.bin").exists())
        release_context_write_lease(self.store, context, lease)

    def test_verified_receipt_drift_is_unknown_and_blocks_release(self) -> None:
        context = self.context()
        paths, lease, spec = self.file_fixture(context)
        publish_context_file(self.store, context, spec, lease)
        receipt = paths.transactions_root / spec.operation_id / "receipt.json"
        receipt.write_bytes(receipt.read_bytes() + b" ")
        self.assertEqual(
            RecoveryDispositionV0.UNKNOWN,
            inspect_context_file_recovery(self.store, context, spec.operation_id).disposition,
        )
        with self.assertRaises(TransactionViolation):
            release_context_write_lease(self.store, context, lease)

    def test_context_release_cannot_bypass_incomplete_parent_transaction(self) -> None:
        context = self.context()
        initialize_project_context(self.store, context)
        lease = acquire_context_write_lease(
            self.store, context, "mixed-backend", owner_token_factory=lambda: OWNER
        )
        staging = self.store.create_staging("mixed-backend")
        payload = b"global postimage\n"
        (staging / "result.bin").write_bytes(payload)
        spec = PublicationSpecV0(
            context.namespace,
            "mixed-backend",
            "result.bin",
            ArtifactHashV0("result.bin", "raw", raw_sha(payload)),
            None,
        )

        def fail(point: str) -> None:
            if point == "AFTER_APPLIED":
                raise InjectedCrash(point)

        with self.assertRaises(InjectedCrash):
            publish_verified_file(self.store, spec, lease, staging, _failure_hook=fail)
        with self.assertRaises(TransactionViolation) as caught:
            release_context_write_lease(self.store, context, lease)
        self.assertEqual(TransactionErrorCode.RECOVERY_REQUIRED, caught.exception.code)
        with self.assertRaises(TransactionViolation) as locked:
            acquire_context_write_lease(
                self.store, context, "successor", owner_token_factory=lambda: "8" * 32
            )
        self.assertEqual(TransactionErrorCode.WRITER_LOCKED, locked.exception.code)

    def run_crash(self, mode: str, boundary: str, code: int) -> None:
        worker = ROOT / "tests/phase3_context_transaction_worker.py"
        completed = subprocess.run(
            [sys.executable, str(worker), mode, str(self.store.root), boundary],
            cwd=ROOT,
            check=False,
            timeout=15,
        )
        self.assertEqual(code, completed.returncode)

    def test_real_exit_single_publication_and_rollback_boundaries_are_recoverable(self) -> None:
        publish = {
            "AFTER_PREPARED": RecoveryDispositionV0.SAFE_RETRY,
            "AFTER_APPLYING": RecoveryDispositionV0.SAFE_RETRY,
            "AFTER_STAGED_FSYNC": RecoveryDispositionV0.SAFE_RETRY,
            "AFTER_REPLACE_BEFORE_APPLIED": RecoveryDispositionV0.ROLLBACK_REQUIRED,
            "AFTER_APPLIED": RecoveryDispositionV0.ROLLBACK_REQUIRED,
            "AFTER_RECEIPT_BEFORE_VERIFIED": RecoveryDispositionV0.ROLLBACK_REQUIRED,
        }
        for index, (boundary, disposition) in enumerate(publish.items()):
            with self.subTest(boundary=boundary):
                if index:
                    self.tearDown()
                    self.setUp()
                self.run_crash("single-publish", boundary, 81)
                context = self.context()
                plan = inspect_context_file_recovery(self.store, context, "single-crash")
                self.assertEqual(disposition, plan.disposition)
                lease = WriteLeaseV0(context.namespace, context.namespace.token, OWNER, "single-crash", 1)
                if disposition is RecoveryDispositionV0.SAFE_RETRY:
                    staging = initialize_project_context(self.store, context).staging_root / "single-crash"
                    payload = b"new\n"
                    spec = PublicationSpecV0(
                        context.namespace, "single-crash", "result.bin",
                        ArtifactHashV0("result.bin", "raw", raw_sha(payload)), raw_sha(b"old\n")
                    )
                    publish_context_file(self.store, context, spec, lease)
                else:
                    rollback_context_file(self.store, context, plan, lease)

        rollback_boundaries = (
            "AFTER_ROLLBACK_TARGET",
            "AFTER_ROLLBACK_SUPERSESSION",
            "AFTER_ROLLBACK_EVIDENCE",
        )
        for boundary in rollback_boundaries:
            with self.subTest(boundary=boundary):
                self.tearDown()
                self.setUp()
                self.run_crash("single-rollback", boundary, 82)
                context = self.context()
                plan = inspect_context_file_recovery(self.store, context, "single-crash")
                self.assertEqual(RecoveryDispositionV0.ROLLBACK_REQUIRED, plan.disposition)
                lease = WriteLeaseV0(context.namespace, context.namespace.token, OWNER, "single-crash", 1)
                rollback_context_file(self.store, context, plan, lease)
                paths = initialize_project_context(self.store, context)
                self.assertEqual(b"old\n", (paths.outputs_root / "result.bin").read_bytes())

    def test_real_exit_group_publication_and_rollback_boundaries_are_recoverable(self) -> None:
        publish = {
            "AFTER_ATOMIC_TEMP_FSYNC:GROUP_PREPARED_JOURNAL": RecoveryDispositionV0.SAFE_RETRY,
            "AFTER_GROUP_PREPARED": RecoveryDispositionV0.SAFE_RETRY,
            "AFTER_ATOMIC_TEMP_FSYNC:GROUP_APPLYING_JOURNAL": RecoveryDispositionV0.SAFE_RETRY,
            "AFTER_GROUP_APPLYING": RecoveryDispositionV0.SAFE_RETRY,
            "AFTER_GROUP_ARTIFACT_STAGED:0001": RecoveryDispositionV0.SAFE_RETRY,
            "AFTER_GROUP_ARTIFACT_STAGED:0002": RecoveryDispositionV0.ROLLBACK_REQUIRED,
            "AFTER_GROUP_ARTIFACT_REPLACED:0001": RecoveryDispositionV0.ROLLBACK_REQUIRED,
            "AFTER_GROUP_ARTIFACT_REPLACED:0002": RecoveryDispositionV0.ROLLBACK_REQUIRED,
            "AFTER_GROUP_APPLIED": RecoveryDispositionV0.ROLLBACK_REQUIRED,
            "AFTER_GROUP_RECEIPT_WRITE": RecoveryDispositionV0.ROLLBACK_REQUIRED,
            "AFTER_GROUP_RECEIPT_BEFORE_VERIFIED": RecoveryDispositionV0.ROLLBACK_REQUIRED,
        }
        for index, (boundary, disposition) in enumerate(publish.items()):
            with self.subTest(boundary=boundary):
                if index:
                    self.tearDown()
                    self.setUp()
                self.run_crash("group-publish", boundary, 83)
                context = self.context()
                plan = inspect_context_group_recovery(self.store, context, "group-crash")
                self.assertEqual(disposition, plan.disposition)
                lease = WriteLeaseV0(context.namespace, context.namespace.token, OWNER, "group-crash", 1)
                if disposition is RecoveryDispositionV0.ROLLBACK_REQUIRED:
                    rollback_context_group(self.store, context, plan, lease)
                else:
                    payloads = {"a.bin": b"new-a\n", "b.bin": b"new-b\n"}
                    entries = tuple(PublicationEntryV0(
                        ArtifactHashV0(name, "raw", raw_sha(payload)),
                        raw_sha(b"old-a\n") if name == "a.bin" else None,
                    ) for name, payload in payloads.items())
                    publish_context_group(
                        self.store, context,
                        PublicationGroupSpecV0(context.namespace, "group-crash", entries), lease
                    )

        rollback_boundaries = (
            "AFTER_GROUP_ROLLBACK_ARTIFACT:0001",
            "AFTER_GROUP_ROLLBACK_ARTIFACT:0002",
            "AFTER_GROUP_ROLLBACK_TARGETS",
            "AFTER_GROUP_ROLLBACK_SUPERSESSION",
            "AFTER_GROUP_ROLLBACK_EVIDENCE",
        )
        for boundary in rollback_boundaries:
            with self.subTest(boundary=boundary):
                self.tearDown()
                self.setUp()
                self.run_crash("group-rollback", boundary, 84)
                context = self.context()
                plan = inspect_context_group_recovery(self.store, context, "group-crash")
                self.assertEqual(RecoveryDispositionV0.ROLLBACK_REQUIRED, plan.disposition)
                lease = WriteLeaseV0(context.namespace, context.namespace.token, OWNER, "group-crash", 1)
                rollback_context_group(self.store, context, plan, lease)
                paths = initialize_project_context(self.store, context)
                self.assertEqual(b"old-a\n", (paths.outputs_root / "a.bin").read_bytes())
                self.assertFalse((paths.outputs_root / "b.bin").exists())


if __name__ == "__main__":
    unittest.main()
