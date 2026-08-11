from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from locpipe.contracts.v0 import ArtifactHashV0, ContractViolation, ErrorCode  # noqa: E402
from locpipe.kernel.v0.transactions import (  # noqa: E402
    NamespaceV0,
    PublicationSpecV0,
    RecoveryDispositionV0,
    RecoveryPlanV0,
    SyntheticTransactionStoreV0,
    TransactionErrorCode,
    TransactionStateV0,
    TransactionViolation,
    WriteLeaseV0,
    acquire_write_lease,
    inspect_recovery,
    publish_verified_file,
    release_write_lease,
    rollback_publication,
    transition_state,
)


OWNER = "a" * 32
OTHER_OWNER = "b" * 32


class InjectedCrash(RuntimeError):
    pass


def raw_sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class TransactionKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_store(self, name: str = "store") -> SyntheticTransactionStoreV0:
        root = self.base / name
        root.mkdir()
        return SyntheticTransactionStoreV0.create(root)

    def make_publication(
        self,
        store: SyntheticTransactionStoreV0,
        *,
        operation_id: str = "op-1",
        target_path: str = "nested/result.bin",
        payload: bytes = b"new bytes",
        preimage: bytes | None = None,
        namespace: NamespaceV0 | None = None,
    ):
        namespace = namespace or NamespaceV0("workspace", "project", "release")
        lease = acquire_write_lease(
            store,
            namespace,
            operation_id,
            owner_token_factory=lambda: OWNER,
            clock=lambda: "2026-08-09T00:00:00.000Z",
        )
        if preimage is not None:
            target = store.target_root(namespace, create=True) / Path(*target_path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(preimage)
        staging = store.create_staging(operation_id)
        staged = staging / Path(*target_path.split("/"))
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(payload)
        spec = PublicationSpecV0(
            namespace,
            operation_id,
            target_path,
            ArtifactHashV0(target_path, "raw", raw_sha(payload)),
            raw_sha(preimage) if preimage is not None else None,
        )
        return namespace, lease, staging, spec

    def test_state_machine_is_small_and_fail_closed(self) -> None:
        self.assertNotIn("STAGED", TransactionStateV0.__members__)
        self.assertEqual(
            transition_state(TransactionStateV0.PREPARED, TransactionStateV0.APPLYING),
            TransactionStateV0.APPLYING,
        )
        self.assertEqual(
            transition_state(TransactionStateV0.APPLIED, TransactionStateV0.VERIFIED),
            TransactionStateV0.VERIFIED,
        )
        with self.assertRaises(TransactionViolation):
            transition_state(TransactionStateV0.PREPARED, TransactionStateV0.VERIFIED)
        with self.assertRaises(TransactionViolation):
            transition_state(TransactionStateV0.VERIFIED, TransactionStateV0.APPLYING)

    def test_store_requires_explicit_empty_marker_bound_root(self) -> None:
        unmarked = self.base / "unmarked"
        unmarked.mkdir()
        with self.assertRaises(TransactionViolation) as caught:
            SyntheticTransactionStoreV0(unmarked)
        self.assertEqual(caught.exception.code, TransactionErrorCode.SYNTHETIC_STORE_REQUIRED)

        nonempty = self.base / "nonempty"
        nonempty.mkdir()
        (nonempty / "data.bin").write_bytes(b"x")
        with self.assertRaises(ContractViolation):
            SyntheticTransactionStoreV0.create(nonempty)

        store = self.make_store()
        self.assertTrue((store.root / ".locpipe-synthetic-v0.json").is_file())

    def test_namespace_is_exact_bounded_and_path_safe(self) -> None:
        values = [
            NamespaceV0("work", "project", "release"),
            NamespaceV0("Work", "project", "release"),
            NamespaceV0("wörk", "project", "release"),
            NamespaceV0("work", "project/child", "release"),
        ]
        self.assertEqual(len({value.token for value in values}), len(values))
        self.assertTrue(all(len(value.token) == 70 for value in values))
        with self.assertRaises(ContractViolation):
            NamespaceV0("x" * 129, "project", "release")

    def test_lease_is_exclusive_fenced_and_never_auto_stolen(self) -> None:
        store = self.make_store()
        namespace = NamespaceV0("w", "p", "r")
        lease = acquire_write_lease(store, namespace, "op", owner_token_factory=lambda: OWNER)
        with self.assertRaises(TransactionViolation) as caught:
            acquire_write_lease(store, namespace, "other", owner_token_factory=lambda: OTHER_OWNER)
        self.assertEqual(caught.exception.code, TransactionErrorCode.WRITER_LOCKED)

        lock, epoch = (
            store.locks / f"{namespace.token}.json",
            store.epochs / f"{namespace.token}.txt",
        )
        self.assertTrue(lock.is_file())
        epoch.write_text("2\n", encoding="ascii")
        with self.assertRaises(TransactionViolation) as stale:
            release_write_lease(store, lease)
        self.assertEqual(stale.exception.code, TransactionErrorCode.FENCE_STALE)

    def test_two_processes_cannot_hold_same_namespace(self) -> None:
        store = self.make_store()
        ready = self.base / "ready"
        release = self.base / "release"
        worker = ROOT / "tests" / "phase2_transaction_worker.py"
        process = subprocess.Popen(
            [sys.executable, str(worker), "hold", str(store.root), str(ready), str(release)],
            cwd=ROOT,
        )
        try:
            deadline = time.monotonic() + 10
            while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists(), "worker did not acquire lease")
            with self.assertRaises(TransactionViolation) as locked:
                acquire_write_lease(
                    store,
                    NamespaceV0("workspace", "project", "release"),
                    "op-other",
                    owner_token_factory=lambda: OTHER_OWNER,
                )
            self.assertEqual(locked.exception.code, TransactionErrorCode.WRITER_LOCKED)
        finally:
            release.write_text("release", encoding="ascii")
            process.wait(timeout=10)
        self.assertEqual(process.returncode, 0)

    def test_publish_absent_target_and_idempotent_verified_receipt(self) -> None:
        store = self.make_store()
        _, lease, staging, spec = self.make_publication(store)
        receipt = publish_verified_file(store, spec, lease, staging)
        self.assertEqual(receipt.target.sha256, spec.staged_artifact.sha256)
        self.assertEqual((store.target_root(spec.namespace) / "nested" / "result.bin").read_bytes(), b"new bytes")
        plan = inspect_recovery(store, spec.operation_id)
        self.assertEqual(plan.disposition, RecoveryDispositionV0.NO_ACTION)
        self.assertEqual(plan.journal_state, TransactionStateV0.VERIFIED)
        self.assertEqual(publish_verified_file(store, spec, lease, staging), receipt)

        changed = b"different bytes"
        (staging / "nested" / "result.bin").write_bytes(changed)
        different_spec = PublicationSpecV0(
            spec.namespace,
            spec.operation_id,
            spec.target_path,
            ArtifactHashV0(spec.target_path, "raw", raw_sha(changed)),
            spec.expected_preimage_sha256,
        )
        with self.assertRaises(TransactionViolation) as drift:
            publish_verified_file(store, different_spec, lease, staging)
        self.assertEqual(drift.exception.code, TransactionErrorCode.TRANSACTION_DRIFT)

    def test_publish_replaces_exact_preimage(self) -> None:
        store = self.make_store()
        _, lease, staging, spec = self.make_publication(store, preimage=b"old bytes")
        publish_verified_file(store, spec, lease, staging)
        self.assertEqual((store.target_root(spec.namespace) / "nested" / "result.bin").read_bytes(), b"new bytes")
        self.assertEqual(
            (store.transaction_dir(spec.operation_id) / "preimage.bin").read_bytes(),
            b"old bytes",
        )

    def test_namespaces_physically_isolate_the_same_relative_target(self) -> None:
        store = self.make_store()
        first_namespace = NamespaceV0("workspace", "project", "release-a")
        second_namespace = NamespaceV0("workspace", "project", "release-b")
        _, first_lease, first_staging, first_spec = self.make_publication(
            store,
            operation_id="op-a",
            target_path="result.bin",
            payload=b"first",
            namespace=first_namespace,
        )
        _, second_lease, second_staging, second_spec = self.make_publication(
            store,
            operation_id="op-b",
            target_path="result.bin",
            payload=b"second",
            namespace=second_namespace,
        )
        publish_verified_file(store, first_spec, first_lease, first_staging)
        publish_verified_file(store, second_spec, second_lease, second_staging)
        self.assertEqual((store.target_root(first_namespace) / "result.bin").read_bytes(), b"first")
        self.assertEqual((store.target_root(second_namespace) / "result.bin").read_bytes(), b"second")
        self.assertEqual(inspect_recovery(store, "op-a").disposition, RecoveryDispositionV0.NO_ACTION)
        self.assertEqual(inspect_recovery(store, "op-b").disposition, RecoveryDispositionV0.NO_ACTION)

    def test_staged_hash_preimage_and_staging_containment_fail_closed(self) -> None:
        store = self.make_store()
        _, lease, staging, spec = self.make_publication(store)
        (staging / "nested" / "result.bin").write_bytes(b"tampered")
        with self.assertRaises(ContractViolation) as mismatch:
            publish_verified_file(store, spec, lease, staging)
        self.assertEqual(mismatch.exception.record.code, ErrorCode.HASH_MISMATCH)

        outside = self.base / "outside"
        outside.mkdir()
        (outside / "nested").mkdir()
        (outside / "nested" / "result.bin").write_bytes(b"new bytes")
        with self.assertRaises(TransactionViolation) as escaped:
            publish_verified_file(store, spec, lease, outside)
        self.assertEqual(escaped.exception.code, TransactionErrorCode.SYNTHETIC_STORE_REQUIRED)

        (staging / "nested" / "result.bin").write_bytes(b"new bytes")
        bad_spec = PublicationSpecV0(
            spec.namespace,
            spec.operation_id,
            spec.target_path,
            spec.staged_artifact,
            raw_sha(b"unexpected old bytes"),
        )
        with self.assertRaises(TransactionViolation) as preimage:
            publish_verified_file(store, bad_spec, lease, staging)
        self.assertEqual(preimage.exception.code, TransactionErrorCode.TRANSACTION_DRIFT)

    def test_staging_rejects_a_second_file(self) -> None:
        store = self.make_store()
        _, lease, staging, spec = self.make_publication(store)
        (staging / "extra.bin").write_bytes(b"not part of transaction")
        with self.assertRaises(ContractViolation) as extra:
            publish_verified_file(store, spec, lease, staging)
        self.assertEqual(extra.exception.record.code, ErrorCode.OUTPUT_CONTRACT_VIOLATION)

    def test_safe_retry_boundaries_resume_same_transaction(self) -> None:
        for index, boundary in enumerate(("AFTER_PREPARED", "AFTER_APPLYING", "AFTER_STAGED_FSYNC")):
            with self.subTest(boundary=boundary):
                store = self.make_store(f"safe-{index}")
                _, lease, staging, spec = self.make_publication(store)

                def fail(point: str) -> None:
                    if point == boundary:
                        raise InjectedCrash(point)

                with self.assertRaises(InjectedCrash):
                    publish_verified_file(store, spec, lease, staging, _failure_hook=fail)
                plan = inspect_recovery(store, spec.operation_id)
                self.assertEqual(plan.disposition, RecoveryDispositionV0.SAFE_RETRY)
                self.assertTrue((store.transaction_dir(spec.operation_id) / "journal.json").is_file())
                publish_verified_file(store, spec, lease, staging)
                self.assertEqual(inspect_recovery(store, spec.operation_id).journal_state, TransactionStateV0.VERIFIED)

    def test_postimage_failure_boundaries_require_exact_rollback(self) -> None:
        boundaries = (
            "AFTER_REPLACE_BEFORE_APPLIED",
            "AFTER_APPLIED",
            "AFTER_RECEIPT_BEFORE_VERIFIED",
        )
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary):
                store = self.make_store(f"rollback-{index}")
                _, lease, staging, spec = self.make_publication(store, preimage=b"old bytes")

                def fail(point: str) -> None:
                    if point == boundary:
                        raise InjectedCrash(point)

                with self.assertRaises(InjectedCrash):
                    publish_verified_file(store, spec, lease, staging, _failure_hook=fail)
                plan = inspect_recovery(store, spec.operation_id)
                self.assertEqual(plan.disposition, RecoveryDispositionV0.ROLLBACK_REQUIRED)
                rollback_publication(store, plan, lease)
                self.assertEqual((store.target_root(spec.namespace) / "nested" / "result.bin").read_bytes(), b"old bytes")
                terminal = inspect_recovery(store, spec.operation_id)
                self.assertEqual(terminal.journal_state, TransactionStateV0.ROLLED_BACK)
                self.assertEqual(terminal.disposition, RecoveryDispositionV0.NO_ACTION)
                if boundary == "AFTER_RECEIPT_BEFORE_VERIFIED":
                    self.assertTrue((store.transaction_dir(spec.operation_id) / "receipt.superseded.json").is_file())

    def test_process_termination_leaves_inspectable_recoverable_evidence(self) -> None:
        store = self.make_store()
        worker = ROOT / "tests" / "phase2_transaction_worker.py"
        completed = subprocess.run(
            [sys.executable, str(worker), "crash", str(store.root), "AFTER_REPLACE_BEFORE_APPLIED"],
            cwd=ROOT,
            check=False,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 71)
        plan = inspect_recovery(store, "op-crash")
        self.assertEqual(plan.disposition, RecoveryDispositionV0.ROLLBACK_REQUIRED)
        namespace = NamespaceV0("workspace", "project", "release")
        lease = WriteLeaseV0(namespace, namespace.token, OWNER, "op-crash", 1)
        rollback_publication(store, plan, lease)
        self.assertFalse((store.target_root(namespace) / "result.bin").exists())

    def test_rollback_is_resumable_after_each_internal_boundary(self) -> None:
        for index, boundary in enumerate(
            ("AFTER_ROLLBACK_TARGET", "AFTER_ROLLBACK_SUPERSESSION", "AFTER_ROLLBACK_EVIDENCE")
        ):
            with self.subTest(boundary=boundary):
                store = self.make_store(f"rollback-resume-{index}")
                _, lease, staging, spec = self.make_publication(store, preimage=b"old bytes")

                def fail_publish(point: str) -> None:
                    if point == "AFTER_RECEIPT_BEFORE_VERIFIED":
                        raise InjectedCrash(point)

                with self.assertRaises(InjectedCrash):
                    publish_verified_file(store, spec, lease, staging, _failure_hook=fail_publish)
                plan = inspect_recovery(store, spec.operation_id)

                def fail_rollback(point: str) -> None:
                    if point == boundary:
                        raise InjectedCrash(point)

                with self.assertRaises(InjectedCrash):
                    rollback_publication(store, plan, lease, _failure_hook=fail_rollback)
                resumed = inspect_recovery(store, spec.operation_id)
                self.assertEqual(resumed.disposition, RecoveryDispositionV0.ROLLBACK_REQUIRED)
                rollback_publication(store, resumed, lease)
                self.assertEqual(inspect_recovery(store, spec.operation_id).journal_state, TransactionStateV0.ROLLED_BACK)

    def test_incomplete_transaction_prevents_lease_release(self) -> None:
        store = self.make_store()
        _, lease, staging, spec = self.make_publication(store)

        def fail(point: str) -> None:
            if point == "AFTER_APPLIED":
                raise InjectedCrash(point)

        with self.assertRaises(InjectedCrash):
            publish_verified_file(store, spec, lease, staging, _failure_hook=fail)
        with self.assertRaises(TransactionViolation) as incomplete:
            release_write_lease(store, lease)
        self.assertEqual(incomplete.exception.code, TransactionErrorCode.RECOVERY_REQUIRED)
        plan = inspect_recovery(store, spec.operation_id)
        rollback_publication(store, plan, lease)
        release_write_lease(store, lease)

    def test_rollback_restores_absence(self) -> None:
        store = self.make_store()
        _, lease, staging, spec = self.make_publication(store)

        def fail(point: str) -> None:
            if point == "AFTER_APPLIED":
                raise InjectedCrash(point)

        with self.assertRaises(InjectedCrash):
            publish_verified_file(store, spec, lease, staging, _failure_hook=fail)
        plan = inspect_recovery(store, spec.operation_id)
        rollback_publication(store, plan, lease)
        self.assertFalse((store.target_root(spec.namespace) / "nested" / "result.bin").exists())

    def test_recovery_recomputes_evidence_and_rejects_journal_drift(self) -> None:
        store = self.make_store()
        _, lease, staging, spec = self.make_publication(store)

        def fail(point: str) -> None:
            if point == "AFTER_APPLIED":
                raise InjectedCrash(point)

        with self.assertRaises(InjectedCrash):
            publish_verified_file(store, spec, lease, staging, _failure_hook=fail)
        real = inspect_recovery(store, spec.operation_id)
        fabricated = RecoveryPlanV0(
            real.operation_id,
            real.disposition,
            real.journal_state,
            real.target_sha256,
            "fabricated detail",
        )
        with self.assertRaises(TransactionViolation) as changed:
            rollback_publication(store, fabricated, lease)
        self.assertEqual(changed.exception.code, TransactionErrorCode.TRANSACTION_DRIFT)

        journal_path = store.transaction_dir(spec.operation_id) / "journal.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        journal["unexpected"] = True
        journal_path.write_text(json.dumps(journal), encoding="utf-8")
        self.assertEqual(inspect_recovery(store, spec.operation_id).disposition, RecoveryDispositionV0.UNKNOWN)

    def test_verified_receipt_or_target_drift_becomes_unknown(self) -> None:
        store = self.make_store()
        _, lease, staging, spec = self.make_publication(store)
        publish_verified_file(store, spec, lease, staging)
        receipt = store.transaction_dir(spec.operation_id) / "receipt.json"
        receipt.write_bytes(receipt.read_bytes() + b" ")
        self.assertEqual(inspect_recovery(store, spec.operation_id).disposition, RecoveryDispositionV0.UNKNOWN)

    def test_verified_journal_identity_drift_cannot_return_pass(self) -> None:
        store = self.make_store()
        _, lease, staging, spec = self.make_publication(store)
        publish_verified_file(store, spec, lease, staging)
        journal_path = store.transaction_dir(spec.operation_id) / "journal.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        journal["owner_token"] = OTHER_OWNER
        journal_path.write_text(json.dumps(journal), encoding="utf-8")
        self.assertEqual(inspect_recovery(store, spec.operation_id).disposition, RecoveryDispositionV0.UNKNOWN)
        with self.assertRaises(TransactionViolation):
            publish_verified_file(store, spec, lease, staging)

    def test_target_drift_at_replace_and_verify_boundaries_fails_closed(self) -> None:
        for index, boundary in enumerate(("AFTER_STAGED_FSYNC", "AFTER_RECEIPT_BEFORE_VERIFIED")):
            with self.subTest(boundary=boundary):
                store = self.make_store(f"target-drift-{index}")
                _, lease, staging, spec = self.make_publication(store)
                target = store.target_root(spec.namespace, create=True) / "nested" / "result.bin"
                target.parent.mkdir(parents=True, exist_ok=True)

                def drift(point: str) -> None:
                    if point == boundary:
                        target.write_bytes(b"out-of-band drift")

                with self.assertRaises(TransactionViolation):
                    publish_verified_file(store, spec, lease, staging, _failure_hook=drift)
                self.assertNotEqual(inspect_recovery(store, spec.operation_id).journal_state, TransactionStateV0.VERIFIED)

    def test_path_escape_is_rejected_before_io(self) -> None:
        namespace = NamespaceV0("w", "p", "r")
        with self.assertRaises(ContractViolation) as escaped:
            PublicationSpecV0(
                namespace,
                "op",
                "../outside.bin",
                ArtifactHashV0("safe.bin", "raw", raw_sha(b"x")),
                None,
            )
        self.assertEqual(escaped.exception.record.code, ErrorCode.PATH_ESCAPE)


if __name__ == "__main__":
    unittest.main()
