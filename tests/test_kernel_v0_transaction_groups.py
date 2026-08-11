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

from locpipe.contracts.v0 import ArtifactHashV0, ContractViolation  # noqa: E402
from locpipe.kernel.v0.transactions import (  # noqa: E402
    GroupRecoveryPlanV0,
    NamespaceV0,
    PublicationEntryV0,
    PublicationGroupSpecV0,
    RecoveryDispositionV0,
    SyntheticTransactionStoreV0,
    TransactionErrorCode,
    TransactionStateV0,
    TransactionViolation,
    WriteLeaseV0,
    acquire_write_lease,
    inspect_group_recovery,
    publish_verified_group,
    release_write_lease,
    rollback_publication_group,
)


OWNER = "e" * 32
OTHER_OWNER = "f" * 32
NAMESPACE = NamespaceV0("workspace", "project", "group-release")
PATHS = ("delta.csv", "manifest.json", "tables/a.csv", "tables/b.csv", "tables/c.bin")
PREIMAGES = {
    "delta.csv": b"old-delta\r\n",
    "tables/a.csv": b"old-a\n",
    "tables/c.bin": b"old-c\x00",
}
POSTIMAGES = {
    "delta.csv": b"new-delta\n",
    "manifest.json": b'{"state":"new"}\n',
    "tables/a.csv": b"new-a\n",
    "tables/b.csv": b"new-b\n",
    "tables/c.bin": b"new-c\x00",
}


def raw_sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class InjectedCrash(RuntimeError):
    pass


class TransactionGroupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_store(self, name: str = "store") -> SyntheticTransactionStoreV0:
        root = self.base / name
        root.mkdir()
        return SyntheticTransactionStoreV0.create(root)

    def make_group(
        self,
        store: SyntheticTransactionStoreV0,
        *,
        operation_id: str = "group-op",
        namespace: NamespaceV0 = NAMESPACE,
    ) -> tuple[WriteLeaseV0, Path, PublicationGroupSpecV0]:
        target_root = store.target_root(namespace, create=True)
        for relative, payload in PREIMAGES.items():
            target = target_root / Path(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        lease = acquire_write_lease(store, namespace, operation_id, owner_token_factory=lambda: OWNER)
        staging = store.create_staging(operation_id)
        entries = []
        for relative in PATHS:
            staged = staging / Path(*relative.split("/"))
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(POSTIMAGES[relative])
            entries.append(PublicationEntryV0(
                ArtifactHashV0(relative, "raw", raw_sha(POSTIMAGES[relative])),
                raw_sha(PREIMAGES[relative]) if relative in PREIMAGES else None,
            ))
        return lease, staging, PublicationGroupSpecV0(namespace, operation_id, tuple(entries))

    def assert_preimages(self, store: SyntheticTransactionStoreV0, namespace: NamespaceV0 = NAMESPACE) -> None:
        root = store.target_root(namespace)
        for relative in PATHS:
            target = root / Path(*relative.split("/"))
            if relative in PREIMAGES:
                self.assertEqual(PREIMAGES[relative], target.read_bytes())
            else:
                self.assertFalse(target.exists())

    def assert_postimages(self, store: SyntheticTransactionStoreV0, namespace: NamespaceV0 = NAMESPACE) -> None:
        root = store.target_root(namespace)
        for relative in PATHS:
            self.assertEqual(POSTIMAGES[relative], (root / Path(*relative.split("/"))).read_bytes())

    def existing_process_spec(self) -> PublicationGroupSpecV0:
        entries = tuple(
            PublicationEntryV0(
                ArtifactHashV0(relative, "raw", raw_sha(POSTIMAGES[relative])),
                raw_sha(PREIMAGES[relative]) if relative in PREIMAGES else None,
            )
            for relative in PATHS
        )
        return PublicationGroupSpecV0(NAMESPACE, "op-group-crash", entries)

    def test_group_publish_verified_reload_and_release(self) -> None:
        store = self.make_store()
        lease, staging, spec = self.make_group(store)
        receipt = publish_verified_group(store, spec, lease, staging)
        self.assertEqual(PATHS, tuple(target.path for target in receipt.targets))
        self.assert_postimages(store)
        plan = inspect_group_recovery(store, spec.operation_id)
        self.assertEqual(RecoveryDispositionV0.NO_ACTION, plan.disposition)
        self.assertEqual(TransactionStateV0.VERIFIED, plan.journal_state)
        self.assertEqual(receipt, publish_verified_group(store, spec, lease, staging))
        release_write_lease(store, lease)

    def test_group_contract_rejects_unbounded_unsorted_duplicate_overlap_and_noop(self) -> None:
        entry_a = PublicationEntryV0(ArtifactHashV0("a", "raw", "1" * 64), None)
        entry_b = PublicationEntryV0(ArtifactHashV0("b", "raw", "2" * 64), None)
        with self.assertRaises(ContractViolation):
            PublicationGroupSpecV0(NAMESPACE, "op", (entry_a,))
        with self.assertRaises(ContractViolation):
            PublicationGroupSpecV0(NAMESPACE, "op", (entry_b, entry_a))
        with self.assertRaises(ContractViolation):
            PublicationGroupSpecV0(NAMESPACE, "op", (entry_a, entry_a))
        overlap = PublicationEntryV0(ArtifactHashV0("a/b", "raw", "3" * 64), None)
        with self.assertRaises(ContractViolation):
            PublicationGroupSpecV0(NAMESPACE, "op", (entry_a, overlap))
        with self.assertRaises(ContractViolation):
            PublicationEntryV0(ArtifactHashV0("same", "raw", "4" * 64), "4" * 64)
        oversized = tuple(
            PublicationEntryV0(ArtifactHashV0(f"path-{index:02d}", "raw", f"{index % 10}" * 64), None)
            for index in range(65)
        )
        with self.assertRaises(ContractViolation):
            PublicationGroupSpecV0(NAMESPACE, "op", oversized)

    def test_group_staging_and_preimage_drift_fail_closed(self) -> None:
        store = self.make_store()
        lease, staging, spec = self.make_group(store)
        (staging / "extra.bin").write_bytes(b"extra")
        with self.assertRaises(ContractViolation):
            publish_verified_group(store, spec, lease, staging)

        other = self.make_store("other")
        other_lease, other_staging, other_spec = self.make_group(other)
        target = other.target_root(NAMESPACE) / "delta.csv"
        target.write_bytes(b"drift")
        with self.assertRaises(TransactionViolation) as drift:
            publish_verified_group(other, other_spec, other_lease, other_staging)
        self.assertEqual(TransactionErrorCode.TRANSACTION_DRIFT, drift.exception.code)

    def test_safe_retry_before_first_replace(self) -> None:
        for index, boundary in enumerate((
            "AFTER_GROUP_PREPARED",
            "AFTER_GROUP_APPLYING",
            "AFTER_GROUP_ARTIFACT_STAGED:0001",
        )):
            with self.subTest(boundary=boundary):
                store = self.make_store(f"safe-{index}")
                lease, staging, spec = self.make_group(store)

                def fail(point: str) -> None:
                    if point == boundary:
                        raise InjectedCrash(point)

                with self.assertRaises(InjectedCrash):
                    publish_verified_group(store, spec, lease, staging, _failure_hook=fail)
                self.assertEqual(RecoveryDispositionV0.SAFE_RETRY, inspect_group_recovery(store, spec.operation_id).disposition)
                publish_verified_group(store, spec, lease, staging)
                self.assert_postimages(store)

    def test_every_partial_postimage_requires_exact_group_rollback(self) -> None:
        boundaries = tuple(f"AFTER_GROUP_ARTIFACT_REPLACED:{index:04d}" for index in range(1, 6)) + (
            "AFTER_GROUP_APPLIED",
            "AFTER_GROUP_RECEIPT_WRITE",
            "AFTER_GROUP_RECEIPT_BEFORE_VERIFIED",
        )
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary):
                store = self.make_store(f"partial-{index}")
                lease, staging, spec = self.make_group(store)

                def fail(point: str) -> None:
                    if point == boundary:
                        raise InjectedCrash(point)

                with self.assertRaises(InjectedCrash):
                    publish_verified_group(store, spec, lease, staging, _failure_hook=fail)
                plan = inspect_group_recovery(store, spec.operation_id)
                self.assertEqual(RecoveryDispositionV0.ROLLBACK_REQUIRED, plan.disposition)
                rollback_publication_group(store, plan, lease)
                self.assert_preimages(store)
                terminal = inspect_group_recovery(store, spec.operation_id)
                self.assertEqual(RecoveryDispositionV0.NO_ACTION, terminal.disposition)
                self.assertEqual(TransactionStateV0.ROLLED_BACK, terminal.journal_state)

    def test_group_rollback_resumes_after_each_artifact(self) -> None:
        for boundary_index in range(1, 6):
            with self.subTest(boundary_index=boundary_index):
                store = self.make_store(f"rollback-{boundary_index}")
                lease, staging, spec = self.make_group(store)

                def fail_publish(point: str) -> None:
                    if point == "AFTER_GROUP_RECEIPT_BEFORE_VERIFIED":
                        raise InjectedCrash(point)

                with self.assertRaises(InjectedCrash):
                    publish_verified_group(store, spec, lease, staging, _failure_hook=fail_publish)
                plan = inspect_group_recovery(store, spec.operation_id)

                def fail_rollback(point: str) -> None:
                    if point == f"AFTER_GROUP_ROLLBACK_ARTIFACT:{boundary_index:04d}":
                        raise InjectedCrash(point)

                with self.assertRaises(InjectedCrash):
                    rollback_publication_group(store, plan, lease, _failure_hook=fail_rollback)
                resumed = inspect_group_recovery(store, spec.operation_id)
                self.assertEqual(RecoveryDispositionV0.ROLLBACK_REQUIRED, resumed.disposition)
                rollback_publication_group(store, resumed, lease)
                self.assert_preimages(store)

    def test_group_drift_and_fabricated_plan_never_pass(self) -> None:
        store = self.make_store()
        lease, staging, spec = self.make_group(store)

        def fail(point: str) -> None:
            if point == "AFTER_GROUP_APPLIED":
                raise InjectedCrash(point)

        with self.assertRaises(InjectedCrash):
            publish_verified_group(store, spec, lease, staging, _failure_hook=fail)
        plan = inspect_group_recovery(store, spec.operation_id)
        fabricated = GroupRecoveryPlanV0(
            plan.operation_id, plan.disposition, plan.journal_state, plan.target_set_sha256, "fabricated"
        )
        with self.assertRaises(TransactionViolation):
            rollback_publication_group(store, fabricated, lease)
        journal_path = store.transaction_dir(spec.operation_id) / "journal.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        journal["unexpected"] = True
        journal_path.write_text(json.dumps(journal), encoding="utf-8")
        self.assertEqual(RecoveryDispositionV0.UNKNOWN, inspect_group_recovery(store, spec.operation_id).disposition)

    def test_verified_group_receipt_and_target_drift_become_unknown(self) -> None:
        for index, kind in enumerate(("receipt", "target")):
            with self.subTest(kind=kind):
                store = self.make_store(f"verified-drift-{index}")
                lease, staging, spec = self.make_group(store)
                publish_verified_group(store, spec, lease, staging)
                if kind == "receipt":
                    receipt = store.transaction_dir(spec.operation_id) / "receipt.json"
                    receipt.write_bytes(receipt.read_bytes() + b" ")
                else:
                    (store.target_root(NAMESPACE) / "delta.csv").write_bytes(b"out-of-band")
                self.assertEqual(
                    RecoveryDispositionV0.UNKNOWN,
                    inspect_group_recovery(store, spec.operation_id).disposition,
                )

    def test_rolled_back_group_binds_original_and_supersession_receipts(self) -> None:
        store = self.make_store()
        lease, staging, spec = self.make_group(store)

        def fail(point: str) -> None:
            if point == "AFTER_GROUP_RECEIPT_BEFORE_VERIFIED":
                raise InjectedCrash(point)

        with self.assertRaises(InjectedCrash):
            publish_verified_group(store, spec, lease, staging, _failure_hook=fail)
        rollback_publication_group(store, inspect_group_recovery(store, spec.operation_id), lease)
        receipt = store.transaction_dir(spec.operation_id) / "receipt.json"
        receipt.write_bytes(receipt.read_bytes() + b" ")
        self.assertEqual(
            RecoveryDispositionV0.UNKNOWN,
            inspect_group_recovery(store, spec.operation_id).disposition,
        )

    def test_namespaces_isolate_identical_group_paths(self) -> None:
        store = self.make_store()
        first = NamespaceV0("workspace", "project", "group-release-a")
        second = NamespaceV0("workspace", "project", "group-release-b")
        first_lease, first_staging, first_spec = self.make_group(
            store, operation_id="group-a", namespace=first
        )
        second_lease, second_staging, second_spec = self.make_group(
            store, operation_id="group-b", namespace=second
        )
        publish_verified_group(store, first_spec, first_lease, first_staging)
        publish_verified_group(store, second_spec, second_lease, second_staging)
        self.assert_postimages(store, first)
        self.assert_postimages(store, second)
        (store.target_root(first) / "delta.csv").write_bytes(b"first-only")
        self.assertEqual(POSTIMAGES["delta.csv"], (store.target_root(second) / "delta.csv").read_bytes())

    def test_incomplete_group_prevents_release(self) -> None:
        store = self.make_store()
        lease, staging, spec = self.make_group(store)

        def fail(point: str) -> None:
            if point == "AFTER_GROUP_ARTIFACT_REPLACED:0001":
                raise InjectedCrash(point)

        with self.assertRaises(InjectedCrash):
            publish_verified_group(store, spec, lease, staging, _failure_hook=fail)
        with self.assertRaises(TransactionViolation) as caught:
            release_write_lease(store, lease)
        self.assertEqual(TransactionErrorCode.RECOVERY_REQUIRED, caught.exception.code)

    def test_process_termination_before_first_replace_is_safely_retryable(self) -> None:
        worker = ROOT / "tests" / "phase2_transaction_worker.py"
        boundaries = (
            "AFTER_ATOMIC_TEMP_FSYNC:GROUP_PREPARED_JOURNAL",
            "AFTER_GROUP_PREPARED",
            "AFTER_ATOMIC_TEMP_FSYNC:GROUP_APPLYING_JOURNAL",
            "AFTER_GROUP_APPLYING",
            "AFTER_GROUP_ARTIFACT_STAGED:0001",
        )
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary):
                store = self.make_store(f"process-safe-{index}")
                completed = subprocess.run(
                    [sys.executable, str(worker), "group-crash", str(store.root), boundary],
                    cwd=ROOT,
                    check=False,
                    timeout=15,
                )
                self.assertEqual(72, completed.returncode)
                self.assertEqual(
                    RecoveryDispositionV0.SAFE_RETRY,
                    inspect_group_recovery(store, "op-group-crash").disposition,
                )
                lease = WriteLeaseV0(NAMESPACE, NAMESPACE.token, OWNER, "op-group-crash", 1)
                publish_verified_group(
                    store,
                    self.existing_process_spec(),
                    lease,
                    store.staging / "op-group-crash",
                )
                self.assert_postimages(store)

    def test_process_termination_after_any_postimage_is_recoverable(self) -> None:
        worker = ROOT / "tests" / "phase2_transaction_worker.py"
        boundaries = tuple(f"AFTER_GROUP_ARTIFACT_STAGED:{index:04d}" for index in range(2, 6)) + tuple(
            f"AFTER_GROUP_ARTIFACT_REPLACED:{index:04d}" for index in range(1, 6)
        ) + (
            "AFTER_GROUP_APPLIED",
            "AFTER_GROUP_RECEIPT_WRITE",
            "AFTER_GROUP_RECEIPT_BEFORE_VERIFIED",
        )
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary):
                store = self.make_store(f"process-{index}")
                completed = subprocess.run(
                    [sys.executable, str(worker), "group-crash", str(store.root), boundary],
                    cwd=ROOT,
                    check=False,
                    timeout=15,
                )
                self.assertEqual(72, completed.returncode)
                plan = inspect_group_recovery(store, "op-group-crash")
                self.assertEqual(RecoveryDispositionV0.ROLLBACK_REQUIRED, plan.disposition)
                lease = WriteLeaseV0(NAMESPACE, NAMESPACE.token, OWNER, "op-group-crash", 1)
                rollback_publication_group(store, plan, lease)
                self.assert_preimages(store)
                target_root = store.target_root(NAMESPACE)
                self.assertFalse(any(path.name.endswith(".staged") for path in target_root.rglob("*")))

    def test_process_termination_during_each_rollback_boundary_is_resumable(self) -> None:
        worker = ROOT / "tests" / "phase2_transaction_worker.py"
        boundaries = tuple(f"AFTER_GROUP_ROLLBACK_ARTIFACT:{index:04d}" for index in range(1, 6)) + (
            "AFTER_GROUP_ROLLBACK_TARGETS",
            "AFTER_GROUP_ROLLBACK_SUPERSESSION",
            "AFTER_GROUP_ROLLBACK_EVIDENCE",
        )
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary):
                store = self.make_store(f"process-rollback-{index}")
                completed = subprocess.run(
                    [sys.executable, str(worker), "group-rollback-crash", str(store.root), boundary],
                    cwd=ROOT,
                    check=False,
                    timeout=15,
                )
                self.assertEqual(73, completed.returncode)
                plan = inspect_group_recovery(store, "op-group-crash")
                self.assertEqual(RecoveryDispositionV0.ROLLBACK_REQUIRED, plan.disposition)
                lease = WriteLeaseV0(NAMESPACE, NAMESPACE.token, OWNER, "op-group-crash", 1)
                rollback_publication_group(store, plan, lease)
                self.assert_preimages(store)


if __name__ == "__main__":
    unittest.main()
