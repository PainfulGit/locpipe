from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.contracts.v0 import ContractViolation, WorkflowProfile, canonical_json_bytes, raw_sha256  # noqa: E402
from locpipe.kernel.v0.context import (  # noqa: E402
    ProjectContextV0,
    acquire_context_write_lease,
    initialize_project_context,
)
from locpipe.kernel.v0.context_transactions import (  # noqa: E402
    inspect_context_group_recovery,
    release_context_write_lease,
    rollback_context_group,
)
from locpipe.kernel.v0.transactions import (  # noqa: E402
    NamespaceV0,
    RecoveryDispositionV0,
    SyntheticTransactionStoreV0,
    TransactionViolation,
)
from locpipe.translation.v0 import (  # noqa: E402
    ProviderSubmissionReceiptV0,
    prepared_translation_artifacts_v0,
    publish_translation_group_v0,
    received_translation_artifacts_v0,
    submission_archive_artifacts_v0,
    translation_job_root_v0,
)
from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402
from tests.test_translation_acceptance_v0 import provider_output, run_acceptance  # noqa: E402
from tests.test_translation_packet_v0 import build_fixture, layers  # noqa: E402


CLOCK = lambda: "2026-08-10T00:00:00Z"


class TranslationPublicationV0Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        (root / "store").mkdir()
        self.store = SyntheticTransactionStoreV0.create(root / "store")
        self.resolved, _corpus, _scope, self.job, self.packet = build_fixture("flat", SyntheticFlatAdapterV0())
        self.context = ProjectContextV0(
            NamespaceV0("workspace", "fixture", "release"),
            WorkflowProfile.CONTENT_ONLY,
            self.resolved.config_snapshot_sha256,
        )
        self.paths = initialize_project_context(self.store, self.context)

    def publish(self, operation, artifacts, expected, *, failure_hook=None):
        owner = (operation.encode().hex() + "0" * 32)[:32]
        lease = acquire_context_write_lease(
            self.store, self.context, operation, owner_token_factory=lambda: owner
        )
        try:
            receipt = publish_translation_group_v0(
                self.store,
                self.context,
                self.job,
                operation,
                artifacts,
                lease,
                expected_preimages=expected,
                clock=CLOCK,
                _failure_hook=failure_hook,
            )
            release_context_write_lease(self.store, self.context, lease)
            return receipt
        except Exception:
            raise

    def prepare_and_submission(self):
        prepared = prepared_translation_artifacts_v0(self.job, self.packet)
        self.publish("translation-prepare", prepared, {path: None for path, _ in prepared})
        raw = provider_output(self.job, self.packet)
        receipt = ProviderSubmissionReceiptV0(
            self.job.job_id,
            self.job.invocation_id,
            self.job.provider,
            "manual-request-1",
            self.job.packet_sha256,
            self.job.output_contract_sha256,
            raw_sha256(raw),
        )
        archive = submission_archive_artifacts_v0(self.job, raw, receipt)
        self.publish("translation-archive", archive, {path: None for path, _ in archive})
        return prepared, raw, receipt

    def test_prepared_archive_received_terminal_are_cas_published(self) -> None:
        prepared, _raw, receipt = self.prepare_and_submission()
        prepared_state = dict(prepared)[f"{translation_job_root_v0(self.job)}/state.json"]
        received = received_translation_artifacts_v0(self.job, receipt)
        received_expected = {
            path: raw_sha256(prepared_state) if path.endswith("/state.json") else None
            for path, _payload in received
        }
        first = self.publish("translation-received", received, received_expected)
        self.assertEqual(2, len(first.targets))

        acceptance_result, terminal, _job = run_acceptance("flat", SyntheticFlatAdapterV0(), provider_output)
        terminal_rows = tuple(sorted(terminal.items()))
        received_state = dict(received)[f"{translation_job_root_v0(self.job)}/state.json"]
        terminal_expected = {
            path: raw_sha256(received_state) if path.endswith("/state.json") else None
            for path, _payload in terminal_rows
        }
        operation = "translation-terminal"
        lease = acquire_context_write_lease(
            self.store, self.context, operation, owner_token_factory=lambda: "d" * 32
        )
        terminal_receipt = publish_translation_group_v0(
            self.store, self.context, self.job, operation, terminal_rows, lease,
            expected_preimages=terminal_expected, clock=CLOCK, acceptance_result=acceptance_result,
        )
        release_context_write_lease(self.store, self.context, lease)
        self.assertEqual(3, len(terminal_receipt.targets))
        for path, payload in terminal_rows:
            self.assertEqual(payload, (self.paths.outputs_root / Path(*path.split("/"))).read_bytes())
        self.assertFalse(any(self.store.targets.rglob("*")))

        with self.assertRaises(TransactionViolation):
            loser_lease = acquire_context_write_lease(
                self.store, self.context, "translation-terminal-loser", owner_token_factory=lambda: "e" * 32
            )
            publish_translation_group_v0(
                self.store, self.context, self.job, "translation-terminal-loser", terminal_rows, loser_lease,
                expected_preimages=terminal_expected, clock=CLOCK, acceptance_result=acceptance_result,
            )

    def test_failed_received_publication_rolls_back_exact_prepared_state(self) -> None:
        prepared, _raw, receipt = self.prepare_and_submission()
        prepared_state = dict(prepared)[f"{translation_job_root_v0(self.job)}/state.json"]
        received = received_translation_artifacts_v0(self.job, receipt)
        expected = {
            path: raw_sha256(prepared_state) if path.endswith("/state.json") else None
            for path, _payload in received
        }
        operation = "translation-received-crash"
        owner = "f" * 32
        lease = acquire_context_write_lease(self.store, self.context, operation, owner_token_factory=lambda: owner)

        def fail(point: str) -> None:
            if point == "AFTER_GROUP_ARTIFACT_REPLACED:0001":
                raise RuntimeError("injected")

        with self.assertRaisesRegex(RuntimeError, "injected"):
            publish_translation_group_v0(
                self.store, self.context, self.job, operation, received, lease,
                expected_preimages=expected, clock=CLOCK, _failure_hook=fail,
            )
        plan = inspect_context_group_recovery(self.store, self.context, operation)
        self.assertEqual(RecoveryDispositionV0.ROLLBACK_REQUIRED, plan.disposition)
        rollback_context_group(self.store, self.context, plan, lease, clock=CLOCK)
        release_context_write_lease(self.store, self.context, lease)
        state_path = self.paths.outputs_root / translation_job_root_v0(self.job) / "state.json"
        self.assertEqual(prepared_state, state_path.read_bytes())
        self.assertFalse((self.paths.outputs_root / translation_job_root_v0(self.job) / "selection.json").exists())

    def test_foreign_job_cannot_reuse_submission_and_contexts_are_isolated(self) -> None:
        _prepared, raw, receipt = self.prepare_and_submission()
        other_resolved, _corpus, _scope, other_job, other_packet = build_fixture(
            "flat", SyntheticFlatAdapterV0(), selected_layers=layers(release="release-2")
        )
        with self.assertRaises(ContractViolation):
            submission_archive_artifacts_v0(other_job, raw, receipt)
        other_context = ProjectContextV0(
            NamespaceV0("workspace", "fixture", "release-2"),
            WorkflowProfile.CONTENT_ONLY,
            other_resolved.config_snapshot_sha256,
        )
        other_paths = initialize_project_context(self.store, other_context)
        foreign_artifacts = prepared_translation_artifacts_v0(self.job, self.packet)
        foreign_lease = acquire_context_write_lease(
            self.store, other_context, "foreign-prepare", owner_token_factory=lambda: "a" * 32
        )
        with self.assertRaisesRegex(ContractViolation, "different project context"):
            publish_translation_group_v0(
                self.store, other_context, self.job, "foreign-prepare", foreign_artifacts, foreign_lease,
                expected_preimages={path: None for path, _payload in foreign_artifacts}, clock=CLOCK,
            )
        release_context_write_lease(self.store, other_context, foreign_lease)
        self.assertFalse(any(other_paths.outputs_root.rglob("*")))

        other_artifacts = prepared_translation_artifacts_v0(other_job, other_packet)
        other_lease = acquire_context_write_lease(
            self.store, other_context, "other-prepare", owner_token_factory=lambda: "b" * 32
        )
        publish_translation_group_v0(
            self.store, other_context, other_job, "other-prepare", other_artifacts, other_lease,
            expected_preimages={path: None for path, _payload in other_artifacts}, clock=CLOCK,
        )
        release_context_write_lease(self.store, other_context, other_lease)
        self.assertNotEqual(self.paths.outputs_root, other_paths.outputs_root)
        self.assertTrue((other_paths.outputs_root / translation_job_root_v0(other_job) / "job.json").is_file())

    def test_identical_retry_with_same_lease_returns_same_receipt(self) -> None:
        artifacts = prepared_translation_artifacts_v0(self.job, self.packet)
        operation = "translation-idempotent"
        lease = acquire_context_write_lease(
            self.store, self.context, operation, owner_token_factory=lambda: "c" * 32
        )
        expected = {path: None for path, _payload in artifacts}
        first = publish_translation_group_v0(
            self.store, self.context, self.job, operation, artifacts, lease,
            expected_preimages=expected, clock=CLOCK,
        )
        second = publish_translation_group_v0(
            self.store, self.context, self.job, operation, artifacts, lease,
            expected_preimages=expected, clock=CLOCK,
        )
        self.assertEqual(first, second)
        release_context_write_lease(self.store, self.context, lease)

    def test_prepared_cannot_skip_directly_to_forged_terminal(self) -> None:
        prepared = prepared_translation_artifacts_v0(self.job, self.packet)
        self.publish("translation-prepare", prepared, {path: None for path, _payload in prepared})
        root = translation_job_root_v0(self.job)
        forged = tuple(sorted((
            (f"{root}/decision.json", canonical_json_bytes({"forged": True})),
            (f"{root}/state.json", canonical_json_bytes({"forged": "accepted"})),
            (f"{root}/target_set.json", canonical_json_bytes({"targets": []})),
        )))
        state_path = f"{root}/state.json"
        prepared_state = dict(prepared)[state_path]
        operation = "translation-forged-terminal"
        lease = acquire_context_write_lease(
            self.store, self.context, operation, owner_token_factory=lambda: "1" * 32
        )
        with self.assertRaises(ContractViolation):
            publish_translation_group_v0(
                self.store, self.context, self.job, operation, forged, lease,
                expected_preimages={
                    f"{root}/decision.json": None,
                    state_path: raw_sha256(prepared_state),
                    f"{root}/target_set.json": None,
                },
                clock=CLOCK,
            )
        self.assertEqual(prepared_state, (self.paths.outputs_root / root / "state.json").read_bytes())
        self.assertFalse((self.paths.outputs_root / root / "decision.json").exists())

    def test_submission_archive_rejects_renamed_paths_without_writes(self) -> None:
        raw = provider_output(self.job, self.packet)
        receipt = ProviderSubmissionReceiptV0(
            self.job.job_id,
            self.job.invocation_id,
            self.job.provider,
            "manual-request-1",
            self.job.packet_sha256,
            self.job.output_contract_sha256,
            raw_sha256(raw),
        )
        canonical = submission_archive_artifacts_v0(self.job, raw, receipt)
        renamed = tuple(
            (path.replace("output.json", "nested-output.json").replace("receipt.json", "nested-receipt.json"), payload)
            for path, payload in canonical
        )
        operation = "translation-renamed-archive"
        lease = acquire_context_write_lease(
            self.store, self.context, operation, owner_token_factory=lambda: "2" * 32
        )
        with self.assertRaisesRegex(ContractViolation, "archive binding drift"):
            publish_translation_group_v0(
                self.store, self.context, self.job, operation, renamed, lease,
                expected_preimages={path: None for path, _payload in renamed}, clock=CLOCK,
            )
        self.assertFalse(any(self.paths.outputs_root.rglob("nested-*.json")))


if __name__ == "__main__":
    unittest.main()
