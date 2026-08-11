from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.contracts.v0 import ContractViolation, canonical_json_bytes, parse_canonical_json, raw_sha256  # noqa: E402
from locpipe.editorial.v0 import (  # noqa: E402
    EditorialSubmissionReceiptV0,
    editorial_job_root_v0,
    editorial_submission_archive_artifacts_v0,
    prepared_editorial_artifacts_v0,
    publish_editorial_bypass_v0,
    publish_editorial_group_v0,
    received_editorial_artifacts_v0,
)
from locpipe.kernel.v0.context import acquire_context_write_lease, initialize_project_context  # noqa: E402
from locpipe.kernel.v0.context_transactions import (  # noqa: E402
    inspect_context_group_recovery,
    release_context_write_lease,
    rollback_context_group,
)
from locpipe.kernel.v0.transactions import RecoveryDispositionV0, SyntheticTransactionStoreV0, TransactionViolation  # noqa: E402
from locpipe.translation.v0 import TranslationTargetSetV0  # noqa: E402
from tests.test_editorial_acceptance_v0 import (  # noqa: E402
    editorial_fixture,
    editorial_output,
    run_editorial_acceptance,
)
from tests.test_editorial_packet_v0 import accepted_fixture, editorial_layers  # noqa: E402


CLOCK = lambda: "2026-08-10T00:00:00Z"


class EditorialPublicationV0Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name) / "store"
        root.mkdir()
        self.store = SyntheticTransactionStoreV0.create(root)
        fixture = editorial_fixture()
        (
            self.context, self.resolved, self.translation_job, self.translation_packet,
            self.translation_decision, self.target_set, self.policy, self.job, self.packet,
            self.parent, self.raw_output, self.submission_receipt, self.translation_state,
        ) = fixture
        self.paths = initialize_project_context(self.store, self.context)

    def publish(self, operation, artifacts, expected, *, result=None, hook=None, release=True):
        owner = (operation.encode().hex() + "0" * 32)[:32]
        lease = acquire_context_write_lease(self.store, self.context, operation, owner_token_factory=lambda: owner)
        try:
            receipt = publish_editorial_group_v0(
                self.store, self.context, self.job, operation, artifacts, lease,
                expected_preimages=expected, clock=CLOCK, acceptance_result=result, _failure_hook=hook,
            )
        except Exception:
            if not (self.paths.transactions_root / operation).exists():
                release_context_write_lease(self.store, self.context, lease)
            raise
        if release:
            release_context_write_lease(self.store, self.context, lease)
        return receipt, lease

    def prepare_archive_received(self):
        prepared = prepared_editorial_artifacts_v0(self.job, self.packet, self.policy, self.parent)
        self.publish("editorial-prepare", prepared, {path: None for path, _ in prepared})
        archive = editorial_submission_archive_artifacts_v0(self.job, self.raw_output, self.submission_receipt)
        self.publish("editorial-archive", archive, {path: None for path, _ in archive})
        received = received_editorial_artifacts_v0(self.job, self.submission_receipt)
        prepared_state = dict(prepared)[f"{editorial_job_root_v0(self.job)}/state.json"]
        expected = {path: raw_sha256(prepared_state) if path.endswith("state.json") else None for path, _ in received}
        self.publish("editorial-received", received, expected)
        return prepared, received

    def test_full_lifecycle_is_context_local_and_terminal_cas_has_one_winner(self) -> None:
        _prepared, received = self.prepare_archive_received()
        result, outputs, _fixture = run_editorial_acceptance()
        terminal = tuple(sorted(outputs.items()))
        received_state = dict(received)[f"{editorial_job_root_v0(self.job)}/state.json"]
        expected = {path: raw_sha256(received_state) if path.endswith("state.json") else None for path, _ in terminal}
        first, _lease = self.publish("editorial-terminal", terminal, expected, result=result)
        self.assertEqual(5, len(first.targets))
        for relative, payload in terminal:
            self.assertEqual(payload, (self.paths.outputs_root / Path(*relative.split("/"))).read_bytes())
        self.assertFalse(any(self.store.targets.rglob("*")))
        with self.assertRaises(TransactionViolation):
            self.publish("editorial-terminal-loser", terminal, expected, result=result)

    def test_terminal_crash_rolls_back_exact_received_preimage(self) -> None:
        _prepared, received = self.prepare_archive_received()
        result, outputs, _fixture = run_editorial_acceptance()
        terminal = tuple(sorted(outputs.items()))
        root = editorial_job_root_v0(self.job)
        received_state = dict(received)[f"{root}/state.json"]
        expected = {path: raw_sha256(received_state) if path.endswith("state.json") else None for path, _ in terminal}
        operation = "editorial-terminal-crash"
        lease = acquire_context_write_lease(self.store, self.context, operation, owner_token_factory=lambda: "f" * 32)

        def fail(point: str) -> None:
            if point == "AFTER_GROUP_ARTIFACT_REPLACED:0002":
                raise RuntimeError("injected")

        with self.assertRaisesRegex(RuntimeError, "injected"):
            publish_editorial_group_v0(
                self.store, self.context, self.job, operation, terminal, lease,
                expected_preimages=expected, clock=CLOCK, acceptance_result=result, _failure_hook=fail,
            )
        plan = inspect_context_group_recovery(self.store, self.context, operation)
        self.assertEqual(RecoveryDispositionV0.ROLLBACK_REQUIRED, plan.disposition)
        rollback_context_group(self.store, self.context, plan, lease, clock=CLOCK)
        release_context_write_lease(self.store, self.context, lease)
        self.assertEqual(received_state, (self.paths.outputs_root / root / "state.json").read_bytes())
        self.assertFalse((self.paths.outputs_root / root / "candidate_set.json").exists())

    def test_unknown_shapes_and_renamed_submission_fail_before_staging(self) -> None:
        result, outputs, _fixture = run_editorial_acceptance()
        terminal = tuple(sorted(outputs.items()))
        with self.assertRaisesRegex(ContractViolation, "requires handler PASS"):
            self.publish("forged-terminal", terminal, {path: None for path, _ in terminal})
        self.assertFalse((self.paths.staging_root / "forged-terminal").exists())

        archive = editorial_submission_archive_artifacts_v0(self.job, self.raw_output, self.submission_receipt)
        renamed = tuple((path.replace("output.json", "nested/output.json"), payload) for path, payload in archive)
        with self.assertRaisesRegex(ContractViolation, "binding drift"):
            self.publish("renamed-archive", renamed, {path: None for path, _ in renamed})
        self.assertFalse((self.paths.staging_root / "renamed-archive").exists())

    def test_identical_prepare_retry_is_idempotent(self) -> None:
        prepared = prepared_editorial_artifacts_v0(self.job, self.packet, self.policy, self.parent)
        expected = {path: None for path, _ in prepared}
        operation = "editorial-idempotent"
        lease = acquire_context_write_lease(self.store, self.context, operation, owner_token_factory=lambda: "c" * 32)
        first = publish_editorial_group_v0(
            self.store, self.context, self.job, operation, prepared, lease,
            expected_preimages=expected, clock=CLOCK,
        )
        second = publish_editorial_group_v0(
            self.store, self.context, self.job, operation, prepared, lease,
            expected_preimages=expected, clock=CLOCK,
        )
        self.assertEqual(first, second)
        release_context_write_lease(self.store, self.context, lease)

    def test_unconfigured_editorial_bypass_is_published_but_configured_is_blocked(self) -> None:
        bypass = accepted_fixture(selected_layers=editorial_layers(configured=False))
        context, resolved, translation_job, translation_packet, decision, target_set, translation_state = bypass
        bypass_root = Path(self.temporary.name) / "bypass-store"
        bypass_root.mkdir()
        bypass_store = SyntheticTransactionStoreV0.create(bypass_root)
        paths = initialize_project_context(bypass_store, context)
        operation = "editorial-bypass"
        lease = acquire_context_write_lease(bypass_store, context, operation, owner_token_factory=lambda: "b" * 32)
        receipt = publish_editorial_bypass_v0(
            bypass_store, context, resolved, translation_job, translation_packet, decision, target_set,
            translation_state, operation, lease, clock=CLOCK,
        )
        release_context_write_lease(bypass_store, context, lease)
        self.assertEqual(2, len(receipt.targets))
        self.assertTrue(any(paths.outputs_root.glob("ed/b/*/candidate_set.json")))

        operation = "editorial-bypass-configured"
        lease = acquire_context_write_lease(self.store, self.context, operation, owner_token_factory=lambda: "a" * 32)
        with self.assertRaisesRegex(ContractViolation, "cannot be bypassed"):
            publish_editorial_bypass_v0(
                self.store, self.context, self.resolved, self.translation_job, self.translation_packet,
                self.translation_decision, self.target_set, self.translation_state,
                operation, lease, clock=CLOCK,
            )
        release_context_write_lease(self.store, self.context, lease)

    def test_bypass_rejects_incomplete_targets_before_publication(self) -> None:
        context, resolved, translation_job, translation_packet, decision, target_set, state = accepted_fixture(
            selected_layers=editorial_layers(configured=False),
        )
        incomplete = TranslationTargetSetV0(
            target_set.job_id, target_set.invocation_id, target_set.target_locale, target_set._target_bytes[:-1],
        )
        bypass_root = Path(self.temporary.name) / "incomplete-bypass-store"
        bypass_root.mkdir()
        store = SyntheticTransactionStoreV0.create(bypass_root)
        paths = initialize_project_context(store, context)
        operation = "editorial-bypass-incomplete"
        lease = acquire_context_write_lease(store, context, operation, owner_token_factory=lambda: "d" * 32)
        with self.assertRaisesRegex(ContractViolation, "target count drift|terminal state"):
            publish_editorial_bypass_v0(
                store, context, resolved, translation_job, translation_packet, decision, incomplete,
                state, operation, lease, clock=CLOCK,
            )
        release_context_write_lease(store, context, lease)
        self.assertFalse(any(paths.outputs_root.rglob("*")))
        self.assertFalse((paths.staging_root / operation).exists())


if __name__ == "__main__":
    unittest.main()
