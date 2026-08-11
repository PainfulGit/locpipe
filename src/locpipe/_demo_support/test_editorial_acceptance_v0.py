from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.contracts.v0 import (  # noqa: E402
    ArtifactHashV0,
    Capability,
    ContractViolation,
    ModuleDescriptorV0,
    OperationRequestV0,
    canonical_json_bytes,
    execute_bound_operation,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
)
from locpipe.editorial.v0 import (  # noqa: E402
    CorrectionEntryV0,
    CorrectionOverlayV0,
    EditorialCandidateSetV0,
    EditorialJobStatusV0,
    EditorialPolicyV0,
    EditorialStateV0,
    EditorialSubmissionReceiptV0,
    bind_editorial_acceptance_v0,
    build_editorial_job_v0,
    apply_correction_overlay_v0,
    editorial_acceptance_output_declarations_v0,
    editorial_job_root_v0,
    editorial_submission_digest_v0,
    editorial_submission_root_v0,
    editorial_terminal_artifacts_v0,
    parse_editorial_candidate_v0,
)
from locpipe.translation.v0 import ProviderBudgetV0, TranslationTargetSetV0, translation_job_root_v0  # noqa: E402
from locpipe._demo_support.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402
from locpipe._demo_support.test_editorial_packet_v0 import accepted_fixture  # noqa: E402
from locpipe._demo_support.test_translation_acceptance_v0 import binding  # noqa: E402


def editorial_output(job, packet, *, actions=None, malformed=False):
    if malformed:
        return canonical_json_bytes({"contract": "locpipe.editorial.provider-output/v0", "bad": []})
    actions = actions or {}
    decisions = []
    rows = {row.stable_id: row for row in packet.rows}
    for stable_id in packet.requested_ids:
        row = rows[stable_id]
        action = actions.get(stable_id, "KEEP")
        target = None
        if action == "CORRECT":
            target = parse_canonical_json(row._target_bytes)
            data = dict(target["data"])
            data["payload"] = f"edited:{stable_id}"
            data["metadata_ref"] = None
            target = dict(target)
            target["data"] = data
        decisions.append({
            "identity": row.identity.as_dict(),
            "action": action,
            "reason_code": "EDITOR_REVIEW",
            "target": target,
        })
    return canonical_json_bytes({"contract": "locpipe.editorial.provider-output/v0", "decisions": decisions})


def editorial_fixture(*, actions=None, malformed=False, policy=None):
    context, resolved, translation_job, translation_packet, translation_decision, target_set, translation_state = accepted_fixture()
    policy = policy or EditorialPolicyV0()
    job, packet, parent = build_editorial_job_v0(
        context, resolved, translation_job, translation_packet, translation_decision, target_set,
        translation_state, policy, budget=ProviderBudgetV0(None, None),
    )
    raw_output = editorial_output(job, packet, actions=actions, malformed=malformed)
    receipt = EditorialSubmissionReceiptV0(
        job.job_id, job.invocation_id, job.provider, "editorial-request-1",
        job.packet_sha256, job.output_contract_sha256, raw_sha256(raw_output),
    )
    return context, resolved, translation_job, translation_packet, translation_decision, target_set, policy, job, packet, parent, raw_output, receipt, translation_state


def run_editorial_acceptance(*, actions=None, malformed=False, receipt_mutator=None, target_set_mutator=None):
    fixture = editorial_fixture(actions=actions, malformed=malformed)
    context, resolved, translation_job, translation_packet, translation_decision, target_set, policy, job, packet, parent, raw_output, receipt, translation_state = fixture
    if target_set_mutator:
        target_set = target_set_mutator(target_set)
    if receipt_mutator:
        receipt = receipt_mutator(receipt)
    submission_sha = editorial_submission_digest_v0(receipt)
    state = EditorialStateV0(job.job_id, job.invocation_id, EditorialJobStatusV0.RECEIVED, submission_sha)
    selection = {
        "contract": "locpipe.editorial.selection/v0", "job_id": job.job_id,
        "invocation_id": job.invocation_id, "submission_sha256": submission_sha,
    }
    eroot = editorial_job_root_v0(job)
    troot = translation_job_root_v0(translation_job)
    sroot = editorial_submission_root_v0(receipt)
    artifacts = {
        f"{troot}/job.json": canonical_json_bytes(translation_job.as_dict()),
        f"{troot}/packet.json": canonical_json_bytes(translation_packet.as_dict()),
        f"{troot}/decision.json": translation_decision,
        f"{troot}/state.json": translation_state,
        f"{troot}/target_set.json": canonical_json_bytes(target_set.as_dict()),
        f"{eroot}/job.json": canonical_json_bytes(job.as_dict()),
        f"{eroot}/packet.json": canonical_json_bytes(packet.as_dict()),
        f"{eroot}/parent_candidate.json": canonical_json_bytes(parent.as_dict()),
        f"{eroot}/policy.json": canonical_json_bytes(policy.as_dict()),
        f"{eroot}/selection.json": canonical_json_bytes(selection),
        f"{eroot}/state.json": canonical_json_bytes(state.as_dict()),
        f"{sroot}/output.json": raw_output,
        f"{sroot}/receipt.json": canonical_json_bytes(receipt.as_dict()),
    }
    module = job.module
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        inputs = temp / "inputs"
        staging = temp / "staging"
        inputs.mkdir()
        staging.mkdir()
        for relative, payload in artifacts.items():
            path = inputs / Path(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        binding_set = binding(SyntheticFlatAdapterV0(), module)
        request = OperationRequestV0(
            "editorial-acceptance", Capability.EDITORIAL_REVIEW, semantic_sha256(binding_set),
            tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in sorted(artifacts.items())),
            editorial_acceptance_output_declarations_v0(job),
        )
        implementation, handler = bind_editorial_acceptance_v0(
            module, context, resolved, job, packet, policy, parent,
            translation_job, translation_packet, translation_decision, target_set,
            translation_state,
        )
        result = execute_bound_operation(
            request.as_envelope(), binding_set, handlers={implementation: handler},
            input_root=inputs, staging_root=staging,
        )
        outputs = {}
        for declaration in editorial_acceptance_output_declarations_v0(job):
            path = staging / Path(*declaration.path.split("/"))
            if path.is_file():
                outputs[declaration.path] = path.read_bytes()
        return result, outputs, fixture


class EditorialAcceptanceV0Tests(unittest.TestCase):
    def test_handler_rejects_target_set_not_bound_by_translation_terminal_state(self) -> None:
        def mutate(target_set):
            first = parse_canonical_json(target_set._target_bytes[0])
            data = dict(first["data"])
            data["payload"] = "post-terminal-drift"
            first = dict(first)
            first["data"] = data
            rows = (canonical_json_bytes(first),) + target_set._target_bytes[1:]
            return TranslationTargetSetV0(
                target_set.job_id, target_set.invocation_id, target_set.target_locale, rows,
            )

        result, outputs, _fixture = run_editorial_acceptance(target_set_mutator=mutate)
        self.assertEqual("FAIL", result["data"]["status"])
        self.assertEqual({}, outputs)

    def test_keep_and_correction_create_ready_overlay_candidate(self) -> None:
        fixture = editorial_fixture()
        requested = fixture[8].requested_ids
        raw_before = fixture[10]
        actions = {requested[0]: "CORRECT"}
        result, outputs, selected = run_editorial_acceptance(actions=actions)
        root = editorial_job_root_v0(selected[7])
        self.assertEqual("PASS", result["data"]["status"])
        state = parse_canonical_json(outputs[f"{root}/state.json"])
        candidate = parse_canonical_json(outputs[f"{root}/candidate_set.json"])
        overlay = parse_canonical_json(outputs[f"{root}/overlay.json"])
        self.assertEqual("ACCEPTED", state["status"])
        self.assertTrue(candidate["ready"])
        self.assertEqual(1, len(overlay["entries"]))
        self.assertEqual(raw_before, fixture[10])

    def test_rework_round_and_exhaustion_are_domain_states(self) -> None:
        fixture = editorial_fixture()
        first_id = fixture[8].requested_ids[0]
        raw = editorial_output(fixture[7], fixture[8], actions={first_id: "REWORK_REQUIRED"})
        artifacts = dict(editorial_terminal_artifacts_v0(fixture[7], fixture[8], fixture[6], fixture[9], fixture[11], raw))
        root = editorial_job_root_v0(fixture[7])
        candidate_value = parse_canonical_json(artifacts[f"{root}/candidate_set.json"])
        self.assertEqual("REWORK_REQUIRED", parse_canonical_json(artifacts[f"{root}/state.json"])["status"])
        self.assertEqual([first_id], candidate_value["unresolved_ids"])

        # A zero-round policy turns the same valid content request into bounded exhaustion.
        exhausted = editorial_fixture(actions={first_id: "REWORK_REQUIRED"}, policy=EditorialPolicyV0(0))
        exhausted_raw = editorial_output(exhausted[7], exhausted[8], actions={first_id: "REWORK_REQUIRED"})
        exhausted_artifacts = dict(editorial_terminal_artifacts_v0(exhausted[7], exhausted[8], exhausted[6], exhausted[9], exhausted[11], exhausted_raw))
        exhausted_root = editorial_job_root_v0(exhausted[7])
        self.assertEqual("REWORK_EXHAUSTED", parse_canonical_json(exhausted_artifacts[f"{exhausted_root}/state.json"])["status"])

    def test_two_focused_rework_rounds_are_new_immutable_jobs(self) -> None:
        fixture = editorial_fixture()
        first_id = fixture[8].requested_ids[0]

        def terminal(job, packet, parent, round_action):
            raw = editorial_output(job, packet, actions={first_id: round_action})
            receipt = EditorialSubmissionReceiptV0(
                job.job_id, job.invocation_id, job.provider, f"request-{job.round_index}",
                job.packet_sha256, job.output_contract_sha256, raw_sha256(raw),
            )
            rows = dict(editorial_terminal_artifacts_v0(job, packet, fixture[6], parent, receipt, raw))
            root = editorial_job_root_v0(job)
            return rows, parse_editorial_candidate_v0(rows[f"{root}/candidate_set.json"]), raw_sha256(rows[f"{root}/decision_set.json"])

        round0, candidate0, decision0 = terminal(fixture[7], fixture[8], fixture[9], "REWORK_REQUIRED")
        root0 = editorial_job_root_v0(fixture[7])
        job1, packet1, parent1 = build_editorial_job_v0(
            *fixture[:6], fixture[12], fixture[6], budget=ProviderBudgetV0(None, None),
            parent_candidate=candidate0,
            parent_state_bytes=round0[f"{root0}/state.json"],
            parent_decision_bytes=round0[f"{root0}/decision_set.json"],
            parent_rework_request_bytes=round0[f"{root0}/rework_request.json"],
            requested_ids=candidate0.unresolved_ids, round_index=1,
        )
        round1, candidate1, decision1 = terminal(job1, packet1, parent1, "REWORK_REQUIRED")
        root1 = editorial_job_root_v0(job1)
        job2, packet2, parent2 = build_editorial_job_v0(
            *fixture[:6], fixture[12], fixture[6], budget=ProviderBudgetV0(None, None),
            parent_candidate=candidate1,
            parent_state_bytes=round1[f"{root1}/state.json"],
            parent_decision_bytes=round1[f"{root1}/decision_set.json"],
            parent_rework_request_bytes=round1[f"{root1}/rework_request.json"],
            requested_ids=candidate1.unresolved_ids, round_index=2,
        )
        round2, candidate2, _decision2 = terminal(job2, packet2, parent2, "REWORK_REQUIRED")
        self.assertEqual((0, 1, 2), (fixture[7].round_index, job1.round_index, job2.round_index))
        self.assertEqual(3, len({fixture[7].job_id, job1.job_id, job2.job_id}))
        self.assertEqual("REWORK_EXHAUSTED", parse_canonical_json(round2[f"{editorial_job_root_v0(job2)}/state.json"])["status"])
        self.assertFalse(candidate2.ready)
        with self.assertRaisesRegex(ContractViolation, "exceeds policy"):
            build_editorial_job_v0(
                *fixture[:6], fixture[12], fixture[6], budget=ProviderBudgetV0(None, None),
                parent_candidate=candidate2, parent_state_bytes=round2[f"{editorial_job_root_v0(job2)}/state.json"],
                parent_decision_bytes=round2[f"{editorial_job_root_v0(job2)}/decision_set.json"],
                parent_rework_request_bytes=round2[f"{editorial_job_root_v0(job2)}/rework_request.json"],
                requested_ids=candidate2.unresolved_ids, round_index=3,
            )

    def test_rework_rejects_shrunk_parent_against_terminal_evidence(self) -> None:
        fixture = editorial_fixture()
        first_id = fixture[8].requested_ids[0]
        raw = editorial_output(fixture[7], fixture[8], actions={first_id: "REWORK_REQUIRED"})
        rows = dict(editorial_terminal_artifacts_v0(
            fixture[7], fixture[8], fixture[6], fixture[9], fixture[11], raw,
        ))
        root = editorial_job_root_v0(fixture[7])
        parent = parse_editorial_candidate_v0(rows[f"{root}/candidate_set.json"])
        forged = EditorialCandidateSetV0(
            parent.job_id, parent.target_locale, False, parent.disposition,
            parent.base_target_set_sha256, parent.parent_candidate_sha256,
            parent.overlay_sha256s, parent.unresolved_ids, parent._target_bytes[:1],
        )
        with self.assertRaisesRegex(ContractViolation, "target coverage drift|parent evidence drift"):
            build_editorial_job_v0(
                *fixture[:6], fixture[12], fixture[6], budget=ProviderBudgetV0(None, None),
                parent_candidate=forged,
                parent_state_bytes=rows[f"{root}/state.json"],
                parent_decision_bytes=rows[f"{root}/decision_set.json"],
                parent_rework_request_bytes=rows[f"{root}/rework_request.json"],
                requested_ids=forged.unresolved_ids, round_index=1,
            )

    def test_overlay_is_exact_preimage_bound_and_cannot_reapply(self) -> None:
        fixture = editorial_fixture()
        parent = fixture[9]
        source = next(row for row in fixture[8].rows if row.stable_id == fixture[8].requested_ids[0])
        current = source._target_bytes
        replacement = parse_canonical_json(current)
        data = dict(replacement["data"])
        data["payload"] = "overlay-change"
        data["metadata_ref"] = f"{editorial_job_root_v0(fixture[7])}/overlay.json"
        replacement = dict(replacement)
        replacement["data"] = data
        replacement_bytes = canonical_json_bytes(replacement)
        overlay = CorrectionOverlayV0(
            fixture[7].job_id, "3" * 64, raw_sha256(canonical_json_bytes(parent.as_dict())),
            (CorrectionEntryV0(source.identity, raw_sha256(current), replacement_bytes),),
        )
        applied = apply_correction_overlay_v0(
            parent, overlay, job_id=fixture[7].job_id, ready=True,
            disposition="ACCEPTED", unresolved_ids=(),
        )
        with self.assertRaisesRegex(ContractViolation, "parent candidate drift"):
            apply_correction_overlay_v0(
                applied, overlay, job_id=fixture[7].job_id, ready=True,
                disposition="ACCEPTED", unresolved_ids=(),
            )

    def test_well_bound_malformed_output_is_rejected_not_tooling_failure(self) -> None:
        result, outputs, fixture = run_editorial_acceptance(malformed=True)
        root = editorial_job_root_v0(fixture[7])
        self.assertEqual("PASS", result["data"]["status"])
        self.assertEqual("REJECTED", parse_canonical_json(outputs[f"{root}/state.json"])["status"])
        self.assertFalse(parse_canonical_json(outputs[f"{root}/candidate_set.json"])["ready"])

        malformed_identity = canonical_json_bytes({
            "contract": "locpipe.editorial.provider-output/v0",
            "decisions": [{"identity": {"bad": "identity"}, "action": "KEEP", "reason_code": "BAD", "target": None}],
        })
        receipt = EditorialSubmissionReceiptV0(
            fixture[7].job_id, fixture[7].invocation_id, fixture[7].provider, "bad-identity",
            fixture[7].packet_sha256, fixture[7].output_contract_sha256, raw_sha256(malformed_identity),
        )
        terminal = dict(editorial_terminal_artifacts_v0(
            fixture[7], fixture[8], fixture[6], fixture[9], receipt, malformed_identity,
        ))
        self.assertEqual("REJECTED", parse_canonical_json(terminal[f"{root}/state.json"])["status"])

    def test_foreign_receipt_fails_without_terminal_outputs(self) -> None:
        def mutate(receipt):
            return EditorialSubmissionReceiptV0(
                "foreign", receipt.invocation_id, receipt.provider, receipt.provider_request_id,
                receipt.packet_sha256, receipt.output_contract_sha256, receipt.raw_output_sha256,
            )

        result, outputs, _fixture = run_editorial_acceptance(receipt_mutator=mutate)
        self.assertEqual("FAIL", result["data"]["status"])
        self.assertEqual({}, outputs)


if __name__ == "__main__":
    unittest.main()
