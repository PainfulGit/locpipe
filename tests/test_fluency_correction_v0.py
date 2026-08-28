from __future__ import annotations

import inspect
import sys
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.contracts.v0 import (  # noqa: E402
    ArtifactHashV0,
    BranchIdentity,
    Capability,
    ContractViolation,
    OperationRequestV0,
    canonical_json_bytes,
    display_id,
    execute_bound_operation,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
)
from locpipe.editorial.v0 import (  # noqa: E402
    EditorialCandidateSetV0,
    EditorialPolicyV0,
    EditorialSubmissionReceiptV0,
    build_editorial_job_v0,
    editorial_acceptance_output_declarations_v0,
    editorial_job_root_v0,
    editorial_terminal_artifacts_v0,
    parse_editorial_candidate_v0,
)
from locpipe.editorial.v0._packet import _build_triggered_editorial_job_v0  # noqa: E402
from locpipe.fluency.v0 import (  # noqa: E402
    FluencyDecisionStatusV0,
    FluencyTargetProjectionRowV0,
    FluencyTargetProjectionV0,
    accept_fluency_submission_v0,
    bind_fluency_accuracy_acceptance_v0,
    bind_fluency_submission_receipt_v0,
    build_fluency_editorial_correction_v0,
    build_fluency_review_job_v0,
    fluency_accuracy_acceptance_inputs_v0,
    fluency_accuracy_provider_inputs_v0,
    fluency_correction_trigger_path_v0,
    parse_fluency_correction_trigger_v0,
)
from locpipe.translation.v0 import (  # noqa: E402
    ProviderBudgetV0,
    TranslationPacketRowV0,
    TranslationPacketV0,
)
from tests.test_editorial_acceptance_v0 import editorial_output  # noqa: E402
from tests.test_editorial_packet_v0 import accepted_fixture, editorial_layers  # noqa: E402
from tests.test_translation_acceptance_v0 import binding  # noqa: E402
from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402


FLUENCY_PROVIDER_SHA = "d" * 64


def correction_layers():
    selected = deepcopy(editorial_layers())
    selected["project"]["provider_bindings"].append({
        "role": "fluency_editor",
        "provider_id": "offline-fluency",
        "version": "1.0.0",
        "config_digest": FLUENCY_PROVIDER_SHA,
    })
    selected["project"]["provider_bindings"].sort(key=lambda row: (row["role"], row["provider_id"]))
    return selected


def correction_fixture(*, findings: bool = True):
    authority = accepted_fixture(selected_layers=correction_layers())
    context, resolved, translation_job, translation_packet = authority[:4]
    translation_decision_bytes, target_set, translation_state_bytes = authority[4:]
    policy = EditorialPolicyV0(2)
    parent_job, parent_packet, parent = build_editorial_job_v0(
        context,
        resolved,
        translation_job,
        translation_packet,
        translation_decision_bytes,
        target_set,
        translation_state_bytes,
        policy,
        budget=ProviderBudgetV0(None, None),
    )
    raw_editorial = editorial_output(parent_job, parent_packet)
    editorial_receipt = EditorialSubmissionReceiptV0(
        parent_job.job_id,
        parent_job.invocation_id,
        parent_job.provider,
        "fluency-parent",
        parent_job.packet_sha256,
        parent_job.output_contract_sha256,
        raw_sha256(raw_editorial),
    )
    terminal = dict(editorial_terminal_artifacts_v0(
        parent_job,
        parent_packet,
        policy,
        parent,
        editorial_receipt,
        raw_editorial,
    ))
    root = editorial_job_root_v0(parent_job)
    candidate = parse_editorial_candidate_v0(terminal[f"{root}/candidate_set.json"])
    candidate_evidence = tuple(sorted((
        (f"{root}/job.json", canonical_json_bytes(parent_job.as_dict())),
        (f"{root}/packet.json", canonical_json_bytes(parent_packet.as_dict())),
        (f"{root}/parent_candidate.json", canonical_json_bytes(parent.as_dict())),
        (f"{root}/policy.json", canonical_json_bytes(policy.as_dict())),
        *terminal.items(),
    )))
    candidate_authority_sha = semantic_sha256([
        {"path": path, "sha256": raw_sha256(payload)}
        for path, payload in candidate_evidence
    ])
    projection_rows = []
    for payload in candidate._target_bytes:
        target = parse_canonical_json(payload)
        identity = BranchIdentity.from_dict(target["data"]["identity"])
        projection_rows.append(FluencyTargetProjectionRowV0(
            display_id(identity), "REVIEW", (), (), (), (),
        ))
    projection = FluencyTargetProjectionV0(
        raw_sha256(canonical_json_bytes(candidate.as_dict())),
        candidate.target_locale,
        tuple(sorted(projection_rows, key=lambda row: row.stable_id)),
    )
    requested = tuple(row.stable_id for row in projection.rows)
    plan, fluency_job, fluency_packet = build_fluency_review_job_v0(
        context,
        resolved,
        candidate,
        projection,
        candidate_authority_sha256=candidate_authority_sha,
        requested_ids=requested,
        budget=ProviderBudgetV0(None, None),
    )
    reviews = [
        {"stable_id": stable_id, "outcome": "NO_FINDINGS", "findings": []}
        for stable_id in plan.requested_ids
    ]
    if findings:
        reviews[0] = {
            "stable_id": plan.requested_ids[0],
            "outcome": "FINDINGS",
            "findings": [
                {"category": "READABILITY", "diagnostic_note": "Речення потребує чіткішої побудови."},
                {"category": "VOICE", "diagnostic_note": "Регістр не відповідає заданому голосу."},
            ],
        }
    raw_fluency = canonical_json_bytes({
        "contract": "locpipe.fluency.provider-output/v0",
        "job_id": fluency_job.job_id,
        "invocation_id": fluency_job.invocation_id,
        "plan_sha256": plan.digest,
        "packet_sha256": fluency_job.packet_sha256,
        "provider": fluency_job.provider.as_dict(),
        "output_contract_sha256": fluency_job.output_contract_sha256,
        "reviews": reviews,
    })
    receipt = bind_fluency_submission_receipt_v0(
        plan,
        fluency_job,
        fluency_packet,
        raw_fluency,
        provider_request_id="fluency-correction",
    )
    receipt_bytes = canonical_json_bytes(receipt.as_dict())
    decision, state = accept_fluency_submission_v0(
        plan,
        fluency_job,
        fluency_packet,
        receipt_bytes,
        raw_fluency,
    )
    return {
        "context": context,
        "resolved": resolved,
        "translation_job": translation_job,
        "translation_packet": translation_packet,
        "translation_decision_bytes": translation_decision_bytes,
        "translation_state_bytes": translation_state_bytes,
        "target_set": target_set,
        "policy": policy,
        "candidate": candidate,
        "candidate_evidence": candidate_evidence,
        "parent_job": parent_job,
        "parent_packet": parent_packet,
        "plan": plan,
        "fluency_job": fluency_job,
        "fluency_packet": fluency_packet,
        "receipt_bytes": receipt_bytes,
        "raw_fluency": raw_fluency,
        "decision": decision,
        "state": state,
    }


def build_correction(fixture, **changes):
    values = dict(fixture)
    values.update(changes)
    return build_fluency_editorial_correction_v0(
        values["context"],
        values["resolved"],
        values["translation_job"],
        values["translation_packet"],
        values["translation_decision_bytes"],
        values["translation_state_bytes"],
        values["target_set"],
        values["policy"],
        values["candidate"],
        values["candidate_evidence"],
        values["parent_job"],
        values["parent_packet"],
        values["plan"],
        values["fluency_job"],
        values["fluency_packet"],
        values["receipt_bytes"],
        values["raw_fluency"],
        values["decision"],
        values["state"],
        budget=ProviderBudgetV0(None, None),
    )


class FluencyCorrectionV0Tests(unittest.TestCase):
    def test_correction_required_builds_deterministic_source_aware_job(self) -> None:
        fixture = correction_fixture()
        first = build_correction(fixture)
        second = build_correction(fixture)
        self.assertEqual(first, second)
        job, packet, trigger_bytes = first
        trigger = parse_fluency_correction_trigger_v0(trigger_bytes)
        self.assertEqual(fixture["decision"].correction_ids, trigger.affected_target_ids)
        self.assertEqual(packet.requested_ids, trigger.requested_source_ids)
        self.assertEqual(job.parent_decision_sha256, raw_sha256(trigger_bytes))
        self.assertEqual(1, job.round_index)
        self.assertNotEqual(trigger.affected_target_ids, trigger.requested_source_ids)
        self.assertEqual(
            ("READABILITY", "VOICE"),
            tuple(row.category.value for row in trigger.entries[0].findings),
        )
        self.assertEqual(
            ("Речення потребує чіткішої побудови.", "Регістр не відповідає заданому голосу."),
            tuple(row.diagnostic_note for row in trigger.entries[0].findings),
        )
        context_ids = tuple(row.stable_id for row in packet.rows if row.role.value == "CONTEXT")
        self.assertFalse(set(context_ids) & set(packet.requested_ids))
        rendered = canonical_json_bytes(packet.as_dict())
        self.assertIn(b"source_revision_sha", rendered)
        self.assertNotIn(b"diagnostic_note", rendered)

    def test_trigger_is_closed_non_authoritative_sidecar(self) -> None:
        fixture = correction_fixture()
        _job, _packet, trigger_bytes = build_correction(fixture)
        self.assertNotIn(b"replacement", trigger_bytes)
        self.assertNotIn(b"source_payload", trigger_bytes)
        forged = parse_canonical_json(trigger_bytes)
        forged["entries"][0]["replacement"] = "forbidden"
        with self.assertRaises(ContractViolation):
            parse_fluency_correction_trigger_v0(canonical_json_bytes(forged))
        signature = inspect.signature(build_fluency_editorial_correction_v0)
        for forbidden in ("root", "path", "publisher", "overlay", "replacement"):
            self.assertNotIn(forbidden, signature.parameters)

    def test_accuracy_provider_bundle_and_acceptance_are_exact_bound(self) -> None:
        fixture = correction_fixture()
        job, packet, trigger_bytes = build_correction(fixture)
        trigger = parse_fluency_correction_trigger_v0(trigger_bytes)
        provider_inputs = fluency_accuracy_provider_inputs_v0(
            fixture["resolved"], job, packet, fixture["policy"], fixture["candidate"], trigger_bytes,
        )
        provider_rows = dict(provider_inputs)
        trigger_path = fluency_correction_trigger_path_v0(trigger)
        self.assertEqual(trigger_bytes, provider_rows[trigger_path])
        self.assertEqual(raw_sha256(trigger_bytes), job.parent_decision_sha256)
        self.assertNotIn(b"diagnostic_note", canonical_json_bytes(packet.as_dict()))
        self.assertIn(b"diagnostic_note", provider_rows[trigger_path])

        raw_accuracy = editorial_output(job, packet)
        receipt = EditorialSubmissionReceiptV0(
            job.job_id,
            job.invocation_id,
            job.provider,
            "fluency-accuracy",
            job.packet_sha256,
            job.output_contract_sha256,
            raw_sha256(raw_accuracy),
        )
        inputs_rows = fluency_accuracy_acceptance_inputs_v0(
            fixture["resolved"], fixture["translation_job"], fixture["translation_packet"],
            fixture["translation_decision_bytes"], fixture["translation_state_bytes"],
            fixture["target_set"], job, packet, fixture["policy"], fixture["candidate"],
            fixture["candidate_evidence"], fixture["plan"], fixture["fluency_job"],
            fixture["fluency_packet"], fixture["receipt_bytes"], fixture["raw_fluency"],
            fixture["decision"], fixture["state"], trigger_bytes, receipt, raw_accuracy,
        )
        implementation, handler = bind_fluency_accuracy_acceptance_v0(
            fixture["context"], fixture["resolved"], fixture["translation_job"],
            fixture["translation_packet"], fixture["translation_decision_bytes"],
            fixture["translation_state_bytes"], fixture["target_set"], fixture["policy"],
            fixture["candidate"], fixture["candidate_evidence"], fixture["parent_job"],
            fixture["parent_packet"], fixture["plan"], fixture["fluency_job"],
            fixture["fluency_packet"], fixture["receipt_bytes"], fixture["raw_fluency"],
            fixture["decision"], fixture["state"], job, packet, trigger_bytes, receipt, raw_accuracy,
        )
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            inputs = temp / "inputs"
            staging = temp / "staging"
            inputs.mkdir()
            staging.mkdir()
            for relative, payload in inputs_rows:
                path = inputs / Path(*relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            module_binding = binding(SyntheticFlatAdapterV0(), job.module)
            request = OperationRequestV0(
                "fluency-accuracy-acceptance",
                Capability.EDITORIAL_REVIEW,
                semantic_sha256(module_binding),
                tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in inputs_rows),
                editorial_acceptance_output_declarations_v0(job),
            )
            result = execute_bound_operation(
                request.as_envelope(), module_binding, handlers={implementation: handler},
                input_root=inputs, staging_root=staging,
            )
            self.assertEqual("PASS", result["data"]["status"])
            for declaration in editorial_acceptance_output_declarations_v0(job):
                self.assertTrue((staging / Path(*declaration.path.split("/"))).is_file())

    def test_provider_bundle_rejects_identity_drift_with_same_config_digest(self) -> None:
        fixture = correction_fixture()
        job, packet, trigger_bytes = build_correction(fixture)
        drifted_job = replace(
            job,
            provider=replace(job.provider, provider_id="foreign-accuracy-provider"),
        )
        self.assertEqual(job.provider.config_digest, drifted_job.provider.config_digest)
        with self.assertRaisesRegex(ContractViolation, "provider input authority drift"):
            fluency_accuracy_provider_inputs_v0(
                fixture["resolved"], drifted_job, packet, fixture["policy"],
                fixture["candidate"], trigger_bytes,
            )

    def test_accuracy_transport_rejects_trigger_receipt_and_declared_input_drift(self) -> None:
        fixture = correction_fixture()
        job, packet, trigger_bytes = build_correction(fixture)
        raw_accuracy = editorial_output(job, packet)
        receipt = EditorialSubmissionReceiptV0(
            job.job_id, job.invocation_id, job.provider, "fluency-accuracy",
            job.packet_sha256, job.output_contract_sha256, raw_sha256(raw_accuracy),
        )
        forged_trigger = parse_canonical_json(trigger_bytes)
        forged_trigger["accuracy_provider_config_digest"] = "0" * 64
        with self.assertRaises(ContractViolation):
            fluency_accuracy_provider_inputs_v0(
                fixture["resolved"], job, packet, fixture["policy"], fixture["candidate"],
                canonical_json_bytes(forged_trigger),
            )
        foreign_receipt = EditorialSubmissionReceiptV0(
            job.job_id, job.invocation_id, job.provider, "fluency-accuracy",
            job.packet_sha256, job.output_contract_sha256, "0" * 64,
        )
        with self.assertRaises(ContractViolation):
            fluency_accuracy_acceptance_inputs_v0(
                fixture["resolved"], fixture["translation_job"], fixture["translation_packet"],
                fixture["translation_decision_bytes"], fixture["translation_state_bytes"],
                fixture["target_set"], job, packet, fixture["policy"], fixture["candidate"],
                fixture["candidate_evidence"], fixture["plan"], fixture["fluency_job"],
                fixture["fluency_packet"], fixture["receipt_bytes"], fixture["raw_fluency"],
                fixture["decision"], fixture["state"], trigger_bytes, foreign_receipt, raw_accuracy,
            )
        with self.assertRaises(ContractViolation):
            fluency_accuracy_acceptance_inputs_v0(
                fixture["resolved"], fixture["translation_job"], fixture["translation_packet"],
                fixture["translation_decision_bytes"], fixture["translation_state_bytes"],
                fixture["target_set"], job, packet, fixture["policy"], fixture["candidate"],
                fixture["candidate_evidence"], fixture["plan"], fixture["fluency_job"],
                fixture["fluency_packet"], fixture["receipt_bytes"], fixture["raw_fluency"],
                fixture["decision"], fixture["state"], trigger_bytes, receipt, raw_accuracy + b" ",
            )

        inputs_rows = fluency_accuracy_acceptance_inputs_v0(
            fixture["resolved"], fixture["translation_job"], fixture["translation_packet"],
            fixture["translation_decision_bytes"], fixture["translation_state_bytes"],
            fixture["target_set"], job, packet, fixture["policy"], fixture["candidate"],
            fixture["candidate_evidence"], fixture["plan"], fixture["fluency_job"],
            fixture["fluency_packet"], fixture["receipt_bytes"], fixture["raw_fluency"],
            fixture["decision"], fixture["state"], trigger_bytes, receipt, raw_accuracy,
        )
        implementation, handler = bind_fluency_accuracy_acceptance_v0(
            fixture["context"], fixture["resolved"], fixture["translation_job"],
            fixture["translation_packet"], fixture["translation_decision_bytes"],
            fixture["translation_state_bytes"], fixture["target_set"], fixture["policy"],
            fixture["candidate"], fixture["candidate_evidence"], fixture["parent_job"],
            fixture["parent_packet"], fixture["plan"], fixture["fluency_job"],
            fixture["fluency_packet"], fixture["receipt_bytes"], fixture["raw_fluency"],
            fixture["decision"], fixture["state"], job, packet, trigger_bytes, receipt, raw_accuracy,
        )
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            inputs = temp / "inputs"
            staging = temp / "staging"
            inputs.mkdir()
            staging.mkdir()
            for relative, payload in inputs_rows:
                path = inputs / Path(*relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            module_binding = binding(SyntheticFlatAdapterV0(), job.module)
            trigger_path = fluency_correction_trigger_path_v0(
                parse_fluency_correction_trigger_v0(trigger_bytes)
            )
            missing = tuple(row for row in inputs_rows if row[0] != trigger_path)
            request = OperationRequestV0(
                "fluency-accuracy-missing-input",
                Capability.EDITORIAL_REVIEW,
                semantic_sha256(module_binding),
                tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in missing),
                editorial_acceptance_output_declarations_v0(job),
            )
            result = execute_bound_operation(
                request.as_envelope(), module_binding, handlers={implementation: handler},
                input_root=inputs, staging_root=staging,
            )
            self.assertEqual("FAIL", result["data"]["status"])
            self.assertEqual([], list(staging.rglob("*")))
            extra_path = "fl/c/foreign/trigger.json"
            extra_file = inputs / Path(*extra_path.split("/"))
            extra_file.parent.mkdir(parents=True, exist_ok=True)
            extra_file.write_bytes(trigger_bytes)
            extra = tuple(sorted((*inputs_rows, (extra_path, trigger_bytes))))
            request = OperationRequestV0(
                "fluency-accuracy-extra-input",
                Capability.EDITORIAL_REVIEW,
                semantic_sha256(module_binding),
                tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in extra),
                editorial_acceptance_output_declarations_v0(job),
            )
            result = execute_bound_operation(
                request.as_envelope(), module_binding, handlers={implementation: handler},
                input_root=inputs, staging_root=staging,
            )
            self.assertEqual("FAIL", result["data"]["status"])
            self.assertEqual([], list(staging.rglob("*")))

    def test_stale_fluency_candidate_config_provider_and_evidence_fail_closed(self) -> None:
        fixture = correction_fixture()
        cases = (
            {"plan": replace(fixture["plan"], candidate_authority_sha256="0" * 64)},
            {"plan": replace(
                fixture["plan"],
                accuracy_provider=replace(fixture["plan"].accuracy_provider, config_digest="0" * 64),
            )},
            {"fluency_job": replace(fixture["fluency_job"], packet_sha256="0" * 64)},
            {"state": replace(fixture["state"], decision_sha256="0" * 64)},
            {"candidate_evidence": tuple((
                path,
                payload + b" " if index == 0 else payload,
            ) for index, (path, payload) in enumerate(fixture["candidate_evidence"]))},
        )
        for index, changes in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ContractViolation):
                build_correction(fixture, **changes)

    def test_verified_input_and_mapping_drift_are_rejected(self) -> None:
        clear = correction_fixture(findings=False)
        self.assertIs(clear["decision"].status, FluencyDecisionStatusV0.FLUENCY_VERIFIED)
        with self.assertRaisesRegex(ContractViolation, "accepted findings"):
            build_correction(clear)

        fixture = correction_fixture()
        packet = fixture["fluency_packet"]
        rows = list(packet.rows)
        changed_target = parse_canonical_json(rows[0]._target_bytes)
        changed_target["data"]["payload"] += " drift"
        from locpipe.fluency.v0 import FluencyReviewPacketRowV0, FluencyReviewPacketV0

        rows[0] = FluencyReviewPacketRowV0(
            rows[0].stable_id,
            rows[0].role,
            rows[0].profile_ids,
            rows[0].group_ids,
            rows[0].relation_ids,
            rows[0]._guidance_bytes,
            canonical_json_bytes(changed_target),
        )
        drifted_packet = FluencyReviewPacketV0(
            packet.target_locale,
            packet.candidate_sha256,
            packet.projection_sha256,
            packet.requested_ids,
            tuple(rows),
        )
        with self.assertRaises(ContractViolation):
            build_correction(fixture, fluency_packet=drifted_packet)

        source = next(row for row in fixture["translation_packet"].rows if row.role.value == "OWNED")
        duplicate = TranslationPacketRowV0(
            BranchIdentity(source.identity.logical_id, "fr", source.identity.selector_path),
            source.role,
            source.source_revision_sha,
            source.content_type,
            source._payload_bytes,
            source._constraints_bytes,
        )
        translation_packet = TranslationPacketV0(
            fixture["translation_packet"].target_locale,
            tuple(sorted((*fixture["translation_packet"].rows, duplicate), key=lambda row: row.stable_id)),
            fixture["translation_packet"]._relation_bytes,
        )
        translation_job = replace(
            fixture["translation_job"],
            packet_sha256=raw_sha256(canonical_json_bytes(translation_packet.as_dict())),
        )
        with self.assertRaisesRegex(ContractViolation, "source selector is ambiguous"):
            build_correction(
                fixture,
                translation_packet=translation_packet,
                translation_job=translation_job,
            )

    def test_shared_triggered_constructor_rejects_foreign_origin_and_bad_coverage(self) -> None:
        fixture = correction_fixture()
        _job, _packet, trigger_bytes = build_correction(fixture)
        module = fixture["plan"].module
        provider = fixture["plan"].accuracy_provider
        common = (
            fixture["context"],
            fixture["resolved"],
            fixture["translation_job"],
            fixture["translation_packet"],
            fixture["translation_decision_bytes"],
            fixture["translation_state_bytes"],
            fixture["candidate"],
            fixture["policy"],
            module,
            provider,
        )
        with self.assertRaisesRegex(ContractViolation, "origin domain"):
            _build_triggered_editorial_job_v0(
                *common,
                requested_ids=(next(iter(fixture["translation_packet"].rows)).stable_id,),
                round_index=1,
                trigger_bytes=trigger_bytes,
                origin_domain="foreign",
                budget=ProviderBudgetV0(None, None),
            )
        with self.assertRaisesRegex(ContractViolation, "coverage drift"):
            _build_triggered_editorial_job_v0(
                *common,
                requested_ids=("foreign-context-id",),
                round_index=1,
                trigger_bytes=trigger_bytes,
                origin_domain="fluency",
                budget=ProviderBudgetV0(None, None),
            )

    def test_no_acceptance_overlay_recheck_or_filesystem_surface_is_created(self) -> None:
        fixture = correction_fixture()
        job, packet, trigger_bytes = build_correction(fixture)
        self.assertTrue(job.job_id.startswith("editorial-"))
        self.assertTrue(packet.requested_ids)
        self.assertEqual("locpipe.fluency.correction-trigger/v0", parse_canonical_json(trigger_bytes)["contract"])
        for rendered in (canonical_json_bytes(job.as_dict()), canonical_json_bytes(packet.as_dict()), trigger_bytes):
            for forbidden in (b"overlay", b"candidate_set", b"recheck", b"terminal", b"publication"):
                self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":
    unittest.main()
