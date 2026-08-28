from __future__ import annotations

import unittest
from copy import deepcopy
from unittest.mock import patch

from locpipe.contracts.v0 import (
    BranchIdentity,
    canonical_json_bytes,
    display_id,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
)
from locpipe.editorial.v0 import (
    EditorialSubmissionReceiptV0,
    editorial_job_root_v0,
    editorial_terminal_artifacts_v0,
    parse_editorial_candidate_v0,
)
from locpipe.fluency.v0 import (
    FluencyCorrectionTerminalStatusV0,
    FluencyTargetProjectionRowV0,
    FluencyTargetProjectionV0,
    accept_fluency_adjudication_v0,
    accept_fluency_submission_v0,
    bind_fluency_correction_terminal_v0,
    bind_fluency_submission_receipt_v0,
    build_fluency_content_validation_job_v0,
    build_fluency_editorial_correction_v0,
    build_fluency_recheck_job_v0,
    build_fluency_review_job_v0,
    fluency_accuracy_provider_inputs_v0,
    fluency_correction_trigger_path_v0,
    parse_fluency_correction_trigger_v0,
)
from locpipe.translation.v0 import ProviderBudgetV0
from locpipe.validation.v0 import (
    content_locale_receipt_v0,
    finalize_content_verified_v0,
    validation_job_root_v0,
)

from locpipe._demo_support import test_content_validation_v0 as content_support
from locpipe._demo_support.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0
from locpipe._demo_support.test_editorial_acceptance_v0 import editorial_output


FLUENCY_PROVIDER_SHA256 = "d" * 64
PROJECTION_PATH = "fluency/validation-authority.json"
FORBIDDEN_PACKET_MARKERS = (
    b'"constraints"',
    b'"diagnostic_note"',
    b'"editorial"',
    b'"overlay"',
    b'"source_payload"',
    b'"trigger"',
)


def _validation_fixture():
    original = content_support.validation_layers

    def selected(*, configured_editor=True, locales=("pl", "uk")):
        base = deepcopy(original(configured_editor=configured_editor, locales=locales))
        base["project"]["provider_bindings"].append({
            "role": "fluency_editor",
            "provider_id": "offline-fluency",
            "version": "1.0.0",
            "config_digest": FLUENCY_PROVIDER_SHA256,
        })
        base["project"]["provider_bindings"].sort(
            key=lambda row: (row["role"], row["provider_id"]),
        )
        return base

    with patch.object(content_support, "validation_layers", side_effect=selected):
        return content_support.validation_fixture(
            "flat",
            SyntheticFlatAdapterV0(),
            target_locale="uk",
            locales=("uk",),
        )


def _candidate_authority(candidate_evidence: tuple[tuple[str, bytes], ...]) -> str:
    return semantic_sha256([
        {"path": path, "sha256": raw_sha256(payload)}
        for path, payload in candidate_evidence
    ])


def _target_ids(candidate) -> tuple[str, ...]:
    values = []
    for payload in candidate._target_bytes:
        target = parse_canonical_json(payload)
        values.append(display_id(BranchIdentity.from_dict(target["data"]["identity"])))
    return tuple(sorted(values))


def _projection(candidate, review_ids: tuple[str, ...], *, context_ids: tuple[str, ...] = ()):
    roles = {stable_id: "REVIEW" for stable_id in review_ids}
    roles.update({stable_id: "CONTEXT" for stable_id in context_ids})
    return FluencyTargetProjectionV0(
        raw_sha256(canonical_json_bytes(candidate.as_dict())),
        candidate.target_locale,
        tuple(sorted((
            FluencyTargetProjectionRowV0(stable_id, role, (), (), (), ())
            for stable_id, role in roles.items()
        ), key=lambda row: row.stable_id)),
    )


def _provider_output(plan, job, *, finding_id: str | None = None) -> bytes:
    reviews = []
    for stable_id in plan.requested_ids:
        findings = []
        outcome = "NO_FINDINGS"
        if stable_id == finding_id:
            outcome = "FINDINGS"
            findings = [{
                "category": "READABILITY",
                "diagnostic_note": "Синтетичний рядок потребує чіткішої побудови.",
            }]
        reviews.append({
            "stable_id": stable_id,
            "outcome": outcome,
            "findings": findings,
        })
    return canonical_json_bytes({
        "contract": "locpipe.fluency.provider-output/v0",
        "job_id": job.job_id,
        "invocation_id": job.invocation_id,
        "plan_sha256": plan.digest,
        "packet_sha256": job.packet_sha256,
        "provider": job.provider.as_dict(),
        "output_contract_sha256": job.output_contract_sha256,
        "reviews": reviews,
    })


def _review_chain(fixture, *, finding: bool):
    candidate = fixture["candidate"]
    projection = _projection(candidate, _target_ids(candidate))
    budget = ProviderBudgetV0(None, None)
    plan, job, packet = build_fluency_review_job_v0(
        fixture["context"],
        fixture["resolved"],
        candidate,
        projection,
        candidate_authority_sha256=_candidate_authority(fixture["candidate_evidence"]),
        requested_ids=tuple(row.stable_id for row in projection.rows),
        budget=budget,
    )
    finding_id = plan.requested_ids[0] if finding else None
    raw_output = _provider_output(plan, job, finding_id=finding_id)
    receipt = bind_fluency_submission_receipt_v0(
        plan,
        job,
        packet,
        raw_output,
        provider_request_id="synthetic-fluency-finding" if finding else "synthetic-fluency-clear",
    )
    receipt_bytes = canonical_json_bytes(receipt.as_dict())
    decision, state = accept_fluency_submission_v0(
        plan,
        job,
        packet,
        receipt_bytes,
        raw_output,
    )
    return {
        "projection": projection,
        "budget": budget,
        "plan": plan,
        "job": job,
        "packet": packet,
        "receipt_bytes": receipt_bytes,
        "raw_output": raw_output,
        "decision": decision,
        "state": state,
    }


def _assert_target_side_packet(test_case: unittest.TestCase, plan, packet) -> None:
    review_ids = tuple(row.stable_id for row in packet.rows if row.role == "REVIEW")
    test_case.assertEqual(plan.requested_ids, review_ids)
    rendered = canonical_json_bytes(packet.as_dict())
    for marker in FORBIDDEN_PACKET_MARKERS:
        test_case.assertNotIn(marker, rendered)


def _validation_call(fixture, candidate, candidate_evidence, editorial_job, editorial_packet, **provenance):
    authority = dict(fixture["authority"])
    return build_fluency_content_validation_job_v0(
        fixture["context"],
        fixture["resolved"],
        fixture["scope"],
        fixture["translation_job"],
        fixture["translation_packet"],
        fixture["translation_decision_bytes"],
        fixture["translation_state_bytes"],
        fixture["translation_target_set"],
        candidate,
        fixture["validator"],
        source_lock_bytes=authority["source/source_lock.json"],
        reconciliation_bytes=authority["reconciliation/reconciliation.json"],
        scope_bytes=authority["scope/scope.json"],
        scope_lock_bytes=authority["scope/scope_lock.json"],
        segments_bytes=authority["corpus/segments.jsonl"],
        candidate_evidence=candidate_evidence,
        editorial_job=editorial_job,
        editorial_packet=editorial_packet,
        editorial_policy=fixture["editorial_policy"],
        **provenance,
    )


def _publish_content_verified(test_case: unittest.TestCase, fixture, validation):
    job, packet, authority = validation
    runnable = dict(fixture)
    runnable.update({"job": job, "packet": packet, "authority": authority})
    operation_result, outputs = content_support.run_validation(runnable)
    test_case.assertEqual("PASS", operation_result["data"]["status"])
    root = validation_job_root_v0(job)
    test_case.assertEqual(
        "LOCALE_VERIFIED",
        parse_canonical_json(outputs[f"{root}/state.json"])["status"],
    )
    publication_receipt, store, temporary = content_support.publish_validation_evidence(
        runnable,
        operation_result,
        outputs,
    )
    try:
        locale_receipt = content_locale_receipt_v0(
            job,
            outputs[f"{root}/report.json"],
            outputs[f"{root}/state.json"],
            outputs[f"{root}/rework_request.json"],
            store=store,
            context=fixture["context"],
            operation_result=operation_result,
            validation_publication_receipt=publication_receipt,
        )
        verification, state = finalize_content_verified_v0(
            fixture["scope"],
            (locale_receipt,),
            validation_evidence=((
                job,
                outputs[f"{root}/report.json"],
                outputs[f"{root}/state.json"],
                outputs[f"{root}/rework_request.json"],
                operation_result,
                publication_receipt,
                store,
                fixture["context"],
            ),),
        )
    finally:
        temporary.cleanup()
    test_case.assertEqual("CONTENT_VERIFIED", parse_canonical_json(state)["state"])
    test_case.assertEqual("uk", verification.locale_receipts[0].target_locale)
    test_case.assertIn(PROJECTION_PATH, dict(authority))
    return job, raw_sha256(state)


def _resulting_candidate_authority(fixture, job, packet, terminal):
    root = editorial_job_root_v0(job)
    terminal_map = dict(terminal)
    candidate = parse_editorial_candidate_v0(terminal_map[f"{root}/candidate_set.json"])
    evidence = tuple(sorted((
        (f"{root}/job.json", canonical_json_bytes(job.as_dict())),
        (f"{root}/packet.json", canonical_json_bytes(packet.as_dict())),
        (f"{root}/parent_candidate.json", canonical_json_bytes(fixture["candidate"].as_dict())),
        (f"{root}/policy.json", canonical_json_bytes(fixture["editorial_policy"].as_dict())),
        *terminal,
    )))
    return candidate, evidence


def _correction_chain(fixture, initial):
    accuracy_job, accuracy_packet, trigger_bytes = build_fluency_editorial_correction_v0(
        fixture["context"],
        fixture["resolved"],
        fixture["translation_job"],
        fixture["translation_packet"],
        fixture["translation_decision_bytes"],
        fixture["translation_state_bytes"],
        fixture["translation_target_set"],
        fixture["editorial_policy"],
        fixture["candidate"],
        fixture["candidate_evidence"],
        fixture["editorial_job"],
        fixture["editorial_packet"],
        initial["plan"],
        initial["job"],
        initial["packet"],
        initial["receipt_bytes"],
        initial["raw_output"],
        initial["decision"],
        initial["state"],
        budget=ProviderBudgetV0(None, None),
    )
    provider_inputs = dict(fluency_accuracy_provider_inputs_v0(
        fixture["resolved"],
        accuracy_job,
        accuracy_packet,
        fixture["editorial_policy"],
        fixture["candidate"],
        trigger_bytes,
    ))
    trigger_path = fluency_correction_trigger_path_v0(
        parse_fluency_correction_trigger_v0(trigger_bytes),
    )
    if provider_inputs.get(trigger_path) != trigger_bytes:
        raise AssertionError("Fluency trigger is not an exact provider input")

    actions = {stable_id: "CORRECT" for stable_id in accuracy_packet.requested_ids}
    raw_value = parse_canonical_json(editorial_output(
        accuracy_job,
        accuracy_packet,
        actions=actions,
    ))
    for row in raw_value["decisions"]:
        row["reason_code"] = "FLUENCY_FINDING_FIXED"
    raw_output = canonical_json_bytes(raw_value)
    receipt = EditorialSubmissionReceiptV0(
        accuracy_job.job_id,
        accuracy_job.invocation_id,
        accuracy_job.provider,
        "synthetic-accuracy-correction",
        accuracy_job.packet_sha256,
        accuracy_job.output_contract_sha256,
        raw_sha256(raw_output),
    )
    terminal = editorial_terminal_artifacts_v0(
        accuracy_job,
        accuracy_packet,
        fixture["editorial_policy"],
        fixture["candidate"],
        receipt,
        raw_output,
    )
    adjudication = accept_fluency_adjudication_v0(
        fixture["resolved"],
        trigger_bytes,
        accuracy_job,
        accuracy_packet,
        fixture["editorial_policy"],
        fixture["candidate"],
        receipt,
        raw_output,
        terminal,
    )
    candidate, evidence = _resulting_candidate_authority(
        fixture,
        accuracy_job,
        accuracy_packet,
        terminal,
    )
    return {
        "accuracy_job": accuracy_job,
        "accuracy_packet": accuracy_packet,
        "trigger_bytes": trigger_bytes,
        "receipt": receipt,
        "raw_output": raw_output,
        "terminal": terminal,
        "adjudication": adjudication,
        "adjudication_bytes": canonical_json_bytes(adjudication.as_dict()),
        "candidate": candidate,
        "candidate_evidence": evidence,
    }


class FluencyLifecycleV0Tests(unittest.TestCase):
    def test_initial_state_reaches_existing_content_verified_publication(self) -> None:
        fixture = _validation_fixture()
        initial = _review_chain(fixture, finding=False)
        self.assertEqual(_target_ids(fixture["candidate"]), initial["plan"].requested_ids)
        _assert_target_side_packet(self, initial["plan"], initial["packet"])
        provenance = {
            "provenance_kind": "INITIAL_STATE",
            "initial_projection": initial["projection"],
            "initial_budget": initial["budget"],
            "initial_plan": initial["plan"],
            "initial_job": initial["job"],
            "initial_packet": initial["packet"],
            "initial_receipt_bytes": initial["receipt_bytes"],
            "initial_raw_output": initial["raw_output"],
            "initial_decision": initial["decision"],
            "initial_state": initial["state"],
        }
        first = _validation_call(
            fixture,
            fixture["candidate"],
            fixture["candidate_evidence"],
            fixture["editorial_job"],
            fixture["editorial_packet"],
            **provenance,
        )
        second = _validation_call(
            fixture,
            fixture["candidate"],
            fixture["candidate_evidence"],
            fixture["editorial_job"],
            fixture["editorial_packet"],
            **provenance,
        )
        self.assertEqual(first, second)
        _publish_content_verified(self, fixture, first)

    def test_one_correction_recheck_reaches_existing_content_verified_publication(self) -> None:
        fixture = _validation_fixture()
        initial = _review_chain(fixture, finding=True)
        self.assertEqual(1, len(initial["decision"].correction_ids))
        _assert_target_side_packet(self, initial["plan"], initial["packet"])
        correction = _correction_chain(fixture, initial)
        adjudication = correction["adjudication"]
        self.assertEqual(1, len(adjudication.corrected_ids))

        all_ids = _target_ids(correction["candidate"])
        context_ids = tuple(
            stable_id for stable_id in all_ids if stable_id not in adjudication.corrected_ids
        )[:1]
        projection = _projection(
            correction["candidate"],
            adjudication.corrected_ids,
            context_ids=context_ids,
        )
        budget = ProviderBudgetV0(None, None)
        common = (
            fixture["context"],
            fixture["resolved"],
            correction["trigger_bytes"],
            correction["adjudication_bytes"],
            correction["accuracy_job"],
            correction["accuracy_packet"],
            fixture["editorial_policy"],
            fixture["candidate"],
            correction["receipt"],
            correction["raw_output"],
            correction["terminal"],
            correction["candidate_evidence"],
        )
        plan, job, packet = build_fluency_recheck_job_v0(
            *common,
            projection,
            budget=budget,
        )
        self.assertEqual(adjudication.corrected_ids, plan.requested_ids)
        self.assertEqual(
            adjudication.corrected_ids,
            tuple(row.stable_id for row in packet.rows if row.role == "REVIEW"),
        )
        self.assertEqual(context_ids, tuple(row.stable_id for row in packet.rows if row.role == "CONTEXT"))
        _assert_target_side_packet(self, plan, packet)

        raw_recheck = _provider_output(plan, job)
        recheck_receipt = bind_fluency_submission_receipt_v0(
            plan,
            job,
            packet,
            raw_recheck,
            provider_request_id="synthetic-fluency-recheck",
        )
        recheck_receipt_bytes = canonical_json_bytes(recheck_receipt.as_dict())
        decision, state = accept_fluency_submission_v0(
            plan,
            job,
            packet,
            recheck_receipt_bytes,
            raw_recheck,
        )
        terminal = bind_fluency_correction_terminal_v0(
            *common,
            recheck_projection=projection,
            recheck_budget=budget,
            recheck_plan=plan,
            recheck_job=job,
            recheck_packet=packet,
            recheck_receipt_bytes=recheck_receipt_bytes,
            recheck_raw_output=raw_recheck,
            recheck_decision=decision,
            recheck_state=state,
        )
        self.assertIs(terminal.status, FluencyCorrectionTerminalStatusV0.FLUENCY_VERIFIED)
        terminal_bytes = canonical_json_bytes(terminal.as_dict())
        provenance = {
            "provenance_kind": "CORRECTION_TERMINAL",
            "correction_terminal_bytes": terminal_bytes,
            "correction_trigger_bytes": correction["trigger_bytes"],
            "correction_adjudication_bytes": correction["adjudication_bytes"],
            "correction_accuracy_job": correction["accuracy_job"],
            "correction_accuracy_packet": correction["accuracy_packet"],
            "correction_accuracy_policy": fixture["editorial_policy"],
            "correction_accuracy_parent_candidate": fixture["candidate"],
            "correction_accuracy_receipt": correction["receipt"],
            "correction_accuracy_raw_output": correction["raw_output"],
            "correction_accuracy_terminal_artifacts": correction["terminal"],
            "correction_recheck_projection": projection,
            "correction_recheck_budget": budget,
            "correction_recheck_plan": plan,
            "correction_recheck_job": job,
            "correction_recheck_packet": packet,
            "correction_recheck_receipt_bytes": recheck_receipt_bytes,
            "correction_recheck_raw_output": raw_recheck,
            "correction_recheck_decision": decision,
            "correction_recheck_state": state,
        }
        first = _validation_call(
            fixture,
            correction["candidate"],
            correction["candidate_evidence"],
            correction["accuracy_job"],
            correction["accuracy_packet"],
            **provenance,
        )
        second = _validation_call(
            fixture,
            correction["candidate"],
            correction["candidate_evidence"],
            correction["accuracy_job"],
            correction["accuracy_packet"],
            **provenance,
        )
        self.assertEqual(first, second)
        self.assertNotEqual(
            raw_sha256(canonical_json_bytes(fixture["candidate"].as_dict())),
            raw_sha256(canonical_json_bytes(correction["candidate"].as_dict())),
        )
        _publish_content_verified(self, fixture, first)


if __name__ == "__main__":
    unittest.main()
