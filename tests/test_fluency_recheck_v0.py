from __future__ import annotations

import sys
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.contracts.v0 import (  # noqa: E402
    BranchIdentity,
    ContractViolation,
    canonical_json_bytes,
    display_id,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
)
from locpipe.editorial.v0 import (  # noqa: E402
    EditorialSubmissionReceiptV0,
    editorial_job_root_v0,
    editorial_terminal_artifacts_v0,
    parse_editorial_candidate_v0,
)
from locpipe.fluency.v0 import (  # noqa: E402
    FluencyAdjudicationStatusV0,
    FluencyTargetProjectionRowV0,
    FluencyTargetProjectionV0,
    accept_fluency_adjudication_v0,
    accept_fluency_submission_v0,
    bind_fluency_submission_receipt_v0,
    build_fluency_editorial_correction_v0,
    build_fluency_recheck_job_v0,
    build_fluency_review_job_v0,
    parse_fluency_correction_trigger_v0,
)
from locpipe.translation.v0 import ProviderBudgetV0  # noqa: E402
from tests.test_editorial_acceptance_v0 import editorial_output  # noqa: E402
from tests.test_fluency_adjudication_v0 import (  # noqa: E402
    CORRECT_REASON,
    KEEP_REASON,
    _accept,
    _accuracy_authority,
)
from tests.test_fluency_correction_v0 import (  # noqa: E402
    build_correction,
    correction_fixture,
)


ROUND_ZERO_JOB_SHA = "865ccfce0019522992652fff1738f8a1e09d307d31b6ac2e8bc228917ddd6fc9"
ROUND_ZERO_PACKET_SHA = "1b162beac4105a3a27dbe6e73f950a6add05f2bd223bc663a20d869631d30752"
ROUND_ZERO_TRIGGER_SHA = "85ad6166b1b24bc3ea70ae04f3fdf15753d5c7e29ce0457630901c8c38842c39"
ROUND_ZERO_JOB_ID = "editorial-5826245025eb8c44bc1f8000edf31158"
ROUND_ZERO_INVOCATION_ID = "invocation-36ee38676bbf0e1a79e94dec0b26ad61"


def _resulting_authority(authority):
    fixture, job, packet, _trigger_bytes, _receipt, _raw_output, terminal = authority
    root = editorial_job_root_v0(job)
    terminal_map = dict(terminal)
    candidate = parse_editorial_candidate_v0(terminal_map[f"{root}/candidate_set.json"])
    evidence = tuple(sorted((
        (f"{root}/job.json", canonical_json_bytes(job.as_dict())),
        (f"{root}/packet.json", canonical_json_bytes(packet.as_dict())),
        (f"{root}/parent_candidate.json", canonical_json_bytes(fixture["candidate"].as_dict())),
        (f"{root}/policy.json", canonical_json_bytes(fixture["policy"].as_dict())),
        *terminal,
    )))
    return candidate, evidence


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


def _recheck_authority(actions=(("CORRECT", CORRECT_REASON), ("CORRECT", CORRECT_REASON))):
    authority = _accuracy_authority(tuple(actions))
    fixture, job, packet, trigger_bytes, receipt, raw_output, terminal = authority
    adjudication = _accept(authority)
    candidate, evidence = _resulting_authority(authority)
    all_ids = _target_ids(candidate)
    context_ids = tuple(stable_id for stable_id in all_ids if stable_id not in adjudication.corrected_ids)[:1]
    projection = _projection(candidate, adjudication.corrected_ids, context_ids=context_ids)
    values = (
        fixture["context"], fixture["resolved"], trigger_bytes,
        canonical_json_bytes(adjudication.as_dict()), job, packet, fixture["policy"],
        fixture["candidate"], receipt, raw_output, terminal, evidence, projection,
    )
    return authority, adjudication, candidate, evidence, projection, values


def _build_recheck(values):
    return build_fluency_recheck_job_v0(*values, budget=ProviderBudgetV0(None, None))


def _rebuild_initial_review_with_two_rounds():
    fixture = correction_fixture(findings=False)
    projection = FluencyTargetProjectionV0(
        fixture["plan"].candidate_sha256,
        fixture["plan"].target_locale,
        tuple(FluencyTargetProjectionRowV0(
            row.stable_id, row.role, row.profile_ids, row.group_ids,
            row.relation_ids, row._guidance_bytes,
        ) for row in fixture["fluency_packet"].rows),
    )
    plan, job, packet = build_fluency_review_job_v0(
        fixture["context"], fixture["resolved"], fixture["candidate"], projection,
        candidate_authority_sha256=fixture["plan"].candidate_authority_sha256,
        requested_ids=fixture["plan"].requested_ids,
        budget=ProviderBudgetV0(None, None),
        max_correction_rounds=2,
    )
    reviews = [
        {"stable_id": stable_id, "outcome": "NO_FINDINGS", "findings": []}
        for stable_id in plan.requested_ids
    ]
    reviews[0] = {
        "stable_id": plan.requested_ids[0],
        "outcome": "FINDINGS",
        "findings": [{"category": "READABILITY", "diagnostic_note": "Потрібне точне виправлення."}],
    }
    raw_output = canonical_json_bytes({
        "contract": "locpipe.fluency.provider-output/v0",
        "job_id": job.job_id,
        "invocation_id": job.invocation_id,
        "plan_sha256": plan.digest,
        "packet_sha256": job.packet_sha256,
        "provider": job.provider.as_dict(),
        "output_contract_sha256": job.output_contract_sha256,
        "reviews": reviews,
    })
    receipt = bind_fluency_submission_receipt_v0(
        plan, job, packet, raw_output, provider_request_id="fluency-recheck-two-rounds",
    )
    receipt_bytes = canonical_json_bytes(receipt.as_dict())
    decision, state = accept_fluency_submission_v0(plan, job, packet, receipt_bytes, raw_output)
    fixture.update({
        "plan": plan,
        "fluency_job": job,
        "fluency_packet": packet,
        "receipt_bytes": receipt_bytes,
        "raw_fluency": raw_output,
        "decision": decision,
        "state": state,
    })
    return fixture


def _round_one_correction_inputs():
    fixture = _rebuild_initial_review_with_two_rounds()
    accuracy_job, accuracy_packet, trigger_bytes = build_correction(fixture)
    trigger = parse_fluency_correction_trigger_v0(trigger_bytes)
    source_actions = {trigger.entries[0].source_stable_id: "CORRECT"}
    raw_value = parse_canonical_json(editorial_output(accuracy_job, accuracy_packet, actions=source_actions))
    raw_value["decisions"][0]["reason_code"] = CORRECT_REASON
    raw_accuracy = canonical_json_bytes(raw_value)
    accuracy_receipt = EditorialSubmissionReceiptV0(
        accuracy_job.job_id, accuracy_job.invocation_id, accuracy_job.provider,
        "fluency-recheck-accuracy", accuracy_job.packet_sha256,
        accuracy_job.output_contract_sha256, raw_sha256(raw_accuracy),
    )
    terminal = editorial_terminal_artifacts_v0(
        accuracy_job, accuracy_packet, fixture["policy"], fixture["candidate"],
        accuracy_receipt, raw_accuracy,
    )
    authority = (fixture, accuracy_job, accuracy_packet, trigger_bytes, accuracy_receipt, raw_accuracy, terminal)
    adjudication = accept_fluency_adjudication_v0(
        fixture["resolved"], trigger_bytes, accuracy_job, accuracy_packet,
        fixture["policy"], fixture["candidate"], accuracy_receipt, raw_accuracy, terminal,
    )
    candidate, evidence = _resulting_authority(authority)
    projection = _projection(candidate, adjudication.corrected_ids)
    recheck_plan, recheck_job, recheck_packet = build_fluency_recheck_job_v0(
        fixture["context"], fixture["resolved"], trigger_bytes,
        canonical_json_bytes(adjudication.as_dict()), accuracy_job, accuracy_packet,
        fixture["policy"], fixture["candidate"], accuracy_receipt, raw_accuracy,
        terminal, evidence, projection, budget=ProviderBudgetV0(None, None),
    )
    raw_recheck = canonical_json_bytes({
        "contract": "locpipe.fluency.provider-output/v0",
        "job_id": recheck_job.job_id,
        "invocation_id": recheck_job.invocation_id,
        "plan_sha256": recheck_plan.digest,
        "packet_sha256": recheck_job.packet_sha256,
        "provider": recheck_job.provider.as_dict(),
        "output_contract_sha256": recheck_job.output_contract_sha256,
        "reviews": [{
            "stable_id": recheck_plan.requested_ids[0],
            "outcome": "FINDINGS",
            "findings": [{"category": "VOICE", "diagnostic_note": "Потрібне повторне виправлення."}],
        }],
    })
    recheck_receipt = bind_fluency_submission_receipt_v0(
        recheck_plan, recheck_job, recheck_packet, raw_recheck,
        provider_request_id="fluency-recheck-round-one",
    )
    recheck_receipt_bytes = canonical_json_bytes(recheck_receipt.as_dict())
    recheck_decision, recheck_state = accept_fluency_submission_v0(
        recheck_plan, recheck_job, recheck_packet, recheck_receipt_bytes, raw_recheck,
    )
    return fixture, adjudication, candidate, evidence, accuracy_job, accuracy_packet, (
        recheck_plan, recheck_job, recheck_packet, recheck_receipt_bytes,
        raw_recheck, recheck_decision, recheck_state,
    ), trigger_bytes


def _build_later_correction(values, parent_adjudication_bytes, parent_trigger_bytes):
    fixture, _adjudication, candidate, evidence, accuracy_job, accuracy_packet, recheck, _trigger_bytes = values
    plan, job, packet, receipt_bytes, raw_output, decision, state = recheck
    return build_fluency_editorial_correction_v0(
        fixture["context"], fixture["resolved"], fixture["translation_job"],
        fixture["translation_packet"], fixture["translation_decision_bytes"],
        fixture["translation_state_bytes"], fixture["target_set"], fixture["policy"],
        candidate, evidence, accuracy_job, accuracy_packet, plan, job, packet,
        receipt_bytes, raw_output, decision, state, budget=ProviderBudgetV0(None, None),
        parent_adjudication_bytes=parent_adjudication_bytes,
        parent_trigger_bytes=parent_trigger_bytes,
    )


def _build_initial_correction(fixture, parent_adjudication_bytes=None, parent_trigger_bytes=None):
    return build_fluency_editorial_correction_v0(
        fixture["context"], fixture["resolved"], fixture["translation_job"],
        fixture["translation_packet"], fixture["translation_decision_bytes"],
        fixture["translation_state_bytes"], fixture["target_set"], fixture["policy"],
        fixture["candidate"], fixture["candidate_evidence"], fixture["parent_job"],
        fixture["parent_packet"], fixture["plan"], fixture["fluency_job"],
        fixture["fluency_packet"], fixture["receipt_bytes"], fixture["raw_fluency"],
        fixture["decision"], fixture["state"], budget=ProviderBudgetV0(None, None),
        parent_adjudication_bytes=parent_adjudication_bytes,
        parent_trigger_bytes=parent_trigger_bytes,
    )


def _replace_recheck(
    values,
    *,
    requested_ids: tuple[str, ...] | None = None,
    round_index: int = 1,
    max_correction_rounds: int = 2,
    parent_adjudication=None,
):
    fixture, adjudication, candidate, evidence, accuracy_job, accuracy_packet, _recheck, trigger_bytes = values
    bound_adjudication = parent_adjudication or adjudication
    requested = requested_ids or adjudication.corrected_ids
    projection = _projection(candidate, requested)
    authority_sha = semantic_sha256([
        {"path": path, "sha256": raw_sha256(payload)} for path, payload in evidence
    ])
    plan, job, packet = build_fluency_review_job_v0(
        fixture["context"], fixture["resolved"], candidate, projection,
        candidate_authority_sha256=authority_sha,
        requested_ids=requested,
        budget=ProviderBudgetV0(None, None),
        round_index=round_index,
        max_correction_rounds=max_correction_rounds,
        parent_terminal_sha256=bound_adjudication.digest,
    )
    raw_output = canonical_json_bytes({
        "contract": "locpipe.fluency.provider-output/v0",
        "job_id": job.job_id,
        "invocation_id": job.invocation_id,
        "plan_sha256": plan.digest,
        "packet_sha256": job.packet_sha256,
        "provider": job.provider.as_dict(),
        "output_contract_sha256": job.output_contract_sha256,
        "reviews": [{
            "stable_id": stable_id,
            "outcome": "FINDINGS",
            "findings": [{"category": "VOICE", "diagnostic_note": "Когерентний підроблений recheck."}],
        } for stable_id in requested],
    })
    receipt = bind_fluency_submission_receipt_v0(
        plan, job, packet, raw_output, provider_request_id="fluency-recheck-forged-chain",
    )
    receipt_bytes = canonical_json_bytes(receipt.as_dict())
    decision, state = accept_fluency_submission_v0(plan, job, packet, receipt_bytes, raw_output)
    return (
        fixture, adjudication, candidate, evidence, accuracy_job, accuracy_packet,
        (plan, job, packet, receipt_bytes, raw_output, decision, state), trigger_bytes,
    )


class FluencyRecheckV0Tests(unittest.TestCase):
    def test_exact_corrected_id_recheck_is_deterministic_and_target_only(self) -> None:
        authority, adjudication, candidate, evidence, projection, values = _recheck_authority()
        first = _build_recheck(values)
        second = _build_recheck(values)
        self.assertEqual(first, second)
        plan, _job, packet = first
        self.assertEqual(adjudication.corrected_ids, plan.requested_ids)
        self.assertEqual(adjudication.corrected_ids, packet.requested_ids)
        self.assertEqual(1, plan.round_index)
        self.assertEqual(1, plan.max_correction_rounds)
        self.assertEqual(adjudication.digest, plan.parent_terminal_sha256)
        self.assertEqual(raw_sha256(canonical_json_bytes(candidate.as_dict())), plan.candidate_sha256)
        self.assertEqual(semantic_sha256([
            {"path": path, "sha256": raw_sha256(payload)} for path, payload in evidence
        ]), plan.candidate_authority_sha256)
        self.assertEqual(
            adjudication.corrected_ids,
            tuple(row.stable_id for row in packet.rows if row.role == "REVIEW"),
        )
        self.assertTrue(any(row.role == "CONTEXT" for row in packet.rows))
        candidate_targets = {
            display_id(BranchIdentity.from_dict(value["data"]["identity"])): payload
            for payload in candidate._target_bytes
            for value in (parse_canonical_json(payload),)
        }
        self.assertTrue(all(candidate_targets[row.stable_id] == row._target_bytes for row in packet.rows))
        rendered = canonical_json_bytes(packet.as_dict())
        for forbidden in (b"diagnostic_note", b"correction-trigger", b"editorial_packet"):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(projection.digest, plan.projection_sha256)
        self.assertEqual(authority[1].round_index, parse_fluency_correction_trigger_v0(authority[3]).next_editorial_round)

    def test_wrong_adjudication_status_and_authority_drift_fail_closed(self) -> None:
        _authority, adjudication, _candidate, evidence, _projection_value, values = _recheck_authority()
        keep_authority = _accuracy_authority((("KEEP", KEEP_REASON),))
        keep_adjudication = _accept(keep_authority)
        forged = replace(adjudication, resulting_candidate_sha256="0" * 64)
        cases = (
            (*values[:3], canonical_json_bytes(keep_adjudication.as_dict()), *values[4:]),
            (*values[:3], canonical_json_bytes(forged.as_dict()), *values[4:]),
            (*values[:11], evidence[:-1], *values[12:]),
            (*values[:10], tuple((*values[10][:-1], (values[10][-1][0], values[10][-1][1] + b" "))), *values[11:]),
        )
        for changed in cases:
            with self.subTest(), self.assertRaises(ContractViolation):
                _build_recheck(changed)

    def test_projection_widening_shrinking_duplicate_locale_and_row_drift_fail_closed(self) -> None:
        _authority, adjudication, candidate, _evidence, projection, values = _recheck_authority()
        all_ids = _target_ids(candidate)
        foreign = next(stable_id for stable_id in all_ids if stable_id not in adjudication.corrected_ids)
        widened = _projection(candidate, tuple(sorted((*adjudication.corrected_ids, foreign))))
        shrunk = _projection(candidate, adjudication.corrected_ids[:1], context_ids=adjudication.corrected_ids[1:])
        cases = (
            replace(projection, candidate_sha256="0" * 64),
            replace(projection, target_locale="zz"),
            widened,
            shrunk,
            FluencyTargetProjectionV0(
                projection.candidate_sha256, projection.target_locale,
                tuple(sorted((*projection.rows, FluencyTargetProjectionRowV0(
                    "foreign|uk|[]", "CONTEXT", (), (), (), (),
                )), key=lambda row: row.stable_id)),
            ),
        )
        for changed_projection in cases:
            with self.subTest(), self.assertRaises(ContractViolation):
                _build_recheck((*values[:-1], changed_projection))
        with self.assertRaises(ContractViolation):
            FluencyTargetProjectionV0(
                projection.candidate_sha256, projection.target_locale,
                tuple(sorted((*projection.rows, projection.rows[0]), key=lambda row: row.stable_id)),
            )

    def test_round_zero_bytes_and_behavior_are_unchanged(self) -> None:
        fixture = correction_fixture()
        job, packet, trigger_bytes = build_correction(fixture)
        self.assertEqual(ROUND_ZERO_JOB_SHA, raw_sha256(canonical_json_bytes(job.as_dict())))
        self.assertEqual(ROUND_ZERO_PACKET_SHA, raw_sha256(canonical_json_bytes(packet.as_dict())))
        self.assertEqual(ROUND_ZERO_TRIGGER_SHA, raw_sha256(trigger_bytes))
        self.assertEqual(ROUND_ZERO_JOB_ID, job.job_id)
        self.assertEqual(ROUND_ZERO_INVOCATION_ID, job.invocation_id)
        for parent_adjudication, parent_trigger in (
            (b"{}", None),
            (None, b"{}"),
            (b"{}", b"{}"),
        ):
            with self.subTest(), self.assertRaises(ContractViolation):
                _build_initial_correction(fixture, parent_adjudication, parent_trigger)

    def test_later_round_requires_exact_parent_adjudication(self) -> None:
        values = _round_one_correction_inputs()
        adjudication_bytes = canonical_json_bytes(values[1].as_dict())
        parent_trigger_bytes = values[7]
        job, packet, trigger_bytes = _build_later_correction(
            values, adjudication_bytes, parent_trigger_bytes,
        )
        trigger = parse_fluency_correction_trigger_v0(trigger_bytes)
        self.assertEqual(2, job.round_index)
        self.assertEqual(1, trigger.current_fluency_round)
        self.assertEqual(2, trigger.next_editorial_round)
        self.assertEqual(values[1].digest, values[6][0].parent_terminal_sha256)
        self.assertEqual(packet.requested_ids, trigger.requested_source_ids)
        foreign_trigger = canonical_json_bytes(replace(
            parse_fluency_correction_trigger_v0(parent_trigger_bytes),
            content_config_digest="0" * 64,
        ).as_dict())
        for parent_adjudication, parent_trigger in (
            (None, parent_trigger_bytes),
            (adjudication_bytes, None),
            (adjudication_bytes, parent_trigger_bytes + b" "),
            (adjudication_bytes, foreign_trigger),
            (canonical_json_bytes(_accept(_accuracy_authority((("KEEP", KEEP_REASON),))).as_dict()), parent_trigger_bytes),
        ):
            with self.subTest(), self.assertRaises(ContractViolation):
                _build_later_correction(values, parent_adjudication, parent_trigger)

    def test_parent_chain_rejects_coherent_requested_id_and_round_policy_bypass(self) -> None:
        values = _round_one_correction_inputs()
        adjudication = values[1]
        adjudication_bytes = canonical_json_bytes(adjudication.as_dict())
        parent_trigger_bytes = values[7]
        extra_id = next(
            stable_id for stable_id in _target_ids(values[2])
            if stable_id not in adjudication.corrected_ids
        )
        widened = _replace_recheck(
            values,
            requested_ids=tuple(sorted((*adjudication.corrected_ids, extra_id))),
        )
        drifted_round = _replace_recheck(values, round_index=2, max_correction_rounds=2)
        forged_adjudication = replace(adjudication, trigger_sha256="0" * 64)
        forged_hash_chain = _replace_recheck(values, parent_adjudication=forged_adjudication)
        cases = (
            (widened, adjudication_bytes),
            (drifted_round, adjudication_bytes),
            (forged_hash_chain, canonical_json_bytes(forged_adjudication.as_dict())),
        )
        for changed_values, changed_adjudication_bytes in cases:
            with self.subTest(), self.assertRaises(ContractViolation):
                _build_later_correction(
                    changed_values, changed_adjudication_bytes, parent_trigger_bytes,
                )

    def test_builder_has_no_provider_terminal_or_filesystem_side_effects(self) -> None:
        _authority, _adjudication, _candidate, _evidence, _projection_value, values = _recheck_authority()
        before = deepcopy(values)
        plan, job, packet = _build_recheck(values)
        self.assertEqual(before, values)
        rendered = canonical_json_bytes({
            "plan": plan.as_dict(), "job": job.as_dict(), "packet": packet.as_dict(),
        })
        self.assertNotIn(b"provider-output", rendered)
        self.assertNotIn(b"publication", rendered)


if __name__ == "__main__":
    unittest.main()
