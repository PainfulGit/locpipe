from __future__ import annotations

from dataclasses import replace
import inspect
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from locpipe.contracts.v0 import ContractViolation, canonical_json_bytes, parse_canonical_json  # noqa: E402
from locpipe.fluency.v0 import (  # noqa: E402
    FluencyDecisionEntryV0,
    FluencyDecisionStatusV0,
    FluencyFindingCategoryV0,
    FluencyFindingV0,
    FluencyReviewOutcomeV0,
    MAX_DIAGNOSTIC_NOTE_CODEPOINTS,
    accept_fluency_submission_v0,
    bind_fluency_submission_receipt_v0,
    build_fluency_review_job_v0,
    fluency_submission_digest_v0,
)
from locpipe.translation.v0 import ProviderBudgetV0  # noqa: E402
from test_fluency_packet_v0 import SHA_C, fixture  # noqa: E402


OTHER_SHA = "d" * 64


def authority():
    context, resolved, candidate, projection, requested = fixture()
    plan, job, packet = build_fluency_review_job_v0(
        context,
        resolved,
        candidate,
        projection,
        candidate_authority_sha256=SHA_C,
        requested_ids=requested,
        budget=ProviderBudgetV0(None, None),
    )
    return plan, job, packet


def clear_reviews(plan):
    return [
        {"stable_id": stable_id, "outcome": "NO_FINDINGS", "findings": []}
        for stable_id in plan.requested_ids
    ]


def provider_output(plan, job, reviews=None, **changes):
    value = {
        "contract": "locpipe.fluency.provider-output/v0",
        "job_id": job.job_id,
        "invocation_id": job.invocation_id,
        "plan_sha256": plan.digest,
        "packet_sha256": job.packet_sha256,
        "provider": job.provider.as_dict(),
        "output_contract_sha256": job.output_contract_sha256,
        "reviews": clear_reviews(plan) if reviews is None else reviews,
    }
    value.update(changes)
    return canonical_json_bytes(value)


def receipt_bytes(plan, job, packet, raw_output):
    receipt = bind_fluency_submission_receipt_v0(
        plan, job, packet, raw_output, provider_request_id="provider-request-1",
    )
    return receipt, canonical_json_bytes(receipt.as_dict())


class FluencyAcceptanceV0Tests(unittest.TestCase):
    def test_deterministic_all_clear_acceptance(self) -> None:
        plan, job, packet = authority()
        raw = provider_output(plan, job)
        receipt, rendered_receipt = receipt_bytes(plan, job, packet, raw)
        first = accept_fluency_submission_v0(plan, job, packet, rendered_receipt, raw)
        second = accept_fluency_submission_v0(plan, job, packet, rendered_receipt, raw)
        self.assertEqual(first, second)
        decision, state = first
        self.assertIs(decision.status, FluencyDecisionStatusV0.FLUENCY_VERIFIED)
        self.assertIs(state.status, FluencyDecisionStatusV0.FLUENCY_VERIFIED)
        self.assertEqual((), decision.correction_ids)
        self.assertEqual(plan.requested_ids, tuple(row.stable_id for row in decision.entries))
        self.assertEqual(fluency_submission_digest_v0(receipt), decision.submission_sha256)
        self.assertEqual(decision.digest, state.decision_sha256)

    def test_findings_are_actionable_evidence_without_target_mutation(self) -> None:
        plan, job, packet = authority()
        packet_before = canonical_json_bytes(packet.as_dict())
        notes = ("Граматична форма не узгоджується.", "Речення потребує чіткішого узгодження.")
        reviews = clear_reviews(plan)
        reviews[0] = {
            "stable_id": plan.requested_ids[0],
            "outcome": "FINDINGS",
            "findings": [
                {"category": "GRAMMAR", "diagnostic_note": note}
                for note in sorted(notes)
            ],
        }
        raw = provider_output(plan, job, reviews)
        _receipt, rendered_receipt = receipt_bytes(plan, job, packet, raw)
        decision, state = accept_fluency_submission_v0(plan, job, packet, rendered_receipt, raw)
        self.assertIs(decision.status, FluencyDecisionStatusV0.CORRECTION_REQUIRED)
        self.assertIs(state.status, FluencyDecisionStatusV0.CORRECTION_REQUIRED)
        self.assertEqual((plan.requested_ids[0],), decision.correction_ids)
        self.assertEqual(notes, tuple(row.diagnostic_note for row in decision.entries[0].findings))
        self.assertEqual(packet_before, canonical_json_bytes(packet.as_dict()))
        for note in notes:
            self.assertNotIn(note.encode("utf-8"), packet_before)

    def test_exact_coverage_missing_extra_duplicate_and_unsorted_fail(self) -> None:
        plan, job, packet = authority()
        base = clear_reviews(plan)
        variants = {
            "missing": base[:-1],
            "extra": [*base, {"stable_id": "foreign-id", "outcome": "NO_FINDINGS", "findings": []}],
            "duplicate": [base[0], *base],
            "unsorted": list(reversed(base)),
        }
        for name, reviews in variants.items():
            with self.subTest(name=name), self.assertRaises(ContractViolation):
                bind_fluency_submission_receipt_v0(
                    plan, job, packet, provider_output(plan, job, reviews),
                    provider_request_id="request",
                )

    def test_outcome_and_finding_cardinality_fail_closed(self) -> None:
        plan, job, packet = authority()
        finding = {"category": "STYLE", "diagnostic_note": "Стиль потребує перегляду."}
        bad_rows = (
            {"stable_id": plan.requested_ids[0], "outcome": "FINDINGS", "findings": []},
            {"stable_id": plan.requested_ids[0], "outcome": "NO_FINDINGS", "findings": [finding]},
        )
        for row in bad_rows:
            reviews = clear_reviews(plan)
            reviews[0] = row
            with self.assertRaises(ContractViolation):
                bind_fluency_submission_receipt_v0(
                    plan, job, packet, provider_output(plan, job, reviews),
                    provider_request_id="request",
                )

    def test_duplicate_finding_rejected_same_category_distinct_notes_allowed(self) -> None:
        plan, job, packet = authority()
        finding = {"category": "READABILITY", "diagnostic_note": "Абзац читається надто важко."}
        reviews = clear_reviews(plan)
        reviews[0] = {
            "stable_id": plan.requested_ids[0], "outcome": "FINDINGS",
            "findings": [finding, dict(finding)],
        }
        with self.assertRaises(ContractViolation):
            bind_fluency_submission_receipt_v0(
                plan, job, packet, provider_output(plan, job, reviews),
                provider_request_id="request",
            )

    def test_unknown_fields_category_outcome_and_status_fail_closed(self) -> None:
        plan, job, packet = authority()
        finding = {"category": "STYLE", "diagnostic_note": "Стиль потребує перегляду."}
        cases = []
        top = parse_canonical_json(provider_output(plan, job))
        top["status"] = "FLUENCY_VERIFIED"
        cases.append(top)
        review_extra = parse_canonical_json(provider_output(plan, job))
        review_extra["reviews"][0]["extra"] = True
        cases.append(review_extra)
        finding_extra = parse_canonical_json(provider_output(plan, job))
        finding_extra["reviews"][0] = {
            "stable_id": plan.requested_ids[0], "outcome": "FINDINGS",
            "findings": [{**finding, "severity": "HIGH"}],
        }
        cases.append(finding_extra)
        unknown_category = parse_canonical_json(provider_output(plan, job))
        unknown_category["reviews"][0] = {
            "stable_id": plan.requested_ids[0], "outcome": "FINDINGS",
            "findings": [{"category": "OTHER", "diagnostic_note": "Інша проблема."}],
        }
        cases.append(unknown_category)
        unknown_outcome = parse_canonical_json(provider_output(plan, job))
        unknown_outcome["reviews"][0]["outcome"] = "KEEP"
        cases.append(unknown_outcome)
        for index, value in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ContractViolation):
                bind_fluency_submission_receipt_v0(
                    plan, job, packet, canonical_json_bytes(value), provider_request_id="request",
                )

    def test_invalid_diagnostic_notes_fail_closed(self) -> None:
        plan, job, packet = authority()
        notes = (
            "",
            "а" * (MAX_DIAGNOSTIC_NOTE_CODEPOINTS + 1),
            "e\u0301",
            "перший\nдругий",
            "керування\x00символом",
            " крайній пробіл",
            "крайній пробіл ",
        )
        for note in notes:
            reviews = clear_reviews(plan)
            reviews[0] = {
                "stable_id": plan.requested_ids[0], "outcome": "FINDINGS",
                "findings": [{"category": "GRAMMAR", "diagnostic_note": note}],
            }
            with self.subTest(note=repr(note)), self.assertRaises(ContractViolation):
                bind_fluency_submission_receipt_v0(
                    plan, job, packet, provider_output(plan, job, reviews),
                    provider_request_id="request",
                )

    def test_forbidden_replacement_suggestion_and_source_quote_fields_fail(self) -> None:
        plan, job, packet = authority()
        for field in ("replacement", "suggestion", "source_quote", "target_copy"):
            reviews = clear_reviews(plan)
            reviews[0] = {
                "stable_id": plan.requested_ids[0], "outcome": "FINDINGS",
                "findings": [{
                    "category": "VOICE",
                    "diagnostic_note": "Голос персонажа неузгоджений.",
                    field: "forbidden",
                }],
            }
            with self.subTest(field=field), self.assertRaises(ContractViolation):
                bind_fluency_submission_receipt_v0(
                    plan, job, packet, provider_output(plan, job, reviews),
                    provider_request_id="request",
                )

    def test_provider_output_identity_and_authority_drift_fail_closed(self) -> None:
        plan, job, packet = authority()
        mutations = {
            "job_id": "foreign-job",
            "invocation_id": "foreign-invocation",
            "plan_sha256": OTHER_SHA,
            "packet_sha256": OTHER_SHA,
            "output_contract_sha256": OTHER_SHA,
            "provider": {**job.provider.as_dict(), "config_digest": OTHER_SHA},
        }
        for field, value in mutations.items():
            with self.subTest(field=field), self.assertRaises(ContractViolation):
                bind_fluency_submission_receipt_v0(
                    plan, job, packet, provider_output(plan, job, **{field: value}),
                    provider_request_id="request",
                )
        stale_plan = replace(plan, candidate_sha256=OTHER_SHA)
        with self.assertRaises(ContractViolation):
            bind_fluency_submission_receipt_v0(
                stale_plan, job, packet, provider_output(plan, job), provider_request_id="request",
            )
        forged_plan = replace(
            plan,
            accuracy_role_contract_sha256=OTHER_SHA,
            fluency_role_contract_sha256=OTHER_SHA,
            output_contract_sha256=OTHER_SHA,
        )
        forged_job = replace(
            job,
            plan_sha256=forged_plan.digest,
            role_contract_sha256=OTHER_SHA,
            output_contract_sha256=OTHER_SHA,
        )
        with self.assertRaises(ContractViolation):
            bind_fluency_submission_receipt_v0(
                forged_plan,
                forged_job,
                packet,
                provider_output(forged_plan, forged_job),
                provider_request_id="request",
            )

    def test_forged_receipt_raw_drift_and_noncanonical_bytes_fail_closed(self) -> None:
        plan, job, packet = authority()
        raw = provider_output(plan, job)
        receipt, rendered = receipt_bytes(plan, job, packet, raw)
        forged = receipt.as_dict()
        forged["role_contract_sha256"] = OTHER_SHA
        with self.assertRaises(ContractViolation):
            accept_fluency_submission_v0(plan, job, packet, canonical_json_bytes(forged), raw)
        changed = parse_canonical_json(raw)
        changed["reviews"][0]["outcome"] = "FINDINGS"
        changed["reviews"][0]["findings"] = [{
            "category": "TYPOGRAPHY", "diagnostic_note": "Пунктуація потребує перегляду.",
        }]
        with self.assertRaises(ContractViolation):
            accept_fluency_submission_v0(plan, job, packet, rendered, canonical_json_bytes(changed))
        with self.assertRaises(ContractViolation):
            accept_fluency_submission_v0(plan, job, packet, rendered[:-1], raw)
        with self.assertRaises(ContractViolation):
            bind_fluency_submission_receipt_v0(
                plan, job, packet, raw[:-1], provider_request_id="request",
            )

    def test_valid_json_with_noncanonical_whitespace_fails_both_apis(self) -> None:
        plan, job, packet = authority()
        canonical_raw = provider_output(plan, job)
        value = parse_canonical_json(canonical_raw)
        noncanonical_raw = json.dumps(
            value, ensure_ascii=False, separators=(", ", ": "), sort_keys=True,
        ).encode("utf-8") + b"\n"
        self.assertNotEqual(canonical_raw, noncanonical_raw)
        with self.assertRaises(ContractViolation):
            bind_fluency_submission_receipt_v0(
                plan, job, packet, noncanonical_raw, provider_request_id="request",
            )
        _receipt, rendered = receipt_bytes(plan, job, packet, canonical_raw)
        with self.assertRaises(ContractViolation):
            accept_fluency_submission_v0(plan, job, packet, rendered, noncanonical_raw)

    def test_caller_collection_mutation_cannot_change_models(self) -> None:
        findings = [FluencyFindingV0(FluencyFindingCategoryV0.STYLE, "Стиль потребує перегляду.")]
        entry = FluencyDecisionEntryV0(
            "stable-id", FluencyReviewOutcomeV0.FINDINGS, tuple(findings),
        )
        findings.clear()
        self.assertEqual(1, len(entry.findings))
        self.assertEqual("Стиль потребує перегляду.", entry.findings[0].diagnostic_note)

    def test_acceptance_surface_has_no_publication_or_correction_side_effects(self) -> None:
        plan, job, packet = authority()
        raw = provider_output(plan, job)
        _receipt, rendered = receipt_bytes(plan, job, packet, raw)
        signature = inspect.signature(accept_fluency_submission_v0)
        self.assertNotIn("root", signature.parameters)
        self.assertNotIn("path", signature.parameters)
        decision, _state = accept_fluency_submission_v0(plan, job, packet, rendered, raw)
        rendered_decision = canonical_json_bytes(decision.as_dict())
        for forbidden in (b"replacement", b"editorial_job", b"validation", b"publication"):
            self.assertNotIn(forbidden, rendered_decision)


if __name__ == "__main__":
    unittest.main()
