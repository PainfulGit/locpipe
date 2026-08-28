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
    ContractViolation,
    canonical_json_bytes,
    parse_canonical_json,
    raw_sha256,
)
from locpipe.editorial.v0 import (  # noqa: E402
    EditorialActionV0,
    EditorialSubmissionReceiptV0,
    editorial_terminal_artifacts_v0,
)
from locpipe.fluency.v0 import (  # noqa: E402
    FluencyAdjudicationStatusV0,
    accept_fluency_adjudication_v0,
    accept_fluency_submission_v0,
    bind_fluency_submission_receipt_v0,
    parse_fluency_adjudication_v0,
    parse_fluency_correction_trigger_v0,
)
from tests.test_editorial_acceptance_v0 import editorial_output  # noqa: E402
from tests.test_fluency_correction_v0 import build_correction, correction_fixture  # noqa: E402


KEEP_REASON = "FLUENCY_DISMISSED_FALSE_POSITIVE"
CORRECT_REASON = "FLUENCY_FINDING_FIXED"


def _correction_authority(*, finding_count: int = 2):
    fixture = correction_fixture(findings=False)
    reviews = [
        {"stable_id": stable_id, "outcome": "NO_FINDINGS", "findings": []}
        for stable_id in fixture["plan"].requested_ids
    ]
    if len(reviews) < finding_count:
        raise AssertionError("Synthetic fixture does not contain enough review rows")
    for index in range(finding_count):
        reviews[index] = {
            "stable_id": reviews[index]["stable_id"],
            "outcome": "FINDINGS",
            "findings": [{
                "category": "READABILITY" if index == 0 else "VOICE",
                "diagnostic_note": f"Діагностичне пояснення {index + 1}.",
            }],
        }
    raw_fluency = canonical_json_bytes({
        "contract": "locpipe.fluency.provider-output/v0",
        "job_id": fixture["fluency_job"].job_id,
        "invocation_id": fixture["fluency_job"].invocation_id,
        "plan_sha256": fixture["plan"].digest,
        "packet_sha256": fixture["fluency_job"].packet_sha256,
        "provider": fixture["fluency_job"].provider.as_dict(),
        "output_contract_sha256": fixture["fluency_job"].output_contract_sha256,
        "reviews": reviews,
    })
    fluency_receipt = bind_fluency_submission_receipt_v0(
        fixture["plan"], fixture["fluency_job"], fixture["fluency_packet"],
        raw_fluency, provider_request_id="fluency-adjudication",
    )
    receipt_bytes = canonical_json_bytes(fluency_receipt.as_dict())
    decision, state = accept_fluency_submission_v0(
        fixture["plan"], fixture["fluency_job"], fixture["fluency_packet"],
        receipt_bytes, raw_fluency,
    )
    fixture.update({
        "receipt_bytes": receipt_bytes,
        "raw_fluency": raw_fluency,
        "decision": decision,
        "state": state,
    })
    job, packet, trigger_bytes = build_correction(fixture)
    return fixture, job, packet, trigger_bytes


def _accuracy_authority(actions: tuple[tuple[str, str], ...]):
    fixture, job, packet, trigger_bytes = _correction_authority(finding_count=len(actions))
    trigger = parse_fluency_correction_trigger_v0(trigger_bytes)
    source_actions = {
        entry.source_stable_id: action
        for entry, (action, _reason) in zip(trigger.entries, actions)
    }
    reasons = {
        entry.source_stable_id: reason
        for entry, (_action, reason) in zip(trigger.entries, actions)
    }
    raw_value = parse_canonical_json(editorial_output(job, packet, actions=source_actions))
    for row in raw_value["decisions"]:
        from locpipe.contracts.v0 import BranchIdentity, display_id
        source_id = display_id(BranchIdentity.from_dict(row["identity"]))
        row["reason_code"] = reasons[source_id]
    raw_output = canonical_json_bytes(raw_value)
    receipt = EditorialSubmissionReceiptV0(
        job.job_id,
        job.invocation_id,
        job.provider,
        "fluency-adjudication-accuracy",
        job.packet_sha256,
        job.output_contract_sha256,
        raw_sha256(raw_output),
    )
    terminal = editorial_terminal_artifacts_v0(
        job, packet, fixture["policy"], fixture["candidate"], receipt, raw_output,
    )
    return fixture, job, packet, trigger_bytes, receipt, raw_output, terminal


def _accept(authority):
    fixture, job, packet, trigger_bytes, receipt, raw_output, terminal = authority
    return accept_fluency_adjudication_v0(
        fixture["resolved"], trigger_bytes, job, packet, fixture["policy"],
        fixture["candidate"], receipt, raw_output, terminal,
    )


class FluencyAdjudicationV0Tests(unittest.TestCase):
    def test_keep_all_is_deterministic_and_nonterminal(self) -> None:
        authority = _accuracy_authority((("KEEP", KEEP_REASON), ("KEEP", KEEP_REASON)))
        first = _accept(authority)
        second = _accept(authority)
        self.assertEqual(first, second)
        self.assertEqual(FluencyAdjudicationStatusV0.DISMISSALS_ONLY, first.status)
        self.assertEqual(tuple(row.target_stable_id for row in first.entries), first.keep_ids)
        self.assertEqual((), first.corrected_ids)
        self.assertTrue(all(row.overlay_entry_sha256 is None for row in first.entries))
        self.assertNotIn(b"diagnostic_note", canonical_json_bytes(first.as_dict()))

    def test_correct_all_is_exactly_overlay_and_changed_targets(self) -> None:
        authority = _accuracy_authority((("CORRECT", CORRECT_REASON), ("CORRECT", CORRECT_REASON)))
        adjudication = _accept(authority)
        self.assertEqual(FluencyAdjudicationStatusV0.CORRECTIONS_READY_FOR_RECHECK, adjudication.status)
        self.assertEqual((), adjudication.keep_ids)
        self.assertEqual(tuple(row.target_stable_id for row in adjudication.entries), adjudication.corrected_ids)
        self.assertTrue(all(row.overlay_entry_sha256 is not None for row in adjudication.entries))

    def test_mixed_actions_preserve_exact_source_to_target_mapping(self) -> None:
        authority = _accuracy_authority((("KEEP", KEEP_REASON), ("CORRECT", CORRECT_REASON)))
        adjudication = _accept(authority)
        trigger = parse_fluency_correction_trigger_v0(authority[3])
        self.assertEqual(
            tuple((row.target_stable_id, row.source_stable_id) for row in trigger.entries),
            tuple((row.target_stable_id, row.source_stable_id) for row in adjudication.entries),
        )
        self.assertNotEqual(adjudication.entries[0].target_stable_id, adjudication.entries[0].source_stable_id)
        self.assertEqual((adjudication.entries[0].target_stable_id,), adjudication.keep_ids)
        self.assertEqual((adjudication.entries[1].target_stable_id,), adjudication.corrected_ids)

    def test_invalid_reason_and_rework_fail_closed(self) -> None:
        for actions in (
            (("KEEP", "EDITOR_REVIEW"),),
            (("CORRECT", "EDITOR_REVIEW"),),
            (("REWORK_REQUIRED", "FLUENCY_DISMISSED_FALSE_POSITIVE"),),
        ):
            with self.subTest(actions=actions):
                with self.assertRaises(ContractViolation):
                    _accept(_accuracy_authority(actions))

    def test_missing_extra_and_duplicate_decisions_fail_closed(self) -> None:
        authority = list(_accuracy_authority((("KEEP", KEEP_REASON), ("KEEP", KEEP_REASON))))
        for mutation in ("missing", "extra", "duplicate"):
            value = deepcopy(parse_canonical_json(authority[5]))
            if mutation == "missing":
                value["decisions"].pop()
            elif mutation == "extra":
                extra = deepcopy(value["decisions"][-1])
                extra["identity"]["logical_id"][-1] = "foreign"
                value["decisions"].append(extra)
            else:
                value["decisions"].append(deepcopy(value["decisions"][-1]))
            raw_output = canonical_json_bytes(value)
            receipt = replace(authority[4], raw_output_sha256=raw_sha256(raw_output))
            terminal = editorial_terminal_artifacts_v0(
                authority[1], authority[2], authority[0]["policy"],
                authority[0]["candidate"], receipt, raw_output,
            )
            changed = (*authority[:4], receipt, raw_output, terminal)
            with self.subTest(mutation=mutation), self.assertRaises(ContractViolation):
                _accept(changed)

    def test_terminal_missing_extra_and_byte_drift_fail_closed(self) -> None:
        authority = list(_accuracy_authority((("KEEP", KEEP_REASON),)))
        terminal = list(authority[6])
        mutations = (
            tuple(terminal[:-1]),
            tuple((*terminal, ("foreign.json", b"{}"))),
            tuple((path, payload + b" ") if index == 0 else (path, payload) for index, (path, payload) in enumerate(terminal)),
        )
        for changed_terminal in mutations:
            changed = (*authority[:6], changed_terminal)
            with self.subTest(size=len(changed_terminal)), self.assertRaises(ContractViolation):
                _accept(changed)

    def test_stale_trigger_job_packet_receipt_and_raw_output_fail_closed(self) -> None:
        authority = list(_accuracy_authority((("KEEP", KEEP_REASON),)))
        trigger_value = parse_canonical_json(authority[3])
        trigger_value["candidate_authority_sha256"] = "0" * 64
        cases = (
            (*authority[:3], canonical_json_bytes(trigger_value), *authority[4:]),
            (authority[0], replace(authority[1], provider=replace(authority[1].provider, provider_id="foreign")), *authority[2:]),
            (*authority[:4], replace(authority[4], raw_output_sha256="0" * 64), *authority[5:]),
            (*authority[:5], authority[5] + b" ", authority[6]),
        )
        for changed in cases:
            with self.subTest(), self.assertRaises(ContractViolation):
                _accept(changed)

    def test_parser_is_strict_and_caller_mutation_cannot_change_artifact(self) -> None:
        authority = list(_accuracy_authority((("KEEP", KEEP_REASON),)))
        terminal_list = list(authority[6])
        authority[6] = terminal_list
        adjudication = _accept(authority)
        digest = adjudication.digest
        terminal_list.clear()
        self.assertEqual(digest, adjudication.digest)
        payload = canonical_json_bytes(adjudication.as_dict())
        self.assertEqual(adjudication, parse_fluency_adjudication_v0(payload))
        with self.assertRaises(ContractViolation):
            parse_fluency_adjudication_v0(payload + b" ")
        unknown = parse_canonical_json(payload)
        unknown["unexpected"] = True
        with self.assertRaises(ContractViolation):
            parse_fluency_adjudication_v0(canonical_json_bytes(unknown))

    def test_adjudication_has_no_next_lifecycle_or_payload_authority(self) -> None:
        adjudication = _accept(_accuracy_authority((("CORRECT", CORRECT_REASON),)))
        rendered = canonical_json_bytes(adjudication.as_dict())
        for forbidden in (b"replacement", b"diagnostic_note", b"recheck", b"terminal", b"publication"):
            self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":
    unittest.main()
