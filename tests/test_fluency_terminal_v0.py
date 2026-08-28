from __future__ import annotations

import inspect
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
    EditorialSubmissionReceiptV0,
    editorial_terminal_artifacts_v0,
)
from locpipe.fluency.v0 import (  # noqa: E402
    FluencyCorrectionTerminalStatusV0,
    accept_fluency_adjudication_v0,
    accept_fluency_submission_v0,
    bind_fluency_correction_terminal_v0,
    bind_fluency_submission_receipt_v0,
    build_fluency_recheck_job_v0,
    parse_fluency_correction_terminal_v0,
    parse_fluency_correction_trigger_v0,
)
from locpipe.fluency.v0._terminal import (  # noqa: E402
    _COMMON_CORRECTION_ROLES,
    _RECHECK_ROLES,
    _closed_correction_chain_root_v0,
)
from locpipe.translation.v0 import ProviderBudgetV0  # noqa: E402
from tests.test_editorial_acceptance_v0 import editorial_output  # noqa: E402
from tests.test_fluency_adjudication_v0 import (  # noqa: E402
    CORRECT_REASON,
    KEEP_REASON,
    _accept,
    _accuracy_authority,
)
from tests.test_fluency_correction_v0 import build_correction  # noqa: E402
from tests.test_fluency_recheck_v0 import (  # noqa: E402
    _projection,
    _rebuild_initial_review_with_two_rounds,
    _resulting_authority,
)


def _accuracy_authority_for_rounds(max_rounds: int):
    if max_rounds == 1:
        return _accuracy_authority((("CORRECT", CORRECT_REASON), ("CORRECT", CORRECT_REASON)))
    fixture = _rebuild_initial_review_with_two_rounds()
    job, packet, trigger_bytes = build_correction(fixture)
    trigger = parse_fluency_correction_trigger_v0(trigger_bytes)
    actions = {entry.source_stable_id: "CORRECT" for entry in trigger.entries}
    raw_value = parse_canonical_json(editorial_output(job, packet, actions=actions))
    for row in raw_value["decisions"]:
        row["reason_code"] = CORRECT_REASON
    raw_output = canonical_json_bytes(raw_value)
    receipt = EditorialSubmissionReceiptV0(
        job.job_id,
        job.invocation_id,
        job.provider,
        "fluency-terminal-accuracy-two-rounds",
        job.packet_sha256,
        job.output_contract_sha256,
        raw_sha256(raw_output),
    )
    terminal = editorial_terminal_artifacts_v0(
        job,
        packet,
        fixture["policy"],
        fixture["candidate"],
        receipt,
        raw_output,
    )
    return fixture, job, packet, trigger_bytes, receipt, raw_output, terminal


def _common_inputs(authority):
    fixture, job, packet, trigger_bytes, receipt, raw_output, terminal = authority
    adjudication = _accept(authority)
    _candidate, evidence = _resulting_authority(authority)
    return (
        fixture["context"],
        fixture["resolved"],
        trigger_bytes,
        canonical_json_bytes(adjudication.as_dict()),
        job,
        packet,
        fixture["policy"],
        fixture["candidate"],
        receipt,
        raw_output,
        terminal,
        evidence,
    ), adjudication


def _recheck_inputs(*, outcome: str, max_rounds: int = 1):
    authority = _accuracy_authority_for_rounds(max_rounds)
    common, adjudication = _common_inputs(authority)
    fixture, job, packet, trigger_bytes, receipt, raw_output, terminal = authority
    candidate, evidence = _resulting_authority(authority)
    projection = _projection(candidate, adjudication.corrected_ids)
    budget = ProviderBudgetV0(None, None)
    plan, recheck_job, recheck_packet = build_fluency_recheck_job_v0(
        fixture["context"],
        fixture["resolved"],
        trigger_bytes,
        canonical_json_bytes(adjudication.as_dict()),
        job,
        packet,
        fixture["policy"],
        fixture["candidate"],
        receipt,
        raw_output,
        terminal,
        evidence,
        projection,
        budget=budget,
    )
    findings = (
        []
        if outcome == "NO_FINDINGS"
        else [{"category": "VOICE", "diagnostic_note": "Після виправлення лишилося зауваження."}]
    )
    raw_recheck = canonical_json_bytes({
        "contract": "locpipe.fluency.provider-output/v0",
        "job_id": recheck_job.job_id,
        "invocation_id": recheck_job.invocation_id,
        "plan_sha256": plan.digest,
        "packet_sha256": recheck_job.packet_sha256,
        "provider": recheck_job.provider.as_dict(),
        "output_contract_sha256": recheck_job.output_contract_sha256,
        "reviews": [
            {"stable_id": stable_id, "outcome": outcome, "findings": findings}
            for stable_id in plan.requested_ids
        ],
    })
    receipt_model = bind_fluency_submission_receipt_v0(
        plan,
        recheck_job,
        recheck_packet,
        raw_recheck,
        provider_request_id=f"fluency-terminal-{outcome.lower()}-{max_rounds}",
    )
    receipt_bytes = canonical_json_bytes(receipt_model.as_dict())
    decision, state = accept_fluency_submission_v0(
        plan,
        recheck_job,
        recheck_packet,
        receipt_bytes,
        raw_recheck,
    )
    kwargs = {
        "recheck_projection": projection,
        "recheck_budget": budget,
        "recheck_plan": plan,
        "recheck_job": recheck_job,
        "recheck_packet": recheck_packet,
        "recheck_receipt_bytes": receipt_bytes,
        "recheck_raw_output": raw_recheck,
        "recheck_decision": decision,
        "recheck_state": state,
    }
    return common, kwargs, adjudication


class FluencyCorrectionTerminalV0Tests(unittest.TestCase):
    def test_dismissals_are_deterministic_and_correction_only(self) -> None:
        common, adjudication = _common_inputs(
            _accuracy_authority((("KEEP", KEEP_REASON), ("KEEP", KEEP_REASON)))
        )
        first = bind_fluency_correction_terminal_v0(*common)
        second = bind_fluency_correction_terminal_v0(*common)
        self.assertEqual(first, second)
        self.assertIs(
            first.status,
            FluencyCorrectionTerminalStatusV0.FLUENCY_VERIFIED_WITH_DISMISSALS,
        )
        self.assertEqual((), first.unresolved_ids)
        self.assertEqual(adjudication.resulting_candidate_sha256, first.candidate_sha256)
        self.assertEqual(first, parse_fluency_correction_terminal_v0(canonical_json_bytes(first.as_dict())))
        missing = list(common)
        missing[2] = None
        with self.assertRaises(ContractViolation):
            bind_fluency_correction_terminal_v0(*missing)
        missing = list(common)
        missing[3] = None
        with self.assertRaises(ContractViolation):
            bind_fluency_correction_terminal_v0(*missing)

    def test_dismissals_reject_every_recheck_artifact(self) -> None:
        common, _adjudication = _common_inputs(_accuracy_authority((("KEEP", KEEP_REASON),)))
        for key, value in (
            ("recheck_receipt_bytes", b"{}"),
            ("recheck_raw_output", b"{}"),
            ("recheck_budget", ProviderBudgetV0(None, None)),
        ):
            with self.subTest(key=key), self.assertRaises(ContractViolation):
                bind_fluency_correction_terminal_v0(*common, **{key: value})

    def test_successful_recheck_is_exact_and_deterministic(self) -> None:
        common, kwargs, adjudication = _recheck_inputs(outcome="NO_FINDINGS")
        first = bind_fluency_correction_terminal_v0(*common, **kwargs)
        second = bind_fluency_correction_terminal_v0(*common, **kwargs)
        self.assertEqual(first, second)
        self.assertIs(first.status, FluencyCorrectionTerminalStatusV0.FLUENCY_VERIFIED)
        self.assertEqual((), first.unresolved_ids)
        self.assertEqual(adjudication.resulting_candidate_sha256, first.candidate_sha256)
        self.assertEqual(1, first.round_index)
        self.assertEqual(1, first.max_correction_rounds)

    def test_findings_at_maximum_create_exact_exhaustion(self) -> None:
        common, kwargs, _adjudication = _recheck_inputs(outcome="FINDINGS")
        terminal = bind_fluency_correction_terminal_v0(*common, **kwargs)
        self.assertIs(terminal.status, FluencyCorrectionTerminalStatusV0.REWORK_EXHAUSTED)
        self.assertEqual(kwargs["recheck_decision"].correction_ids, terminal.unresolved_ids)
        self.assertEqual(terminal.round_index, terminal.max_correction_rounds)

    def test_findings_with_remaining_round_are_nonterminal(self) -> None:
        common, kwargs, _adjudication = _recheck_inputs(outcome="FINDINGS", max_rounds=2)
        self.assertLess(kwargs["recheck_plan"].round_index, kwargs["recheck_plan"].max_correction_rounds)
        with self.assertRaises(ContractViolation):
            bind_fluency_correction_terminal_v0(*common, **kwargs)

    def test_closed_domain_separated_role_sets_fail_on_inventory_drift(self) -> None:
        common = {role: "0" * 64 for role in _COMMON_CORRECTION_ROLES}
        recheck = {**common, **{role: "1" * 64 for role in _RECHECK_ROLES}}
        dismissals_root = _closed_correction_chain_root_v0("dismissals", common)
        recheck_root = _closed_correction_chain_root_v0("recheck", recheck)
        self.assertNotEqual(dismissals_root, recheck_root)
        self.assertEqual(tuple(sorted((*_COMMON_CORRECTION_ROLES, *_RECHECK_ROLES))), tuple(sorted(recheck)))
        for role_set, rows in (
            ("dismissals", {key: value for key, value in common.items() if key != "trigger"}),
            ("dismissals", {**common, "foreign": "2" * 64}),
            ("recheck", common),
            ("foreign", recheck),
        ):
            with self.subTest(role_set=role_set), self.assertRaises(ContractViolation):
                _closed_correction_chain_root_v0(role_set, rows)

    def test_stale_recheck_and_terminal_authority_fail_closed(self) -> None:
        common, kwargs, _adjudication = _recheck_inputs(outcome="NO_FINDINGS")
        cases = (
            {**kwargs, "recheck_plan": replace(kwargs["recheck_plan"], context_digest="0" * 64)},
            {**kwargs, "recheck_receipt_bytes": kwargs["recheck_receipt_bytes"] + b" "},
            {**kwargs, "recheck_raw_output": kwargs["recheck_raw_output"] + b" "},
            {**kwargs, "recheck_state": replace(kwargs["recheck_state"], decision_sha256="0" * 64)},
        )
        for changed in cases:
            with self.subTest(), self.assertRaises(ContractViolation):
                bind_fluency_correction_terminal_v0(*common, **changed)
        changed_common = list(common)
        changed_common[10] = tuple((*common[10][:-1], (common[10][-1][0], common[10][-1][1] + b" ")))
        with self.assertRaises(ContractViolation):
            bind_fluency_correction_terminal_v0(*changed_common, **kwargs)

    def test_parser_is_strict_and_models_copy_collections(self) -> None:
        common, kwargs, _adjudication = _recheck_inputs(outcome="FINDINGS")
        terminal = bind_fluency_correction_terminal_v0(*common, **kwargs)
        payload = canonical_json_bytes(terminal.as_dict())
        with self.assertRaises(ContractViolation):
            parse_fluency_correction_terminal_v0(payload + b" ")
        unknown = parse_canonical_json(payload)
        unknown["unexpected"] = True
        with self.assertRaises(ContractViolation):
            parse_fluency_correction_terminal_v0(canonical_json_bytes(unknown))
        unresolved = list(terminal.unresolved_ids)
        copied = replace(terminal, unresolved_ids=tuple(unresolved))
        unresolved.clear()
        self.assertEqual(terminal.unresolved_ids, copied.unresolved_ids)

    def test_binder_is_pure_and_has_no_next_lifecycle_surface(self) -> None:
        common, kwargs, _adjudication = _recheck_inputs(outcome="NO_FINDINGS")
        before_common = deepcopy(common)
        before_kwargs = deepcopy(kwargs)
        terminal = bind_fluency_correction_terminal_v0(*common, **kwargs)
        self.assertEqual(before_common, common)
        self.assertEqual(before_kwargs, kwargs)
        signature = inspect.signature(bind_fluency_correction_terminal_v0)
        for forbidden in ("root", "path", "provider", "publication", "validation"):
            self.assertNotIn(forbidden, signature.parameters)
        rendered = canonical_json_bytes(terminal.as_dict())
        for forbidden in (b"diagnostic_note", b"provider-output", b"publication", b"validation"):
            self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":
    unittest.main()
