from __future__ import annotations

import sys
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.content.v0 import frozen_scope_artifacts_v0, reconcile_sources_v0  # noqa: E402
from locpipe.contracts.v0 import (  # noqa: E402
    Capability,
    ContractViolation,
    canonical_json_bytes,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
    strict_loads,
)
from locpipe.editorial.v0 import (  # noqa: E402
    EditorialSubmissionReceiptV0,
    editorial_job_root_v0,
    editorial_terminal_artifacts_v0,
    parse_editorial_candidate_v0,
)
from locpipe.fluency.v0 import (  # noqa: E402
    accept_fluency_submission_v0,
    bind_fluency_correction_terminal_v0,
    bind_fluency_submission_receipt_v0,
    build_fluency_content_validation_job_v0,
    build_fluency_recheck_job_v0,
    build_fluency_review_job_v0,
)
from locpipe.translation.v0 import ProviderBudgetV0  # noqa: E402
from locpipe.validation.v0 import (  # noqa: E402
    build_validation_editorial_rework_v0,
    content_validation_terminal_artifacts_v0,
    validation_editorial_trigger_path_v0,
    validation_job_root_v0,
)
from tests import test_content_validation_v0 as content_tests  # noqa: E402
from tests import test_fluency_correction_v0 as correction_tests  # noqa: E402
from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402
from tests.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0  # noqa: E402
from tests.test_editorial_acceptance_v0 import editorial_output  # noqa: E402
from tests.test_fluency_acceptance_v0 import clear_reviews, provider_output  # noqa: E402
from tests.test_fluency_adjudication_v0 import (  # noqa: E402
    CORRECT_REASON,
    KEEP_REASON,
    _accept,
    _accuracy_authority,
)
from tests.test_fluency_recheck_v0 import (  # noqa: E402
    _projection,
    _resulting_authority,
    _target_ids,
)
from tests.test_translation_packet_v0 import FIXTURES, build_fixture  # noqa: E402


PROJECTION_PATH = "fluency/validation-authority.json"


def _combined_layers(*, configured_editor=True, locales=("pl", "uk")):
    selected = deepcopy(content_tests.validation_layers(
        configured_editor=configured_editor,
        locales=locales,
    ))
    selected["project"]["provider_bindings"].append({
        "role": "fluency_editor",
        "provider_id": "offline-fluency",
        "version": "1.0.0",
        "config_digest": correction_tests.FLUENCY_PROVIDER_SHA,
    })
    selected["project"]["provider_bindings"].sort(
        key=lambda row: (row["role"], row["provider_id"]),
    )
    return selected


def _validation_fixture(name="flat", adapter=None, *, broken_placeholder=False):
    original = content_tests.validation_layers

    def selected(*, configured_editor=True, locales=("pl", "uk")):
        base = deepcopy(original(configured_editor=configured_editor, locales=locales))
        base["project"]["provider_bindings"].append({
            "role": "fluency_editor",
            "provider_id": "offline-fluency",
            "version": "1.0.0",
            "config_digest": correction_tests.FLUENCY_PROVIDER_SHA,
        })
        base["project"]["provider_bindings"].sort(
            key=lambda row: (row["role"], row["provider_id"]),
        )
        return base

    with patch.object(content_tests, "validation_layers", side_effect=selected):
        return content_tests.validation_fixture(
            name,
            adapter,
            broken_placeholder=broken_placeholder,
        )


def _validation_call(
    fixture,
    candidate=None,
    candidate_evidence=None,
    editorial_job=None,
    editorial_packet=None,
    editorial_policy=None,
    **provenance,
):
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
        candidate or fixture["candidate"],
        fixture["validator"],
        source_lock_bytes=authority["source/source_lock.json"],
        reconciliation_bytes=authority["reconciliation/reconciliation.json"],
        scope_bytes=authority["scope/scope.json"],
        scope_lock_bytes=authority["scope/scope_lock.json"],
        segments_bytes=authority["corpus/segments.jsonl"],
        candidate_evidence=candidate_evidence or fixture["candidate_evidence"],
        editorial_job=editorial_job or fixture["editorial_job"],
        editorial_packet=editorial_packet or fixture["editorial_packet"],
        editorial_policy=editorial_policy or fixture["editorial_policy"],
        **provenance,
    )


def _initial_provenance(fixture, *, provider_request_id="fluency-validation-initial"):
    candidate = fixture["candidate"]
    candidate_authority = semantic_sha256([
        {"path": path, "sha256": raw_sha256(payload)}
        for path, payload in fixture["candidate_evidence"]
    ])
    projection = _projection(candidate, _target_ids(candidate))
    budget = ProviderBudgetV0(None, None)
    plan, job, packet = build_fluency_review_job_v0(
        fixture["context"],
        fixture["resolved"],
        candidate,
        projection,
        candidate_authority_sha256=candidate_authority,
        requested_ids=tuple(row.stable_id for row in projection.rows),
        budget=budget,
    )
    raw_output = provider_output(plan, job, clear_reviews(plan))
    receipt = bind_fluency_submission_receipt_v0(
        plan,
        job,
        packet,
        raw_output,
        provider_request_id=provider_request_id,
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
        "provenance_kind": "INITIAL_STATE",
        "initial_projection": projection,
        "initial_budget": budget,
        "initial_plan": plan,
        "initial_job": job,
        "initial_packet": packet,
        "initial_receipt_bytes": receipt_bytes,
        "initial_raw_output": raw_output,
        "initial_decision": decision,
        "initial_state": state,
    }


def _accuracy_authority_with_validation(actions):
    original = correction_tests.correction_layers

    def selected():
        base = deepcopy(original())
        base["project"]["module_bindings"].append({
            "capability": Capability.CONTENT_VALIDATION.value,
            "module_id": "fixture.content-validation",
            "version": "1.0.0",
            "digest": content_tests.VALIDATOR_SHA,
        })
        base["project"]["module_bindings"].sort(
            key=lambda row: (row["capability"], row["module_id"]),
        )
        return base

    with patch.object(correction_tests, "correction_layers", side_effect=selected):
        return _accuracy_authority(actions)


def _correction_validation_fixture(authority):
    source_fixture, accuracy_job, accuracy_packet, _trigger, _receipt, _raw, _terminal = authority
    layers = _combined_layers()
    resolved, corpus, scope, translation_job, translation_packet = build_fixture(
        "flat",
        SyntheticFlatAdapterV0(),
        target_locale="uk",
        selected_layers=layers,
    )
    assert resolved == source_fixture["resolved"]
    assert translation_job == source_fixture["translation_job"]
    assert translation_packet == source_fixture["translation_packet"]
    scope_artifacts = dict(frozen_scope_artifacts_v0(scope))
    candidate, evidence = _resulting_authority(authority)
    return {
        "context": source_fixture["context"],
        "resolved": resolved,
        "scope": scope,
        "translation_job": translation_job,
        "translation_packet": translation_packet,
        "translation_decision_bytes": source_fixture["translation_decision_bytes"],
        "translation_state_bytes": source_fixture["translation_state_bytes"],
        "translation_target_set": source_fixture["target_set"],
        "candidate": candidate,
        "candidate_evidence": evidence,
        "editorial_job": accuracy_job,
        "editorial_packet": accuracy_packet,
        "editorial_policy": source_fixture["policy"],
        "validator": content_tests.SyntheticContentValidatorV0(),
        "authority": (
            ("corpus/segments.jsonl", (FIXTURES / "flat/golden/segments.jsonl").read_bytes()),
            ("scope/scope.json", scope_artifacts["scope/scope.json"]),
            ("scope/scope_lock.json", scope_artifacts["scope/scope_lock.json"]),
            ("reconciliation/reconciliation.json", canonical_json_bytes(reconcile_sources_v0(corpus).as_dict())),
            ("source/source_lock.json", canonical_json_bytes(corpus.lock.as_dict())),
        ),
    }


def _correction_provenance(authority, *, recheck_outcome=None):
    fixture, accuracy_job, accuracy_packet, trigger_bytes, receipt, raw_output, terminal = authority
    adjudication = _accept(authority)
    candidate, evidence = _resulting_authority(authority)
    adjudication_bytes = canonical_json_bytes(adjudication.as_dict())
    common = {
        "provenance_kind": "CORRECTION_TERMINAL",
        "correction_trigger_bytes": trigger_bytes,
        "correction_adjudication_bytes": adjudication_bytes,
        "correction_accuracy_job": accuracy_job,
        "correction_accuracy_packet": accuracy_packet,
        "correction_accuracy_policy": fixture["policy"],
        "correction_accuracy_parent_candidate": fixture["candidate"],
        "correction_accuracy_receipt": receipt,
        "correction_accuracy_raw_output": raw_output,
        "correction_accuracy_terminal_artifacts": terminal,
    }
    terminal_args = (
        fixture["context"],
        fixture["resolved"],
        trigger_bytes,
        adjudication_bytes,
        accuracy_job,
        accuracy_packet,
        fixture["policy"],
        fixture["candidate"],
        receipt,
        raw_output,
        terminal,
        evidence,
    )
    if recheck_outcome is None:
        terminal_model = bind_fluency_correction_terminal_v0(*terminal_args)
    else:
        projection = _projection(candidate, adjudication.corrected_ids)
        budget = ProviderBudgetV0(None, None)
        plan, job, packet = build_fluency_recheck_job_v0(
            *terminal_args,
            projection,
            budget=budget,
        )
        findings = [] if recheck_outcome == "NO_FINDINGS" else [
            {"category": "VOICE", "diagnostic_note": "Після виправлення лишилося зауваження."},
        ]
        raw_recheck = canonical_json_bytes({
            "contract": "locpipe.fluency.provider-output/v0",
            "job_id": job.job_id,
            "invocation_id": job.invocation_id,
            "plan_sha256": plan.digest,
            "packet_sha256": job.packet_sha256,
            "provider": job.provider.as_dict(),
            "output_contract_sha256": job.output_contract_sha256,
            "reviews": [
                {"stable_id": stable_id, "outcome": recheck_outcome, "findings": findings}
                for stable_id in plan.requested_ids
            ],
        })
        recheck_receipt = bind_fluency_submission_receipt_v0(
            plan,
            job,
            packet,
            raw_recheck,
            provider_request_id=f"fluency-validation-{recheck_outcome.lower()}",
        )
        recheck_receipt_bytes = canonical_json_bytes(recheck_receipt.as_dict())
        decision, state = accept_fluency_submission_v0(
            plan,
            job,
            packet,
            recheck_receipt_bytes,
            raw_recheck,
        )
        recheck = {
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
        terminal_model = bind_fluency_correction_terminal_v0(
            *terminal_args,
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
        common.update(recheck)
    common["correction_terminal_bytes"] = canonical_json_bytes(terminal_model.as_dict())
    return common


def _validation_origin_corrected_candidate(fixture):
    findings = fixture["validator"].validate(fixture["packet"])
    terminal = dict(content_validation_terminal_artifacts_v0(fixture["job"], findings))
    validation_root = validation_job_root_v0(fixture["job"])
    accuracy_job, accuracy_packet, trigger_bytes = build_validation_editorial_rework_v0(
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
        fixture["job"],
        fixture["packet"],
        terminal[f"{validation_root}/report.json"],
        terminal[f"{validation_root}/state.json"],
        terminal[f"{validation_root}/rework_request.json"],
        budget=ProviderBudgetV0(None, None),
    )
    decisions = []
    for row in accuracy_packet.rows:
        if row.stable_id not in accuracy_packet.requested_ids:
            continue
        target = parse_canonical_json(row._target_bytes)
        constraints = strict_loads(row._constraints_bytes)
        placeholder = constraints.get("placeholder")
        data = dict(target["data"])
        if isinstance(placeholder, str) and placeholder != "none" and placeholder not in data["payload"]:
            data["payload"] = f"{data['payload']} {placeholder}"
        data["metadata_ref"] = None
        corrected = dict(target)
        corrected["data"] = data
        decisions.append({
            "identity": row.identity.as_dict(),
            "action": "CORRECT",
            "reason_code": "VALIDATION_FINDING_FIXED",
            "target": corrected,
        })
    raw_output = canonical_json_bytes({
        "contract": "locpipe.editorial.provider-output/v0",
        "decisions": decisions,
    })
    receipt = EditorialSubmissionReceiptV0(
        accuracy_job.job_id,
        accuracy_job.invocation_id,
        accuracy_job.provider,
        "fluency-validation-origin",
        accuracy_job.packet_sha256,
        accuracy_job.output_contract_sha256,
        raw_sha256(raw_output),
    )
    accuracy_terminal = editorial_terminal_artifacts_v0(
        accuracy_job,
        accuracy_packet,
        fixture["editorial_policy"],
        fixture["candidate"],
        receipt,
        raw_output,
    )
    accuracy_root = editorial_job_root_v0(accuracy_job)
    terminal_map = dict(accuracy_terminal)
    candidate = parse_editorial_candidate_v0(terminal_map[f"{accuracy_root}/candidate_set.json"])
    evidence = tuple(sorted((
        (f"{accuracy_root}/job.json", canonical_json_bytes(accuracy_job.as_dict())),
        (f"{accuracy_root}/packet.json", canonical_json_bytes(accuracy_packet.as_dict())),
        (f"{accuracy_root}/parent_candidate.json", canonical_json_bytes(fixture["candidate"].as_dict())),
        (f"{accuracy_root}/policy.json", canonical_json_bytes(fixture["editorial_policy"].as_dict())),
        (validation_editorial_trigger_path_v0(fixture["job"]), trigger_bytes),
        *accuracy_terminal,
    )))
    return candidate, evidence, accuracy_job, accuracy_packet


class FluencyValidationBridgeV0Tests(unittest.TestCase):
    def test_initial_state_is_deterministic_and_exactly_supplemental(self) -> None:
        fixture = _validation_fixture()
        provenance = _initial_provenance(fixture)
        first = _validation_call(fixture, **provenance)
        second = _validation_call(fixture, **provenance)
        self.assertEqual(first, second)
        job, packet, authority = first
        supplemental = [(path, payload) for path, payload in authority if path == PROJECTION_PATH]
        self.assertEqual(1, len(supplemental))
        projection = parse_canonical_json(supplemental[0][1])
        self.assertEqual("locpipe.fluency.validation-authority-projection/v0", projection["contract"])
        self.assertEqual("INITIAL_STATE", projection["provenance_kind"])
        self.assertEqual([], projection["unresolved_ids"])
        self.assertEqual(job.candidate_sha256, projection["candidate_sha256"])
        self.assertEqual(job.candidate_authority_sha256, projection["candidate_authority_sha256"])
        rendered = supplemental[0][1]
        for forbidden in (b"diagnostic_note", b"raw_output", b"source_payload", b"roles"):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(fixture["packet"], packet)

    def test_dismissals_and_successful_recheck_are_admitted(self) -> None:
        dismissals = _accuracy_authority_with_validation((("KEEP", KEEP_REASON), ("KEEP", KEEP_REASON)))
        dismissals_fixture = _correction_validation_fixture(dismissals)
        dismissals_result = _validation_call(
            dismissals_fixture,
            **_correction_provenance(dismissals),
        )
        dismissals_projection = parse_canonical_json(dict(dismissals_result[2])[PROJECTION_PATH])
        self.assertEqual("FLUENCY_VERIFIED_WITH_DISMISSALS", dismissals_projection["outcome"])

        corrected = _accuracy_authority_with_validation((("CORRECT", CORRECT_REASON), ("CORRECT", CORRECT_REASON)))
        corrected_fixture = _correction_validation_fixture(corrected)
        corrected_result = _validation_call(
            corrected_fixture,
            **_correction_provenance(corrected, recheck_outcome="NO_FINDINGS"),
        )
        corrected_projection = parse_canonical_json(dict(corrected_result[2])[PROJECTION_PATH])
        self.assertEqual("FLUENCY_VERIFIED", corrected_projection["outcome"])
        self.assertNotEqual(
            dismissals_projection["fluency_authority_sha256"],
            corrected_projection["fluency_authority_sha256"],
        )

    def test_exact_one_provenance_group_is_enforced(self) -> None:
        fixture = _validation_fixture()
        initial = _initial_provenance(fixture)
        with self.assertRaises(ContractViolation):
            _validation_call(fixture, **{**initial, "provenance_kind": "UNKNOWN"})
        incomplete = dict(initial)
        incomplete["initial_state"] = None
        with self.assertRaises(ContractViolation):
            _validation_call(fixture, **incomplete)
        mixed = dict(initial)
        mixed["correction_terminal_bytes"] = b"{}"
        with self.assertRaises(ContractViolation):
            _validation_call(fixture, **mixed)

    def test_initial_chain_drift_and_correction_as_initial_fail_closed(self) -> None:
        fixture = _validation_fixture()
        initial = _initial_provenance(fixture)
        for key, value in (
            ("initial_receipt_bytes", initial["initial_receipt_bytes"] + b" "),
            ("initial_job", replace(initial["initial_job"], packet_sha256="0" * 64)),
            ("initial_job", replace(
                initial["initial_job"],
                provider=replace(initial["initial_job"].provider, provider_id="foreign-fluency"),
            )),
            ("initial_projection", replace(
                initial["initial_projection"], candidate_sha256="2" * 64,
            )),
            ("initial_plan", replace(
                initial["initial_plan"], candidate_authority_sha256="3" * 64,
            )),
            ("initial_state", replace(initial["initial_state"], candidate_sha256="1" * 64)),
        ):
            drifted = dict(initial)
            drifted[key] = value
            with self.assertRaises(ContractViolation):
                _validation_call(fixture, **drifted)

        correction = _accuracy_authority_with_validation((("KEEP", KEEP_REASON), ("KEEP", KEEP_REASON)))
        terminal = _correction_provenance(correction)
        disguised = dict(initial)
        disguised["initial_receipt_bytes"] = terminal["correction_terminal_bytes"]
        with self.assertRaises(ContractViolation):
            _validation_call(fixture, **disguised)

    def test_terminal_drift_and_exhaustion_fail_closed(self) -> None:
        authority = _accuracy_authority_with_validation((("CORRECT", CORRECT_REASON), ("CORRECT", CORRECT_REASON)))
        fixture = _correction_validation_fixture(authority)
        success = _correction_provenance(authority, recheck_outcome="NO_FINDINGS")
        drifted = dict(success)
        drifted["correction_terminal_bytes"] += b" "
        with self.assertRaises(ContractViolation):
            _validation_call(fixture, **drifted)
        exhausted = _correction_provenance(authority, recheck_outcome="FINDINGS")
        with self.assertRaises(ContractViolation):
            _validation_call(fixture, **exhausted)

    def test_same_candidate_distinct_verified_chains_change_job_authority(self) -> None:
        fixture = _validation_fixture()
        first = _validation_call(
            fixture,
            **_initial_provenance(fixture, provider_request_id="fluency-chain-a"),
        )
        second = _validation_call(
            fixture,
            **_initial_provenance(fixture, provider_request_id="fluency-chain-b"),
        )
        self.assertEqual(first[0].candidate_sha256, second[0].candidate_sha256)
        self.assertNotEqual(first[0].authority_sha256, second[0].authority_sha256)
        self.assertNotEqual(first[0].job_id, second[0].job_id)

    def test_validation_origin_candidate_requires_fresh_round_zero_fluency(self) -> None:
        fixture = _validation_fixture(
            "structured",
            SyntheticStructuredAdapterV0(),
            broken_placeholder=True,
        )
        old_authority = _initial_provenance(fixture)
        candidate, evidence, editorial_job, editorial_packet = _validation_origin_corrected_candidate(fixture)
        with self.assertRaises(ContractViolation):
            _validation_call(
                fixture,
                candidate=candidate,
                candidate_evidence=evidence,
                editorial_job=editorial_job,
                editorial_packet=editorial_packet,
                editorial_policy=fixture["editorial_policy"],
                **old_authority,
            )
        corrected_fixture = dict(fixture)
        corrected_fixture.update({
            "candidate": candidate,
            "candidate_evidence": evidence,
            "editorial_job": editorial_job,
            "editorial_packet": editorial_packet,
        })
        fresh_authority = _initial_provenance(corrected_fixture)
        job, _packet, authority = _validation_call(
            corrected_fixture,
            **fresh_authority,
        )
        projection = parse_canonical_json(dict(authority)[PROJECTION_PATH])
        self.assertEqual(raw_sha256(canonical_json_bytes(candidate.as_dict())), job.candidate_sha256)
        self.assertEqual(job.candidate_sha256, projection["candidate_sha256"])


if __name__ == "__main__":
    unittest.main()
