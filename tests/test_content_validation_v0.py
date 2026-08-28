from __future__ import annotations

import sys
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.content.v0 import frozen_scope_artifacts_v0, reconcile_sources_v0  # noqa: E402
from locpipe.contracts.v0 import (  # noqa: E402
    ArtifactHashV0,
    Capability,
    ContractViolation,
    ErrorCode,
    ModuleDescriptorV0,
    OperationRequestV0,
    canonical_json_bytes,
    execute_bound_operation,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
    strict_loads,
)
from locpipe.editorial.v0 import (  # noqa: E402
    EditorialCandidateSetV0,
    EditorialPolicyV0,
    EditorialSubmissionReceiptV0,
    build_editorial_bypass_v0,
    build_editorial_job_v0,
    editorial_job_root_v0,
    editorial_acceptance_output_declarations_v0,
    editorial_submission_digest_v0,
    editorial_terminal_artifacts_v0,
    parse_editorial_candidate_v0,
)
from locpipe.kernel.v0.context import (  # noqa: E402
    acquire_context_write_lease,
    initialize_project_context,
    resolve_project_paths,
)
from locpipe.kernel.v0.context_transactions import (  # noqa: E402
    inspect_context_group_recovery,
    release_context_write_lease,
    rollback_context_group,
)
from locpipe.kernel.v0.transactions import (  # noqa: E402
    PublicationGroupReceiptV0,
    RecoveryDispositionV0,
    SyntheticTransactionStoreV0,
)
from locpipe.translation.v0 import (  # noqa: E402
    ProviderBudgetV0,
    TranslationStateV0,
    TranslationTargetSetV0,
)
from locpipe.validation.v0 import (  # noqa: E402
    ContentFindingV0,
    ContentValidationStatusV0,
    FindingSeverityV0,
    bind_content_validator_v0,
    bind_validation_editorial_acceptance_v0,
    build_content_validation_job_v0,
    build_validation_editorial_rework_v0,
    content_locale_receipt_v0,
    content_validation_output_declarations_v0,
    finalize_content_verified_v0,
    publish_content_locale_receipt_v0,
    publish_content_validation_group_v0,
    publish_content_verified_v0,
    content_validation_terminal_artifacts_v0,
    validation_editorial_acceptance_inputs_v0,
    validation_editorial_trigger_path_v0,
    validation_job_root_v0,
)
from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402
from tests.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0  # noqa: E402
from tests.test_editorial_acceptance_v0 import editorial_output  # noqa: E402
from tests.test_editorial_packet_v0 import accepted_fixture, editorial_layers  # noqa: E402
from tests.test_translation_acceptance_v0 import binding  # noqa: E402
from tests.test_translation_packet_v0 import FIXTURES, build_fixture  # noqa: E402


VALIDATOR_SHA = "7" * 64
RULE_SHA = semantic_sha256({"contract": "synthetic.content-rules/v0", "rules": ["nonempty", "placeholder"]})


def validation_layers(*, configured_editor=True, locales=("pl", "uk")):
    selected = deepcopy(editorial_layers(configured=configured_editor))
    selected["project"]["target_locales"] = list(locales)
    selected["project"]["module_bindings"].append({
        "capability": Capability.CONTENT_VALIDATION.value,
        "module_id": "fixture.content-validation",
        "version": "1.0.0",
        "digest": VALIDATOR_SHA,
    })
    selected["project"]["module_bindings"].sort(key=lambda row: (row["capability"], row["module_id"]))
    return selected


class SyntheticContentValidatorV0:
    descriptor = ModuleDescriptorV0(
        Capability.CONTENT_VALIDATION,
        "fixture.content-validation",
        "1.0.0",
        VALIDATOR_SHA,
    )
    rule_contract_sha256 = RULE_SHA
    supported_content_types = ("plain_text",)
    supported_constraint_keys = ("context", "placeholder")

    def __init__(self, *, warning=False):
        self.warning = warning

    def validate(self, packet):
        findings = []
        for row in packet.rows:
            if row.role != "OWNED":
                continue
            source = strict_loads(row._source_bytes)
            target = parse_canonical_json(row._target_bytes)
            constraints = strict_loads(row._constraints_bytes)
            source_text = source if isinstance(source, str) else str(source)
            target_text = target["data"]["payload"]
            evidence = semantic_sha256({
                "source": raw_sha256(row._source_bytes),
                "target": raw_sha256(row._target_bytes),
                "constraints": raw_sha256(row._constraints_bytes),
            })
            if not isinstance(target_text, str) or not target_text:
                findings.append(ContentFindingV0(
                    row.stable_id, "nonempty", FindingSeverityV0.ERROR, "EMPTY_TARGET", evidence,
                ))
            placeholder = constraints.get("placeholder")
            if isinstance(placeholder, str) and placeholder != "none" and target_text.count(placeholder) != 1:
                findings.append(ContentFindingV0(
                    row.stable_id, "placeholder", FindingSeverityV0.ERROR, "PLACEHOLDER_MISMATCH", evidence,
                ))
        if self.warning:
            row = next(row for row in packet.rows if row.role == "OWNED")
            findings.append(ContentFindingV0(
                row.stable_id, "style-warning", FindingSeverityV0.WARNING, "SYNTHETIC_WARNING", "9" * 64,
            ))
        return tuple(sorted(findings, key=lambda row: (row.stable_id, row.rule_id, row.reason_code, row.finding_id)))


class AdversarialContentValidatorV0(SyntheticContentValidatorV0):
    def __init__(self, mode):
        super().__init__()
        self.mode = mode

    def validate(self, packet):
        row = next(row for row in packet.rows if row.role == "OWNED")
        finding_a = ContentFindingV0(
            row.stable_id, "a-rule", FindingSeverityV0.WARNING, "A", "1" * 64,
        )
        finding_z = ContentFindingV0(
            row.stable_id, "z-rule", FindingSeverityV0.WARNING, "Z", "2" * 64,
        )
        if self.mode == "list":
            return [finding_a]
        if self.mode == "unordered":
            return (finding_z, finding_a)
        if self.mode == "foreign":
            return (ContentFindingV0("foreign", "a-rule", FindingSeverityV0.ERROR, "FOREIGN", "3" * 64),)
        if self.mode == "descriptor-drift":
            self.descriptor = ModuleDescriptorV0(
                Capability.CONTENT_VALIDATION, "fixture.drifted", "1.0.0", "4" * 64,
            )
            return ()
        raise AssertionError("unknown adversarial mode")


class InjectedValidationCrash(RuntimeError):
    pass


def _preserve_placeholders(target_set, translation_packet, *, broken=False):
    sources = {(row.identity.logical_id, row.identity.selector_path): row for row in translation_packet.rows}
    rows = []
    for payload in target_set._target_bytes:
        target = parse_canonical_json(payload)
        identity = target["data"]["identity"]
        from locpipe.contracts.v0 import BranchIdentity

        parsed_identity = BranchIdentity.from_dict(identity)
        source = sources[(parsed_identity.logical_id, parsed_identity.selector_path)]
        constraints = strict_loads(source._constraints_bytes)
        placeholder = constraints.get("placeholder")
        if isinstance(placeholder, str) and placeholder != "none" and not broken:
            data = dict(target["data"])
            data["payload"] = f"{data['payload']} {placeholder}"
            target = dict(target)
            target["data"] = data
        rows.append(canonical_json_bytes(target))
    return TranslationTargetSetV0(
        target_set.job_id, target_set.invocation_id, target_set.target_locale, tuple(rows),
    )


def validation_fixture(
    name="flat",
    adapter=None,
    *,
    target_locale="uk",
    locales=("pl", "uk"),
    configured_editor=True,
    broken_placeholder=False,
    warning=False,
):
    adapter = adapter or SyntheticFlatAdapterV0()
    layers = validation_layers(configured_editor=configured_editor, locales=locales)
    context, resolved, translation_job, translation_packet, decision_bytes, target_set, _state_bytes = accepted_fixture(
        name, adapter, selected_layers=layers, target_locale=target_locale,
    )
    target_set = _preserve_placeholders(target_set, translation_packet, broken=broken_placeholder)
    decision = parse_canonical_json(decision_bytes)
    state = TranslationStateV0(
        translation_job.job_id,
        translation_job.invocation_id,
        __import__("locpipe.translation.v0", fromlist=["TranslationJobStatusV0"]).TranslationJobStatusV0.ACCEPTED,
        decision["submission_sha256"],
        raw_sha256(decision_bytes),
        raw_sha256(canonical_json_bytes(target_set.as_dict())),
    )
    state_bytes = canonical_json_bytes(state.as_dict())
    policy = EditorialPolicyV0(2)
    if configured_editor:
        editorial_job, editorial_packet, parent = build_editorial_job_v0(
            context, resolved, translation_job, translation_packet, decision_bytes, target_set, state_bytes,
            policy, budget=ProviderBudgetV0(None, None),
        )
        raw = editorial_output(editorial_job, editorial_packet)
        receipt = EditorialSubmissionReceiptV0(
            editorial_job.job_id, editorial_job.invocation_id, editorial_job.provider, "validation-editorial",
            editorial_job.packet_sha256, editorial_job.output_contract_sha256, raw_sha256(raw),
        )
        terminal = dict(editorial_terminal_artifacts_v0(
            editorial_job, editorial_packet, policy, parent, receipt, raw,
        ))
        eroot = editorial_job_root_v0(editorial_job)
        candidate = parse_editorial_candidate_v0(terminal[f"{eroot}/candidate_set.json"])
        candidate_evidence = tuple(sorted((
            (f"{eroot}/job.json", canonical_json_bytes(editorial_job.as_dict())),
            (f"{eroot}/packet.json", canonical_json_bytes(editorial_packet.as_dict())),
            (f"{eroot}/parent_candidate.json", canonical_json_bytes(parent.as_dict())),
            (f"{eroot}/policy.json", canonical_json_bytes(policy.as_dict())),
            *terminal.items(),
        )))
    else:
        editorial_job = editorial_packet = policy = None
        candidate = build_editorial_bypass_v0(
            context, resolved, translation_job, translation_packet, decision_bytes, target_set, state_bytes,
        )
        token = candidate.job_id.removeprefix("editorial-base-")[:20]
        eroot = f"ed/b/{token}"
        candidate_bytes = canonical_json_bytes(candidate.as_dict())
        disposition = canonical_json_bytes({
            "contract": "locpipe.editorial.bypass/v0",
            "context_digest": context.context_digest,
            "translation_job_id": translation_job.job_id,
            "candidate_sha256": raw_sha256(candidate_bytes),
            "disposition": "BYPASSED_BY_CONFIG",
        })
        candidate_evidence = (
            (f"{eroot}/candidate_set.json", candidate_bytes),
            (f"{eroot}/disposition.json", disposition),
        )
    resolved2, corpus, scope, translation_job2, translation_packet2 = build_fixture(
        name, adapter, target_locale=target_locale, selected_layers=layers,
    )
    assert resolved2 == resolved and translation_job2 == translation_job and translation_packet2 == translation_packet
    reconciliation = reconcile_sources_v0(corpus)
    source_lock = canonical_json_bytes(corpus.lock.as_dict())
    reconciliation_bytes = canonical_json_bytes(reconciliation.as_dict())
    scope_artifacts = dict(frozen_scope_artifacts_v0(scope))
    segments = (FIXTURES / name / "golden/segments.jsonl").read_bytes()
    validator = SyntheticContentValidatorV0(warning=warning)
    job, packet, authority = build_content_validation_job_v0(
        context, resolved, scope, translation_job, translation_packet, decision_bytes, state_bytes,
        target_set, candidate, validator,
        source_lock_bytes=source_lock,
        reconciliation_bytes=reconciliation_bytes,
        scope_bytes=scope_artifacts["scope/scope.json"],
        scope_lock_bytes=scope_artifacts["scope/scope_lock.json"],
        segments_bytes=segments,
        candidate_evidence=candidate_evidence,
        editorial_job=editorial_job,
        editorial_packet=editorial_packet,
        editorial_policy=policy,
    )
    return {
        "adapter": adapter,
        "context": context,
        "resolved": resolved,
        "scope": scope,
        "translation_job": translation_job,
        "translation_packet": translation_packet,
        "candidate": candidate,
        "candidate_evidence": candidate_evidence,
        "editorial_job": editorial_job,
        "editorial_packet": editorial_packet,
        "editorial_policy": policy,
        "translation_decision_bytes": decision_bytes,
        "translation_state_bytes": state_bytes,
        "translation_target_set": target_set,
        "validator": validator,
        "job": job,
        "packet": packet,
        "authority": authority,
    }


def run_validation(fixture):
    job = fixture["job"]
    packet = fixture["packet"]
    validator = fixture["validator"]
    root = validation_job_root_v0(job)
    artifacts = dict(fixture["authority"])
    artifacts[f"{root}/job.json"] = canonical_json_bytes(job.as_dict())
    artifacts[f"{root}/packet.json"] = canonical_json_bytes(packet.as_dict())
    module_binding = binding(fixture["adapter"], job.validator)
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
        request = OperationRequestV0(
            "content-validation",
            Capability.CONTENT_VALIDATION,
            semantic_sha256(module_binding),
            tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in sorted(artifacts.items())),
            content_validation_output_declarations_v0(job),
        )
        implementation, handler = bind_content_validator_v0(validator, job, packet, fixture["authority"])
        result = execute_bound_operation(
            request.as_envelope(), module_binding, handlers={implementation: handler},
            input_root=inputs, staging_root=staging,
        )
        outputs = {
            declaration.path: (staging / Path(*declaration.path.split("/"))).read_bytes()
            for declaration in content_validation_output_declarations_v0(job)
            if (staging / Path(*declaration.path.split("/"))).is_file()
        }
        return result, outputs


def publish_validation_evidence(fixture, operation_result, outputs):
    temporary = tempfile.TemporaryDirectory()
    store_root = Path(temporary.name) / "store"
    store_root.mkdir()
    store = SyntheticTransactionStoreV0.create(store_root)
    initialize_project_context(store, fixture["context"])
    lease = acquire_context_write_lease(
        store, fixture["context"], "validation-proof", owner_token_factory=lambda: "f" * 32,
    )
    receipt = publish_content_validation_group_v0(
        store, fixture["context"], fixture["job"], "validation-proof",
        tuple(sorted(outputs.items())), lease, operation_result=operation_result,
        clock=lambda: "2026-08-10T00:00:05.000Z",
    )
    release_context_write_lease(store, fixture["context"], lease)
    return receipt, store, temporary


class ContentValidationV0Tests(unittest.TestCase):
    def test_validation_editorial_rework_characterization_v0(self) -> None:
        fixture = validation_fixture(
            "structured", SyntheticStructuredAdapterV0(), broken_placeholder=True,
        )
        _result, outputs = run_validation(fixture)
        root = validation_job_root_v0(fixture["job"])
        editorial_job, editorial_packet, trigger_bytes = build_validation_editorial_rework_v0(
            fixture["context"], fixture["resolved"], fixture["translation_job"],
            fixture["translation_packet"], fixture["translation_decision_bytes"],
            fixture["translation_state_bytes"], fixture["translation_target_set"],
            fixture["editorial_policy"], fixture["candidate"], fixture["candidate_evidence"],
            fixture["editorial_job"], fixture["editorial_packet"], fixture["job"], fixture["packet"],
            outputs[f"{root}/report.json"], outputs[f"{root}/state.json"],
            outputs[f"{root}/rework_request.json"], budget=ProviderBudgetV0(None, None),
        )
        self.assertEqual(
            {
                "trigger_sha256": "3a8bb6027da1cd89f72c288409aefda8d8d46921998e47b0064540c9b89e4b58",
                "packet_sha256": "75dfa146a18098a1afd3c897446f995e5ce2e291a429e5ea0824e8123ff81fb8",
                "job_sha256": "9adeee30c7d033b114987be6b2f3d424a76b7c9b2001875fefc8a42bfd0d6c2a",
                "job_id": "editorial-c0aaf8810358d13e58aaf04bf520ee52",
                "invocation_id": "invocation-3c68576dc3c5981954b3d6b105a2b8b6",
            },
            {
                "trigger_sha256": raw_sha256(trigger_bytes),
                "packet_sha256": raw_sha256(canonical_json_bytes(editorial_packet.as_dict())),
                "job_sha256": raw_sha256(canonical_json_bytes(editorial_job.as_dict())),
                "job_id": editorial_job.job_id,
                "invocation_id": editorial_job.invocation_id,
            },
        )
        trigger = parse_canonical_json(trigger_bytes)
        self.assertEqual("locpipe.validation.editorial-trigger/v0", trigger["contract"])
        self.assertEqual(list(editorial_packet.requested_ids), trigger["requested_ids"])
        self.assertEqual(fixture["job"].editorial_round_index, trigger["previous_round"])
        self.assertEqual(editorial_job.round_index, trigger["next_round"])
        self.assertEqual(tuple(sorted(editorial_packet.requested_ids)), editorial_packet.requested_ids)

        def rebuild(*, validation_job=None, policy=None, rework_bytes=None):
            return build_validation_editorial_rework_v0(
                fixture["context"], fixture["resolved"], fixture["translation_job"],
                fixture["translation_packet"], fixture["translation_decision_bytes"],
                fixture["translation_state_bytes"], fixture["translation_target_set"],
                policy or fixture["editorial_policy"], fixture["candidate"], fixture["candidate_evidence"],
                fixture["editorial_job"], fixture["editorial_packet"], validation_job or fixture["job"],
                fixture["packet"], outputs[f"{root}/report.json"], outputs[f"{root}/state.json"],
                rework_bytes or outputs[f"{root}/rework_request.json"],
                budget=ProviderBudgetV0(None, None),
            )

        cases = (
            (
                {"validation_job": replace(fixture["job"], candidate_authority_sha256="0" * 64)},
                "Validation parent editorial authority drift",
            ),
            (
                {"validation_job": replace(
                    fixture["job"], editorial_round_index=fixture["job"].editorial_round_index + 1,
                )},
                "Validation/editorial authority differs from translation context",
            ),
            (
                {"policy": EditorialPolicyV0(1)},
                "Validation/editorial authority differs from translation context",
            ),
            (
                {"rework_bytes": canonical_json_bytes({
                    **parse_canonical_json(outputs[f"{root}/rework_request.json"]),
                    "requested_ids": [],
                })},
                "Validation-origin editorial trigger drift",
            ),
        )
        for arguments, detail in cases:
            with self.subTest(detail=detail):
                with self.assertRaises(ContractViolation) as caught:
                    rebuild(**arguments)
                self.assertEqual(ErrorCode.BINDING_MISMATCH, caught.exception.record.code)
                self.assertEqual(detail, caught.exception.record.detail)

    def test_flat_and_structured_are_deterministic_and_locale_verified(self) -> None:
        for name, adapter in (("flat", SyntheticFlatAdapterV0()), ("structured", SyntheticStructuredAdapterV0())):
            first = validation_fixture(name, adapter)
            second = validation_fixture(name, adapter)
            self.assertEqual(first["job"], second["job"])
            self.assertEqual(first["packet"], second["packet"])
            result, outputs = run_validation(first)
            root = validation_job_root_v0(first["job"])
            self.assertEqual("PASS", result["data"]["status"])
            self.assertEqual("LOCALE_VERIFIED", parse_canonical_json(outputs[f"{root}/state.json"])["status"])

    def test_placeholder_error_enters_bounded_rework_and_bypass_is_unavailable(self) -> None:
        broken = validation_fixture(
            "structured", SyntheticStructuredAdapterV0(), broken_placeholder=True,
        )
        result, outputs = run_validation(broken)
        root = validation_job_root_v0(broken["job"])
        self.assertEqual("PASS", result["data"]["status"])
        self.assertEqual("REWORK_REQUIRED", parse_canonical_json(outputs[f"{root}/state.json"])["status"])
        self.assertTrue(parse_canonical_json(outputs[f"{root}/rework_request.json"])["requested_ids"])

        bypass = validation_fixture(
            "structured", SyntheticStructuredAdapterV0(), configured_editor=False, broken_placeholder=True,
        )
        _result, unavailable = run_validation(bypass)
        root = validation_job_root_v0(bypass["job"])
        self.assertEqual("REWORK_UNAVAILABLE", parse_canonical_json(unavailable[f"{root}/state.json"])["status"])

    def test_warning_is_nonblocking_and_two_locales_aggregate_exactly(self) -> None:
        receipts = []
        evidence = []
        temporary_evidence = []
        selected_scope = None
        for locale in ("pl", "uk"):
            fixture = validation_fixture(target_locale=locale, warning=True)
            operation_result, outputs = run_validation(fixture)
            root = validation_job_root_v0(fixture["job"])
            publication_receipt, store, temporary = publish_validation_evidence(
                fixture, operation_result, outputs,
            )
            temporary_evidence.append(temporary)
            receipts.append(content_locale_receipt_v0(
                fixture["job"], outputs[f"{root}/report.json"], outputs[f"{root}/state.json"],
                outputs[f"{root}/rework_request.json"],
                store=store, context=fixture["context"], operation_result=operation_result,
                validation_publication_receipt=publication_receipt,
            ))
            evidence.append((
                fixture["job"], outputs[f"{root}/report.json"], outputs[f"{root}/state.json"],
                outputs[f"{root}/rework_request.json"], operation_result, publication_receipt,
                store, fixture["context"],
            ))
            selected_scope = fixture["scope"]
        verification, state = finalize_content_verified_v0(
            selected_scope, tuple(reversed(receipts)), validation_evidence=tuple(reversed(evidence)),
        )
        self.assertEqual(("pl", "uk"), tuple(row.target_locale for row in verification.locale_receipts))
        self.assertEqual("CONTENT_VERIFIED", parse_canonical_json(state)["state"])
        with self.assertRaisesRegex(Exception, "exactly cover"):
            finalize_content_verified_v0(
                selected_scope, (receipts[0],), validation_evidence=(evidence[0],),
            )
        forged = (replace(receipts[0], candidate_sha256="1" * 64), receipts[1])
        with self.assertRaisesRegex(Exception, "exact verified validation evidence"):
            finalize_content_verified_v0(
                selected_scope, forged, validation_evidence=tuple(evidence),
            )
        for temporary in temporary_evidence:
            temporary.cleanup()

    def test_direct_terminal_bytes_without_validator_publication_cannot_issue_locale_receipt(self) -> None:
        fixture = validation_fixture(
            "structured", SyntheticStructuredAdapterV0(), broken_placeholder=True, locales=("uk",),
        )
        operation_result, _actual_outputs = run_validation(fixture)
        direct_outputs = dict(content_validation_terminal_artifacts_v0(fixture["job"], ()))
        forged_result = deepcopy(operation_result)
        forged_result["data"]["outputs"] = [
            ArtifactHashV0(path, "raw", raw_sha256(payload)).as_dict()
            for path, payload in sorted(direct_outputs.items())
        ]
        fake_publication = PublicationGroupReceiptV0(
            "validation-direct", "9" * 64,
            tuple(
                ArtifactHashV0(path, "raw", raw_sha256(payload))
                for path, payload in sorted(direct_outputs.items())
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            store_root = Path(directory) / "store"
            store_root.mkdir()
            store = SyntheticTransactionStoreV0.create(store_root)
            initialize_project_context(store, fixture["context"])
            root = validation_job_root_v0(fixture["job"])
            with self.assertRaisesRegex(Exception, "binding is missing|terminal context evidence"):
                content_locale_receipt_v0(
                    fixture["job"], direct_outputs[f"{root}/report.json"],
                    direct_outputs[f"{root}/state.json"], direct_outputs[f"{root}/rework_request.json"],
                    store=store, context=fixture["context"], operation_result=forged_result,
                    validation_publication_receipt=fake_publication,
                )

    def test_context_publication_is_isolated_and_uses_single_for_locale_receipt(self) -> None:
        fixture = validation_fixture(locales=("uk",))
        result, outputs = run_validation(fixture)
        root = validation_job_root_v0(fixture["job"])
        with tempfile.TemporaryDirectory() as directory:
            store_root = Path(directory) / "store"
            store_root.mkdir()
            store = SyntheticTransactionStoreV0.create(store_root)
            paths = initialize_project_context(store, fixture["context"])
            lease = acquire_context_write_lease(
                store, fixture["context"], "validation-terminal", owner_token_factory=lambda: "a" * 32,
            )
            terminal_receipt = publish_content_validation_group_v0(
                store, fixture["context"], fixture["job"], "validation-terminal",
                tuple(sorted(outputs.items())), lease, operation_result=result,
                clock=lambda: "2026-08-10T00:00:00.000Z",
            )
            self.assertEqual(3, len(terminal_receipt.targets))
            self.assertEqual(
                terminal_receipt,
                publish_content_validation_group_v0(
                    store, fixture["context"], fixture["job"], "validation-terminal",
                    tuple(sorted(outputs.items())), lease, operation_result=result,
                    clock=lambda: "2026-08-10T00:00:00.500Z",
                ),
            )
            release_context_write_lease(store, fixture["context"], lease)

            locale_receipt = content_locale_receipt_v0(
                fixture["job"], outputs[f"{root}/report.json"], outputs[f"{root}/state.json"],
                outputs[f"{root}/rework_request.json"],
                store=store, context=fixture["context"], operation_result=result,
                validation_publication_receipt=terminal_receipt,
            )
            lease = acquire_context_write_lease(
                store, fixture["context"], "locale-receipt", owner_token_factory=lambda: "b" * 32,
            )
            published_locale = publish_content_locale_receipt_v0(
                store, fixture["context"], "locale-receipt", locale_receipt, lease,
                clock=lambda: "2026-08-10T00:00:01.000Z",
            )
            release_context_write_lease(store, fixture["context"], lease)
            self.assertEqual("content/locales/uk/receipt.json", published_locale.target.path)

            verification, state = finalize_content_verified_v0(
                fixture["scope"], (locale_receipt,),
                validation_evidence=((
                    fixture["job"], outputs[f"{root}/report.json"], outputs[f"{root}/state.json"],
                    outputs[f"{root}/rework_request.json"], result, terminal_receipt,
                    store, fixture["context"],
                ),),
            )
            lease = acquire_context_write_lease(
                store, fixture["context"], "content-final", owner_token_factory=lambda: "c" * 32,
            )
            final_receipt = publish_content_verified_v0(
                store, fixture["context"], "content-final", verification, state, lease,
                clock=lambda: "2026-08-10T00:00:02.000Z",
            )
            release_context_write_lease(store, fixture["context"], lease)
            self.assertEqual(2, len(final_receipt.targets))
            self.assertTrue((paths.outputs_root / "content/state.json").is_file())
            self.assertEqual([], list(store.targets.rglob("*")))
            self.assertEqual([], list(store.staging.rglob("*")))
            self.assertEqual([], list(store.transactions.rglob("*")))

    def test_validation_error_creates_focused_editorial_overlay_then_revalidates(self) -> None:
        fixture = validation_fixture(
            "structured", SyntheticStructuredAdapterV0(), broken_placeholder=True,
        )
        result, validation_outputs = run_validation(fixture)
        self.assertEqual("PASS", result["data"]["status"])
        validation_root = validation_job_root_v0(fixture["job"])
        editorial_job, editorial_packet, trigger_bytes = build_validation_editorial_rework_v0(
            fixture["context"], fixture["resolved"], fixture["translation_job"],
            fixture["translation_packet"], fixture["translation_decision_bytes"],
            fixture["translation_state_bytes"], fixture["translation_target_set"],
            fixture["editorial_policy"], fixture["candidate"], fixture["candidate_evidence"],
            fixture["editorial_job"], fixture["editorial_packet"], fixture["job"], fixture["packet"],
            validation_outputs[f"{validation_root}/report.json"],
            validation_outputs[f"{validation_root}/state.json"],
            validation_outputs[f"{validation_root}/rework_request.json"],
            budget=ProviderBudgetV0(None, None),
        )
        requested = set(editorial_packet.requested_ids)
        self.assertTrue(requested)
        report = parse_canonical_json(validation_outputs[f"{validation_root}/report.json"])
        self.assertEqual(
            requested,
            {row["stable_id"] for row in report["findings"] if row["severity"] == "ERROR"},
        )
        decisions = []
        for row in editorial_packet.rows:
            if row.stable_id not in requested:
                continue
            target = parse_canonical_json(row._target_bytes)
            constraints = strict_loads(row._constraints_bytes)
            placeholder = constraints.get("placeholder")
            data = dict(target["data"])
            if isinstance(placeholder, str) and placeholder != "none" and placeholder not in data["payload"]:
                data["payload"] = f"{data['payload']} {placeholder}"
            data["metadata_ref"] = None
            target = dict(target)
            target["data"] = data
            decisions.append({
                "identity": row.identity.as_dict(),
                "action": "CORRECT",
                "reason_code": "VALIDATION_FINDING_FIXED",
                "target": target,
            })
        raw_output = canonical_json_bytes({
            "contract": "locpipe.editorial.provider-output/v0",
            "decisions": decisions,
        })
        receipt = EditorialSubmissionReceiptV0(
            editorial_job.job_id, editorial_job.invocation_id, editorial_job.provider,
            "validation-rework", editorial_job.packet_sha256,
            editorial_job.output_contract_sha256, raw_sha256(raw_output),
        )
        inputs_rows = validation_editorial_acceptance_inputs_v0(
            fixture["translation_job"], fixture["translation_packet"],
            fixture["translation_decision_bytes"], fixture["translation_state_bytes"],
            fixture["translation_target_set"], editorial_job, editorial_packet,
            fixture["editorial_policy"], fixture["candidate"], fixture["candidate_evidence"],
            fixture["job"], fixture["packet"], validation_outputs[f"{validation_root}/report.json"],
            validation_outputs[f"{validation_root}/state.json"],
            validation_outputs[f"{validation_root}/rework_request.json"], trigger_bytes, receipt, raw_output,
        )
        implementation, handler = bind_validation_editorial_acceptance_v0(
            fixture["context"], fixture["resolved"], fixture["translation_job"],
            fixture["translation_packet"], fixture["translation_decision_bytes"],
            fixture["translation_state_bytes"], fixture["translation_target_set"],
            fixture["editorial_policy"], fixture["candidate"], fixture["candidate_evidence"],
            fixture["editorial_job"], fixture["editorial_packet"], fixture["job"], fixture["packet"],
            validation_outputs[f"{validation_root}/report.json"],
            validation_outputs[f"{validation_root}/state.json"],
            validation_outputs[f"{validation_root}/rework_request.json"],
            editorial_job, editorial_packet, trigger_bytes, receipt, raw_output,
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
            module_binding = binding(fixture["adapter"], editorial_job.module)
            request = OperationRequestV0(
                "validation-editorial", Capability.EDITORIAL_REVIEW, semantic_sha256(module_binding),
                tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in inputs_rows),
                editorial_acceptance_output_declarations_v0(editorial_job),
            )
            editorial_result = execute_bound_operation(
                request.as_envelope(), module_binding, handlers={implementation: handler},
                input_root=inputs, staging_root=staging,
            )
            self.assertEqual("PASS", editorial_result["data"]["status"])
            eroot = editorial_job_root_v0(editorial_job)
            terminal = {
                declaration.path: (staging / Path(*declaration.path.split("/"))).read_bytes()
                for declaration in editorial_acceptance_output_declarations_v0(editorial_job)
            }
        corrected = parse_editorial_candidate_v0(terminal[f"{eroot}/candidate_set.json"])
        corrected_evidence = tuple(sorted((
            (f"{eroot}/job.json", canonical_json_bytes(editorial_job.as_dict())),
            (f"{eroot}/packet.json", canonical_json_bytes(editorial_packet.as_dict())),
            (f"{eroot}/parent_candidate.json", canonical_json_bytes(fixture["candidate"].as_dict())),
            (f"{eroot}/policy.json", canonical_json_bytes(fixture["editorial_policy"].as_dict())),
            (validation_editorial_trigger_path_v0(fixture["job"]), trigger_bytes),
            *terminal.items(),
        )))
        authority = dict(fixture["authority"])
        next_job, next_packet, next_authority = build_content_validation_job_v0(
            fixture["context"], fixture["resolved"], fixture["scope"], fixture["translation_job"],
            fixture["translation_packet"], fixture["translation_decision_bytes"],
            fixture["translation_state_bytes"], fixture["translation_target_set"], corrected,
            fixture["validator"], source_lock_bytes=authority["source/source_lock.json"],
            reconciliation_bytes=authority["reconciliation/reconciliation.json"],
            scope_bytes=authority["scope/scope.json"], scope_lock_bytes=authority["scope/scope_lock.json"],
            segments_bytes=authority["corpus/segments.jsonl"], candidate_evidence=corrected_evidence,
            editorial_job=editorial_job, editorial_packet=editorial_packet,
            editorial_policy=fixture["editorial_policy"],
        )
        result, outputs = run_validation({
            "job": next_job, "packet": next_packet, "validator": fixture["validator"],
            "authority": next_authority, "adapter": fixture["adapter"],
        })
        self.assertEqual("PASS", result["data"]["status"])
        self.assertEqual(
            "LOCALE_VERIFIED",
            parse_canonical_json(outputs[f"{validation_job_root_v0(next_job)}/state.json"])["status"],
        )

    def test_rework_state_allows_two_rounds_but_never_a_third(self) -> None:
        fixture = validation_fixture()
        row = next(row for row in fixture["packet"].rows if row.role == "OWNED")
        finding = ContentFindingV0(
            row.stable_id, "synthetic", FindingSeverityV0.ERROR, "BLOCKING", "8" * 64,
        )
        states = []
        for round_index in (0, 1, 2):
            job = replace(fixture["job"], editorial_round_index=round_index)
            artifacts = dict(content_validation_terminal_artifacts_v0(job, (finding,)))
            states.append(parse_canonical_json(artifacts[f"{validation_job_root_v0(job)}/state.json"])["status"])
        self.assertEqual(["REWORK_REQUIRED", "REWORK_REQUIRED", "REWORK_EXHAUSTED"], states)

    def test_malformed_unordered_foreign_and_drifting_validator_outputs_fail_closed(self) -> None:
        for mode in ("list", "unordered", "foreign", "descriptor-drift"):
            fixture = validation_fixture()
            fixture["validator"] = AdversarialContentValidatorV0(mode)
            result, outputs = run_validation(fixture)
            self.assertEqual("FAIL", result["data"]["status"], mode)
            self.assertEqual({}, outputs, mode)

    def test_stale_source_and_forged_candidate_authority_fail_before_handler(self) -> None:
        fixture = validation_fixture()
        authority = dict(fixture["authority"])

        def build(candidate, candidate_evidence, segments):
            return build_content_validation_job_v0(
                fixture["context"], fixture["resolved"], fixture["scope"], fixture["translation_job"],
                fixture["translation_packet"], fixture["translation_decision_bytes"],
                fixture["translation_state_bytes"], fixture["translation_target_set"], candidate,
                fixture["validator"], source_lock_bytes=authority["source/source_lock.json"],
                reconciliation_bytes=authority["reconciliation/reconciliation.json"],
                scope_bytes=authority["scope/scope.json"], scope_lock_bytes=authority["scope/scope_lock.json"],
                segments_bytes=segments, candidate_evidence=candidate_evidence,
                editorial_job=fixture["editorial_job"], editorial_packet=fixture["editorial_packet"],
                editorial_policy=fixture["editorial_policy"],
            )

        with self.assertRaisesRegex(Exception, "segments differ"):
            build(
                fixture["candidate"], fixture["candidate_evidence"],
                authority["corpus/segments.jsonl"] + b"\n",
            )
        current = fixture["candidate"]
        forged = EditorialCandidateSetV0(
            current.job_id, current.target_locale, True, current.disposition,
            current.base_target_set_sha256, current.parent_candidate_sha256,
            current.overlay_sha256s, (), current._target_bytes[:-1],
        )
        with self.assertRaisesRegex(Exception, "authority|candidate"):
            build(forged, fixture["candidate_evidence"], authority["corpus/segments.jsonl"])

        candidate_doc = deepcopy(current.as_dict())
        candidate_doc["targets"][0]["data"]["payload"] += " forged outside overlay"
        candidate_bytes = canonical_json_bytes(candidate_doc)
        internally_bound = parse_editorial_candidate_v0(candidate_bytes)
        evidence = dict(fixture["candidate_evidence"])
        eroot = editorial_job_root_v0(fixture["editorial_job"])
        rework_path = f"{eroot}/rework_request.json"
        state_path = f"{eroot}/state.json"
        candidate_path = f"{eroot}/candidate_set.json"
        rework_doc = parse_canonical_json(evidence[rework_path])
        rework_doc["candidate_sha256"] = raw_sha256(candidate_bytes)
        rework_bytes = canonical_json_bytes(rework_doc)
        state_doc = parse_canonical_json(evidence[state_path])
        state_doc["candidate_sha256"] = raw_sha256(candidate_bytes)
        state_doc["rework_request_sha256"] = raw_sha256(rework_bytes)
        evidence[candidate_path] = candidate_bytes
        evidence[rework_path] = rework_bytes
        evidence[state_path] = canonical_json_bytes(state_doc)
        with self.assertRaisesRegex(Exception, "parent plus overlay"):
            build(internally_bound, tuple(sorted(evidence.items())), authority["corpus/segments.jsonl"])

    def test_terminal_publication_crash_rolls_back_exact_absent_preimage(self) -> None:
        fixture = validation_fixture(locales=("uk",))
        result, outputs = run_validation(fixture)
        with tempfile.TemporaryDirectory() as directory:
            store_root = Path(directory) / "store"
            store_root.mkdir()
            store = SyntheticTransactionStoreV0.create(store_root)
            paths = initialize_project_context(store, fixture["context"])
            lease = acquire_context_write_lease(
                store, fixture["context"], "validation-crash", owner_token_factory=lambda: "e" * 32,
            )

            def crash(point):
                if point == "AFTER_GROUP_ARTIFACT_REPLACED:0001":
                    raise InjectedValidationCrash(point)

            with self.assertRaises(InjectedValidationCrash):
                publish_content_validation_group_v0(
                    store, fixture["context"], fixture["job"], "validation-crash",
                    tuple(sorted(outputs.items())), lease, operation_result=result,
                    clock=lambda: "2026-08-10T00:00:03.000Z", _failure_hook=crash,
                )
            plan = inspect_context_group_recovery(store, fixture["context"], "validation-crash")
            self.assertEqual(RecoveryDispositionV0.ROLLBACK_REQUIRED, plan.disposition)
            rollback_context_group(
                store, fixture["context"], plan, lease,
                clock=lambda: "2026-08-10T00:00:04.000Z",
            )
            release_context_write_lease(store, fixture["context"], lease)
            for relative in outputs:
                self.assertFalse((paths.outputs_root / Path(*relative.split("/"))).exists())


if __name__ == "__main__":
    unittest.main()
