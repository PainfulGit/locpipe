from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.content.v0 import frozen_scope_artifacts_v0, reconcile_sources_v0  # noqa: E402
from locpipe.contracts.v0 import (  # noqa: E402
    ArtifactHashV0,
    BranchIdentity,
    Capability,
    ModuleDescriptorV0,
    OperationRequestV0,
    WorkflowProfile,
    canonical_json_bytes,
    execute_bound_operation,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
    strict_loads,
)
from locpipe.editorial.v0 import (  # noqa: E402
    EditorialPolicyV0,
    EditorialSubmissionReceiptV0,
    bind_editorial_acceptance_v0,
    build_editorial_job_v0,
    editorial_acceptance_output_declarations_v0,
    editorial_job_root_v0,
    editorial_submission_digest_v0,
    editorial_submission_root_v0,
    parse_editorial_candidate_v0,
)
from locpipe.editorial.v0._evidence import EditorialStateV0  # noqa: E402
from locpipe.editorial.v0._models import EditorialJobStatusV0  # noqa: E402
from locpipe.kernel.v0.context import ProjectContextV0  # noqa: E402
from locpipe.kernel.v0.transactions import NamespaceV0  # noqa: E402
from locpipe.translation.v0 import (  # noqa: E402
    ProviderBudgetV0,
    ProviderSubmissionReceiptV0,
    TranslationJobStatusV0,
    TranslationStateV0,
    TranslationTargetSetV0,
    bind_translation_acceptance_v0,
    submission_digest_v0,
    translation_acceptance_output_declarations_v0,
    translation_job_root_v0,
    translation_submission_root_v0,
)
from locpipe.validation.v0 import (  # noqa: E402
    build_content_validation_job_v0,
    content_locale_receipt_v0,
    finalize_content_verified_v0,
    validation_job_root_v0,
)
from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402
from tests.conformance.adapter_v0.runner import run_public_fixture_v0  # noqa: E402
from tests.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0  # noqa: E402
from tests.test_content_validation_v0 import (  # noqa: E402
    SyntheticContentValidatorV0,
    publish_validation_evidence,
    run_validation,
    validation_layers,
)
from tests.test_editorial_acceptance_v0 import editorial_output  # noqa: E402
from tests.test_translation_acceptance_v0 import binding, provider_output  # noqa: E402
from tests.test_translation_packet_v0 import FIXTURES, build_fixture  # noqa: E402


def _module(resolved, capability: Capability) -> ModuleDescriptorV0:
    rows = [row for row in resolved.get_value("module_bindings") if row["capability"] == capability.value]
    if len(rows) != 1:
        raise AssertionError(f"missing module binding: {capability.value}")
    row = rows[0]
    return ModuleDescriptorV0(capability, row["module_id"], row["version"], row["digest"])


def _write_inputs(root: Path, rows: dict[str, bytes]) -> None:
    for relative, payload in rows.items():
        path = root / Path(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def _real_translation(name, adapter, context, resolved, corpus, scope, job, packet):
    raw_value = parse_canonical_json(provider_output(job, packet))
    sources = {(row.identity.logical_id, row.identity.selector_path): row for row in packet.rows}
    targets = []
    for target in raw_value["targets"]:
        identity = BranchIdentity.from_dict(target["data"]["identity"])
        source = sources[(identity.logical_id, identity.selector_path)]
        constraints = strict_loads(source._constraints_bytes)
        placeholder = constraints.get("placeholder")
        selected = dict(target)
        data = dict(selected["data"])
        if isinstance(placeholder, str) and placeholder != "none" and placeholder not in data["payload"]:
            data["payload"] = f"{data['payload']} {placeholder}"
        selected["data"] = data
        targets.append(selected)
    raw_output = canonical_json_bytes({"contract": raw_value["contract"], "targets": targets})
    receipt = ProviderSubmissionReceiptV0(
        job.job_id, job.invocation_id, job.provider, f"{name}-translation",
        job.packet_sha256, job.output_contract_sha256, raw_sha256(raw_output),
    )
    submission_sha = submission_digest_v0(receipt)
    received = TranslationStateV0(job.job_id, job.invocation_id, TranslationJobStatusV0.RECEIVED, submission_sha)
    selection = canonical_json_bytes({
        "contract": "locpipe.translation.selection/v0",
        "job_id": job.job_id,
        "invocation_id": job.invocation_id,
        "submission_sha256": submission_sha,
    })
    reconciliation = reconcile_sources_v0(corpus)
    source_lock = canonical_json_bytes(corpus.lock.as_dict())
    reconciliation_bytes = canonical_json_bytes(reconciliation.as_dict())
    scope_artifacts = dict(frozen_scope_artifacts_v0(scope))
    golden = FIXTURES / name / "golden"
    root = translation_job_root_v0(job)
    submission_root = translation_submission_root_v0(receipt)
    artifacts = {
        "corpus/source_snapshot.json": (golden / "source_snapshot.json").read_bytes(),
        "corpus/segments.jsonl": (golden / "segments.jsonl").read_bytes(),
        "source/source_lock.json": source_lock,
        "reconciliation/reconciliation.json": reconciliation_bytes,
        "scope/scope.json": scope_artifacts["scope/scope.json"],
        "scope/scope_lock.json": scope_artifacts["scope/scope_lock.json"],
        f"{root}/job.json": canonical_json_bytes(job.as_dict()),
        f"{root}/packet.json": canonical_json_bytes(packet.as_dict()),
        f"{root}/selection.json": selection,
        f"{root}/state.json": canonical_json_bytes(received.as_dict()),
        f"{submission_root}/output.json": raw_output,
        f"{submission_root}/receipt.json": canonical_json_bytes(receipt.as_dict()),
    }
    if (golden / "relations.jsonl").is_file():
        artifacts["corpus/relations.jsonl"] = (golden / "relations.jsonl").read_bytes()
    module = _module(resolved, Capability.TRANSLATION)
    module_binding = binding(adapter, module)
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        inputs = temp / "inputs"
        staging = temp / "staging"
        inputs.mkdir()
        staging.mkdir()
        _write_inputs(inputs, artifacts)
        request = OperationRequestV0(
            "translation-e2e", Capability.TRANSLATION, semantic_sha256(module_binding),
            tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in sorted(artifacts.items())),
            translation_acceptance_output_declarations_v0(job),
        )
        implementation, handler = bind_translation_acceptance_v0(module, context, resolved, job, packet)
        result = execute_bound_operation(
            request.as_envelope(), module_binding, handlers={implementation: handler},
            input_root=inputs, staging_root=staging,
        )
        if result["data"]["status"] != "PASS":
            raise AssertionError(result)
        outputs = {
            row.path: (staging / Path(*row.path.split("/"))).read_bytes()
            for row in translation_acceptance_output_declarations_v0(job)
        }
    target_value = parse_canonical_json(outputs[f"{root}/target_set.json"])
    target_set = TranslationTargetSetV0(
        target_value["job_id"], target_value["invocation_id"], target_value["target_locale"],
        tuple(canonical_json_bytes(row) for row in target_value["targets"]),
    )
    return outputs[f"{root}/decision.json"], outputs[f"{root}/state.json"], target_set, artifacts


def _real_editorial(adapter, context, resolved, translation_job, translation_packet, decision, state, target_set):
    policy = EditorialPolicyV0(2)
    job, packet, parent = build_editorial_job_v0(
        context, resolved, translation_job, translation_packet, decision, target_set, state, policy,
        budget=ProviderBudgetV0(None, None),
    )
    raw_output = editorial_output(job, packet)
    receipt = EditorialSubmissionReceiptV0(
        job.job_id, job.invocation_id, job.provider, "editorial-e2e",
        job.packet_sha256, job.output_contract_sha256, raw_sha256(raw_output),
    )
    submission_sha = editorial_submission_digest_v0(receipt)
    received = EditorialStateV0(job.job_id, job.invocation_id, EditorialJobStatusV0.RECEIVED, submission_sha)
    selection = canonical_json_bytes({
        "contract": "locpipe.editorial.selection/v0", "job_id": job.job_id,
        "invocation_id": job.invocation_id, "submission_sha256": submission_sha,
    })
    troot = translation_job_root_v0(translation_job)
    eroot = editorial_job_root_v0(job)
    sroot = editorial_submission_root_v0(receipt)
    artifacts = {
        f"{troot}/job.json": canonical_json_bytes(translation_job.as_dict()),
        f"{troot}/packet.json": canonical_json_bytes(translation_packet.as_dict()),
        f"{troot}/decision.json": decision,
        f"{troot}/state.json": state,
        f"{troot}/target_set.json": canonical_json_bytes(target_set.as_dict()),
        f"{eroot}/job.json": canonical_json_bytes(job.as_dict()),
        f"{eroot}/packet.json": canonical_json_bytes(packet.as_dict()),
        f"{eroot}/parent_candidate.json": canonical_json_bytes(parent.as_dict()),
        f"{eroot}/policy.json": canonical_json_bytes(policy.as_dict()),
        f"{eroot}/selection.json": selection,
        f"{eroot}/state.json": canonical_json_bytes(received.as_dict()),
        f"{sroot}/output.json": raw_output,
        f"{sroot}/receipt.json": canonical_json_bytes(receipt.as_dict()),
    }
    module_binding = binding(adapter, job.module)
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        inputs = temp / "inputs"
        staging = temp / "staging"
        inputs.mkdir()
        staging.mkdir()
        _write_inputs(inputs, artifacts)
        request = OperationRequestV0(
            "editorial-e2e", Capability.EDITORIAL_REVIEW, semantic_sha256(module_binding),
            tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in sorted(artifacts.items())),
            editorial_acceptance_output_declarations_v0(job),
        )
        implementation, handler = bind_editorial_acceptance_v0(
            job.module, context, resolved, job, packet, policy, parent,
            translation_job, translation_packet, decision, target_set, state,
        )
        result = execute_bound_operation(
            request.as_envelope(), module_binding, handlers={implementation: handler},
            input_root=inputs, staging_root=staging,
        )
        if result["data"]["status"] != "PASS":
            raise AssertionError(result)
        terminal = {
            row.path: (staging / Path(*row.path.split("/"))).read_bytes()
            for row in editorial_acceptance_output_declarations_v0(job)
        }
    candidate = parse_editorial_candidate_v0(terminal[f"{eroot}/candidate_set.json"])
    evidence = tuple(sorted((
        (f"{eroot}/job.json", canonical_json_bytes(job.as_dict())),
        (f"{eroot}/packet.json", canonical_json_bytes(packet.as_dict())),
        (f"{eroot}/parent_candidate.json", canonical_json_bytes(parent.as_dict())),
        (f"{eroot}/policy.json", canonical_json_bytes(policy.as_dict())),
        *terminal.items(),
    )))
    return job, packet, policy, candidate, evidence


class ContentLifecycleSlice04Tests(unittest.TestCase):
    def test_flat_and_structured_real_handlers_reach_content_verified(self) -> None:
        for name, adapter in (("flat", SyntheticFlatAdapterV0()), ("structured", SyntheticStructuredAdapterV0())):
            conformance = run_public_fixture_v0(FIXTURES / name, adapter)
            layers = validation_layers(locales=("uk",))
            resolved, corpus, scope, translation_job, translation_packet = build_fixture(
                name, adapter, selected_layers=layers, target_locale="uk",
            )
            context = ProjectContextV0(
                NamespaceV0("workspace", "fixture", "release"),
                WorkflowProfile.CONTENT_ONLY, resolved.config_snapshot_sha256,
            )
            decision, translation_state, target_set, translation_inputs = _real_translation(
                name, adapter, context, resolved, corpus, scope, translation_job, translation_packet,
            )
            editorial_job, editorial_packet, policy, candidate, candidate_evidence = _real_editorial(
                adapter, context, resolved, translation_job, translation_packet,
                decision, translation_state, target_set,
            )
            validator = SyntheticContentValidatorV0()
            validation_job, validation_packet, authority = build_content_validation_job_v0(
                context, resolved, scope, translation_job, translation_packet, decision,
                translation_state, target_set, candidate, validator,
                source_lock_bytes=translation_inputs["source/source_lock.json"],
                reconciliation_bytes=translation_inputs["reconciliation/reconciliation.json"],
                scope_bytes=translation_inputs["scope/scope.json"],
                scope_lock_bytes=translation_inputs["scope/scope_lock.json"],
                segments_bytes=translation_inputs["corpus/segments.jsonl"],
                candidate_evidence=candidate_evidence, editorial_job=editorial_job,
                editorial_packet=editorial_packet, editorial_policy=policy,
            )
            result, outputs = run_validation({
                "job": validation_job, "packet": validation_packet, "validator": validator,
                "authority": authority, "adapter": adapter,
            })
            self.assertEqual("PASS", result["data"]["status"])
            root = validation_job_root_v0(validation_job)
            self.assertEqual(
                "LOCALE_VERIFIED", parse_canonical_json(outputs[f"{root}/state.json"])["status"], name,
            )
            validation_publication, validation_store, validation_temporary = publish_validation_evidence(
                {"job": validation_job, "context": context}, result, outputs,
            )
            receipt = content_locale_receipt_v0(
                validation_job, outputs[f"{root}/report.json"], outputs[f"{root}/state.json"],
                outputs[f"{root}/rework_request.json"],
                store=validation_store, context=context, operation_result=result,
                validation_publication_receipt=validation_publication,
            )
            verification, state = finalize_content_verified_v0(
                scope, (receipt,), validation_evidence=((
                    validation_job, outputs[f"{root}/report.json"], outputs[f"{root}/state.json"],
                    outputs[f"{root}/rework_request.json"], result, validation_publication,
                    validation_store, context,
                ),),
            )
            validation_temporary.cleanup()
            self.assertEqual("CONTENT_VERIFIED", parse_canonical_json(state)["state"])
            self.assertEqual("uk", verification.locale_receipts[0].target_locale)
            self.assertEqual(
                conformance["output_hashes"]["segments.jsonl"],
                raw_sha256(translation_inputs["corpus/segments.jsonl"]),
            )


if __name__ == "__main__":
    unittest.main()
