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
    Capability,
    KIND_TO_SCHEMA,
    ModuleDescriptorV0,
    OperationRequestV0,
    WorkflowProfile,
    canonical_json_bytes,
    display_id,
    execute_bound_operation,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
)
from locpipe.contracts.v0.constants import CONTRACT_VERSION  # noqa: E402
from locpipe.kernel.v0.context import ProjectContextV0  # noqa: E402
from locpipe.kernel.v0.transactions import NamespaceV0  # noqa: E402
from locpipe.translation.v0 import (  # noqa: E402
    ProviderSubmissionReceiptV0,
    TranslationJobStatusV0,
    TranslationStateV0,
    bind_translation_acceptance_v0,
    submission_digest_v0,
    translation_acceptance_output_declarations_v0,
    translation_job_root_v0,
    translation_submission_root_v0,
)
from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402
from tests.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0  # noqa: E402
from tests.test_translation_packet_v0 import FIXTURES, build_fixture  # noqa: E402


MODULE_SHA = "d" * 64


def binding(adapter, module):
    return {
        "schema_id": "urn:locpipe:contracts:v0:binding",
        "schema_version": CONTRACT_VERSION,
        "kind": "binding_set",
        "data": {
            "adapter": {
                "adapter_id": adapter.descriptor.adapter_id,
                "version": adapter.descriptor.version,
                "digest": adapter.descriptor.digest,
                "capabilities": [row.value for row in adapter.descriptor.capabilities],
            },
            "modules": [{
                "capability": module.capability.value,
                "module_id": module.module_id,
                "version": module.version,
                "digest": module.digest,
            }],
        },
    }


def provider_output(
    job,
    packet,
    *,
    omit_last=False,
    extra=False,
    locale=None,
    duplicate=False,
    include_context=False,
    content_type=None,
):
    targets = []
    owned = [row for row in packet.rows if row.role.value == "OWNED"]
    if omit_last:
        owned = owned[:-1]
    for row in owned:
        identity = {
            "logical_id": list(row.identity.logical_id),
            "locale": locale or job.target_locale,
            "selector_path": [step.as_dict() for step in row.identity.selector_path],
        }
        targets.append({
            "schema_id": KIND_TO_SCHEMA["target_branch"],
            "schema_version": CONTRACT_VERSION,
            "kind": "target_branch",
            "data": {
                "identity": identity,
                "source_logical_id": list(row.identity.logical_id),
                "content_type": content_type or row.content_type,
                "payload": f"translated:{display_id(row.identity)}",
                "metadata_ref": None,
            },
        })
    if duplicate and targets:
        targets.append(dict(targets[0]))
    if include_context:
        row = next(row for row in packet.rows if row.role.value == "CONTEXT")
        targets.append({
            "schema_id": KIND_TO_SCHEMA["target_branch"],
            "schema_version": CONTRACT_VERSION,
            "kind": "target_branch",
            "data": {
                "identity": {
                    "logical_id": list(row.identity.logical_id),
                    "locale": job.target_locale,
                    "selector_path": [step.as_dict() for step in row.identity.selector_path],
                },
                "source_logical_id": list(row.identity.logical_id),
                "content_type": row.content_type,
                "payload": "context-must-not-be-translated",
                "metadata_ref": None,
            },
        })
    if extra:
        targets.append({
            "schema_id": KIND_TO_SCHEMA["target_branch"],
            "schema_version": CONTRACT_VERSION,
            "kind": "target_branch",
            "data": {
                "identity": {"logical_id": ["extra"], "locale": job.target_locale, "selector_path": []},
                "source_logical_id": ["extra"],
                "content_type": "text",
                "payload": "extra",
                "metadata_ref": None,
            },
        })
    targets.sort(key=lambda row: display_id(__import__("locpipe.contracts.v0", fromlist=["BranchIdentity"]).BranchIdentity.from_dict(row["data"]["identity"])))
    return canonical_json_bytes({"contract": "locpipe.translation.provider-output/v0", "targets": targets})


def run_acceptance(
    name,
    adapter,
    raw_output_factory,
    *,
    receipt_mutator=None,
    owned_count=None,
    artifact_mutator=None,
):
    resolved, corpus, scope, job, packet = build_fixture(name, adapter, owned_count=owned_count)
    context = ProjectContextV0(
        NamespaceV0("workspace", "fixture", "release"),
        WorkflowProfile.CONTENT_ONLY,
        resolved.config_snapshot_sha256,
    )
    raw_output = raw_output_factory(job, packet)
    receipt = ProviderSubmissionReceiptV0(
        job.job_id,
        job.invocation_id,
        job.provider,
        "manual-request-1",
        job.packet_sha256,
        job.output_contract_sha256,
        raw_sha256(raw_output),
    )
    if receipt_mutator is not None:
        receipt = receipt_mutator(receipt)
    submission_sha = submission_digest_v0(receipt)
    state = TranslationStateV0(job.job_id, job.invocation_id, TranslationJobStatusV0.RECEIVED, submission_sha)
    selection = {
        "contract": "locpipe.translation.selection/v0",
        "job_id": job.job_id,
        "invocation_id": job.invocation_id,
        "submission_sha256": submission_sha,
    }
    golden = FIXTURES / name / "golden"
    reconciliation = reconcile_sources_v0(corpus)
    source_lock = canonical_json_bytes(corpus.lock.as_dict())
    reconciliation_bytes = canonical_json_bytes(reconciliation.as_dict())
    scope_artifacts = dict(frozen_scope_artifacts_v0(scope))
    root = translation_job_root_v0(job)
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        inputs = temp / "inputs"
        staging = temp / "staging"
        inputs.mkdir()
        staging.mkdir()
        artifacts = {
            "corpus/source_snapshot.json": (golden / "source_snapshot.json").read_bytes(),
            "corpus/segments.jsonl": (golden / "segments.jsonl").read_bytes(),
            "source/source_lock.json": source_lock,
            "reconciliation/reconciliation.json": reconciliation_bytes,
            "scope/scope.json": scope_artifacts["scope/scope.json"],
            "scope/scope_lock.json": scope_artifacts["scope/scope_lock.json"],
            f"{root}/job.json": canonical_json_bytes(job.as_dict()),
            f"{root}/packet.json": canonical_json_bytes(packet.as_dict()),
            f"{root}/selection.json": canonical_json_bytes(selection),
            f"{root}/state.json": canonical_json_bytes(state.as_dict()),
            f"{translation_submission_root_v0(receipt)}/output.json": raw_output,
            f"{translation_submission_root_v0(receipt)}/receipt.json": canonical_json_bytes(receipt.as_dict()),
        }
        if (golden / "relations.jsonl").is_file():
            artifacts["corpus/relations.jsonl"] = (golden / "relations.jsonl").read_bytes()
        if artifact_mutator is not None:
            artifact_mutator(artifacts, root)
        for relative, payload in artifacts.items():
            path = inputs / Path(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        module = ModuleDescriptorV0(Capability.TRANSLATION, "locpipe.translation", "0.1.0", MODULE_SHA)
        binding_set = binding(adapter, module)
        request = OperationRequestV0(
            "translation-acceptance",
            Capability.TRANSLATION,
            semantic_sha256(binding_set),
            tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in sorted(artifacts.items())),
            translation_acceptance_output_declarations_v0(job),
        )
        implementation, handler = bind_translation_acceptance_v0(module, context, resolved, job, packet)
        result = execute_bound_operation(
            request.as_envelope(),
            binding_set,
            handlers={implementation: handler},
            input_root=inputs,
            staging_root=staging,
        )
        outputs = {}
        for declaration in translation_acceptance_output_declarations_v0(job):
            path = staging / Path(*declaration.path.split("/"))
            if path.is_file():
                outputs[declaration.path] = path.read_bytes()
        return result, outputs, job


class TranslationAcceptanceV0Tests(unittest.TestCase):
    def test_flat_and_structured_exact_outputs_are_accepted(self) -> None:
        for name, adapter in (("flat", SyntheticFlatAdapterV0()), ("structured", SyntheticStructuredAdapterV0())):
            result, outputs, job = run_acceptance(name, adapter, provider_output)
            self.assertEqual("PASS", result["data"]["status"])
            state = parse_canonical_json(outputs[f"{translation_job_root_v0(job)}/state.json"])
            target_set = parse_canonical_json(outputs[f"{translation_job_root_v0(job)}/target_set.json"])
            self.assertEqual("ACCEPTED", state["status"])
            self.assertGreater(len(target_set["targets"]), 0)
            self.assertTrue(all(row["data"]["metadata_ref"].endswith("/decision.json") for row in target_set["targets"]))

    def test_well_bound_missing_extra_and_cross_locale_are_domain_rejected(self) -> None:
        cases = (
            (lambda job, packet: provider_output(job, packet, omit_last=True), "MISSING_TARGET"),
            (lambda job, packet: provider_output(job, packet, extra=True), "EXTRA_OR_SELECTOR_DRIFT"),
            (lambda job, packet: provider_output(job, packet, locale="pl"), "TARGET_LOCALE_MISMATCH"),
        )
        for factory, reason in cases:
            result, outputs, job = run_acceptance("flat", SyntheticFlatAdapterV0(), factory)
            self.assertEqual("PASS", result["data"]["status"])
            decision = parse_canonical_json(outputs[f"{translation_job_root_v0(job)}/decision.json"])
            target_set = parse_canonical_json(outputs[f"{translation_job_root_v0(job)}/target_set.json"])
            self.assertEqual("REJECTED", decision["status"])
            self.assertEqual(reason, decision["reason_code"])
            self.assertEqual([], target_set["targets"])

    def test_duplicate_context_content_type_and_malformed_outputs_are_rejected(self) -> None:
        cases = (
            (lambda job, packet: provider_output(job, packet, duplicate=True), "DUPLICATE_TARGET", None),
            (lambda job, packet: provider_output(job, packet, include_context=True), "CONTEXT_TARGET", 1),
            (lambda job, packet: provider_output(job, packet, content_type="wrong"), "CONTENT_TYPE_MISMATCH", None),
            (lambda _job, _packet: b"{", "MALFORMED_PROVIDER_OUTPUT", None),
        )
        for factory, reason, owned_count in cases:
            result, outputs, job = run_acceptance(
                "flat", SyntheticFlatAdapterV0(), factory, owned_count=owned_count
            )
            self.assertEqual("PASS", result["data"]["status"])
            decision = parse_canonical_json(outputs[f"{translation_job_root_v0(job)}/decision.json"])
            self.assertEqual("REJECTED", decision["status"])
            self.assertEqual(reason, decision["reason_code"])

    def test_foreign_receipt_fails_without_terminal_outputs(self) -> None:
        def foreign(receipt):
            return ProviderSubmissionReceiptV0(
                "foreign-job", receipt.invocation_id, receipt.provider, receipt.provider_request_id,
                receipt.packet_sha256, receipt.output_contract_sha256, receipt.raw_output_sha256,
            )
        result, outputs, _job = run_acceptance("flat", SyntheticFlatAdapterV0(), provider_output, receipt_mutator=foreign)
        self.assertEqual("FAIL", result["data"]["status"])
        self.assertEqual({}, outputs)

    def test_receipt_sha_and_packet_substitution_fail_without_terminal_outputs(self) -> None:
        def wrong_sha(receipt):
            return ProviderSubmissionReceiptV0(
                receipt.job_id, receipt.invocation_id, receipt.provider, receipt.provider_request_id,
                receipt.packet_sha256, receipt.output_contract_sha256, "e" * 64,
            )

        result, outputs, _job = run_acceptance(
            "flat", SyntheticFlatAdapterV0(), provider_output, receipt_mutator=wrong_sha
        )
        self.assertEqual("FAIL", result["data"]["status"])
        self.assertEqual({}, outputs)

        def replace_packet(artifacts, root):
            packet = parse_canonical_json(artifacts[f"{root}/packet.json"])
            packet["target_locale"] = "pl"
            artifacts[f"{root}/packet.json"] = canonical_json_bytes(packet)

        result, outputs, _job = run_acceptance(
            "flat", SyntheticFlatAdapterV0(), provider_output, artifact_mutator=replace_packet
        )
        self.assertEqual("FAIL", result["data"]["status"])
        self.assertEqual({}, outputs)


if __name__ == "__main__":
    unittest.main()
