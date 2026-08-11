from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.adapters.v0 import adapter_output_declarations_v0, bind_read_only_adapter_v0  # noqa: E402
from locpipe.content.v0 import (  # noqa: E402
    ScopeEntryV0,
    ScopeRoleV0,
    bind_source_reconciliation_v0,
    bind_source_snapshot_v0,
    freeze_scope_v0,
    frozen_scope_artifacts_v0,
    load_accepted_source_corpus_v0,
    load_source_corpus_v0,
    reconcile_sources_v0,
    source_lock_output_declarations_v0,
    source_reconciliation_output_declarations_v0,
)
from locpipe.contracts.v0 import (  # noqa: E402
    ArtifactHashV0,
    Capability,
    ModuleDescriptorV0,
    OperationRequestV0,
    WorkflowProfile,
    canonical_json_bytes,
    execute_bound_operation,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
)
from locpipe.kernel.v0.context import (  # noqa: E402
    ProjectContextV0,
    acquire_context_write_lease,
    initialize_project_context,
)
from locpipe.kernel.v0.context_transactions import (  # noqa: E402
    create_context_staging,
    publish_context_file,
    publish_context_group,
    release_context_write_lease,
)
from locpipe.kernel.v0.transactions import (  # noqa: E402
    NamespaceV0,
    PublicationEntryV0,
    PublicationGroupSpecV0,
    PublicationSpecV0,
    SyntheticTransactionStoreV0,
)
from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402


CONFIG_SHA = "c" * 64
SOURCE_MODULE_SHA = "d" * 64
RECONCILE_MODULE_SHA = "e" * 64
OWNER = "8" * 32


def adapter_data(descriptor) -> dict[str, object]:
    return {
        "adapter_id": descriptor.adapter_id,
        "version": descriptor.version,
        "digest": descriptor.digest,
        "capabilities": [capability.value for capability in descriptor.capabilities],
    }


def binding(descriptor, module: ModuleDescriptorV0 | None = None) -> dict[str, object]:
    modules = [] if module is None else [{
        "capability": module.capability.value,
        "module_id": module.module_id,
        "version": module.version,
        "digest": module.digest,
    }]
    return {
        "schema_id": "urn:locpipe:contracts:v0:binding",
        "schema_version": "0.1.0-draft.2",
        "kind": "binding_set",
        "data": {"adapter": adapter_data(descriptor), "modules": modules},
    }


class ContentLifecycleSlice01Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        store_root = self.root / "store"
        store_root.mkdir()
        self.store = SyntheticTransactionStoreV0.create(store_root)
        self.context = ProjectContextV0(
            NamespaceV0("workspace", "synthetic-flat", "release-1"),
            WorkflowProfile.CONTENT_ONLY,
            CONFIG_SHA,
        )
        self.paths = initialize_project_context(self.store, self.context)
        self.adapter = SyntheticFlatAdapterV0()

    def publish_group(self, operation: str, artifacts: tuple[tuple[str, bytes], ...]) -> None:
        lease = acquire_context_write_lease(self.store, self.context, operation, owner_token_factory=lambda: OWNER)
        staging = create_context_staging(self.store, self.context, operation)
        entries = []
        for relative, payload in sorted(artifacts):
            path = staging / Path(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            entries.append(PublicationEntryV0(ArtifactHashV0(relative, "raw", raw_sha256(payload)), None))
        spec = PublicationGroupSpecV0(self.context.namespace, operation, tuple(entries))
        publish_context_group(self.store, self.context, spec, lease)
        release_context_write_lease(self.store, self.context, lease)

    def publish_file(self, operation: str, relative: str, payload: bytes) -> None:
        lease = acquire_context_write_lease(self.store, self.context, operation, owner_token_factory=lambda: OWNER)
        staging = create_context_staging(self.store, self.context, operation)
        path = staging / Path(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        spec = PublicationSpecV0(
            self.context.namespace,
            operation,
            relative,
            ArtifactHashV0(relative, "raw", raw_sha256(payload)),
            None,
        )
        publish_context_file(self.store, self.context, spec, lease)
        release_context_write_lease(self.store, self.context, lease)

    def test_real_handlers_publish_extract_lock_reconcile_and_scope(self) -> None:
        fixture = ROOT / "tests/conformance/adapter_v0/fixtures/flat"
        extract_inputs = self.root / "extract-inputs"
        extract_staging = self.root / "extract-staging"
        extract_inputs.mkdir(parents=True)
        extract_staging.mkdir()
        shutil.copy2(fixture / "input/flat.csv", extract_inputs / "flat.csv")
        source_payload = (extract_inputs / "flat.csv").read_bytes()
        adapter_binding = binding(self.adapter.descriptor)
        extract_request = OperationRequestV0(
            "extract-import",
            Capability.EXTRACT_IMPORT,
            semantic_sha256(adapter_binding),
            (ArtifactHashV0("flat.csv", "raw", raw_sha256(source_payload)),),
            adapter_output_declarations_v0(include_relations=False),
        )
        adapter_implementation, adapter_handler = bind_read_only_adapter_v0(self.adapter)
        extract_result = execute_bound_operation(
            extract_request.as_envelope(),
            adapter_binding,
            handlers={adapter_implementation: adapter_handler},
            input_root=extract_inputs,
            staging_root=extract_staging,
        )
        self.assertEqual("PASS", extract_result["data"]["status"], extract_result["data"]["error"])
        corpus_artifacts = tuple(
            (f"corpus/{name}", (extract_staging / name).read_bytes())
            for name in ("segments.jsonl", "source_snapshot.json")
        )
        self.publish_group("publish-corpus", corpus_artifacts)

        source_module = ModuleDescriptorV0(
            Capability.SOURCE_SNAPSHOT, "locpipe.source-lock", "0.1.0", SOURCE_MODULE_SHA
        )
        source_binding = binding(self.adapter.descriptor, source_module)
        source_inputs = tuple(
            ArtifactHashV0(relative, "raw", raw_sha256((self.paths.outputs_root / relative).read_bytes()))
            for relative in ("corpus/segments.jsonl", "corpus/source_snapshot.json")
        )
        source_request = OperationRequestV0(
            "source-lock",
            Capability.SOURCE_SNAPSHOT,
            semantic_sha256(source_binding),
            source_inputs,
            source_lock_output_declarations_v0(),
        )
        source_implementation, source_handler = bind_source_snapshot_v0(
            source_module, self.adapter.descriptor, CONFIG_SHA
        )
        source_staging = self.root / "source-staging"
        source_staging.mkdir()
        source_result = execute_bound_operation(
            source_request.as_envelope(),
            source_binding,
            handlers={source_implementation: source_handler},
            input_root=self.paths.outputs_root,
            staging_root=source_staging,
        )
        self.assertEqual("PASS", source_result["data"]["status"])
        source_lock = (source_staging / "source/source_lock.json").read_bytes()
        self.publish_file("publish-source-lock", "source/source_lock.json", source_lock)

        reconciliation_inputs = self.root / "reconciliation-inputs"
        (reconciliation_inputs / "current").mkdir(parents=True)
        shutil.copy2(self.paths.outputs_root / "corpus/source_snapshot.json", reconciliation_inputs / "current/source_snapshot.json")
        shutil.copy2(self.paths.outputs_root / "corpus/segments.jsonl", reconciliation_inputs / "current/segments.jsonl")
        shutil.copy2(self.paths.outputs_root / "source/source_lock.json", reconciliation_inputs / "current/source_lock.json")
        reconcile_module = ModuleDescriptorV0(
            Capability.SOURCE_RECONCILIATION, "locpipe.source-reconciliation", "0.1.0", RECONCILE_MODULE_SHA
        )
        reconcile_binding = binding(self.adapter.descriptor, reconcile_module)
        reconcile_inputs = tuple(
            ArtifactHashV0(relative, "raw", raw_sha256((reconciliation_inputs / relative).read_bytes()))
            for relative in ("current/segments.jsonl", "current/source_lock.json", "current/source_snapshot.json")
        )
        reconcile_request = OperationRequestV0(
            "source-reconciliation",
            Capability.SOURCE_RECONCILIATION,
            semantic_sha256(reconcile_binding),
            reconcile_inputs,
            source_reconciliation_output_declarations_v0(),
        )
        reconcile_implementation, reconcile_handler = bind_source_reconciliation_v0(
            reconcile_module, self.adapter.descriptor, CONFIG_SHA
        )
        reconcile_staging = self.root / "reconcile-staging"
        reconcile_staging.mkdir()
        reconcile_result = execute_bound_operation(
            reconcile_request.as_envelope(),
            reconcile_binding,
            handlers={reconcile_implementation: reconcile_handler},
            input_root=reconciliation_inputs,
            staging_root=reconcile_staging,
        )
        self.assertEqual("PASS", reconcile_result["data"]["status"])
        reconciliation_bytes = (reconcile_staging / "reconciliation/reconciliation.json").read_bytes()
        self.publish_file(
            "publish-reconciliation", "reconciliation/reconciliation.json", reconciliation_bytes
        )

        corpus = load_accepted_source_corpus_v0(
            self.paths.outputs_root,
            snapshot_path="corpus/source_snapshot.json",
            segments_path="corpus/segments.jsonl",
            relations_path=None,
            source_lock_path="source/source_lock.json",
            descriptor=self.adapter.descriptor,
            expected_config_snapshot_sha256=CONFIG_SHA,
        )
        reconciliation = reconcile_sources_v0(corpus)
        published_reconciliation = (self.paths.outputs_root / "reconciliation/reconciliation.json").read_bytes()
        scope = freeze_scope_v0(
            corpus,
            reconciliation,
            tuple(ScopeEntryV0(row.identity, ScopeRoleV0.OWNED) for row in corpus.segments),
            target_locales=("pl", "uk"),
            config_snapshot_sha256=CONFIG_SHA,
            source_lock_bytes=(self.paths.outputs_root / "source/source_lock.json").read_bytes(),
            reconciliation_bytes=published_reconciliation,
        )
        self.publish_group("scope-freeze", frozen_scope_artifacts_v0(scope))

        for relative in (
            "corpus/segments.jsonl",
            "corpus/source_snapshot.json",
            "source/source_lock.json",
            "reconciliation/reconciliation.json",
            "scope/scope.json",
            "scope/scope_lock.json",
        ):
            self.assertTrue((self.paths.outputs_root / relative).is_file(), relative)
        self.assertEqual([], list(self.store.targets.iterdir()))
        self.assertEqual([], list(self.store.staging.iterdir()))
        self.assertEqual([], list(self.store.transactions.iterdir()))
        self.assertFalse((self.paths.outputs_root / "build").exists())
        self.assertFalse((self.paths.outputs_root / "install").exists())

    def test_reconciliation_preserves_historical_lock_and_rejects_rebinding(self) -> None:
        fixture = ROOT / "tests/conformance/adapter_v0/fixtures/flat/golden"
        input_root = self.root / "historical-inputs"
        for role in ("current", "previous"):
            (input_root / role).mkdir(parents=True)
            shutil.copy2(fixture / "source_snapshot.json", input_root / role / "source_snapshot.json")
            shutil.copy2(fixture / "segments.jsonl", input_root / role / "segments.jsonl")
        previous = load_source_corpus_v0(
            input_root,
            snapshot_path="previous/source_snapshot.json",
            segments_path="previous/segments.jsonl",
            relations_path=None,
            descriptor=self.adapter.descriptor,
            config_snapshot_sha256=CONFIG_SHA,
        )
        current_config = "f" * 64
        current = load_source_corpus_v0(
            input_root,
            snapshot_path="current/source_snapshot.json",
            segments_path="current/segments.jsonl",
            relations_path=None,
            descriptor=self.adapter.descriptor,
            config_snapshot_sha256=current_config,
        )
        (input_root / "previous/source_lock.json").write_bytes(canonical_json_bytes(previous.lock.as_dict()))
        (input_root / "current/source_lock.json").write_bytes(canonical_json_bytes(current.lock.as_dict()))
        module = ModuleDescriptorV0(
            Capability.SOURCE_RECONCILIATION, "locpipe.source-reconciliation", "0.1.0", RECONCILE_MODULE_SHA
        )
        module_binding = binding(self.adapter.descriptor, module)
        input_paths = tuple(
            f"{role}/{name}"
            for role in ("current", "previous")
            for name in ("segments.jsonl", "source_lock.json", "source_snapshot.json")
        )
        request = OperationRequestV0(
            "historical-reconciliation",
            Capability.SOURCE_RECONCILIATION,
            semantic_sha256(module_binding),
            tuple(ArtifactHashV0(path, "raw", raw_sha256((input_root / path).read_bytes())) for path in input_paths),
            source_reconciliation_output_declarations_v0(),
        )
        implementation, handler = bind_source_reconciliation_v0(
            module, self.adapter.descriptor, current_config
        )
        staging = self.root / "historical-staging"
        staging.mkdir()
        result = execute_bound_operation(
            request.as_envelope(), module_binding, handlers={implementation: handler},
            input_root=input_root, staging_root=staging,
        )
        self.assertEqual("PASS", result["data"]["status"], result["data"]["error"])
        evidence = parse_canonical_json((staging / "reconciliation/reconciliation.json").read_bytes())
        self.assertEqual(previous.lock.corpus_digest, evidence["previous_corpus_digest"])
        self.assertEqual(current.lock.corpus_digest, evidence["current_corpus_digest"])
        self.assertNotEqual(previous.lock.corpus_digest, current.lock.corpus_digest)
        self.assertEqual({"UNCHANGED": 3}, evidence["summary"])

        (input_root / "current/source_lock.json").write_bytes(canonical_json_bytes(previous.lock.as_dict()))
        tampered_request = OperationRequestV0(
            "tampered-current-lock",
            Capability.SOURCE_RECONCILIATION,
            semantic_sha256(module_binding),
            tuple(ArtifactHashV0(path, "raw", raw_sha256((input_root / path).read_bytes())) for path in input_paths),
            source_reconciliation_output_declarations_v0(),
        )
        tampered_staging = self.root / "tampered-staging"
        tampered_staging.mkdir()
        tampered = execute_bound_operation(
            tampered_request.as_envelope(), module_binding, handlers={implementation: handler},
            input_root=input_root, staging_root=tampered_staging,
        )
        self.assertEqual("FAIL", tampered["data"]["status"])
        self.assertFalse((tampered_staging / "reconciliation/reconciliation.json").exists())


if __name__ == "__main__":
    unittest.main()
