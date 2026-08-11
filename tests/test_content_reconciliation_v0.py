from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from locpipe.content.v0 import (  # noqa: E402
    LineageDirectiveV0,
    ReconciliationStateV0,
    SourceDependencyV0,
    TargetBindingV0,
    TargetValidityStateV0,
    bind_source_snapshot_v0,
    load_source_corpus_v0,
    reconcile_sources_v0,
    source_lock_output_declarations_v0,
)
from locpipe.contracts.v0 import (  # noqa: E402
    AdapterDescriptorV0,
    ArtifactHashV0,
    BranchIdentity,
    Capability,
    ContractViolation,
    ErrorCode,
    ModuleDescriptorV0,
    OperationRequestV0,
    canonical_json_bytes,
    canonical_jsonl_bytes,
    display_id,
    execute_bound_operation,
    raw_sha256,
    semantic_sha256,
    source_revision_sha,
)
from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402


SHA = "a" * 64
CONFIG_SHA = "c" * 64
MODULE_SHA = "d" * 64


def identity(name: str, locale: str = "en") -> BranchIdentity:
    return BranchIdentity(("phase5", name), locale)


def make_corpus(root: Path, descriptor: AdapterDescriptorV0, rows: list[tuple[str, str, str]]) -> None:
    envelopes = []
    for name, payload, locator in rows:
        row_identity = identity(name)
        envelopes.append({
            "schema_id": "urn:locpipe:contracts:v0:segment",
            "schema_version": "0.1.0-draft.2",
            "kind": "source_branch",
            "data": {
                "identity": row_identity.as_dict(),
                "content_type": "plain_text",
                "payload": payload,
                "constraints": {},
                "source_revision_sha": source_revision_sha(
                    identity=row_identity,
                    content_type="plain_text",
                    payload=payload,
                    constraints={},
                ),
                "locator": {"path": locator},
            },
        })
    segments = canonical_jsonl_bytes(envelopes, sort_key=lambda row: display_id(BranchIdentity.from_dict(row["data"]["identity"])))
    branch_ids = sorted(display_id(BranchIdentity.from_dict(row["data"]["identity"])) for row in envelopes)
    snapshot = {
        "schema_id": "urn:locpipe:contracts:v0:source-snapshot",
        "schema_version": "0.1.0-draft.2",
        "kind": "source_snapshot",
        "data": {
            "snapshot_id": "phase5.synthetic",
            "source_locale": "en",
            "source_version": "1",
            "source_raw_sha256": SHA,
            "adapter": {
                "adapter_id": descriptor.adapter_id,
                "version": descriptor.version,
                "digest": descriptor.digest,
                "capabilities": [capability.value for capability in descriptor.capabilities],
            },
            "branch_ids": branch_ids,
        },
    }
    root.mkdir(parents=True, exist_ok=True)
    (root / "source_snapshot.json").write_bytes(canonical_json_bytes(snapshot))
    (root / "segments.jsonl").write_bytes(segments)


def load(root: Path, descriptor: AdapterDescriptorV0):
    return load_source_corpus_v0(
        root,
        snapshot_path="source_snapshot.json",
        segments_path="segments.jsonl",
        relations_path=None,
        descriptor=descriptor,
        config_snapshot_sha256=CONFIG_SHA,
    )


class ContentReconciliationV0Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.descriptor = SyntheticFlatAdapterV0().descriptor

    def test_initial_import_and_repeat_are_deterministic(self) -> None:
        make_corpus(self.root / "current", self.descriptor, [("a", "Alpha", "one"), ("b", "Beta", "two")])
        current = load(self.root / "current", self.descriptor)
        first = reconcile_sources_v0(current)
        second = reconcile_sources_v0(current)
        self.assertEqual(first, second)
        self.assertEqual(["ADDED", "ADDED"], [row.state.value for row in first.events])
        self.assertEqual(canonical_json_bytes(first.as_dict()), canonical_json_bytes(second.as_dict()))

    def test_source_revision_is_recomputed_and_previous_bytes_are_read_only(self) -> None:
        make_corpus(self.root / "previous", self.descriptor, [("a", "Alpha", "one")])
        make_corpus(self.root / "current", self.descriptor, [("a", "Alpha changed", "one")])
        previous_bytes = {
            path.name: path.read_bytes() for path in (self.root / "previous").iterdir() if path.is_file()
        }
        previous = load(self.root / "previous", self.descriptor)
        current = load(self.root / "current", self.descriptor)
        reconcile_sources_v0(current, previous=previous)
        self.assertEqual(
            previous_bytes,
            {path.name: path.read_bytes() for path in (self.root / "previous").iterdir() if path.is_file()},
        )

        records = [json.loads(line) for line in (self.root / "current/segments.jsonl").read_text(encoding="utf-8").splitlines()]
        records[0]["data"]["source_revision_sha"] = "f" * 64
        (self.root / "current/segments.jsonl").write_bytes(
            canonical_jsonl_bytes(
                records,
                sort_key=lambda row: display_id(BranchIdentity.from_dict(row["data"]["identity"])),
            )
        )
        with self.assertRaisesRegex(ContractViolation, "revision"):
            load(self.root / "current", self.descriptor)

    def test_moved_changed_removed_and_target_invalidation(self) -> None:
        make_corpus(
            self.root / "previous",
            self.descriptor,
            [("a", "Alpha", "old"), ("b", "Beta", "same"), ("c", "Gone", "gone")],
        )
        make_corpus(
            self.root / "current",
            self.descriptor,
            [("a", "Alpha", "new"), ("b", "Beta changed", "same")],
        )
        previous = load(self.root / "previous", self.descriptor)
        current = load(self.root / "current", self.descriptor)
        previous_rows = {row.stable_id: row for row in previous.segments}
        bindings = (
            TargetBindingV0(
                identity("target_a", "uk"),
                "1" * 64,
                (SourceDependencyV0(identity("a"), previous_rows[display_id(identity("a"))].source_revision_sha),),
            ),
            TargetBindingV0(
                identity("target_b", "uk"),
                "2" * 64,
                (SourceDependencyV0(identity("b"), previous_rows[display_id(identity("b"))].source_revision_sha),),
            ),
            TargetBindingV0(
                identity("target_c", "uk"),
                "3" * 64,
                (SourceDependencyV0(identity("c"), previous_rows[display_id(identity("c"))].source_revision_sha),),
            ),
        )
        result = reconcile_sources_v0(current, previous=previous, target_bindings=bindings)
        states = {tuple(row.old_ids or row.new_ids): row.state for row in result.events}
        self.assertEqual(ReconciliationStateV0.MOVED, states[(display_id(identity("a")),)])
        self.assertEqual(ReconciliationStateV0.CHANGED, states[(display_id(identity("b")),)])
        self.assertEqual(ReconciliationStateV0.REMOVED, states[(display_id(identity("c")),)])
        validity = {row.target_id: row.state for row in result.target_validity}
        self.assertEqual(TargetValidityStateV0.VALID, validity[display_id(identity("target_a", "uk"))])
        self.assertEqual(TargetValidityStateV0.STALE_SOURCE, validity[display_id(identity("target_b", "uk"))])
        self.assertEqual(TargetValidityStateV0.REMOVED_SOURCE, validity[display_id(identity("target_c", "uk"))])

    def test_ambiguous_cross_identity_move_requires_directive(self) -> None:
        make_corpus(self.root / "previous", self.descriptor, [("old", "Same", "one")])
        make_corpus(self.root / "current", self.descriptor, [("new", "Same", "two")])
        previous = load(self.root / "previous", self.descriptor)
        current = load(self.root / "current", self.descriptor)
        # Revision hashes include selector identity, so emulate a migration-preserved revision.
        current_row = current.segments[0]
        object.__setattr__(current_row, "source_revision_sha", previous.segments[0].source_revision_sha)
        with self.assertRaisesRegex(ContractViolation, "ambiguous"):
            reconcile_sources_v0(current, previous=previous)
        directive = LineageDirectiveV0(
            ReconciliationStateV0.SUPERSEDES,
            (identity("old"),),
            (identity("new"),),
        )
        accepted = reconcile_sources_v0(current, previous=previous, directives=(directive,))
        self.assertEqual(ReconciliationStateV0.SUPERSEDES, accepted.events[0].state)

    def test_split_merge_and_overlap_validation(self) -> None:
        split = LineageDirectiveV0(
            ReconciliationStateV0.SPLIT,
            (identity("old"),),
            (identity("new_a"), identity("new_b")),
        )
        merged = LineageDirectiveV0(
            ReconciliationStateV0.MERGED,
            (identity("old_a"), identity("old_b")),
            (identity("new"),),
        )
        self.assertEqual("SPLIT", split.state.value)
        self.assertEqual("MERGED", merged.state.value)
        with self.assertRaises(ContractViolation):
            LineageDirectiveV0(ReconciliationStateV0.SPLIT, (identity("old"),), (identity("new"),))

    def test_source_snapshot_handler_runs_through_bound_operation(self) -> None:
        fixture = ROOT / "tests/conformance/adapter_v0/fixtures/flat/golden"
        input_root = self.root / "inputs"
        (input_root / "corpus").mkdir(parents=True)
        shutil.copy2(fixture / "source_snapshot.json", input_root / "corpus/source_snapshot.json")
        shutil.copy2(fixture / "segments.jsonl", input_root / "corpus/segments.jsonl")
        module = ModuleDescriptorV0(Capability.SOURCE_SNAPSHOT, "locpipe.source-lock", "0.1.0", MODULE_SHA)
        implementation, handler = bind_source_snapshot_v0(module, self.descriptor, CONFIG_SHA)
        binding = {
            "schema_id": "urn:locpipe:contracts:v0:binding",
            "schema_version": "0.1.0-draft.2",
            "kind": "binding_set",
            "data": {
                "adapter": {
                    "adapter_id": self.descriptor.adapter_id,
                    "version": self.descriptor.version,
                    "digest": self.descriptor.digest,
                    "capabilities": [capability.value for capability in self.descriptor.capabilities],
                },
                "modules": [{
                    "capability": module.capability.value,
                    "module_id": module.module_id,
                    "version": module.version,
                    "digest": module.digest,
                }],
            },
        }
        inputs = tuple(
            ArtifactHashV0(path, "raw", raw_sha256((input_root / Path(*path.split("/"))).read_bytes()))
            for path in ("corpus/segments.jsonl", "corpus/source_snapshot.json")
        )
        request = OperationRequestV0(
            "source-lock",
            Capability.SOURCE_SNAPSHOT,
            semantic_sha256(binding),
            inputs,
            source_lock_output_declarations_v0(),
        ).as_envelope()
        (self.root / "staging").mkdir()
        result = execute_bound_operation(
            request,
            binding,
            handlers={implementation: handler},
            input_root=input_root,
            staging_root=self.root / "staging",
        )
        self.assertEqual("PASS", result["data"]["status"])
        lock = json.loads((self.root / "staging/source/source_lock.json").read_text(encoding="utf-8"))
        self.assertEqual(CONFIG_SHA, lock["config_snapshot_sha256"])


if __name__ == "__main__":
    unittest.main()
