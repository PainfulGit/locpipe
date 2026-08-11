from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.content.v0 import (  # noqa: E402
    ScopeEntryV0,
    ScopeRoleV0,
    freeze_scope_v0,
    frozen_scope_artifacts_v0,
    load_source_corpus_v0,
    reconcile_sources_v0,
    validate_frozen_scope_artifacts_v0,
)
from locpipe.contracts.v0 import (  # noqa: E402
    ArtifactHashV0,
    BranchIdentity,
    ContractViolation,
    WorkflowProfile,
    canonical_json_bytes,
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
    publish_context_group,
    release_context_write_lease,
)
from locpipe.kernel.v0.transactions import (  # noqa: E402
    NamespaceV0,
    PublicationEntryV0,
    PublicationGroupSpecV0,
    SyntheticTransactionStoreV0,
)
from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402
from tests.conformance.adapter_v0.runner import run_public_fixture_v0  # noqa: E402
from tests.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0  # noqa: E402


CONFIG_SHA = "c" * 64
OWNER = "9" * 32
FIXTURES = ROOT / "tests/conformance/adapter_v0/fixtures"


def load_fixture(name: str, adapter):
    golden = FIXTURES / name / "golden"
    return load_source_corpus_v0(
        golden,
        snapshot_path="source_snapshot.json",
        segments_path="segments.jsonl",
        relations_path="relations.jsonl" if (golden / "relations.jsonl").is_file() else None,
        descriptor=adapter.descriptor,
        config_snapshot_sha256=CONFIG_SHA,
    )


def freeze_verified(corpus, reconciliation, entries, *, target_locales, config_snapshot_sha256):
    return freeze_scope_v0(
        corpus,
        reconciliation,
        entries,
        target_locales=target_locales,
        config_snapshot_sha256=config_snapshot_sha256,
        source_lock_bytes=canonical_json_bytes(corpus.lock.as_dict()),
        reconciliation_bytes=canonical_json_bytes(reconciliation.as_dict()),
    )


class ContentScopeV0Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_flat_and_structured_extract_reconcile_and_freeze_deterministically(self) -> None:
        cases = (("flat", SyntheticFlatAdapterV0()), ("structured", SyntheticStructuredAdapterV0()))
        for name, adapter in cases:
            run_public_fixture_v0(FIXTURES / name, adapter)
            corpus = load_fixture(name, adapter)
            reconciliation = reconcile_sources_v0(corpus)
            entries = tuple(ScopeEntryV0(row.identity, ScopeRoleV0.OWNED) for row in reversed(corpus.segments))
            first = freeze_verified(
                corpus, reconciliation, entries, target_locales=("uk",), config_snapshot_sha256=CONFIG_SHA
            )
            second = freeze_verified(
                corpus, reconciliation, tuple(reversed(entries)),
                target_locales=("uk",), config_snapshot_sha256=CONFIG_SHA,
            )
            self.assertEqual(first, second)
            self.assertEqual(frozen_scope_artifacts_v0(first), frozen_scope_artifacts_v0(second))

    def test_relation_closure_requires_all_related_branches_in_scope(self) -> None:
        adapter = SyntheticStructuredAdapterV0()
        corpus = load_fixture("structured", adapter)
        reconciliation = reconcile_sources_v0(corpus)
        owned = ScopeEntryV0(corpus.segments[0].identity, ScopeRoleV0.OWNED)
        with self.assertRaisesRegex(ContractViolation, "related branch"):
            freeze_verified(
                corpus, reconciliation, (owned,), target_locales=("uk",), config_snapshot_sha256=CONFIG_SHA
            )
        complete = (owned,) + tuple(
            ScopeEntryV0(row.identity, ScopeRoleV0.CONTEXT) for row in corpus.segments[1:]
        )
        frozen = freeze_verified(
            corpus, reconciliation, complete, target_locales=("uk",), config_snapshot_sha256=CONFIG_SHA
        )
        self.assertEqual(1, sum(row.role is ScopeRoleV0.OWNED for row in frozen.entries))

    def test_missing_overlap_locale_and_binding_drift_fail_closed(self) -> None:
        corpus = load_fixture("flat", SyntheticFlatAdapterV0())
        reconciliation = reconcile_sources_v0(corpus)
        missing = ScopeEntryV0(BranchIdentity(("missing",), "en"), ScopeRoleV0.OWNED)
        with self.assertRaises(ContractViolation):
            freeze_verified(
                corpus, reconciliation, (missing,), target_locales=("uk",), config_snapshot_sha256=CONFIG_SHA
            )
        duplicate = (
            ScopeEntryV0(corpus.segments[0].identity, ScopeRoleV0.OWNED),
            ScopeEntryV0(corpus.segments[0].identity, ScopeRoleV0.CONTEXT),
        )
        with self.assertRaises(ContractViolation):
            freeze_verified(
                corpus, reconciliation, duplicate, target_locales=("uk",), config_snapshot_sha256=CONFIG_SHA
            )
        with self.assertRaises(ContractViolation):
            freeze_verified(
                corpus, reconciliation,
                (ScopeEntryV0(corpus.segments[0].identity, ScopeRoleV0.OWNED),),
                target_locales=("en",), config_snapshot_sha256=CONFIG_SHA,
            )
        with self.assertRaises(ContractViolation):
            freeze_verified(
                corpus, reconciliation,
                (ScopeEntryV0(corpus.segments[0].identity, ScopeRoleV0.OWNED),),
                target_locales=("uk",), config_snapshot_sha256="f" * 64,
            )

    def test_scope_and_lock_drift_are_detected(self) -> None:
        corpus = load_fixture("flat", SyntheticFlatAdapterV0())
        reconciliation = reconcile_sources_v0(corpus)
        frozen = freeze_verified(
            corpus,
            reconciliation,
            tuple(ScopeEntryV0(row.identity, ScopeRoleV0.OWNED) for row in corpus.segments),
            target_locales=("uk",),
            config_snapshot_sha256=CONFIG_SHA,
        )
        artifacts = dict(frozen_scope_artifacts_v0(frozen))
        self.assertEqual(
            frozen,
            validate_frozen_scope_artifacts_v0(
                artifacts["scope/scope.json"], artifacts["scope/scope_lock.json"], corpus, reconciliation,
                source_lock_bytes=canonical_json_bytes(corpus.lock.as_dict()),
                reconciliation_bytes=canonical_json_bytes(reconciliation.as_dict()),
            ),
        )
        scope = parse_canonical_json(artifacts["scope/scope.json"])
        scope["entries"][0]["role"] = "CONTEXT"
        with self.assertRaises(ContractViolation):
            validate_frozen_scope_artifacts_v0(
                canonical_json_bytes(scope), artifacts["scope/scope_lock.json"], corpus, reconciliation,
                source_lock_bytes=canonical_json_bytes(corpus.lock.as_dict()),
                reconciliation_bytes=canonical_json_bytes(reconciliation.as_dict()),
            )
        lock = parse_canonical_json(artifacts["scope/scope_lock.json"])
        lock["source_corpus_digest"] = "f" * 64
        with self.assertRaises(ContractViolation):
            validate_frozen_scope_artifacts_v0(
                artifacts["scope/scope.json"], canonical_json_bytes(lock), corpus, reconciliation,
                source_lock_bytes=canonical_json_bytes(corpus.lock.as_dict()),
                reconciliation_bytes=canonical_json_bytes(reconciliation.as_dict()),
            )
        published_lock = parse_canonical_json(canonical_json_bytes(corpus.lock.as_dict()))
        published_lock["snapshot_sha256"] = "f" * 64
        published_lock["corpus_digest"] = semantic_sha256({
            "snapshot_sha256": published_lock["snapshot_sha256"],
            "segments_sha256": published_lock["segments_sha256"],
            "relations_sha256": published_lock["relations_sha256"],
            "config_snapshot_sha256": published_lock["config_snapshot_sha256"],
        })
        with self.assertRaises(ContractViolation):
            validate_frozen_scope_artifacts_v0(
                artifacts["scope/scope.json"], artifacts["scope/scope_lock.json"], corpus, reconciliation,
                source_lock_bytes=canonical_json_bytes(published_lock),
                reconciliation_bytes=canonical_json_bytes(reconciliation.as_dict()),
            )
        published_reconciliation = parse_canonical_json(canonical_json_bytes(reconciliation.as_dict()))
        published_reconciliation["summary"]["ADDED"] += 1
        with self.assertRaises(ContractViolation):
            validate_frozen_scope_artifacts_v0(
                artifacts["scope/scope.json"], artifacts["scope/scope_lock.json"], corpus, reconciliation,
                source_lock_bytes=canonical_json_bytes(corpus.lock.as_dict()),
                reconciliation_bytes=canonical_json_bytes(published_reconciliation),
            )

    def test_context_publication_is_isolated_and_idempotent(self) -> None:
        corpus = load_fixture("flat", SyntheticFlatAdapterV0())
        reconciliation = reconcile_sources_v0(corpus)
        frozen = freeze_verified(
            corpus,
            reconciliation,
            tuple(ScopeEntryV0(row.identity, ScopeRoleV0.OWNED) for row in corpus.segments),
            target_locales=("uk",),
            config_snapshot_sha256=CONFIG_SHA,
        )
        artifacts = frozen_scope_artifacts_v0(frozen)
        store_root = self.root / "store"
        store_root.mkdir()
        store = SyntheticTransactionStoreV0.create(store_root)
        contexts = (
            ProjectContextV0(NamespaceV0("workspace", "project-a", "release-1"), WorkflowProfile.CONTENT_ONLY, CONFIG_SHA),
            ProjectContextV0(NamespaceV0("workspace", "project-b", "release-1"), WorkflowProfile.CONTENT_ONLY, CONFIG_SHA),
            ProjectContextV0(NamespaceV0("workspace", "project-a", "release-2"), WorkflowProfile.CONTENT_ONLY, CONFIG_SHA),
        )
        roots = []
        for index, context in enumerate(contexts):
            paths = initialize_project_context(store, context)
            operation = f"scope-freeze-{index}"
            lease = acquire_context_write_lease(store, context, operation, owner_token_factory=lambda: OWNER)
            staging = create_context_staging(store, context, operation)
            entries = []
            for relative, payload in artifacts:
                path = staging / Path(*relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
                entries.append(PublicationEntryV0(ArtifactHashV0(relative, "raw", raw_sha256(payload)), None))
            spec = PublicationGroupSpecV0(context.namespace, operation, tuple(sorted(entries, key=lambda row: row.staged_artifact.path)))
            receipt = publish_context_group(store, context, spec, lease)
            self.assertEqual(receipt, publish_context_group(store, context, spec, lease))
            release_context_write_lease(store, context, lease)
            roots.append(paths.outputs_root)
            for relative, payload in artifacts:
                self.assertEqual(payload, (paths.outputs_root / Path(*relative.split("/"))).read_bytes())
        self.assertEqual(3, len(set(roots)))
        self.assertEqual([], list(store.targets.iterdir()))
        self.assertEqual([], list(store.staging.iterdir()))
        self.assertEqual([], list(store.transactions.iterdir()))


if __name__ == "__main__":
    unittest.main()
