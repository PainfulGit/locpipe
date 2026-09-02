from __future__ import annotations

import copy
from collections.abc import Iterator, Mapping
from dataclasses import replace
import gc
import pickle
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.content.v0 import (  # noqa: E402
    PreparedSourceAuthorityV0,
    PreparedSourceRelationV0,
    PreparedSourceSegmentV0,
    freeze_scope_v0,
    frozen_scope_artifacts_v0,
    prepare_accepted_source_authority_v0,
    rebind_prepared_source_authority_v0,
)
from locpipe.content.v0 import _corpus as corpus_module  # noqa: E402
from locpipe.content.v0 import _prepared as prepared_module  # noqa: E402
from locpipe.contracts.v0 import (  # noqa: E402
    ContractViolation,
    WorkflowProfile,
    canonical_json_bytes,
    display_id,
    raw_sha256,
    strict_loads,
)
from locpipe.kernel.v0.context import ProjectContextV0  # noqa: E402
from locpipe.kernel.v0.transactions import NamespaceV0  # noqa: E402
from locpipe.translation.v0 import (  # noqa: E402
    ProviderBudgetV0,
    build_translation_job_prepared_v0,
    build_translation_job_v0,
)
from locpipe.translation.v0 import _packet as translation_packet_module  # noqa: E402
from locpipe.validation.v0 import build_content_validation_job_prepared_v0  # noqa: E402
from locpipe.validation.v0 import _packet as validation_packet_module  # noqa: E402
from tests.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0  # noqa: E402
from tests.test_content_validation_v0 import validation_fixture  # noqa: E402
from tests.test_translation_packet_v0 import FIXTURES, build_fixture  # noqa: E402


class _LookupOnlyMapping(Mapping):
    def __init__(self, source: Mapping):
        self.source = source
        self.lookups = 0

    def __getitem__(self, key):
        self.lookups += 1
        return self.source[key]

    def get(self, key, default=None):
        self.lookups += 1
        return self.source.get(key, default)

    def __iter__(self) -> Iterator:
        raise AssertionError("warm prepared access iterated a full index")

    def __len__(self) -> int:
        raise AssertionError("warm prepared access measured a full index")


class PreparedSourceAuthorityV0Tests(unittest.TestCase):
    def _access_view(self, authority, **overrides):
        names = (
            "corpus", "reconciliation", "source_lock_bytes", "reconciliation_bytes", "segments_bytes",
            "segments", "relations", "_segment_index", "_revision_index", "_relations_by_branch",
            "_relations_by_logical", "_segments_by_logical", "_source_lock_sha256",
            "_reconciliation_sha256", "_segments_sha256", "_reconciliation_digest",
        )
        values = {name: getattr(authority, name) for name in names}
        values.update(overrides)
        return SimpleNamespace(**values)

    def _materialize_accepted(
        self,
        directory: str,
        *,
        name: str,
        source_lock_bytes: bytes,
    ) -> Path:
        root = Path(directory)
        golden = FIXTURES / name / "golden"
        for filename in ("source_snapshot.json", "segments.jsonl", "relations.jsonl"):
            source = golden / filename
            if source.is_file():
                (root / filename).write_bytes(source.read_bytes())
        (root / "source_lock.json").write_bytes(source_lock_bytes)
        return root

    def _prepared_translation_fixture(self):
        adapter = SyntheticStructuredAdapterV0()
        resolved, corpus, scope, canonical_job, canonical_packet = build_fixture("structured", adapter)
        source_lock_bytes = canonical_json_bytes(corpus.lock.as_dict())
        temporary = tempfile.TemporaryDirectory()
        root = self._materialize_accepted(
            temporary.name,
            name="structured",
            source_lock_bytes=source_lock_bytes,
        )
        authority = prepare_accepted_source_authority_v0(
            root,
            snapshot_path="source_snapshot.json",
            segments_path="segments.jsonl",
            relations_path="relations.jsonl",
            source_lock_path="source_lock.json",
            expected_config_snapshot_sha256=resolved.config_snapshot_sha256,
        )
        context = ProjectContextV0(
            NamespaceV0("workspace", "fixture", "release"),
            WorkflowProfile.CONTENT_ONLY,
            resolved.config_snapshot_sha256,
        )
        scope_artifacts = dict(frozen_scope_artifacts_v0(scope))
        return temporary, resolved, corpus, scope, canonical_job, canonical_packet, authority, context, scope_artifacts

    def _prepared_validation_fixture(self):
        fixture = validation_fixture()
        source_authority = dict(fixture["authority"])
        temporary = tempfile.TemporaryDirectory()
        root = self._materialize_accepted(
            temporary.name,
            name="flat",
            source_lock_bytes=source_authority["source/source_lock.json"],
        )
        authority = prepare_accepted_source_authority_v0(
            root,
            snapshot_path="source_snapshot.json",
            segments_path="segments.jsonl",
            relations_path=None,
            source_lock_path="source_lock.json",
            descriptor=fixture["adapter"].descriptor,
            expected_config_snapshot_sha256=fixture["resolved"].config_snapshot_sha256,
        )
        return temporary, fixture, source_authority, authority

    def test_prepare_parses_source_once_and_repeated_prepared_builds_do_not_reparse(self) -> None:
        adapter = SyntheticStructuredAdapterV0()
        resolved, corpus, scope, canonical_job, canonical_packet = build_fixture("structured", adapter)
        source_lock_bytes = canonical_json_bytes(corpus.lock.as_dict())
        with tempfile.TemporaryDirectory() as directory:
            root = self._materialize_accepted(
                directory,
                name="structured",
                source_lock_bytes=source_lock_bytes,
            )
            with (
                patch.object(corpus_module, "parse_canonical_json", wraps=corpus_module.parse_canonical_json) as parse_json,
                patch.object(corpus_module, "parse_canonical_jsonl", wraps=corpus_module.parse_canonical_jsonl) as parse_jsonl,
            ):
                authority = prepare_accepted_source_authority_v0(
                    root,
                    snapshot_path="source_snapshot.json",
                    segments_path="segments.jsonl",
                    relations_path="relations.jsonl",
                    source_lock_path="source_lock.json",
                )
                self.assertEqual(2, parse_json.call_count)
                self.assertEqual(2, parse_jsonl.call_count)
                parse_counts = (parse_json.call_count, parse_jsonl.call_count)
                context = ProjectContextV0(
                    NamespaceV0("workspace", "fixture", "release"),
                    WorkflowProfile.CONTENT_ONLY,
                    resolved.config_snapshot_sha256,
                )
                scope_artifacts = dict(frozen_scope_artifacts_v0(scope))
                for _ in range(2):
                    job, packet = build_translation_job_prepared_v0(
                        context,
                        resolved,
                        authority,
                        scope,
                        scope_bytes=scope_artifacts["scope/scope.json"],
                        scope_lock_bytes=scope_artifacts["scope/scope_lock.json"],
                        target_locale="uk",
                        budget=ProviderBudgetV0(None, None),
                    )
                    self.assertEqual((canonical_job, canonical_packet), (job, packet))
                self.assertEqual(parse_counts, (parse_json.call_count, parse_jsonl.call_count))
                self.assertTrue(all(row.text_payload is not None for row in authority.segments))

    def test_translation_and_validation_have_exact_canonical_parity(self) -> None:
        temporary, resolved, corpus, scope, canonical_job, canonical_packet, authority, context, scope_artifacts = (
            self._prepared_translation_fixture()
        )
        self.addCleanup(temporary.cleanup)
        prepared_job, prepared_packet = build_translation_job_prepared_v0(
            context,
            resolved,
            authority,
            scope,
            scope_bytes=scope_artifacts["scope/scope.json"],
            scope_lock_bytes=scope_artifacts["scope/scope_lock.json"],
            target_locale="uk",
            budget=ProviderBudgetV0(None, None),
        )
        self.assertEqual(canonical_json_bytes(corpus.lock.as_dict()), authority.source_lock_bytes)
        self.assertEqual((canonical_job, canonical_packet), (prepared_job, prepared_packet))

        prepared_rows = {row.stable_id: row for row in authority.segments}
        for packet_row in prepared_packet.rows:
            source_row = prepared_rows[display_id(packet_row.identity)]
            self.assertIs(packet_row._payload_bytes, source_row.payload_bytes)
            self.assertIs(packet_row._constraints_bytes, source_row.constraints_bytes)
        prepared_relation_bytes = {id(row.envelope_bytes) for row in authority.relations}
        self.assertTrue(all(id(row) in prepared_relation_bytes for row in prepared_packet._relation_bytes))

        validation_temporary, fixture, source_authority, validation_authority = self._prepared_validation_fixture()
        with validation_temporary:
            with (
                patch.object(corpus_module, "parse_canonical_json", wraps=corpus_module.parse_canonical_json) as parse_json,
                patch.object(corpus_module, "parse_canonical_jsonl", wraps=corpus_module.parse_canonical_jsonl) as parse_jsonl,
            ):
                actual = build_content_validation_job_prepared_v0(
                    fixture["context"],
                    fixture["resolved"],
                    validation_authority,
                    fixture["scope"],
                    fixture["translation_job"],
                    fixture["translation_packet"],
                    fixture["translation_decision_bytes"],
                    fixture["translation_state_bytes"],
                    fixture["translation_target_set"],
                    fixture["candidate"],
                    fixture["validator"],
                    scope_bytes=source_authority["scope/scope.json"],
                    scope_lock_bytes=source_authority["scope/scope_lock.json"],
                    candidate_evidence=fixture["candidate_evidence"],
                    editorial_job=fixture["editorial_job"],
                    editorial_packet=fixture["editorial_packet"],
                    editorial_policy=fixture["editorial_policy"],
                )
                self.assertEqual(0, parse_json.call_count)
                self.assertEqual(0, parse_jsonl.call_count)
            self.assertEqual((fixture["job"], fixture["packet"], fixture["authority"]), actual)

    def test_rebind_reuses_source_rows_relations_and_indexes_by_identity(self) -> None:
        temporary, _resolved, _corpus, _scope, _job, _packet, authority, _context, _scope_artifacts = (
            self._prepared_translation_fixture()
        )
        self.addCleanup(temporary.cleanup)
        original_parts = prepared_module._prepared_source_parts_v0(authority)
        rebound = rebind_prepared_source_authority_v0(
            authority,
            config_snapshot_sha256="f" * 64,
        )
        rebound_parts = prepared_module._prepared_source_parts_v0(rebound)
        self.assertIsNot(authority, rebound)
        self.assertIs(original_parts.segments, rebound_parts.segments)
        self.assertIs(original_parts.relations, rebound_parts.relations)
        self.assertIs(original_parts._segment_index, rebound_parts._segment_index)
        self.assertIs(original_parts._revision_index, rebound_parts._revision_index)
        self.assertIs(original_parts._relations_by_branch, rebound_parts._relations_by_branch)
        self.assertIs(original_parts._relations_by_logical, rebound_parts._relations_by_logical)
        self.assertIs(original_parts._segments_by_logical, rebound_parts._segments_by_logical)
        self.assertIs(authority.segments, rebound.segments)
        self.assertIs(authority.relations, rebound.relations)
        for original, reused in zip(authority.segments, rebound.segments, strict=True):
            self.assertIs(original, reused)
            self.assertIs(original.payload_bytes, reused.payload_bytes)
            self.assertIs(original.constraints_bytes, reused.constraints_bytes)
        for original, reused in zip(authority.relations, rebound.relations, strict=True):
            self.assertIs(original, reused)
            self.assertIs(original.envelope_bytes, reused.envelope_bytes)
        self.assertNotEqual(authority.source_lock_bytes, rebound.source_lock_bytes)
        self.assertNotEqual(authority.reconciliation_bytes, rebound.reconciliation_bytes)

    def test_indexes_reference_the_single_prepared_row_layer(self) -> None:
        temporary, _resolved, _corpus, _scope, _job, _packet, authority, _context, _artifacts = (
            self._prepared_translation_fixture()
        )
        self.addCleanup(temporary.cleanup)
        segment_ids = {id(row) for row in authority.segments}
        relation_ids = {id(row) for row in authority.relations}
        self.assertTrue(all(id(row) in segment_ids for row in authority._segment_index.values()))
        for buckets in (authority._relations_by_branch.values(), authority._relations_by_logical.values()):
            self.assertTrue(all(id(row) in relation_ids for bucket in buckets for row in bucket))
        self.assertEqual(
            {
                "reference",
                "state",
                "segment_index_id",
                "source_lock_key",
                "process_id",
            },
            set(prepared_module._BinderRecord.__dataclass_fields__),
        )

    def test_binder_rejects_copy_pickle_manual_construction_and_tamper(self) -> None:
        temporary, resolved, _corpus, scope, _job, _packet, authority, context, scope_artifacts = (
            self._prepared_translation_fixture()
        )
        self.addCleanup(temporary.cleanup)
        for operation in (
            lambda: copy.copy(authority),
            lambda: copy.deepcopy(authority),
            lambda: pickle.dumps(authority),
            lambda: replace(authority),
        ):
            with self.assertRaises(TypeError):
                operation()
        forged = object.__new__(PreparedSourceAuthorityV0)
        with self.assertRaisesRegex(ContractViolation, "not bound"):
            prepared_module._prepared_source_parts_v0(forged)
        with patch.object(prepared_module.os, "getpid", return_value=prepared_module.os.getpid() + 1):
            with self.assertRaisesRegex(ContractViolation, "not bound in this process"):
                prepared_module._prepared_source_parts_v0(authority)
        with self.assertRaises(TypeError):
            authority._segment_index[authority.segments[0].stable_id] = authority.segments[0]
        object.__setattr__(authority, "source_lock_bytes", authority.source_lock_bytes + b"\n")
        with self.assertRaisesRegex(ContractViolation, "tampered"):
            build_translation_job_prepared_v0(
                context,
                resolved,
                authority,
                scope,
                scope_bytes=scope_artifacts["scope/scope.json"],
                scope_lock_bytes=scope_artifacts["scope/scope_lock.json"],
                target_locale="uk",
                budget=ProviderBudgetV0(None, None),
            )

    def test_weak_binder_cleanup_and_error_parity(self) -> None:
        temporary, resolved, corpus, scope, _job, _packet, authority, context, scope_artifacts = (
            self._prepared_translation_fixture()
        )
        key = id(authority)
        self.assertIn(key, prepared_module._BINDER_REGISTRY)
        scope_bytes = scope_artifacts["scope/scope.json"]
        lock_bytes = scope_artifacts["scope/scope_lock.json"]

        def rewritten(mutator):
            raw_scope = strict_loads(scope_bytes)
            raw_lock = strict_loads(lock_bytes)
            mutator(raw_scope, raw_lock)
            changed_scope = canonical_json_bytes(raw_scope)
            if raw_lock["scope_sha256"] == strict_loads(lock_bytes)["scope_sha256"]:
                raw_lock["scope_sha256"] = raw_sha256(changed_scope)
            return changed_scope, canonical_json_bytes(raw_lock)

        duplicate = rewritten(lambda raw_scope, _raw_lock: raw_scope["entries"].append(raw_scope["entries"][0]))

        def make_missing(raw_scope, _raw_lock):
            raw_scope["entries"][0]["identity"]["logical_id"].append("outside-current-corpus")

        missing = rewritten(make_missing)
        source_locale_target = rewritten(
            lambda raw_scope, _raw_lock: raw_scope["target_locales"].append(corpus.lock.source_locale)
        )

        def omit_relation_dependency(raw_scope, _raw_lock):
            raw_scope["entries"].pop()

        omitted_dependency = rewritten(omit_relation_dependency)

        def drift_config(_raw_scope, raw_lock):
            raw_lock["config_snapshot_sha256"] = "f" * 64

        config_mismatch = rewritten(drift_config)

        def drift_hash(_raw_scope, raw_lock):
            raw_lock["scope_sha256"] = "0" * 64

        hash_drift = rewritten(drift_hash)
        cases = (
            (scope_bytes + b"\n", lock_bytes),
            duplicate,
            missing,
            source_locale_target,
            omitted_dependency,
            config_mismatch,
            hash_drift,
        )

        reconciliation = authority.reconciliation
        for changed_scope, changed_lock in cases:
            def canonical_call():
                return build_translation_job_v0(
                    context,
                    resolved,
                    corpus,
                    reconciliation,
                    scope,
                    source_lock_bytes=authority.source_lock_bytes,
                    reconciliation_bytes=authority.reconciliation_bytes,
                    scope_bytes=changed_scope,
                    scope_lock_bytes=changed_lock,
                    segments_bytes=authority.segments_bytes,
                    target_locale="uk",
                    budget=ProviderBudgetV0(None, None),
                )

            def prepared_call():
                return build_translation_job_prepared_v0(
                    context,
                    resolved,
                    authority,
                    scope,
                    scope_bytes=changed_scope,
                    scope_lock_bytes=changed_lock,
                    target_locale="uk",
                    budget=ProviderBudgetV0(None, None),
                )

            failures = []
            for operation in (canonical_call, prepared_call):
                with self.assertRaises(ContractViolation) as caught:
                    operation()
                failures.append((caught.exception.record.code, caught.exception.record.detail))
            self.assertEqual(failures[0], failures[1])

        del canonical_call, prepared_call
        del authority
        temporary.cleanup()
        gc.collect()
        self.assertNotIn(key, prepared_module._BINDER_REGISTRY)

    def test_warm_binder_access_does_not_touch_child_rows(self) -> None:
        temporary, _resolved, _corpus, _scope, _job, _packet, authority, _context, _artifacts = (
            self._prepared_translation_fixture()
        )
        self.addCleanup(temporary.cleanup)

        def poison(_self, _name):
            raise AssertionError("binder validation touched a prepared child row")

        with (
            patch.object(PreparedSourceSegmentV0, "__getattribute__", poison),
            patch.object(PreparedSourceRelationV0, "__getattribute__", poison),
        ):
            first = prepared_module._prepared_source_parts_v0(authority)
            second = prepared_module._prepared_source_parts_v0(authority)
        self.assertIs(first._segment_index, second._segment_index)
        self.assertIs(first._revision_index, second._revision_index)
        self.assertIs(first._relations_by_branch, second._relations_by_branch)
        self.assertIs(first._relations_by_logical, second._relations_by_logical)
        self.assertIs(first._segments_by_logical, second._segments_by_logical)

    def test_prepared_batch_uses_only_scope_and_incident_relation_buckets(self) -> None:
        temporary, resolved, _corpus, scope, canonical_job, canonical_packet, authority, context, artifacts = (
            self._prepared_translation_fixture()
        )
        self.addCleanup(temporary.cleanup)
        prepared = prepared_module._prepared_source_parts_v0(authority)
        segment_index = _LookupOnlyMapping(prepared._segment_index)
        relation_by_branch = _LookupOnlyMapping(prepared._relations_by_branch)
        relation_by_logical = _LookupOnlyMapping(prepared._relations_by_logical)
        access = self._access_view(
            prepared,
            _segment_index=segment_index,
            _relations_by_branch=relation_by_branch,
            _relations_by_logical=relation_by_logical,
        )
        with patch.object(translation_packet_module, "_prepared_source_parts_v0", return_value=access):
            actual = build_translation_job_prepared_v0(
                context,
                resolved,
                authority,
                scope,
                scope_bytes=artifacts["scope/scope.json"],
                scope_lock_bytes=artifacts["scope/scope_lock.json"],
                target_locale="uk",
                budget=ProviderBudgetV0(None, None),
            )
        self.assertEqual((canonical_job, canonical_packet), actual)
        owned = tuple(entry for entry in scope.entries if entry.role.value == "OWNED")
        self.assertEqual(2 * len(scope.entries), segment_index.lookups)
        self.assertEqual(2 * len({display_id(entry.identity) for entry in owned}), relation_by_branch.lookups)
        self.assertEqual(2 * len({entry.identity.logical_id for entry in owned}), relation_by_logical.lookups)

    def test_canonical_path_does_not_construct_prepared_rows(self) -> None:
        temporary, resolved, corpus, scope, canonical_job, canonical_packet, authority, context, artifacts = (
            self._prepared_translation_fixture()
        )
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(corpus_module, "_prepared_segment", side_effect=AssertionError("prepared segment constructed")),
            patch.object(corpus_module, "_prepared_relation", side_effect=AssertionError("prepared relation constructed")),
        ):
            rebuilt = build_fixture("structured", SyntheticStructuredAdapterV0())
            actual = build_translation_job_v0(
                context,
                resolved,
                corpus,
                authority.reconciliation,
                scope,
                source_lock_bytes=authority.source_lock_bytes,
                reconciliation_bytes=authority.reconciliation_bytes,
                scope_bytes=artifacts["scope/scope.json"],
                scope_lock_bytes=artifacts["scope/scope_lock.json"],
                segments_bytes=authority.segments_bytes,
                target_locale="uk",
                budget=ProviderBudgetV0(None, None),
            )
        self.assertEqual((canonical_job, canonical_packet), actual)
        self.assertEqual((resolved, corpus, scope, canonical_job, canonical_packet), rebuilt)

    def test_prepared_validation_reuses_revision_index_without_copy_or_iteration(self) -> None:
        temporary, fixture, source_authority, authority = self._prepared_validation_fixture()
        self.addCleanup(temporary.cleanup)
        prepared = prepared_module._prepared_source_parts_v0(authority)
        revisions = _LookupOnlyMapping(prepared._revision_index)
        access = self._access_view(prepared, _revision_index=revisions)

        original_raw_sha256 = validation_packet_module.raw_sha256

        def reject_full_authority_rehash(payload):
            if payload is prepared.segments_bytes or payload is prepared.reconciliation_bytes:
                raise AssertionError("prepared validation rehashed full source authority")
            return original_raw_sha256(payload)

        with (
            patch.object(validation_packet_module, "_prepared_source_parts_v0", return_value=access),
            patch.object(validation_packet_module, "raw_sha256", side_effect=reject_full_authority_rehash),
        ):
            actual = build_content_validation_job_prepared_v0(
                fixture["context"],
                fixture["resolved"],
                authority,
                fixture["scope"],
                fixture["translation_job"],
                fixture["translation_packet"],
                fixture["translation_decision_bytes"],
                fixture["translation_state_bytes"],
                fixture["translation_target_set"],
                fixture["candidate"],
                fixture["validator"],
                scope_bytes=source_authority["scope/scope.json"],
                scope_lock_bytes=source_authority["scope/scope_lock.json"],
                candidate_evidence=fixture["candidate_evidence"],
                editorial_job=fixture["editorial_job"],
                editorial_packet=fixture["editorial_packet"],
                editorial_policy=fixture["editorial_policy"],
            )
        self.assertEqual((fixture["job"], fixture["packet"], fixture["authority"]), actual)
        self.assertEqual(len(fixture["translation_packet"].rows), revisions.lookups)


if __name__ == "__main__":
    unittest.main()
