import gc
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Iterator, Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.content.v0 import (  # noqa: E402
    PreparedSourceCacheReceiptV0,
    ScopeEntryV0,
    build_prepared_source_cache_v0,
    freeze_scope_prepared_v0,
    freeze_scope_v0,
    frozen_scope_artifacts_v0,
    load_prepared_source_authority_v0,
    prepare_accepted_source_authority_v0,
    rebind_prepared_source_authority_v0,
)
from locpipe.content.v0 import _cache as cache_module  # noqa: E402
from locpipe.content.v0 import _prepared as prepared_module  # noqa: E402
from locpipe.content.v0 import _scope as scope_module  # noqa: E402
from locpipe.contracts.v0 import (  # noqa: E402
    ContractViolation,
    ErrorCode,
    WorkflowProfile,
    canonical_json_bytes,
    raw_sha256,
    strict_loads,
)
from locpipe.fluency.v0 import _bridge as fluency_bridge_module  # noqa: E402
from locpipe.kernel.v0.context import ProjectContextV0  # noqa: E402
from locpipe.kernel.v0.transactions import NamespaceV0  # noqa: E402
from locpipe.translation.v0 import ProviderBudgetV0, build_translation_job_prepared_v0  # noqa: E402
from locpipe.translation.v0 import _packet as translation_packet_module  # noqa: E402
from locpipe.validation.v0 import build_content_validation_job_prepared_v0  # noqa: E402
from locpipe.validation.v0 import _packet as validation_packet_module  # noqa: E402
from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402
from tests.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0  # noqa: E402
from tests.test_translation_packet_v0 import FIXTURES, build_fixture  # noqa: E402
from tests.test_content_validation_v0 import validation_fixture  # noqa: E402
from tests.test_fluency_validation_bridge_v0 import (  # noqa: E402
    KEEP_REASON,
    _accuracy_authority_with_validation,
    _correction_provenance,
    _correction_validation_fixture,
    _initial_provenance,
    _prepared_validation_call,
    _validation_call,
    _validation_fixture,
)


PRODUCER_SHA = "d" * 64


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
        raise AssertionError("cache-warm operation iterated a full prepared index")

    def __len__(self) -> int:
        raise AssertionError("cache-warm operation measured a full prepared index")


class PreparedSourceCacheV0Tests(unittest.TestCase):
    def _authority(self, directory: str, name: str = "structured", *, previous=None):
        adapter = SyntheticStructuredAdapterV0() if name == "structured" else SyntheticFlatAdapterV0()
        resolved, corpus, scope, _job, _packet = build_fixture(name, adapter)
        root = Path(directory)
        golden = FIXTURES / name / "golden"
        for filename in ("source_snapshot.json", "segments.jsonl", "relations.jsonl"):
            source = golden / filename
            if source.is_file():
                (root / filename).write_bytes(source.read_bytes())
        (root / "source_lock.json").write_bytes(canonical_json_bytes(corpus.lock.as_dict()))
        authority = prepare_accepted_source_authority_v0(
            root,
            snapshot_path="source_snapshot.json",
            segments_path="segments.jsonl",
            relations_path="relations.jsonl" if name == "structured" else None,
            source_lock_path="source_lock.json",
            descriptor=adapter.descriptor,
            expected_config_snapshot_sha256=resolved.config_snapshot_sha256,
            previous=previous,
        )
        return resolved, corpus, scope, authority

    @staticmethod
    def _tree(root: Path) -> dict[str, bytes]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }

    @staticmethod
    def _access_view(authority, **overrides):
        prepared = prepared_module._prepared_source_parts_v0(authority)
        names = (
            "corpus", "reconciliation", "source_lock_bytes", "reconciliation_bytes",
            "segments_bytes", "segments", "relations", "_segment_index", "_revision_index",
            "_relations_by_branch", "_relations_by_logical", "_segments_by_logical",
            "_source_lock_sha256", "_reconciliation_sha256", "_segments_sha256",
            "_reconciliation_digest",
        )
        values = {name: getattr(prepared, name) for name in names}
        values.update(overrides)
        return SimpleNamespace(**values)

    def _cached_fixture_authority(self, fixture, source_directory: str, cache_parent: str):
        root = Path(source_directory)
        adapter = fixture.get("adapter") or SyntheticFlatAdapterV0()
        name = "structured" if isinstance(adapter, SyntheticStructuredAdapterV0) else "flat"
        golden = FIXTURES / name / "golden"
        for filename in ("source_snapshot.json", "segments.jsonl", "relations.jsonl"):
            source = golden / filename
            if source.is_file():
                (root / filename).write_bytes(source.read_bytes())
        source_authority = dict(fixture["authority"])
        (root / "source_lock.json").write_bytes(source_authority["source/source_lock.json"])
        authority = prepare_accepted_source_authority_v0(
            root,
            snapshot_path="source_snapshot.json",
            segments_path="segments.jsonl",
            relations_path="relations.jsonl" if (root / "relations.jsonl").is_file() else None,
            source_lock_path="source_lock.json",
            descriptor=adapter.descriptor,
            expected_config_snapshot_sha256=fixture["resolved"].config_snapshot_sha256,
        )
        receipt = build_prepared_source_cache_v0(
            authority,
            Path(cache_parent),
            producer_distribution_sha256=PRODUCER_SHA,
        )
        for path in root.iterdir():
            path.unlink()
        return load_prepared_source_authority_v0(Path(cache_parent) / receipt.cache_id, expected=receipt)

    def test_cache_is_deterministic_and_rebuilds_equivalent_authority(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as first_parent, tempfile.TemporaryDirectory() as second_parent:
            resolved, _corpus, scope, authority = self._authority(source_directory)
            _canonical_resolved, _canonical_corpus, _canonical_scope, canonical_job, canonical_packet = build_fixture(
                "structured", SyntheticStructuredAdapterV0()
            )
            receipts = []
            for seed, destination in (("314159", first_parent), ("271828", second_parent)):
                script = (
                    "import sys;from pathlib import Path;"
                    f"sys.path.insert(0,{str(ROOT / 'src')!r});"
                    "from locpipe.content.v0 import build_prepared_source_cache_v0,prepare_accepted_source_authority_v0;"
                    f"root=Path({source_directory!r});"
                    "authority=prepare_accepted_source_authority_v0(root,snapshot_path='source_snapshot.json',"
                    "segments_path='segments.jsonl',relations_path='relations.jsonl',source_lock_path='source_lock.json');"
                    f"receipt=build_prepared_source_cache_v0(authority,Path({destination!r}),producer_distribution_sha256={PRODUCER_SHA!r});"
                    "sys.stdout.buffer.write(receipt.canonical_bytes())"
                )
                environment = dict(os.environ)
                environment["PYTHONHASHSEED"] = seed
                completed = subprocess.run(
                    [sys.executable, "-c", script],
                    check=False,
                    capture_output=True,
                    env=environment,
                )
                self.assertEqual(0, completed.returncode, completed.stderr.decode("utf-8"))
                receipts.append(PreparedSourceCacheReceiptV0.from_bytes(completed.stdout))
            first, second = receipts
            self.assertEqual(first, second)
            first_root = Path(first_parent) / first.cache_id
            second_root = Path(second_parent) / first.cache_id
            self.assertEqual(self._tree(first_root), self._tree(second_root))
            self.assertEqual(first.file_count, len(self._tree(first_root)))

            for path in Path(source_directory).iterdir():
                path.unlink()
            loaded = load_prepared_source_authority_v0(first_root, expected=first)
            self.assertEqual(authority.source_lock_bytes, loaded.source_lock_bytes)
            self.assertEqual(authority.reconciliation_bytes, loaded.reconciliation_bytes)
            self.assertEqual(authority.segments_bytes, loaded.segments_bytes)
            self.assertEqual(authority.relations_bytes, loaded.relations_bytes)
            self.assertEqual(authority.segments, loaded.segments)
            self.assertEqual(authority.relations, loaded.relations)
            self.assertIsNot(authority._segment_index, loaded._segment_index)

            prepared_parts = prepared_module._prepared_source_parts_v0(loaded)
            scope_segment_index = _LookupOnlyMapping(prepared_parts._segment_index)
            scope_relations_by_branch = _LookupOnlyMapping(prepared_parts._relations_by_branch)
            scope_relations_by_logical = _LookupOnlyMapping(prepared_parts._relations_by_logical)
            scope_segments_by_logical = _LookupOnlyMapping(prepared_parts._segments_by_logical)
            scope_access = self._access_view(
                loaded,
                _segment_index=scope_segment_index,
                _relations_by_branch=scope_relations_by_branch,
                _relations_by_logical=scope_relations_by_logical,
                _segments_by_logical=scope_segments_by_logical,
            )
            with patch.object(scope_module, "_prepared_source_parts_v0", return_value=scope_access):
                prepared_scope = freeze_scope_prepared_v0(
                    loaded,
                    tuple(ScopeEntryV0(row.identity, entry.role) for row, entry in zip(loaded.segments, scope.entries, strict=True)),
                    target_locales=scope.target_locales,
                    config_snapshot_sha256=resolved.config_snapshot_sha256,
                )
            self.assertGreater(scope_segment_index.lookups, 0)
            self.assertGreater(scope_relations_by_branch.lookups + scope_relations_by_logical.lookups, 0)
            self.assertEqual(scope, prepared_scope)
            self.assertEqual(frozen_scope_artifacts_v0(scope), frozen_scope_artifacts_v0(prepared_scope))
            scope_artifacts = dict(frozen_scope_artifacts_v0(prepared_scope))
            context = ProjectContextV0(
                NamespaceV0("workspace", "fixture", "release"),
                WorkflowProfile.CONTENT_ONLY,
                resolved.config_snapshot_sha256,
            )
            translation_segment_index = _LookupOnlyMapping(prepared_parts._segment_index)
            translation_relations_by_branch = _LookupOnlyMapping(prepared_parts._relations_by_branch)
            translation_relations_by_logical = _LookupOnlyMapping(prepared_parts._relations_by_logical)
            translation_access = self._access_view(
                loaded,
                _segment_index=translation_segment_index,
                _relations_by_branch=translation_relations_by_branch,
                _relations_by_logical=translation_relations_by_logical,
            )
            with patch.object(
                translation_packet_module,
                "_prepared_source_parts_v0",
                return_value=translation_access,
            ):
                prepared_job, prepared_packet = build_translation_job_prepared_v0(
                    context,
                    resolved,
                    loaded,
                    prepared_scope,
                    scope_bytes=scope_artifacts["scope/scope.json"],
                    scope_lock_bytes=scope_artifacts["scope/scope_lock.json"],
                    target_locale="uk",
                    budget=ProviderBudgetV0(None, None),
                )
            self.assertGreater(translation_segment_index.lookups, 0)
            self.assertGreater(translation_relations_by_branch.lookups + translation_relations_by_logical.lookups, 0)
            self.assertEqual((canonical_job, canonical_packet), (prepared_job, prepared_packet))

    def test_prepared_scope_uses_prebuilt_relation_indexes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            resolved, _corpus, scope, authority = self._authority(directory)
            with patch.object(scope_module, "_canonical_scope_access_v0", side_effect=AssertionError("canonical scan")):
                actual = freeze_scope_prepared_v0(
                    authority,
                    scope.entries,
                    target_locales=scope.target_locales,
                    config_snapshot_sha256=resolved.config_snapshot_sha256,
                )
            self.assertEqual(scope, actual)

            rebound = rebind_prepared_source_authority_v0(authority, config_snapshot_sha256="f" * 64)
            canonical = freeze_scope_v0(
                rebound.corpus,
                rebound.reconciliation,
                scope.entries,
                target_locales=scope.target_locales,
                config_snapshot_sha256="f" * 64,
                source_lock_bytes=rebound.source_lock_bytes,
                reconciliation_bytes=rebound.reconciliation_bytes,
            )
            prepared = freeze_scope_prepared_v0(
                rebound,
                scope.entries,
                target_locales=scope.target_locales,
                config_snapshot_sha256="f" * 64,
            )
            self.assertEqual(canonical, prepared)
            self.assertEqual(frozen_scope_artifacts_v0(canonical), frozen_scope_artifacts_v0(prepared))

    def test_load_works_in_fresh_process_and_binder_is_process_local(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as cache_parent:
            _resolved, _corpus, _scope, authority = self._authority(source_directory)
            receipt = build_prepared_source_cache_v0(
                authority,
                Path(cache_parent),
                producer_distribution_sha256=PRODUCER_SHA,
            )
            receipt_path = Path(cache_parent) / "receipt.json"
            receipt_path.write_bytes(receipt.canonical_bytes())
            for path in Path(source_directory).iterdir():
                path.unlink()
            script = (
                "import os,sys;from pathlib import Path;"
                f"sys.path.insert(0,{str(ROOT / 'src')!r});"
                "from locpipe.content.v0 import PreparedSourceCacheReceiptV0,load_prepared_source_authority_v0;"
                f"receipt=PreparedSourceCacheReceiptV0.from_bytes(Path({str(receipt_path)!r}).read_bytes());"
                f"authority=load_prepared_source_authority_v0(Path({str(Path(cache_parent) / receipt.cache_id)!r}),expected=receipt);"
                "print(os.getpid(),len(authority.segments),authority.corpus.lock.corpus_digest)"
            )
            completed = subprocess.run(
                [sys.executable, "-c", script],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            child_pid, segment_count, digest = completed.stdout.strip().split()
            self.assertNotEqual(str(cache_module.os.getpid()), child_pid)
            self.assertEqual(str(receipt.segment_count), segment_count)
            self.assertEqual(receipt.corpus_digest, digest)

    def test_receipt_canonical_roundtrip_and_closed_parser(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as cache_parent:
            _resolved, _corpus, _scope, authority = self._authority(source_directory)
            receipt = build_prepared_source_cache_v0(
                authority,
                Path(cache_parent),
                producer_distribution_sha256=PRODUCER_SHA,
            )
            payload = receipt.canonical_bytes()
            self.assertEqual(receipt, PreparedSourceCacheReceiptV0.from_bytes(payload))
            raw = strict_loads(payload)
            cases = []
            unknown = dict(raw)
            unknown["contract"] = "locpipe.content.prepared-source-cache-receipt/unknown"
            cases.append((canonical_json_bytes(unknown), ErrorCode.SCHEMA_UNKNOWN))
            missing = dict(raw)
            missing.pop("cache_id")
            cases.append((canonical_json_bytes(missing), ErrorCode.MALFORMED_ARTIFACT))
            extra = dict(raw)
            extra["unexpected"] = True
            cases.append((canonical_json_bytes(extra), ErrorCode.MALFORMED_ARTIFACT))
            cases.append((payload + b"\n", ErrorCode.MALFORMED_ARTIFACT))
            for candidate, code in cases:
                with self.subTest(code=code), self.assertRaises(ContractViolation) as caught:
                    PreparedSourceCacheReceiptV0.from_bytes(candidate)
                self.assertEqual(code, caught.exception.record.code)

    def test_reconciliation_parser_rejects_semantic_history_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _resolved, _corpus, _scope, authority = self._authority(directory)
            branch_ids = authority.corpus.lock.branch_ids
            raw = strict_loads(authority.reconciliation_bytes)
            mutations = []

            unsorted = strict_loads(authority.reconciliation_bytes)
            unsorted["events"].reverse()
            mutations.append(unsorted)

            duplicate = strict_loads(authority.reconciliation_bytes)
            duplicate["events"].append(dict(duplicate["events"][0]))
            mutations.append(duplicate)

            invalid_added = strict_loads(authority.reconciliation_bytes)
            invalid_added["events"][0]["old_ids"] = [branch_ids[0]]
            mutations.append(invalid_added)

            invalid_split = strict_loads(authority.reconciliation_bytes)
            invalid_split["events"][0]["state"] = "SPLIT"
            mutations.append(invalid_split)

            invalid_tombstone = strict_loads(authority.reconciliation_bytes)
            invalid_tombstone["tombstones"] = [branch_ids[0]]
            mutations.append(invalid_tombstone)

            invalid_target = strict_loads(authority.reconciliation_bytes)
            invalid_target["target_validity"] = [{
                "target_id": "target-a",
                "state": "VALID",
                "invalid_source_ids": [branch_ids[0]],
            }]
            mutations.append(invalid_target)

            duplicate_target = strict_loads(authority.reconciliation_bytes)
            duplicate_target["target_validity"] = [
                {"target_id": "target-a", "state": "VALID", "invalid_source_ids": []},
                {"target_id": "target-a", "state": "VALID", "invalid_source_ids": []},
            ]
            mutations.append(duplicate_target)

            for index, candidate in enumerate(mutations):
                with self.subTest(index=index), self.assertRaises(ContractViolation):
                    cache_module._parse_reconciliation(
                        canonical_json_bytes(candidate),
                        current_branch_ids=branch_ids,
                    )

    def test_cache_warm_content_validation_is_exact_and_keyed(self) -> None:
        fixture = validation_fixture()
        source_authority = dict(fixture["authority"])
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as cache_parent:
            loaded = self._cached_fixture_authority(fixture, source_directory, cache_parent)
            prepared = prepared_module._prepared_source_parts_v0(loaded)
            revisions = _LookupOnlyMapping(prepared._revision_index)
            access = self._access_view(loaded, _revision_index=revisions)
            with (
                patch.object(validation_packet_module, "_prepared_source_parts_v0", return_value=access),
                patch.object(
                    validation_packet_module,
                    "parse_canonical_jsonl",
                    side_effect=AssertionError("cache-warm validation parsed source JSONL"),
                ),
            ):
                actual = build_content_validation_job_prepared_v0(
                    fixture["context"],
                    fixture["resolved"],
                    loaded,
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

    def test_cache_warm_fluency_initial_and_correction_paths_are_exact_and_keyed(self) -> None:
        correction_authority = _accuracy_authority_with_validation(
            (("KEEP", KEEP_REASON), ("KEEP", KEEP_REASON))
        )
        cases = (
            ("initial", _validation_fixture(), None),
            (
                "correction",
                _correction_validation_fixture(correction_authority),
                correction_authority,
            ),
        )
        for label, fixture, correction in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as cache_parent:
                provenance = (
                    _initial_provenance(fixture)
                    if correction is None
                    else _correction_provenance(correction)
                )
                canonical = _validation_call(fixture, **provenance)
                loaded = self._cached_fixture_authority(fixture, source_directory, cache_parent)
                prepared = prepared_module._prepared_source_parts_v0(loaded)
                revisions = _LookupOnlyMapping(prepared._revision_index)
                access = self._access_view(loaded, _revision_index=revisions)
                with (
                    patch.object(fluency_bridge_module, "_prepared_source_parts_v0", return_value=access),
                    patch.object(
                        validation_packet_module,
                        "parse_canonical_jsonl",
                        side_effect=AssertionError("cache-warm fluency validation parsed source JSONL"),
                    ),
                ):
                    actual = _prepared_validation_call(fixture, loaded, **provenance)
                self.assertEqual(canonical, actual)
                self.assertEqual(len(fixture["translation_packet"].rows), revisions.lookups)

    def test_reconciliation_history_and_relation_absence_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as historical_directory, tempfile.TemporaryDirectory() as cache_parent:
            _resolved, corpus, _scope, _authority = self._authority(source_directory)
            _resolved, _corpus, _scope, authority = self._authority(historical_directory, previous=corpus)
            receipt = build_prepared_source_cache_v0(authority, Path(cache_parent), producer_distribution_sha256=PRODUCER_SHA)
            loaded = load_prepared_source_authority_v0(Path(cache_parent) / receipt.cache_id, expected=receipt)
            self.assertEqual(authority.reconciliation_bytes, loaded.reconciliation_bytes)
            self.assertEqual(authority.reconciliation, loaded.reconciliation)

        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as cache_parent:
            _resolved, _corpus, _scope, authority = self._authority(source_directory, "flat")
            receipt = build_prepared_source_cache_v0(authority, Path(cache_parent), producer_distribution_sha256=PRODUCER_SHA)
            loaded = load_prepared_source_authority_v0(Path(cache_parent) / receipt.cache_id, expected=receipt)
            self.assertIsNone(loaded.relations_bytes)
            self.assertEqual((), loaded.relations)

    def test_collision_receipt_corruption_and_inventory_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as cache_parent:
            _resolved, _corpus, _scope, authority = self._authority(source_directory)
            receipt = build_prepared_source_cache_v0(authority, Path(cache_parent), producer_distribution_sha256=PRODUCER_SHA)
            root = Path(cache_parent) / receipt.cache_id
            original = self._tree(root)
            with self.assertRaises(ContractViolation) as collision:
                build_prepared_source_cache_v0(authority, Path(cache_parent), producer_distribution_sha256=PRODUCER_SHA)
            self.assertEqual(ErrorCode.OUTPUT_CONTRACT_VIOLATION, collision.exception.record.code)
            self.assertEqual(original, self._tree(root))

            wrong = replace(receipt, producer_distribution_sha256="e" * 64)
            with self.assertRaises(ContractViolation) as mismatch:
                load_prepared_source_authority_v0(root, expected=wrong)
            self.assertEqual(ErrorCode.BINDING_MISMATCH, mismatch.exception.record.code)

            (root / "unexpected").write_bytes(b"x")
            with self.assertRaises(ContractViolation) as extra:
                load_prepared_source_authority_v0(root, expected=receipt)
            self.assertEqual(ErrorCode.MALFORMED_ARTIFACT, extra.exception.record.code)
            (root / "unexpected").unlink()

            shard = next((root / "prepared" / "segments").glob("*.jsonl"))
            shard.write_bytes(shard.read_bytes() + b"x")
            with self.assertRaises(ContractViolation) as corrupt:
                load_prepared_source_authority_v0(root, expected=receipt)
            self.assertEqual(ErrorCode.HASH_MISMATCH, corrupt.exception.record.code)

    def test_cross_shard_relation_reorder_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as cache_parent, patch.object(
            cache_module,
            "_SHARD_TARGET_BYTES",
            1,
        ):
            _resolved, _corpus, _scope, authority = self._authority(source_directory)
            receipt = build_prepared_source_cache_v0(
                authority,
                Path(cache_parent),
                producer_distribution_sha256=PRODUCER_SHA,
            )
            root = Path(cache_parent) / receipt.cache_id
            manifest = strict_loads((root / "manifest.json").read_bytes())
            relation_rows = [row for row in manifest["files"] if row["role"] == "PREPARED_RELATIONS"]
            self.assertGreaterEqual(len(relation_rows), 2)
            first_path = root / Path(*relation_rows[0]["path"].split("/"))
            second_path = root / Path(*relation_rows[1]["path"].split("/"))
            first_payload = first_path.read_bytes()
            second_payload = second_path.read_bytes()
            first_path.write_bytes(second_payload)
            second_path.write_bytes(first_payload)
            for row, payload in ((relation_rows[0], second_payload), (relation_rows[1], first_payload)):
                row["byte_length"] = len(payload)
                row["record_count"] = payload.count(b"\n")
                row["sha256"] = raw_sha256(payload)
            relation_payloads = [
                (root / Path(*row["path"].split("/"))).read_bytes()
                for row in relation_rows
            ]
            manifest["aggregates"]["prepared_relations_sha256"] = hashlib.sha256(
                b"".join(relation_payloads)
            ).hexdigest()
            projection = dict(manifest)
            projection.pop("cache_id")
            manifest["cache_id"] = raw_sha256(canonical_json_bytes(projection))
            manifest_bytes = canonical_json_bytes(manifest)
            (root / "manifest.json").write_bytes(manifest_bytes)
            rebound_root = root.parent / manifest["cache_id"]
            root.rename(rebound_root)
            rebound_receipt = cache_module._receipt(manifest, manifest_bytes)
            with self.assertRaises(ContractViolation) as reordered:
                load_prepared_source_authority_v0(rebound_root, expected=rebound_receipt)
            self.assertEqual(ErrorCode.HASH_MISMATCH, reordered.exception.record.code)
            self.assertIn("crosses shard boundary", reordered.exception.record.detail)

    def test_owned_cleanup_attempts_all_roots_and_has_stable_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            staging = parent / ".locpipe-cache-staging-test"
            final = parent / ("a" * 64)
            staging.mkdir()
            final.mkdir()
            original_rmtree = cache_module.shutil.rmtree
            attempted = []

            def fail_staging(path):
                attempted.append(Path(path))
                if Path(path) == staging:
                    raise OSError("synthetic staging cleanup failure")
                return original_rmtree(path)

            with patch.object(cache_module.shutil, "rmtree", side_effect=fail_staging):
                with self.assertRaises(ContractViolation) as caught:
                    cache_module._cleanup_owned((staging, final), parent)
            self.assertEqual(ErrorCode.OUTPUT_CONTRACT_VIOLATION, caught.exception.record.code)
            self.assertEqual([staging, final], attempted)
            self.assertTrue(staging.is_dir())
            self.assertFalse(final.exists())

    def test_staging_cleanup_failure_removes_owned_final_and_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as cache_parent:
            _resolved, _corpus, _scope, authority = self._authority(source_directory)
            original_rmtree = cache_module.shutil.rmtree

            def fail_staging(path):
                candidate = Path(path)
                if candidate.name.startswith(".locpipe-cache-staging-"):
                    raise OSError("synthetic staging cleanup failure")
                return original_rmtree(path)

            with (
                patch.object(cache_module.shutil, "rmtree", side_effect=fail_staging),
                self.assertRaises(ContractViolation) as caught,
            ):
                build_prepared_source_cache_v0(
                    authority,
                    Path(cache_parent),
                    producer_distribution_sha256=PRODUCER_SHA,
                )
            self.assertEqual(ErrorCode.OUTPUT_CONTRACT_VIOLATION, caught.exception.record.code)
            children = tuple(Path(cache_parent).iterdir())
            self.assertTrue(any(path.name.startswith(".locpipe-cache-staging-") for path in children))
            self.assertFalse(any(len(path.name) == 64 for path in children))

    def test_final_verification_cleanup_failure_after_manifest_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as cache_parent:
            _resolved, _corpus, _scope, authority = self._authority(source_directory)
            original_rmtree = cache_module.shutil.rmtree

            def fail_final(path):
                candidate = Path(path)
                if len(candidate.name) == 64:
                    raise OSError("synthetic final cleanup failure")
                return original_rmtree(path)

            verification_error = ContractViolation(ErrorCode.HASH_MISMATCH, "synthetic final verification failure")
            with (
                patch.object(cache_module, "_read_and_validate_inventory", side_effect=verification_error),
                patch.object(cache_module.shutil, "rmtree", side_effect=fail_final),
                self.assertRaises(ContractViolation) as caught,
            ):
                build_prepared_source_cache_v0(
                    authority,
                    Path(cache_parent),
                    producer_distribution_sha256=PRODUCER_SHA,
                )
            self.assertEqual(ErrorCode.OUTPUT_CONTRACT_VIOLATION, caught.exception.record.code)
            final_roots = [path for path in Path(cache_parent).iterdir() if len(path.name) == 64]
            self.assertEqual(1, len(final_roots))
            self.assertTrue((final_roots[0] / "manifest.json").is_file())

    def test_missing_manifest_sharding_and_registry_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as cache_parent:
            _resolved, _corpus, _scope, authority = self._authority(source_directory)
            receipt = build_prepared_source_cache_v0(authority, Path(cache_parent), producer_distribution_sha256=PRODUCER_SHA)
            root = Path(cache_parent) / receipt.cache_id
            (root / "manifest.json").unlink()
            with self.assertRaises(ContractViolation) as partial:
                load_prepared_source_authority_v0(root, expected=receipt)
            self.assertEqual(ErrorCode.MALFORMED_ARTIFACT, partial.exception.record.code)

        with tempfile.TemporaryDirectory() as staging_directory, patch.object(cache_module, "_SHARD_TARGET_BYTES", 8):
            rows, aggregate = cache_module._stage_shards(
                Path(staging_directory),
                (b"123\n", b"456\n", b"oversize\n"),
                family="segments",
                role="PREPARED_SEGMENTS",
            )
            self.assertEqual(
                ["prepared/segments/000000.jsonl", "prepared/segments/000001.jsonl"],
                [row["path"] for row in rows],
            )
            self.assertEqual(
                [8, 9],
                [(Path(staging_directory) / Path(*row["path"].split("/"))).stat().st_size for row in rows],
            )
        self.assertEqual(raw_sha256(b"123\n456\noversize\n"), aggregate)

        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as cache_parent:
            _resolved, _corpus, _scope, authority = self._authority(source_directory)
            receipt = build_prepared_source_cache_v0(authority, Path(cache_parent), producer_distribution_sha256=PRODUCER_SHA)
            root = Path(cache_parent) / receipt.cache_id
            loaded = [load_prepared_source_authority_v0(root, expected=receipt) for _ in range(8)]
            loaded_keys = {id(row) for row in loaded}
            self.assertTrue(loaded_keys <= set(prepared_module._BINDER_REGISTRY))
            loaded.clear()
            del authority
        gc.collect()
        self.assertTrue(loaded_keys.isdisjoint(prepared_module._BINDER_REGISTRY))


if __name__ == "__main__":
    unittest.main()
