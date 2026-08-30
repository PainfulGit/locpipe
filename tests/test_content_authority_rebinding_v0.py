from __future__ import annotations

from dataclasses import replace
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.content.v0 import (  # noqa: E402
    LoadedSourceCorpusV0,
    ScopeEntryV0,
    ScopeRoleV0,
    SourceReconciliationV0,
    TargetValidityStateV0,
    TargetValidityV0,
    freeze_scope_v0,
    load_source_corpus_v0,
    rebind_source_authority_v0,
    reconcile_sources_v0,
)
from locpipe.contracts.v0 import ContractViolation, canonical_json_bytes  # noqa: E402
from tests.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0  # noqa: E402


CONFIG_A = "a" * 64
CONFIG_B = "b" * 64
CONFIG_C = "c" * 64
FIXTURE = ROOT / "tests/conformance/adapter_v0/fixtures/structured/golden"


def _load(config_snapshot_sha256: str) -> LoadedSourceCorpusV0:
    adapter = SyntheticStructuredAdapterV0()
    return load_source_corpus_v0(
        FIXTURE,
        snapshot_path="source_snapshot.json",
        segments_path="segments.jsonl",
        relations_path="relations.jsonl",
        descriptor=adapter.descriptor,
        config_snapshot_sha256=config_snapshot_sha256,
    )


def _lock_bytes(corpus: LoadedSourceCorpusV0) -> bytes:
    return canonical_json_bytes(corpus.lock.as_dict())


def _reconciliation_bytes(reconciliation: SourceReconciliationV0) -> bytes:
    return canonical_json_bytes(reconciliation.as_dict())


def _freeze(
    corpus: LoadedSourceCorpusV0,
    reconciliation: SourceReconciliationV0,
    *,
    config_snapshot_sha256: str,
    source_lock_bytes: bytes | None = None,
    reconciliation_bytes: bytes | None = None,
):
    entries = tuple(ScopeEntryV0(row.identity, ScopeRoleV0.OWNED) for row in corpus.segments)
    return freeze_scope_v0(
        corpus,
        reconciliation,
        entries,
        target_locales=("uk",),
        config_snapshot_sha256=config_snapshot_sha256,
        source_lock_bytes=_lock_bytes(corpus) if source_lock_bytes is None else source_lock_bytes,
        reconciliation_bytes=(
            _reconciliation_bytes(reconciliation)
            if reconciliation_bytes is None
            else reconciliation_bytes
        ),
    )


class ContentAuthorityRebindingV0Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = _load(CONFIG_A)
        self.base_reconciliation = reconcile_sources_v0(self.base)

    def test_same_and_cross_config_rebinding_matches_independent_direct_loads(self) -> None:
        base_lock = _lock_bytes(self.base)
        base_reconciliation = _reconciliation_bytes(self.base_reconciliation)
        base_segments = self.base.segments
        base_relations = self.base.relation_envelopes

        for config_sha in (CONFIG_A, CONFIG_B):
            with self.subTest(config_sha=config_sha):
                rebound, reconciliation = rebind_source_authority_v0(
                    self.base,
                    self.base_reconciliation,
                    config_snapshot_sha256=config_sha,
                )
                direct = _load(config_sha)
                direct_reconciliation = reconcile_sources_v0(direct)
                self.assertIsNot(rebound, self.base)
                self.assertIsNot(reconciliation, self.base_reconciliation)
                self.assertIs(rebound.segments, self.base.segments)
                self.assertIs(rebound.relation_envelopes, self.base.relation_envelopes)
                self.assertTrue(all(left is right for left, right in zip(rebound.segments, self.base.segments)))
                self.assertTrue(all(
                    left is right
                    for left, right in zip(rebound.relation_envelopes, self.base.relation_envelopes)
                ))
                self.assertEqual(_lock_bytes(direct), _lock_bytes(rebound))
                self.assertEqual(
                    _reconciliation_bytes(direct_reconciliation),
                    _reconciliation_bytes(reconciliation),
                )

        self.assertIs(base_segments, self.base.segments)
        self.assertIs(base_relations, self.base.relation_envelopes)
        self.assertEqual(base_lock, _lock_bytes(self.base))
        self.assertEqual(base_reconciliation, _reconciliation_bytes(self.base_reconciliation))

    def test_rebinding_does_not_read_or_parse_canonical_authority(self) -> None:
        with (
            patch.object(Path, "read_bytes", side_effect=AssertionError("filesystem read")),
            patch("locpipe.content.v0._corpus.parse_canonical_json", side_effect=AssertionError("JSON parse")),
            patch("locpipe.content.v0._corpus.parse_canonical_jsonl", side_effect=AssertionError("JSONL parse")),
        ):
            rebound, reconciliation = rebind_source_authority_v0(
                self.base,
                self.base_reconciliation,
                config_snapshot_sha256=CONFIG_B,
            )
        self.assertEqual(CONFIG_B, rebound.lock.config_snapshot_sha256)
        self.assertEqual(rebound.lock.corpus_digest, reconciliation.current_corpus_digest)

    def test_same_digest_input_history_is_not_copied_to_rebound_reconciliation(self) -> None:
        supplied = SourceReconciliationV0(
            "d" * 64,
            self.base.lock.corpus_digest,
            (),
            ("synthetic.tombstone",),
            (TargetValidityV0("synthetic.target", TargetValidityStateV0.VALID, ()),),
        )
        rebound, reconciliation = rebind_source_authority_v0(
            self.base,
            supplied,
            config_snapshot_sha256=CONFIG_B,
        )
        expected = reconcile_sources_v0(rebound)
        self.assertEqual(_reconciliation_bytes(expected), _reconciliation_bytes(reconciliation))
        self.assertIsNone(reconciliation.previous_corpus_digest)
        self.assertNotEqual(supplied.events, reconciliation.events)
        self.assertNotEqual(supplied.tombstones, reconciliation.tombstones)
        self.assertNotEqual(supplied.target_validity, reconciliation.target_validity)

    def test_exact_types_sha_and_foreign_reconciliation_fail_before_construction(self) -> None:
        class CorpusSubclass(LoadedSourceCorpusV0):
            pass

        class ReconciliationSubclass(SourceReconciliationV0):
            pass

        class ShaSubclass(str):
            pass

        corpus_subclass = CorpusSubclass(
            self.base.lock,
            self.base.segments,
            self.base.relation_envelopes,
        )
        reconciliation_subclass = ReconciliationSubclass(
            self.base_reconciliation.previous_corpus_digest,
            self.base_reconciliation.current_corpus_digest,
            self.base_reconciliation.events,
            self.base_reconciliation.tombstones,
            self.base_reconciliation.target_validity,
        )
        invalid_rows = (
            (corpus_subclass, self.base_reconciliation, CONFIG_B),
            (self.base, reconciliation_subclass, CONFIG_B),
            (self.base, self.base_reconciliation, ShaSubclass(CONFIG_B)),
            (self.base, self.base_reconciliation, True),
            (self.base, self.base_reconciliation, b"b" * 64),
            (self.base, self.base_reconciliation, "B" * 64),
            (self.base, self.base_reconciliation, "b" * 63),
        )
        for corpus, reconciliation, config_sha in invalid_rows:
            with self.subTest(config_sha=repr(config_sha)):
                with self.assertRaises(ContractViolation):
                    rebind_source_authority_v0(
                        corpus,
                        reconciliation,
                        config_snapshot_sha256=config_sha,
                    )

        foreign = reconcile_sources_v0(_load(CONFIG_C))
        stale = replace(
            self.base_reconciliation,
            current_corpus_digest="f" * 64,
        )
        for reconciliation in (foreign, stale):
            with patch(
                "locpipe.content.v0._reconciliation._rebind_loaded_source_corpus_v0"
            ) as rebinder:
                with self.assertRaises(ContractViolation):
                    rebind_source_authority_v0(
                        self.base,
                        reconciliation,
                        config_snapshot_sha256=CONFIG_B,
                    )
                rebinder.assert_not_called()

    def test_same_config_scope_accepts_and_cross_config_authority_fails_closed(self) -> None:
        rebound_a, reconciliation_a = rebind_source_authority_v0(
            self.base,
            self.base_reconciliation,
            config_snapshot_sha256=CONFIG_A,
        )
        rebound_b, reconciliation_b = rebind_source_authority_v0(
            self.base,
            self.base_reconciliation,
            config_snapshot_sha256=CONFIG_B,
        )
        rebound_c, reconciliation_c = rebind_source_authority_v0(
            self.base,
            self.base_reconciliation,
            config_snapshot_sha256=CONFIG_C,
        )
        self.assertEqual(CONFIG_A, _freeze(
            rebound_a,
            reconciliation_a,
            config_snapshot_sha256=CONFIG_A,
        ).config_snapshot_sha256)
        self.assertEqual(CONFIG_B, _freeze(
            rebound_b,
            reconciliation_b,
            config_snapshot_sha256=CONFIG_B,
        ).config_snapshot_sha256)

        mismatches = (
            {
                "corpus": rebound_b,
                "reconciliation": reconciliation_b,
                "config_snapshot_sha256": CONFIG_B,
                "source_lock_bytes": _lock_bytes(self.base),
            },
            {
                "corpus": rebound_b,
                "reconciliation": self.base_reconciliation,
                "config_snapshot_sha256": CONFIG_B,
            },
            {
                "corpus": rebound_b,
                "reconciliation": reconciliation_b,
                "config_snapshot_sha256": CONFIG_C,
            },
            {
                "corpus": rebound_b,
                "reconciliation": reconciliation_c,
                "config_snapshot_sha256": CONFIG_B,
            },
            {
                "corpus": rebound_c,
                "reconciliation": reconciliation_c,
                "config_snapshot_sha256": CONFIG_C,
                "reconciliation_bytes": _reconciliation_bytes(reconciliation_b),
            },
        )
        for mismatch in mismatches:
            with self.subTest(mismatch=tuple(sorted(mismatch))):
                with self.assertRaises(ContractViolation):
                    _freeze(**mismatch)


if __name__ == "__main__":
    unittest.main()
