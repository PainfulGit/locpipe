from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from inspect import signature
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.contracts.v0 import (
    BranchIdentity,
    ContractViolation,
    ErrorCode,
    canonical_json_bytes,
    canonical_jsonl_bytes,
    display_id,
    parse_canonical_json,
    parse_canonical_jsonl,
    raw_sha256,
    semantic_sha256,
)
from locpipe.editorial.v0 import EditorialCandidateSetV0
from locpipe.translation.v0 import TranslationPacketV0
import locpipe.validation.v0._packet as validation_packet

from test_content_validation_v0 import SyntheticContentValidatorV0, validation_fixture
from tests.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0


_GOLDEN = {
    "editorial": {
        "job_id": "validation-2d76789d87d4c0b599049a08e75dac42",
        "job_sha256": "dda2ca28a72c143579eb3246eac3af671e0fea5ef06bc9fc506a6d0fbaa9bb34",
        "packet_sha256": "6bc4d4db127ff9eeecfe2c5a47be8f3682b63ea2a43700ebf85cc1abc64b4314",
        "authority_manifest_sha256": "999ebb3ceefc74952122f8ec978fc998662f6fc6f6beb7f2a6d451a401102481",
        "authority_sha256": "5808da661e282e9420782bf0262d0fcd92abaa6937aec4eda55bb22aac3a554f",
        "candidate_authority_sha256": "652edc5f52f27b6e3bd655dbeceb7b3c43820aa75efd25eb4a287957f2187832",
    },
    "bypass": {
        "job_id": "validation-dc335be35d62c610fec756d967a97992",
        "job_sha256": "6888e88224a2cac4f63b2cdecf6e5048a3a7970dfb5a7dccd204a465d8bb992d",
        "packet_sha256": "18507b0f51e164d7829e3dca01430d44e27547c6ea7c7ac7cc0f878f73caade9",
        "authority_manifest_sha256": "68630a089a8d33b8657b769176ac6fa881b18e49525a1ebd114f242b333631cd",
        "authority_sha256": "88568370ad4cf870e5583ae67da7d8ad18e5deb38fa913c7e8cffb1e361a5349",
        "candidate_authority_sha256": "091b96cdac4d9c43bcadb6ff11afec6a848f0c8b86010dc4d42b5f24e6a29a85",
    },
}


def _authority_manifest_bytes(rows: tuple[tuple[str, bytes], ...]) -> bytes:
    return canonical_json_bytes([
        {"path": path, "sha256": raw_sha256(payload)}
        for path, payload in rows
    ])


def _builder_call(
    fixture,
    *,
    function=validation_packet.build_content_validation_job_v0,
    supplemental_authority=None,
    **overrides,
):
    authority = dict(fixture["authority"])
    values = {
        "context": fixture["context"],
        "resolved": fixture["resolved"],
        "scope": fixture["scope"],
        "translation_job": fixture["translation_job"],
        "translation_packet": fixture["translation_packet"],
        "translation_decision_bytes": fixture["translation_decision_bytes"],
        "translation_state_bytes": fixture["translation_state_bytes"],
        "target_set": fixture["translation_target_set"],
        "candidate": fixture["candidate"],
        "validator": fixture["validator"],
        "source_lock_bytes": authority["source/source_lock.json"],
        "reconciliation_bytes": authority["reconciliation/reconciliation.json"],
        "scope_bytes": authority["scope/scope.json"],
        "scope_lock_bytes": authority["scope/scope_lock.json"],
        "segments_bytes": authority["corpus/segments.jsonl"],
        "candidate_evidence": fixture["candidate_evidence"],
        "editorial_job": fixture["editorial_job"],
        "editorial_packet": fixture["editorial_packet"],
        "editorial_policy": fixture["editorial_policy"],
    }
    values.update(overrides)
    positional = tuple(values.pop(name) for name in (
        "context",
        "resolved",
        "scope",
        "translation_job",
        "translation_packet",
        "translation_decision_bytes",
        "translation_state_bytes",
        "target_set",
        "candidate",
        "validator",
    ))
    if supplemental_authority is not None:
        values["supplemental_authority"] = supplemental_authority
    return function(*positional, **values)


def _assert_violation(test, code, message, callback) -> None:
    with test.assertRaises(ContractViolation) as caught:
        callback()
    test.assertEqual(code, caught.exception.record.code)
    test.assertIn(message, str(caught.exception))


class ValidationV0CompatibilityTests(unittest.TestCase):
    def test_pre_refactor_editorial_and_bypass_golden_bytes(self) -> None:
        for label, configured_editor in (("editorial", True), ("bypass", False)):
            with self.subTest(label=label):
                fixture = validation_fixture(configured_editor=configured_editor)
                job = fixture["job"]
                expected = _GOLDEN[label]
                self.assertEqual(expected["job_id"], job.job_id)
                self.assertEqual(
                    expected["job_sha256"],
                    raw_sha256(canonical_json_bytes(job.as_dict())),
                )
                self.assertEqual(
                    expected["packet_sha256"],
                    raw_sha256(canonical_json_bytes(fixture["packet"].as_dict())),
                )
                self.assertEqual(
                    expected["authority_manifest_sha256"],
                    raw_sha256(_authority_manifest_bytes(fixture["authority"])),
                )
                self.assertEqual(expected["authority_sha256"], job.authority_sha256)
                self.assertEqual(
                    expected["candidate_authority_sha256"],
                    job.candidate_authority_sha256,
                )

    def test_public_wrapper_delegates_with_empty_supplemental_authority(self) -> None:
        fixture = validation_fixture()
        expected_parameters = (
            "context", "resolved", "scope", "translation_job", "translation_packet",
            "translation_decision_bytes", "translation_state_bytes", "target_set",
            "candidate", "validator", "source_lock_bytes", "reconciliation_bytes",
            "scope_bytes", "scope_lock_bytes", "segments_bytes", "candidate_evidence",
            "editorial_job", "editorial_packet", "editorial_policy",
        )
        self.assertEqual(
            expected_parameters,
            tuple(signature(validation_packet.build_content_validation_job_v0).parameters),
        )
        original = validation_packet._build_content_validation_job_from_authority_v0
        with patch.object(
            validation_packet,
            "_build_content_validation_job_from_authority_v0",
            wraps=original,
        ) as delegated:
            actual = _builder_call(fixture)
        self.assertEqual((fixture["job"], fixture["packet"], fixture["authority"]), actual)
        self.assertEqual((), delegated.call_args.kwargs["supplemental_authority"])

    def test_representative_base_failures_keep_codes_and_boundaries(self) -> None:
        fixture = validation_fixture()
        authority = dict(fixture["authority"])

        _assert_violation(
            self,
            ErrorCode.BINDING_MISMATCH,
            "context",
            lambda: _builder_call(
                fixture,
                context=replace(fixture["context"], config_snapshot_sha256="0" * 64),
            ),
        )
        _assert_violation(
            self,
            ErrorCode.HASH_MISMATCH,
            "translation packet drift",
            lambda: _builder_call(
                fixture,
                translation_job=replace(fixture["translation_job"], packet_sha256="0" * 64),
            ),
        )
        _assert_violation(
            self,
            ErrorCode.HASH_MISMATCH,
            "segments differ",
            lambda: _builder_call(
                fixture,
                segments_bytes=authority["corpus/segments.jsonl"] + b"\n",
            ),
        )
        _assert_violation(
            self,
            ErrorCode.BINDING_MISMATCH,
            "candidate evidence shape",
            lambda: _builder_call(
                fixture,
                candidate_evidence=fixture["candidate_evidence"][:-1],
            ),
        )
        current = fixture["candidate"]
        incomplete = EditorialCandidateSetV0(
            current.job_id,
            current.target_locale,
            True,
            current.disposition,
            current.base_target_set_sha256,
            current.parent_candidate_sha256,
            current.overlay_sha256s,
            (),
            current._target_bytes[:-1],
        )
        _assert_violation(
            self,
            ErrorCode.BINDING_MISMATCH,
            "candidate authority",
            lambda: _builder_call(fixture, candidate=incomplete),
        )

        class MissingPlaceholderConstraintValidator(SyntheticContentValidatorV0):
            supported_constraint_keys = ()

        _assert_violation(
            self,
            ErrorCode.CAPABILITY_MISSING,
            "does not support packet constraints",
            lambda: _builder_call(
                fixture,
                validator=MissingPlaceholderConstraintValidator(),
            ),
        )

    def test_source_revision_and_relation_failures_keep_exact_codes(self) -> None:
        fixture = validation_fixture(name="structured", adapter=SyntheticStructuredAdapterV0())
        authority = dict(fixture["authority"])
        sort_key = lambda row: display_id(BranchIdentity.from_dict(row["data"]["identity"]))
        source_rows = parse_canonical_jsonl(
            authority["corpus/segments.jsonl"],
            sort_key=sort_key,
        )
        drifted_rows = deepcopy(source_rows)
        drifted_rows[0]["data"]["source_revision_sha"] = "f" * 64
        drifted_segments = canonical_jsonl_bytes(drifted_rows, sort_key=sort_key)
        source_lock = parse_canonical_json(authority["source/source_lock.json"])
        source_lock["segments_sha256"] = raw_sha256(drifted_segments)
        source_lock_bytes = canonical_json_bytes(source_lock)
        drifted_translation_job = replace(
            fixture["translation_job"],
            source_lock_sha256=raw_sha256(source_lock_bytes),
        )
        _assert_violation(
            self,
            ErrorCode.HASH_MISMATCH,
            "source dependency is stale",
            lambda: _builder_call(
                fixture,
                translation_job=drifted_translation_job,
                source_lock_bytes=source_lock_bytes,
                segments_bytes=drifted_segments,
            ),
        )

        relation_rows = [parse_canonical_json(row) for row in fixture["translation_packet"]._relation_bytes]
        self.assertTrue(relation_rows)
        relation_rows[0] = deepcopy(relation_rows[0])
        reference = relation_rows[0]["data"]["from_ref"]
        if reference["kind"] == "branch":
            reference["identity"]["logical_id"] = ["foreign", "relation"]
        else:
            reference["logical_id"] = ["foreign", "relation"]
        relation_bytes = tuple(sorted(
            (canonical_json_bytes(row) for row in relation_rows),
            key=lambda payload: semantic_sha256(parse_canonical_json(payload)),
        ))
        drifted_packet = TranslationPacketV0(
            fixture["translation_packet"].target_locale,
            fixture["translation_packet"].rows,
            relation_bytes,
        )
        drifted_job = replace(
            fixture["translation_job"],
            packet_sha256=raw_sha256(canonical_json_bytes(drifted_packet.as_dict())),
        )
        _assert_violation(
            self,
            ErrorCode.DANGLING_RELATION,
            "outside packet",
            lambda: _builder_call(
                fixture,
                translation_job=drifted_job,
                translation_packet=drifted_packet,
            ),
        )

    def test_supplemental_authority_is_closed_deterministic_and_collision_safe(self) -> None:
        fixture = validation_fixture()
        supplemental = (("fluency/validation-authority.json", b'{"contract":"fixture.supplemental/v0"}\n'),)
        first = _builder_call(
            fixture,
            function=validation_packet._build_content_validation_job_from_authority_v0,
            supplemental_authority=supplemental,
        )
        second = _builder_call(
            fixture,
            function=validation_packet._build_content_validation_job_from_authority_v0,
            supplemental_authority=supplemental,
        )
        self.assertEqual(first, second)
        job, packet, authority = first
        self.assertNotEqual(fixture["job"].job_id, job.job_id)
        self.assertNotEqual(fixture["job"].authority_sha256, job.authority_sha256)
        self.assertEqual(fixture["job"].candidate_authority_sha256, job.candidate_authority_sha256)
        self.assertEqual(fixture["packet"], packet)
        self.assertEqual(supplemental[0][1], dict(authority)[supplemental[0][0]])

        invalid = (
            (
                (("z.json", b"{}\n"), ("a.json", b"{}\n")),
                ErrorCode.DUPLICATE_IDENTITY,
            ),
            (
                (("a.json", b"{}\n"), ("a.json", b"{}\n")),
                ErrorCode.DUPLICATE_IDENTITY,
            ),
            (
                (("a.json", bytearray(b"{}\n")),),
                ErrorCode.MALFORMED_ARTIFACT,
            ),
            *(
                (((unsafe_path, b"{}\n"),), ErrorCode.MALFORMED_ARTIFACT)
                for unsafe_path in (
                    "../escape.json",
                    "/absolute.json",
                    "C:/drive.json",
                    "x\\y.json",
                    "x//y.json",
                    "x/../corpus/segments.jsonl",
                )
            ),
            (
                (("corpus/segments.jsonl", b"{}\n"),),
                ErrorCode.BINDING_MISMATCH,
            ),
        )
        for rows, code in invalid:
            with self.subTest(code=code, rows=rows):
                _assert_violation(
                    self,
                    code,
                    "supplemental authority",
                    lambda rows=rows: _builder_call(
                        fixture,
                        function=validation_packet._build_content_validation_job_from_authority_v0,
                        supplemental_authority=rows,
                    ),
                )


if __name__ == "__main__":
    unittest.main()
