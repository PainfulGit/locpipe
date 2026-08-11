from __future__ import annotations

import copy
import json
import math
import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from locpipe.contracts.v0 import (  # noqa: E402
    AdapterDescriptorV0,
    BranchIdentity,
    Capability,
    ContractViolation,
    ErrorCode,
    ModuleDescriptorV0,
    SelectorStep,
    WorkflowProfile,
    canonical_json_bytes,
    canonical_jsonl_bytes,
    display_id,
    load_schema_registry,
    normalized_text,
    parse_canonical_json,
    parse_canonical_jsonl,
    parse_display_id,
    semantic_sha256,
    source_revision_sha,
    strict_loads,
    validate_envelope,
    validate_module_bindings,
    validate_profile,
    validate_profile_bindings,
    validate_relation_set,
)


CONTRACT = ROOT / "src" / "locpipe" / "contracts" / "v0"
SCHEMAS = CONTRACT / "schemas"
FIXTURES = CONTRACT / "fixtures"
SHA = "a" * 64
REQUIRED = {
    Capability.EXTRACT_IMPORT,
    Capability.SOURCE_SNAPSHOT,
    Capability.SOURCE_RECONCILIATION,
    Capability.CONTENT_VALIDATION,
}
OPTIONAL = {
    Capability.TRANSLATION,
    Capability.EDITORIAL_REVIEW,
    Capability.TERMINOLOGY,
    Capability.ISSUES,
}


def identity(locale: str = "en", value: str = "one") -> BranchIdentity:
    return BranchIdentity(
        ("synthetic", "dialogue", "greeting"),
        locale,
        (SelectorStep("count", "plural", value),),
    )


def source_envelope() -> dict[str, object]:
    branch = identity()
    constraints = {"placeholder": "none"}
    return {
        "schema_id": "urn:locpipe:contracts:v0:segment",
        "schema_version": "0.1.0-draft.2",
        "kind": "source_branch",
        "data": {
            "identity": branch.as_dict(),
            "content_type": "plain_text",
            "payload": "One signal.",
            "constraints": constraints,
            "source_revision_sha": source_revision_sha(
                identity=branch,
                content_type="plain_text",
                payload="One signal.",
                constraints=constraints,
            ),
            "locator": {"resource": "dialogue/greeting", "row": 1},
        },
    }


class CanonicalBytesTests(unittest.TestCase):
    def test_rfc8785_primitive_vector(self) -> None:
        value = {
            "numbers": [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27],
            "string": "€$\x0f\nA'B\"\\\\\"/",
            "literals": [None, True, False],
        }
        expected = (
            b'{"literals":[null,true,false],"numbers":[333333333.3333333,'
            b'1e+30,4.5,0.002,1e-27],"string":"\xe2\x82\xac$\\u000f\\nA\'B'
            b'\\"\\\\\\\\\\\"/"}'
        )
        self.assertEqual(expected + b"\n", canonical_json_bytes(value))

    def test_utf16_key_sorting_vector(self) -> None:
        value = {
            "€": "Euro Sign",
            "\r": "Carriage Return",
            "דּ": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "😀": "Emoji: Grinning Face",
            "\u0080": "Control",
            "ö": "Latin Small Letter O With Diaeresis",
        }
        encoded = canonical_json_bytes(value)
        order = [
            encoded.index(label.encode("utf-8"))
            for label in (
                "Carriage Return", "One", "Control",
                "Latin Small Letter O With Diaeresis", "Euro Sign",
                "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh",
            )
        ]
        self.assertEqual(sorted(order), order)

    def test_canonical_json_requires_exact_lf_and_no_bom(self) -> None:
        payload = canonical_json_bytes({"b": 2, "a": 1})
        self.assertEqual({"a": 1, "b": 2}, parse_canonical_json(payload))
        for broken in (payload[:-1], payload + b"\n", b"\xef\xbb\xbf" + payload, payload.replace(b"\n", b"\r\n")):
            with self.assertRaises(ContractViolation):
                parse_canonical_json(broken)

    def test_strict_parser_rejects_duplicate_nonfinite_and_unsafe_integer(self) -> None:
        for payload in (b'{"a":1,"a":2}', b'{"n":NaN}', b'{"n":Infinity}', b'{"n":9007199254740992}'):
            with self.assertRaises(ContractViolation):
                strict_loads(payload)
        with self.assertRaises(ContractViolation):
            canonical_json_bytes({"n": math.inf})

    def test_jsonl_requires_declared_unique_order(self) -> None:
        rows = [{"id": "b"}, {"id": "a"}]
        self.assertEqual(b'{"id":"a"}\n{"id":"b"}\n', canonical_jsonl_bytes(rows, sort_key=lambda row: row["id"]))
        with self.assertRaises(ContractViolation):
            canonical_jsonl_bytes(rows, sort_key=None)
        with self.assertRaises(ContractViolation):
            canonical_jsonl_bytes([{"id": "a"}, {"id": "a"}], sort_key=lambda row: row["id"])
        with self.assertRaises(ContractViolation):
            canonical_jsonl_bytes([], sort_key=lambda row: row["id"])

    def test_jsonl_parser_rejects_reversed_duplicate_scalar_and_empty(self) -> None:
        key = lambda row: row["id"]
        valid = b'{"id":"a"}\n{"id":"b"}\n'
        self.assertEqual(2, len(parse_canonical_jsonl(valid, sort_key=key)))
        for payload in (
            b'{"id":"b"}\n{"id":"a"}\n',
            b'{"id":"a"}\n{"id":"a"}\n',
            b'1\n',
            b'',
        ):
            with self.assertRaises(ContractViolation):
                parse_canonical_jsonl(payload, sort_key=key)

    def test_normalization_is_explicit_only(self) -> None:
        decomposed = "e\u0301"
        self.assertNotEqual(decomposed, normalized_text(decomposed))
        self.assertNotEqual(semantic_sha256(decomposed), semantic_sha256(normalized_text(decomposed)))


class IdentityTests(unittest.TestCase):
    def test_display_id_is_lossless_for_delimiters_unicode_and_case(self) -> None:
        values = [
            BranchIdentity(("a|b", "C"), "uk", ()),
            BranchIdentity(("a", "b|C"), "uk", ()),
            BranchIdentity(("é",), "uk", ()),
            BranchIdentity(("e\u0301",), "uk", ()),
            BranchIdentity(("Case",), "uk", ()),
            BranchIdentity(("case",), "uk", ()),
        ]
        ids = [display_id(value) for value in values]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(values, [parse_display_id(value) for value in ids])

    def test_branch_revision_ignores_locator_reorder_and_unrelated_branch(self) -> None:
        branch = identity()
        baseline = source_revision_sha(identity=branch, content_type="plain_text", payload="One signal.", constraints={"x": 1})
        reordered_constraints = {"x": 1}
        self.assertEqual(
            baseline,
            source_revision_sha(identity=branch, content_type="plain_text", payload="One signal.", constraints=reordered_constraints),
        )
        self.assertNotEqual(
            baseline,
            source_revision_sha(identity=branch, content_type="plain_text", payload="Changed.", constraints={"x": 1}),
        )
        self.assertEqual(
            baseline,
            source_revision_sha(identity=branch, content_type="plain_text", payload="One signal.", constraints={"x": 1}),
        )

    def test_selector_types_and_names_fail_closed(self) -> None:
        with self.assertRaises(ContractViolation):
            SelectorStep("count", "unknown", "one")
        with self.assertRaises(ContractViolation):
            BranchIdentity(("x",), "en", (SelectorStep("n", "select", "a"), SelectorStep("n", "plural", "one")))
        for broken in (
            {"name": 1, "type": "plural", "value": "one"},
            {"name": "count", "type": "plural", "value": True},
        ):
            with self.assertRaises(ContractViolation):
                SelectorStep.from_dict(broken)
        with self.assertRaises(ContractViolation):
            BranchIdentity.from_dict({"logical_id": ["x"], "locale": 1, "selector_path": []})


class ProfileAndBindingTests(unittest.TestCase):
    def available(self, profile: WorkflowProfile) -> set[Capability]:
        result = set(REQUIRED)
        if profile in {WorkflowProfile.ARTIFACT_BUILD, WorkflowProfile.INSTALLED_PATCH}:
            result.add(Capability.ARTIFACT_BUILD)
        if profile is WorkflowProfile.INSTALLED_PATCH:
            result.add(Capability.DELIVERY)
        return result

    def test_all_three_profiles_validate(self) -> None:
        for profile in WorkflowProfile:
            validate_profile(profile, self.available(profile), disabled_optional=OPTIONAL)

    def test_missing_forbidden_unknown_and_implicit_optional_fail(self) -> None:
        with self.assertRaisesRegex(ContractViolation, ErrorCode.CAPABILITY_MISSING.value):
            validate_profile(WorkflowProfile.CONTENT_ONLY, REQUIRED - {Capability.CONTENT_VALIDATION}, disabled_optional=OPTIONAL)
        with self.assertRaisesRegex(ContractViolation, ErrorCode.CAPABILITY_FORBIDDEN.value):
            validate_profile(WorkflowProfile.CONTENT_ONLY, REQUIRED | {Capability.ARTIFACT_BUILD}, disabled_optional=OPTIONAL)
        with self.assertRaisesRegex(ContractViolation, ErrorCode.CAPABILITY_UNKNOWN.value):
            validate_profile(WorkflowProfile.CONTENT_ONLY, [*(item.value for item in REQUIRED), "mystery"], disabled_optional=OPTIONAL)
        with self.assertRaisesRegex(ContractViolation, ErrorCode.CAPABILITY_MISSING.value):
            validate_profile(WorkflowProfile.CONTENT_ONLY, REQUIRED)
        with self.assertRaisesRegex(ContractViolation, ErrorCode.CAPABILITY_FORBIDDEN.value):
            validate_profile(
                WorkflowProfile.CONTENT_ONLY,
                REQUIRED,
                disabled_optional=OPTIONAL | {Capability.CONTENT_VALIDATION},
            )

    def test_pins_must_be_exact_sorted_and_unique(self) -> None:
        adapter = AdapterDescriptorV0("synthetic.adapter", "0.1.0", SHA, tuple(sorted(REQUIRED, key=lambda item: item.value)))
        self.assertEqual("synthetic.adapter", adapter.adapter_id)
        with self.assertRaises(ContractViolation):
            AdapterDescriptorV0("synthetic.adapter", ">=0.1", SHA, ())
        rows = (
            ModuleDescriptorV0(Capability.EDITORIAL_REVIEW, "first.review", "0.1.0", SHA),
            ModuleDescriptorV0(Capability.TERMINOLOGY, "first.terms", "0.1.0", SHA),
        )
        self.assertEqual(rows, validate_module_bindings(rows))
        with self.assertRaises(ContractViolation):
            validate_module_bindings((rows[1], rows[0]))
        with self.assertRaises(ContractViolation):
            validate_module_bindings((rows[0], rows[0]))

    def test_profile_capabilities_are_derived_from_pinned_bindings(self) -> None:
        available = sorted(capability.value for capability in REQUIRED)
        profile = {
            "schema_id": "urn:locpipe:contracts:v0:workflow-profile",
            "schema_version": "0.1.0-draft.2",
            "kind": "workflow_profile",
            "data": {
                "profile": "content-only",
                "available_capabilities": available,
                "disabled_optional": sorted(capability.value for capability in OPTIONAL),
                "terminal_state": "CONTENT_VERIFIED",
            },
        }
        binding = {
            "schema_id": "urn:locpipe:contracts:v0:binding",
            "schema_version": "0.1.0-draft.2",
            "kind": "binding_set",
            "data": {
                "adapter": {
                    "adapter_id": "synthetic.adapter",
                    "version": "0.1.0",
                    "digest": SHA,
                    "capabilities": available,
                },
                "modules": [],
            },
        }
        self.assertEqual(set(REQUIRED), set(validate_profile_bindings(profile, binding)))
        broken = copy.deepcopy(binding)
        broken["data"]["adapter"]["capabilities"].remove("content_validation")
        with self.assertRaisesRegex(ContractViolation, ErrorCode.HASH_MISMATCH.value):
            validate_profile_bindings(profile, broken)
        duplicate_owner = copy.deepcopy(binding)
        duplicate_owner["data"]["modules"] = [{
            "capability": "content_validation",
            "module_id": "synthetic.validation",
            "version": "0.1.0",
            "digest": "b" * 64,
        }]
        with self.assertRaisesRegex(ContractViolation, ErrorCode.DUPLICATE_IDENTITY.value):
            validate_profile_bindings(profile, duplicate_owner)

    def test_binding_fields_are_not_coerced(self) -> None:
        with self.assertRaises(ContractViolation):
            AdapterDescriptorV0(1, "0.1.0", SHA, ())
        with self.assertRaises(ContractViolation):
            ModuleDescriptorV0(Capability.TERMINOLOGY, "module", True, SHA)


class SchemaAndEnvelopeTests(unittest.TestCase):
    def test_schema_files_are_draft_2020_12_with_unique_ids(self) -> None:
        registry = load_schema_registry(SCHEMAS)
        self.assertEqual(10, len(registry))

    def test_schema_registry_rejects_unknown_reference_and_version_drift(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source in SCHEMAS.glob("*.schema.json"):
                (root / source.name).write_bytes(source.read_bytes())
            segment = json.loads((root / "segment.schema.json").read_text(encoding="utf-8"))
            segment["properties"]["schema_version"]["const"] = "0.2.0"
            (root / "segment.schema.json").write_text(json.dumps(segment), encoding="utf-8")
            with self.assertRaisesRegex(ContractViolation, ErrorCode.SCHEMA_VERSION_UNSUPPORTED.value):
                load_schema_registry(root)
            segment["properties"]["schema_version"]["const"] = "0.1.0-draft.2"
            segment["properties"]["data"] = {"$ref": "urn:locpipe:contracts:v0:missing"}
            (root / "segment.schema.json").write_text(json.dumps(segment), encoding="utf-8")
            with self.assertRaisesRegex(ContractViolation, ErrorCode.SCHEMA_UNKNOWN.value):
                load_schema_registry(root)

    def test_schema_registry_rejects_duplicate_json_keys(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source in SCHEMAS.glob("*.schema.json"):
                (root / source.name).write_bytes(source.read_bytes())
            path = root / "common.schema.json"
            path.write_bytes(path.read_bytes().replace(b'{\n  "$schema":', b'{\n  "$id":"duplicate",\n  "$schema":', 1))
            with self.assertRaises(ContractViolation):
                load_schema_registry(root)

    def test_source_envelope_validates_and_hash_drift_blocks(self) -> None:
        value = source_envelope()
        self.assertEqual(value, validate_envelope(value))
        broken = copy.deepcopy(value)
        broken["data"]["payload"] = "Changed."
        with self.assertRaisesRegex(ContractViolation, ErrorCode.HASH_MISMATCH.value):
            validate_envelope(broken)

    def test_unknown_kind_version_and_field_fail_closed(self) -> None:
        value = source_envelope()
        for field, replacement, code in (
            ("kind", "unknown", ErrorCode.SCHEMA_UNKNOWN),
            ("schema_version", "0.2.0", ErrorCode.SCHEMA_VERSION_UNSUPPORTED),
        ):
            broken = copy.deepcopy(value)
            broken[field] = replacement
            with self.assertRaisesRegex(ContractViolation, code.value):
                validate_envelope(broken)
        broken = copy.deepcopy(value)
        broken["data"]["extra"] = True
        with self.assertRaisesRegex(ContractViolation, ErrorCode.MALFORMED_ARTIFACT.value):
            validate_envelope(broken)

    def test_target_must_reference_same_logical_message(self) -> None:
        value = {
            "schema_id": "urn:locpipe:contracts:v0:segment",
            "schema_version": "0.1.0-draft.2",
            "kind": "target_branch",
            "data": {
                "identity": identity("uk").as_dict(),
                "source_logical_id": ["other"],
                "content_type": "plain_text",
                "payload": "Один сигнал.",
                "metadata_ref": None,
            },
        }
        with self.assertRaises(ContractViolation):
            validate_envelope(value)

    def test_typed_relation_rejects_dangling_endpoint(self) -> None:
        target = identity("uk")
        relation = {
            "schema_id": "urn:locpipe:contracts:v0:relation",
            "schema_version": "0.1.0-draft.2",
            "kind": "relation",
            "data": {
                "relation_type": "TARGET_OF",
                "from_ref": {"kind": "branch", "identity": target.as_dict()},
                "to_ref": {"kind": "logical_message", "logical_id": list(target.logical_id)},
            },
        }
        self.assertEqual(1, validate_relation_set([relation], branch_identities=[target], locales=["en", "uk"]))
        broken = copy.deepcopy(relation)
        broken["data"]["from_ref"]["identity"]["locale"] = "pl"
        with self.assertRaisesRegex(ContractViolation, ErrorCode.DANGLING_RELATION.value):
            validate_relation_set([broken], branch_identities=[target], locales=["en", "uk"])

    def test_receipt_rejects_non_posix_escape(self) -> None:
        import tempfile

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        artifact = root / "schemas" / "a.json"
        artifact.parent.mkdir()
        artifact.write_bytes(b"artifact")
        artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
        receipt = {
            "schema_id": "urn:locpipe:contracts:v0:receipt",
            "schema_version": "0.1.0-draft.2",
            "kind": "receipt",
            "data": {
                "operation": "schema-parse",
                "inputs": [{"path": "schemas/a.json", "hash_domain": "raw", "sha256": artifact_sha}],
                "outputs": [],
                "contract_sha256": SHA,
                "status": "PASS",
            },
        }
        validate_envelope(receipt, artifact_root=root)
        with self.assertRaises(ContractViolation):
            validate_envelope(receipt)
        for path in ("../outside", "a/./b", "a//b", "C:" + "/absolute", "a\\b"):
            broken = copy.deepcopy(receipt)
            broken["data"]["inputs"][0]["path"] = path
            with self.assertRaises(ContractViolation):
                validate_envelope(broken)

    def test_receipt_rejects_missing_mismatched_and_unverified_domains(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.json"
            artifact.write_bytes(b"{}\n")
            base = {
                "schema_id": "urn:locpipe:contracts:v0:receipt",
                "schema_version": "0.1.0-draft.2",
                "kind": "receipt",
                "data": {
                    "operation": "verify",
                    "inputs": [{"path": "artifact.json", "hash_domain": "raw", "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}],
                    "outputs": [],
                    "contract_sha256": SHA,
                    "status": "PASS",
                },
            }
            validate_envelope(base, artifact_root=root)
            missing = copy.deepcopy(base)
            missing["data"]["inputs"][0]["path"] = "missing.json"
            with self.assertRaisesRegex(ContractViolation, ErrorCode.HASH_MISMATCH.value):
                validate_envelope(missing, artifact_root=root)
            mismatch = copy.deepcopy(base)
            mismatch["data"]["inputs"][0]["sha256"] = "b" * 64
            with self.assertRaisesRegex(ContractViolation, ErrorCode.HASH_MISMATCH.value):
                validate_envelope(mismatch, artifact_root=root)
            semantic = copy.deepcopy(base)
            semantic["data"]["inputs"][0]["hash_domain"] = "semantic"
            with self.assertRaisesRegex(ContractViolation, ErrorCode.MALFORMED_ARTIFACT.value):
                validate_envelope(semantic, artifact_root=root)
            semantic["data"]["inputs"][0]["sha256"] = semantic_sha256({})
            validate_envelope(
                semantic,
                artifact_root=root,
                hash_verifiers={"semantic": lambda path: semantic_sha256(strict_loads(path.read_bytes()[:-1]))},
            )

    def test_error_next_commands_must_be_a_list(self) -> None:
        value = {
            "schema_id": "urn:locpipe:contracts:v0:error",
            "schema_version": "0.1.0-draft.2",
            "kind": "error",
            "data": {
                "code": "MALFORMED_ARTIFACT",
                "category": "CONTRACT",
                "artifact": None,
                "safe_to_resume": False,
                "next_commands": False,
                "detail": "bad",
            },
        }
        with self.assertRaises(ContractViolation):
            validate_envelope(value)

    def test_synthetic_fixture_is_canonical_and_valid(self) -> None:
        payload = (FIXTURES / "synthetic_records.jsonl").read_bytes()
        order = {"source_branch": 0, "target_branch": 1, "relation": 2}
        records = parse_canonical_jsonl(payload, sort_key=lambda row: order[row["kind"]])
        self.assertEqual(3, len(records))
        for record in records:
            validate_envelope(record)



if __name__ == "__main__":
    unittest.main()
