from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from locpipe.contracts.v0 import (  # noqa: E402
    BranchIdentity,
    Capability,
    ContractViolation,
    KIND_TO_SCHEMA,
    WorkflowProfile,
    canonical_json_bytes,
    canonical_value_bytes,
    display_id,
    parse_canonical_json,
    raw_sha256,
)
from locpipe.contracts.v0.constants import CONTRACT_VERSION  # noqa: E402
from locpipe.editorial.v0 import EditorialCandidateSetV0  # noqa: E402
from locpipe.fluency.v0 import (  # noqa: E402
    FluencyReviewPacketRowV0,
    FluencyReviewPacketV0,
    FluencyTargetProjectionRowV0,
    FluencyTargetProjectionV0,
    build_fluency_review_job_v0,
    fluency_bindings_from_config_v0,
)
from locpipe.kernel.v0.config import (  # noqa: E402
    ConfigCheckpointV0,
    load_config_registry_v0,
    resolve_config_v0,
)
from locpipe.kernel.v0.context import ProjectContextV0  # noqa: E402
from locpipe.kernel.v0.transactions import NamespaceV0  # noqa: E402
from locpipe.translation.v0 import ProviderBudgetV0  # noqa: E402


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
REGISTRY = load_config_registry_v0((ROOT / "src/locpipe/resources/config_key_registry.csv").read_bytes())


def layers(*, include_accuracy: bool = True, include_fluency: bool = True):
    providers = [{
        "role": "translator",
        "provider_id": "offline-translator",
        "version": "1.0.0",
        "config_digest": SHA_A,
    }]
    if include_accuracy:
        providers.append({
            "role": "accuracy_editor",
            "provider_id": "offline-accuracy",
            "version": "1.0.0",
            "config_digest": SHA_B,
        })
    if include_fluency:
        providers.append({
            "role": "fluency_editor",
            "provider_id": "offline-fluency",
            "version": "1.0.0",
            "config_digest": SHA_C,
        })
    providers.sort(key=lambda row: (row["role"], row["provider_id"]))
    modules = [
        {
            "capability": Capability.EDITORIAL_REVIEW.value,
            "module_id": "fixture.editorial",
            "version": "1.0.0",
            "digest": SHA_B,
        },
        {
            "capability": Capability.TRANSLATION.value,
            "module_id": "fixture.translation",
            "version": "1.0.0",
            "digest": SHA_A,
        },
    ]
    modules.sort(key=lambda row: (row["capability"], row["module_id"]))
    return {
        "defaults": {"build_profile": {"mode": "default"}},
        "workspace": {"workspace_id": "workspace"},
        "project": {
            "project_id": "fixture",
            "workflow_profile": "content-only",
            "source_locale": "en",
            "target_locales": ["uk"],
            "module_bindings": modules,
            "provider_bindings": providers,
        },
        "release": {"release_id": "release"},
    }


def target(logical_id: str, payload: str) -> tuple[str, bytes]:
    identity = BranchIdentity((logical_id,), "uk", ())
    envelope = {
        "schema_id": KIND_TO_SCHEMA["target_branch"],
        "schema_version": CONTRACT_VERSION,
        "kind": "target_branch",
        "data": {
            "identity": identity.as_dict(),
            "source_logical_id": [logical_id],
            "content_type": "text",
            "payload": payload,
            "metadata_ref": None,
        },
    }
    return display_id(identity), canonical_json_bytes(envelope)


def guidance(kind: str, value: object, *, origin: str = "target_profile", extra: bool = False) -> bytes:
    payload_sha = raw_sha256(canonical_value_bytes(value))
    block = {
        "guidance_kind": kind,
        "origin": origin,
        "payload": value,
        "payload_sha256": payload_sha,
    }
    if extra:
        block["source_payload"] = "forbidden"
    return canonical_value_bytes(block)


def fixture(*, selected_layers=None):
    selected = selected_layers or layers()
    initial = resolve_config_v0(REGISTRY, selected, ConfigCheckpointV0.RELEASE_INIT)
    resolved = resolve_config_v0(REGISTRY, selected, ConfigCheckpointV0.SCOPE_FREEZE, initial.snapshot)
    context = ProjectContextV0(
        NamespaceV0("workspace", "fixture", "release"),
        WorkflowProfile.CONTENT_ONLY,
        resolved.config_snapshot_sha256,
    )
    targets = tuple(sorted((
        target("alpha", "Ціль альфа"),
        target("beta", "Ціль бета"),
        target("context", "Контекст цілі"),
    )))
    candidate = EditorialCandidateSetV0(
        "editorial-ready",
        "uk",
        True,
        "ACCEPTED",
        SHA_A,
        None,
        (),
        (),
        tuple(payload for _stable_id, payload in targets),
    )
    candidate_sha = raw_sha256(canonical_json_bytes(candidate.as_dict()))
    projection_rows = tuple(sorted((
        FluencyTargetProjectionRowV0(
            targets[0][0], "REVIEW", ("profile-main",), ("group-a",), (),
            (guidance("voice", {"register": "formal"}),),
        ),
        FluencyTargetProjectionRowV0(
            targets[1][0], "REVIEW", ("profile-main",), ("group-a",), ("relation-a",),
            (guidance("style", {"density": "compact"}),),
        ),
        FluencyTargetProjectionRowV0(
            targets[2][0], "CONTEXT", (), ("group-a",), ("relation-a",), (),
        ),
    ), key=lambda row: row.stable_id))
    projection = FluencyTargetProjectionV0(candidate_sha, "uk", projection_rows)
    requested = tuple(row.stable_id for row in projection.rows if row.role == "REVIEW")
    return context, resolved, candidate, projection, requested


class FluencyPacketV0Tests(unittest.TestCase):
    def test_deterministic_target_only_job_and_exact_requested_coverage(self) -> None:
        inputs = fixture()
        first = build_fluency_review_job_v0(
            *inputs[:4], candidate_authority_sha256=SHA_C, requested_ids=inputs[4],
            budget=ProviderBudgetV0(None, None),
        )
        second = build_fluency_review_job_v0(
            *inputs[:4], candidate_authority_sha256=SHA_C, requested_ids=inputs[4],
            budget=ProviderBudgetV0(None, None),
        )
        self.assertEqual(first, second)
        plan, job, packet = first
        self.assertEqual(inputs[4], plan.requested_ids)
        self.assertEqual(inputs[4], packet.requested_ids)
        self.assertEqual("accuracy_editor", plan.accuracy_provider.role)
        self.assertEqual("fluency_editor", job.provider.role)
        rendered = canonical_json_bytes(packet.as_dict())
        for forbidden in (b"source_payload", b"source_revision", b"constraints", b"bilingual_glossary"):
            self.assertNotIn(forbidden, rendered)

    def test_requested_subset_and_context_are_explicit_not_full_corpus_policy(self) -> None:
        context, resolved, candidate, projection, requested = fixture()
        self.assertLess(len(requested), len(candidate.as_dict()["targets"]))
        _plan, _job, packet = build_fluency_review_job_v0(
            context, resolved, candidate, projection,
            candidate_authority_sha256=SHA_C, requested_ids=requested,
            budget=ProviderBudgetV0(None, None),
        )
        context_id = next(row.stable_id for row in packet.rows if row.role == "CONTEXT")
        self.assertNotIn(context_id, packet.requested_ids)

    def test_missing_provider_roles_fail_closed(self) -> None:
        for include_accuracy, include_fluency in ((False, True), (True, False)):
            with self.subTest(accuracy=include_accuracy, fluency=include_fluency):
                selected = layers(include_accuracy=include_accuracy, include_fluency=include_fluency)
                initial = resolve_config_v0(REGISTRY, selected, ConfigCheckpointV0.RELEASE_INIT)
                resolved = resolve_config_v0(REGISTRY, selected, ConfigCheckpointV0.SCOPE_FREEZE, initial.snapshot)
                with self.assertRaisesRegex(ContractViolation, "missing or ambiguous"):
                    fluency_bindings_from_config_v0(resolved)

    def test_projection_requested_and_target_drift_fail_closed(self) -> None:
        context, resolved, candidate, projection, requested = fixture()
        with self.assertRaisesRegex(ContractViolation, "requested IDs"):
            build_fluency_review_job_v0(
                context, resolved, candidate, projection,
                candidate_authority_sha256=SHA_C, requested_ids=requested[:-1],
                budget=ProviderBudgetV0(None, None),
            )
        drifted = FluencyTargetProjectionV0(SHA_A, projection.target_locale, projection.rows)
        with self.assertRaisesRegex(ContractViolation, "candidate drift"):
            build_fluency_review_job_v0(
                context, resolved, candidate, drifted,
                candidate_authority_sha256=SHA_C, requested_ids=requested,
                budget=ProviderBudgetV0(None, None),
            )
        changed_targets = [canonical_json_bytes(row) for row in candidate.as_dict()["targets"]]
        changed_envelope = parse_canonical_json(changed_targets[0])
        changed_envelope["data"]["payload"] = "Інша ціль"
        changed_targets[0] = canonical_json_bytes(changed_envelope)
        changed = EditorialCandidateSetV0(
            candidate.job_id, candidate.target_locale, candidate.ready, candidate.disposition,
            candidate.base_target_set_sha256, candidate.parent_candidate_sha256,
            candidate.overlay_sha256s, candidate.unresolved_ids, tuple(changed_targets),
        )
        with self.assertRaisesRegex(ContractViolation, "candidate drift"):
            build_fluency_review_job_v0(
                context, resolved, changed, projection,
                candidate_authority_sha256=SHA_C, requested_ids=requested,
                budget=ProviderBudgetV0(None, None),
            )

    def test_closed_guidance_and_policy_bounds_fail_closed(self) -> None:
        stable_id = fixture()[4][0]
        for forbidden_origin in ("source_artifact", "source_packet", "bilingual_glossary"):
            with self.subTest(origin=forbidden_origin), self.assertRaisesRegex(ContractViolation, "not target-side"):
                FluencyTargetProjectionRowV0(
                    stable_id, "REVIEW", (), (), (),
                    (guidance("voice", {"sentinel": "FORBIDDEN_SOURCE"}, origin=forbidden_origin),),
                )
        signature = inspect.signature(build_fluency_review_job_v0)
        self.assertNotIn("source_packet", signature.parameters)
        self.assertNotIn("source_artifact", signature.parameters)
        with self.assertRaisesRegex(ContractViolation, "fields are invalid"):
            FluencyTargetProjectionRowV0(
                stable_id, "REVIEW", (), (), (), (guidance("voice", {}, extra=True),),
            )
        with self.assertRaises(ContractViolation):
            FluencyReviewPacketRowV0(stable_id, "REVIEW", (), (), (), (), b"{}\n")
        context, resolved, candidate, projection, requested = fixture()
        with self.assertRaisesRegex(ContractViolation, "finite within 0..2"):
            build_fluency_review_job_v0(
                context, resolved, candidate, projection,
                candidate_authority_sha256=SHA_C, requested_ids=requested,
                budget=ProviderBudgetV0(None, None), max_correction_rounds=3,
            )

    def test_packet_and_config_drift_fail_closed(self) -> None:
        context, resolved, candidate, projection, requested = fixture()
        _plan, _job, packet = build_fluency_review_job_v0(
            context, resolved, candidate, projection,
            candidate_authority_sha256=SHA_C, requested_ids=requested,
            budget=ProviderBudgetV0(None, None),
        )
        with self.assertRaisesRegex(ContractViolation, "coverage differs"):
            FluencyReviewPacketV0(
                packet.target_locale, packet.candidate_sha256, packet.projection_sha256,
                requested[:-1], packet.rows,
            )
        drifted_context = ProjectContextV0(
            NamespaceV0("workspace", "fixture", "release"),
            WorkflowProfile.CONTENT_ONLY,
            "d" * 64,
        )
        with self.assertRaisesRegex(ContractViolation, "config drift"):
            build_fluency_review_job_v0(
                drifted_context, resolved, candidate, projection,
                candidate_authority_sha256=SHA_C, requested_ids=requested,
                budget=ProviderBudgetV0(None, None),
            )

    def test_target_guidance_is_opaque_and_candidate_authority_is_declared_identity(self) -> None:
        context, resolved, candidate, projection, requested = fixture()
        first_row = projection.rows[0]
        opaque = FluencyTargetProjectionRowV0(
            first_row.stable_id, first_row.role, first_row.profile_ids,
            first_row.group_ids, first_row.relation_ids,
            (guidance("voice", {"opaque_target_note": "ENGLISH_SENTINEL"}),),
        )
        rows = tuple(sorted((opaque, *projection.rows[1:]), key=lambda row: row.stable_id))
        opaque_projection = FluencyTargetProjectionV0(
            projection.candidate_sha256, projection.target_locale, rows,
        )
        first = build_fluency_review_job_v0(
            context, resolved, candidate, opaque_projection,
            candidate_authority_sha256=SHA_C, requested_ids=requested,
            budget=ProviderBudgetV0(None, None),
        )
        second = build_fluency_review_job_v0(
            context, resolved, candidate, opaque_projection,
            candidate_authority_sha256="d" * 64, requested_ids=requested,
            budget=ProviderBudgetV0(None, None),
        )
        self.assertIn(b"ENGLISH_SENTINEL", canonical_json_bytes(first[2].as_dict()))
        self.assertEqual(first[2], second[2])
        self.assertNotEqual(first[0].digest, second[0].digest)
        self.assertNotEqual(first[1].job_id, second[1].job_id)

    def test_caller_collection_mutation_does_not_change_models(self) -> None:
        context, resolved, candidate, projection, requested = fixture()
        mutable = list(requested)
        plan, _job, _packet = build_fluency_review_job_v0(
            context, resolved, candidate, projection,
            candidate_authority_sha256=SHA_C, requested_ids=tuple(mutable),
            budget=ProviderBudgetV0(None, None),
        )
        mutable.reverse()
        self.assertEqual(requested, plan.requested_ids)


if __name__ == "__main__":
    unittest.main()
