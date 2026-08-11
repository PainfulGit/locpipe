from __future__ import annotations

import sys
import unittest
from copy import deepcopy
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
)
from locpipe.contracts.v0 import ContractViolation, WorkflowProfile, canonical_json_bytes  # noqa: E402
from locpipe.kernel.v0.config import (  # noqa: E402
    ConfigCheckpointV0,
    load_config_registry_v0,
    resolve_config_v0,
)
from locpipe.kernel.v0.context import ProjectContextV0  # noqa: E402
from locpipe.kernel.v0.transactions import NamespaceV0  # noqa: E402
from locpipe.translation.v0 import (  # noqa: E402
    ProviderBudgetV0,
    build_translation_job_v0,
    provider_binding_from_config_v0,
)
from tests.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402
from tests.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0  # noqa: E402


REGISTRY = load_config_registry_v0(
    (ROOT / "src/locpipe/resources/config_key_registry.csv").read_bytes()
)
FIXTURES = ROOT / "tests/conformance/adapter_v0/fixtures"
PROVIDER_SHA = "a" * 64
MODULE_SHA = "b" * 64


def layers(*, project="fixture", release="release", locales=("pl", "uk"), provider_sha=PROVIDER_SHA):
    return {
        "defaults": {"build_profile": {"mode": "default"}},
        "workspace": {"workspace_id": "workspace"},
        "project": {
            "project_id": project,
            "workflow_profile": "content-only",
            "source_locale": "en",
            "target_locales": list(locales),
            "module_bindings": [{
                "capability": "translation",
                "module_id": "fixture.translation",
                "version": "1.0.0",
                "digest": MODULE_SHA,
            }],
            "provider_bindings": [{
                "role": "translator",
                "provider_id": "offline",
                "version": "1.0.0",
                "config_digest": provider_sha,
            }],
        },
        "release": {"release_id": release},
    }


def build_fixture(
    name: str,
    adapter,
    *,
    target_locale="uk",
    selected_layers=None,
    context=None,
    owned_count: int | None = None,
):
    active_layers = selected_layers or layers()
    initial = resolve_config_v0(REGISTRY, active_layers, ConfigCheckpointV0.RELEASE_INIT)
    resolved = resolve_config_v0(REGISTRY, active_layers, ConfigCheckpointV0.SCOPE_FREEZE, initial.snapshot)
    effective_context = context or ProjectContextV0(
        NamespaceV0(
            resolved.get_value("workspace_id"),
            resolved.get_value("project_id"),
            resolved.get_value("release_id"),
        ),
        WorkflowProfile.CONTENT_ONLY,
        resolved.config_snapshot_sha256,
    )
    golden = FIXTURES / name / "golden"
    segments_bytes = (golden / "segments.jsonl").read_bytes()
    corpus = load_source_corpus_v0(
        golden,
        snapshot_path="source_snapshot.json",
        segments_path="segments.jsonl",
        relations_path="relations.jsonl" if (golden / "relations.jsonl").is_file() else None,
        descriptor=adapter.descriptor,
        config_snapshot_sha256=resolved.config_snapshot_sha256,
    )
    reconciliation = reconcile_sources_v0(corpus)
    source_lock_bytes = canonical_json_bytes(corpus.lock.as_dict())
    reconciliation_bytes = canonical_json_bytes(reconciliation.as_dict())
    owned_ids = {
        row.stable_id for row in corpus.segments[: owned_count if owned_count is not None else len(corpus.segments)]
    }
    scope = freeze_scope_v0(
        corpus,
        reconciliation,
        tuple(
            ScopeEntryV0(row.identity, ScopeRoleV0.OWNED if row.stable_id in owned_ids else ScopeRoleV0.CONTEXT)
            for row in reversed(corpus.segments)
        ),
        target_locales=tuple(resolved.get_value("target_locales")),
        config_snapshot_sha256=resolved.config_snapshot_sha256,
        source_lock_bytes=source_lock_bytes,
        reconciliation_bytes=reconciliation_bytes,
    )
    scope_artifacts = dict(frozen_scope_artifacts_v0(scope))
    job, packet = build_translation_job_v0(
        effective_context,
        resolved,
        corpus,
        reconciliation,
        scope,
        source_lock_bytes=source_lock_bytes,
        reconciliation_bytes=reconciliation_bytes,
        scope_bytes=scope_artifacts["scope/scope.json"],
        scope_lock_bytes=scope_artifacts["scope/scope_lock.json"],
        segments_bytes=segments_bytes,
        target_locale=target_locale,
        budget=ProviderBudgetV0(None, None),
    )
    return resolved, corpus, scope, job, packet


class TranslationPacketV0Tests(unittest.TestCase):
    def test_flat_and_structured_build_deterministic_jobs(self) -> None:
        for name, adapter in (("flat", SyntheticFlatAdapterV0()), ("structured", SyntheticStructuredAdapterV0())):
            first = build_fixture(name, adapter)
            second = build_fixture(name, adapter)
            self.assertEqual(first[3:], second[3:])
            self.assertEqual(len(first[2].entries), len(first[4].rows))
            self.assertTrue(all("locator" not in row for row in first[4].as_dict()["rows"]))

    def test_two_locales_and_provider_change_create_independent_jobs(self) -> None:
        adapter = SyntheticFlatAdapterV0()
        uk = build_fixture("flat", adapter, target_locale="uk")
        pl = build_fixture("flat", adapter, target_locale="pl")
        changed = build_fixture("flat", adapter, selected_layers=layers(provider_sha="c" * 64))
        self.assertNotEqual(uk[3].job_id, pl[3].job_id)
        self.assertNotEqual(uk[3].job_id, changed[3].job_id)
        self.assertEqual("translator", provider_binding_from_config_v0(uk[0]).role)

    def test_empty_owned_unknown_locale_and_context_config_drift_fail(self) -> None:
        adapter = SyntheticFlatAdapterV0()
        resolved, corpus, scope, _job, _packet = build_fixture("flat", adapter)
        wrong = ProjectContextV0(
            NamespaceV0("workspace", "fixture", "release"),
            WorkflowProfile.CONTENT_ONLY,
            "f" * 64,
        )
        with self.assertRaisesRegex(ContractViolation, "config drift"):
            build_fixture("flat", adapter, context=wrong)
        with self.assertRaisesRegex(ContractViolation, "outside frozen scope"):
            build_fixture("flat", adapter, target_locale="de")

        golden = FIXTURES / "flat/golden"
        reconciliation = reconcile_sources_v0(corpus)
        source_lock = canonical_json_bytes(corpus.lock.as_dict())
        reconciliation_bytes = canonical_json_bytes(reconciliation.as_dict())
        context_scope = freeze_scope_v0(
            corpus,
            reconciliation,
            tuple(ScopeEntryV0(row.identity, ScopeRoleV0.CONTEXT) for row in corpus.segments),
            target_locales=("uk",),
            config_snapshot_sha256=resolved.config_snapshot_sha256,
            source_lock_bytes=source_lock,
            reconciliation_bytes=reconciliation_bytes,
        )
        artifacts = dict(frozen_scope_artifacts_v0(context_scope))
        context = ProjectContextV0(NamespaceV0("workspace", "fixture", "release"), WorkflowProfile.CONTENT_ONLY, resolved.config_snapshot_sha256)
        with self.assertRaisesRegex(ContractViolation, "owned rows"):
            build_translation_job_v0(
                context, resolved, corpus, reconciliation, context_scope,
                source_lock_bytes=source_lock,
                reconciliation_bytes=reconciliation_bytes,
                scope_bytes=artifacts["scope/scope.json"],
                scope_lock_bytes=artifacts["scope/scope_lock.json"],
                segments_bytes=(golden / "segments.jsonl").read_bytes(),
                target_locale="uk",
                budget=ProviderBudgetV0(None, None),
            )

    def test_caller_mapping_mutation_does_not_change_provider_binding(self) -> None:
        selected = layers()
        initial = resolve_config_v0(REGISTRY, selected, ConfigCheckpointV0.RELEASE_INIT)
        resolved = resolve_config_v0(REGISTRY, selected, ConfigCheckpointV0.SCOPE_FREEZE, initial.snapshot)
        binding = provider_binding_from_config_v0(resolved)
        selected["project"]["provider_bindings"][0]["provider_id"] = "mutated"
        self.assertEqual("offline", binding.provider_id)


if __name__ == "__main__":
    unittest.main()
