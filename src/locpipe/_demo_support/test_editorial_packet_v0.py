from __future__ import annotations

import sys
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from locpipe.contracts.v0 import (  # noqa: E402
    BranchIdentity,
    Capability,
    ContractViolation,
    KIND_TO_SCHEMA,
    WorkflowProfile,
    canonical_json_bytes,
    display_id,
    parse_canonical_json,
    raw_sha256,
)
from locpipe.contracts.v0.constants import CONTRACT_VERSION  # noqa: E402
from locpipe.editorial.v0 import (  # noqa: E402
    EditorialPolicyV0,
    build_editorial_bypass_v0,
    build_editorial_job_v0,
    editorial_bindings_from_config_v0,
)
from locpipe.kernel.v0.context import ProjectContextV0  # noqa: E402
from locpipe.kernel.v0.transactions import NamespaceV0  # noqa: E402
from locpipe.translation.v0 import (  # noqa: E402
    ProviderBudgetV0,
    TranslationDecisionV0,
    TranslationJobStatusV0,
    TranslationStateV0,
    TranslationTargetSetV0,
    translation_job_root_v0,
)
from locpipe._demo_support.conformance.adapter_v0.flat_adapter import SyntheticFlatAdapterV0  # noqa: E402
from locpipe._demo_support.conformance.adapter_v0.structured_adapter import SyntheticStructuredAdapterV0  # noqa: E402
from locpipe._demo_support.test_translation_acceptance_v0 import provider_output  # noqa: E402
from locpipe._demo_support.test_translation_packet_v0 import build_fixture, layers  # noqa: E402


EDITOR_SHA = "e" * 64
EDITOR_PROVIDER_SHA = "f" * 64


def editorial_layers(*, configured=True, half=None):
    selected = deepcopy(layers())
    if configured or half == "module":
        selected["project"]["module_bindings"].append({
            "capability": Capability.EDITORIAL_REVIEW.value,
            "module_id": "fixture.editorial",
            "version": "1.0.0",
            "digest": EDITOR_SHA,
        })
        selected["project"]["module_bindings"].sort(key=lambda row: (row["capability"], row["module_id"]))
    if configured or half == "provider":
        selected["project"]["provider_bindings"].append({
            "role": "accuracy_editor",
            "provider_id": "offline",
            "version": "1.0.0",
            "config_digest": EDITOR_PROVIDER_SHA,
        })
        selected["project"]["provider_bindings"].sort(key=lambda row: (row["role"], row["provider_id"]))
    return selected


def accepted_fixture(name="flat", adapter=None, *, selected_layers=None, target_locale="uk"):
    adapter = adapter or SyntheticFlatAdapterV0()
    resolved, _corpus, _scope, job, packet = build_fixture(
        name,
        adapter,
        target_locale=target_locale,
        selected_layers=selected_layers or editorial_layers(),
    )
    raw = parse_canonical_json(provider_output(job, packet))
    root = translation_job_root_v0(job)
    targets = []
    for envelope in raw["targets"]:
        selected = dict(envelope)
        data = dict(selected["data"])
        data["metadata_ref"] = f"{root}/decision.json"
        selected["data"] = data
        targets.append(canonical_json_bytes(selected))
    target_set = TranslationTargetSetV0(job.job_id, job.invocation_id, job.target_locale, tuple(targets))
    decision = TranslationDecisionV0(
        job.job_id,
        job.invocation_id,
        TranslationJobStatusV0.ACCEPTED,
        "1" * 64,
        "ACCEPTED_EXACT_SCOPE",
        len(targets),
    )
    decision_bytes = canonical_json_bytes(decision.as_dict())
    state = TranslationStateV0(
        job.job_id, job.invocation_id, TranslationJobStatusV0.ACCEPTED,
        decision.submission_sha256, raw_sha256(decision_bytes), raw_sha256(canonical_json_bytes(target_set.as_dict())),
    )
    state_bytes = canonical_json_bytes(state.as_dict())
    context = ProjectContextV0(
        NamespaceV0("workspace", "fixture", "release"),
        WorkflowProfile.CONTENT_ONLY,
        resolved.config_snapshot_sha256,
    )
    return context, resolved, job, packet, decision_bytes, target_set, state_bytes


class EditorialPacketV0Tests(unittest.TestCase):
    def test_flat_and_structured_jobs_are_deterministic_and_source_closed(self) -> None:
        for name, adapter in (("flat", SyntheticFlatAdapterV0()), ("structured", SyntheticStructuredAdapterV0())):
            fixture = accepted_fixture(name, adapter)
            first = build_editorial_job_v0(*fixture[:6], fixture[6], EditorialPolicyV0(), budget=ProviderBudgetV0(None, None))
            second = build_editorial_job_v0(*fixture[:6], fixture[6], EditorialPolicyV0(), budget=ProviderBudgetV0(None, None))
            self.assertEqual(first, second)
            job, packet, _base = first
            self.assertEqual(0, job.round_index)
            self.assertTrue(packet.requested_ids)
            self.assertTrue(all("locator" not in row for row in packet.as_dict()["rows"]))
            self.assertEqual(
                {row.stable_id for row in packet.rows if row.role.value == "OWNED"},
                set(packet.requested_ids),
            )

    def test_two_locales_and_policy_change_create_independent_jobs(self) -> None:
        uk = accepted_fixture(target_locale="uk")
        pl = accepted_fixture(target_locale="pl")
        uk_job = build_editorial_job_v0(*uk[:6], uk[6], EditorialPolicyV0(2), budget=ProviderBudgetV0(None, None))[0]
        pl_job = build_editorial_job_v0(*pl[:6], pl[6], EditorialPolicyV0(2), budget=ProviderBudgetV0(None, None))[0]
        strict_job = build_editorial_job_v0(*uk[:6], uk[6], EditorialPolicyV0(0), budget=ProviderBudgetV0(None, None))[0]
        self.assertNotEqual(uk_job.job_id, pl_job.job_id)
        self.assertNotEqual(uk_job.job_id, strict_job.job_id)
        bindings = editorial_bindings_from_config_v0(uk[1])
        self.assertEqual("accuracy_editor", bindings[1].role)

    def test_optional_bypass_and_half_binding_fail_closed(self) -> None:
        fixture = accepted_fixture(selected_layers=editorial_layers(configured=False))
        bypass = build_editorial_bypass_v0(*fixture[:6], fixture[6])
        self.assertTrue(bypass.ready)
        self.assertEqual("BYPASSED_BY_CONFIG", bypass.disposition)

        configured = accepted_fixture()
        with self.assertRaisesRegex(ContractViolation, "cannot be bypassed"):
            build_editorial_bypass_v0(*configured[:6], configured[6])
        for half in ("module", "provider"):
            broken = accepted_fixture(selected_layers=editorial_layers(configured=False, half=half))
            with self.assertRaisesRegex(ContractViolation, "missing or ambiguous"):
                editorial_bindings_from_config_v0(broken[1])

    def test_initial_review_cannot_shrink_scope_or_exceed_policy(self) -> None:
        fixture = accepted_fixture()
        job, packet, base = build_editorial_job_v0(*fixture[:6], fixture[6], EditorialPolicyV0(), budget=ProviderBudgetV0(None, None))
        with self.assertRaisesRegex(ContractViolation, "every owned ID"):
            build_editorial_job_v0(
                *fixture[:6], fixture[6], EditorialPolicyV0(), budget=ProviderBudgetV0(None, None),
                requested_ids=packet.requested_ids[:-1],
            )
        with self.assertRaisesRegex(ContractViolation, "exceeds policy"):
            build_editorial_job_v0(
                *fixture[:6], fixture[6], EditorialPolicyV0(0), budget=ProviderBudgetV0(None, None),
                parent_candidate=base, parent_state_bytes=b"{}\n", parent_decision_bytes=b"{}\n",
                parent_rework_request_bytes=b"{}\n", requested_ids=base.unresolved_ids, round_index=1,
            )


if __name__ == "__main__":
    unittest.main()
