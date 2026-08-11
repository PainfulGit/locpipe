from __future__ import annotations

import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from locpipe.contracts.v0 import ContractViolation, ErrorCode  # noqa: E402
from locpipe.kernel.v0.config import (  # noqa: E402
    ConfigCheckpointV0,
    ConfigLayerV0,
    create_project_context_from_config,
    explain_config_v0,
    load_config_registry_v0,
    resolve_config_v0,
    validate_context_config_binding,
)
from locpipe.kernel.v0.context import initialize_project_context  # noqa: E402
from locpipe.kernel.v0.transactions import NamespaceV0, SyntheticTransactionStoreV0  # noqa: E402


REGISTRY_PATH = (
    ROOT / "src" / "locpipe" / "resources" / "config_key_registry.csv"
)
SHA_A = "a" * 64
SHA_B = "b" * 64


def base_layers(*, project: str = "project-a", release: str = "release-a") -> dict[str, dict]:
    return {
        "defaults": {"build_profile": {"mode": "default"}},
        "workspace": {"workspace_id": "workspace"},
        "project": {
            "project_id": project,
            "workflow_profile": "content-only",
            "source_locale": "en",
            "target_locales": ["pl", "uk"],
            "module_bindings": [
                {
                    "capability": "translation",
                    "module_id": "fixture.translation",
                    "version": "1.0.0",
                    "digest": SHA_A,
                }
            ],
            "provider_bindings": [
                {
                    "role": "translator",
                    "provider_id": "offline",
                    "version": "1.0.0",
                    "config_digest": SHA_A,
                }
            ],
        },
        "release": {"release_id": release},
        "local": {
            "build_output": "C:" + "/" + "private/build-output",
            "install_target": "C:" + "/" + "Users/private/game.asset",
            "secret_ref": {"identity": "vault/private-token", "version": "7"},
        },
    }


class ConfigResolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry_bytes = REGISTRY_PATH.read_bytes()
        cls.registry = load_config_registry_v0(cls.registry_bytes)

    def resolve(self, layers: dict | None = None, *, checkpoint=ConfigCheckpointV0.RELEASE_INIT, previous=None):
        return resolve_config_v0(self.registry, layers or base_layers(), checkpoint, previous)

    def test_registry_is_immutable_semantic_authority(self) -> None:
        registry = self.registry
        self.assertEqual(22, len(registry.specs))
        self.assertEqual(tuple(sorted(spec.key for spec in registry.specs)), tuple(spec.key for spec in registry.specs))
        self.assertEqual(64, len(registry.semantic_sha256))
        with self.assertRaises(ContractViolation):
            load_config_registry_v0(self.registry_bytes + self.registry_bytes.splitlines(keepends=True)[1])
        with self.assertRaises(ContractViolation):
            load_config_registry_v0(b"unknown\nvalue\n")

    def test_precedence_is_deterministic_and_disallowed_overrides_fail_closed(self) -> None:
        layers = base_layers()
        layers["release"].update({"workflow_profile": "artifact-build", "target_locales": ["uk"]})
        resolved = self.resolve(layers)
        self.assertEqual("artifact-build", resolved.get_value("workflow_profile"))
        self.assertEqual(["uk"], resolved.get_value("target_locales"))
        origin = {entry.key: entry.origin for entry in explain_config_v0(resolved)}
        self.assertEqual(ConfigLayerV0.RELEASE, origin["workflow_profile"])

        forbidden = deepcopy(layers)
        forbidden["cli"] = {"target_locales": ["de"]}
        with self.assertRaises(ContractViolation) as caught:
            self.resolve(forbidden)
        self.assertEqual(ErrorCode.CAPABILITY_FORBIDDEN, caught.exception.record.code)

        unknown = deepcopy(layers)
        unknown["project"]["game_specific_option"] = True
        with self.assertRaises(ContractViolation) as caught:
            self.resolve(unknown)
        self.assertEqual(ErrorCode.CAPABILITY_UNKNOWN, caught.exception.record.code)

    def test_mapping_order_and_caller_mutation_do_not_change_snapshot(self) -> None:
        layers = base_layers()
        resolved = self.resolve(layers)
        reordered = {key: dict(reversed(list(value.items()))) for key, value in reversed(list(layers.items()))}
        repeated = self.resolve(reordered)
        self.assertEqual(resolved.snapshot, repeated.snapshot)

        layers["project"]["target_locales"].append("zz")
        layers["project"]["provider_bindings"][0]["provider_id"] = "mutated"
        self.assertEqual(["pl", "uk"], resolved.get_value("target_locales"))
        self.assertEqual("offline", resolved.get_value("provider_bindings")[0]["provider_id"])

    def test_public_snapshot_and_repr_never_leak_redacted_values(self) -> None:
        resolved = self.resolve()
        rendered = json.dumps(resolved.as_public_dict(), ensure_ascii=False) + repr(resolved)
        for forbidden in ("C:" + "/" + "private/build-output", "C:" + "/" + "Users/private/game.asset", "vault/private-token"):
            self.assertNotIn(forbidden, rendered)
        explanations = {entry.key: entry.as_dict() for entry in explain_config_v0(resolved)}
        self.assertEqual("<redacted:local_path>", explanations["install_target"]["effective_value"])
        self.assertEqual("<redacted:secret>", explanations["secret_ref"]["effective_value"])
        self.assertEqual("C:" + "/" + "Users/private/game.asset", resolved.get_value("install_target"))

    def test_domain_digest_sensitivity_matrix(self) -> None:
        baseline = self.resolve()

        cases = {
            "content": ("project", "language_policy", {"policy": "v2"}, {"content"}),
            "build": ("project", "build_profile", {"mode": "release"}, {"build"}),
            "runtime": ("local", "install_target", "D:" + "/other/game.asset", {"runtime"}),
            "provider": (
                "local",
                "provider_bindings",
                [{"role": "translator", "provider_id": "offline", "version": "1.0.1", "config_digest": SHA_B}],
                {"content", "runtime"},
            ),
        }
        for name, (layer, key, value, changed) in cases.items():
            with self.subTest(name=name):
                layers = base_layers()
                layers.setdefault(layer, {})[key] = value
                selected = self.resolve(layers)
                actual = {
                    domain
                    for domain, before, after in (
                        ("content", baseline.content_config_digest, selected.content_config_digest),
                        ("build", baseline.build_config_digest, selected.build_config_digest),
                        ("runtime", baseline.runtime_config_digest, selected.runtime_config_digest),
                    )
                    if before != after
                }
                self.assertEqual(changed, actual)
                if layer == "local":
                    self.assertEqual(baseline.config_snapshot_sha256, selected.config_snapshot_sha256)

        identity_layers = base_layers(project="project-b")
        identity = self.resolve(identity_layers)
        self.assertNotEqual(baseline.config_snapshot_sha256, identity.config_snapshot_sha256)
        self.assertNotEqual(baseline.content_config_digest, identity.content_config_digest)
        self.assertNotEqual(baseline.build_config_digest, identity.build_config_digest)
        self.assertNotEqual(baseline.runtime_config_digest, identity.runtime_config_digest)

    def test_transition_freezes_value_origin_presence_and_registry(self) -> None:
        initial = self.resolve()
        profile_drift = base_layers()
        profile_drift["release"]["workflow_profile"] = "artifact-build"
        with self.assertRaises(ContractViolation) as caught:
            self.resolve(profile_drift, checkpoint=ConfigCheckpointV0.SOURCE_SNAPSHOT, previous=initial.snapshot)
        self.assertEqual(ErrorCode.BINDING_MISMATCH, caught.exception.record.code)

        adapter = base_layers()
        adapter["project"].update({"adapter_id": "fixture", "adapter_version": "1.0.0", "adapter_digest": SHA_A})
        source = self.resolve(adapter, checkpoint=ConfigCheckpointV0.SOURCE_SNAPSHOT, previous=initial.snapshot)
        adapter["release"].update({"adapter_id": "fixture", "adapter_version": "1.0.0", "adapter_digest": SHA_A})
        with self.assertRaises(ContractViolation):
            self.resolve(adapter, checkpoint=ConfigCheckpointV0.SOURCE_SNAPSHOT, previous=source.snapshot)

        with self.assertRaises(ContractViolation):
            self.resolve(base_layers(), checkpoint=ConfigCheckpointV0.RELEASE_INIT, previous=source.snapshot)

        drifted_registry = load_config_registry_v0(
            self.registry_bytes.replace(b"Opaque schema-validated", b"Strict schema-validated", 1)
        )
        with self.assertRaises(ContractViolation):
            resolve_config_v0(drifted_registry, base_layers(), ConfigCheckpointV0.SOURCE_SNAPSHOT, initial.snapshot)

    def test_null_empty_and_one_shot_install_authorization_are_distinct(self) -> None:
        null = base_layers()
        null["project"]["project_policy"] = None
        with self.assertRaises(ContractViolation):
            self.resolve(null)

        empty_string = base_layers()
        empty_string["project"]["project_policy"] = ""
        empty_list = base_layers()
        empty_list["project"]["project_policy"] = []
        self.assertNotEqual(
            self.resolve(empty_string).content_config_digest,
            self.resolve(empty_list).content_config_digest,
        )

        early = base_layers()
        early["cli"] = {"allow_install": True}
        with self.assertRaises(ContractViolation):
            self.resolve(early)

        for layer in ConfigLayerV0:
            if layer is ConfigLayerV0.CLI:
                continue
            invalid_origin = base_layers()
            invalid_origin.setdefault(layer.value, {})["allow_install"] = True
            with self.subTest(layer=layer.value):
                with self.assertRaises(ContractViolation) as caught:
                    self.resolve(
                        invalid_origin,
                        checkpoint=ConfigCheckpointV0.INSTALL_AUTHORIZE,
                        previous=self.resolve().snapshot,
                    )
                self.assertEqual(ErrorCode.CAPABILITY_FORBIDDEN, caught.exception.record.code)

        initial = self.resolve()
        authorized = base_layers()
        authorized["cli"] = {"allow_install": True}
        install = self.resolve(
            authorized,
            checkpoint=ConfigCheckpointV0.INSTALL_AUTHORIZE,
            previous=initial.snapshot,
        )
        repeated = self.resolve(
            base_layers(),
            checkpoint=ConfigCheckpointV0.INSTALL_AUTHORIZE,
            previous=install.snapshot,
        )
        self.assertNotEqual(install.runtime_config_digest, repeated.runtime_config_digest)
        with self.assertRaises(ContractViolation):
            repeated.get_value("allow_install")

    def test_binding_validation_and_realistic_multi_project_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            root.mkdir()
            store = SyntheticTransactionStoreV0.create(root)
            roots = []
            for project in ("project-a", "project-b"):
                for release in ("release-a", "release-b"):
                    resolved = self.resolve(base_layers(project=project, release=release))
                    namespace = NamespaceV0("workspace", project, release)
                    context = create_project_context_from_config(namespace, resolved)
                    validate_context_config_binding(context, resolved)
                    roots.append(initialize_project_context(store, context))
            for field in ("state_root", "cache_root", "staging_root", "transactions_root", "receipts_root", "outputs_root"):
                self.assertEqual(4, len({getattr(paths, field) for paths in roots}))

            before = set(root.rglob("*"))
            changed = base_layers()
            changed["release"]["workflow_profile"] = "artifact-build"
            initial = self.resolve()
            with self.assertRaises(ContractViolation):
                self.resolve(changed, checkpoint=ConfigCheckpointV0.SOURCE_SNAPSHOT, previous=initial.snapshot)
            self.assertEqual(before, set(root.rglob("*")))

            wrong = self.resolve()
            with self.assertRaises(ContractViolation) as caught:
                create_project_context_from_config(NamespaceV0("workspace", "other", "release-a"), wrong)
            self.assertEqual(ErrorCode.BINDING_MISMATCH, caught.exception.record.code)

    def test_binding_contracts_reject_unsorted_duplicates_and_floating_versions(self) -> None:
        duplicate_provider = base_layers()
        duplicate_provider["project"]["provider_bindings"].append(
            {"role": "translator", "provider_id": "other", "version": "1.0.0", "config_digest": SHA_B}
        )
        with self.assertRaises(ContractViolation):
            self.resolve(duplicate_provider)

        floating_module = base_layers()
        floating_module["project"]["module_bindings"][0]["version"] = "latest"
        with self.assertRaises(ContractViolation):
            self.resolve(floating_module)

        bad_secret = base_layers()
        bad_secret["local"]["secret_ref"] = {"identity": "vault/ref", "version": "1", "value": "plaintext"}
        with self.assertRaises(ContractViolation) as caught:
            self.resolve(bad_secret)
        self.assertNotIn("plaintext", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
