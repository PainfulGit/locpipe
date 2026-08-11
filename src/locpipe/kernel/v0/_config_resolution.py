from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from locpipe.contracts.v0 import (
    ContractViolation,
    ErrorCategory,
    ErrorCode,
    WorkflowProfile,
    canonical_value_bytes,
    raw_sha256,
)

from ._config_models import (
    CHECKPOINT_RANK,
    CONFIG_LAYER_ORDER,
    ConfigCheckpointV0,
    ConfigDigestDomainV0,
    ConfigExplanationV0,
    ConfigLayerV0,
    ConfigRedactionV0,
    ConfigRegistryV0,
    ConfigSnapshotV0,
    ResolvedConfigV0,
    config_projection_sha256,
)
from ._config_validation import validate_config_value
from ._context_models import ProjectContextV0
from ._transaction_models import NamespaceV0


def _fail(code: ErrorCode, detail: str) -> ContractViolation:
    return ContractViolation(code, detail, category=ErrorCategory.CONFIGURATION)


def _canonicalize_layers(
    registry: ConfigRegistryV0,
    layers: Mapping[ConfigLayerV0 | str, Mapping[str, Any]],
    checkpoint: ConfigCheckpointV0,
) -> dict[ConfigLayerV0, dict[str, bytes]]:
    if not isinstance(layers, Mapping):
        raise _fail(ErrorCode.MALFORMED_ARTIFACT, "Config layers must be a mapping")
    parsed: dict[ConfigLayerV0, dict[str, bytes]] = {}
    for raw_layer, values in layers.items():
        try:
            layer = ConfigLayerV0(raw_layer)
        except (TypeError, ValueError) as error:
            raise _fail(ErrorCode.CAPABILITY_UNKNOWN, "Unknown config layer") from error
        if layer in parsed:
            raise _fail(ErrorCode.DUPLICATE_IDENTITY, "Duplicate config layer")
        if not isinstance(values, Mapping):
            raise _fail(ErrorCode.MALFORMED_ARTIFACT, "Config layer values must be a mapping")
        canonical: dict[str, bytes] = {}
        for key, value in values.items():
            if not isinstance(key, str):
                raise _fail(ErrorCode.MALFORMED_ARTIFACT, "Config key must be a string")
            spec = registry.spec_for(key)
            if key == "allow_install" and layer is not ConfigLayerV0.CLI:
                raise _fail(
                    ErrorCode.CAPABILITY_FORBIDDEN,
                    "allow_install is permitted only in the cli layer",
                )
            if layer is not ConfigLayerV0.DEFAULTS and layer not in spec.allowed_layers:
                raise _fail(ErrorCode.CAPABILITY_FORBIDDEN, f"Config key {key!r} is forbidden in layer {layer.value}")
            validate_config_value(key, value, checkpoint)
            canonical[key] = canonical_value_bytes(value)
        parsed[layer] = canonical
    return parsed


def _validate_transition(previous: ConfigSnapshotV0, current: ConfigSnapshotV0) -> None:
    if current.registry_sha256 != previous.registry_sha256:
        raise _fail(ErrorCode.BINDING_MISMATCH, "Config registry drift")
    if CHECKPOINT_RANK[current.checkpoint] < CHECKPOINT_RANK[previous.checkpoint]:
        raise _fail(ErrorCode.BINDING_MISMATCH, "Config checkpoint cannot move backwards")
    prior = {entry.key: entry for entry in previous.entries if entry.key != "allow_install"}
    next_entries = {entry.key: entry for entry in current.entries if entry.key != "allow_install"}
    for key in sorted(set(prior) | set(next_entries)):
        selected = prior.get(key) or next_entries[key]
        if CHECKPOINT_RANK[selected.frozen_after] <= CHECKPOINT_RANK[previous.checkpoint]:
            if key not in prior or key not in next_entries:
                raise _fail(ErrorCode.BINDING_MISMATCH, f"Frozen config key {key!r} was added or removed")
            if prior[key].transition_identity() != next_entries[key].transition_identity():
                raise _fail(ErrorCode.BINDING_MISMATCH, f"Frozen config key {key!r} drift")


def resolve_config_v0(
    registry: ConfigRegistryV0,
    layers: Mapping[ConfigLayerV0 | str, Mapping[str, Any]],
    checkpoint: ConfigCheckpointV0 | str,
    previous: ConfigSnapshotV0 | None = None,
) -> ResolvedConfigV0:
    if not isinstance(registry, ConfigRegistryV0):
        raise _fail(ErrorCode.MALFORMED_ARTIFACT, "Config registry binding is invalid")
    try:
        selected_checkpoint = ConfigCheckpointV0(checkpoint)
    except (TypeError, ValueError) as error:
        raise _fail(ErrorCode.MALFORMED_ARTIFACT, "Config checkpoint is invalid") from error
    if previous is None and selected_checkpoint is not ConfigCheckpointV0.RELEASE_INIT:
        raise _fail(ErrorCode.BINDING_MISMATCH, "Initial release config snapshot must be RELEASE_INIT")
    if previous is not None and not isinstance(previous, ConfigSnapshotV0):
        raise _fail(ErrorCode.MALFORMED_ARTIFACT, "Previous config snapshot is invalid")

    parsed = _canonicalize_layers(registry, layers, selected_checkpoint)
    effective: dict[str, tuple[ConfigLayerV0, bytes]] = {}
    for layer in CONFIG_LAYER_ORDER:
        for key, payload in parsed.get(layer, {}).items():
            effective[key] = (layer, payload)

    explanations: list[ConfigExplanationV0] = []
    private_values: list[tuple[str, bytes]] = []
    for key in sorted(effective):
        origin, payload = effective[key]
        spec = registry.spec_for(key)
        fingerprint = raw_sha256(payload)
        explanations.append(
            ConfigExplanationV0(
                key=key,
                origin=origin,
                frozen_after=spec.frozen_after,
                redaction=spec.redaction,
                digest_domains=spec.digest_domains,
                value_fingerprint=fingerprint,
                _public_value=payload if spec.redaction is ConfigRedactionV0.PUBLIC else None,
            )
        )
        private_values.append((key, payload))
    entries = tuple(explanations)
    release_init_entries = tuple(
        entry
        for entry in entries
        if CHECKPOINT_RANK[entry.frozen_after] <= CHECKPOINT_RANK[ConfigCheckpointV0.RELEASE_INIT]
    )
    domain_entries = {
        domain: tuple(entry for entry in entries if domain in entry.digest_domains)
        for domain in ConfigDigestDomainV0
    }
    snapshot = ConfigSnapshotV0(
        checkpoint=selected_checkpoint,
        registry_sha256=registry.semantic_sha256,
        config_snapshot_sha256=config_projection_sha256(
            registry.semantic_sha256, release_init_entries, "release_init"
        ),
        effective_snapshot_sha256=config_projection_sha256(registry.semantic_sha256, entries, "effective"),
        content_config_digest=config_projection_sha256(
            registry.semantic_sha256, domain_entries[ConfigDigestDomainV0.CONTENT], "content"
        ),
        build_config_digest=config_projection_sha256(
            registry.semantic_sha256, domain_entries[ConfigDigestDomainV0.BUILD], "build"
        ),
        runtime_config_digest=config_projection_sha256(
            registry.semantic_sha256, domain_entries[ConfigDigestDomainV0.RUNTIME], "runtime"
        ),
        entries=entries,
    )
    if previous is not None:
        _validate_transition(previous, snapshot)
    return ResolvedConfigV0(snapshot, tuple(private_values))


def create_project_context_from_config(
    namespace: NamespaceV0,
    resolved: ResolvedConfigV0,
) -> ProjectContextV0:
    if not isinstance(namespace, NamespaceV0) or not isinstance(resolved, ResolvedConfigV0):
        raise _fail(ErrorCode.MALFORMED_ARTIFACT, "Project context config binding is invalid")
    try:
        configured = NamespaceV0(
            resolved.get_value("workspace_id"),
            resolved.get_value("project_id"),
            resolved.get_value("release_id"),
        )
        profile = WorkflowProfile(resolved.get_value("workflow_profile"))
    except ContractViolation:
        raise
    except (TypeError, ValueError) as error:
        raise _fail(ErrorCode.BINDING_MISMATCH, "Project context identity config is invalid") from error
    if configured != namespace:
        raise _fail(ErrorCode.BINDING_MISMATCH, "Project context namespace does not match config")
    return ProjectContextV0(namespace, profile, resolved.config_snapshot_sha256)


def validate_context_config_binding(context: ProjectContextV0, resolved: ResolvedConfigV0) -> None:
    if not isinstance(context, ProjectContextV0):
        raise _fail(ErrorCode.MALFORMED_ARTIFACT, "Project context is invalid")
    expected = create_project_context_from_config(context.namespace, resolved)
    if expected != context:
        raise _fail(ErrorCode.BINDING_MISMATCH, "Project context configuration binding drift")


def explain_config_v0(resolved: ResolvedConfigV0) -> tuple[ConfigExplanationV0, ...]:
    if not isinstance(resolved, ResolvedConfigV0):
        raise _fail(ErrorCode.MALFORMED_ARTIFACT, "Resolved config is invalid")
    return resolved.snapshot.entries
