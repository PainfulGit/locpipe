from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from locpipe.contracts.v0 import (
    ContractViolation,
    ErrorCategory,
    ErrorCode,
    canonical_value_bytes,
    raw_sha256,
    semantic_sha256,
    strict_loads,
)
from locpipe.contracts.v0.profiles import SHA256_RE


class ConfigLayerV0(str, Enum):
    DEFAULTS = "defaults"
    WORKSPACE = "workspace"
    PROJECT = "project"
    RELEASE = "release"
    LOCAL = "local"
    ENVIRONMENT = "environment"
    CLI = "cli"


CONFIG_LAYER_ORDER = tuple(ConfigLayerV0)


class ConfigCheckpointV0(str, Enum):
    WORKSPACE_INIT = "WORKSPACE_INIT"
    PROJECT_INIT = "PROJECT_INIT"
    RELEASE_INIT = "RELEASE_INIT"
    SOURCE_SNAPSHOT = "SOURCE_SNAPSHOT"
    SCOPE_FREEZE = "SCOPE_FREEZE"
    PACKAGE_START = "PACKAGE_START"
    BUILD_START = "BUILD_START"
    HOOK_START = "HOOK_START"
    INSTALL_AUTHORIZE = "INSTALL_AUTHORIZE"


CHECKPOINT_ORDER = tuple(ConfigCheckpointV0)
CHECKPOINT_RANK = {checkpoint: index for index, checkpoint in enumerate(CHECKPOINT_ORDER)}


class ConfigRedactionV0(str, Enum):
    PUBLIC = "public"
    LOCAL_PATH = "local_path"
    SECRET = "secret"


class ConfigDigestDomainV0(str, Enum):
    CONTENT = "content"
    BUILD = "build"
    RUNTIME = "runtime"


DIGEST_DOMAIN_ORDER = tuple(ConfigDigestDomainV0)


def _configuration_error(detail: str) -> ContractViolation:
    return ContractViolation(
        ErrorCode.MALFORMED_ARTIFACT,
        detail,
        category=ErrorCategory.CONFIGURATION,
    )


@dataclass(frozen=True)
class ConfigKeySpecV0:
    key: str
    allowed_layers: tuple[ConfigLayerV0, ...]
    frozen_after: ConfigCheckpointV0
    redaction: ConfigRedactionV0
    digest_domains: tuple[ConfigDigestDomainV0, ...]
    notes: str

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key or not self.key.replace("_", "a").isalnum():
            raise _configuration_error("Config registry key is invalid")
        if not self.allowed_layers or ConfigLayerV0.DEFAULTS in self.allowed_layers:
            raise _configuration_error("Config registry allowed layers are invalid")
        expected_layers = tuple(layer for layer in CONFIG_LAYER_ORDER if layer in self.allowed_layers)
        if expected_layers != self.allowed_layers or len(set(self.allowed_layers)) != len(self.allowed_layers):
            raise _configuration_error("Config registry layers must be unique and ordered")
        expected_domains = tuple(domain for domain in DIGEST_DOMAIN_ORDER if domain in self.digest_domains)
        if not self.digest_domains or expected_domains != self.digest_domains:
            raise _configuration_error("Config registry digest domains must be unique and ordered")
        if not isinstance(self.frozen_after, ConfigCheckpointV0):
            raise _configuration_error("Config registry checkpoint is invalid")
        if not isinstance(self.redaction, ConfigRedactionV0):
            raise _configuration_error("Config registry redaction is invalid")
        if not isinstance(self.notes, str) or not self.notes:
            raise _configuration_error("Config registry notes are required")

    def as_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "allowed_layers": [layer.value for layer in self.allowed_layers],
            "frozen_after": self.frozen_after.value,
            "redaction": self.redaction.value,
            "digest_domains": [domain.value for domain in self.digest_domains],
            "notes": self.notes,
        }


@dataclass(frozen=True)
class ConfigRegistryV0:
    specs: tuple[ConfigKeySpecV0, ...]
    semantic_sha256: str

    def __post_init__(self) -> None:
        keys = tuple(spec.key for spec in self.specs)
        if not self.specs or keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise _configuration_error("Config registry specs must be unique and sorted")
        if not isinstance(self.semantic_sha256, str) or not SHA256_RE.fullmatch(self.semantic_sha256):
            raise _configuration_error("Config registry semantic SHA is invalid")
        expected = semantic_sha256([spec.as_dict() for spec in self.specs])
        if self.semantic_sha256 != expected:
            raise _configuration_error("Config registry semantic SHA does not match specs")

    def spec_for(self, key: str) -> ConfigKeySpecV0:
        for spec in self.specs:
            if spec.key == key:
                return spec
        raise ContractViolation(
            ErrorCode.CAPABILITY_UNKNOWN,
            f"Unknown config key {key!r}",
            category=ErrorCategory.CONFIGURATION,
        )


@dataclass(frozen=True)
class ConfigExplanationV0:
    key: str
    origin: ConfigLayerV0
    frozen_after: ConfigCheckpointV0
    redaction: ConfigRedactionV0
    digest_domains: tuple[ConfigDigestDomainV0, ...]
    value_fingerprint: str
    _public_value: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key:
            raise _configuration_error("Config explanation key is invalid")
        if not isinstance(self.origin, ConfigLayerV0):
            raise _configuration_error("Config explanation origin is invalid")
        if not isinstance(self.frozen_after, ConfigCheckpointV0):
            raise _configuration_error("Config explanation checkpoint is invalid")
        if not isinstance(self.redaction, ConfigRedactionV0):
            raise _configuration_error("Config explanation redaction is invalid")
        if not isinstance(self.value_fingerprint, str) or not SHA256_RE.fullmatch(self.value_fingerprint):
            raise _configuration_error("Config explanation fingerprint is invalid")
        if self.redaction is ConfigRedactionV0.PUBLIC:
            if not isinstance(self._public_value, bytes):
                raise _configuration_error("Public config explanation requires canonical value bytes")
            try:
                value = strict_loads(self._public_value)
            except ContractViolation as error:
                raise _configuration_error("Public config explanation value is invalid") from error
            if canonical_value_bytes(value) != self._public_value:
                raise _configuration_error("Public config explanation value is not canonical")
            if raw_sha256(self._public_value) != self.value_fingerprint:
                raise _configuration_error("Public config explanation fingerprint drift")
        elif self._public_value is not None:
            raise _configuration_error("Redacted config explanation cannot retain public value bytes")

    def public_value(self) -> Any:
        if self._public_value is None:
            return f"<redacted:{self.redaction.value}>"
        return strict_loads(self._public_value)

    def as_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "origin": self.origin.value,
            "frozen_after": self.frozen_after.value,
            "redaction": self.redaction.value,
            "digest_domains": [domain.value for domain in self.digest_domains],
            "effective_value": self.public_value(),
            "value_fingerprint": self.value_fingerprint,
        }

    def transition_identity(self) -> tuple[str, str]:
        return self.origin.value, self.value_fingerprint


@dataclass(frozen=True)
class ConfigSnapshotV0:
    checkpoint: ConfigCheckpointV0
    registry_sha256: str
    config_snapshot_sha256: str
    effective_snapshot_sha256: str
    content_config_digest: str
    build_config_digest: str
    runtime_config_digest: str
    entries: tuple[ConfigExplanationV0, ...]

    def __post_init__(self) -> None:
        hashes = (
            self.registry_sha256,
            self.config_snapshot_sha256,
            self.effective_snapshot_sha256,
            self.content_config_digest,
            self.build_config_digest,
            self.runtime_config_digest,
        )
        if not isinstance(self.checkpoint, ConfigCheckpointV0):
            raise _configuration_error("Config snapshot checkpoint is invalid")
        if any(not isinstance(value, str) or not SHA256_RE.fullmatch(value) for value in hashes):
            raise _configuration_error("Config snapshot SHA is invalid")
        keys = tuple(entry.key for entry in self.entries)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise _configuration_error("Config snapshot entries must be unique and sorted")
        release_init = tuple(
            entry
            for entry in self.entries
            if CHECKPOINT_RANK[entry.frozen_after] <= CHECKPOINT_RANK[ConfigCheckpointV0.RELEASE_INIT]
        )
        domains = {
            domain: tuple(entry for entry in self.entries if domain in entry.digest_domains)
            for domain in ConfigDigestDomainV0
        }
        expected = (
            config_projection_sha256(self.registry_sha256, release_init, "release_init"),
            config_projection_sha256(self.registry_sha256, self.entries, "effective"),
            config_projection_sha256(self.registry_sha256, domains[ConfigDigestDomainV0.CONTENT], "content"),
            config_projection_sha256(self.registry_sha256, domains[ConfigDigestDomainV0.BUILD], "build"),
            config_projection_sha256(self.registry_sha256, domains[ConfigDigestDomainV0.RUNTIME], "runtime"),
        )
        if hashes[1:] != expected:
            raise _configuration_error("Config snapshot digest projection drift")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": 0,
            "checkpoint": self.checkpoint.value,
            "registry_sha256": self.registry_sha256,
            "config_snapshot_sha256": self.config_snapshot_sha256,
            "effective_snapshot_sha256": self.effective_snapshot_sha256,
            "content_config_digest": self.content_config_digest,
            "build_config_digest": self.build_config_digest,
            "runtime_config_digest": self.runtime_config_digest,
            "entries": [entry.as_dict() for entry in self.entries],
        }


@dataclass(frozen=True)
class ResolvedConfigV0:
    snapshot: ConfigSnapshotV0
    _values: tuple[tuple[str, bytes], ...] = field(repr=False)

    def __post_init__(self) -> None:
        keys = tuple(key for key, _value in self._values)
        if keys != tuple(entry.key for entry in self.snapshot.entries):
            raise _configuration_error("Resolved config values do not match snapshot entries")
        for (_key, payload), entry in zip(self._values, self.snapshot.entries, strict=True):
            if not isinstance(payload, bytes):
                raise _configuration_error("Resolved config values must be canonical bytes")
            try:
                value = strict_loads(payload)
            except ContractViolation as error:
                raise _configuration_error("Resolved config value is invalid") from error
            if canonical_value_bytes(value) != payload or raw_sha256(payload) != entry.value_fingerprint:
                raise _configuration_error("Resolved config value binding drift")

    @property
    def config_snapshot_sha256(self) -> str:
        return self.snapshot.config_snapshot_sha256

    @property
    def effective_snapshot_sha256(self) -> str:
        return self.snapshot.effective_snapshot_sha256

    @property
    def content_config_digest(self) -> str:
        return self.snapshot.content_config_digest

    @property
    def build_config_digest(self) -> str:
        return self.snapshot.build_config_digest

    @property
    def runtime_config_digest(self) -> str:
        return self.snapshot.runtime_config_digest

    def get_value(self, key: str) -> Any:
        for selected, payload in self._values:
            if selected == key:
                return strict_loads(payload)
        raise ContractViolation(
            ErrorCode.CAPABILITY_MISSING,
            f"Config key {key!r} is not effective",
            category=ErrorCategory.CONFIGURATION,
        )

    def as_public_dict(self) -> dict[str, object]:
        return self.snapshot.as_dict()


def _entry_projection(entry: ConfigExplanationV0) -> dict[str, object]:
    value: object
    if entry.redaction is ConfigRedactionV0.PUBLIC:
        value = entry.public_value()
    else:
        value = {"redacted": entry.redaction.value, "value_fingerprint": entry.value_fingerprint}
    return {"key": entry.key, "origin": entry.origin.value, "value": value}


def config_projection_sha256(
    registry_sha256: str,
    entries: tuple[ConfigExplanationV0, ...],
    purpose: str,
) -> str:
    return semantic_sha256(
        {
            "schema_version": 0,
            "purpose": purpose,
            "registry_sha256": registry_sha256,
            "entries": [_entry_projection(entry) for entry in entries],
        }
    )
