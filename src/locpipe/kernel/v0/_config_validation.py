from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from locpipe.contracts.v0 import (
    Capability,
    ContractViolation,
    ErrorCategory,
    ErrorCode,
    ModuleDescriptorV0,
    WorkflowProfile,
    validate_module_bindings,
)
from locpipe.contracts.v0.profiles import EXACT_VERSION_RE, SHA256_RE

from ._config_models import ConfigCheckpointV0
from ._transaction_models import NamespaceV0


def _fail(detail: str) -> ContractViolation:
    return ContractViolation(
        ErrorCode.MALFORMED_ARTIFACT,
        detail,
        category=ErrorCategory.CONFIGURATION,
    )


def _nonempty_string(value: Any, detail: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _fail(detail)
    return value


def _exact_mapping(value: Any, fields: set[str], detail: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _fail(detail)
    return value


def _validate_module_bindings(value: Any) -> None:
    if not isinstance(value, list):
        raise _fail("module_bindings must be a list")
    parsed: list[ModuleDescriptorV0] = []
    for row in value:
        selected = _exact_mapping(
            row,
            {"capability", "module_id", "version", "digest"},
            "Module binding fields are invalid",
        )
        try:
            capability = Capability(selected["capability"])
        except (TypeError, ValueError) as error:
            raise _fail("Module binding capability is invalid") from error
        parsed.append(
            ModuleDescriptorV0(
                capability,
                selected["module_id"],
                selected["version"],
                selected["digest"],
            )
        )
    validate_module_bindings(parsed)


def _validate_provider_bindings(value: Any) -> None:
    if not isinstance(value, list):
        raise _fail("provider_bindings must be a list")
    order: list[tuple[str, str]] = []
    roles: set[str] = set()
    for row in value:
        selected = _exact_mapping(
            row,
            {"role", "provider_id", "version", "config_digest"},
            "Provider binding fields are invalid",
        )
        role = _nonempty_string(selected["role"], "Provider role is invalid")
        provider_id = _nonempty_string(selected["provider_id"], "Provider ID is invalid")
        version = _nonempty_string(selected["version"], "Provider version is invalid")
        digest = _nonempty_string(selected["config_digest"], "Provider config digest is invalid")
        if not EXACT_VERSION_RE.fullmatch(version) or not SHA256_RE.fullmatch(digest):
            raise _fail("Provider binding requires exact version and SHA-256 digest")
        if role in roles:
            raise ContractViolation(
                ErrorCode.DUPLICATE_IDENTITY,
                "Duplicate provider role binding",
                category=ErrorCategory.CONFIGURATION,
            )
        roles.add(role)
        order.append((role, provider_id))
    if order != sorted(order):
        raise _fail("Provider bindings must be sorted")


def validate_config_value(key: str, value: Any, checkpoint: ConfigCheckpointV0) -> None:
    if value is None:
        raise _fail("Config values cannot be null")
    if key in {"workspace_id", "project_id", "release_id"}:
        selected = _nonempty_string(value, "Config namespace identity is invalid")
        values = {"workspace_id": "w", "project_id": "p", "release_id": "r"}
        values[key] = selected
        NamespaceV0(values["workspace_id"], values["project_id"], values["release_id"])
    elif key == "workflow_profile":
        try:
            WorkflowProfile(value)
        except (TypeError, ValueError) as error:
            raise _fail("workflow_profile is invalid") from error
    elif key == "source_locale":
        _nonempty_string(value, "source_locale is invalid")
    elif key == "target_locales":
        if (
            not isinstance(value, list)
            or not value
            or any(not isinstance(locale, str) or not locale for locale in value)
            or value != sorted(value)
            or len(value) != len(set(value))
        ):
            raise _fail("target_locales must be non-empty, unique and sorted")
    elif key == "adapter_version":
        if not isinstance(value, str) or not EXACT_VERSION_RE.fullmatch(value):
            raise _fail("adapter_version must be exact SemVer")
    elif key in {"adapter_digest", "runtime_dependency_lock"}:
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise _fail(f"{key} must be a lowercase SHA-256")
    elif key == "module_bindings":
        _validate_module_bindings(value)
    elif key == "provider_bindings":
        _validate_provider_bindings(value)
    elif key in {"build_output", "runtime_executable", "install_target"}:
        _nonempty_string(value, f"{key} path is invalid")
    elif key == "secret_ref":
        selected = _exact_mapping(
            value,
            {"identity", "version"},
            "secret_ref must contain only identity and version",
        )
        _nonempty_string(selected["identity"], "secret_ref identity is invalid")
        _nonempty_string(selected["version"], "secret_ref version is invalid")
    elif key == "allow_install":
        if value is not True or checkpoint is not ConfigCheckpointV0.INSTALL_AUTHORIZE:
            raise _fail("allow_install is a one-shot true value at INSTALL_AUTHORIZE")
