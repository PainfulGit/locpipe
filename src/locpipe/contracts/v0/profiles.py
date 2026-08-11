from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .errors import ContractViolation, ErrorCategory, ErrorCode


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXACT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


class Capability(str, Enum):
    EXTRACT_IMPORT = "extract_import"
    SOURCE_SNAPSHOT = "source_snapshot"
    SOURCE_RECONCILIATION = "source_reconciliation"
    CONTENT_VALIDATION = "content_validation"
    TRANSLATION = "translation"
    EDITORIAL_REVIEW = "editorial_review"
    TERMINOLOGY = "terminology"
    ISSUES = "issues"
    ARTIFACT_BUILD = "artifact_build"
    DELIVERY = "delivery"


class Requirement(str, Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    FORBIDDEN = "forbidden"


class WorkflowProfile(str, Enum):
    CONTENT_ONLY = "content-only"
    ARTIFACT_BUILD = "artifact-build"
    INSTALLED_PATCH = "installed-patch"


BASE_REQUIRED = {
    Capability.EXTRACT_IMPORT,
    Capability.SOURCE_SNAPSHOT,
    Capability.SOURCE_RECONCILIATION,
    Capability.CONTENT_VALIDATION,
}
OPTIONAL_MODULES = {
    Capability.TRANSLATION,
    Capability.EDITORIAL_REVIEW,
    Capability.TERMINOLOGY,
    Capability.ISSUES,
}


def profile_requirements(profile: WorkflowProfile | str) -> dict[Capability, Requirement]:
    try:
        selected = WorkflowProfile(profile)
    except ValueError as error:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Unknown workflow profile {profile!r}") from error
    result = {capability: Requirement.OPTIONAL for capability in Capability}
    for capability in BASE_REQUIRED:
        result[capability] = Requirement.REQUIRED
    if selected is WorkflowProfile.CONTENT_ONLY:
        result[Capability.ARTIFACT_BUILD] = Requirement.FORBIDDEN
        result[Capability.DELIVERY] = Requirement.FORBIDDEN
    elif selected is WorkflowProfile.ARTIFACT_BUILD:
        result[Capability.ARTIFACT_BUILD] = Requirement.REQUIRED
        result[Capability.DELIVERY] = Requirement.FORBIDDEN
    else:
        result[Capability.ARTIFACT_BUILD] = Requirement.REQUIRED
        result[Capability.DELIVERY] = Requirement.REQUIRED
    return result


def parse_capabilities(values: Iterable[str | Capability]) -> set[Capability]:
    parsed: set[Capability] = set()
    for value in values:
        try:
            capability = Capability(value)
        except ValueError as error:
            raise ContractViolation(ErrorCode.CAPABILITY_UNKNOWN, f"Unknown capability {value!r}") from error
        if capability in parsed:
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, f"Duplicate capability {capability.value}")
        parsed.add(capability)
    return parsed


def validate_profile(
    profile: WorkflowProfile | str,
    available: Iterable[str | Capability],
    *,
    disabled_optional: Iterable[str | Capability] = (),
) -> tuple[Capability, ...]:
    requirements = profile_requirements(profile)
    available_set = parse_capabilities(available)
    disabled_set = parse_capabilities(disabled_optional)
    invalid_disabled = {
        capability for capability in disabled_set
        if requirements[capability] is not Requirement.OPTIONAL
    }
    if invalid_disabled or available_set & disabled_set:
        raise ContractViolation(
            ErrorCode.CAPABILITY_FORBIDDEN,
            "Only unavailable optional capabilities may be explicitly disabled",
            category=ErrorCategory.CONFIGURATION,
        )
    for capability, requirement in requirements.items():
        if requirement is Requirement.REQUIRED and capability not in available_set:
            raise ContractViolation(
                ErrorCode.CAPABILITY_MISSING,
                f"Required capability {capability.value} is unavailable",
                category=ErrorCategory.CONFIGURATION,
                safe_to_resume=True,
            )
        if requirement is Requirement.FORBIDDEN and capability in available_set:
            raise ContractViolation(
                ErrorCode.CAPABILITY_FORBIDDEN,
                f"Capability {capability.value} is forbidden by {WorkflowProfile(profile).value}",
                category=ErrorCategory.CONFIGURATION,
            )
        if requirement is Requirement.OPTIONAL and capability not in available_set and capability not in disabled_set:
            raise ContractViolation(
                ErrorCode.CAPABILITY_MISSING,
                f"Optional capability {capability.value} must be bound or explicitly disabled",
                category=ErrorCategory.CONFIGURATION,
                safe_to_resume=True,
            )
    return tuple(sorted(available_set, key=lambda item: item.value))


def _validate_pin(identifier: str, version: str, digest: str) -> None:
    if (
        not isinstance(identifier, str)
        or not identifier
        or not isinstance(version, str)
        or not EXACT_VERSION_RE.fullmatch(version)
        or not isinstance(digest, str)
        or not SHA256_RE.fullmatch(digest)
    ):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Binding requires ID, exact SemVer and SHA-256 digest")


@dataclass(frozen=True)
class AdapterDescriptorV0:
    adapter_id: str
    version: str
    digest: str
    capabilities: tuple[Capability, ...]

    def __post_init__(self) -> None:
        _validate_pin(self.adapter_id, self.version, self.digest)
        parsed = parse_capabilities(self.capabilities)
        if tuple(sorted(parsed, key=lambda item: item.value)) != self.capabilities:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Adapter capabilities must be unique and sorted")


@dataclass(frozen=True)
class ModuleDescriptorV0:
    capability: Capability
    module_id: str
    version: str
    digest: str

    def __post_init__(self) -> None:
        _validate_pin(self.module_id, self.version, self.digest)


def validate_module_bindings(bindings: Iterable[ModuleDescriptorV0]) -> tuple[ModuleDescriptorV0, ...]:
    rows = tuple(bindings)
    keys = [(row.capability.value, row.module_id) for row in rows]
    if len({row.capability for row in rows}) != len(rows):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Duplicate module capability binding")
    if keys != sorted(keys):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Module bindings must be sorted")
    return rows
