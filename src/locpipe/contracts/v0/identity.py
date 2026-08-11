from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import canonical_value_bytes, semantic_sha256, strict_loads
from .errors import ContractViolation, ErrorCode


SELECTOR_TYPES = {"select", "plural"}


def _nonempty(value: str, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{field} must be non-empty")
    return value


@dataclass(frozen=True)
class SelectorStep:
    name: str
    type: str
    value: str

    def __post_init__(self) -> None:
        _nonempty(self.name, "selector name")
        _nonempty(self.value, "selector value")
        if self.type not in SELECTOR_TYPES:
            raise ContractViolation(
                ErrorCode.MALFORMED_ARTIFACT,
                f"Unknown selector type {self.type!r}",
            )

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "type": self.type, "value": self.value}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SelectorStep":
        if set(value) != {"name", "type", "value"}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid selector fields")
        return cls(value["name"], value["type"], value["value"])


@dataclass(frozen=True)
class BranchIdentity:
    logical_id: tuple[str, ...]
    locale: str
    selector_path: tuple[SelectorStep, ...] = ()

    def __post_init__(self) -> None:
        if not self.logical_id or any(not isinstance(part, str) or not part for part in self.logical_id):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "logical_id must contain non-empty strings")
        _nonempty(self.locale, "locale")
        names = [step.name for step in self.selector_path]
        if len(names) != len(set(names)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "selector names must be unique within a path")

    def as_dict(self) -> dict[str, Any]:
        return {
            "logical_id": list(self.logical_id),
            "locale": self.locale,
            "selector_path": [step.as_dict() for step in self.selector_path],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BranchIdentity":
        if set(value) != {"logical_id", "locale", "selector_path"}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid branch identity fields")
        logical = value["logical_id"]
        path = value["selector_path"]
        if not isinstance(logical, list) or not isinstance(path, list):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid identity collection fields")
        return cls(
            tuple(logical),
            value["locale"],
            tuple(SelectorStep.from_dict(step) for step in path),
        )


def display_id(identity: BranchIdentity) -> str:
    encoded = base64.urlsafe_b64encode(canonical_value_bytes(identity.as_dict())).decode("ascii")
    return "sid:v0:" + encoded.rstrip("=")


def parse_display_id(value: str) -> BranchIdentity:
    prefix = "sid:v0:"
    if not value.startswith(prefix):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Unsupported display ID")
    token = value[len(prefix):]
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        parsed = strict_loads(raw)
    except (ValueError, UnicodeError) as error:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid display ID") from error
    if not isinstance(parsed, dict):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Display ID must encode an object")
    identity = BranchIdentity.from_dict(parsed)
    if display_id(identity) != value:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Display ID is not canonical")
    return identity


def source_revision_sha(
    *,
    identity: BranchIdentity,
    content_type: str,
    payload: Any,
    constraints: Mapping[str, Any],
) -> str:
    projection = {
        "content_type": _nonempty(content_type, "content_type"),
        "selector_path": [step.as_dict() for step in identity.selector_path],
        "payload": payload,
        "constraints": dict(constraints),
    }
    return semantic_sha256(projection)
