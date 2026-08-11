from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .constants import CONTRACT_VERSION, KIND_TO_SCHEMA, SCHEMA_PREFIX
from .canonical import strict_loads
from .errors import ContractViolation, ErrorCode


JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
COMMON_SCHEMA_ID = SCHEMA_PREFIX + "common"


def _resolve_pointer(value: Any, pointer: str) -> Any:
    current = value
    if not pointer:
        return current
    if not pointer.startswith("/"):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Invalid schema pointer #{pointer}")
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or token not in current:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Dangling schema pointer #{pointer}")
        current = current[token]
    return current


def _walk(value: Any):
    yield value
    if isinstance(value, Mapping):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def load_schema_registry(schema_dir: Path) -> dict[str, dict[str, Any]]:
    registry: dict[str, dict[str, Any]] = {}
    for path in sorted(schema_dir.glob("*.schema.json")):
        try:
            schema = strict_loads(path.read_bytes())
        except (OSError, json.JSONDecodeError, ContractViolation) as error:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Cannot parse schema {path.name}: {error}") from error
        if not isinstance(schema, dict) or schema.get("$schema") != JSON_SCHEMA_DIALECT:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Invalid schema dialect in {path.name}")
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str) or schema_id in registry:
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, f"Missing or duplicate schema ID in {path.name}")
        registry[schema_id] = schema
    expected = {COMMON_SCHEMA_ID, *KIND_TO_SCHEMA.values()}
    if set(registry) != expected:
        raise ContractViolation(
            ErrorCode.SCHEMA_UNKNOWN,
            f"Schema registry differs; missing={sorted(expected - set(registry))}, unknown={sorted(set(registry) - expected)}",
        )
    for schema_id, schema in registry.items():
        for node in _walk(schema):
            if not isinstance(node, Mapping) or "$ref" not in node:
                continue
            reference = node["$ref"]
            if not isinstance(reference, str):
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Non-string $ref in {schema_id}")
            base, separator, fragment = reference.partition("#")
            target = registry.get(base)
            if target is None:
                raise ContractViolation(ErrorCode.SCHEMA_UNKNOWN, f"Unknown schema reference {reference}")
            if separator:
                _resolve_pointer(target, fragment)
        if schema_id != COMMON_SCHEMA_ID:
            version = schema.get("properties", {}).get("schema_version", {}).get("const")
            if version != CONTRACT_VERSION:
                raise ContractViolation(ErrorCode.SCHEMA_VERSION_UNSUPPORTED, f"Schema version drift in {schema_id}")
    return registry
