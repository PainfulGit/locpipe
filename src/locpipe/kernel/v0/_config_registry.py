from __future__ import annotations

import csv
import io

from locpipe.contracts.v0 import ContractViolation, ErrorCategory, ErrorCode, semantic_sha256

from ._config_models import (
    CONFIG_LAYER_ORDER,
    DIGEST_DOMAIN_ORDER,
    ConfigCheckpointV0,
    ConfigDigestDomainV0,
    ConfigKeySpecV0,
    ConfigLayerV0,
    ConfigRedactionV0,
    ConfigRegistryV0,
)


REGISTRY_COLUMNS = (
    "key",
    "allowed_layers",
    "frozen_after",
    "redaction",
    "digest_domains",
    "notes",
)


def _fail(detail: str) -> ContractViolation:
    return ContractViolation(
        ErrorCode.MALFORMED_ARTIFACT,
        detail,
        category=ErrorCategory.CONFIGURATION,
    )


def _split_enum(value: str, enum_type: type, order: tuple) -> tuple:
    if not value:
        raise _fail("Config registry list field is empty")
    try:
        parsed = tuple(enum_type(item) for item in value.split("|"))
    except ValueError as error:
        raise _fail("Config registry contains an unknown enum value") from error
    expected = tuple(item for item in order if item in parsed)
    if parsed != expected or len(parsed) != len(set(parsed)):
        raise _fail("Config registry list field must be unique and ordered")
    return parsed


def load_config_registry_v0(csv_bytes: bytes) -> ConfigRegistryV0:
    if not isinstance(csv_bytes, bytes) or not csv_bytes or csv_bytes.startswith(b"\xef\xbb\xbf"):
        raise _fail("Config registry must be non-empty UTF-8 without BOM")
    try:
        text = csv_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise _fail("Config registry is not valid UTF-8") from error
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if tuple(reader.fieldnames or ()) != REGISTRY_COLUMNS:
            raise _fail("Config registry columns are invalid")
        rows = list(reader)
    except csv.Error as error:
        raise _fail("Config registry CSV is malformed") from error
    if not rows or any(None in row or set(row) != set(REGISTRY_COLUMNS) for row in rows):
        raise _fail("Config registry rows are malformed")

    specs: list[ConfigKeySpecV0] = []
    for row in rows:
        try:
            checkpoint = ConfigCheckpointV0(row["frozen_after"])
            redaction = ConfigRedactionV0(row["redaction"])
        except ValueError as error:
            raise _fail("Config registry contains an unknown enum value") from error
        layers = _split_enum(row["allowed_layers"], ConfigLayerV0, CONFIG_LAYER_ORDER)
        domains = _split_enum(row["digest_domains"], ConfigDigestDomainV0, DIGEST_DOMAIN_ORDER)
        specs.append(
            ConfigKeySpecV0(
                key=row["key"],
                allowed_layers=layers,
                frozen_after=checkpoint,
                redaction=redaction,
                digest_domains=domains,
                notes=row["notes"],
            )
        )
    ordered = tuple(sorted(specs, key=lambda spec: spec.key))
    if len({spec.key for spec in ordered}) != len(ordered):
        raise ContractViolation(
            ErrorCode.DUPLICATE_IDENTITY,
            "Duplicate config registry key",
            category=ErrorCategory.CONFIGURATION,
        )
    digest = semantic_sha256([spec.as_dict() for spec in ordered])
    return ConfigRegistryV0(ordered, digest)
