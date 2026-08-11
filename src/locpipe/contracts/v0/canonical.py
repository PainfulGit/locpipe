from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from typing import Any

import rfc8785

from .errors import ContractViolation, ErrorCategory, ErrorCode


MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _fail(detail: str) -> ContractViolation:
    return ContractViolation(
        ErrorCode.CANONICALIZATION_ERROR,
        detail,
        category=ErrorCategory.INTEGRITY,
    )


def validate_json_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise _fail(f"Invalid Unicode at {path}") from error
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise _fail(f"Integer outside the I-JSON safe range at {path}")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _fail(f"Non-finite number at {path}")
        return
    if isinstance(value, list) or isinstance(value, tuple):
        for index, item in enumerate(value):
            validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _fail(f"Non-string object key at {path}")
            validate_json_value(key, f"{path}.<key>")
            validate_json_value(item, f"{path}.{key}")
        return
    raise _fail(f"Unsupported JSON value {type(value).__name__} at {path}")


def canonical_value_bytes(value: Any) -> bytes:
    validate_json_value(value)
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeError, ValueError) as error:
        raise _fail(str(error)) from error


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_value_bytes(value) + b"\n"


def semantic_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_value_bytes(value)).hexdigest()


def raw_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def normalized_text(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _reject_constant(value: str) -> None:
    raise _fail(f"Invalid JSON constant {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise _fail(f"Duplicate object key {key!r}")
        output[key] = value
    return output


def strict_loads(payload: bytes) -> Any:
    if payload.startswith(b"\xef\xbb\xbf"):
        raise _fail("UTF-8 BOM is forbidden")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise _fail("Artifact is not valid UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ContractViolation:
        raise
    except (json.JSONDecodeError, ValueError) as error:
        raise _fail(f"Malformed JSON: {error}") from error
    validate_json_value(value)
    return value


def parse_canonical_json(payload: bytes) -> Any:
    if not payload.endswith(b"\n") or payload.endswith(b"\n\n"):
        raise _fail("Canonical JSON requires exactly one trailing LF")
    body = payload[:-1]
    if b"\r" in body or b"\n" in body:
        raise _fail("Canonical JSON must not contain formatting newlines")
    value = strict_loads(body)
    if canonical_json_bytes(value) != payload:
        raise _fail("JSON bytes are not canonical")
    return value


def canonical_jsonl_bytes(
    records: Iterable[Mapping[str, Any]],
    *,
    sort_key: Callable[[Mapping[str, Any]], Any] | None,
) -> bytes:
    if sort_key is None:
        raise _fail("JSONL schema must declare a record ordering key")
    materialized = list(records)
    if not materialized:
        raise _fail("Canonical JSONL must contain at least one record")
    if any(not isinstance(record, Mapping) for record in materialized):
        raise _fail("Canonical JSONL records must be objects")
    keyed = [(canonical_value_bytes(sort_key(record)), record) for record in materialized]
    if len({key for key, _record in keyed}) != len(keyed):
        raise _fail("JSONL ordering key is not unique")
    return b"".join(canonical_json_bytes(dict(record)) for _key, record in sorted(keyed, key=lambda item: item[0]))


def parse_canonical_jsonl(
    payload: bytes,
    *,
    sort_key: Callable[[Mapping[str, Any]], Any] | None,
) -> list[Mapping[str, Any]]:
    if sort_key is None:
        raise _fail("JSONL schema must declare a record ordering key")
    if not payload or not payload.endswith(b"\n") or b"\r" in payload:
        raise _fail("Canonical JSONL requires LF-terminated records")
    records: list[Mapping[str, Any]] = []
    ordering_keys: list[bytes] = []
    for index, line in enumerate(payload.splitlines(), start=1):
        if not line:
            raise _fail(f"Blank JSONL record at line {index}")
        value = strict_loads(line)
        if canonical_value_bytes(value) != line:
            raise _fail(f"Non-canonical JSONL record at line {index}")
        if not isinstance(value, Mapping):
            raise _fail(f"JSONL record at line {index} is not an object")
        records.append(value)
        ordering_keys.append(canonical_value_bytes(sort_key(value)))
    if len(set(ordering_keys)) != len(ordering_keys):
        raise _fail("JSONL ordering key is not unique")
    if ordering_keys != sorted(ordering_keys):
        raise _fail("JSONL records do not follow their declared ordering")
    return records
