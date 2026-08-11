from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ErrorCategory(str, Enum):
    CONTRACT = "CONTRACT"
    INTEGRITY = "INTEGRITY"
    CONFIGURATION = "CONFIGURATION"
    AUTHORIZATION = "AUTHORIZATION"
    ENVIRONMENT = "ENVIRONMENT"
    CONTENT = "CONTENT"
    INTERNAL = "INTERNAL"


class ErrorCode(str, Enum):
    SCHEMA_UNKNOWN = "SCHEMA_UNKNOWN"
    SCHEMA_VERSION_UNSUPPORTED = "SCHEMA_VERSION_UNSUPPORTED"
    MALFORMED_ARTIFACT = "MALFORMED_ARTIFACT"
    CAPABILITY_UNKNOWN = "CAPABILITY_UNKNOWN"
    CAPABILITY_MISSING = "CAPABILITY_MISSING"
    CAPABILITY_FORBIDDEN = "CAPABILITY_FORBIDDEN"
    DUPLICATE_IDENTITY = "DUPLICATE_IDENTITY"
    DANGLING_RELATION = "DANGLING_RELATION"
    CANONICALIZATION_ERROR = "CANONICALIZATION_ERROR"
    HASH_MISMATCH = "HASH_MISMATCH"
    BINDING_MISMATCH = "BINDING_MISMATCH"
    PATH_ESCAPE = "PATH_ESCAPE"
    OUTPUT_CONTRACT_VIOLATION = "OUTPUT_CONTRACT_VIOLATION"
    PROTECTED_PATH_DRIFT = "PROTECTED_PATH_DRIFT"
    HANDLER_EXCEPTION = "HANDLER_EXCEPTION"


@dataclass(frozen=True)
class ErrorRecord:
    code: ErrorCode
    category: ErrorCategory
    artifact: str | None
    safe_to_resume: bool
    next_commands: tuple[str, ...]
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "category": self.category.value,
            "artifact": self.artifact,
            "safe_to_resume": self.safe_to_resume,
            "next_commands": list(self.next_commands),
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ErrorRecord":
        if not isinstance(value, dict) or set(value) != {
            "code", "category", "artifact", "safe_to_resume", "next_commands", "detail"
        }:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid structured error fields")
        try:
            code = ErrorCode(value["code"])
            category = ErrorCategory(value["category"])
        except (TypeError, ValueError) as error:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Unknown structured error value") from error
        if value["artifact"] is not None and not isinstance(value["artifact"], str):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Error artifact must be string or null")
        if not isinstance(value["safe_to_resume"], bool):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "safe_to_resume must be boolean")
        commands = value["next_commands"]
        if not isinstance(commands, list) or any(not isinstance(item, str) or not item for item in commands):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "next_commands must contain non-empty strings")
        if not isinstance(value["detail"], str) or not value["detail"]:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Error detail must be non-empty")
        return cls(code, category, value["artifact"], value["safe_to_resume"], tuple(commands), value["detail"])


class ContractViolation(ValueError):
    def __init__(
        self,
        code: ErrorCode,
        detail: str,
        *,
        category: ErrorCategory = ErrorCategory.CONTRACT,
        artifact: str | None = None,
        safe_to_resume: bool = False,
        next_commands: tuple[str, ...] = (),
    ) -> None:
        self.record = ErrorRecord(
            code=code,
            category=category,
            artifact=artifact,
            safe_to_resume=safe_to_resume,
            next_commands=next_commands,
            detail=detail,
        )
        super().__init__(f"{code.value}: {detail}")
