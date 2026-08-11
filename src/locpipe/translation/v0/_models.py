from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from locpipe.contracts.v0 import (
    BranchIdentity,
    ContractViolation,
    ErrorCode,
    canonical_value_bytes,
    display_id,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
    strict_loads,
)
from locpipe.contracts.v0.profiles import EXACT_VERSION_RE, SHA256_RE
from locpipe.content.v0 import ScopeRoleV0


def _nonempty(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be non-empty")
    return value


def _sha(value: object, name: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be lowercase SHA-256")
    return value


def _positive_or_none(value: object, name: str) -> int | None:
    if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value <= 0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be a positive integer or null")
    return value


@dataclass(frozen=True)
class ProviderBindingV0:
    role: str
    provider_id: str
    version: str
    config_digest: str

    def __post_init__(self) -> None:
        _nonempty(self.role, "provider role")
        _nonempty(self.provider_id, "provider ID")
        if not isinstance(self.version, str) or EXACT_VERSION_RE.fullmatch(self.version) is None:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Provider version must be exact SemVer")
        _sha(self.config_digest, "provider config digest")

    def as_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "provider_id": self.provider_id,
            "version": self.version,
            "config_digest": self.config_digest,
        }


@dataclass(frozen=True)
class ProviderBudgetV0:
    max_seconds: int | None
    max_tokens: int | None

    def __post_init__(self) -> None:
        _positive_or_none(self.max_seconds, "max_seconds")
        _positive_or_none(self.max_tokens, "max_tokens")

    def as_dict(self) -> dict[str, int | None]:
        return {"max_seconds": self.max_seconds, "max_tokens": self.max_tokens}


@dataclass(frozen=True)
class TranslationPacketRowV0:
    identity: BranchIdentity
    role: ScopeRoleV0
    source_revision_sha: str
    content_type: str
    _payload_bytes: bytes = field(repr=False)
    _constraints_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.identity, BranchIdentity) or not isinstance(self.role, ScopeRoleV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation packet row identity or role is invalid")
        _sha(self.source_revision_sha, "source revision")
        _nonempty(self.content_type, "content type")
        for payload, name in ((self._payload_bytes, "payload"), (self._constraints_bytes, "constraints")):
            if not isinstance(payload, bytes):
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Packet {name} must be canonical bytes")
            value = strict_loads(payload)
            if canonical_value_bytes(value) != payload:
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Packet {name} is not canonical")
            if name == "constraints" and not isinstance(value, Mapping):
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Packet constraints must be an object")

    @property
    def stable_id(self) -> str:
        return display_id(self.identity)

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.as_dict(),
            "role": self.role.value,
            "source_revision_sha": self.source_revision_sha,
            "content_type": self.content_type,
            "payload": strict_loads(self._payload_bytes),
            "constraints": strict_loads(self._constraints_bytes),
        }


@dataclass(frozen=True)
class TranslationPacketV0:
    target_locale: str
    rows: tuple[TranslationPacketRowV0, ...]
    _relation_bytes: tuple[bytes, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _nonempty(self.target_locale, "target locale")
        rows = tuple(self.rows)
        keys = tuple(row.stable_id for row in rows)
        if not rows or any(not isinstance(row, TranslationPacketRowV0) for row in rows):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation packet rows are invalid")
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Translation packet rows must be unique and sorted")
        if not any(row.role is ScopeRoleV0.OWNED for row in rows):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation packet requires owned rows")
        object.__setattr__(self, "rows", rows)
        relations = tuple(self._relation_bytes)
        parsed = []
        for payload in relations:
            if not isinstance(payload, bytes):
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Packet relation must be canonical bytes")
            value = parse_canonical_json(payload)
            if not isinstance(value, Mapping):
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Packet relation must be an object")
            parsed.append(value)
        if tuple(semantic_sha256(row) for row in parsed) != tuple(sorted(semantic_sha256(row) for row in parsed)):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Packet relations must be sorted")
        object.__setattr__(self, "_relation_bytes", relations)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.translation.packet/v0",
            "target_locale": self.target_locale,
            "rows": [row.as_dict() for row in self.rows],
            "relations": [parse_canonical_json(row) for row in self._relation_bytes],
        }

    @property
    def digest(self) -> str:
        return semantic_sha256(self.as_dict())


class TranslationJobStatusV0(str, Enum):
    PREPARED = "PREPARED"
    RECEIVED = "RECEIVED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class TranslationJobV0:
    job_id: str
    invocation_id: str
    context_digest: str
    scope_sha256: str
    source_lock_sha256: str
    reconciliation_sha256: str
    content_config_digest: str
    effective_snapshot_sha256: str
    provider: ProviderBindingV0
    target_locale: str
    packet_sha256: str
    role_contract_sha256: str
    output_contract_sha256: str
    budget: ProviderBudgetV0
    attempt: int = 1
    max_invocations: int = 1

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "job ID")
        _nonempty(self.invocation_id, "invocation ID")
        for value, name in (
            (self.context_digest, "context digest"),
            (self.scope_sha256, "scope SHA"),
            (self.source_lock_sha256, "source lock SHA"),
            (self.reconciliation_sha256, "reconciliation SHA"),
            (self.content_config_digest, "content config digest"),
            (self.effective_snapshot_sha256, "effective snapshot SHA"),
            (self.packet_sha256, "packet SHA"),
            (self.role_contract_sha256, "role contract SHA"),
            (self.output_contract_sha256, "output contract SHA"),
        ):
            _sha(value, name)
        if not isinstance(self.provider, ProviderBindingV0) or not isinstance(self.budget, ProviderBudgetV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation job provider or budget is invalid")
        _nonempty(self.target_locale, "target locale")
        if self.attempt != 1 or self.max_invocations != 1:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation v0 allows exactly one invocation")

    def identity_projection(self) -> dict[str, Any]:
        return {
            "context_digest": self.context_digest,
            "scope_sha256": self.scope_sha256,
            "source_lock_sha256": self.source_lock_sha256,
            "reconciliation_sha256": self.reconciliation_sha256,
            "content_config_digest": self.content_config_digest,
            "effective_snapshot_sha256": self.effective_snapshot_sha256,
            "provider": self.provider.as_dict(),
            "target_locale": self.target_locale,
            "packet_sha256": self.packet_sha256,
            "role_contract_sha256": self.role_contract_sha256,
            "output_contract_sha256": self.output_contract_sha256,
            "budget": self.budget.as_dict(),
            "attempt": self.attempt,
            "max_invocations": self.max_invocations,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.translation.job/v0",
            "job_id": self.job_id,
            "invocation_id": self.invocation_id,
            **self.identity_projection(),
        }


@dataclass(frozen=True)
class ProviderSubmissionReceiptV0:
    job_id: str
    invocation_id: str
    provider: ProviderBindingV0
    provider_request_id: str
    packet_sha256: str
    output_contract_sha256: str
    raw_output_sha256: str

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "job ID")
        _nonempty(self.invocation_id, "invocation ID")
        if not isinstance(self.provider, ProviderBindingV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Submission provider is invalid")
        _nonempty(self.provider_request_id, "provider request ID")
        _sha(self.packet_sha256, "packet SHA")
        _sha(self.output_contract_sha256, "output contract SHA")
        _sha(self.raw_output_sha256, "raw output SHA")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.translation.submission-receipt/v0",
            "job_id": self.job_id,
            "invocation_id": self.invocation_id,
            "provider": self.provider.as_dict(),
            "provider_request_id": self.provider_request_id,
            "packet_sha256": self.packet_sha256,
            "output_contract_sha256": self.output_contract_sha256,
            "raw_output_sha256": self.raw_output_sha256,
        }


@dataclass(frozen=True)
class TranslationStateV0:
    job_id: str
    invocation_id: str
    status: TranslationJobStatusV0
    selected_submission_sha256: str | None = None
    decision_sha256: str | None = None
    target_set_sha256: str | None = None

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "job ID")
        _nonempty(self.invocation_id, "invocation ID")
        if not isinstance(self.status, TranslationJobStatusV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation state is invalid")
        for value, name in (
            (self.selected_submission_sha256, "selected submission SHA"),
            (self.decision_sha256, "decision SHA"),
            (self.target_set_sha256, "target set SHA"),
        ):
            if value is not None:
                _sha(value, name)
        if self.status is TranslationJobStatusV0.PREPARED and any(
            value is not None for value in (self.selected_submission_sha256, self.decision_sha256, self.target_set_sha256)
        ):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "PREPARED state cannot select or decide output")
        if self.status is TranslationJobStatusV0.RECEIVED and (
            self.selected_submission_sha256 is None or self.decision_sha256 is not None or self.target_set_sha256 is not None
        ):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "RECEIVED state binding is invalid")
        if self.status in {TranslationJobStatusV0.ACCEPTED, TranslationJobStatusV0.REJECTED} and any(
            value is None for value in (self.selected_submission_sha256, self.decision_sha256, self.target_set_sha256)
        ):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Terminal state evidence is incomplete")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.translation.state/v0",
            "job_id": self.job_id,
            "invocation_id": self.invocation_id,
            "status": self.status.value,
            "selected_submission_sha256": self.selected_submission_sha256,
            "decision_sha256": self.decision_sha256,
            "target_set_sha256": self.target_set_sha256,
        }


@dataclass(frozen=True)
class TranslationDecisionV0:
    job_id: str
    invocation_id: str
    status: TranslationJobStatusV0
    submission_sha256: str
    reason_code: str
    target_count: int

    def __post_init__(self) -> None:
        if self.status not in {TranslationJobStatusV0.ACCEPTED, TranslationJobStatusV0.REJECTED}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Decision must be terminal")
        _nonempty(self.job_id, "job ID")
        _nonempty(self.invocation_id, "invocation ID")
        _sha(self.submission_sha256, "submission SHA")
        _nonempty(self.reason_code, "reason code")
        if not isinstance(self.target_count, int) or isinstance(self.target_count, bool) or self.target_count < 0:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target count is invalid")
        if self.status is TranslationJobStatusV0.REJECTED and self.target_count != 0:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Rejected decision cannot retain targets")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.translation.decision/v0",
            "job_id": self.job_id,
            "invocation_id": self.invocation_id,
            "status": self.status.value,
            "submission_sha256": self.submission_sha256,
            "reason_code": self.reason_code,
            "target_count": self.target_count,
        }


@dataclass(frozen=True)
class TranslationTargetSetV0:
    job_id: str
    invocation_id: str
    target_locale: str
    _target_bytes: tuple[bytes, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "job ID")
        _nonempty(self.invocation_id, "invocation ID")
        _nonempty(self.target_locale, "target locale")
        rows = tuple(self._target_bytes)
        parsed = [parse_canonical_json(payload) for payload in rows]
        keys = tuple(display_id(BranchIdentity.from_dict(row["data"]["identity"])) for row in parsed)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Target set must be unique and sorted")
        object.__setattr__(self, "_target_bytes", rows)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.translation.target-set/v0",
            "job_id": self.job_id,
            "invocation_id": self.invocation_id,
            "target_locale": self.target_locale,
            "targets": [parse_canonical_json(row) for row in self._target_bytes],
        }

    @property
    def digest(self) -> str:
        return semantic_sha256(self.as_dict())


def artifact_sha(value: object) -> str:
    return raw_sha256(canonical_value_bytes(value))
