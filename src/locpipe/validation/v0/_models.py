from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from locpipe.contracts.v0 import (
    BranchIdentity,
    ContractViolation,
    ErrorCode,
    ModuleDescriptorV0,
    canonical_json_bytes,
    canonical_value_bytes,
    display_id,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
    strict_loads,
)
from locpipe.contracts.v0.profiles import SHA256_RE


def _nonempty(value: str, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be non-empty")
    return value


def _sha(value: str, name: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be lowercase SHA-256")
    return value


class FindingSeverityV0(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"


class ContentValidationStatusV0(str, Enum):
    LOCALE_VERIFIED = "LOCALE_VERIFIED"
    REWORK_REQUIRED = "REWORK_REQUIRED"
    REWORK_EXHAUSTED = "REWORK_EXHAUSTED"
    REWORK_UNAVAILABLE = "REWORK_UNAVAILABLE"


@dataclass(frozen=True)
class ContentValidationPacketRowV0:
    identity: BranchIdentity
    role: str
    source_revision_sha: str
    content_type: str
    _source_bytes: bytes = field(repr=False)
    _target_bytes: bytes | None = field(repr=False)
    _constraints_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.identity, BranchIdentity) or self.role not in {"OWNED", "CONTEXT"}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation packet row identity/role is invalid")
        _sha(self.source_revision_sha, "source revision SHA")
        _nonempty(self.content_type, "content type")
        source = strict_loads(self._source_bytes)
        constraints = strict_loads(self._constraints_bytes)
        if canonical_value_bytes(source) != self._source_bytes or canonical_value_bytes(constraints) != self._constraints_bytes:
            raise ContractViolation(ErrorCode.CANONICALIZATION_ERROR, "Validation packet source/constraints are not canonical")
        if not isinstance(constraints, dict):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation constraints must be an object")
        if self.role == "OWNED" and self._target_bytes is None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Owned validation row requires a target")
        if self.role == "CONTEXT" and self._target_bytes is not None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Context validation row cannot expose a target")
        if self._target_bytes is not None:
            target = parse_canonical_json(self._target_bytes)
            if canonical_json_bytes(target) != self._target_bytes or target.get("kind") != "target_branch":
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation target is invalid")

    @property
    def stable_id(self) -> str:
        return display_id(self.identity)

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.as_dict(),
            "role": self.role,
            "source_revision_sha": self.source_revision_sha,
            "content_type": self.content_type,
            "source": strict_loads(self._source_bytes),
            "target": None if self._target_bytes is None else parse_canonical_json(self._target_bytes),
            "constraints": strict_loads(self._constraints_bytes),
        }


@dataclass(frozen=True)
class ContentValidationPacketV0:
    target_locale: str
    rows: tuple[ContentValidationPacketRowV0, ...]
    _relation_bytes: tuple[bytes, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _nonempty(self.target_locale, "validation target locale")
        rows = tuple(self.rows)
        keys = tuple(row.stable_id for row in rows)
        if not rows or keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Validation rows must be non-empty, unique and sorted")
        if not any(row.role == "OWNED" for row in rows):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation packet requires owned rows")
        relations = tuple(self._relation_bytes)
        if relations != tuple(sorted(relations)) or len(relations) != len(set(relations)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Validation relations must be unique and sorted")
        for payload in relations:
            value = parse_canonical_json(payload)
            if canonical_json_bytes(value) != payload or value.get("kind") != "relation":
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation relation is invalid")
        object.__setattr__(self, "rows", rows)
        object.__setattr__(self, "_relation_bytes", relations)

    @property
    def owned_ids(self) -> tuple[str, ...]:
        return tuple(row.stable_id for row in self.rows if row.role == "OWNED")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.validation.packet/v0",
            "target_locale": self.target_locale,
            "rows": [row.as_dict() for row in self.rows],
            "relations": [parse_canonical_json(row) for row in self._relation_bytes],
        }


@dataclass(frozen=True)
class ContentValidationJobV0:
    job_id: str
    context_digest: str
    config_snapshot_sha256: str
    content_config_digest: str
    scope_sha256: str
    source_lock_sha256: str
    reconciliation_sha256: str
    candidate_sha256: str
    candidate_authority_sha256: str
    target_locale: str
    validator: ModuleDescriptorV0
    rule_contract_sha256: str
    packet_sha256: str
    authority_sha256: str
    editorial_available: bool
    editorial_round_index: int
    max_rework_rounds: int

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "validation job ID")
        _nonempty(self.target_locale, "validation locale")
        for value, name in (
            (self.context_digest, "context digest"),
            (self.config_snapshot_sha256, "config snapshot SHA"),
            (self.content_config_digest, "content config digest"),
            (self.scope_sha256, "scope SHA"),
            (self.source_lock_sha256, "source lock SHA"),
            (self.reconciliation_sha256, "reconciliation SHA"),
            (self.candidate_sha256, "candidate SHA"),
            (self.candidate_authority_sha256, "candidate authority SHA"),
            (self.rule_contract_sha256, "rule contract SHA"),
            (self.packet_sha256, "packet SHA"),
            (self.authority_sha256, "authority SHA"),
        ):
            _sha(value, name)
        if not isinstance(self.validator, ModuleDescriptorV0) or self.validator.capability.value != "content_validation":
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation job requires content_validation module")
        if not isinstance(self.editorial_available, bool):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial availability must be boolean")
        if self.editorial_round_index not in {0, 1, 2} or self.max_rework_rounds not in {0, 1, 2}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation rework bounds are invalid")
        if self.editorial_round_index > self.max_rework_rounds:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation round exceeds rework policy")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.validation.job/v0",
            "job_id": self.job_id,
            "context_digest": self.context_digest,
            "config_snapshot_sha256": self.config_snapshot_sha256,
            "content_config_digest": self.content_config_digest,
            "scope_sha256": self.scope_sha256,
            "source_lock_sha256": self.source_lock_sha256,
            "reconciliation_sha256": self.reconciliation_sha256,
            "candidate_sha256": self.candidate_sha256,
            "candidate_authority_sha256": self.candidate_authority_sha256,
            "target_locale": self.target_locale,
            "validator": {
                "capability": self.validator.capability.value,
                "module_id": self.validator.module_id,
                "version": self.validator.version,
                "digest": self.validator.digest,
            },
            "rule_contract_sha256": self.rule_contract_sha256,
            "packet_sha256": self.packet_sha256,
            "authority_sha256": self.authority_sha256,
            "editorial_available": self.editorial_available,
            "editorial_round_index": self.editorial_round_index,
            "max_rework_rounds": self.max_rework_rounds,
        }


@dataclass(frozen=True)
class ContentFindingV0:
    stable_id: str
    rule_id: str
    severity: FindingSeverityV0
    reason_code: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        _nonempty(self.stable_id, "finding stable ID")
        _nonempty(self.rule_id, "finding rule ID")
        _nonempty(self.reason_code, "finding reason code")
        if not isinstance(self.severity, FindingSeverityV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Finding severity is invalid")
        _sha(self.evidence_sha256, "finding evidence SHA")

    @property
    def finding_id(self) -> str:
        return "finding-" + semantic_sha256({
            "stable_id": self.stable_id,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "reason_code": self.reason_code,
            "evidence_sha256": self.evidence_sha256,
        })[:32]

    def as_dict(self) -> dict[str, str]:
        return {
            "finding_id": self.finding_id,
            "stable_id": self.stable_id,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "reason_code": self.reason_code,
            "evidence_sha256": self.evidence_sha256,
        }


@dataclass(frozen=True)
class ContentValidationReportV0:
    job_id: str
    validator: ModuleDescriptorV0
    rule_contract_sha256: str
    candidate_sha256: str
    findings: tuple[ContentFindingV0, ...]

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "validation report job ID")
        if not isinstance(self.validator, ModuleDescriptorV0) or self.validator.capability.value != "content_validation":
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation report requires content_validation module")
        _sha(self.rule_contract_sha256, "validation rule contract SHA")
        _sha(self.candidate_sha256, "validation report candidate SHA")
        rows = tuple(self.findings)
        keys = tuple((row.stable_id, row.rule_id, row.reason_code, row.finding_id) for row in rows)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Validation findings must be unique and sorted")
        object.__setattr__(self, "findings", rows)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.validation.report/v0",
            "job_id": self.job_id,
            "validator": {
                "capability": self.validator.capability.value,
                "module_id": self.validator.module_id,
                "version": self.validator.version,
                "digest": self.validator.digest,
            },
            "rule_contract_sha256": self.rule_contract_sha256,
            "candidate_sha256": self.candidate_sha256,
            "findings": [row.as_dict() for row in self.findings],
        }


@dataclass(frozen=True)
class ValidationReworkRequestV0:
    job_id: str
    status: ContentValidationStatusV0
    report_sha256: str
    candidate_sha256: str
    next_round: int | None
    requested_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "validation rework job ID")
        if not isinstance(self.status, ContentValidationStatusV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation rework status is invalid")
        _sha(self.report_sha256, "validation report SHA")
        _sha(self.candidate_sha256, "validation candidate SHA")
        ids = tuple(self.requested_ids)
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Validation rework IDs must be unique and sorted")
        if self.status is ContentValidationStatusV0.REWORK_REQUIRED:
            if self.next_round not in {1, 2} or not ids:
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Active validation rework requires round and IDs")
        elif self.next_round is not None or ids:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Terminal validation state cannot request rework")
        object.__setattr__(self, "requested_ids", ids)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.validation.rework-request/v0",
            "job_id": self.job_id,
            "status": self.status.value,
            "report_sha256": self.report_sha256,
            "candidate_sha256": self.candidate_sha256,
            "next_round": self.next_round,
            "requested_ids": list(self.requested_ids),
        }


@dataclass(frozen=True)
class ContentValidationStateV0:
    job_id: str
    status: ContentValidationStatusV0
    candidate_sha256: str
    report_sha256: str
    rework_request_sha256: str

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "validation state job ID")
        if not isinstance(self.status, ContentValidationStatusV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation state status is invalid")
        for value, name in (
            (self.candidate_sha256, "validation candidate SHA"),
            (self.report_sha256, "validation state report SHA"),
            (self.rework_request_sha256, "validation rework request SHA"),
        ):
            _sha(value, name)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.validation.state/v0",
            "job_id": self.job_id,
            "status": self.status.value,
            "candidate_sha256": self.candidate_sha256,
            "report_sha256": self.report_sha256,
            "rework_request_sha256": self.rework_request_sha256,
        }


@dataclass(frozen=True)
class ContentLocaleReceiptV0:
    context_digest: str
    config_snapshot_sha256: str
    content_config_digest: str
    scope_sha256: str
    source_lock_sha256: str
    reconciliation_sha256: str
    target_locale: str
    candidate_sha256: str
    validation_job_id: str
    report_sha256: str
    state_sha256: str
    operation_result_sha256: str
    validation_publication_receipt_sha256: str

    def __post_init__(self) -> None:
        _nonempty(self.target_locale, "locale receipt locale")
        _nonempty(self.validation_job_id, "locale receipt job ID")
        for value, name in (
            (self.context_digest, "locale context digest"),
            (self.config_snapshot_sha256, "locale config snapshot SHA"),
            (self.content_config_digest, "locale content config digest"),
            (self.scope_sha256, "locale scope SHA"),
            (self.source_lock_sha256, "locale source lock SHA"),
            (self.reconciliation_sha256, "locale reconciliation SHA"),
            (self.candidate_sha256, "locale candidate SHA"),
            (self.report_sha256, "locale report SHA"),
            (self.state_sha256, "locale state SHA"),
            (self.operation_result_sha256, "locale operation result SHA"),
            (self.validation_publication_receipt_sha256, "locale validation publication receipt SHA"),
        ):
            _sha(value, name)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.validation.locale-receipt/v0",
            "context_digest": self.context_digest,
            "config_snapshot_sha256": self.config_snapshot_sha256,
            "content_config_digest": self.content_config_digest,
            "scope_sha256": self.scope_sha256,
            "source_lock_sha256": self.source_lock_sha256,
            "reconciliation_sha256": self.reconciliation_sha256,
            "target_locale": self.target_locale,
            "candidate_sha256": self.candidate_sha256,
            "validation_job_id": self.validation_job_id,
            "report_sha256": self.report_sha256,
            "state_sha256": self.state_sha256,
            "operation_result_sha256": self.operation_result_sha256,
            "validation_publication_receipt_sha256": self.validation_publication_receipt_sha256,
            "status": "LOCALE_VERIFIED",
        }


@dataclass(frozen=True)
class ContentVerificationSetV0:
    context_digest: str
    config_snapshot_sha256: str
    content_config_digest: str
    scope_sha256: str
    source_lock_sha256: str
    reconciliation_sha256: str
    locale_receipts: tuple[ContentLocaleReceiptV0, ...]

    def __post_init__(self) -> None:
        for value, name in (
            (self.context_digest, "verification context digest"),
            (self.config_snapshot_sha256, "verification config snapshot SHA"),
            (self.content_config_digest, "verification content config digest"),
            (self.scope_sha256, "verification scope SHA"),
            (self.source_lock_sha256, "verification source lock SHA"),
            (self.reconciliation_sha256, "verification reconciliation SHA"),
        ):
            _sha(value, name)
        rows = tuple(self.locale_receipts)
        locales = tuple(row.target_locale for row in rows)
        if not rows or locales != tuple(sorted(locales)) or len(locales) != len(set(locales)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Locale receipts must be non-empty, unique and sorted")
        object.__setattr__(self, "locale_receipts", rows)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.validation.verification-set/v0",
            "context_digest": self.context_digest,
            "config_snapshot_sha256": self.config_snapshot_sha256,
            "content_config_digest": self.content_config_digest,
            "scope_sha256": self.scope_sha256,
            "source_lock_sha256": self.source_lock_sha256,
            "reconciliation_sha256": self.reconciliation_sha256,
            "locale_receipts": [row.as_dict() for row in self.locale_receipts],
            "terminal_state": "CONTENT_VERIFIED",
        }


class ContentValidatorV0(Protocol):
    descriptor: ModuleDescriptorV0
    rule_contract_sha256: str
    supported_content_types: tuple[str, ...]
    supported_constraint_keys: tuple[str, ...]

    def validate(self, packet: ContentValidationPacketV0) -> tuple[ContentFindingV0, ...]: ...


def artifact_raw_sha(value: object) -> str:
    return raw_sha256(canonical_json_bytes(value))
