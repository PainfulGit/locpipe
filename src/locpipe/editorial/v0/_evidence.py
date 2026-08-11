from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from locpipe.contracts.v0 import (
    BranchIdentity,
    ContractViolation,
    ErrorCode,
    canonical_json_bytes,
    display_id,
    parse_canonical_json,
    raw_sha256,
)
from locpipe.translation.v0 import ProviderBindingV0

from ._models import EditorialActionV0, EditorialJobStatusV0, _canonical_target, _nonempty, _sha


@dataclass(frozen=True)
class EditorialSubmissionReceiptV0:
    job_id: str
    invocation_id: str
    provider: ProviderBindingV0
    provider_request_id: str
    packet_sha256: str
    output_contract_sha256: str
    raw_output_sha256: str

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "editorial job ID")
        _nonempty(self.invocation_id, "editorial invocation ID")
        if not isinstance(self.provider, ProviderBindingV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial submission provider is invalid")
        _nonempty(self.provider_request_id, "editorial provider request ID")
        for value, name in ((self.packet_sha256, "packet SHA"), (self.output_contract_sha256, "output contract SHA"), (self.raw_output_sha256, "raw output SHA")):
            _sha(value, name)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.editorial.submission-receipt/v0", "job_id": self.job_id,
            "invocation_id": self.invocation_id, "provider": self.provider.as_dict(),
            "provider_request_id": self.provider_request_id, "packet_sha256": self.packet_sha256,
            "output_contract_sha256": self.output_contract_sha256, "raw_output_sha256": self.raw_output_sha256,
        }


@dataclass(frozen=True)
class EditorialDecisionEntryV0:
    identity: BranchIdentity
    action: EditorialActionV0
    reason_code: str
    replacement_sha256: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, BranchIdentity) or not isinstance(self.action, EditorialActionV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial decision identity/action is invalid")
        _nonempty(self.reason_code, "editorial reason code")
        if self.replacement_sha256 is not None:
            _sha(self.replacement_sha256, "editorial replacement SHA")
        if (self.action is EditorialActionV0.CORRECT) != (self.replacement_sha256 is not None):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial correction replacement binding is invalid")

    @property
    def stable_id(self) -> str:
        return display_id(self.identity)

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.as_dict(), "action": self.action.value,
            "reason_code": self.reason_code, "replacement_sha256": self.replacement_sha256,
        }


@dataclass(frozen=True)
class EditorialDecisionSetV0:
    job_id: str
    submission_sha256: str
    status: EditorialJobStatusV0
    reason_code: str
    decisions: tuple[EditorialDecisionEntryV0, ...]

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "decision job ID")
        _sha(self.submission_sha256, "decision submission SHA")
        if self.status not in {
            EditorialJobStatusV0.ACCEPTED, EditorialJobStatusV0.REWORK_REQUIRED,
            EditorialJobStatusV0.REWORK_EXHAUSTED, EditorialJobStatusV0.REJECTED,
        }:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial decision status is not terminal")
        _nonempty(self.reason_code, "decision-set reason code")
        rows = tuple(self.decisions)
        keys = tuple(row.stable_id for row in rows)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Editorial decisions must be unique and sorted")
        if self.status is EditorialJobStatusV0.REJECTED and rows:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Rejected editorial decision cannot retain entries")
        object.__setattr__(self, "decisions", rows)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.editorial.decision-set/v0", "job_id": self.job_id,
            "submission_sha256": self.submission_sha256, "status": self.status.value,
            "reason_code": self.reason_code, "decisions": [row.as_dict() for row in self.decisions],
        }


@dataclass(frozen=True)
class CorrectionEntryV0:
    source_identity: BranchIdentity
    preimage_target_sha256: str
    _replacement_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.source_identity, BranchIdentity):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Correction source identity is invalid")
        _sha(self.preimage_target_sha256, "correction preimage SHA")
        key, envelope = _canonical_target(self._replacement_bytes, BranchIdentity.from_dict(parse_canonical_json(self._replacement_bytes)["data"]["identity"]).locale)
        replacement_identity = BranchIdentity.from_dict(envelope["data"]["identity"])
        if replacement_identity.logical_id != self.source_identity.logical_id or replacement_identity.selector_path != self.source_identity.selector_path:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Correction source/target identity drift")

    @property
    def stable_id(self) -> str:
        return display_id(self.source_identity)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_identity": self.source_identity.as_dict(),
            "preimage_target_sha256": self.preimage_target_sha256,
            "replacement": parse_canonical_json(self._replacement_bytes),
        }


@dataclass(frozen=True)
class CorrectionOverlayV0:
    job_id: str
    decision_set_sha256: str
    parent_candidate_sha256: str
    entries: tuple[CorrectionEntryV0, ...]

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "overlay job ID")
        _sha(self.decision_set_sha256, "overlay decision SHA")
        _sha(self.parent_candidate_sha256, "overlay parent candidate SHA")
        rows = tuple(self.entries)
        keys = tuple(row.stable_id for row in rows)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Correction overlay must be unique and sorted")
        object.__setattr__(self, "entries", rows)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.editorial.correction-overlay/v0", "job_id": self.job_id,
            "decision_set_sha256": self.decision_set_sha256, "parent_candidate_sha256": self.parent_candidate_sha256,
            "entries": [row.as_dict() for row in self.entries],
        }

    @property
    def raw_digest(self) -> str:
        return raw_sha256(canonical_json_bytes(self.as_dict()))


@dataclass(frozen=True)
class EditorialReworkRequestV0:
    job_id: str
    disposition: str
    candidate_sha256: str
    parent_decision_sha256: str
    policy_sha256: str
    next_round: int | None
    requested_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "rework job ID")
        _nonempty(self.disposition, "rework disposition")
        _sha(self.candidate_sha256, "rework candidate SHA")
        _sha(self.parent_decision_sha256, "rework decision SHA")
        _sha(self.policy_sha256, "rework policy SHA")
        if self.next_round is not None and self.next_round not in {1, 2}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial next round must be 1 or 2")
        ids = tuple(self.requested_ids)
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Editorial rework IDs must be unique and sorted")
        if (self.next_round is not None) != bool(ids):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial active rework must have round and IDs")
        object.__setattr__(self, "requested_ids", ids)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.editorial.rework-request/v0", "job_id": self.job_id,
            "disposition": self.disposition, "candidate_sha256": self.candidate_sha256,
            "parent_decision_sha256": self.parent_decision_sha256, "next_round": self.next_round,
            "policy_sha256": self.policy_sha256,
            "requested_ids": list(self.requested_ids),
        }


@dataclass(frozen=True)
class EditorialStateV0:
    job_id: str
    invocation_id: str
    status: EditorialJobStatusV0
    selected_submission_sha256: str | None = None
    decision_set_sha256: str | None = None
    overlay_sha256: str | None = None
    candidate_sha256: str | None = None
    rework_request_sha256: str | None = None

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "editorial state job ID")
        _nonempty(self.invocation_id, "editorial state invocation ID")
        if not isinstance(self.status, EditorialJobStatusV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial state status is invalid")
        values = (self.selected_submission_sha256, self.decision_set_sha256, self.overlay_sha256, self.candidate_sha256, self.rework_request_sha256)
        for value in values:
            if value is not None:
                _sha(value, "editorial state artifact SHA")
        if self.status is EditorialJobStatusV0.PREPARED and any(value is not None for value in values):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "PREPARED editorial state cannot bind outputs")
        if self.status is EditorialJobStatusV0.RECEIVED and (self.selected_submission_sha256 is None or any(value is not None for value in values[1:])):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "RECEIVED editorial state binding is invalid")
        if self.status in {EditorialJobStatusV0.ACCEPTED, EditorialJobStatusV0.REWORK_REQUIRED, EditorialJobStatusV0.REWORK_EXHAUSTED, EditorialJobStatusV0.REJECTED} and any(value is None for value in values):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Terminal editorial state evidence is incomplete")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.editorial.state/v0", "job_id": self.job_id, "invocation_id": self.invocation_id,
            "status": self.status.value, "selected_submission_sha256": self.selected_submission_sha256,
            "decision_set_sha256": self.decision_set_sha256, "overlay_sha256": self.overlay_sha256,
            "candidate_sha256": self.candidate_sha256, "rework_request_sha256": self.rework_request_sha256,
        }
