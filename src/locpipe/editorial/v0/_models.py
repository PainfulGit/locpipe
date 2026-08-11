from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from locpipe.content.v0 import ScopeRoleV0
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
    validate_envelope,
)
from locpipe.contracts.v0.profiles import SHA256_RE
from locpipe.translation.v0 import ProviderBindingV0, ProviderBudgetV0


def _nonempty(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be non-empty")
    return value


def _sha(value: object, name: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be lowercase SHA-256")
    return value


def _canonical_target(payload: bytes, target_locale: str) -> tuple[str, dict[str, Any]]:
    if not isinstance(payload, bytes):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target must be canonical bytes")
    envelope = parse_canonical_json(payload)
    if canonical_json_bytes(envelope) != payload:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target is not canonical")
    validate_envelope(envelope)
    if envelope.get("kind") != "target_branch":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial target must be target_branch")
    identity = BranchIdentity.from_dict(envelope["data"]["identity"])
    if identity.locale != target_locale:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial target locale drift")
    return display_id(identity), envelope


@dataclass(frozen=True)
class EditorialPolicyV0:
    max_rework_rounds: int = 2

    def __post_init__(self) -> None:
        if not isinstance(self.max_rework_rounds, int) or isinstance(self.max_rework_rounds, bool) or not 0 <= self.max_rework_rounds <= 2:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial max_rework_rounds must be 0..2")

    def as_dict(self) -> dict[str, Any]:
        return {"contract": "locpipe.editorial.policy/v0", "max_rework_rounds": self.max_rework_rounds}

    @property
    def digest(self) -> str:
        return semantic_sha256(self.as_dict())


@dataclass(frozen=True)
class EditorialPacketRowV0:
    identity: BranchIdentity
    role: ScopeRoleV0
    source_revision_sha: str
    content_type: str
    _source_payload_bytes: bytes = field(repr=False)
    _constraints_bytes: bytes = field(repr=False)
    _target_bytes: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.identity, BranchIdentity) or not isinstance(self.role, ScopeRoleV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial packet identity or role is invalid")
        _sha(self.source_revision_sha, "source revision")
        _nonempty(self.content_type, "content type")
        for payload, name in ((self._source_payload_bytes, "source payload"), (self._constraints_bytes, "constraints")):
            if not isinstance(payload, bytes) or canonical_value_bytes(strict_loads(payload)) != payload:
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Editorial {name} is not canonical")
        if self.role is ScopeRoleV0.OWNED:
            if self._target_bytes is None:
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Owned editorial row requires target")
            _key, target = _canonical_target(self._target_bytes, self.target_locale)
            target_identity = BranchIdentity.from_dict(target["data"]["identity"])
            if target_identity.logical_id != self.identity.logical_id or target_identity.selector_path != self.identity.selector_path:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial source/target identity drift")
            if target["data"]["content_type"] != self.content_type:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial content type drift")
        elif self._target_bytes is not None:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Context editorial row cannot carry target")

    @property
    def stable_id(self) -> str:
        return display_id(self.identity)

    @property
    def target_locale(self) -> str:
        if self._target_bytes is None:
            return ""
        envelope = parse_canonical_json(self._target_bytes)
        return BranchIdentity.from_dict(envelope["data"]["identity"]).locale

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.as_dict(),
            "role": self.role.value,
            "source_revision_sha": self.source_revision_sha,
            "content_type": self.content_type,
            "source_payload": strict_loads(self._source_payload_bytes),
            "constraints": strict_loads(self._constraints_bytes),
            "target": None if self._target_bytes is None else parse_canonical_json(self._target_bytes),
        }


@dataclass(frozen=True)
class EditorialPacketV0:
    target_locale: str
    round_index: int
    requested_ids: tuple[str, ...]
    rows: tuple[EditorialPacketRowV0, ...]
    _relation_bytes: tuple[bytes, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _nonempty(self.target_locale, "target locale")
        if not isinstance(self.round_index, int) or isinstance(self.round_index, bool) or not 0 <= self.round_index <= 2:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial round must be 0..2")
        rows = tuple(self.rows)
        keys = tuple(row.stable_id for row in rows)
        if not rows or keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Editorial packet rows must be unique and sorted")
        requested = tuple(self.requested_ids)
        owned = {row.stable_id for row in rows if row.role is ScopeRoleV0.OWNED}
        if not requested or requested != tuple(sorted(requested)) or len(requested) != len(set(requested)) or not set(requested) <= owned:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial requested IDs are invalid")
        for row in rows:
            if row.role is ScopeRoleV0.OWNED and row.target_locale != self.target_locale:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial packet target locale drift")
        relations = tuple(self._relation_bytes)
        digests = []
        for payload in relations:
            value = parse_canonical_json(payload)
            if canonical_json_bytes(value) != payload or value.get("kind") != "relation":
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial relation is invalid")
            digests.append(semantic_sha256(value))
        if tuple(digests) != tuple(sorted(digests)):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial relations must be sorted")
        object.__setattr__(self, "rows", rows)
        object.__setattr__(self, "requested_ids", requested)
        object.__setattr__(self, "_relation_bytes", relations)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.editorial.packet/v0",
            "target_locale": self.target_locale,
            "round_index": self.round_index,
            "requested_ids": list(self.requested_ids),
            "rows": [row.as_dict() for row in self.rows],
            "relations": [parse_canonical_json(row) for row in self._relation_bytes],
        }

    @property
    def digest(self) -> str:
        return semantic_sha256(self.as_dict())


class EditorialActionV0(str, Enum):
    KEEP = "KEEP"
    CORRECT = "CORRECT"
    REWORK_REQUIRED = "REWORK_REQUIRED"


class EditorialJobStatusV0(str, Enum):
    PREPARED = "PREPARED"
    RECEIVED = "RECEIVED"
    ACCEPTED = "ACCEPTED"
    REWORK_REQUIRED = "REWORK_REQUIRED"
    REWORK_EXHAUSTED = "REWORK_EXHAUSTED"
    REJECTED = "REJECTED"
    BYPASSED = "BYPASSED"


@dataclass(frozen=True)
class EditorialJobV0:
    job_id: str
    invocation_id: str
    context_digest: str
    translation_job_id: str
    translation_decision_sha256: str
    translation_state_sha256: str
    base_target_set_sha256: str
    parent_candidate_sha256: str
    parent_decision_sha256: str | None
    scope_sha256: str
    source_lock_sha256: str
    reconciliation_sha256: str
    content_config_digest: str
    effective_snapshot_sha256: str
    module: ModuleDescriptorV0
    provider: ProviderBindingV0
    target_locale: str
    packet_sha256: str
    policy_sha256: str
    role_contract_sha256: str
    output_contract_sha256: str
    budget: ProviderBudgetV0
    round_index: int
    max_invocations: int = 1

    def __post_init__(self) -> None:
        for value, name in ((self.job_id, "job ID"), (self.invocation_id, "invocation ID"), (self.translation_job_id, "translation job ID"), (self.target_locale, "target locale")):
            _nonempty(value, name)
        for value, name in (
            (self.context_digest, "context digest"), (self.translation_decision_sha256, "translation decision SHA"),
            (self.translation_state_sha256, "translation state SHA"),
            (self.base_target_set_sha256, "base target set SHA"), (self.parent_candidate_sha256, "parent candidate SHA"),
            (self.scope_sha256, "scope SHA"), (self.source_lock_sha256, "source lock SHA"),
            (self.reconciliation_sha256, "reconciliation SHA"), (self.content_config_digest, "content config digest"),
            (self.effective_snapshot_sha256, "effective snapshot SHA"), (self.packet_sha256, "packet SHA"),
            (self.policy_sha256, "policy SHA"), (self.role_contract_sha256, "role contract SHA"),
            (self.output_contract_sha256, "output contract SHA"),
        ):
            _sha(value, name)
        if self.parent_decision_sha256 is not None:
            _sha(self.parent_decision_sha256, "parent decision SHA")
        if not isinstance(self.module, ModuleDescriptorV0) or not isinstance(self.provider, ProviderBindingV0) or not isinstance(self.budget, ProviderBudgetV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial bindings or budget are invalid")
        if self.round_index not in {0, 1, 2} or self.max_invocations != 1:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial v0 round or invocation ceiling is invalid")
        if self.round_index == 0 and self.parent_decision_sha256 is not None:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Initial editorial job cannot have parent decision")
        if self.round_index > 0 and self.parent_decision_sha256 is None:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Rework editorial job requires parent decision")

    def identity_projection(self) -> dict[str, Any]:
        return {key: value for key, value in self.as_dict().items() if key not in {"contract", "job_id", "invocation_id"}}

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.editorial.job/v0", "job_id": self.job_id, "invocation_id": self.invocation_id,
            "context_digest": self.context_digest, "translation_job_id": self.translation_job_id,
            "translation_decision_sha256": self.translation_decision_sha256,
            "translation_state_sha256": self.translation_state_sha256,
            "base_target_set_sha256": self.base_target_set_sha256,
            "parent_candidate_sha256": self.parent_candidate_sha256, "parent_decision_sha256": self.parent_decision_sha256,
            "scope_sha256": self.scope_sha256, "source_lock_sha256": self.source_lock_sha256,
            "reconciliation_sha256": self.reconciliation_sha256, "content_config_digest": self.content_config_digest,
            "effective_snapshot_sha256": self.effective_snapshot_sha256, "module": {
                "capability": self.module.capability.value, "module_id": self.module.module_id,
                "version": self.module.version, "digest": self.module.digest,
            }, "provider": self.provider.as_dict(), "target_locale": self.target_locale,
            "packet_sha256": self.packet_sha256, "policy_sha256": self.policy_sha256,
            "role_contract_sha256": self.role_contract_sha256, "output_contract_sha256": self.output_contract_sha256,
            "budget": self.budget.as_dict(), "round_index": self.round_index, "max_invocations": self.max_invocations,
        }


@dataclass(frozen=True)
class EditorialCandidateSetV0:
    job_id: str
    target_locale: str
    ready: bool
    disposition: str
    base_target_set_sha256: str
    parent_candidate_sha256: str | None
    overlay_sha256s: tuple[str, ...]
    unresolved_ids: tuple[str, ...]
    _target_bytes: tuple[bytes, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "candidate job ID")
        _nonempty(self.target_locale, "candidate locale")
        _nonempty(self.disposition, "candidate disposition")
        _sha(self.base_target_set_sha256, "base target set SHA")
        if self.parent_candidate_sha256 is not None:
            _sha(self.parent_candidate_sha256, "parent candidate SHA")
        for value in self.overlay_sha256s:
            _sha(value, "overlay SHA")
        targets = tuple(self._target_bytes)
        keys = tuple(_canonical_target(row, self.target_locale)[0] for row in targets)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Editorial candidate targets must be unique and sorted")
        unresolved = tuple(self.unresolved_ids)
        if unresolved != tuple(sorted(unresolved)) or len(unresolved) != len(set(unresolved)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Editorial unresolved IDs must be unique and sorted")
        if self.ready == bool(unresolved):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial candidate readiness disagrees with unresolved IDs")
        object.__setattr__(self, "_target_bytes", targets)
        object.__setattr__(self, "overlay_sha256s", tuple(self.overlay_sha256s))
        object.__setattr__(self, "unresolved_ids", unresolved)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.editorial.candidate-set/v0", "job_id": self.job_id,
            "target_locale": self.target_locale, "ready": self.ready, "disposition": self.disposition,
            "base_target_set_sha256": self.base_target_set_sha256, "parent_candidate_sha256": self.parent_candidate_sha256,
            "overlay_sha256s": list(self.overlay_sha256s), "unresolved_ids": list(self.unresolved_ids),
            "targets": [parse_canonical_json(row) for row in self._target_bytes],
        }

    @property
    def digest(self) -> str:
        return semantic_sha256(self.as_dict())


def target_bytes_by_id(candidate: EditorialCandidateSetV0) -> dict[str, bytes]:
    return {_canonical_target(row, candidate.target_locale)[0]: row for row in candidate._target_bytes}


def candidate_raw_sha(candidate: EditorialCandidateSetV0) -> str:
    return raw_sha256(canonical_json_bytes(candidate.as_dict()))
