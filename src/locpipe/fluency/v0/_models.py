from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from locpipe.contracts.v0 import (
    Capability,
    ContractViolation,
    ErrorCode,
    ModuleDescriptorV0,
    canonical_json_bytes,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
    strict_loads,
)
from locpipe.contracts.v0.profiles import SHA256_RE
from locpipe.translation.v0 import ProviderBindingV0, ProviderBudgetV0

from ._serialization import canonical_guidance_block_v0, canonical_target_v0


FLUENCY_ROLES = frozenset({"CONTEXT", "REVIEW"})


def _nonempty(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be non-empty")
    return value


def _sha(value: object, name: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be lowercase SHA-256")
    return value


def _sorted_ids(values: tuple[str, ...], name: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    selected = tuple(values)
    if (not allow_empty and not selected) or any(not isinstance(value, str) or not value for value in selected):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} are invalid")
    if selected != tuple(sorted(selected)) or len(selected) != len(set(selected)):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, f"{name} must be unique and sorted")
    return selected


@dataclass(frozen=True)
class FluencyTargetProjectionRowV0:
    stable_id: str
    role: str
    profile_ids: tuple[str, ...] = ()
    group_ids: tuple[str, ...] = ()
    relation_ids: tuple[str, ...] = ()
    _guidance_bytes: tuple[bytes, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        _nonempty(self.stable_id, "Fluency projection stable ID")
        if self.role not in FLUENCY_ROLES:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency projection role is invalid")
        object.__setattr__(self, "profile_ids", _sorted_ids(self.profile_ids, "Fluency profile IDs"))
        object.__setattr__(self, "group_ids", _sorted_ids(self.group_ids, "Fluency group IDs"))
        object.__setattr__(self, "relation_ids", _sorted_ids(self.relation_ids, "Fluency relation IDs"))
        guidance = tuple(self._guidance_bytes)
        parsed = tuple(canonical_guidance_block_v0(payload) for payload in guidance)
        keys = tuple((row["guidance_kind"], row["origin"], row["payload_sha256"]) for row in parsed)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency guidance blocks must be unique and sorted")
        object.__setattr__(self, "_guidance_bytes", guidance)

    def as_dict(self) -> dict[str, Any]:
        return {
            "stable_id": self.stable_id,
            "role": self.role,
            "profile_ids": list(self.profile_ids),
            "group_ids": list(self.group_ids),
            "relation_ids": list(self.relation_ids),
            "guidance": [strict_loads(payload) for payload in self._guidance_bytes],
        }


@dataclass(frozen=True)
class FluencyTargetProjectionV0:
    """Trusted project-produced target-side projection.

    Generic core proves the closed shape, allowed origin labels and exact
    candidate binding. The project producer proves that policy/context payloads
    came only from approved target-side authorities. No language detection is
    performed here.
    """

    candidate_sha256: str
    target_locale: str
    rows: tuple[FluencyTargetProjectionRowV0, ...]

    def __post_init__(self) -> None:
        _sha(self.candidate_sha256, "Fluency projection candidate SHA")
        _nonempty(self.target_locale, "Fluency projection locale")
        rows = tuple(self.rows)
        keys = tuple(row.stable_id for row in rows)
        if not rows or keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency projection rows must be unique and sorted")
        if not any(row.role == "REVIEW" for row in rows):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency projection requires a review row")
        object.__setattr__(self, "rows", rows)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.fluency.target-projection/v0",
            "candidate_sha256": self.candidate_sha256,
            "target_locale": self.target_locale,
            "rows": [row.as_dict() for row in self.rows],
        }

    @property
    def digest(self) -> str:
        return semantic_sha256(self.as_dict())


@dataclass(frozen=True)
class FluencyReviewPlanV0:
    context_digest: str
    candidate_sha256: str
    candidate_authority_sha256: str
    projection_sha256: str
    content_config_digest: str
    effective_snapshot_sha256: str
    module: ModuleDescriptorV0
    accuracy_provider: ProviderBindingV0
    fluency_provider: ProviderBindingV0
    target_locale: str
    requested_ids: tuple[str, ...]
    accuracy_role_contract_sha256: str
    fluency_role_contract_sha256: str
    output_contract_sha256: str
    round_index: int
    max_correction_rounds: int
    parent_terminal_sha256: str | None = None

    def __post_init__(self) -> None:
        for value, name in (
            (self.context_digest, "Fluency context digest"),
            (self.candidate_sha256, "Fluency candidate SHA"),
            (self.candidate_authority_sha256, "Fluency candidate authority SHA"),
            (self.projection_sha256, "Fluency projection SHA"),
            (self.content_config_digest, "Fluency content config digest"),
            (self.effective_snapshot_sha256, "Fluency effective snapshot SHA"),
            (self.accuracy_role_contract_sha256, "Accuracy role contract SHA"),
            (self.fluency_role_contract_sha256, "Fluency role contract SHA"),
            (self.output_contract_sha256, "Fluency output contract SHA"),
        ):
            _sha(value, name)
        if self.parent_terminal_sha256 is not None:
            _sha(self.parent_terminal_sha256, "Fluency parent terminal SHA")
        _nonempty(self.target_locale, "Fluency plan locale")
        if not isinstance(self.module, ModuleDescriptorV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency module binding is invalid")
        if self.module.capability is not Capability.EDITORIAL_REVIEW:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency module capability is invalid")
        if not isinstance(self.accuracy_provider, ProviderBindingV0) or not isinstance(self.fluency_provider, ProviderBindingV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency provider binding is invalid")
        if self.accuracy_provider.role != "accuracy_editor" or self.fluency_provider.role != "fluency_editor":
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency provider roles are invalid")
        object.__setattr__(self, "requested_ids", _sorted_ids(self.requested_ids, "Fluency requested IDs", allow_empty=False))
        if (
            not isinstance(self.round_index, int)
            or isinstance(self.round_index, bool)
            or not isinstance(self.max_correction_rounds, int)
            or isinstance(self.max_correction_rounds, bool)
            or not 0 <= self.round_index <= self.max_correction_rounds <= 2
        ):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction policy must be finite within 0..2")
        if (self.round_index == 0) != (self.parent_terminal_sha256 is None):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency parent terminal binding disagrees with round")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.fluency.review-plan/v0",
            "context_digest": self.context_digest,
            "candidate_sha256": self.candidate_sha256,
            "candidate_authority_sha256": self.candidate_authority_sha256,
            "projection_sha256": self.projection_sha256,
            "content_config_digest": self.content_config_digest,
            "effective_snapshot_sha256": self.effective_snapshot_sha256,
            "module": {
                "capability": self.module.capability.value,
                "module_id": self.module.module_id,
                "version": self.module.version,
                "digest": self.module.digest,
            },
            "accuracy_provider": self.accuracy_provider.as_dict(),
            "fluency_provider": self.fluency_provider.as_dict(),
            "target_locale": self.target_locale,
            "requested_ids": list(self.requested_ids),
            "accuracy_role_contract_sha256": self.accuracy_role_contract_sha256,
            "fluency_role_contract_sha256": self.fluency_role_contract_sha256,
            "output_contract_sha256": self.output_contract_sha256,
            "round_index": self.round_index,
            "max_correction_rounds": self.max_correction_rounds,
            "parent_terminal_sha256": self.parent_terminal_sha256,
        }

    @property
    def digest(self) -> str:
        return semantic_sha256(self.as_dict())


@dataclass(frozen=True)
class FluencyReviewPacketRowV0:
    stable_id: str
    role: str
    profile_ids: tuple[str, ...]
    group_ids: tuple[str, ...]
    relation_ids: tuple[str, ...]
    _guidance_bytes: tuple[bytes, ...] = field(repr=False)
    _target_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        projection = FluencyTargetProjectionRowV0(
            self.stable_id,
            self.role,
            self.profile_ids,
            self.group_ids,
            self.relation_ids,
            self._guidance_bytes,
        )
        target_id, _target = canonical_target_v0(self._target_bytes, None)
        if target_id != projection.stable_id:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency packet target identity drift")
        object.__setattr__(self, "profile_ids", projection.profile_ids)
        object.__setattr__(self, "group_ids", projection.group_ids)
        object.__setattr__(self, "relation_ids", projection.relation_ids)
        object.__setattr__(self, "_guidance_bytes", projection._guidance_bytes)

    @property
    def target_locale(self) -> str:
        envelope = parse_canonical_json(self._target_bytes)
        return envelope["data"]["identity"]["locale"]

    @property
    def target_sha256(self) -> str:
        return raw_sha256(self._target_bytes)

    def as_dict(self) -> dict[str, Any]:
        return {
            "stable_id": self.stable_id,
            "role": self.role,
            "profile_ids": list(self.profile_ids),
            "group_ids": list(self.group_ids),
            "relation_ids": list(self.relation_ids),
            "guidance": [strict_loads(payload) for payload in self._guidance_bytes],
            "target_sha256": self.target_sha256,
            "target": parse_canonical_json(self._target_bytes),
        }


@dataclass(frozen=True)
class FluencyReviewPacketV0:
    target_locale: str
    candidate_sha256: str
    projection_sha256: str
    requested_ids: tuple[str, ...]
    rows: tuple[FluencyReviewPacketRowV0, ...]

    def __post_init__(self) -> None:
        _nonempty(self.target_locale, "Fluency packet locale")
        _sha(self.candidate_sha256, "Fluency packet candidate SHA")
        _sha(self.projection_sha256, "Fluency packet projection SHA")
        requested = _sorted_ids(self.requested_ids, "Fluency packet requested IDs", allow_empty=False)
        rows = tuple(self.rows)
        keys = tuple(row.stable_id for row in rows)
        if not rows or keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency packet rows must be unique and sorted")
        review_ids = tuple(row.stable_id for row in rows if row.role == "REVIEW")
        if requested != review_ids:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency packet coverage differs from requested IDs")
        if any(row.target_locale != self.target_locale for row in rows):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency packet target locale drift")
        object.__setattr__(self, "requested_ids", requested)
        object.__setattr__(self, "rows", rows)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.fluency.review-packet/v0",
            "target_locale": self.target_locale,
            "candidate_sha256": self.candidate_sha256,
            "projection_sha256": self.projection_sha256,
            "requested_ids": list(self.requested_ids),
            "rows": [row.as_dict() for row in self.rows],
        }

    @property
    def digest(self) -> str:
        return semantic_sha256(self.as_dict())


@dataclass(frozen=True)
class FluencyReviewJobV0:
    job_id: str
    invocation_id: str
    plan_sha256: str
    packet_sha256: str
    module: ModuleDescriptorV0
    provider: ProviderBindingV0
    role_contract_sha256: str
    output_contract_sha256: str
    budget: ProviderBudgetV0
    attempt: int = 1
    max_invocations: int = 1

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "Fluency job ID")
        _nonempty(self.invocation_id, "Fluency invocation ID")
        _sha(self.plan_sha256, "Fluency plan SHA")
        _sha(self.packet_sha256, "Fluency packet SHA")
        _sha(self.role_contract_sha256, "Fluency role contract SHA")
        _sha(self.output_contract_sha256, "Fluency output contract SHA")
        if not isinstance(self.module, ModuleDescriptorV0) or not isinstance(self.provider, ProviderBindingV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency job bindings are invalid")
        if self.provider.role != "fluency_editor" or not isinstance(self.budget, ProviderBudgetV0):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency job provider or budget is invalid")
        if self.attempt != 1 or self.max_invocations != 1:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency v0 allows exactly one invocation")

    def identity_projection(self) -> dict[str, Any]:
        return {
            "plan_sha256": self.plan_sha256,
            "packet_sha256": self.packet_sha256,
            "module": {
                "capability": self.module.capability.value,
                "module_id": self.module.module_id,
                "version": self.module.version,
                "digest": self.module.digest,
            },
            "provider": self.provider.as_dict(),
            "role_contract_sha256": self.role_contract_sha256,
            "output_contract_sha256": self.output_contract_sha256,
            "budget": self.budget.as_dict(),
            "attempt": self.attempt,
            "max_invocations": self.max_invocations,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.fluency.review-job/v0",
            "job_id": self.job_id,
            "invocation_id": self.invocation_id,
            **self.identity_projection(),
        }


def candidate_raw_sha(candidate: object) -> str:
    return raw_sha256(canonical_json_bytes(candidate.as_dict()))
