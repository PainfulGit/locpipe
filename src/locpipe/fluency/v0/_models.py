from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import unicodedata

from locpipe.contracts.v0 import (
    BranchIdentity,
    Capability,
    ContractViolation,
    ErrorCode,
    ModuleDescriptorV0,
    canonical_json_bytes,
    display_id,
    normalized_text,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
    strict_loads,
)
from locpipe.contracts.v0.profiles import SHA256_RE
from locpipe.translation.v0 import ProviderBindingV0, ProviderBudgetV0

from ._serialization import canonical_guidance_block_v0, canonical_target_v0


FLUENCY_ROLES = frozenset({"CONTEXT", "REVIEW"})
MAX_DIAGNOSTIC_NOTE_CODEPOINTS = 1024


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


class FluencyFindingCategoryV0(str, Enum):
    GRAMMAR = "GRAMMAR"
    READABILITY = "READABILITY"
    STYLE = "STYLE"
    VOICE = "VOICE"
    CONSISTENCY = "CONSISTENCY"
    TERMINOLOGY = "TERMINOLOGY"
    TYPOGRAPHY = "TYPOGRAPHY"
    TARGET_LOCALE_CONVENTION = "TARGET_LOCALE_CONVENTION"


class FluencyReviewOutcomeV0(str, Enum):
    NO_FINDINGS = "NO_FINDINGS"
    FINDINGS = "FINDINGS"


class FluencyDecisionStatusV0(str, Enum):
    FLUENCY_VERIFIED = "FLUENCY_VERIFIED"
    CORRECTION_REQUIRED = "CORRECTION_REQUIRED"


def _diagnostic_note(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_DIAGNOSTIC_NOTE_CODEPOINTS:
        raise ContractViolation(
            ErrorCode.MALFORMED_ARTIFACT,
            f"Fluency diagnostic note must contain 1..{MAX_DIAGNOSTIC_NOTE_CODEPOINTS} Unicode code points",
        )
    if normalized_text(value) != value:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency diagnostic note must be NFC-normalized")
    if value.strip() != value:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency diagnostic note has edge whitespace")
    if len(value.splitlines()) != 1 or any(unicodedata.category(character) == "Cc" for character in value):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency diagnostic note must be one control-free line")
    return value


@dataclass(frozen=True)
class FluencyFindingV0:
    category: FluencyFindingCategoryV0
    diagnostic_note: str

    def __post_init__(self) -> None:
        if not isinstance(self.category, FluencyFindingCategoryV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency finding category is invalid")
        _diagnostic_note(self.diagnostic_note)

    @property
    def identity(self) -> tuple[str, str]:
        return self.category.value, self.diagnostic_note

    def as_dict(self) -> dict[str, str]:
        return {"category": self.category.value, "diagnostic_note": self.diagnostic_note}


@dataclass(frozen=True)
class FluencyDecisionEntryV0:
    stable_id: str
    outcome: FluencyReviewOutcomeV0
    findings: tuple[FluencyFindingV0, ...] = ()

    def __post_init__(self) -> None:
        _nonempty(self.stable_id, "Fluency decision stable ID")
        if not isinstance(self.outcome, FluencyReviewOutcomeV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency review outcome is invalid")
        rows = tuple(self.findings)
        if any(not isinstance(row, FluencyFindingV0) for row in rows):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency findings are invalid")
        identities = tuple(row.identity for row in rows)
        if identities != tuple(sorted(identities)) or len(identities) != len(set(identities)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency findings must be unique and sorted")
        if (self.outcome is FluencyReviewOutcomeV0.NO_FINDINGS) != (not rows):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency outcome disagrees with findings")
        object.__setattr__(self, "findings", rows)

    def as_dict(self) -> dict[str, Any]:
        return {
            "stable_id": self.stable_id,
            "outcome": self.outcome.value,
            "findings": [row.as_dict() for row in self.findings],
        }


@dataclass(frozen=True)
class FluencySubmissionReceiptV0:
    job_id: str
    invocation_id: str
    provider: ProviderBindingV0
    provider_request_id: str
    plan_sha256: str
    packet_sha256: str
    role_contract_sha256: str
    output_contract_sha256: str
    raw_output_sha256: str

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "Fluency receipt job ID")
        _nonempty(self.invocation_id, "Fluency receipt invocation ID")
        if not isinstance(self.provider, ProviderBindingV0) or self.provider.role != "fluency_editor":
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency receipt provider is invalid")
        _nonempty(self.provider_request_id, "Fluency provider request ID")
        for value, name in (
            (self.plan_sha256, "Fluency receipt plan SHA"),
            (self.packet_sha256, "Fluency receipt packet SHA"),
            (self.role_contract_sha256, "Fluency receipt role contract SHA"),
            (self.output_contract_sha256, "Fluency receipt output contract SHA"),
            (self.raw_output_sha256, "Fluency receipt raw output SHA"),
        ):
            _sha(value, name)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.fluency.submission-receipt/v0",
            "job_id": self.job_id,
            "invocation_id": self.invocation_id,
            "provider": self.provider.as_dict(),
            "provider_request_id": self.provider_request_id,
            "plan_sha256": self.plan_sha256,
            "packet_sha256": self.packet_sha256,
            "role_contract_sha256": self.role_contract_sha256,
            "output_contract_sha256": self.output_contract_sha256,
            "raw_output_sha256": self.raw_output_sha256,
        }


@dataclass(frozen=True)
class FluencyDecisionV0:
    job_id: str
    invocation_id: str
    plan_sha256: str
    packet_sha256: str
    candidate_sha256: str
    content_config_digest: str
    provider_config_digest: str
    raw_output_sha256: str
    submission_sha256: str
    status: FluencyDecisionStatusV0
    entries: tuple[FluencyDecisionEntryV0, ...]
    correction_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "Fluency decision job ID")
        _nonempty(self.invocation_id, "Fluency decision invocation ID")
        for value, name in (
            (self.plan_sha256, "Fluency decision plan SHA"),
            (self.packet_sha256, "Fluency decision packet SHA"),
            (self.candidate_sha256, "Fluency decision candidate SHA"),
            (self.content_config_digest, "Fluency decision content config digest"),
            (self.provider_config_digest, "Fluency decision provider config digest"),
            (self.raw_output_sha256, "Fluency decision raw output SHA"),
            (self.submission_sha256, "Fluency decision submission SHA"),
        ):
            _sha(value, name)
        if not isinstance(self.status, FluencyDecisionStatusV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency decision status is invalid")
        entries = tuple(self.entries)
        keys = tuple(row.stable_id for row in entries)
        if not entries or any(not isinstance(row, FluencyDecisionEntryV0) for row in entries):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency decision entries are invalid")
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency decision entries must be unique and sorted")
        correction_ids = _sorted_ids(self.correction_ids, "Fluency correction IDs")
        expected_corrections = tuple(row.stable_id for row in entries if row.findings)
        if correction_ids != expected_corrections:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction IDs drift")
        expected_status = (
            FluencyDecisionStatusV0.CORRECTION_REQUIRED
            if correction_ids
            else FluencyDecisionStatusV0.FLUENCY_VERIFIED
        )
        if self.status is not expected_status:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency decision status drift")
        object.__setattr__(self, "entries", entries)
        object.__setattr__(self, "correction_ids", correction_ids)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.fluency.decision/v0",
            "job_id": self.job_id,
            "invocation_id": self.invocation_id,
            "plan_sha256": self.plan_sha256,
            "packet_sha256": self.packet_sha256,
            "candidate_sha256": self.candidate_sha256,
            "content_config_digest": self.content_config_digest,
            "provider_config_digest": self.provider_config_digest,
            "raw_output_sha256": self.raw_output_sha256,
            "submission_sha256": self.submission_sha256,
            "status": self.status.value,
            "entries": [row.as_dict() for row in self.entries],
            "correction_ids": list(self.correction_ids),
        }

    @property
    def digest(self) -> str:
        return raw_sha256(canonical_json_bytes(self.as_dict()))


@dataclass(frozen=True)
class FluencyStateV0:
    job_id: str
    invocation_id: str
    plan_sha256: str
    packet_sha256: str
    candidate_sha256: str
    content_config_digest: str
    provider_config_digest: str
    raw_output_sha256: str
    selected_submission_sha256: str
    decision_sha256: str
    status: FluencyDecisionStatusV0

    def __post_init__(self) -> None:
        _nonempty(self.job_id, "Fluency state job ID")
        _nonempty(self.invocation_id, "Fluency state invocation ID")
        for value, name in (
            (self.plan_sha256, "Fluency state plan SHA"),
            (self.packet_sha256, "Fluency state packet SHA"),
            (self.candidate_sha256, "Fluency state candidate SHA"),
            (self.content_config_digest, "Fluency state content config digest"),
            (self.provider_config_digest, "Fluency state provider config digest"),
            (self.raw_output_sha256, "Fluency state raw output SHA"),
            (self.selected_submission_sha256, "Fluency state submission SHA"),
            (self.decision_sha256, "Fluency state decision SHA"),
        ):
            _sha(value, name)
        if not isinstance(self.status, FluencyDecisionStatusV0):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency state status is invalid")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.fluency.state/v0",
            "job_id": self.job_id,
            "invocation_id": self.invocation_id,
            "plan_sha256": self.plan_sha256,
            "packet_sha256": self.packet_sha256,
            "candidate_sha256": self.candidate_sha256,
            "content_config_digest": self.content_config_digest,
            "provider_config_digest": self.provider_config_digest,
            "raw_output_sha256": self.raw_output_sha256,
            "selected_submission_sha256": self.selected_submission_sha256,
            "decision_sha256": self.decision_sha256,
            "status": self.status.value,
        }


@dataclass(frozen=True)
class FluencyCorrectionTriggerEntryV0:
    target_stable_id: str
    target_sha256: str
    source_identity: BranchIdentity
    source_revision_sha256: str
    content_type: str
    findings: tuple[FluencyFindingV0, ...]

    def __post_init__(self) -> None:
        _nonempty(self.target_stable_id, "Fluency correction target stable ID")
        _sha(self.target_sha256, "Fluency correction target SHA")
        if not isinstance(self.source_identity, BranchIdentity):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction source identity is invalid")
        _sha(self.source_revision_sha256, "Fluency correction source revision SHA")
        _nonempty(self.content_type, "Fluency correction content type")
        findings = tuple(self.findings)
        if not findings or any(not isinstance(row, FluencyFindingV0) for row in findings):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction findings are invalid")
        identities = tuple(row.identity for row in findings)
        if identities != tuple(sorted(identities)) or len(identities) != len(set(identities)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency correction findings must be unique and sorted")
        object.__setattr__(self, "findings", findings)

    @property
    def source_stable_id(self) -> str:
        return display_id(self.source_identity)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_stable_id": self.target_stable_id,
            "target_sha256": self.target_sha256,
            "source_identity": self.source_identity.as_dict(),
            "source_revision_sha256": self.source_revision_sha256,
            "content_type": self.content_type,
            "findings": [row.as_dict() for row in self.findings],
        }


@dataclass(frozen=True)
class FluencyCorrectionTriggerV0:
    plan_sha256: str
    fluency_job_sha256: str
    fluency_packet_sha256: str
    candidate_sha256: str
    candidate_authority_sha256: str
    content_config_digest: str
    effective_snapshot_sha256: str
    accuracy_provider_config_digest: str
    fluency_provider_config_digest: str
    raw_output_sha256: str
    submission_sha256: str
    decision_sha256: str
    state_sha256: str
    current_fluency_round: int
    max_fluency_correction_rounds: int
    parent_editorial_round: int
    next_editorial_round: int
    editorial_policy_sha256: str
    entries: tuple[FluencyCorrectionTriggerEntryV0, ...]

    def __post_init__(self) -> None:
        for value, name in (
            (self.plan_sha256, "Fluency correction plan SHA"),
            (self.fluency_job_sha256, "Fluency correction job SHA"),
            (self.fluency_packet_sha256, "Fluency correction packet SHA"),
            (self.candidate_sha256, "Fluency correction candidate SHA"),
            (self.candidate_authority_sha256, "Fluency correction candidate authority SHA"),
            (self.content_config_digest, "Fluency correction config digest"),
            (self.effective_snapshot_sha256, "Fluency correction snapshot SHA"),
            (self.accuracy_provider_config_digest, "Fluency correction accuracy provider digest"),
            (self.fluency_provider_config_digest, "Fluency correction reviewer provider digest"),
            (self.raw_output_sha256, "Fluency correction raw output SHA"),
            (self.submission_sha256, "Fluency correction submission SHA"),
            (self.decision_sha256, "Fluency correction decision SHA"),
            (self.state_sha256, "Fluency correction state SHA"),
            (self.editorial_policy_sha256, "Fluency correction policy SHA"),
        ):
            _sha(value, name)
        values = (
            self.current_fluency_round,
            self.max_fluency_correction_rounds,
            self.parent_editorial_round,
            self.next_editorial_round,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Fluency correction rounds are invalid")
        if (
            not 0 <= self.current_fluency_round < self.max_fluency_correction_rounds <= 2
            or self.parent_editorial_round < 0
            or self.next_editorial_round != self.parent_editorial_round + 1
        ):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Fluency correction round bindings drift")
        entries = tuple(self.entries)
        keys = tuple(row.target_stable_id for row in entries)
        if (
            not entries
            or any(not isinstance(row, FluencyCorrectionTriggerEntryV0) for row in entries)
            or keys != tuple(sorted(keys))
            or len(keys) != len(set(keys))
        ):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency correction entries must be non-empty, unique and sorted")
        source_ids = tuple(row.source_stable_id for row in entries)
        if len(source_ids) != len(set(source_ids)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Fluency correction source mapping is ambiguous")
        object.__setattr__(self, "entries", entries)

    @property
    def affected_target_ids(self) -> tuple[str, ...]:
        return tuple(row.target_stable_id for row in self.entries)

    @property
    def requested_source_ids(self) -> tuple[str, ...]:
        return tuple(sorted(row.source_stable_id for row in self.entries))

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": "locpipe.fluency.correction-trigger/v0",
            "plan_sha256": self.plan_sha256,
            "fluency_job_sha256": self.fluency_job_sha256,
            "fluency_packet_sha256": self.fluency_packet_sha256,
            "candidate_sha256": self.candidate_sha256,
            "candidate_authority_sha256": self.candidate_authority_sha256,
            "content_config_digest": self.content_config_digest,
            "effective_snapshot_sha256": self.effective_snapshot_sha256,
            "accuracy_provider_config_digest": self.accuracy_provider_config_digest,
            "fluency_provider_config_digest": self.fluency_provider_config_digest,
            "raw_output_sha256": self.raw_output_sha256,
            "submission_sha256": self.submission_sha256,
            "decision_sha256": self.decision_sha256,
            "state_sha256": self.state_sha256,
            "current_fluency_round": self.current_fluency_round,
            "max_fluency_correction_rounds": self.max_fluency_correction_rounds,
            "parent_editorial_round": self.parent_editorial_round,
            "next_editorial_round": self.next_editorial_round,
            "editorial_policy_sha256": self.editorial_policy_sha256,
            "entries": [row.as_dict() for row in self.entries],
        }

    @property
    def digest(self) -> str:
        return raw_sha256(canonical_json_bytes(self.as_dict()))


def candidate_raw_sha(candidate: object) -> str:
    return raw_sha256(canonical_json_bytes(candidate.as_dict()))
