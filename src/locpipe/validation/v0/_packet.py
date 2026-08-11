from __future__ import annotations

from collections.abc import Mapping
import posixpath
from typing import Any

from locpipe.content.v0 import FrozenScopeV0
from locpipe.contracts.v0 import (
    BranchIdentity,
    Capability,
    ContractViolation,
    ErrorCode,
    ModuleDescriptorV0,
    canonical_json_bytes,
    canonical_value_bytes,
    display_id,
    parse_canonical_json,
    parse_canonical_jsonl,
    raw_sha256,
    semantic_sha256,
    strict_loads,
    validate_envelope,
)
from locpipe.editorial.v0 import (
    CorrectionEntryV0,
    CorrectionOverlayV0,
    EditorialActionV0,
    EditorialCandidateSetV0,
    EditorialDecisionEntryV0,
    EditorialDecisionSetV0,
    EditorialJobStatusV0,
    EditorialJobV0,
    EditorialPacketV0,
    EditorialPolicyV0,
    apply_correction_overlay_v0,
    editorial_bindings_from_config_v0,
    editorial_job_root_v0,
    parse_editorial_candidate_v0,
)
from locpipe.editorial.v0._packet import _validate_translation_authority
from locpipe.editorial.v0._serialization import parse_editorial_state_v0
from locpipe.kernel.v0.config import ResolvedConfigV0, validate_context_config_binding
from locpipe.kernel.v0.context import ProjectContextV0
from locpipe.translation.v0 import TranslationJobV0, TranslationPacketV0, TranslationTargetSetV0, translation_job_root_v0

from ._models import (
    ContentValidationJobV0,
    ContentValidationPacketRowV0,
    ContentValidationPacketV0,
    ContentValidatorV0,
)


def content_validation_binding_from_config_v0(resolved: ResolvedConfigV0) -> ModuleDescriptorV0:
    raw = resolved.get_value("module_bindings")
    rows = [row for row in raw if isinstance(row, Mapping) and row.get("capability") == Capability.CONTENT_VALIDATION.value]
    if len(rows) != 1:
        raise ContractViolation(ErrorCode.CAPABILITY_MISSING, "Content validation module binding is missing or ambiguous")
    row = rows[0]
    if set(row) != {"capability", "module_id", "version", "digest"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Content validation module binding fields are invalid")
    return ModuleDescriptorV0(Capability.CONTENT_VALIDATION, row["module_id"], row["version"], row["digest"])


def _artifact_projection(rows: tuple[tuple[str, bytes], ...]) -> list[dict[str, str]]:
    paths = tuple(path for path, _payload in rows)
    if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Validation authority paths must be unique and sorted")
    return [{"path": path, "sha256": raw_sha256(payload)} for path, payload in rows]


def _target_key(payload: bytes) -> tuple[tuple[str, ...], tuple[Any, ...]]:
    value = parse_canonical_json(payload)
    validate_envelope(value)
    if value.get("kind") != "target_branch":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation candidate contains a non-target envelope")
    identity = BranchIdentity.from_dict(value["data"]["identity"])
    return identity.logical_id, identity.selector_path


def _validate_candidate_authority(
    candidate: EditorialCandidateSetV0,
    evidence: tuple[tuple[str, bytes], ...],
    editorial_job: EditorialJobV0 | None,
    editorial_packet: EditorialPacketV0 | None,
    editorial_policy: EditorialPolicyV0 | None,
) -> tuple[str, int, int, bool]:
    artifacts = dict(evidence)
    projection_sha = semantic_sha256(_artifact_projection(evidence))
    candidate_bytes = canonical_json_bytes(candidate.as_dict())
    candidate_paths = [path for path, payload in evidence if path.endswith("candidate_set.json") and payload == candidate_bytes]
    if len(candidate_paths) != 1 or not candidate.ready:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation candidate authority is missing or not ready")
    if candidate.disposition == EditorialJobStatusV0.ACCEPTED.value:
        if editorial_job is None or editorial_packet is None or editorial_policy is None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Accepted candidate requires complete editorial authority")
        root = editorial_job_root_v0(editorial_job)
        required = {posixpath.join(root, name) for name in (
            "job.json", "packet.json", "policy.json", "parent_candidate.json", "candidate_set.json",
            "decision_set.json", "overlay.json", "rework_request.json", "state.json",
        )}
        trigger_paths = [path for path in artifacts if path.rsplit("/", 1)[-1] == "editorial-trigger.json"]
        if set(artifacts) != required | set(trigger_paths) or len(trigger_paths) > 1:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Accepted candidate evidence shape is invalid")
        if artifacts[posixpath.join(root, "job.json")] != canonical_json_bytes(editorial_job.as_dict()):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial job evidence drift")
        if artifacts[posixpath.join(root, "packet.json")] != canonical_json_bytes(editorial_packet.as_dict()):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial packet evidence drift")
        if artifacts[posixpath.join(root, "policy.json")] != canonical_json_bytes(editorial_policy.as_dict()):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial policy evidence drift")
        parent_bytes = artifacts[posixpath.join(root, "parent_candidate.json")]
        parent = parse_editorial_candidate_v0(parent_bytes)
        if raw_sha256(parent_bytes) != editorial_job.parent_candidate_sha256:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial parent candidate evidence drift")
        state = parse_editorial_state_v0(artifacts[posixpath.join(root, "state.json")])
        decision_path = posixpath.join(root, "decision_set.json")
        overlay_path = posixpath.join(root, "overlay.json")
        rework_path = posixpath.join(root, "rework_request.json")
        decision = parse_canonical_json(artifacts[decision_path])
        overlay = parse_canonical_json(artifacts[overlay_path])
        rework = parse_canonical_json(artifacts[rework_path])
        try:
            decision_model = EditorialDecisionSetV0(
                decision["job_id"], decision["submission_sha256"],
                EditorialJobStatusV0(decision["status"]), decision["reason_code"],
                tuple(EditorialDecisionEntryV0(
                    BranchIdentity.from_dict(row["identity"]), EditorialActionV0(row["action"]),
                    row["reason_code"], row["replacement_sha256"],
                ) for row in decision["decisions"]),
            )
            overlay_model = CorrectionOverlayV0(
                overlay["job_id"], overlay["decision_set_sha256"], overlay["parent_candidate_sha256"],
                tuple(CorrectionEntryV0(
                    BranchIdentity.from_dict(row["source_identity"]), row["preimage_target_sha256"],
                    canonical_json_bytes(row["replacement"]),
                ) for row in overlay["entries"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial decision/overlay evidence is malformed") from error
        corrected = {
            row.stable_id: row.replacement_sha256 for row in decision_model.decisions
            if row.action is EditorialActionV0.CORRECT
        }
        overlay_replacements = {row.stable_id: raw_sha256(row._replacement_bytes) for row in overlay_model.entries}
        if (
            canonical_json_bytes(decision_model.as_dict()) != artifacts[decision_path]
            or canonical_json_bytes(overlay_model.as_dict()) != artifacts[overlay_path]
            or tuple(row.stable_id for row in decision_model.decisions) != editorial_packet.requested_ids
            or corrected != overlay_replacements
        ):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial decision/overlay semantic drift")
        rebuilt_candidate = apply_correction_overlay_v0(
            parent, overlay_model, job_id=editorial_job.job_id, ready=True,
            disposition=EditorialJobStatusV0.ACCEPTED.value, unresolved_ids=(),
        )
        if rebuilt_candidate != candidate:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial candidate does not equal parent plus overlay")
        if trigger_paths:
            trigger_bytes = artifacts[trigger_paths[0]]
            trigger = parse_canonical_json(trigger_bytes)
            if (
                editorial_job.round_index == 0
                or raw_sha256(trigger_bytes) != editorial_job.parent_decision_sha256
                or trigger.get("contract") != "locpipe.validation.editorial-trigger/v0"
                or trigger.get("next_round") != editorial_job.round_index
                or tuple(trigger.get("requested_ids", ())) != editorial_packet.requested_ids
                or trigger.get("parent_candidate_sha256") != candidate.parent_candidate_sha256
            ):
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation-origin editorial trigger drift")
        if (
            state.status is not EditorialJobStatusV0.ACCEPTED
            or state.job_id != editorial_job.job_id
            or state.candidate_sha256 != raw_sha256(candidate_bytes)
            or state.decision_set_sha256 != raw_sha256(artifacts[decision_path])
            or state.overlay_sha256 != raw_sha256(artifacts[overlay_path])
            or state.rework_request_sha256 != raw_sha256(artifacts[rework_path])
            or decision.get("job_id") != editorial_job.job_id
            or decision.get("status") != EditorialJobStatusV0.ACCEPTED.value
            or overlay.get("job_id") != editorial_job.job_id
            or overlay.get("decision_set_sha256") != state.decision_set_sha256
            or rework.get("job_id") != editorial_job.job_id
            or rework.get("status", rework.get("disposition")) != EditorialJobStatusV0.ACCEPTED.value
            or rework.get("candidate_sha256") != state.candidate_sha256
            or rework.get("requested_ids") != []
            or editorial_job.round_index > editorial_policy.max_rework_rounds
        ):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Accepted editorial terminal evidence drift")
        return projection_sha, editorial_job.round_index, editorial_policy.max_rework_rounds, True
    if candidate.disposition == "BYPASSED_BY_CONFIG":
        if any(value is not None for value in (editorial_job, editorial_packet, editorial_policy)):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Bypass candidate cannot carry editorial job authority")
        if len(artifacts) != 2:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Bypass candidate evidence shape is invalid")
        disposition_paths = [path for path in artifacts if path.endswith("disposition.json")]
        if len(disposition_paths) != 1:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Bypass disposition evidence is missing")
        disposition = parse_canonical_json(artifacts[disposition_paths[0]])
        if (
            disposition.get("contract") != "locpipe.editorial.bypass/v0"
            or disposition.get("candidate_sha256") != raw_sha256(candidate_bytes)
            or disposition.get("disposition") != "BYPASSED_BY_CONFIG"
        ):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Bypass disposition evidence drift")
        return projection_sha, 0, 0, False
    raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Candidate disposition is not validatable")


def _validate_relations(packet: TranslationPacketV0) -> None:
    branch_ids = {row.stable_id for row in packet.rows}
    logical_ids = {row.identity.logical_id for row in packet.rows}
    for payload in packet._relation_bytes:
        relation = parse_canonical_json(payload)
        validate_envelope(relation)
        if relation.get("kind") != "relation":
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation relation kind is invalid")
        for name in ("from_ref", "to_ref"):
            reference = relation["data"][name]
            if reference["kind"] == "branch":
                if display_id(BranchIdentity.from_dict(reference["identity"])) not in branch_ids:
                    raise ContractViolation(ErrorCode.DANGLING_RELATION, "Validation relation branch is outside packet")
            elif reference["kind"] == "logical_message":
                if tuple(reference["logical_id"]) not in logical_ids:
                    raise ContractViolation(ErrorCode.DANGLING_RELATION, "Validation relation logical message is outside packet")


def build_content_validation_job_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    scope: FrozenScopeV0,
    translation_job: TranslationJobV0,
    translation_packet: TranslationPacketV0,
    translation_decision_bytes: bytes,
    translation_state_bytes: bytes,
    target_set: TranslationTargetSetV0,
    candidate: EditorialCandidateSetV0,
    validator: ContentValidatorV0,
    *,
    source_lock_bytes: bytes,
    reconciliation_bytes: bytes,
    scope_bytes: bytes,
    scope_lock_bytes: bytes,
    segments_bytes: bytes,
    candidate_evidence: tuple[tuple[str, bytes], ...],
    editorial_job: EditorialJobV0 | None = None,
    editorial_packet: EditorialPacketV0 | None = None,
    editorial_policy: EditorialPolicyV0 | None = None,
) -> tuple[ContentValidationJobV0, ContentValidationPacketV0, tuple[tuple[str, bytes], ...]]:
    validate_context_config_binding(context, resolved)
    if context.context_digest != translation_job.context_digest or context.config_snapshot_sha256 != resolved.config_snapshot_sha256:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation context differs from translation authority")
    module = content_validation_binding_from_config_v0(resolved)
    if validator.descriptor != module or validator.descriptor.capability is not Capability.CONTENT_VALIDATION:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validator descriptor differs from config binding")
    if not isinstance(validator.rule_contract_sha256, str) or len(validator.rule_contract_sha256) != 64:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validator rule contract SHA is invalid")
    if tuple(sorted(set(validator.supported_content_types))) != validator.supported_content_types:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validator content types must be unique and sorted")
    if tuple(sorted(set(validator.supported_constraint_keys))) != validator.supported_constraint_keys:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validator constraint keys must be unique and sorted")
    _validate_translation_authority(
        translation_job, translation_packet, translation_decision_bytes, target_set, translation_state_bytes,
    )
    if (
        raw_sha256(scope_bytes) != translation_job.scope_sha256
        or raw_sha256(source_lock_bytes) != translation_job.source_lock_sha256
        or raw_sha256(reconciliation_bytes) != translation_job.reconciliation_sha256
        or canonical_json_bytes(scope.scope_dict()) != scope_bytes
        or context.config_snapshot_sha256 != scope.config_snapshot_sha256
        or translation_job.target_locale not in scope.target_locales
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation source/scope authority drift")
    scope_lock = parse_canonical_json(scope_lock_bytes)
    if scope_lock.get("scope_sha256") != raw_sha256(scope_bytes):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation scope lock drift")
    source_lock = parse_canonical_json(source_lock_bytes)
    if source_lock.get("segments_sha256") != raw_sha256(segments_bytes):
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Validation segments differ from source lock")
    source_rows = parse_canonical_jsonl(
        segments_bytes,
        sort_key=lambda row: display_id(BranchIdentity.from_dict(row["data"]["identity"])),
    )
    current_revisions = {
        display_id(BranchIdentity.from_dict(row["data"]["identity"])): row["data"]["source_revision_sha"]
        for row in source_rows
    }
    candidate_authority_sha, round_index, max_rounds, editorial_available = _validate_candidate_authority(
        candidate, candidate_evidence, editorial_job, editorial_packet, editorial_policy,
    )
    if editorial_available != (editorial_bindings_from_config_v0(resolved) is not None):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation editorial availability differs from config")
    if candidate.base_target_set_sha256 != raw_sha256(canonical_json_bytes(target_set.as_dict())):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation candidate base target set drift")
    targets = {_target_key(payload): payload for payload in candidate._target_bytes}
    if len(targets) != len(candidate._target_bytes):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Validation candidate target collision")
    packet_rows = []
    owned_scope = {
        (entry.identity.logical_id, entry.identity.selector_path)
        for entry in scope.entries if entry.role.value == "OWNED"
    }
    context_scope = {
        (entry.identity.logical_id, entry.identity.selector_path)
        for entry in scope.entries if entry.role.value == "CONTEXT"
    }
    if set(targets) != owned_scope:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation candidate does not exactly cover owned scope")
    packet_by_key = {(row.identity.logical_id, row.identity.selector_path): row for row in translation_packet.rows}
    if set(packet_by_key) != owned_scope | context_scope:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation translation packet differs from frozen scope")
    for key, source in packet_by_key.items():
        if current_revisions.get(source.stable_id) != source.source_revision_sha:
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "Validation source dependency is stale or removed")
        constraints = strict_loads(source._constraints_bytes)
        if source.content_type not in validator.supported_content_types:
            raise ContractViolation(ErrorCode.CAPABILITY_MISSING, "Validator does not support packet content type")
        if not set(constraints).issubset(set(validator.supported_constraint_keys)):
            raise ContractViolation(ErrorCode.CAPABILITY_MISSING, "Validator does not support packet constraints")
        target = targets.get(key)
        if target is not None:
            value = parse_canonical_json(target)
            identity = BranchIdentity.from_dict(value["data"]["identity"])
            if (
                identity.locale != translation_job.target_locale
                or value["data"]["source_logical_id"] != list(source.identity.logical_id)
                or value["data"]["content_type"] != source.content_type
            ):
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation target identity/content drift")
        packet_rows.append(ContentValidationPacketRowV0(
            source.identity,
            source.role.value,
            source.source_revision_sha,
            source.content_type,
            source._payload_bytes,
            target,
            source._constraints_bytes,
        ))
    _validate_relations(translation_packet)
    packet = ContentValidationPacketV0(
        translation_job.target_locale,
        tuple(sorted(packet_rows, key=lambda row: row.stable_id)),
        tuple(sorted(translation_packet._relation_bytes)),
    )
    translation_root = translation_job_root_v0(translation_job)
    authority = tuple(sorted((
        ("corpus/segments.jsonl", bytes(segments_bytes)),
        ("reconciliation/reconciliation.json", bytes(reconciliation_bytes)),
        ("scope/scope.json", bytes(scope_bytes)),
        ("scope/scope_lock.json", bytes(scope_lock_bytes)),
        ("source/source_lock.json", bytes(source_lock_bytes)),
        (posixpath.join(translation_root, "decision.json"), bytes(translation_decision_bytes)),
        (posixpath.join(translation_root, "job.json"), canonical_json_bytes(translation_job.as_dict())),
        (posixpath.join(translation_root, "packet.json"), canonical_json_bytes(translation_packet.as_dict())),
        (posixpath.join(translation_root, "state.json"), bytes(translation_state_bytes)),
        (posixpath.join(translation_root, "target_set.json"), canonical_json_bytes(target_set.as_dict())),
        *candidate_evidence,
    )))
    authority_sha = semantic_sha256(_artifact_projection(authority))
    packet_sha = raw_sha256(canonical_json_bytes(packet.as_dict()))
    identity = {
        "context_digest": context.context_digest,
        "config_snapshot_sha256": resolved.config_snapshot_sha256,
        "content_config_digest": resolved.content_config_digest,
        "scope_sha256": translation_job.scope_sha256,
        "source_lock_sha256": translation_job.source_lock_sha256,
        "reconciliation_sha256": translation_job.reconciliation_sha256,
        "candidate_sha256": raw_sha256(canonical_json_bytes(candidate.as_dict())),
        "candidate_authority_sha256": candidate_authority_sha,
        "target_locale": translation_job.target_locale,
        "validator": {"module_id": module.module_id, "version": module.version, "digest": module.digest},
        "rule_contract_sha256": validator.rule_contract_sha256,
        "packet_sha256": packet_sha,
        "authority_sha256": authority_sha,
        "editorial_available": editorial_available,
        "editorial_round_index": round_index,
        "max_rework_rounds": max_rounds,
    }
    job_id = "validation-" + semantic_sha256({"kind": "content-validation-job", **identity})[:32]
    job = ContentValidationJobV0(
        job_id,
        context.context_digest,
        resolved.config_snapshot_sha256,
        resolved.content_config_digest,
        translation_job.scope_sha256,
        translation_job.source_lock_sha256,
        translation_job.reconciliation_sha256,
        identity["candidate_sha256"],
        candidate_authority_sha,
        translation_job.target_locale,
        module,
        validator.rule_contract_sha256,
        packet_sha,
        authority_sha,
        editorial_available,
        round_index,
        max_rounds,
    )
    return job, packet, authority


def validation_job_root_v0(job: ContentValidationJobV0) -> str:
    return f"validation/j/{job.job_id.removeprefix('validation-')[:20]}"
