from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any
import posixpath

from locpipe.contracts.v0 import (
    ArtifactDeclarationV0,
    BranchIdentity,
    Capability,
    ContractViolation,
    ErrorCode,
    ErrorRecord,
    ImplementationRefV0,
    KIND_TO_SCHEMA,
    ModuleDescriptorV0,
    OperationContextV0,
    OperationHandlerV0,
    OperationRequestV0,
    canonical_json_bytes,
    display_id,
    parse_canonical_json,
    raw_sha256,
    validate_envelope,
)
from locpipe.contracts.v0.constants import CONTRACT_VERSION
from locpipe.kernel.v0.config import ResolvedConfigV0
from locpipe.kernel.v0.context import ProjectContextV0
from locpipe.translation.v0 import TranslationJobV0, TranslationPacketV0, TranslationTargetSetV0, translation_job_root_v0

from ._evidence import (
    CorrectionEntryV0,
    CorrectionOverlayV0,
    EditorialDecisionEntryV0,
    EditorialDecisionSetV0,
    EditorialReworkRequestV0,
    EditorialStateV0,
    EditorialSubmissionReceiptV0,
)
from ._models import (
    EditorialActionV0,
    EditorialCandidateSetV0,
    EditorialJobStatusV0,
    EditorialJobV0,
    EditorialPacketV0,
    EditorialPolicyV0,
    candidate_raw_sha,
)
from ._overlay import apply_correction_overlay_v0
from ._packet import build_editorial_job_v0
from ._serialization import parse_editorial_state_v0, parse_editorial_submission_receipt_v0


class _DomainReject(Exception):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code


def editorial_job_root_v0(job: EditorialJobV0) -> str:
    return editorial_job_root_from_id_v0(job.job_id)


def editorial_job_root_from_id_v0(job_id: str) -> str:
    if not isinstance(job_id, str) or not job_id:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial job ID is invalid")
    return f"ed/j/{job_id.removeprefix('editorial-')[:20]}"


def editorial_submission_root_from_digest_v0(submission_sha256: str) -> str:
    if not isinstance(submission_sha256, str) or len(submission_sha256) != 64:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Editorial submission digest is invalid")
    return f"ed/s/{submission_sha256[:20]}"


def editorial_submission_digest_v0(receipt: EditorialSubmissionReceiptV0) -> str:
    return raw_sha256(canonical_json_bytes(receipt.as_dict()))


def editorial_submission_root_v0(receipt: EditorialSubmissionReceiptV0) -> str:
    return editorial_submission_root_from_digest_v0(editorial_submission_digest_v0(receipt))


def editorial_acceptance_output_declarations_v0(job: EditorialJobV0) -> tuple[ArtifactDeclarationV0, ...]:
    root = editorial_job_root_v0(job)
    return tuple(ArtifactDeclarationV0(posixpath.join(root, name), "raw") for name in (
        "candidate_set.json", "decision_set.json", "overlay.json", "rework_request.json", "state.json",
    ))


def _implementation(module: ModuleDescriptorV0) -> ImplementationRefV0:
    if not isinstance(module, ModuleDescriptorV0) or module.capability is not Capability.EDITORIAL_REVIEW:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial module has the wrong capability")
    return ImplementationRefV0("module", module.module_id, module.version, module.digest, Capability.EDITORIAL_REVIEW)


def _input_paths(
    job: EditorialJobV0,
    parent: EditorialCandidateSetV0,
    translation_job: TranslationJobV0,
    submission_sha: str,
) -> tuple[str, ...]:
    editorial_root = editorial_job_root_v0(job)
    translation_root = translation_job_root_v0(translation_job)
    paths = [
        posixpath.join(translation_root, name) for name in ("decision.json", "job.json", "packet.json", "state.json", "target_set.json")
    ] + [
        posixpath.join(editorial_root, name) for name in ("job.json", "packet.json", "parent_candidate.json", "policy.json", "selection.json", "state.json")
    ] + [
        posixpath.join(editorial_submission_root_from_digest_v0(submission_sha), name) for name in ("output.json", "receipt.json")
    ]
    if job.round_index > 0:
        parent_root = editorial_job_root_from_id_v0(parent.job_id)
        paths.extend(posixpath.join(parent_root, name) for name in (
            "candidate_set.json", "decision_set.json", "rework_request.json", "state.json",
        ))
    return tuple(sorted(paths))


def _current_target_by_source(packet: EditorialPacketV0, candidate: EditorialCandidateSetV0) -> dict[str, bytes]:
    targets = {}
    for payload in candidate._target_bytes:
        identity = BranchIdentity.from_dict(parse_canonical_json(payload)["data"]["identity"])
        targets[(identity.logical_id, identity.selector_path)] = payload
    result = {}
    for row in packet.rows:
        if row.role.value == "OWNED":
            payload = targets.get((row.identity.logical_id, row.identity.selector_path))
            if payload is None:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial candidate lacks owned target")
            result[row.stable_id] = payload
    return result


def _corrected_target(
    raw: object,
    row,
    current: bytes,
    job: EditorialJobV0,
) -> bytes:
    if not isinstance(raw, Mapping):
        raise _DomainReject("MALFORMED_CORRECTION")
    try:
        validate_envelope(raw)
        if raw.get("kind") != "target_branch":
            raise _DomainReject("MALFORMED_CORRECTION")
        data = raw["data"]
        identity = BranchIdentity.from_dict(data["identity"])
        if (
            identity.logical_id != row.identity.logical_id
            or identity.selector_path != row.identity.selector_path
            or identity.locale != job.target_locale
        ):
            raise _DomainReject("CORRECTION_IDENTITY_DRIFT")
        if data["source_logical_id"] != list(row.identity.logical_id) or data["content_type"] != row.content_type:
            raise _DomainReject("CORRECTION_CONTENT_TYPE_DRIFT")
        if data["metadata_ref"] is not None:
            raise _DomainReject("PROVIDER_METADATA_FORBIDDEN")
        selected = dict(raw)
        selected_data = dict(data)
        selected_data["metadata_ref"] = posixpath.join(editorial_job_root_v0(job), "overlay.json")
        selected["data"] = selected_data
        replacement = canonical_json_bytes(selected)
        if raw_sha256(replacement) == raw_sha256(current):
            raise _DomainReject("NOOP_CORRECTION")
        return replacement
    except _DomainReject:
        raise
    except (ContractViolation, KeyError, TypeError) as error:
        raise _DomainReject("MALFORMED_CORRECTION") from error


def _accepted_terminal(
    job: EditorialJobV0,
    packet: EditorialPacketV0,
    policy: EditorialPolicyV0,
    parent: EditorialCandidateSetV0,
    submission_sha: str,
    raw_output: bytes,
) -> tuple[EditorialDecisionSetV0, CorrectionOverlayV0, EditorialCandidateSetV0, EditorialReworkRequestV0, EditorialJobStatusV0]:
    try:
        value = parse_canonical_json(raw_output)
        if canonical_json_bytes(value) != raw_output or not isinstance(value, Mapping) or set(value) != {"contract", "decisions"}:
            raise _DomainReject("MALFORMED_EDITORIAL_OUTPUT")
        if value["contract"] != "locpipe.editorial.provider-output/v0" or not isinstance(value["decisions"], list):
            raise _DomainReject("MALFORMED_EDITORIAL_OUTPUT")
        rows_by_id = {row.stable_id: row for row in packet.rows if row.role.value == "OWNED"}
        current = _current_target_by_source(packet, parent)
        decisions = []
        corrections = []
        unresolved = []
        seen = []
        for raw_decision in value["decisions"]:
            if not isinstance(raw_decision, Mapping) or set(raw_decision) != {"identity", "action", "reason_code", "target"}:
                raise _DomainReject("MALFORMED_EDITORIAL_OUTPUT")
            identity = BranchIdentity.from_dict(raw_decision["identity"])
            key = display_id(identity)
            row = rows_by_id.get(key)
            if row is None or key not in packet.requested_ids:
                raise _DomainReject("DECISION_SCOPE_DRIFT")
            try:
                action = EditorialActionV0(raw_decision["action"])
            except (TypeError, ValueError) as error:
                raise _DomainReject("UNKNOWN_EDITORIAL_ACTION") from error
            reason = raw_decision["reason_code"]
            if not isinstance(reason, str) or not reason:
                raise _DomainReject("MALFORMED_EDITORIAL_OUTPUT")
            target = raw_decision["target"]
            replacement = None
            if action is EditorialActionV0.CORRECT:
                replacement = _corrected_target(target, row, current[key], job)
                corrections.append(CorrectionEntryV0(identity, raw_sha256(current[key]), replacement))
            elif target is not None:
                raise _DomainReject("UNEXPECTED_EDITORIAL_TARGET")
            if action is EditorialActionV0.REWORK_REQUIRED:
                unresolved.append(key)
            decisions.append(EditorialDecisionEntryV0(identity, action, reason, None if replacement is None else raw_sha256(replacement)))
            seen.append(key)
        if tuple(seen) != tuple(sorted(seen)) or len(seen) != len(set(seen)):
            raise _DomainReject("NONCANONICAL_DECISION_ORDER")
        if set(seen) != set(packet.requested_ids):
            raise _DomainReject("INCOMPLETE_EDITORIAL_COVERAGE")
        if unresolved and job.round_index < policy.max_rework_rounds:
            status = EditorialJobStatusV0.REWORK_REQUIRED
            reason = "BOUNDED_REWORK_REQUIRED"
        elif unresolved:
            status = EditorialJobStatusV0.REWORK_EXHAUSTED
            reason = "REWORK_LIMIT_REACHED"
        else:
            status = EditorialJobStatusV0.ACCEPTED
            reason = "EDITORIAL_ACCEPTED"
        decision = EditorialDecisionSetV0(job.job_id, submission_sha, status, reason, tuple(decisions))
        decision_sha = raw_sha256(canonical_json_bytes(decision.as_dict()))
        overlay = CorrectionOverlayV0(job.job_id, decision_sha, candidate_raw_sha(parent), tuple(corrections))
        candidate = apply_correction_overlay_v0(
            parent, overlay, job_id=job.job_id, ready=not unresolved,
            disposition=status.value, unresolved_ids=tuple(sorted(unresolved)),
        )
        candidate_sha = candidate_raw_sha(candidate)
        rework = EditorialReworkRequestV0(
            job.job_id,
            status.value,
            candidate_sha,
            decision_sha,
            policy.digest,
            job.round_index + 1 if status is EditorialJobStatusV0.REWORK_REQUIRED else None,
            tuple(sorted(unresolved)) if status is EditorialJobStatusV0.REWORK_REQUIRED else (),
        )
        return decision, overlay, candidate, rework, status
    except _DomainReject as reject:
        rejection_reason = reject.reason_code
    except (ContractViolation, KeyError, TypeError) as error:
        rejection_reason = "MALFORMED_EDITORIAL_OUTPUT"
    else:
        raise AssertionError("Editorial terminal parser returned without result")

    if rejection_reason:
        status = EditorialJobStatusV0.REJECTED
        decision = EditorialDecisionSetV0(job.job_id, submission_sha, status, rejection_reason, ())
        decision_sha = raw_sha256(canonical_json_bytes(decision.as_dict()))
        overlay = CorrectionOverlayV0(job.job_id, decision_sha, candidate_raw_sha(parent), ())
        candidate = EditorialCandidateSetV0(
            job.job_id, parent.target_locale, False, status.value, parent.base_target_set_sha256,
            candidate_raw_sha(parent), parent.overlay_sha256s, packet.requested_ids, parent._target_bytes,
        )
        candidate_sha = candidate_raw_sha(candidate)
        rework = EditorialReworkRequestV0(job.job_id, status.value, candidate_sha, decision_sha, policy.digest, None, ())
        return decision, overlay, candidate, rework, status


def editorial_terminal_artifacts_v0(
    job: EditorialJobV0,
    packet: EditorialPacketV0,
    policy: EditorialPolicyV0,
    parent: EditorialCandidateSetV0,
    receipt: EditorialSubmissionReceiptV0,
    raw_output: bytes,
) -> tuple[tuple[str, bytes], ...]:
    submission_sha = editorial_submission_digest_v0(receipt)
    decision, overlay, candidate, rework, status = _accepted_terminal(job, packet, policy, parent, submission_sha, raw_output)
    decision_bytes = canonical_json_bytes(decision.as_dict())
    overlay_bytes = canonical_json_bytes(overlay.as_dict())
    candidate_bytes = canonical_json_bytes(candidate.as_dict())
    rework_bytes = canonical_json_bytes(rework.as_dict())
    state = EditorialStateV0(
        job.job_id, job.invocation_id, status, submission_sha, raw_sha256(decision_bytes),
        raw_sha256(overlay_bytes), raw_sha256(candidate_bytes), raw_sha256(rework_bytes),
    )
    root = editorial_job_root_v0(job)
    return tuple(sorted((
        (posixpath.join(root, "candidate_set.json"), candidate_bytes),
        (posixpath.join(root, "decision_set.json"), decision_bytes),
        (posixpath.join(root, "overlay.json"), overlay_bytes),
        (posixpath.join(root, "rework_request.json"), rework_bytes),
        (posixpath.join(root, "state.json"), canonical_json_bytes(state.as_dict())),
    )))


def bind_editorial_acceptance_v0(
    module: ModuleDescriptorV0,
    project_context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    expected_job: EditorialJobV0,
    expected_packet: EditorialPacketV0,
    expected_policy: EditorialPolicyV0,
    expected_parent: EditorialCandidateSetV0,
    translation_job: TranslationJobV0,
    translation_packet: TranslationPacketV0,
    translation_decision_bytes: bytes,
    translation_target_set: TranslationTargetSetV0,
    translation_state_bytes: bytes,
    parent_state_bytes: bytes | None = None,
    parent_decision_bytes: bytes | None = None,
    parent_rework_request_bytes: bytes | None = None,
) -> tuple[ImplementationRefV0, OperationHandlerV0]:
    implementation = _implementation(module)

    def handler(request: OperationRequestV0, operation_context: OperationContextV0) -> ErrorRecord | None:
        try:
            if request.capability is not Capability.EDITORIAL_REVIEW:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial handler received wrong capability")
            if request.declared_outputs != editorial_acceptance_output_declarations_v0(expected_job):
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Editorial outputs differ from contract")
            root = editorial_job_root_v0(expected_job)
            job_bytes = (operation_context.input_root / root / "job.json").read_bytes()
            packet_bytes = (operation_context.input_root / root / "packet.json").read_bytes()
            policy_bytes = (operation_context.input_root / root / "policy.json").read_bytes()
            parent_bytes = (operation_context.input_root / root / "parent_candidate.json").read_bytes()
            if job_bytes != canonical_json_bytes(expected_job.as_dict()) or packet_bytes != canonical_json_bytes(expected_packet.as_dict()) or policy_bytes != canonical_json_bytes(expected_policy.as_dict()) or parent_bytes != canonical_json_bytes(expected_parent.as_dict()):
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial prepared authority drift")
            state = parse_editorial_state_v0((operation_context.input_root / root / "state.json").read_bytes())
            if state.job_id != expected_job.job_id or state.invocation_id != expected_job.invocation_id or state.status is not EditorialJobStatusV0.RECEIVED:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial state is not selected RECEIVED")
            submission_sha = state.selected_submission_sha256
            assert submission_sha is not None
            selection = parse_canonical_json((operation_context.input_root / root / "selection.json").read_bytes())
            if selection != {"contract": "locpipe.editorial.selection/v0", "job_id": expected_job.job_id, "invocation_id": expected_job.invocation_id, "submission_sha256": submission_sha}:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial selection receipt drift")
            if tuple(row.path for row in request.inputs) != _input_paths(expected_job, expected_parent, translation_job, submission_sha):
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Editorial inputs differ from contract")
            translation_root = translation_job_root_v0(translation_job)
            expected_translation = {
                "job.json": canonical_json_bytes(translation_job.as_dict()),
                "packet.json": canonical_json_bytes(translation_packet.as_dict()),
                "decision.json": translation_decision_bytes,
                "state.json": translation_state_bytes,
                "target_set.json": canonical_json_bytes(translation_target_set.as_dict()),
            }
            for name, payload in expected_translation.items():
                if (operation_context.input_root / translation_root / name).read_bytes() != payload:
                    raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial translation authority drift")
            if expected_job.round_index > 0:
                if any(value is None for value in (parent_state_bytes, parent_decision_bytes, parent_rework_request_bytes)):
                    raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial parent terminal evidence is missing")
                parent_root = editorial_job_root_from_id_v0(expected_parent.job_id)
                parent_artifacts = {
                    "candidate_set.json": canonical_json_bytes(expected_parent.as_dict()),
                    "decision_set.json": parent_decision_bytes,
                    "rework_request.json": parent_rework_request_bytes,
                    "state.json": parent_state_bytes,
                }
                for name, payload in parent_artifacts.items():
                    if (operation_context.input_root / parent_root / name).read_bytes() != payload:
                        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial parent terminal authority drift")
            submission_root = operation_context.input_root / Path(*editorial_submission_root_from_digest_v0(submission_sha).split("/"))
            raw_output = (submission_root / "output.json").read_bytes()
            receipt_bytes = (submission_root / "receipt.json").read_bytes()
            receipt = parse_editorial_submission_receipt_v0(receipt_bytes)
            expected_receipt = EditorialSubmissionReceiptV0(
                expected_job.job_id, expected_job.invocation_id, expected_job.provider, receipt.provider_request_id,
                expected_job.packet_sha256, expected_job.output_contract_sha256, raw_sha256(raw_output),
            )
            if receipt != expected_receipt or receipt_bytes != canonical_json_bytes(receipt.as_dict()) or editorial_submission_digest_v0(receipt) != submission_sha:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial submission is foreign or drifted")
            rebuilt_job, rebuilt_packet, rebuilt_parent = build_editorial_job_v0(
                project_context, resolved, translation_job, translation_packet, translation_decision_bytes,
                translation_target_set, translation_state_bytes, expected_policy, budget=expected_job.budget,
                parent_candidate=None if expected_job.round_index == 0 else expected_parent,
                parent_state_bytes=parent_state_bytes,
                parent_decision_bytes=parent_decision_bytes,
                parent_rework_request_bytes=parent_rework_request_bytes,
                requested_ids=expected_packet.requested_ids, round_index=expected_job.round_index,
            )
            if rebuilt_job != expected_job or rebuilt_packet != expected_packet or rebuilt_parent != expected_parent:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial job/packet rebuild drift")
            for relative, payload in editorial_terminal_artifacts_v0(expected_job, expected_packet, expected_policy, expected_parent, receipt, raw_output):
                path = operation_context.staging_root / Path(*relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            return None
        except ContractViolation as error:
            return error.as_record()

    return implementation, handler
