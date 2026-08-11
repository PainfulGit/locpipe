from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
import posixpath
from typing import Any

from locpipe.contracts.v0 import (
    ArtifactHashV0,
    Capability,
    ContractViolation,
    ErrorCode,
    OperationResultV0,
    canonical_json_bytes,
    parse_canonical_json,
    raw_sha256,
    semantic_sha256,
    validate_envelope,
)
from locpipe.contracts.v0.artifacts import has_reparse_component, resolve_artifact_root
from locpipe.kernel.v0.config import ResolvedConfigV0
from locpipe.kernel.v0.context import ProjectContextV0, resolve_project_paths
from locpipe.kernel.v0.context_transactions import create_context_staging, publish_context_group
from locpipe.kernel.v0.transactions import (
    PublicationEntryV0,
    PublicationGroupReceiptV0,
    PublicationGroupSpecV0,
    SyntheticTransactionStoreV0,
    WriteLeaseV0,
)
from locpipe.translation.v0 import TranslationJobV0, TranslationPacketV0, TranslationTargetSetV0

from ._acceptance import editorial_job_root_v0, editorial_submission_root_v0
from ._evidence import EditorialStateV0, EditorialSubmissionReceiptV0
from ._models import EditorialCandidateSetV0, EditorialJobStatusV0, EditorialJobV0, EditorialPacketV0, EditorialPolicyV0
from ._packet import build_editorial_bypass_v0
from ._serialization import parse_editorial_state_v0, parse_editorial_submission_receipt_v0


def _exact_preimages(expected: Mapping[str, str | None], required: Mapping[str, str | None]) -> None:
    if dict(expected) != dict(required):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial lifecycle preimages differ from contract")


def prepared_editorial_artifacts_v0(
    job: EditorialJobV0,
    packet: EditorialPacketV0,
    policy: EditorialPolicyV0,
    parent: EditorialCandidateSetV0,
) -> tuple[tuple[str, bytes], ...]:
    if raw_sha256(canonical_json_bytes(packet.as_dict())) != job.packet_sha256 or policy.digest != job.policy_sha256:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Prepared editorial packet or policy differs from job")
    if raw_sha256(canonical_json_bytes(parent.as_dict())) != job.parent_candidate_sha256:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Prepared editorial parent candidate differs from job")
    root = editorial_job_root_v0(job)
    state = EditorialStateV0(job.job_id, job.invocation_id, EditorialJobStatusV0.PREPARED)
    return tuple(sorted((
        (posixpath.join(root, "job.json"), canonical_json_bytes(job.as_dict())),
        (posixpath.join(root, "packet.json"), canonical_json_bytes(packet.as_dict())),
        (posixpath.join(root, "parent_candidate.json"), canonical_json_bytes(parent.as_dict())),
        (posixpath.join(root, "policy.json"), canonical_json_bytes(policy.as_dict())),
        (posixpath.join(root, "state.json"), canonical_json_bytes(state.as_dict())),
    )))


def editorial_submission_archive_artifacts_v0(
    job: EditorialJobV0,
    raw_output: bytes,
    receipt: EditorialSubmissionReceiptV0,
) -> tuple[tuple[str, bytes], ...]:
    expected = EditorialSubmissionReceiptV0(
        job.job_id, job.invocation_id, job.provider, receipt.provider_request_id,
        job.packet_sha256, job.output_contract_sha256, raw_sha256(raw_output),
    )
    if receipt != expected:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial submission receipt does not bind job/output")
    root = editorial_submission_root_v0(receipt)
    return tuple(sorted((
        (posixpath.join(root, "output.json"), bytes(raw_output)),
        (posixpath.join(root, "receipt.json"), canonical_json_bytes(receipt.as_dict())),
    )))


def received_editorial_artifacts_v0(
    job: EditorialJobV0,
    receipt: EditorialSubmissionReceiptV0,
) -> tuple[tuple[str, bytes], ...]:
    from ._acceptance import editorial_submission_digest_v0

    submission_sha = editorial_submission_digest_v0(receipt)
    root = editorial_job_root_v0(job)
    selection = {
        "contract": "locpipe.editorial.selection/v0", "job_id": job.job_id,
        "invocation_id": job.invocation_id, "submission_sha256": submission_sha,
    }
    state = EditorialStateV0(job.job_id, job.invocation_id, EditorialJobStatusV0.RECEIVED, submission_sha)
    return tuple(sorted((
        (posixpath.join(root, "selection.json"), canonical_json_bytes(selection)),
        (posixpath.join(root, "state.json"), canonical_json_bytes(state.as_dict())),
    )))


def _validate_submission(job: EditorialJobV0, artifacts: Mapping[str, bytes], paths: set[str]) -> None:
    receipts = [payload for path, payload in artifacts.items() if path.endswith("receipt.json")]
    outputs = [payload for path, payload in artifacts.items() if path.endswith("output.json")]
    if len(receipts) != 1 or len(outputs) != 1 or len(paths) != 2:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial submission archive shape is invalid")
    receipt = parse_editorial_submission_receipt_v0(receipts[0])
    expected = EditorialSubmissionReceiptV0(
        job.job_id, job.invocation_id, job.provider, receipt.provider_request_id,
        job.packet_sha256, job.output_contract_sha256, raw_sha256(outputs[0]),
    )
    root = editorial_submission_root_v0(receipt)
    expected_paths = {posixpath.join(root, "output.json"), posixpath.join(root, "receipt.json")}
    if receipt != expected or receipts[0] != canonical_json_bytes(receipt.as_dict()) or paths != expected_paths:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial submission archive binding drift")


def _validate_terminal(
    job: EditorialJobV0,
    artifacts: Mapping[str, bytes],
    expected_preimages: Mapping[str, str | None],
    acceptance_result: Mapping[str, Any] | None,
) -> None:
    if acceptance_result is None:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial terminal publication requires handler PASS evidence")
    validate_envelope(acceptance_result)
    result = OperationResultV0.from_data(acceptance_result["data"])
    rows = tuple(sorted(artifacts.items()))
    output_hashes = tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in rows)
    if result.status != "PASS" or result.capability is not Capability.EDITORIAL_REVIEW or result.outputs != output_hashes:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial handler result differs from terminal artifacts")
    root = editorial_job_root_v0(job)
    state_path = posixpath.join(root, "state.json")
    state = parse_editorial_state_v0(artifacts[state_path])
    if state.job_id != job.job_id or state.invocation_id != job.invocation_id or state.status not in {
        EditorialJobStatusV0.ACCEPTED, EditorialJobStatusV0.REWORK_REQUIRED,
        EditorialJobStatusV0.REWORK_EXHAUSTED, EditorialJobStatusV0.REJECTED,
    }:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial terminal state binding drift")
    bindings = {
        "decision_set.json": state.decision_set_sha256,
        "overlay.json": state.overlay_sha256,
        "candidate_set.json": state.candidate_sha256,
        "rework_request.json": state.rework_request_sha256,
    }
    for name, expected_sha in bindings.items():
        path = posixpath.join(root, name)
        if raw_sha256(artifacts[path]) != expected_sha:
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "Editorial terminal artifact SHA drift")
    decision = parse_canonical_json(artifacts[posixpath.join(root, "decision_set.json")])
    overlay = parse_canonical_json(artifacts[posixpath.join(root, "overlay.json")])
    candidate = parse_canonical_json(artifacts[posixpath.join(root, "candidate_set.json")])
    rework = parse_canonical_json(artifacts[posixpath.join(root, "rework_request.json")])
    decision_sha = raw_sha256(artifacts[posixpath.join(root, "decision_set.json")])
    candidate_sha = raw_sha256(artifacts[posixpath.join(root, "candidate_set.json")])
    if (
        decision.get("job_id") != job.job_id
        or decision.get("status") != state.status.value
        or decision.get("submission_sha256") != state.selected_submission_sha256
        or overlay.get("job_id") != job.job_id
        or overlay.get("decision_set_sha256") != decision_sha
        or overlay.get("parent_candidate_sha256") != job.parent_candidate_sha256
        or candidate.get("job_id") != job.job_id
        or candidate.get("base_target_set_sha256") != job.base_target_set_sha256
        or candidate.get("parent_candidate_sha256") != job.parent_candidate_sha256
        or rework.get("job_id") != job.job_id
        or rework.get("candidate_sha256") != candidate_sha
        or rework.get("parent_decision_sha256") != decision_sha
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial terminal cross-binding drift")
    if bool(candidate.get("ready")) != (state.status is EditorialJobStatusV0.ACCEPTED):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial terminal readiness drift")
    received = EditorialStateV0(job.job_id, job.invocation_id, EditorialJobStatusV0.RECEIVED, state.selected_submission_sha256)
    required = {path: None for path in artifacts}
    required[state_path] = raw_sha256(canonical_json_bytes(received.as_dict()))
    _exact_preimages(expected_preimages, required)


def _validate_group(
    job: EditorialJobV0,
    rows: tuple[tuple[str, bytes], ...],
    expected_preimages: Mapping[str, str | None],
    acceptance_result: Mapping[str, Any] | None,
) -> None:
    artifacts = dict(rows)
    paths = set(artifacts)
    root = editorial_job_root_v0(job)
    prepared_paths = {posixpath.join(root, name) for name in ("job.json", "packet.json", "parent_candidate.json", "policy.json", "state.json")}
    received_paths = {posixpath.join(root, name) for name in ("selection.json", "state.json")}
    terminal_paths = {posixpath.join(root, name) for name in ("candidate_set.json", "decision_set.json", "overlay.json", "rework_request.json", "state.json")}
    if paths == prepared_paths:
        if acceptance_result is not None or artifacts[posixpath.join(root, "job.json")] != canonical_json_bytes(job.as_dict()):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial PREPARED binding drift")
        state = parse_editorial_state_v0(artifacts[posixpath.join(root, "state.json")])
        if state != EditorialStateV0(job.job_id, job.invocation_id, EditorialJobStatusV0.PREPARED):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial PREPARED state drift")
        if raw_sha256(artifacts[posixpath.join(root, "packet.json")]) != job.packet_sha256:
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "Editorial PREPARED packet SHA drift")
        if raw_sha256(artifacts[posixpath.join(root, "parent_candidate.json")]) != job.parent_candidate_sha256:
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "Editorial PREPARED parent candidate drift")
        policy = parse_canonical_json(artifacts[posixpath.join(root, "policy.json")])
        if policy.get("contract") != "locpipe.editorial.policy/v0" or semantic_sha256(policy) != job.policy_sha256:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial PREPARED policy drift")
        _exact_preimages(expected_preimages, {path: None for path in paths})
        return
    if all(path.startswith("ed/s/") for path in paths):
        if acceptance_result is not None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial submission cannot carry handler result")
        _validate_submission(job, artifacts, paths)
        _exact_preimages(expected_preimages, {path: None for path in paths})
        return
    if paths == received_paths:
        if acceptance_result is not None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial RECEIVED cannot carry terminal result")
        state_path = posixpath.join(root, "state.json")
        state = parse_editorial_state_v0(artifacts[state_path])
        selection = parse_canonical_json(artifacts[posixpath.join(root, "selection.json")])
        if state.status is not EditorialJobStatusV0.RECEIVED or selection != {
            "contract": "locpipe.editorial.selection/v0", "job_id": job.job_id,
            "invocation_id": job.invocation_id, "submission_sha256": state.selected_submission_sha256,
        }:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial RECEIVED binding drift")
        prepared = EditorialStateV0(job.job_id, job.invocation_id, EditorialJobStatusV0.PREPARED)
        _exact_preimages(expected_preimages, {
            posixpath.join(root, "selection.json"): None,
            state_path: raw_sha256(canonical_json_bytes(prepared.as_dict())),
        })
        return
    if paths == terminal_paths:
        _validate_terminal(job, artifacts, expected_preimages, acceptance_result)
        return
    raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Unknown editorial lifecycle group shape")


def _publish_rows(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    operation_id: str,
    rows: tuple[tuple[str, bytes], ...],
    expected_preimages: Mapping[str, str | None],
    lease: WriteLeaseV0,
    *,
    clock: Callable[[], str],
    _failure_hook: Callable[[str], None] | None,
) -> PublicationGroupReceiptV0:
    paths = tuple(path for path, _payload in rows)
    try:
        staging = create_context_staging(store, context, operation_id)
    except FileExistsError:
        staging = resolve_project_paths(store, context).staging_root / operation_id
        resolved = resolve_artifact_root(staging)
        actual = set()
        for candidate in resolved.rglob("*"):
            if candidate.is_symlink() or has_reparse_component(resolved, candidate):
                raise ContractViolation(ErrorCode.PATH_ESCAPE, "Editorial retry staging contains a link")
            if candidate.is_file():
                actual.add(candidate.relative_to(resolved).as_posix())
        if actual != set(paths):
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Editorial retry staging drift")
        for relative, payload in rows:
            if (resolved / Path(*relative.split("/"))).read_bytes() != payload:
                raise ContractViolation(ErrorCode.HASH_MISMATCH, "Editorial retry bytes drift")
    entries = []
    for relative, payload in rows:
        output = staging / Path(*relative.split("/"))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(payload)
        entries.append(PublicationEntryV0(ArtifactHashV0(relative, "raw", raw_sha256(payload)), expected_preimages[relative]))
    return publish_context_group(
        store, context, PublicationGroupSpecV0(context.namespace, operation_id, tuple(entries)), lease,
        clock=clock, _failure_hook=_failure_hook,
    )


def publish_editorial_group_v0(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    job: EditorialJobV0,
    operation_id: str,
    artifacts: tuple[tuple[str, bytes], ...],
    lease: WriteLeaseV0,
    *,
    expected_preimages: Mapping[str, str | None],
    clock: Callable[[], str],
    acceptance_result: Mapping[str, Any] | None = None,
    _failure_hook: Callable[[str], None] | None = None,
) -> PublicationGroupReceiptV0:
    if job.context_digest != context.context_digest:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Editorial job belongs to another context")
    rows = tuple(sorted((path, bytes(payload)) for path, payload in artifacts))
    paths = tuple(path for path, _payload in rows)
    if len(paths) < 2 or len(paths) != len(set(paths)) or set(paths) != set(expected_preimages):
        raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Editorial publication group is invalid")
    root = editorial_job_root_v0(job) + "/"
    if any(not path.startswith((root, "ed/s/")) for path in paths):
        raise ContractViolation(ErrorCode.PATH_ESCAPE, "Editorial helper only publishes job/submission artifacts")
    _validate_group(job, rows, expected_preimages, acceptance_result)
    return _publish_rows(store, context, operation_id, rows, expected_preimages, lease, clock=clock, _failure_hook=_failure_hook)


def publish_editorial_bypass_v0(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    translation_job: TranslationJobV0,
    translation_packet: TranslationPacketV0,
    translation_decision_bytes: bytes,
    target_set: TranslationTargetSetV0,
    translation_state_bytes: bytes,
    operation_id: str,
    lease: WriteLeaseV0,
    *,
    clock: Callable[[], str],
    _failure_hook: Callable[[str], None] | None = None,
) -> PublicationGroupReceiptV0:
    candidate = build_editorial_bypass_v0(
        context, resolved, translation_job, translation_packet, translation_decision_bytes,
        target_set, translation_state_bytes,
    )
    token = candidate.job_id.removeprefix("editorial-base-")[:20]
    root = f"ed/b/{token}"
    disposition = {
        "contract": "locpipe.editorial.bypass/v0", "context_digest": context.context_digest,
        "translation_job_id": translation_job.job_id, "candidate_sha256": raw_sha256(canonical_json_bytes(candidate.as_dict())),
        "disposition": "BYPASSED_BY_CONFIG",
    }
    rows = tuple(sorted((
        (posixpath.join(root, "candidate_set.json"), canonical_json_bytes(candidate.as_dict())),
        (posixpath.join(root, "disposition.json"), canonical_json_bytes(disposition)),
    )))
    expected = {path: None for path, _payload in rows}
    return _publish_rows(store, context, operation_id, rows, expected, lease, clock=clock, _failure_hook=_failure_hook)
