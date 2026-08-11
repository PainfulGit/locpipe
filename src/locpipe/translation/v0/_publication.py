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
    validate_envelope,
)
from locpipe.contracts.v0.artifacts import has_reparse_component, resolve_artifact_root
from locpipe.kernel.v0.context import ProjectContextV0, resolve_project_paths
from locpipe.kernel.v0.context_transactions import create_context_staging, publish_context_group
from locpipe.kernel.v0.transactions import (
    PublicationEntryV0,
    PublicationGroupReceiptV0,
    PublicationGroupSpecV0,
    SyntheticTransactionStoreV0,
    WriteLeaseV0,
)

from ._acceptance import submission_digest_v0, translation_job_root_v0, translation_submission_root_v0
from ._models import (
    ProviderSubmissionReceiptV0,
    TranslationJobStatusV0,
    TranslationJobV0,
    TranslationPacketV0,
    TranslationStateV0,
)
from ._serialization import parse_submission_receipt_v0, parse_translation_state_v0


def _canonical_object(payload: bytes, name: str) -> Mapping[str, Any]:
    value = parse_canonical_json(payload)
    if not isinstance(value, Mapping) or canonical_json_bytes(value) != payload:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be a canonical object")
    return value


def _exact_preimages(
    expected: Mapping[str, str | None],
    required: Mapping[str, str | None],
) -> None:
    if dict(expected) != dict(required):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation lifecycle preimages differ from contract")


def _validate_lifecycle_group(
    job: TranslationJobV0,
    rows: tuple[tuple[str, bytes], ...],
    expected_preimages: Mapping[str, str | None],
    acceptance_result: Mapping[str, Any] | None,
) -> None:
    artifacts = dict(rows)
    root = translation_job_root_v0(job)
    job_path = posixpath.join(root, "job.json")
    packet_path = posixpath.join(root, "packet.json")
    state_path = posixpath.join(root, "state.json")
    selection_path = posixpath.join(root, "selection.json")
    decision_path = posixpath.join(root, "decision.json")
    target_set_path = posixpath.join(root, "target_set.json")
    paths = set(artifacts)

    if paths == {job_path, packet_path, state_path}:
        if acceptance_result is not None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "PREPARED publication cannot use acceptance evidence")
        if artifacts[job_path] != canonical_json_bytes(job.as_dict()):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "PREPARED job bytes drift")
        packet = _canonical_object(artifacts[packet_path], "Translation packet")
        if packet.get("contract") != "locpipe.translation.packet/v0" or packet.get("target_locale") != job.target_locale:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "PREPARED packet binding drift")
        if raw_sha256(artifacts[packet_path]) != job.packet_sha256:
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "PREPARED packet SHA drift")
        state = parse_translation_state_v0(artifacts[state_path])
        if state != TranslationStateV0(job.job_id, job.invocation_id, TranslationJobStatusV0.PREPARED):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "PREPARED state drift")
        _exact_preimages(expected_preimages, {path: None for path in paths})
        return

    if all(path.startswith("tr/s/") for path in paths):
        if acceptance_result is not None or len(paths) != 2:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Submission archive group shape is invalid")
        receipts = [payload for path, payload in rows if path.endswith("receipt.json")]
        outputs = [payload for path, payload in rows if path.endswith("output.json")]
        if len(receipts) != 1 or len(outputs) != 1:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Submission archive artifacts are incomplete")
        receipt = parse_submission_receipt_v0(receipts[0])
        if canonical_json_bytes(receipt.as_dict()) != receipts[0]:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Submission receipt is not canonical")
        expected_receipt = ProviderSubmissionReceiptV0(
            job.job_id, job.invocation_id, job.provider, receipt.provider_request_id,
            job.packet_sha256, job.output_contract_sha256, raw_sha256(outputs[0]),
        )
        expected_root = translation_submission_root_v0(receipt)
        expected_paths = {
            posixpath.join(expected_root, "output.json"),
            posixpath.join(expected_root, "receipt.json"),
        }
        if receipt != expected_receipt or paths != expected_paths:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Submission archive binding drift")
        _exact_preimages(expected_preimages, {path: None for path in paths})
        return

    if paths == {selection_path, state_path}:
        if acceptance_result is not None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "RECEIVED publication cannot use terminal evidence")
        state = parse_translation_state_v0(artifacts[state_path])
        if state.status is not TranslationJobStatusV0.RECEIVED or state.job_id != job.job_id or state.invocation_id != job.invocation_id:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "RECEIVED state binding drift")
        selection = _canonical_object(artifacts[selection_path], "Translation selection")
        if selection != {
            "contract": "locpipe.translation.selection/v0",
            "job_id": job.job_id,
            "invocation_id": job.invocation_id,
            "submission_sha256": state.selected_submission_sha256,
        }:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "RECEIVED selection drift")
        prepared_state = TranslationStateV0(job.job_id, job.invocation_id, TranslationJobStatusV0.PREPARED)
        _exact_preimages(expected_preimages, {
            selection_path: None,
            state_path: raw_sha256(canonical_json_bytes(prepared_state.as_dict())),
        })
        return

    if paths == {decision_path, state_path, target_set_path}:
        if acceptance_result is None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Terminal publication requires handler PASS evidence")
        validate_envelope(acceptance_result)
        if acceptance_result.get("kind") != "operation_result":
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Terminal evidence has wrong kind")
        result = OperationResultV0.from_data(acceptance_result["data"])
        output_rows = tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in rows)
        if result.status != "PASS" or result.capability is not Capability.TRANSLATION or result.outputs != output_rows:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Terminal handler evidence differs from artifacts")
        state = parse_translation_state_v0(artifacts[state_path])
        if state.status not in {TranslationJobStatusV0.ACCEPTED, TranslationJobStatusV0.REJECTED} or state.job_id != job.job_id or state.invocation_id != job.invocation_id:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Terminal state binding drift")
        decision = _canonical_object(artifacts[decision_path], "Translation decision")
        target_set = _canonical_object(artifacts[target_set_path], "Translation target set")
        if set(decision) != {"contract", "job_id", "invocation_id", "status", "submission_sha256", "reason_code", "target_count"}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Terminal decision fields are invalid")
        if set(target_set) != {"contract", "job_id", "invocation_id", "target_locale", "targets"} or not isinstance(target_set["targets"], list):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Terminal target-set fields are invalid")
        if decision["contract"] != "locpipe.translation.decision/v0" or target_set["contract"] != "locpipe.translation.target-set/v0":
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Terminal artifact contract drift")
        if (
            decision["job_id"] != job.job_id
            or decision["invocation_id"] != job.invocation_id
            or decision["status"] != state.status.value
            or decision["submission_sha256"] != state.selected_submission_sha256
            or target_set["job_id"] != job.job_id
            or target_set["invocation_id"] != job.invocation_id
            or target_set["target_locale"] != job.target_locale
            or decision["target_count"] != len(target_set["targets"])
            or state.decision_sha256 != raw_sha256(artifacts[decision_path])
            or state.target_set_sha256 != raw_sha256(artifacts[target_set_path])
        ):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Terminal artifact cross-binding drift")
        if state.status is TranslationJobStatusV0.REJECTED and target_set["targets"]:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Rejected terminal state retained targets")
        received_state = TranslationStateV0(
            job.job_id, job.invocation_id, TranslationJobStatusV0.RECEIVED, state.selected_submission_sha256
        )
        _exact_preimages(expected_preimages, {
            decision_path: None,
            state_path: raw_sha256(canonical_json_bytes(received_state.as_dict())),
            target_set_path: None,
        })
        return

    raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Unknown translation lifecycle group shape")


def prepared_translation_artifacts_v0(job: TranslationJobV0, packet: TranslationPacketV0) -> tuple[tuple[str, bytes], ...]:
    if raw_sha256(canonical_json_bytes(packet.as_dict())) != job.packet_sha256:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Prepared packet differs from job")
    root = translation_job_root_v0(job)
    state = TranslationStateV0(job.job_id, job.invocation_id, TranslationJobStatusV0.PREPARED)
    return tuple(sorted((
        (posixpath.join(root, "job.json"), canonical_json_bytes(job.as_dict())),
        (posixpath.join(root, "packet.json"), canonical_json_bytes(packet.as_dict())),
        (posixpath.join(root, "state.json"), canonical_json_bytes(state.as_dict())),
    )))


def submission_archive_artifacts_v0(
    job: TranslationJobV0,
    raw_output: bytes,
    receipt: ProviderSubmissionReceiptV0,
) -> tuple[tuple[str, bytes], ...]:
    expected = ProviderSubmissionReceiptV0(
        job.job_id, job.invocation_id, job.provider, receipt.provider_request_id,
        job.packet_sha256, job.output_contract_sha256, raw_sha256(raw_output),
    )
    if receipt != expected:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Submission receipt does not bind raw output and job")
    root = translation_submission_root_v0(receipt)
    return tuple(sorted((
        (posixpath.join(root, "output.json"), bytes(raw_output)),
        (posixpath.join(root, "receipt.json"), canonical_json_bytes(receipt.as_dict())),
    )))


def received_translation_artifacts_v0(
    job: TranslationJobV0,
    receipt: ProviderSubmissionReceiptV0,
) -> tuple[tuple[str, bytes], ...]:
    submission_sha = submission_digest_v0(receipt)
    root = translation_job_root_v0(job)
    selection = {
        "contract": "locpipe.translation.selection/v0",
        "job_id": job.job_id,
        "invocation_id": job.invocation_id,
        "submission_sha256": submission_sha,
    }
    state = TranslationStateV0(job.job_id, job.invocation_id, TranslationJobStatusV0.RECEIVED, submission_sha)
    return tuple(sorted((
        (posixpath.join(root, "selection.json"), canonical_json_bytes(selection)),
        (posixpath.join(root, "state.json"), canonical_json_bytes(state.as_dict())),
    )))


def publish_translation_group_v0(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    job: TranslationJobV0,
    operation_id: str,
    artifacts: tuple[tuple[str, bytes], ...],
    lease: WriteLeaseV0,
    *,
    expected_preimages: Mapping[str, str | None],
    clock: Callable[[], str],
    acceptance_result: Mapping[str, Any] | None = None,
    _failure_hook: Callable[[str], None] | None = None,
) -> PublicationGroupReceiptV0:
    if not isinstance(job, TranslationJobV0) or job.context_digest != context.context_digest:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation job belongs to a different project context")
    rows = tuple(sorted((path, bytes(payload)) for path, payload in artifacts))
    paths = tuple(path for path, _payload in rows)
    if len(rows) < 2 or len(paths) != len(set(paths)) or set(paths) != set(expected_preimages):
        raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Translation publication group is invalid")
    job_prefix = translation_job_root_v0(job) + "/"
    if any(not path.startswith((job_prefix, "tr/s/")) for path in paths):
        raise ContractViolation(ErrorCode.PATH_ESCAPE, "Translation helper only publishes translation job artifacts")
    submission_rows = [(path, payload) for path, payload in rows if path.startswith("tr/s/")]
    if submission_rows:
        receipts = [payload for path, payload in submission_rows if path.endswith("receipt.json")]
        if len(receipts) != 1:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Submission publication lacks one receipt")
        submission = parse_submission_receipt_v0(receipts[0])
        if submission.job_id != job.job_id or submission.invocation_id != job.invocation_id or submission.provider != job.provider:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Submission publication belongs to another job")
        expected_root = translation_submission_root_v0(submission) + "/"
        if any(not path.startswith(expected_root) for path, _payload in submission_rows):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Submission publication path differs from receipt")
    _validate_lifecycle_group(job, rows, expected_preimages, acceptance_result)
    try:
        staging = create_context_staging(store, context, operation_id)
    except FileExistsError:
        staging = resolve_project_paths(store, context).staging_root / operation_id
        resolved = resolve_artifact_root(staging)
        expected_files = set(paths)
        actual_files = set()
        for candidate in resolved.rglob("*"):
            if candidate.is_symlink() or has_reparse_component(resolved, candidate):
                raise ContractViolation(ErrorCode.PATH_ESCAPE, "Translation retry staging contains a link")
            if candidate.is_file():
                actual_files.add(candidate.relative_to(resolved).as_posix())
        if actual_files != expected_files:
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Translation retry staging drift")
        for relative, payload in rows:
            if (resolved / Path(*relative.split("/"))).read_bytes() != payload:
                raise ContractViolation(ErrorCode.HASH_MISMATCH, "Translation retry bytes drift")
    entries = []
    for relative, payload in rows:
        output = staging / Path(*relative.split("/"))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(payload)
        entries.append(PublicationEntryV0(
            ArtifactHashV0(relative, "raw", raw_sha256(payload)),
            expected_preimages[relative],
        ))
    spec = PublicationGroupSpecV0(context.namespace, operation_id, tuple(entries))
    return publish_context_group(store, context, spec, lease, clock=clock, _failure_hook=_failure_hook)
