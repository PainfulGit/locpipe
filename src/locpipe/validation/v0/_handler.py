from __future__ import annotations

from pathlib import Path
import posixpath
from collections.abc import Mapping

from locpipe.contracts.v0 import (
    ArtifactDeclarationV0,
    ArtifactHashV0,
    Capability,
    ContractViolation,
    ErrorCode,
    ErrorRecord,
    ImplementationRefV0,
    OperationContextV0,
    OperationHandlerV0,
    OperationRequestV0,
    OperationResultV0,
    canonical_json_bytes,
    raw_sha256,
    semantic_sha256,
    validate_envelope,
)
from locpipe.kernel.v0.context import ProjectContextV0, resolve_project_paths
from locpipe.kernel.v0.context_transactions import inspect_context_group_recovery
from locpipe.kernel.v0.transactions import (
    PublicationGroupReceiptV0,
    RecoveryDispositionV0,
    SyntheticTransactionStoreV0,
)

from ._models import (
    ContentFindingV0,
    ContentLocaleReceiptV0,
    ContentValidationJobV0,
    ContentValidationPacketV0,
    ContentValidationReportV0,
    ContentValidationStateV0,
    ContentValidationStatusV0,
    ContentValidatorV0,
    FindingSeverityV0,
    ValidationReworkRequestV0,
)
from ._packet import validation_job_root_v0


def content_validation_output_declarations_v0(job: ContentValidationJobV0) -> tuple[ArtifactDeclarationV0, ...]:
    root = validation_job_root_v0(job)
    return tuple(ArtifactDeclarationV0(posixpath.join(root, name), "raw") for name in (
        "report.json", "rework_request.json", "state.json",
    ))


def _implementation(job: ContentValidationJobV0) -> ImplementationRefV0:
    return ImplementationRefV0(
        "module",
        job.validator.module_id,
        job.validator.version,
        job.validator.digest,
        Capability.CONTENT_VALIDATION,
    )


def _authority_digest(rows: tuple[tuple[str, bytes], ...]) -> str:
    return semantic_sha256([{"path": path, "sha256": raw_sha256(payload)} for path, payload in rows])


def content_validation_terminal_artifacts_v0(
    job: ContentValidationJobV0,
    findings: tuple[ContentFindingV0, ...],
) -> tuple[tuple[str, bytes], ...]:
    rows = tuple(findings)
    keys = tuple((row.stable_id, row.rule_id, row.reason_code, row.finding_id) for row in rows)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Validator findings are not unique and sorted")
    report = ContentValidationReportV0(
        job.job_id,
        job.validator,
        job.rule_contract_sha256,
        job.candidate_sha256,
        rows,
    )
    report_bytes = canonical_json_bytes(report.as_dict())
    blocking = tuple(sorted({row.stable_id for row in rows if row.severity is FindingSeverityV0.ERROR}))
    if not blocking:
        status = ContentValidationStatusV0.LOCALE_VERIFIED
        next_round = None
    elif not job.editorial_available:
        status = ContentValidationStatusV0.REWORK_UNAVAILABLE
        next_round = None
    elif job.editorial_round_index < job.max_rework_rounds:
        status = ContentValidationStatusV0.REWORK_REQUIRED
        next_round = job.editorial_round_index + 1
    else:
        status = ContentValidationStatusV0.REWORK_EXHAUSTED
        next_round = None
    rework = ValidationReworkRequestV0(
        job.job_id,
        status,
        raw_sha256(report_bytes),
        job.candidate_sha256,
        next_round,
        blocking if status is ContentValidationStatusV0.REWORK_REQUIRED else (),
    )
    rework_bytes = canonical_json_bytes(rework.as_dict())
    state = ContentValidationStateV0(
        job.job_id,
        status,
        job.candidate_sha256,
        raw_sha256(report_bytes),
        raw_sha256(rework_bytes),
    )
    root = validation_job_root_v0(job)
    return tuple(sorted((
        (posixpath.join(root, "report.json"), report_bytes),
        (posixpath.join(root, "rework_request.json"), rework_bytes),
        (posixpath.join(root, "state.json"), canonical_json_bytes(state.as_dict())),
    )))


def bind_content_validator_v0(
    validator: ContentValidatorV0,
    expected_job: ContentValidationJobV0,
    expected_packet: ContentValidationPacketV0,
    authority_artifacts: tuple[tuple[str, bytes], ...],
) -> tuple[ImplementationRefV0, OperationHandlerV0]:
    if validator.descriptor != expected_job.validator or validator.rule_contract_sha256 != expected_job.rule_contract_sha256:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validator implementation differs from validation job")
    authority = tuple(sorted((path, bytes(payload)) for path, payload in authority_artifacts))
    if _authority_digest(authority) != expected_job.authority_sha256:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Validation authority differs from job")
    packet_bytes = canonical_json_bytes(expected_packet.as_dict())
    if raw_sha256(packet_bytes) != expected_job.packet_sha256:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Validation packet differs from job")
    root = validation_job_root_v0(expected_job)
    job_path = posixpath.join(root, "job.json")
    packet_path = posixpath.join(root, "packet.json")
    input_rows = tuple(sorted((*authority, (job_path, canonical_json_bytes(expected_job.as_dict())), (packet_path, packet_bytes))))
    expected_paths = tuple(path for path, _payload in input_rows)
    expected_payloads = dict(input_rows)
    owned_ids = set(expected_packet.owned_ids)
    implementation = _implementation(expected_job)

    def handler(request: OperationRequestV0, context: OperationContextV0) -> ErrorRecord | None:
        try:
            if validator.descriptor != expected_job.validator or validator.rule_contract_sha256 != expected_job.rule_contract_sha256:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validator binding drifted before execution")
            if request.capability is not Capability.CONTENT_VALIDATION:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation handler received wrong capability")
            if request.declared_outputs != content_validation_output_declarations_v0(expected_job):
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Validation outputs differ from contract")
            if tuple(row.path for row in request.inputs) != expected_paths:
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Validation inputs differ from contract")
            for relative, payload in input_rows:
                if (context.input_root / Path(*relative.split("/"))).read_bytes() != payload:
                    raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation input authority drift")
            findings = validator.validate(expected_packet)
            if validator.descriptor != expected_job.validator or validator.rule_contract_sha256 != expected_job.rule_contract_sha256:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validator binding drifted during execution")
            if not isinstance(findings, tuple) or any(not isinstance(row, ContentFindingV0) for row in findings):
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validator must return immutable findings")
            if any(row.stable_id not in owned_ids for row in findings):
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validator finding is outside owned scope")
            artifacts = content_validation_terminal_artifacts_v0(expected_job, findings)
            for relative, payload in artifacts:
                output = context.staging_root / Path(*relative.split("/"))
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(payload)
            return None
        except ContractViolation as error:
            return error.as_record()

    return implementation, handler


def content_locale_receipt_v0(
    job: ContentValidationJobV0,
    report_bytes: bytes,
    state_bytes: bytes,
    rework_request_bytes: bytes,
    *,
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    operation_result: Mapping[str, object],
    validation_publication_receipt: PublicationGroupReceiptV0,
) -> ContentLocaleReceiptV0:
    import json

    try:
        report = json.loads(report_bytes)
        state = json.loads(state_bytes)
        rework = json.loads(rework_request_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation locale evidence is malformed") from error
    if not isinstance(report, dict) or not isinstance(state, dict) or not isinstance(rework, dict):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation locale evidence must contain objects")
    if not isinstance(validation_publication_receipt, PublicationGroupReceiptV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation publication receipt is missing")
    if not isinstance(store, SyntheticTransactionStoreV0) or not isinstance(context, ProjectContextV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation publication context is missing")
    if context.context_digest != job.context_digest:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation publication context differs from job")
    recovery = inspect_context_group_recovery(
        store, context, validation_publication_receipt.operation_id,
    )
    receipt_path = (
        resolve_project_paths(store, context).transactions_root
        / validation_publication_receipt.operation_id
        / "receipt.json"
    )
    if (
        recovery.disposition is not RecoveryDispositionV0.NO_ACTION
        or not receipt_path.is_file()
        or receipt_path.read_bytes() != canonical_json_bytes(validation_publication_receipt.as_envelope())
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation publication receipt is not terminal context evidence")
    validate_envelope(operation_result)
    result = OperationResultV0.from_data(operation_result["data"])
    root = validation_job_root_v0(job)
    expected_outputs = tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in sorted((
        (posixpath.join(root, "report.json"), report_bytes),
        (posixpath.join(root, "rework_request.json"), rework_request_bytes),
        (posixpath.join(root, "state.json"), state_bytes),
    )))
    if (
        result.status != "PASS"
        or result.capability is not Capability.CONTENT_VALIDATION
        or result.outputs != expected_outputs
        or validation_publication_receipt.targets != expected_outputs
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Locale receipt lacks validator PASS and publication evidence")
    if (
        set(report) != {"contract", "job_id", "validator", "rule_contract_sha256", "candidate_sha256", "findings"}
        or set(state) != {"contract", "job_id", "status", "candidate_sha256", "report_sha256", "rework_request_sha256"}
        or set(rework) != {"contract", "job_id", "status", "report_sha256", "candidate_sha256", "next_round", "requested_ids"}
        or not isinstance(report.get("findings"), list)
    ):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation locale evidence fields are invalid")
    parsed_findings = []
    for row in report["findings"]:
        if not isinstance(row, dict) or set(row) != {
            "finding_id", "stable_id", "rule_id", "severity", "reason_code", "evidence_sha256",
        }:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation finding fields are invalid")
        try:
            finding = ContentFindingV0(
                row["stable_id"], row["rule_id"], FindingSeverityV0(row["severity"]),
                row["reason_code"], row["evidence_sha256"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Validation finding is malformed") from error
        if row["finding_id"] != finding.finding_id:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation finding ID drift")
        parsed_findings.append(finding)
    try:
        validated_report = ContentValidationReportV0(
            job.job_id, job.validator, job.rule_contract_sha256, job.candidate_sha256,
            tuple(parsed_findings),
        )
    except ContractViolation:
        raise
    if (
        canonical_json_bytes(report) != report_bytes
        or canonical_json_bytes(state) != state_bytes
        or canonical_json_bytes(rework) != rework_request_bytes
        or state.get("contract") != "locpipe.validation.state/v0"
        or state.get("job_id") != job.job_id
        or state.get("status") != ContentValidationStatusV0.LOCALE_VERIFIED.value
        or state.get("candidate_sha256") != job.candidate_sha256
        or state.get("report_sha256") != raw_sha256(report_bytes)
        or state.get("rework_request_sha256") != raw_sha256(rework_request_bytes)
        or report.get("job_id") != job.job_id
        or report != validated_report.as_dict()
        or any(row.severity is FindingSeverityV0.ERROR for row in parsed_findings)
        or report.get("candidate_sha256") != job.candidate_sha256
        or rework.get("contract") != "locpipe.validation.rework-request/v0"
        or rework.get("job_id") != job.job_id
        or rework.get("status") != ContentValidationStatusV0.LOCALE_VERIFIED.value
        or rework.get("requested_ids") != []
        or rework.get("next_round") is not None
        or rework.get("candidate_sha256") != job.candidate_sha256
        or rework.get("report_sha256") != raw_sha256(report_bytes)
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Locale receipt evidence is not verified or drifted")
    return ContentLocaleReceiptV0(
        job.context_digest,
        job.config_snapshot_sha256,
        job.content_config_digest,
        job.scope_sha256,
        job.source_lock_sha256,
        job.reconciliation_sha256,
        job.target_locale,
        job.candidate_sha256,
        job.job_id,
        raw_sha256(report_bytes),
        raw_sha256(state_bytes),
        raw_sha256(canonical_json_bytes(operation_result)),
        raw_sha256(canonical_json_bytes(validation_publication_receipt.as_envelope())),
    )
