from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
import posixpath

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
from locpipe.kernel.v0.context import ProjectContextV0, resolve_project_paths
from locpipe.kernel.v0.context_transactions import (
    create_context_staging,
    publish_context_file,
    publish_context_group,
)
from locpipe.kernel.v0.transactions import (
    PublicationEntryV0,
    PublicationGroupReceiptV0,
    PublicationGroupSpecV0,
    PublicationReceiptV0,
    PublicationSpecV0,
    SyntheticTransactionStoreV0,
    WriteLeaseV0,
)

from ._models import ContentLocaleReceiptV0, ContentValidationJobV0, ContentVerificationSetV0
from ._packet import validation_job_root_v0


def _publish(
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
    rows = tuple(sorted((path, bytes(payload)) for path, payload in rows))
    paths = tuple(path for path, _payload in rows)
    if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)) or set(paths) != set(expected_preimages):
        raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Content validation publication shape is invalid")
    try:
        staging = create_context_staging(store, context, operation_id)
        reused = False
    except FileExistsError:
        staging = resolve_project_paths(store, context).staging_root / operation_id
        reused = True
        actual = {path.relative_to(staging).as_posix() for path in staging.rglob("*") if path.is_file()}
        if actual != set(paths):
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Content validation retry staging drift")
        for relative, payload in rows:
            if (staging / Path(*relative.split("/"))).read_bytes() != payload:
                raise ContractViolation(ErrorCode.HASH_MISMATCH, "Content validation retry bytes drift")
    entries = []
    for relative, payload in rows:
        output = staging / Path(*relative.split("/"))
        if not reused:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(payload)
        entries.append(PublicationEntryV0(
            ArtifactHashV0(relative, "raw", raw_sha256(payload)),
            expected_preimages[relative],
        ))
    return publish_context_group(
        store,
        context,
        PublicationGroupSpecV0(context.namespace, operation_id, tuple(entries)),
        lease,
        clock=clock,
        _failure_hook=_failure_hook,
    )


def _publish_file(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    operation_id: str,
    row: tuple[str, bytes],
    expected_preimage: str | None,
    lease: WriteLeaseV0,
    *,
    clock: Callable[[], str],
    _failure_hook: Callable[[str], None] | None,
) -> PublicationReceiptV0:
    relative, payload = row[0], bytes(row[1])
    try:
        staging = create_context_staging(store, context, operation_id)
        reused = False
    except FileExistsError:
        staging = resolve_project_paths(store, context).staging_root / operation_id
        reused = True
        actual = {path.relative_to(staging).as_posix() for path in staging.rglob("*") if path.is_file()}
        if actual != {relative} or (staging / Path(*relative.split("/"))).read_bytes() != payload:
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Content receipt retry staging drift")
    output = staging / Path(*relative.split("/"))
    if not reused:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(payload)
    spec = PublicationSpecV0(
        context.namespace,
        operation_id,
        relative,
        ArtifactHashV0(relative, "raw", raw_sha256(payload)),
        expected_preimage,
    )
    return publish_context_file(
        store,
        context,
        spec,
        lease,
        clock=clock,
        _failure_hook=_failure_hook,
    )


def publish_content_validation_group_v0(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    job: ContentValidationJobV0,
    operation_id: str,
    artifacts: tuple[tuple[str, bytes], ...],
    lease: WriteLeaseV0,
    *,
    operation_result: Mapping[str, object],
    clock: Callable[[], str],
    _failure_hook: Callable[[str], None] | None = None,
) -> PublicationReceiptV0:
    if job.context_digest != context.context_digest:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation job belongs to another context")
    validate_envelope(operation_result)
    result = OperationResultV0.from_data(operation_result["data"])
    rows = tuple(sorted(artifacts))
    expected_outputs = tuple(ArtifactHashV0(path, "raw", raw_sha256(payload)) for path, payload in rows)
    root = validation_job_root_v0(job)
    expected_paths = {posixpath.join(root, name) for name in ("report.json", "rework_request.json", "state.json")}
    if (
        result.status != "PASS"
        or result.capability is not Capability.CONTENT_VALIDATION
        or result.outputs != expected_outputs
        or {path for path, _payload in rows} != expected_paths
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation terminal publication lacks matching PASS result")
    report_path = posixpath.join(root, "report.json")
    rework_path = posixpath.join(root, "rework_request.json")
    state = parse_canonical_json(dict(rows)[posixpath.join(root, "state.json")])
    report = parse_canonical_json(dict(rows)[report_path])
    rework = parse_canonical_json(dict(rows)[rework_path])
    if (
        state.get("job_id") != job.job_id
        or state.get("candidate_sha256") != job.candidate_sha256
        or state.get("report_sha256") != raw_sha256(dict(rows)[report_path])
        or state.get("rework_request_sha256") != raw_sha256(dict(rows)[rework_path])
        or report.get("job_id") != job.job_id
        or report.get("candidate_sha256") != job.candidate_sha256
        or report.get("rule_contract_sha256") != job.rule_contract_sha256
        or report.get("validator") != {
            "capability": job.validator.capability.value,
            "module_id": job.validator.module_id,
            "version": job.validator.version,
            "digest": job.validator.digest,
        }
        or rework.get("job_id") != job.job_id
        or rework.get("status") != state.get("status")
        or rework.get("candidate_sha256") != job.candidate_sha256
        or rework.get("report_sha256") != raw_sha256(dict(rows)[report_path])
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Validation terminal cross-binding drift")
    return _publish(
        store,
        context,
        operation_id,
        rows,
        {path: None for path, _payload in rows},
        lease,
        clock=clock,
        _failure_hook=_failure_hook,
    )


def content_locale_receipt_artifact_v0(receipt: ContentLocaleReceiptV0) -> tuple[str, bytes]:
    return posixpath.join("content", "locales", receipt.target_locale, "receipt.json"), canonical_json_bytes(receipt.as_dict())


def publish_content_locale_receipt_v0(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    operation_id: str,
    receipt: ContentLocaleReceiptV0,
    lease: WriteLeaseV0,
    *,
    clock: Callable[[], str],
    _failure_hook: Callable[[str], None] | None = None,
) -> PublicationGroupReceiptV0:
    if receipt.context_digest != context.context_digest:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Locale receipt belongs to another context")
    row = content_locale_receipt_artifact_v0(receipt)
    return _publish_file(
        store,
        context,
        operation_id,
        row,
        None,
        lease,
        clock=clock,
        _failure_hook=_failure_hook,
    )


def content_verified_artifacts_v0(
    verification: ContentVerificationSetV0,
    state_bytes: bytes,
) -> tuple[tuple[str, bytes], ...]:
    verification_bytes = canonical_json_bytes(verification.as_dict())
    state = parse_canonical_json(state_bytes)
    if (
        state.get("contract") != "locpipe.validation.content-state/v0"
        or state.get("state") != "CONTENT_VERIFIED"
        or state.get("context_digest") != verification.context_digest
        or state.get("scope_sha256") != verification.scope_sha256
        or state.get("verification_set_sha256") != raw_sha256(verification_bytes)
    ):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "CONTENT_VERIFIED state differs from verification set")
    return (
        ("content/content_verified.json", verification_bytes),
        ("content/state.json", bytes(state_bytes)),
    )


def publish_content_verified_v0(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    operation_id: str,
    verification: ContentVerificationSetV0,
    state_bytes: bytes,
    lease: WriteLeaseV0,
    *,
    clock: Callable[[], str],
    _failure_hook: Callable[[str], None] | None = None,
) -> PublicationGroupReceiptV0:
    if verification.context_digest != context.context_digest:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Content verification belongs to another context")
    rows = content_verified_artifacts_v0(verification, state_bytes)
    return _publish(
        store,
        context,
        operation_id,
        rows,
        {path: None for path, _payload in rows},
        lease,
        clock=clock,
        _failure_hook=_failure_hook,
    )
