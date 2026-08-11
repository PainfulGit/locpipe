from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any
import posixpath

from locpipe.content.v0 import (
    ScopeRoleV0,
    load_accepted_source_corpus_v0,
    validate_frozen_scope_artifacts_v0,
)
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

from ._models import (
    ProviderSubmissionReceiptV0,
    TranslationDecisionV0,
    TranslationJobStatusV0,
    TranslationJobV0,
    TranslationPacketV0,
    TranslationStateV0,
    TranslationTargetSetV0,
)
from ._packet import build_translation_job_v0
from ._serialization import (
    parse_reconciliation_v0,
    parse_submission_receipt_v0,
    parse_translation_job_v0,
    parse_translation_state_v0,
)


class _DomainReject(Exception):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code


def translation_job_root_v0(job: TranslationJobV0) -> str:
    token = job.job_id.removeprefix("translation-")[:20]
    return f"tr/j/{token}"


def translation_submission_root_v0(receipt: ProviderSubmissionReceiptV0) -> str:
    return translation_submission_root_from_digest_v0(submission_digest_v0(receipt))


def translation_submission_root_from_digest_v0(submission_sha256: str) -> str:
    if not isinstance(submission_sha256, str) or len(submission_sha256) != 64:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Submission digest is invalid")
    return f"tr/s/{submission_sha256[:20]}"


def translation_acceptance_output_declarations_v0(job: TranslationJobV0) -> tuple[ArtifactDeclarationV0, ...]:
    root = translation_job_root_v0(job)
    return tuple(ArtifactDeclarationV0(posixpath.join(root, name), "raw") for name in ("decision.json", "state.json", "target_set.json"))


def submission_digest_v0(receipt: ProviderSubmissionReceiptV0) -> str:
    return raw_sha256(canonical_json_bytes(receipt.as_dict()))


def _implementation(module: ModuleDescriptorV0) -> ImplementationRefV0:
    if not isinstance(module, ModuleDescriptorV0) or module.capability is not Capability.TRANSLATION:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation module has the wrong capability")
    return ImplementationRefV0("module", module.module_id, module.version, module.digest, Capability.TRANSLATION)


def _input_paths(job: TranslationJobV0, submission_sha: str, include_relations: bool) -> tuple[str, ...]:
    root = translation_job_root_v0(job)
    paths = [
        "corpus/segments.jsonl",
        "corpus/source_snapshot.json",
        "reconciliation/reconciliation.json",
        "scope/scope.json",
        "scope/scope_lock.json",
        "source/source_lock.json",
        posixpath.join(root, "job.json"),
        posixpath.join(root, "packet.json"),
        posixpath.join(root, "selection.json"),
        posixpath.join(root, "state.json"),
        posixpath.join(translation_submission_root_from_digest_v0(submission_sha), "output.json"),
        posixpath.join(translation_submission_root_from_digest_v0(submission_sha), "receipt.json"),
    ]
    if include_relations:
        paths.append("corpus/relations.jsonl")
    return tuple(sorted(paths))


def _target_identity(source: BranchIdentity, target_locale: str) -> BranchIdentity:
    return BranchIdentity(source.logical_id, target_locale, source.selector_path)


def _accept_targets(
    raw_output: bytes,
    job: TranslationJobV0,
    packet: TranslationPacketV0,
) -> TranslationTargetSetV0:
    try:
        value = parse_canonical_json(raw_output)
    except ContractViolation as error:
        raise _DomainReject("MALFORMED_PROVIDER_OUTPUT") from error
    if canonical_json_bytes(value) != raw_output:
        raise _DomainReject("NONCANONICAL_PROVIDER_OUTPUT")
    if not isinstance(value, Mapping) or set(value) != {"contract", "targets"} or value["contract"] != "locpipe.translation.provider-output/v0" or not isinstance(value["targets"], list):
        raise _DomainReject("MALFORMED_PROVIDER_OUTPUT")
    owned = {display_id(_target_identity(row.identity, job.target_locale)): row for row in packet.rows if row.role is ScopeRoleV0.OWNED}
    context = {display_id(_target_identity(row.identity, job.target_locale)) for row in packet.rows if row.role is ScopeRoleV0.CONTEXT}
    parsed: list[tuple[str, Mapping[str, Any]]] = []
    try:
        for envelope in value["targets"]:
            if not isinstance(envelope, Mapping):
                raise _DomainReject("MALFORMED_PROVIDER_OUTPUT")
            validate_envelope(envelope)
            if envelope.get("kind") != "target_branch":
                raise _DomainReject("MALFORMED_PROVIDER_OUTPUT")
            data = envelope["data"]
            identity = BranchIdentity.from_dict(data["identity"])
            key = display_id(identity)
            if key in context:
                raise _DomainReject("CONTEXT_TARGET")
            if identity.locale != job.target_locale:
                raise _DomainReject("TARGET_LOCALE_MISMATCH")
            source = owned.get(key)
            if source is None:
                raise _DomainReject("EXTRA_OR_SELECTOR_DRIFT")
            if data["content_type"] != source.content_type:
                raise _DomainReject("CONTENT_TYPE_MISMATCH")
            if data["metadata_ref"] is not None:
                raise _DomainReject("PROVIDER_METADATA_FORBIDDEN")
            parsed.append((key, envelope))
    except _DomainReject:
        raise
    except ContractViolation as error:
        raise _DomainReject("MALFORMED_PROVIDER_OUTPUT") from error
    keys = tuple(key for key, _row in parsed)
    if len(keys) != len(set(keys)):
        raise _DomainReject("DUPLICATE_TARGET")
    if keys != tuple(sorted(keys)):
        raise _DomainReject("NONCANONICAL_TARGET_ORDER")
    if set(keys) != set(owned):
        raise _DomainReject("MISSING_TARGET")
    decision_ref = posixpath.join(translation_job_root_v0(job), "decision.json")
    derived = []
    for _key, envelope in parsed:
        data = dict(envelope["data"])
        data["metadata_ref"] = decision_ref
        derived.append(canonical_json_bytes({
            "schema_id": KIND_TO_SCHEMA["target_branch"],
            "schema_version": CONTRACT_VERSION,
            "kind": "target_branch",
            "data": data,
        }))
    return TranslationTargetSetV0(job.job_id, job.invocation_id, job.target_locale, tuple(derived))


def _terminal_artifacts(
    job: TranslationJobV0,
    packet: TranslationPacketV0,
    receipt: ProviderSubmissionReceiptV0,
    raw_output: bytes,
) -> tuple[tuple[str, bytes], ...]:
    submission_sha = submission_digest_v0(receipt)
    try:
        target_set = _accept_targets(raw_output, job, packet)
        status = TranslationJobStatusV0.ACCEPTED
        reason = "ACCEPTED_EXACT_SCOPE"
    except _DomainReject as reject:
        target_set = TranslationTargetSetV0(job.job_id, job.invocation_id, job.target_locale, ())
        status = TranslationJobStatusV0.REJECTED
        reason = reject.reason_code
    target_bytes = canonical_json_bytes(target_set.as_dict())
    decision = TranslationDecisionV0(job.job_id, job.invocation_id, status, submission_sha, reason, len(target_set._target_bytes))
    decision_bytes = canonical_json_bytes(decision.as_dict())
    state = TranslationStateV0(
        job.job_id,
        job.invocation_id,
        status,
        submission_sha,
        raw_sha256(decision_bytes),
        raw_sha256(target_bytes),
    )
    root = translation_job_root_v0(job)
    return tuple(sorted((
        (posixpath.join(root, "decision.json"), decision_bytes),
        (posixpath.join(root, "state.json"), canonical_json_bytes(state.as_dict())),
        (posixpath.join(root, "target_set.json"), target_bytes),
    )))


def bind_translation_acceptance_v0(
    module: ModuleDescriptorV0,
    project_context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    expected_job: TranslationJobV0,
    expected_packet: TranslationPacketV0,
) -> tuple[ImplementationRefV0, OperationHandlerV0]:
    implementation = _implementation(module)

    def handler(request: OperationRequestV0, operation_context: OperationContextV0) -> ErrorRecord | None:
        try:
            if request.capability is not Capability.TRANSLATION:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation handler received wrong capability")
            if request.declared_outputs != translation_acceptance_output_declarations_v0(expected_job):
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Translation outputs differ from contract")
            root = translation_job_root_v0(expected_job)
            job_bytes = (operation_context.input_root / root / "job.json").read_bytes()
            packet_bytes = (operation_context.input_root / root / "packet.json").read_bytes()
            state_bytes = (operation_context.input_root / root / "state.json").read_bytes()
            job = parse_translation_job_v0(job_bytes)
            if job != expected_job or canonical_json_bytes(expected_job.as_dict()) != job_bytes:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation job drift")
            state = parse_translation_state_v0(state_bytes)
            if state.job_id != job.job_id or state.invocation_id != job.invocation_id or state.status is not TranslationJobStatusV0.RECEIVED:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation state is not selected RECEIVED")
            submission_sha = state.selected_submission_sha256
            assert submission_sha is not None
            selection = parse_canonical_json((operation_context.input_root / root / "selection.json").read_bytes())
            if selection != {
                "contract": "locpipe.translation.selection/v0",
                "job_id": job.job_id,
                "invocation_id": job.invocation_id,
                "submission_sha256": submission_sha,
            }:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation selection receipt drift")
            if tuple(row.path for row in request.inputs) != _input_paths(job, submission_sha, "corpus/relations.jsonl" in {row.path for row in request.inputs}):
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Translation inputs differ from contract")
            submission_root = operation_context.input_root / Path(*translation_submission_root_from_digest_v0(submission_sha).split("/"))
            raw_output = (submission_root / "output.json").read_bytes()
            receipt_bytes = (submission_root / "receipt.json").read_bytes()
            receipt = parse_submission_receipt_v0(receipt_bytes)
            if canonical_json_bytes(receipt.as_dict()) != receipt_bytes or submission_digest_v0(receipt) != submission_sha:
                raise ContractViolation(ErrorCode.HASH_MISMATCH, "Submission archive identity drift")
            if receipt != ProviderSubmissionReceiptV0(
                job.job_id, job.invocation_id, job.provider, receipt.provider_request_id,
                job.packet_sha256, job.output_contract_sha256, raw_sha256(raw_output),
            ):
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Provider submission is foreign or drifted")
            relations = "corpus/relations.jsonl" if (operation_context.input_root / "corpus/relations.jsonl").is_file() else None
            corpus = load_accepted_source_corpus_v0(
                operation_context.input_root,
                snapshot_path="corpus/source_snapshot.json",
                segments_path="corpus/segments.jsonl",
                relations_path=relations,
                source_lock_path="source/source_lock.json",
                expected_config_snapshot_sha256=resolved.config_snapshot_sha256,
            )
            reconciliation_bytes = (operation_context.input_root / "reconciliation/reconciliation.json").read_bytes()
            reconciliation = parse_reconciliation_v0(reconciliation_bytes)
            scope_bytes = (operation_context.input_root / "scope/scope.json").read_bytes()
            scope_lock_bytes = (operation_context.input_root / "scope/scope_lock.json").read_bytes()
            source_lock_bytes = (operation_context.input_root / "source/source_lock.json").read_bytes()
            scope = validate_frozen_scope_artifacts_v0(
                scope_bytes, scope_lock_bytes, corpus, reconciliation,
                source_lock_bytes=source_lock_bytes, reconciliation_bytes=reconciliation_bytes,
            )
            rebuilt_job, rebuilt_packet = build_translation_job_v0(
                project_context, resolved, corpus, reconciliation, scope,
                source_lock_bytes=source_lock_bytes,
                reconciliation_bytes=reconciliation_bytes,
                scope_bytes=scope_bytes,
                scope_lock_bytes=scope_lock_bytes,
                segments_bytes=(operation_context.input_root / "corpus/segments.jsonl").read_bytes(),
                target_locale=job.target_locale,
                budget=job.budget,
            )
            if rebuilt_job != job or rebuilt_packet != expected_packet or canonical_json_bytes(rebuilt_packet.as_dict()) != packet_bytes:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation packet or authority drift")
            for relative, payload in _terminal_artifacts(job, expected_packet, receipt, raw_output):
                path = operation_context.staging_root / Path(*relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            return None
        except ContractViolation as error:
            return error.record

    return implementation, handler
