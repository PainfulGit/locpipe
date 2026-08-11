from __future__ import annotations

import os
import tempfile
from pathlib import Path

from locpipe.contracts.v0 import (
    AdapterDescriptorV0,
    Capability,
    ContractViolation,
    ErrorCategory,
    ErrorCode,
    ErrorRecord,
    ImplementationRefV0,
    OperationContextV0,
    OperationHandlerV0,
    OperationRequestV0,
)
from locpipe.contracts.v0.artifacts import has_reparse_component, resolve_artifact_root

from ._corpus import validate_adapter_corpus_v0
from ._models import AdapterExtractContextV0, AdapterMapContextV0, AdapterProbeContextV0
from ._protocol import ReadOnlyAdapterV0


def _binding_error(detail: str) -> ErrorRecord:
    return ErrorRecord(ErrorCode.BINDING_MISMATCH, ErrorCategory.INTEGRITY, None, False, (), detail)


def _descriptor(adapter: ReadOnlyAdapterV0) -> AdapterDescriptorV0:
    value = adapter.descriptor
    if not isinstance(value, AdapterDescriptorV0):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Adapter descriptor has the wrong type")
    if Capability.EXTRACT_IMPORT not in value.capabilities:
        raise ContractViolation(ErrorCode.CAPABILITY_MISSING, "Adapter does not declare extract_import")
    return value


def _safe_clear_staging(staging_root: Path) -> None:
    root = resolve_artifact_root(staging_root)
    entries = sorted(root.rglob("*"), key=lambda path: len(path.parts), reverse=True)
    for entry in entries:
        if entry.is_symlink() or has_reparse_component(root, entry):
            raise ContractViolation(ErrorCode.PATH_ESCAPE, "Partial staging contains a link or reparse point")
        if not entry.is_file() and not entry.is_dir():
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Partial staging contains an unsupported entry")
    for entry in entries:
        if entry.is_dir():
            entry.rmdir()
        else:
            entry.unlink()


def _sanitized_exception(hook: str) -> ErrorRecord:
    return ErrorRecord(
        ErrorCode.HANDLER_EXCEPTION,
        ErrorCategory.INTERNAL,
        None,
        False,
        (),
        f"Adapter {hook} hook raised an unexpected exception",
    )


def _run_hook(adapter: ReadOnlyAdapterV0, hook: str, context: object) -> ErrorRecord | None:
    try:
        result = getattr(adapter, hook)(context)
    except Exception:
        return _sanitized_exception(hook)
    if result is not None and not isinstance(result, ErrorRecord):
        return ErrorRecord(
            ErrorCode.MALFORMED_ARTIFACT,
            ErrorCategory.CONTRACT,
            None,
            False,
            (),
            f"Adapter {hook} hook must return ErrorRecord or None",
        )
    return result


def bind_read_only_adapter_v0(
    adapter: ReadOnlyAdapterV0,
) -> tuple[ImplementationRefV0, OperationHandlerV0]:
    descriptor = _descriptor(adapter)
    frozen = AdapterDescriptorV0(
        descriptor.adapter_id,
        descriptor.version,
        descriptor.digest,
        tuple(descriptor.capabilities),
    )
    implementation = ImplementationRefV0(
        "adapter", frozen.adapter_id, frozen.version, frozen.digest, Capability.EXTRACT_IMPORT
    )

    def handler(request: OperationRequestV0, context: OperationContextV0) -> ErrorRecord | None:
        if request.capability is not Capability.EXTRACT_IMPORT:
            return _binding_error("Read-only adapter handler received the wrong capability")
        try:
            if _descriptor(adapter) != frozen:
                return _binding_error("Adapter descriptor drifted after binding")
            input_root = resolve_artifact_root(context.input_root)
            staging_root = resolve_artifact_root(context.staging_root)
            with tempfile.TemporaryDirectory(prefix="locpipe-adapter-work-") as directory:
                work_root = Path(os.path.abspath(directory)).resolve(strict=True)
                phases = (
                    ("probe", AdapterProbeContextV0(input_root)),
                    ("extract", AdapterExtractContextV0(input_root, work_root)),
                    ("map", AdapterMapContextV0(work_root, staging_root)),
                )
                for hook, hook_context in phases:
                    if _descriptor(adapter) != frozen:
                        outcome = _binding_error(f"Adapter descriptor drifted before {hook}")
                    else:
                        outcome = _run_hook(adapter, hook, hook_context)
                    if outcome is not None:
                        _safe_clear_staging(staging_root)
                        return outcome
                if _descriptor(adapter) != frozen:
                    _safe_clear_staging(staging_root)
                    return _binding_error("Adapter descriptor drifted after map")
                validate_adapter_corpus_v0(request, staging_root, frozen)
            return None
        except ContractViolation as error:
            try:
                _safe_clear_staging(context.staging_root)
            except ContractViolation as cleanup_error:
                return cleanup_error.record
            return error.record

    return implementation, handler
