from __future__ import annotations

import re
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .artifacts import (
    HashVerifier,
    artifact_sha256,
    has_reparse_component,
    has_reparse_in_path,
    resolve_artifact_root,
    resolve_existing_artifact,
    validate_relative_posix_path,
    verify_artifact_hashes,
)
from .canonical import semantic_sha256
from .errors import ContractViolation, ErrorCategory, ErrorCode, ErrorRecord
from .profiles import Capability, EXACT_VERSION_RE, SHA256_RE


OPERATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HASH_DOMAINS = {"raw", "semantic", "directory_manifest"}


def _exact(value: Mapping[str, Any], fields: set[str], name: str) -> None:
    if set(value) != fields:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Invalid {name} fields")


def _sorted_unique_paths(rows: Sequence[object], name: str) -> None:
    paths = [getattr(row, "path") for row in rows]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, f"{name} paths must be unique and sorted")


def _reject_path_overlaps(rows: Sequence[object], name: str) -> None:
    paths = [getattr(row, "path") for row in rows]
    for left in paths:
        for right in paths:
            if left != right and right.startswith(left + "/"):
                raise ContractViolation(
                    ErrorCode.OUTPUT_CONTRACT_VIOLATION,
                    f"{name} paths overlap: {left} and {right}",
                )


@dataclass(frozen=True)
class ArtifactHashV0:
    path: str
    hash_domain: str
    sha256: str

    def __post_init__(self) -> None:
        validate_relative_posix_path(self.path)
        if self.hash_domain not in HASH_DOMAINS:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Unknown artifact hash domain")
        if not isinstance(self.sha256, str) or not SHA256_RE.fullmatch(self.sha256):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Artifact SHA must be lowercase SHA-256")

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "hash_domain": self.hash_domain, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ArtifactHashV0":
        _exact(value, {"path", "hash_domain", "sha256"}, "artifact hash")
        return cls(value["path"], value["hash_domain"], value["sha256"])


@dataclass(frozen=True)
class ArtifactDeclarationV0:
    path: str
    hash_domain: str

    def __post_init__(self) -> None:
        validate_relative_posix_path(self.path)
        if self.hash_domain not in HASH_DOMAINS:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Unknown artifact hash domain")

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "hash_domain": self.hash_domain}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ArtifactDeclarationV0":
        _exact(value, {"path", "hash_domain"}, "artifact declaration")
        return cls(value["path"], value["hash_domain"])


@dataclass(frozen=True)
class ImplementationRefV0:
    owner_kind: str
    implementation_id: str
    version: str
    digest: str
    capability: Capability

    def __post_init__(self) -> None:
        if self.owner_kind not in {"adapter", "module"}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Unknown implementation owner kind")
        if not isinstance(self.implementation_id, str) or not self.implementation_id:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Implementation ID must be non-empty")
        if not isinstance(self.version, str) or not EXACT_VERSION_RE.fullmatch(self.version):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Implementation version must be exact SemVer")
        if not isinstance(self.digest, str) or not SHA256_RE.fullmatch(self.digest):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Implementation digest must be SHA-256")
        if not isinstance(self.capability, Capability):
            raise ContractViolation(ErrorCode.CAPABILITY_UNKNOWN, "Implementation capability is unknown")

    def as_dict(self) -> dict[str, str]:
        return {
            "owner_kind": self.owner_kind,
            "implementation_id": self.implementation_id,
            "version": self.version,
            "digest": self.digest,
            "capability": self.capability.value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ImplementationRefV0":
        _exact(value, {"owner_kind", "implementation_id", "version", "digest", "capability"}, "implementation")
        try:
            capability = Capability(value["capability"])
        except (TypeError, ValueError) as error:
            raise ContractViolation(ErrorCode.CAPABILITY_UNKNOWN, "Implementation capability is unknown") from error
        return cls(value["owner_kind"], value["implementation_id"], value["version"], value["digest"], capability)


@dataclass(frozen=True)
class OperationRequestV0:
    operation_id: str
    capability: Capability
    binding_sha256: str
    inputs: tuple[ArtifactHashV0, ...]
    declared_outputs: tuple[ArtifactDeclarationV0, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, str) or not OPERATION_ID_RE.fullmatch(self.operation_id):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid operation ID")
        if not isinstance(self.capability, Capability):
            raise ContractViolation(ErrorCode.CAPABILITY_UNKNOWN, "Operation capability is unknown")
        if not isinstance(self.binding_sha256, str) or not SHA256_RE.fullmatch(self.binding_sha256):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "binding_sha256 must be lowercase SHA-256")
        _sorted_unique_paths(self.inputs, "Input")
        _sorted_unique_paths(self.declared_outputs, "Declared output")
        _reject_path_overlaps(self.inputs, "Input")
        _reject_path_overlaps(self.declared_outputs, "Declared output")

    def as_data(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "capability": self.capability.value,
            "binding_sha256": self.binding_sha256,
            "inputs": [row.as_dict() for row in self.inputs],
            "declared_outputs": [row.as_dict() for row in self.declared_outputs],
        }

    def as_envelope(self) -> dict[str, Any]:
        from .constants import CONTRACT_VERSION, KIND_TO_SCHEMA

        return {
            "schema_id": KIND_TO_SCHEMA["operation_request"],
            "schema_version": CONTRACT_VERSION,
            "kind": "operation_request",
            "data": self.as_data(),
        }

    @classmethod
    def from_data(cls, value: Mapping[str, Any]) -> "OperationRequestV0":
        _exact(value, {"operation_id", "capability", "binding_sha256", "inputs", "declared_outputs"}, "operation request")
        if not isinstance(value["inputs"], list) or not isinstance(value["declared_outputs"], list):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Operation artifacts must be lists")
        try:
            capability = Capability(value["capability"])
        except (TypeError, ValueError) as error:
            raise ContractViolation(ErrorCode.CAPABILITY_UNKNOWN, "Operation capability is unknown") from error
        return cls(
            value["operation_id"],
            capability,
            value["binding_sha256"],
            tuple(ArtifactHashV0.from_dict(row) for row in value["inputs"]),
            tuple(ArtifactDeclarationV0.from_dict(row) for row in value["declared_outputs"]),
        )


@dataclass(frozen=True)
class OperationResultV0:
    operation_id: str
    capability: Capability
    request_sha256: str
    binding_sha256: str
    implementation: ImplementationRefV0
    status: str
    outputs: tuple[ArtifactHashV0, ...]
    error: ErrorRecord | None

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, str) or not OPERATION_ID_RE.fullmatch(self.operation_id):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid operation ID")
        for value, name in ((self.request_sha256, "request_sha256"), (self.binding_sha256, "binding_sha256")):
            if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be lowercase SHA-256")
        if self.implementation.capability is not self.capability:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Result capability differs from implementation")
        _sorted_unique_paths(self.outputs, "Output")
        if self.status == "PASS" and (self.error is not None):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "PASS result cannot contain an error")
        if self.status == "FAIL" and (self.error is None or self.outputs):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "FAIL result requires one error and no outputs")
        if self.status not in {"PASS", "FAIL"}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Unknown operation result status")

    def as_data(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "capability": self.capability.value,
            "request_sha256": self.request_sha256,
            "binding_sha256": self.binding_sha256,
            "implementation": self.implementation.as_dict(),
            "status": self.status,
            "outputs": [row.as_dict() for row in self.outputs],
            "error": None if self.error is None else self.error.as_dict(),
        }

    def as_envelope(self) -> dict[str, Any]:
        from .constants import CONTRACT_VERSION, KIND_TO_SCHEMA

        return {
            "schema_id": KIND_TO_SCHEMA["operation_result"],
            "schema_version": CONTRACT_VERSION,
            "kind": "operation_result",
            "data": self.as_data(),
        }

    @classmethod
    def from_data(cls, value: Mapping[str, Any]) -> "OperationResultV0":
        _exact(
            value,
            {"operation_id", "capability", "request_sha256", "binding_sha256", "implementation", "status", "outputs", "error"},
            "operation result",
        )
        if not isinstance(value["outputs"], list) or not isinstance(value["implementation"], Mapping):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid operation result collections")
        try:
            capability = Capability(value["capability"])
        except (TypeError, ValueError) as error:
            raise ContractViolation(ErrorCode.CAPABILITY_UNKNOWN, "Operation capability is unknown") from error
        raw_error = value["error"]
        if raw_error is not None and not isinstance(raw_error, Mapping):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Operation error must be an object or null")
        return cls(
            value["operation_id"],
            capability,
            value["request_sha256"],
            value["binding_sha256"],
            ImplementationRefV0.from_dict(value["implementation"]),
            value["status"],
            tuple(ArtifactHashV0.from_dict(row) for row in value["outputs"]),
            None if raw_error is None else ErrorRecord.from_dict(raw_error),
        )


@dataclass(frozen=True)
class OperationContextV0:
    input_root: Path
    staging_root: Path


class OperationHandlerV0(Protocol):
    def __call__(self, request: OperationRequestV0, context: OperationContextV0) -> ErrorRecord | None: ...


def resolve_implementation(binding_envelope: Mapping[str, Any], capability: Capability) -> ImplementationRefV0:
    from .validation import validate_envelope

    validate_envelope(binding_envelope)
    if binding_envelope["kind"] != "binding_set":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Capability resolution requires a binding_set")
    data = binding_envelope["data"]
    adapter = data["adapter"]
    if capability.value in adapter["capabilities"]:
        return ImplementationRefV0("adapter", adapter["adapter_id"], adapter["version"], adapter["digest"], capability)
    for module in data["modules"]:
        if module["capability"] == capability.value:
            return ImplementationRefV0("module", module["module_id"], module["version"], module["digest"], capability)
    raise ContractViolation(
        ErrorCode.CAPABILITY_MISSING,
        f"Capability {capability.value} has no pinned implementation",
        category=ErrorCategory.CONFIGURATION,
        safe_to_resume=True,
    )


def _protected_snapshot(paths: Sequence[Path]) -> dict[Path, tuple[Path, str]]:
    snapshot: dict[Path, tuple[Path, str]] = {}
    for path in paths:
        lexical = Path(os.path.abspath(path))
        if has_reparse_in_path(lexical):
            raise ContractViolation(ErrorCode.PROTECTED_PATH_DRIFT, f"Protected path crosses a symlink or reparse point: {path}")
        try:
            resolved = lexical.resolve(strict=True)
        except OSError as error:
            raise ContractViolation(ErrorCode.PROTECTED_PATH_DRIFT, f"Protected path is missing: {path}") from error
        if not resolved.is_file():
            raise ContractViolation(ErrorCode.PROTECTED_PATH_DRIFT, f"Protected path is not a regular file: {path}")
        snapshot[lexical] = (resolved, artifact_sha256(resolved, "raw"))
    return snapshot


def _assert_protected_unchanged(snapshot: Mapping[Path, tuple[Path, str]]) -> None:
    for lexical, (original_target, expected) in snapshot.items():
        try:
            if has_reparse_in_path(lexical):
                raise OSError("protected path became a symlink or reparse point")
            current_target = lexical.resolve(strict=True)
            if current_target != original_target or not current_target.is_file():
                raise OSError("protected path changed target or type")
            actual = artifact_sha256(current_target, "raw")
        except (OSError, ContractViolation) as error:
            raise ContractViolation(
                ErrorCode.PROTECTED_PATH_DRIFT,
                f"Protected path disappeared or changed type: {lexical}",
                category=ErrorCategory.INTEGRITY,
            ) from error
        if actual != expected:
            raise ContractViolation(
                ErrorCode.PROTECTED_PATH_DRIFT,
                f"Protected path changed during handler execution: {lexical}",
                category=ErrorCategory.INTEGRITY,
            )


def _copy_declared_input(source: Path, destination: Path) -> None:
    if source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
        return
    if not source.is_dir():
        raise ContractViolation(ErrorCode.PATH_ESCAPE, f"Unsupported declared input type: {source}")
    destination.mkdir(parents=True, exist_ok=True)
    for candidate in source.rglob("*"):
        if candidate.is_symlink() or has_reparse_component(source, candidate):
            raise ContractViolation(ErrorCode.PATH_ESCAPE, f"Declared input contains a symlink or reparse point: {candidate}")
        relative = candidate.relative_to(source)
        output = destination / relative
        if candidate.is_dir():
            output.mkdir(parents=True, exist_ok=True)
        elif candidate.is_file():
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(candidate.read_bytes())
        else:
            raise ContractViolation(ErrorCode.PATH_ESCAPE, f"Unsupported declared input entry: {candidate}")


def _materialize_input_view(
    request: OperationRequestV0,
    input_root: Path,
    view_root: Path,
    *,
    hash_verifiers: Mapping[str, HashVerifier] | None,
) -> Path:
    resolved_view = resolve_artifact_root(view_root, require_empty=True)
    for row in request.inputs:
        source = resolve_existing_artifact(input_root, row.path)
        destination = resolved_view / Path(*row.path.split("/"))
        _copy_declared_input(source, destination)
    verify_artifact_hashes(request.inputs, artifact_root=resolved_view, hash_verifiers=hash_verifiers)
    return resolved_view


def _verified_outputs(
    request: OperationRequestV0,
    staging_root: Path,
    *,
    hash_verifiers: Mapping[str, HashVerifier] | None,
) -> tuple[ArtifactHashV0, ...]:
    declared = {row.path: row for row in request.declared_outputs}
    allowed_parents = {""}
    for path in declared:
        parts = path.split("/")[:-1]
        allowed_parents.update("/".join(parts[:index]) for index in range(1, len(parts) + 1))
    for left in declared:
        for right in declared:
            if left != right and right.startswith(left + "/"):
                raise ContractViolation(
                    ErrorCode.OUTPUT_CONTRACT_VIOLATION,
                    f"Declared outputs overlap: {left} and {right}",
                )
    resolved_declarations: dict[str, Path] = {}
    directory_outputs: set[str] = set()
    for relative, declaration in declared.items():
        path = resolve_existing_artifact(staging_root, relative)
        if declaration.hash_domain == "directory_manifest":
            if not path.is_dir():
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, f"Directory output is not a directory: {relative}")
            directory_outputs.add(relative)
        elif not path.is_file():
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, f"Output is not a file: {relative}")
        resolved_declarations[relative] = path
    for candidate in staging_root.rglob("*"):
        relative = candidate.relative_to(staging_root).as_posix()
        if candidate.is_symlink() or has_reparse_component(staging_root, candidate):
            raise ContractViolation(ErrorCode.PATH_ESCAPE, f"Staged output crosses a symlink or reparse point: {relative}")
        if not candidate.is_file() and not candidate.is_dir():
            raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, f"Unsupported staging entry: {relative}")
        if relative in allowed_parents or relative in declared:
            continue
        if any(relative.startswith(root + "/") for root in directory_outputs):
            continue
        raise ContractViolation(
            ErrorCode.OUTPUT_CONTRACT_VIOLATION,
            f"Undeclared staging entry: {relative}",
            category=ErrorCategory.INTEGRITY,
        )
    outputs = []
    for relative, declaration in sorted(declared.items()):
        path = resolved_declarations[relative]
        outputs.append(ArtifactHashV0(relative, declaration.hash_domain, artifact_sha256(path, declaration.hash_domain, hash_verifiers=hash_verifiers)))
    return tuple(outputs)


def execute_bound_operation(
    request_envelope: Mapping[str, Any],
    binding_envelope: Mapping[str, Any],
    *,
    handlers: Mapping[ImplementationRefV0, OperationHandlerV0],
    input_root: Path,
    staging_root: Path,
    hash_verifiers: Mapping[str, HashVerifier] | None = None,
    protected_paths: Sequence[Path] = (),
) -> Mapping[str, Any]:
    from .validation import validate_envelope

    validate_envelope(request_envelope)
    if request_envelope["kind"] != "operation_request":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Execution requires an operation_request")
    request = OperationRequestV0.from_data(request_envelope["data"])
    actual_binding_sha = semantic_sha256(binding_envelope)
    if actual_binding_sha != request.binding_sha256:
        raise ContractViolation(
            ErrorCode.BINDING_MISMATCH,
            "Operation request is not bound to the supplied binding_set",
            category=ErrorCategory.INTEGRITY,
        )
    implementation = resolve_implementation(binding_envelope, request.capability)
    handler = handlers.get(implementation)
    if handler is None:
        raise ContractViolation(
            ErrorCode.BINDING_MISMATCH,
            "Pinned implementation is not present in the explicit handler registry",
            category=ErrorCategory.CONFIGURATION,
            safe_to_resume=True,
        )
    resolved_input = resolve_artifact_root(input_root)
    resolved_staging = resolve_artifact_root(staging_root, require_empty=True)
    verify_artifact_hashes(request.inputs, artifact_root=resolved_input, hash_verifiers=hash_verifiers)
    protected = _protected_snapshot(tuple(protected_paths))
    with tempfile.TemporaryDirectory(prefix="locpipe-input-") as directory:
        input_view = _materialize_input_view(
            request,
            resolved_input,
            Path(directory),
            hash_verifiers=hash_verifiers,
        )
        context = OperationContextV0(input_view, resolved_staging)
        try:
            outcome = handler(request, context)
        except Exception as error:  # trusted adapter boundary; never expose a traceback in the contract
            outcome = ErrorRecord(
                ErrorCode.HANDLER_EXCEPTION,
                ErrorCategory.INTERNAL,
                None,
                False,
                (),
                f"Handler raised {type(error).__name__}",
            )
        _assert_protected_unchanged(protected)
        if resolve_artifact_root(resolved_staging) != resolved_staging:
            raise ContractViolation(ErrorCode.PATH_ESCAPE, "Staging root changed during handler execution")
        if resolve_artifact_root(resolved_input) != resolved_input:
            raise ContractViolation(ErrorCode.PATH_ESCAPE, "Original input root changed during handler execution")
        if resolve_artifact_root(input_view) != input_view:
            raise ContractViolation(ErrorCode.PATH_ESCAPE, "Input view changed during handler execution")
        verify_artifact_hashes(request.inputs, artifact_root=resolved_input, hash_verifiers=hash_verifiers)
        verify_artifact_hashes(request.inputs, artifact_root=input_view, hash_verifiers=hash_verifiers)
        request_sha = semantic_sha256(request_envelope)
        if outcome is not None:
            if not isinstance(outcome, ErrorRecord):
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Handler must return ErrorRecord or None")
            result = OperationResultV0(
                request.operation_id,
                request.capability,
                request_sha,
                request.binding_sha256,
                implementation,
                "FAIL",
                (),
                outcome,
            )
        else:
            outputs = _verified_outputs(request, resolved_staging, hash_verifiers=hash_verifiers)
            result = OperationResultV0(
                request.operation_id,
                request.capability,
                request_sha,
                request.binding_sha256,
                implementation,
                "PASS",
                outputs,
                None,
            )
    envelope = result.as_envelope()
    validate_envelope(envelope)
    return envelope
