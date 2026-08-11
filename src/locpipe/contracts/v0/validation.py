from __future__ import annotations

import re
import hashlib
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .canonical import semantic_sha256
from .constants import CONTRACT_VERSION, KIND_TO_SCHEMA
from .errors import ContractViolation, ErrorCategory, ErrorCode
from .identity import BranchIdentity, source_revision_sha
from .profiles import (
    AdapterDescriptorV0,
    Capability,
    ModuleDescriptorV0,
    WorkflowProfile,
    parse_capabilities,
    validate_module_bindings,
    validate_profile,
)


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _object(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be an object")
    return value


def _exact(value: Mapping[str, Any], fields: set[str], name: str) -> None:
    if set(value) != fields:
        missing = sorted(fields - set(value))
        unknown = sorted(set(value) - fields)
        raise ContractViolation(
            ErrorCode.MALFORMED_ARTIFACT,
            f"{name} fields differ; missing={missing}, unknown={unknown}",
        )


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be lowercase SHA-256")
    return value


def _strings(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be a list of non-empty strings")
    return value


def _validate_source_branch(data: Mapping[str, Any]) -> BranchIdentity:
    _exact(
        data,
        {"identity", "content_type", "payload", "constraints", "source_revision_sha", "locator"},
        "source_branch",
    )
    identity = BranchIdentity.from_dict(_object(data["identity"], "identity"))
    if not isinstance(data["content_type"], str) or not data["content_type"]:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "content_type must be non-empty")
    constraints = _object(data["constraints"], "constraints")
    _object(data["locator"], "locator")
    expected = source_revision_sha(
        identity=identity,
        content_type=data["content_type"],
        payload=data["payload"],
        constraints=constraints,
    )
    if _sha(data["source_revision_sha"], "source_revision_sha") != expected:
        raise ContractViolation(
            ErrorCode.HASH_MISMATCH,
            "source_revision_sha does not match the semantic branch projection",
            category=ErrorCategory.INTEGRITY,
        )
    return identity


def _validate_target_branch(data: Mapping[str, Any]) -> BranchIdentity:
    _exact(
        data,
        {"identity", "source_logical_id", "content_type", "payload", "metadata_ref"},
        "target_branch",
    )
    identity = BranchIdentity.from_dict(_object(data["identity"], "identity"))
    source_logical = _strings(data["source_logical_id"], "source_logical_id")
    if tuple(source_logical) != identity.logical_id:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "target branch must reference its logical message")
    if not isinstance(data["content_type"], str) or not data["content_type"]:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "content_type must be non-empty")
    if data["metadata_ref"] is not None and not isinstance(data["metadata_ref"], str):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "metadata_ref must be string or null")
    return identity


def _descriptor(value: Mapping[str, Any]) -> AdapterDescriptorV0:
    _exact(value, {"adapter_id", "version", "digest", "capabilities"}, "adapter descriptor")
    raw_capabilities = _strings(value["capabilities"], "capabilities")
    parsed = parse_capabilities(raw_capabilities)
    ordered = tuple(sorted(parsed, key=lambda item: item.value))
    if raw_capabilities != [capability.value for capability in ordered]:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Adapter capabilities must be sorted")
    return AdapterDescriptorV0(value["adapter_id"], value["version"], value["digest"], ordered)


def _validate_source_snapshot(data: Mapping[str, Any]) -> None:
    _exact(
        data,
        {"snapshot_id", "source_locale", "source_version", "source_raw_sha256", "adapter", "branch_ids"},
        "source_snapshot",
    )
    for field in ("snapshot_id", "source_locale", "source_version"):
        if not isinstance(data[field], str) or not data[field]:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{field} must be non-empty")
    _sha(data["source_raw_sha256"], "source_raw_sha256")
    _descriptor(_object(data["adapter"], "adapter"))
    ids = _strings(data["branch_ids"], "branch_ids")
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "branch_ids must be unique and sorted")
    from .identity import parse_display_id

    for branch_id in ids:
        if parse_display_id(branch_id).locale != data["source_locale"]:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Snapshot branch locale differs from source_locale")


def _relation_ref(value: Mapping[str, Any]) -> tuple[str, Any]:
    kind = value.get("kind")
    if kind == "locale":
        _exact(value, {"kind", "locale"}, "locale relation reference")
        if not isinstance(value["locale"], str) or not value["locale"]:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "locale reference must be non-empty")
        return "locale", value["locale"]
    if kind == "branch":
        _exact(value, {"kind", "identity"}, "branch relation reference")
        return "branch", BranchIdentity.from_dict(_object(value["identity"], "relation identity"))
    if kind == "logical_message":
        _exact(value, {"kind", "logical_id"}, "logical relation reference")
        return "logical_message", tuple(_strings(value["logical_id"], "logical_id"))
    raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Unknown relation reference kind {kind!r}")


def _validate_relation(data: Mapping[str, Any]) -> tuple[tuple[str, Any], tuple[str, Any]]:
    _exact(data, {"relation_type", "from_ref", "to_ref"}, "relation")
    if not isinstance(data["relation_type"], str) or not data["relation_type"]:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "relation_type must be non-empty")
    return (
        _relation_ref(_object(data["from_ref"], "from_ref")),
        _relation_ref(_object(data["to_ref"], "to_ref")),
    )


TERMINAL_STATES = {
    WorkflowProfile.CONTENT_ONLY: "CONTENT_VERIFIED",
    WorkflowProfile.ARTIFACT_BUILD: "ARTIFACT_VERIFIED",
    WorkflowProfile.INSTALLED_PATCH: "INSTALLED_VERIFIED",
}


def _validate_workflow_profile(data: Mapping[str, Any]) -> None:
    _exact(data, {"profile", "available_capabilities", "disabled_optional", "terminal_state"}, "workflow_profile")
    try:
        profile = WorkflowProfile(data["profile"])
    except ValueError as error:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Unknown workflow profile {data['profile']!r}") from error
    available_raw = _strings(data["available_capabilities"], "available_capabilities")
    disabled_raw = _strings(data["disabled_optional"], "disabled_optional")
    for values, name in ((available_raw, "available_capabilities"), (disabled_raw, "disabled_optional")):
        parsed = parse_capabilities(values)
        if values != sorted(capability.value for capability in parsed):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{name} must be unique and sorted")
    validate_profile(
        profile,
        available_raw,
        disabled_optional=disabled_raw,
    )
    if data["terminal_state"] != TERMINAL_STATES[profile]:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "terminal_state does not match workflow profile")


def _validate_binding_set(data: Mapping[str, Any]) -> None:
    _exact(data, {"adapter", "modules"}, "binding_set")
    adapter = _descriptor(_object(data["adapter"], "adapter"))
    if not isinstance(data["modules"], list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "modules must be a list")
    modules = []
    for value in data["modules"]:
        row = _object(value, "module")
        _exact(row, {"capability", "module_id", "version", "digest"}, "module")
        try:
            capability = Capability(row["capability"])
        except ValueError as error:
            raise ContractViolation(ErrorCode.CAPABILITY_UNKNOWN, f"Unknown capability {row['capability']!r}") from error
        modules.append(ModuleDescriptorV0(capability, row["module_id"], row["version"], row["digest"]))
    validated_modules = validate_module_bindings(modules)
    overlap = set(adapter.capabilities) & {module.capability for module in validated_modules}
    if overlap:
        raise ContractViolation(
            ErrorCode.DUPLICATE_IDENTITY,
            f"Capability has both adapter and module owners: {sorted(item.value for item in overlap)}",
        )


def validate_profile_bindings(
    profile_envelope: Mapping[str, Any],
    binding_envelope: Mapping[str, Any],
) -> tuple[Capability, ...]:
    if profile_envelope.get("kind") != "workflow_profile" or binding_envelope.get("kind") != "binding_set":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Joint validation requires profile and binding envelopes")
    validate_envelope(profile_envelope)
    validate_envelope(binding_envelope)
    profile_data = _object(profile_envelope["data"], "profile data")
    binding_data = _object(binding_envelope["data"], "binding data")
    adapter = _descriptor(_object(binding_data["adapter"], "adapter"))
    effective = set(adapter.capabilities)
    for raw_module in binding_data["modules"]:
        module = _object(raw_module, "module")
        try:
            capability = Capability(module["capability"])
        except ValueError as error:
            raise ContractViolation(ErrorCode.CAPABILITY_UNKNOWN, f"Unknown capability {module['capability']!r}") from error
        if capability in effective:
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, f"Capability {capability.value} has multiple pinned owners")
        effective.add(capability)
    claimed = parse_capabilities(_strings(profile_data["available_capabilities"], "available_capabilities"))
    if claimed != effective:
        raise ContractViolation(
            ErrorCode.HASH_MISMATCH,
            "Workflow capability claims differ from pinned adapter/module bindings",
            category=ErrorCategory.INTEGRITY,
        )
    return validate_profile(
        profile_data["profile"],
        effective,
        disabled_optional=_strings(profile_data["disabled_optional"], "disabled_optional"),
    )


def _validate_receipt(data: Mapping[str, Any]) -> None:
    _exact(data, {"operation", "inputs", "outputs", "contract_sha256", "status"}, "receipt")
    if not isinstance(data["operation"], str) or not data["operation"]:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "receipt operation must be non-empty")
    for field in ("inputs", "outputs"):
        rows = data[field]
        if not isinstance(rows, list):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"{field} must be a list")
        paths = []
        for row_value in rows:
            row = _object(row_value, field)
            _exact(row, {"path", "hash_domain", "sha256"}, field)
            path = row["path"]
            parts = path.split("/") if isinstance(path, str) else []
            if (
                not isinstance(path, str)
                or not path
                or "\\" in path
                or path.startswith("/")
                or (len(path) >= 2 and path[1] == ":")
                or any(part in {"", ".", ".."} for part in parts)
            ):
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, f"Invalid relative POSIX path {path!r}")
            if row["hash_domain"] not in {"raw", "semantic", "directory_manifest"}:
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Unknown receipt hash domain")
            _sha(row["sha256"], "artifact sha256")
            paths.append(path)
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, f"{field} paths must be unique and sorted")
    _sha(data["contract_sha256"], "contract_sha256")
    if data["status"] not in {"PASS", "FAIL", "SKIPPED_WITH_RECEIPT"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Unknown receipt status")


def _validate_error(data: Mapping[str, Any]) -> None:
    _exact(data, {"code", "category", "artifact", "safe_to_resume", "next_commands", "detail"}, "error")
    from .errors import ErrorCategory, ErrorCode

    try:
        ErrorCode(data["code"])
        ErrorCategory(data["category"])
    except ValueError as error:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Unknown structured error value") from error
    if data["artifact"] is not None and not isinstance(data["artifact"], str):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "artifact must be string or null")
    if not isinstance(data["safe_to_resume"], bool):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "safe_to_resume must be boolean")
    if not isinstance(data["next_commands"], list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "next_commands must be a list")
    _strings(data["next_commands"], "next_commands") if data["next_commands"] else []
    if not isinstance(data["detail"], str) or not data["detail"]:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "detail must be non-empty")


def _validate_operation_request(data: Mapping[str, Any]) -> None:
    from .interfaces import OperationRequestV0

    OperationRequestV0.from_data(data)


def _validate_operation_result(data: Mapping[str, Any]) -> None:
    from .interfaces import OperationResultV0

    OperationResultV0.from_data(data)


def _has_reparse_component(root: Path, target: Path) -> bool:
    current = root
    relative = target.relative_to(root)
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
        try:
            attributes = getattr(os.lstat(current), "st_file_attributes", 0)
        except OSError:
            return True
        if attributes & getattr(os.stat_result, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            return True
    return False


def verify_receipt_artifacts(
    value: Mapping[str, Any],
    *,
    artifact_root: Path,
    hash_verifiers: Mapping[str, Any] | None = None,
) -> int:
    if value.get("kind") != "receipt":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Artifact verification requires a receipt envelope")
    data = _object(value.get("data"), "receipt data")
    _validate_receipt(data)
    try:
        root = artifact_root.resolve(strict=True)
    except OSError as error:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Artifact root does not exist") from error
    verifiers = dict(hash_verifiers or {})
    checked = 0
    for group in ("inputs", "outputs"):
        for row in data[group]:
            relative = Path(*row["path"].split("/"))
            candidate = root / relative
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, ValueError) as error:
                raise ContractViolation(
                    ErrorCode.HASH_MISMATCH,
                    f"Receipt artifact is missing or escapes root: {row['path']}",
                    category=ErrorCategory.INTEGRITY,
                ) from error
            if _has_reparse_component(root, candidate):
                raise ContractViolation(
                    ErrorCode.HASH_MISMATCH,
                    f"Receipt artifact crosses a symlink or reparse point: {row['path']}",
                    category=ErrorCategory.INTEGRITY,
                )
            domain = row["hash_domain"]
            if domain == "raw":
                if not resolved.is_file():
                    raise ContractViolation(ErrorCode.HASH_MISMATCH, f"Raw artifact is not a file: {row['path']}")
                actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
            else:
                verifier = verifiers.get(domain)
                if not callable(verifier):
                    raise ContractViolation(
                        ErrorCode.MALFORMED_ARTIFACT,
                        f"No fail-closed verifier registered for {domain}",
                    )
                actual = verifier(resolved)
            if actual != row["sha256"]:
                raise ContractViolation(
                    ErrorCode.HASH_MISMATCH,
                    f"Receipt SHA mismatch for {row['path']}",
                    category=ErrorCategory.INTEGRITY,
                )
            checked += 1
    return checked


def validate_envelope(
    value: Mapping[str, Any],
    *,
    artifact_root: Path | None = None,
    hash_verifiers: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    _exact(value, {"schema_id", "schema_version", "kind", "data"}, "contract envelope")
    kind = value["kind"]
    if kind not in KIND_TO_SCHEMA:
        raise ContractViolation(ErrorCode.SCHEMA_UNKNOWN, f"Unknown contract kind {kind!r}")
    if value["schema_id"] != KIND_TO_SCHEMA[kind]:
        raise ContractViolation(ErrorCode.SCHEMA_UNKNOWN, "schema_id does not match contract kind")
    if value["schema_version"] != CONTRACT_VERSION:
        raise ContractViolation(ErrorCode.SCHEMA_VERSION_UNSUPPORTED, f"Unsupported schema version {value['schema_version']!r}")
    data = _object(value["data"], "data")
    validators = {
        "source_branch": _validate_source_branch,
        "target_branch": _validate_target_branch,
        "source_snapshot": _validate_source_snapshot,
        "relation": _validate_relation,
        "workflow_profile": _validate_workflow_profile,
        "binding_set": _validate_binding_set,
        "receipt": _validate_receipt,
        "error": _validate_error,
        "operation_request": _validate_operation_request,
        "operation_result": _validate_operation_result,
    }
    validators[kind](data)
    if kind == "receipt" and data["status"] == "PASS":
        if artifact_root is None:
            raise ContractViolation(
                ErrorCode.MALFORMED_ARTIFACT,
                "PASS receipt requires context-aware artifact verification",
            )
        verify_receipt_artifacts(value, artifact_root=artifact_root, hash_verifiers=hash_verifiers)
    return value


def validate_relation_set(
    relations: Iterable[Mapping[str, Any]],
    *,
    branch_identities: Iterable[BranchIdentity],
    locales: Iterable[str],
) -> int:
    branches = set(branch_identities)
    logical = {branch.logical_id for branch in branches}
    known_locales = set(locales)
    count = 0
    for envelope in relations:
        validate_envelope(envelope)
        left, right = _validate_relation(_object(envelope["data"], "relation data"))
        for kind, reference in (left, right):
            present = (
                reference in known_locales if kind == "locale" else
                reference in branches if kind == "branch" else
                reference in logical
            )
            if not present:
                raise ContractViolation(
                    ErrorCode.DANGLING_RELATION,
                    f"Dangling {kind} relation endpoint",
                    category=ErrorCategory.INTEGRITY,
                )
        count += 1
    return count


def envelope_semantic_sha256(value: Mapping[str, Any]) -> str:
    validate_envelope(value)
    return semantic_sha256(value)
