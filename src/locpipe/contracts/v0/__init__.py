"""Experimental locpipe contract surface v0.

This package is deliberately not connected to any production project pipeline.
Its API may change until the cross-platform canonical-byte gate closes.
"""

from .canonical import (
    canonical_json_bytes,
    canonical_jsonl_bytes,
    canonical_value_bytes,
    normalized_text,
    parse_canonical_json,
    parse_canonical_jsonl,
    raw_sha256,
    semantic_sha256,
    strict_loads,
)
from .constants import CONTRACT_VERSION, KIND_TO_SCHEMA
from .errors import ContractViolation, ErrorCategory, ErrorCode, ErrorRecord
from .identity import BranchIdentity, SelectorStep, display_id, parse_display_id, source_revision_sha
from .interfaces import (
    ArtifactDeclarationV0,
    ArtifactHashV0,
    ImplementationRefV0,
    OperationContextV0,
    OperationHandlerV0,
    OperationRequestV0,
    OperationResultV0,
    execute_bound_operation,
    resolve_implementation,
)
from .profiles import (
    AdapterDescriptorV0,
    Capability,
    ModuleDescriptorV0,
    Requirement,
    WorkflowProfile,
    profile_requirements,
    validate_module_bindings,
    validate_profile,
)
from .schema_registry import load_schema_registry
from .validation import (
    envelope_semantic_sha256,
    validate_envelope,
    validate_profile_bindings,
    validate_relation_set,
    verify_receipt_artifacts,
)

__all__ = [
    "AdapterDescriptorV0",
    "ArtifactDeclarationV0",
    "ArtifactHashV0",
    "BranchIdentity",
    "Capability",
    "CONTRACT_VERSION",
    "ContractViolation",
    "ErrorCategory",
    "ErrorCode",
    "ErrorRecord",
    "KIND_TO_SCHEMA",
    "ImplementationRefV0",
    "ModuleDescriptorV0",
    "OperationContextV0",
    "OperationHandlerV0",
    "OperationRequestV0",
    "OperationResultV0",
    "Requirement",
    "SelectorStep",
    "WorkflowProfile",
    "canonical_json_bytes",
    "canonical_jsonl_bytes",
    "canonical_value_bytes",
    "display_id",
    "envelope_semantic_sha256",
    "execute_bound_operation",
    "normalized_text",
    "load_schema_registry",
    "parse_canonical_json",
    "parse_canonical_jsonl",
    "parse_display_id",
    "profile_requirements",
    "raw_sha256",
    "resolve_implementation",
    "semantic_sha256",
    "source_revision_sha",
    "strict_loads",
    "validate_module_bindings",
    "validate_envelope",
    "validate_profile",
    "validate_profile_bindings",
    "validate_relation_set",
    "verify_receipt_artifacts",
]
