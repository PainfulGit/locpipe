from __future__ import annotations

from pathlib import Path

from locpipe.contracts.v0 import (
    AdapterDescriptorV0,
    ArtifactDeclarationV0,
    BranchIdentity,
    Capability,
    ContractViolation,
    ErrorCategory,
    ErrorCode,
    ErrorRecord,
    ImplementationRefV0,
    ModuleDescriptorV0,
    OperationContextV0,
    OperationHandlerV0,
    OperationRequestV0,
    canonical_json_bytes,
    parse_canonical_json,
)
from locpipe.contracts.v0.artifacts import resolve_existing_artifact

from ._corpus import load_accepted_source_corpus_v0, load_source_corpus_v0
from ._models import LineageDirectiveV0, ReconciliationStateV0, SourceDependencyV0, TargetBindingV0
from ._reconciliation import reconcile_sources_v0


SOURCE_LOCK_PATH = "source/source_lock.json"
RECONCILIATION_PATH = "reconciliation/reconciliation.json"


def source_lock_output_declarations_v0() -> tuple[ArtifactDeclarationV0, ...]:
    return (ArtifactDeclarationV0(SOURCE_LOCK_PATH, "raw"),)


def source_reconciliation_output_declarations_v0() -> tuple[ArtifactDeclarationV0, ...]:
    return (ArtifactDeclarationV0(RECONCILIATION_PATH, "raw"),)


def _implementation(module: ModuleDescriptorV0, capability: Capability) -> ImplementationRefV0:
    if not isinstance(module, ModuleDescriptorV0) or module.capability is not capability:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Content module has the wrong capability")
    return ImplementationRefV0("module", module.module_id, module.version, module.digest, capability)


def _error(error: ContractViolation) -> ErrorRecord:
    return error.record


def bind_source_snapshot_v0(
    module: ModuleDescriptorV0,
    descriptor: AdapterDescriptorV0,
    config_snapshot_sha256: str,
) -> tuple[ImplementationRefV0, OperationHandlerV0]:
    implementation = _implementation(module, Capability.SOURCE_SNAPSHOT)

    def handler(request: OperationRequestV0, context: OperationContextV0) -> ErrorRecord | None:
        try:
            if request.capability is not Capability.SOURCE_SNAPSHOT:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Source-lock handler received the wrong capability")
            if request.declared_outputs != source_lock_output_declarations_v0():
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Source-lock outputs differ from contract")
            paths = tuple(row.path for row in request.inputs)
            allowed = (
                ("corpus/segments.jsonl", "corpus/source_snapshot.json"),
                ("corpus/relations.jsonl", "corpus/segments.jsonl", "corpus/source_snapshot.json"),
            )
            if paths not in allowed:
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Source-lock inputs differ from contract")
            relations = "corpus/relations.jsonl" if "corpus/relations.jsonl" in paths else None
            corpus = load_source_corpus_v0(
                context.input_root,
                snapshot_path="corpus/source_snapshot.json",
                segments_path="corpus/segments.jsonl",
                relations_path=relations,
                descriptor=descriptor,
                config_snapshot_sha256=config_snapshot_sha256,
            )
            output = context.staging_root / SOURCE_LOCK_PATH
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(canonical_json_bytes(corpus.lock.as_dict()))
            return None
        except ContractViolation as error:
            return _error(error)

    return implementation, handler

def _load_target_bindings(path: Path) -> tuple[TargetBindingV0, ...]:
    value = parse_canonical_json(path.read_bytes())
    if not isinstance(value, dict) or set(value) != {"bindings"} or not isinstance(value["bindings"], list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target binding artifact is invalid")
    rows = []
    for raw in value["bindings"]:
        if not isinstance(raw, dict) or set(raw) != {"target_identity", "target_payload_sha256", "source_dependencies"}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target binding row is invalid")
        dependencies = raw["source_dependencies"]
        if not isinstance(dependencies, list):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target dependencies must be a list")
        parsed = []
        for dependency in dependencies:
            if not isinstance(dependency, dict) or set(dependency) != {"identity", "source_revision_sha"}:
                raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source dependency row is invalid")
            parsed.append(SourceDependencyV0(BranchIdentity.from_dict(dependency["identity"]), dependency["source_revision_sha"]))
        rows.append(TargetBindingV0(BranchIdentity.from_dict(raw["target_identity"]), raw["target_payload_sha256"], tuple(parsed)))
    return tuple(rows)


def _load_directives(path: Path) -> tuple[LineageDirectiveV0, ...]:
    value = parse_canonical_json(path.read_bytes())
    if not isinstance(value, dict) or set(value) != {"directives"} or not isinstance(value["directives"], list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Lineage artifact is invalid")
    rows = []
    for raw in value["directives"]:
        if not isinstance(raw, dict) or set(raw) != {"state", "old_ids", "new_ids"}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Lineage row is invalid")
        try:
            state = ReconciliationStateV0(raw["state"])
        except ValueError as error:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Lineage state is invalid") from error
        rows.append(
            LineageDirectiveV0(
                state,
                tuple(BranchIdentity.from_dict(row) for row in raw["old_ids"]),
                tuple(BranchIdentity.from_dict(row) for row in raw["new_ids"]),
            )
        )
    return tuple(rows)


def bind_source_reconciliation_v0(
    module: ModuleDescriptorV0,
    descriptor: AdapterDescriptorV0,
    config_snapshot_sha256: str,
) -> tuple[ImplementationRefV0, OperationHandlerV0]:
    implementation = _implementation(module, Capability.SOURCE_RECONCILIATION)

    def handler(request: OperationRequestV0, context: OperationContextV0) -> ErrorRecord | None:
        try:
            if request.capability is not Capability.SOURCE_RECONCILIATION:
                raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Reconciliation handler received the wrong capability")
            if request.declared_outputs != source_reconciliation_output_declarations_v0():
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Reconciliation outputs differ from contract")
            paths = {row.path for row in request.inputs}
            current_required = {"current/source_snapshot.json", "current/segments.jsonl", "current/source_lock.json"}
            if not current_required <= paths:
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Current corpus inputs are incomplete")
            known = current_required | {
                "current/relations.jsonl",
                "previous/source_snapshot.json",
                "previous/segments.jsonl",
                "previous/relations.jsonl",
                "previous/source_lock.json",
                "targets/target_bindings.json",
                "directives/lineage.json",
            }
            if not paths <= known:
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Reconciliation contains unknown inputs")
            previous_present = bool(paths & {
                "previous/source_snapshot.json", "previous/segments.jsonl",
                "previous/relations.jsonl", "previous/source_lock.json",
            })
            if previous_present and not {
                "previous/source_snapshot.json", "previous/segments.jsonl", "previous/source_lock.json",
            } <= paths:
                raise ContractViolation(ErrorCode.OUTPUT_CONTRACT_VIOLATION, "Previous corpus inputs are incomplete")
            current = load_accepted_source_corpus_v0(
                context.input_root,
                snapshot_path="current/source_snapshot.json",
                segments_path="current/segments.jsonl",
                relations_path="current/relations.jsonl" if "current/relations.jsonl" in paths else None,
                source_lock_path="current/source_lock.json",
                descriptor=descriptor,
                expected_config_snapshot_sha256=config_snapshot_sha256,
            )
            previous = None
            if previous_present:
                previous = load_accepted_source_corpus_v0(
                    context.input_root,
                    snapshot_path="previous/source_snapshot.json",
                    segments_path="previous/segments.jsonl",
                    relations_path="previous/relations.jsonl" if "previous/relations.jsonl" in paths else None,
                    source_lock_path="previous/source_lock.json",
                )
            targets = ()
            if "targets/target_bindings.json" in paths:
                targets = _load_target_bindings(resolve_existing_artifact(context.input_root, "targets/target_bindings.json"))
            directives = ()
            if "directives/lineage.json" in paths:
                directives = _load_directives(resolve_existing_artifact(context.input_root, "directives/lineage.json"))
            result = reconcile_sources_v0(current, previous=previous, directives=directives, target_bindings=targets)
            output = context.staging_root / RECONCILIATION_PATH
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(canonical_json_bytes(result.as_dict()))
            return None
        except ContractViolation as error:
            return _error(error)
        except Exception:
            return ErrorRecord(
                ErrorCode.HANDLER_EXCEPTION,
                ErrorCategory.INTERNAL,
                None,
                False,
                (),
                "Content reconciliation handler raised an unexpected exception",
            )

    return implementation, handler
