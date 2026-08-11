from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from locpipe.content.v0 import (
    FrozenScopeV0,
    LoadedSourceCorpusV0,
    ScopeRoleV0,
    SourceReconciliationV0,
    validate_frozen_scope_artifacts_v0,
)
from locpipe.contracts.v0 import (
    BranchIdentity,
    ContractViolation,
    ErrorCode,
    canonical_json_bytes,
    canonical_value_bytes,
    display_id,
    parse_canonical_jsonl,
    raw_sha256,
    semantic_sha256,
)
from locpipe.kernel.v0.config import ResolvedConfigV0, validate_context_config_binding
from locpipe.kernel.v0.context import ProjectContextV0

from ._models import (
    ProviderBindingV0,
    ProviderBudgetV0,
    TranslationJobV0,
    TranslationPacketRowV0,
    TranslationPacketV0,
)


ROLE_CONTRACT_SHA256 = semantic_sha256({
    "contract": "locpipe.translation.role/translator/v0",
    "role": "translator",
    "writes": "target_branch_payloads_only",
    "context_is_read_only": True,
})
OUTPUT_CONTRACT_SHA256 = semantic_sha256({
    "contract": "locpipe.translation.provider-output/v0",
    "shape": {"contract": "locpipe.translation.provider-output/v0", "targets": ["target_branch"]},
    "coverage": "exact_owned_scope",
})


def provider_binding_from_config_v0(
    resolved: ResolvedConfigV0,
    *,
    role: str = "translator",
) -> ProviderBindingV0:
    if not isinstance(resolved, ResolvedConfigV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Resolved config is invalid")
    raw = resolved.get_value("provider_bindings")
    matches = [row for row in raw if isinstance(row, Mapping) and row.get("role") == role]
    if len(matches) != 1:
        raise ContractViolation(ErrorCode.CAPABILITY_MISSING, "Translator provider binding is missing or ambiguous")
    row = matches[0]
    if set(row) != {"role", "provider_id", "version", "config_digest"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translator provider binding fields are invalid")
    return ProviderBindingV0(row["role"], row["provider_id"], row["version"], row["config_digest"])


def _source_identity(envelope: Mapping[str, Any]) -> BranchIdentity:
    if envelope.get("kind") != "source_branch" or not isinstance(envelope.get("data"), Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation packet source row is invalid")
    return BranchIdentity.from_dict(envelope["data"]["identity"])


def _relation_touches_owned(envelope: Mapping[str, Any], owned: set[str], owned_logical: set[tuple[str, ...]]) -> bool:
    if envelope.get("kind") != "relation" or not isinstance(envelope.get("data"), Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation relation is invalid")
    for name in ("from_ref", "to_ref"):
        reference = envelope["data"].get(name)
        if not isinstance(reference, Mapping):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation relation reference is invalid")
        if reference.get("kind") == "branch" and display_id(BranchIdentity.from_dict(reference["identity"])) in owned:
            return True
        if reference.get("kind") == "logical_message" and tuple(reference["logical_id"]) in owned_logical:
            return True
    return False


def build_translation_job_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    corpus: LoadedSourceCorpusV0,
    reconciliation: SourceReconciliationV0,
    scope: FrozenScopeV0,
    *,
    source_lock_bytes: bytes,
    reconciliation_bytes: bytes,
    scope_bytes: bytes,
    scope_lock_bytes: bytes,
    segments_bytes: bytes,
    target_locale: str,
    budget: ProviderBudgetV0,
) -> tuple[TranslationJobV0, TranslationPacketV0]:
    if not isinstance(context, ProjectContextV0) or not isinstance(resolved, ResolvedConfigV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation context or config is invalid")
    if context.config_snapshot_sha256 != resolved.config_snapshot_sha256:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation context config drift")
    validate_context_config_binding(context, resolved)
    rebuilt_scope = validate_frozen_scope_artifacts_v0(
        scope_bytes,
        scope_lock_bytes,
        corpus,
        reconciliation,
        source_lock_bytes=source_lock_bytes,
        reconciliation_bytes=reconciliation_bytes,
    )
    if rebuilt_scope != scope:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation scope differs from frozen authority")
    if target_locale not in scope.target_locales:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Target locale is outside frozen scope")
    raw_rows = parse_canonical_jsonl(segments_bytes, sort_key=lambda row: display_id(_source_identity(row)))
    source_by_id = {display_id(_source_identity(row)): row for row in raw_rows}
    if tuple(sorted(source_by_id)) != corpus.lock.branch_ids:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Packet source rows differ from accepted corpus")
    packet_rows: list[TranslationPacketRowV0] = []
    owned: set[str] = set()
    owned_logical: set[tuple[str, ...]] = set()
    for entry in scope.entries:
        stable_id = display_id(entry.identity)
        raw = source_by_id.get(stable_id)
        if raw is None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Frozen scope row is missing from corpus")
        data = raw["data"]
        packet_rows.append(
            TranslationPacketRowV0(
                entry.identity,
                entry.role,
                data["source_revision_sha"],
                data["content_type"],
                canonical_value_bytes(data["payload"]),
                canonical_value_bytes(data["constraints"]),
            )
        )
        if entry.role is ScopeRoleV0.OWNED:
            owned.add(stable_id)
            owned_logical.add(entry.identity.logical_id)
    relation_rows = tuple(
        canonical_json_bytes(row)
        for row in corpus.relation_envelopes
        if _relation_touches_owned(row, owned, owned_logical)
    )
    packet = TranslationPacketV0(target_locale, tuple(packet_rows), relation_rows)
    packet_bytes = canonical_json_bytes(packet.as_dict())
    provider = provider_binding_from_config_v0(resolved)
    identity_projection = {
        "context_digest": context.context_digest,
        "scope_sha256": raw_sha256(scope_bytes),
        "source_lock_sha256": raw_sha256(source_lock_bytes),
        "reconciliation_sha256": raw_sha256(reconciliation_bytes),
        "content_config_digest": resolved.content_config_digest,
        "effective_snapshot_sha256": resolved.effective_snapshot_sha256,
        "provider": provider.as_dict(),
        "target_locale": target_locale,
        "packet_sha256": raw_sha256(packet_bytes),
        "role_contract_sha256": ROLE_CONTRACT_SHA256,
        "output_contract_sha256": OUTPUT_CONTRACT_SHA256,
        "budget": budget.as_dict(),
        "attempt": 1,
        "max_invocations": 1,
    }
    job_id = "translation-" + semantic_sha256({"kind": "job", **identity_projection})[:32]
    invocation_id = "invocation-" + semantic_sha256({"job_id": job_id, "attempt": 1, "provider": provider.as_dict()})[:32]
    return (
        TranslationJobV0(
            job_id,
            invocation_id,
            context.context_digest,
            raw_sha256(scope_bytes),
            raw_sha256(source_lock_bytes),
            raw_sha256(reconciliation_bytes),
            resolved.content_config_digest,
            resolved.effective_snapshot_sha256,
            provider,
            target_locale,
            raw_sha256(packet_bytes),
            ROLE_CONTRACT_SHA256,
            OUTPUT_CONTRACT_SHA256,
            budget,
        ),
        packet,
    )
