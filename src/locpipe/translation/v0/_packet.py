from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Callable

from locpipe.content.v0 import (
    FrozenScopeV0,
    LoadedSourceCorpusV0,
    PreparedSourceAuthorityV0,
    ScopeRoleV0,
    SourceReconciliationV0,
    validate_frozen_scope_artifacts_v0,
)
from locpipe.content.v0._prepared import (
    _incident_prepared_relation_bytes_v0,
    _prepared_source_parts_v0,
)
from locpipe.content.v0._scope import _validate_prepared_frozen_scope_artifacts_v0
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


_SourceLookupV0 = Callable[[str], tuple[str, str, bytes, bytes] | None]
_RelationLookupV0 = Callable[[set[str], set[tuple[str, ...]]], tuple[bytes, ...]]


def _source_identity(envelope: Mapping[str, Any]) -> BranchIdentity:
    if envelope.get("kind") != "source_branch" or not isinstance(envelope.get("data"), Mapping):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation packet source row is invalid")
    return BranchIdentity.from_dict(envelope["data"]["identity"])


def _relation_touches_owned(
    envelope: Mapping[str, Any],
    owned: set[str],
    owned_logical: set[tuple[str, ...]],
) -> bool:
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


def _build_translation_job_from_source_access_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    corpus: LoadedSourceCorpusV0,
    reconciliation: SourceReconciliationV0,
    scope: FrozenScopeV0,
    source_ids: tuple[str, ...] | None,
    source_lookup: _SourceLookupV0,
    relation_lookup: _RelationLookupV0,
    *,
    source_lock_bytes: bytes,
    reconciliation_bytes: bytes,
    scope_bytes: bytes,
    scope_lock_bytes: bytes,
    target_locale: str,
    budget: ProviderBudgetV0,
    validated_scope: FrozenScopeV0 | None = None,
    known_source_lock_sha256: str | None = None,
    known_reconciliation_sha256: str | None = None,
) -> tuple[TranslationJobV0, TranslationPacketV0]:
    if not isinstance(context, ProjectContextV0) or not isinstance(resolved, ResolvedConfigV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Translation context or config is invalid")
    if context.config_snapshot_sha256 != resolved.config_snapshot_sha256:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Translation context config drift")
    validate_context_config_binding(context, resolved)
    rebuilt_scope = validated_scope or validate_frozen_scope_artifacts_v0(
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
    if source_ids is not None and source_ids != corpus.lock.branch_ids:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Packet source rows differ from accepted corpus")
    packet_rows: list[TranslationPacketRowV0] = []
    owned: set[str] = set()
    owned_logical: set[tuple[str, ...]] = set()
    for entry in scope.entries:
        stable_id = display_id(entry.identity)
        source = source_lookup(stable_id)
        if source is None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Frozen scope row is missing from corpus")
        source_revision, content_type, payload_bytes, constraints_bytes = source
        packet_rows.append(
            TranslationPacketRowV0(
                entry.identity,
                entry.role,
                source_revision,
                content_type,
                payload_bytes,
                constraints_bytes,
            )
        )
        if entry.role is ScopeRoleV0.OWNED:
            owned.add(stable_id)
            owned_logical.add(entry.identity.logical_id)
    relation_rows = relation_lookup(owned, owned_logical)
    packet = TranslationPacketV0(target_locale, tuple(packet_rows), relation_rows)
    packet_bytes = canonical_json_bytes(packet.as_dict())
    provider = provider_binding_from_config_v0(resolved)
    source_lock_sha256 = known_source_lock_sha256 or raw_sha256(source_lock_bytes)
    reconciliation_sha256 = known_reconciliation_sha256 or raw_sha256(reconciliation_bytes)
    identity_projection = {
        "context_digest": context.context_digest,
        "scope_sha256": raw_sha256(scope_bytes),
        "source_lock_sha256": source_lock_sha256,
        "reconciliation_sha256": reconciliation_sha256,
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
            source_lock_sha256,
            reconciliation_sha256,
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
    raw_rows = parse_canonical_jsonl(segments_bytes, sort_key=lambda row: display_id(_source_identity(row)))
    source_by_id = {display_id(_source_identity(row)): row for row in raw_rows}

    def source_lookup(stable_id: str) -> tuple[str, str, bytes, bytes] | None:
        raw = source_by_id.get(stable_id)
        if raw is None:
            return None
        data = raw["data"]
        return (
            data["source_revision_sha"],
            data["content_type"],
            canonical_value_bytes(data["payload"]),
            canonical_value_bytes(data["constraints"]),
        )

    def relation_lookup(owned: set[str], owned_logical: set[tuple[str, ...]]) -> tuple[bytes, ...]:
        return tuple(
            canonical_json_bytes(row)
            for row in corpus.relation_envelopes
            if _relation_touches_owned(row, owned, owned_logical)
        )

    return _build_translation_job_from_source_access_v0(
        context,
        resolved,
        corpus,
        reconciliation,
        scope,
        tuple(sorted(source_by_id)),
        source_lookup,
        relation_lookup,
        source_lock_bytes=source_lock_bytes,
        reconciliation_bytes=reconciliation_bytes,
        scope_bytes=scope_bytes,
        scope_lock_bytes=scope_lock_bytes,
        target_locale=target_locale,
        budget=budget,
    )


def build_translation_job_prepared_v0(
    context: ProjectContextV0,
    resolved: ResolvedConfigV0,
    authority: PreparedSourceAuthorityV0,
    scope: FrozenScopeV0,
    *,
    scope_bytes: bytes,
    scope_lock_bytes: bytes,
    target_locale: str,
    budget: ProviderBudgetV0,
) -> tuple[TranslationJobV0, TranslationPacketV0]:
    prepared = _prepared_source_parts_v0(authority)

    def source_lookup(stable_id: str) -> tuple[str, str, bytes, bytes] | None:
        source = prepared._segment_index.get(stable_id)
        if source is None:
            return None
        return source.source_revision_sha, source.content_type, source.payload_bytes, source.constraints_bytes

    def relation_lookup(owned: set[str], owned_logical: set[tuple[str, ...]]) -> tuple[bytes, ...]:
        return _incident_prepared_relation_bytes_v0(
            owned,
            owned_logical,
            prepared._relations_by_branch,
            prepared._relations_by_logical,
        )

    validated_scope = _validate_prepared_frozen_scope_artifacts_v0(
        scope_bytes,
        scope_lock_bytes,
        prepared.corpus,
        prepared.reconciliation,
        source_lock_sha256=prepared._source_lock_sha256,
        reconciliation_digest=prepared._reconciliation_digest,
        segment_index=prepared._segment_index,
        relations_by_branch=prepared._relations_by_branch,
        relations_by_logical=prepared._relations_by_logical,
        segments_by_logical=prepared._segments_by_logical,
    )
    return _build_translation_job_from_source_access_v0(
        context,
        resolved,
        prepared.corpus,
        prepared.reconciliation,
        scope,
        None,
        source_lookup,
        relation_lookup,
        source_lock_bytes=prepared.source_lock_bytes,
        reconciliation_bytes=prepared.reconciliation_bytes,
        scope_bytes=scope_bytes,
        scope_lock_bytes=scope_lock_bytes,
        target_locale=target_locale,
        budget=budget,
        validated_scope=validated_scope,
        known_source_lock_sha256=prepared._source_lock_sha256,
        known_reconciliation_sha256=prepared._reconciliation_sha256,
    )
