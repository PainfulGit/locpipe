from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable

from locpipe.contracts.v0 import (
    BranchIdentity,
    ContractViolation,
    ErrorCode,
    canonical_json_bytes,
    display_id,
    parse_canonical_json,
    raw_sha256,
)

from ._corpus import LoadedSourceCorpusV0, validate_source_lock_v0
from ._models import FrozenScopeV0, ScopeEntryV0, ScopeRoleV0
from ._prepared import PreparedSourceAuthorityV0, _prepared_source_parts_v0
from ._reconciliation import SourceReconciliationV0


SCOPE_PATH = "scope/scope.json"
SCOPE_LOCK_PATH = "scope/scope_lock.json"


@dataclass(frozen=True, slots=True)
class _ScopeSourceAccessV0:
    contains_stable_id: Callable[[str], bool]
    required_relation_ids: Callable[[set[str], set[tuple[str, ...]]], set[str]]


def _relation_required_ids(corpus: LoadedSourceCorpusV0, owned: set[str]) -> set[str]:
    by_logical: dict[tuple[str, ...], set[str]] = {}
    for segment in corpus.segments:
        by_logical.setdefault(segment.identity.logical_id, set()).add(segment.stable_id)
    required: set[str] = set()
    for envelope in corpus.relation_envelopes:
        data = envelope["data"]
        branch_ids: set[str] = set()
        logical_ids: set[tuple[str, ...]] = set()
        for name in ("from_ref", "to_ref"):
            reference = data[name]
            if reference["kind"] == "branch":
                branch_ids.add(display_id(BranchIdentity.from_dict(reference["identity"])))
            elif reference["kind"] == "logical_message":
                logical_ids.add(tuple(reference["logical_id"]))
        touches_owned = bool(branch_ids & owned) or any(by_logical.get(logical, set()) & owned for logical in logical_ids)
        if touches_owned:
            required.update(branch_ids)
            for logical in logical_ids:
                required.update(by_logical.get(logical, set()))
    return required


def _canonical_scope_access_v0(corpus: LoadedSourceCorpusV0) -> _ScopeSourceAccessV0:
    current: set[str] | None = None

    def contains(stable_id: str) -> bool:
        nonlocal current
        if current is None:
            current = {row.stable_id for row in corpus.segments}
        return stable_id in current

    def required(owned: set[str], _owned_logical: set[tuple[str, ...]]) -> set[str]:
        return _relation_required_ids(corpus, owned)

    return _ScopeSourceAccessV0(contains, required)


def _prepared_scope_access_v0(
    segment_index: Mapping[str, object],
    relations_by_branch: Mapping[str, tuple[object, ...]],
    relations_by_logical: Mapping[tuple[str, ...], tuple[object, ...]],
    segments_by_logical: Mapping[tuple[str, ...], tuple[str, ...]],
) -> _ScopeSourceAccessV0:
    def contains(stable_id: str) -> bool:
        return segment_index.get(stable_id) is not None

    def required(owned: set[str], owned_logical: set[tuple[str, ...]]) -> set[str]:
        incident: dict[str, object] = {}
        for stable_id in owned:
            for relation in relations_by_branch.get(stable_id, ()):
                incident.setdefault(relation.digest, relation)
        for logical_id in owned_logical:
            for relation in relations_by_logical.get(logical_id, ()):
                incident.setdefault(relation.digest, relation)
        required_ids: set[str] = set()
        for relation in incident.values():
            required_ids.update(relation.branch_ids)
            for logical_id in relation.logical_ids:
                required_ids.update(segments_by_logical.get(logical_id, ()))
        return required_ids

    return _ScopeSourceAccessV0(contains, required)


def _accept_scope_v0(
    corpus: LoadedSourceCorpusV0,
    reconciliation: SourceReconciliationV0,
    entries: tuple[ScopeEntryV0, ...],
    *,
    target_locales: tuple[str, ...],
    config_snapshot_sha256: str,
    source_lock_sha256: str,
    reconciliation_digest: str,
    access: _ScopeSourceAccessV0,
) -> FrozenScopeV0:
    if reconciliation.current_corpus_digest != corpus.lock.corpus_digest:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Reconciliation does not bind the current corpus")
    if config_snapshot_sha256 != corpus.lock.config_snapshot_sha256:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Scope config differs from the source lock")
    raw_entries = tuple(entries)
    if any(not isinstance(row, ScopeEntryV0) for row in raw_entries):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Scope entries are invalid")
    ordered = tuple(sorted(raw_entries, key=lambda row: display_id(row.identity)))
    keys = tuple(display_id(row.identity) for row in ordered)
    if len(keys) != len(set(keys)):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Scope identity has multiple roles")
    missing = sorted(stable_id for stable_id in keys if not access.contains_stable_id(stable_id))
    if missing:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Scope contains IDs outside the current source snapshot")
    locales = tuple(sorted(tuple(target_locales)))
    if corpus.lock.source_locale in locales:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target locales cannot contain the source locale")
    owned_rows = tuple(row for row in ordered if row.role is ScopeRoleV0.OWNED)
    owned = {display_id(row.identity) for row in owned_rows}
    owned_logical = {row.identity.logical_id for row in owned_rows}
    relation_missing = sorted(access.required_relation_ids(owned, owned_logical) - set(keys))
    if relation_missing:
        raise ContractViolation(ErrorCode.DANGLING_RELATION, "Owned scope omits a related branch dependency")
    scope_projection = {
        "contract": "locpipe.content.scope/v0",
        "entries": [row.as_dict() for row in ordered],
        "target_locales": list(locales),
    }
    scope_sha = raw_sha256(canonical_json_bytes(scope_projection))
    return FrozenScopeV0(
        ordered,
        locales,
        corpus.lock.corpus_digest,
        source_lock_sha256,
        reconciliation_digest,
        config_snapshot_sha256,
        scope_sha,
    )


def freeze_scope_v0(
    corpus: LoadedSourceCorpusV0,
    reconciliation: SourceReconciliationV0,
    entries: tuple[ScopeEntryV0, ...],
    *,
    target_locales: tuple[str, ...],
    config_snapshot_sha256: str,
    source_lock_bytes: bytes,
    reconciliation_bytes: bytes,
) -> FrozenScopeV0:
    validate_source_lock_v0(source_lock_bytes, corpus)
    if canonical_json_bytes(reconciliation.as_dict()) != reconciliation_bytes:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Published reconciliation differs from verified reconciliation")
    return _accept_scope_v0(
        corpus,
        reconciliation,
        entries,
        target_locales=target_locales,
        config_snapshot_sha256=config_snapshot_sha256,
        source_lock_sha256=raw_sha256(source_lock_bytes),
        reconciliation_digest=reconciliation.digest,
        access=_canonical_scope_access_v0(corpus),
    )


def freeze_scope_prepared_v0(
    authority: PreparedSourceAuthorityV0,
    entries: tuple[ScopeEntryV0, ...],
    *,
    target_locales: tuple[str, ...],
    config_snapshot_sha256: str,
) -> FrozenScopeV0:
    prepared = _prepared_source_parts_v0(authority)
    return _accept_scope_v0(
        prepared.corpus,
        prepared.reconciliation,
        entries,
        target_locales=target_locales,
        config_snapshot_sha256=config_snapshot_sha256,
        source_lock_sha256=prepared._source_lock_sha256,
        reconciliation_digest=prepared._reconciliation_digest,
        access=_prepared_scope_access_v0(
            prepared._segment_index,
            prepared._relations_by_branch,
            prepared._relations_by_logical,
            prepared._segments_by_logical,
        ),
    )


def frozen_scope_artifacts_v0(scope: FrozenScopeV0) -> tuple[tuple[str, bytes], ...]:
    if not isinstance(scope, FrozenScopeV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Frozen scope has the wrong type")
    scope_bytes = canonical_json_bytes(scope.scope_dict())
    if raw_sha256(scope_bytes) != scope.scope_sha256:
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Frozen scope bytes drifted")
    return (
        (SCOPE_PATH, scope_bytes),
        (SCOPE_LOCK_PATH, canonical_json_bytes(scope.lock_dict())),
    )


def validate_frozen_scope_artifacts_v0(
    scope_bytes: bytes,
    lock_bytes: bytes,
    corpus: LoadedSourceCorpusV0,
    reconciliation: SourceReconciliationV0,
    *,
    source_lock_bytes: bytes,
    reconciliation_bytes: bytes,
) -> FrozenScopeV0:
    parsed_entries, target_locales, raw_lock = _parse_scope_artifacts_v0(scope_bytes, lock_bytes)
    rebuilt = freeze_scope_v0(
        corpus,
        reconciliation,
        parsed_entries,
        target_locales=target_locales,
        config_snapshot_sha256=raw_lock["config_snapshot_sha256"],
        source_lock_bytes=source_lock_bytes,
        reconciliation_bytes=reconciliation_bytes,
    )
    return _match_scope_artifacts_v0(scope_bytes, raw_lock, rebuilt)


def _parse_scope_artifacts_v0(
    scope_bytes: bytes,
    lock_bytes: bytes,
) -> tuple[tuple[ScopeEntryV0, ...], tuple[str, ...], Mapping[str, object]]:
    raw_scope = parse_canonical_json(scope_bytes)
    raw_lock = parse_canonical_json(lock_bytes)
    if not isinstance(raw_scope, Mapping) or set(raw_scope) != {"contract", "entries", "target_locales"}:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Scope artifact fields are invalid")
    if raw_scope["contract"] != "locpipe.content.scope/v0" or not isinstance(raw_scope["entries"], list):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Scope artifact contract is invalid")
    if not isinstance(raw_lock, Mapping) or set(raw_lock) != {
        "contract", "scope_sha256", "source_corpus_digest", "reconciliation_digest",
        "source_lock_sha256", "config_snapshot_sha256", "target_locales",
    }:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Scope lock fields are invalid")
    if raw_lock["contract"] != "locpipe.content.scope-lock/v0":
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Scope lock contract is invalid")
    parsed_entries: list[ScopeEntryV0] = []
    for row in raw_scope["entries"]:
        if not isinstance(row, Mapping) or set(row) != {"identity", "role"}:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Scope entry fields are invalid")
        try:
            role = ScopeRoleV0(row["role"])
        except ValueError as error:
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Scope role is invalid") from error
        parsed_entries.append(ScopeEntryV0(BranchIdentity.from_dict(row["identity"]), role))
    return tuple(parsed_entries), tuple(raw_scope["target_locales"]), raw_lock


def _match_scope_artifacts_v0(
    scope_bytes: bytes,
    raw_lock: Mapping[str, object],
    rebuilt: FrozenScopeV0,
) -> FrozenScopeV0:
    if raw_sha256(scope_bytes) != raw_lock["scope_sha256"] or rebuilt.lock_dict() != dict(raw_lock):
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Frozen scope or lock drifted")
    return rebuilt


def _validate_prepared_frozen_scope_artifacts_v0(
    scope_bytes: bytes,
    lock_bytes: bytes,
    corpus: LoadedSourceCorpusV0,
    reconciliation: SourceReconciliationV0,
    *,
    source_lock_sha256: str,
    reconciliation_digest: str,
    segment_index: Mapping[str, object],
    relations_by_branch: Mapping[str, tuple[object, ...]],
    relations_by_logical: Mapping[tuple[str, ...], tuple[object, ...]],
    segments_by_logical: Mapping[tuple[str, ...], tuple[str, ...]],
) -> FrozenScopeV0:
    parsed_entries, target_locales, raw_lock = _parse_scope_artifacts_v0(scope_bytes, lock_bytes)
    rebuilt = _accept_scope_v0(
        corpus,
        reconciliation,
        parsed_entries,
        target_locales=target_locales,
        config_snapshot_sha256=raw_lock["config_snapshot_sha256"],
        source_lock_sha256=source_lock_sha256,
        reconciliation_digest=reconciliation_digest,
        access=_prepared_scope_access_v0(
            segment_index,
            relations_by_branch,
            relations_by_logical,
            segments_by_logical,
        ),
    )
    return _match_scope_artifacts_v0(scope_bytes, raw_lock, rebuilt)
