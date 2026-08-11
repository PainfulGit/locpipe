from __future__ import annotations

from collections.abc import Mapping

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
from ._reconciliation import SourceReconciliationV0


SCOPE_PATH = "scope/scope.json"
SCOPE_LOCK_PATH = "scope/scope_lock.json"


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
    current = {row.stable_id for row in corpus.segments}
    missing = sorted(set(keys) - current)
    if missing:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Scope contains IDs outside the current source snapshot")
    locales = tuple(sorted(tuple(target_locales)))
    if corpus.lock.source_locale in locales:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Target locales cannot contain the source locale")
    owned = {display_id(row.identity) for row in ordered if row.role is ScopeRoleV0.OWNED}
    scoped = set(keys)
    relation_missing = sorted(_relation_required_ids(corpus, owned) - scoped)
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
        raw_sha256(source_lock_bytes),
        reconciliation.digest,
        config_snapshot_sha256,
        scope_sha,
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
    rebuilt = freeze_scope_v0(
        corpus,
        reconciliation,
        tuple(parsed_entries),
        target_locales=tuple(raw_scope["target_locales"]),
        config_snapshot_sha256=raw_lock["config_snapshot_sha256"],
        source_lock_bytes=source_lock_bytes,
        reconciliation_bytes=reconciliation_bytes,
    )
    if raw_sha256(scope_bytes) != raw_lock["scope_sha256"] or rebuilt.lock_dict() != dict(raw_lock):
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Frozen scope or lock drifted")
    return rebuilt
