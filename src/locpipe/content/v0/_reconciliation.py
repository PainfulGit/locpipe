from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from locpipe.contracts.v0 import ContractViolation, ErrorCategory, ErrorCode, display_id, semantic_sha256
from locpipe.contracts.v0.profiles import SHA256_RE

from ._corpus import LoadedSourceCorpusV0, _rebind_loaded_source_corpus_v0
from ._models import (
    LineageDirectiveV0,
    ReconciliationStateV0,
    SourceSegmentV0,
    TargetBindingV0,
    TargetValidityStateV0,
)


@dataclass(frozen=True)
class ReconciliationEventV0:
    state: ReconciliationStateV0
    old_ids: tuple[str, ...]
    new_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"state": self.state.value, "old_ids": list(self.old_ids), "new_ids": list(self.new_ids)}


@dataclass(frozen=True)
class TargetValidityV0:
    target_id: str
    state: TargetValidityStateV0
    invalid_source_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "state": self.state.value,
            "invalid_source_ids": list(self.invalid_source_ids),
        }


@dataclass(frozen=True)
class SourceReconciliationV0:
    previous_corpus_digest: str | None
    current_corpus_digest: str
    events: tuple[ReconciliationEventV0, ...]
    tombstones: tuple[str, ...]
    target_validity: tuple[TargetValidityV0, ...]

    def as_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for row in self.events:
            counts[row.state.value] = counts.get(row.state.value, 0) + 1
        return {
            "contract": "locpipe.content.reconciliation/v0",
            "previous_corpus_digest": self.previous_corpus_digest,
            "current_corpus_digest": self.current_corpus_digest,
            "events": [row.as_dict() for row in self.events],
            "tombstones": list(self.tombstones),
            "target_validity": [row.as_dict() for row in self.target_validity],
            "summary": {key: counts[key] for key in sorted(counts)},
        }

    @property
    def digest(self) -> str:
        return semantic_sha256(self.as_dict())


def _by_id(rows: Iterable[SourceSegmentV0]) -> dict[str, SourceSegmentV0]:
    output: dict[str, SourceSegmentV0] = {}
    for row in rows:
        if row.stable_id in output:
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Source corpus contains duplicate stable IDs")
        output[row.stable_id] = row
    return output


def reconcile_sources_v0(
    current: LoadedSourceCorpusV0,
    *,
    previous: LoadedSourceCorpusV0 | None = None,
    directives: tuple[LineageDirectiveV0, ...] = (),
    target_bindings: tuple[TargetBindingV0, ...] = (),
) -> SourceReconciliationV0:
    current_by_id = _by_id(current.segments)
    previous_by_id = {} if previous is None else _by_id(previous.segments)
    events: list[ReconciliationEventV0] = []
    old_remaining = set(previous_by_id) - set(current_by_id)
    new_remaining = set(current_by_id) - set(previous_by_id)
    for stable_id in sorted(set(previous_by_id) & set(current_by_id)):
        before = previous_by_id[stable_id]
        after = current_by_id[stable_id]
        state = (
            ReconciliationStateV0.CHANGED
            if before.source_revision_sha != after.source_revision_sha
            else ReconciliationStateV0.MOVED
            if before.locator_sha256 != after.locator_sha256
            else ReconciliationStateV0.UNCHANGED
        )
        events.append(ReconciliationEventV0(state, (stable_id,), (stable_id,)))

    consumed_old: set[str] = set()
    consumed_new: set[str] = set()
    for directive in directives:
        old_ids = tuple(display_id(row) for row in directive.old_ids)
        new_ids = tuple(display_id(row) for row in directive.new_ids)
        if not set(old_ids) <= old_remaining or not set(new_ids) <= new_remaining:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Lineage directive does not bind unmatched snapshot IDs")
        if consumed_old & set(old_ids) or consumed_new & set(new_ids):
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Lineage directives overlap")
        consumed_old.update(old_ids)
        consumed_new.update(new_ids)
        events.append(ReconciliationEventV0(directive.state, old_ids, new_ids))
    old_remaining -= consumed_old
    new_remaining -= consumed_new

    old_revision: dict[str, set[str]] = {}
    new_revision: dict[str, set[str]] = {}
    for stable_id in old_remaining:
        old_revision.setdefault(previous_by_id[stable_id].source_revision_sha, set()).add(stable_id)
    for stable_id in new_remaining:
        new_revision.setdefault(current_by_id[stable_id].source_revision_sha, set()).add(stable_id)
    if set(old_revision) & set(new_revision):
        raise ContractViolation(
            ErrorCode.BINDING_MISMATCH,
            "Cross-identity source match is ambiguous without an explicit lineage directive",
            category=ErrorCategory.CONTENT,
        )
    events.extend(ReconciliationEventV0(ReconciliationStateV0.REMOVED, (row,), ()) for row in sorted(old_remaining))
    events.extend(ReconciliationEventV0(ReconciliationStateV0.ADDED, (), (row,)) for row in sorted(new_remaining))
    events.sort(key=lambda row: (row.state.value, row.old_ids, row.new_ids))
    tombstones = tuple(sorted((set(previous_by_id) - set(current_by_id))))

    target_rows: list[TargetValidityV0] = []
    target_ids: set[str] = set()
    for binding in target_bindings:
        target_id = display_id(binding.target_identity)
        if target_id in target_ids:
            raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Duplicate target binding")
        target_ids.add(target_id)
        removed: list[str] = []
        stale: list[str] = []
        for dependency in binding.source_dependencies:
            source_id = display_id(dependency.identity)
            current_row = current_by_id.get(source_id)
            if current_row is None:
                removed.append(source_id)
            elif current_row.source_revision_sha != dependency.source_revision_sha:
                stale.append(source_id)
        if removed:
            state = TargetValidityStateV0.REMOVED_SOURCE
            invalid = tuple(sorted(removed + stale))
        elif stale:
            state = TargetValidityStateV0.STALE_SOURCE
            invalid = tuple(sorted(stale))
        else:
            state = TargetValidityStateV0.VALID
            invalid = ()
        target_rows.append(TargetValidityV0(target_id, state, invalid))
    target_rows.sort(key=lambda row: row.target_id)
    return SourceReconciliationV0(
        None if previous is None else previous.lock.corpus_digest,
        current.lock.corpus_digest,
        tuple(events),
        tombstones,
        tuple(target_rows),
    )


def rebind_source_authority_v0(
    corpus: LoadedSourceCorpusV0,
    reconciliation: SourceReconciliationV0,
    *,
    config_snapshot_sha256: str,
) -> tuple[LoadedSourceCorpusV0, SourceReconciliationV0]:
    """Rebind already parsed source authority to an exact config snapshot."""

    if type(corpus) is not LoadedSourceCorpusV0 or type(reconciliation) is not SourceReconciliationV0:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Source authority rebinding input is invalid")
    if type(config_snapshot_sha256) is not str or SHA256_RE.fullmatch(config_snapshot_sha256) is None:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Config snapshot SHA must be lowercase SHA-256")
    if reconciliation.current_corpus_digest != corpus.lock.corpus_digest:
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Source reconciliation differs from loaded corpus")
    rebound_corpus = _rebind_loaded_source_corpus_v0(corpus, config_snapshot_sha256)
    return rebound_corpus, reconcile_sources_v0(rebound_corpus)
