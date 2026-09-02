"""Process-local prepared source authority.

Preparation retains the accepted raw bytes, the compatibility corpus, one prepared
row layer, and immutable indexes whose values reference those exact rows.  It does
not retain a second per-row collection or duplicate payload, constraint, or relation
envelope buffers.  That representation overlap is paid once per accepted authority;
warm batch work is proportional to selected rows plus their incident dependencies.

This is a trusted-process contract.  The binder rejects ordinary unsupported
construction, copying, pickling, cross-process use, and top-level container or index
substitution.  Deliberate same-process mutation through ``object.__setattr__``,
monkeypatching, ``ctypes``, or private registry manipulation is outside the contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import threading
from types import MappingProxyType
from typing import TYPE_CHECKING, Mapping
import weakref

from locpipe.contracts.v0 import (
    BranchIdentity,
    ContractViolation,
    ErrorCode,
    canonical_json_bytes,
    canonical_value_bytes,
    display_id,
    raw_sha256,
    semantic_sha256,
    strict_loads,
)

if TYPE_CHECKING:
    from ._corpus import LoadedSourceCorpusV0
    from ._reconciliation import SourceReconciliationV0


@dataclass(frozen=True, slots=True)
class PreparedSourceSegmentV0:
    identity: BranchIdentity
    content_type: str
    source_revision_sha: str
    locator_sha256: str
    payload_bytes: bytes
    constraints_bytes: bytes
    text_payload: str | None

    def __post_init__(self) -> None:
        payload = strict_loads(self.payload_bytes) if type(self.payload_bytes) is bytes else None
        constraints = strict_loads(self.constraints_bytes) if type(self.constraints_bytes) is bytes else None
        if (
            not isinstance(self.identity, BranchIdentity)
            or type(self.content_type) is not str
            or not self.content_type
            or type(self.source_revision_sha) is not str
            or type(self.locator_sha256) is not str
            or canonical_value_bytes(payload) != self.payload_bytes
            or canonical_value_bytes(constraints) != self.constraints_bytes
            or self.text_payload != (payload if type(payload) is str else None)
        ):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Prepared source segment is invalid")

    @property
    def stable_id(self) -> str:
        return display_id(self.identity)


@dataclass(frozen=True, slots=True)
class PreparedSourceRelationV0:
    digest: str
    relation_type: str
    envelope_bytes: bytes
    branch_ids: tuple[str, ...]
    logical_ids: tuple[tuple[str, ...], ...]

    def __post_init__(self) -> None:
        envelope = strict_loads(self.envelope_bytes) if type(self.envelope_bytes) is bytes else None
        if (
            type(self.digest) is not str
            or type(self.relation_type) is not str
            or not self.relation_type
            or canonical_json_bytes(envelope) != self.envelope_bytes
            or semantic_sha256(envelope) != self.digest
            or self.branch_ids != tuple(sorted(set(self.branch_ids)))
            or self.logical_ids != tuple(sorted(set(self.logical_ids)))
        ):
            raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Prepared source relation is invalid")


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False, init=False, repr=False)
class PreparedSourceAuthorityV0:
    corpus: LoadedSourceCorpusV0 = field(init=False)
    reconciliation: SourceReconciliationV0 = field(init=False)
    source_lock_bytes: bytes = field(init=False)
    reconciliation_bytes: bytes = field(init=False)
    segments_bytes: bytes = field(init=False)
    relations_bytes: bytes | None = field(init=False)
    segments: tuple[PreparedSourceSegmentV0, ...] = field(init=False)
    relations: tuple[PreparedSourceRelationV0, ...] = field(init=False)
    _segment_index: Mapping[str, PreparedSourceSegmentV0] = field(init=False, repr=False)
    _revision_index: Mapping[str, str] = field(init=False, repr=False)
    _relations_by_branch: Mapping[str, tuple[PreparedSourceRelationV0, ...]] = field(init=False, repr=False)
    _relations_by_logical: Mapping[tuple[str, ...], tuple[PreparedSourceRelationV0, ...]] = field(
        init=False,
        repr=False,
    )
    _segments_by_logical: Mapping[tuple[str, ...], tuple[str, ...]] = field(init=False, repr=False)
    _source_lock_sha256: str = field(init=False, repr=False)
    _reconciliation_sha256: str = field(init=False, repr=False)
    _segments_sha256: str = field(init=False, repr=False)
    _reconciliation_digest: str = field(init=False, repr=False)

    def __init__(self) -> None:
        raise TypeError("Prepared source authority is factory-bound")

    def __copy__(self) -> PreparedSourceAuthorityV0:
        raise TypeError("Prepared source authority cannot be copied")

    def __deepcopy__(self, memo: object) -> PreparedSourceAuthorityV0:
        raise TypeError("Prepared source authority cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("Prepared source authority cannot be pickled")

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("Prepared source authority cannot be pickled")


@dataclass(frozen=True, slots=True)
class _BinderRecord:
    reference: weakref.ReferenceType[PreparedSourceAuthorityV0]
    state: tuple[object, ...]
    segment_index_id: int
    source_lock_key: tuple[int, str]
    process_id: int


_BINDER_LOCK = threading.RLock()
_BINDER_LIMIT = 1024
_BINDER_REGISTRY: dict[int, _BinderRecord] = {}
_SOURCE_LOCK_BINDINGS: dict[tuple[int, str], weakref.ReferenceType[PreparedSourceAuthorityV0]] = {}
_MAPPING_PROXY_TYPE = type(MappingProxyType({}))


def _authority_state(authority: PreparedSourceAuthorityV0) -> tuple[int, ...]:
    return (
        id(authority.corpus),
        id(authority.reconciliation),
        id(authority.source_lock_bytes),
        id(authority.reconciliation_bytes),
        id(authority.segments_bytes),
        id(authority.relations_bytes),
        id(authority.segments),
        id(authority.relations),
        id(authority._segment_index),
        id(authority._revision_index),
        id(authority._relations_by_branch),
        id(authority._relations_by_logical),
        id(authority._segments_by_logical),
        id(authority._source_lock_sha256),
        id(authority._reconciliation_sha256),
        id(authority._segments_sha256),
        id(authority._reconciliation_digest),
    )


def _bind_prepared_source_authority_v0(
    corpus: LoadedSourceCorpusV0,
    reconciliation: SourceReconciliationV0,
    *,
    source_lock_bytes: bytes,
    reconciliation_bytes: bytes,
    segments_bytes: bytes,
    relations_bytes: bytes | None,
    segments: tuple[PreparedSourceSegmentV0, ...],
    relations: tuple[PreparedSourceRelationV0, ...],
    segment_index: Mapping[str, PreparedSourceSegmentV0] | None = None,
    revision_index: Mapping[str, str] | None = None,
    relations_by_branch: Mapping[str, tuple[PreparedSourceRelationV0, ...]] | None = None,
    relations_by_logical: Mapping[tuple[str, ...], tuple[PreparedSourceRelationV0, ...]] | None = None,
    segments_by_logical: Mapping[tuple[str, ...], tuple[str, ...]] | None = None,
) -> PreparedSourceAuthorityV0:
    authority = object.__new__(PreparedSourceAuthorityV0)
    rows = tuple(segments)
    relation_rows = tuple(relations)
    if segment_index is None:
        index = MappingProxyType({row.stable_id: row for row in rows})
        revisions = MappingProxyType({row.stable_id: row.source_revision_sha for row in rows})
        branch_buckets: dict[str, list[PreparedSourceRelationV0]] = {}
        logical_buckets: dict[tuple[str, ...], list[PreparedSourceRelationV0]] = {}
        segment_logical_buckets: dict[tuple[str, ...], list[str]] = {}
        for row in rows:
            segment_logical_buckets.setdefault(row.identity.logical_id, []).append(row.stable_id)
        for relation in relation_rows:
            for stable_id in relation.branch_ids:
                branch_buckets.setdefault(stable_id, []).append(relation)
            for logical_id in relation.logical_ids:
                logical_buckets.setdefault(logical_id, []).append(relation)
        by_branch = MappingProxyType({key: tuple(value) for key, value in branch_buckets.items()})
        by_logical = MappingProxyType({key: tuple(value) for key, value in logical_buckets.items()})
        segments_for_logical = MappingProxyType({
            key: tuple(value) for key, value in segment_logical_buckets.items()
        })
    elif (
        type(segment_index) is _MAPPING_PROXY_TYPE
        and type(revision_index) is _MAPPING_PROXY_TYPE
        and type(relations_by_branch) is _MAPPING_PROXY_TYPE
        and type(relations_by_logical) is _MAPPING_PROXY_TYPE
        and type(segments_by_logical) is _MAPPING_PROXY_TYPE
    ):
        index = segment_index
        revisions = revision_index
        by_branch = relations_by_branch
        by_logical = relations_by_logical
        segments_for_logical = segments_by_logical
    else:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Prepared source indexes are mutable or incomplete")
    if segment_index is None and (tuple(index) != corpus.lock.branch_ids or tuple(index.values()) != rows):
        raise ContractViolation(ErrorCode.HASH_MISMATCH, "Prepared source rows differ from accepted corpus")
    values = {
        "corpus": corpus,
        "reconciliation": reconciliation,
        "source_lock_bytes": bytes(source_lock_bytes),
        "reconciliation_bytes": bytes(reconciliation_bytes),
        "segments_bytes": bytes(segments_bytes),
        "relations_bytes": None if relations_bytes is None else bytes(relations_bytes),
        "segments": rows,
        "relations": relation_rows,
        "_segment_index": index,
        "_revision_index": revisions,
        "_relations_by_branch": by_branch,
        "_relations_by_logical": by_logical,
        "_segments_by_logical": segments_for_logical,
        "_source_lock_sha256": raw_sha256(source_lock_bytes),
        "_reconciliation_sha256": raw_sha256(reconciliation_bytes),
        "_segments_sha256": corpus.lock.segments_sha256,
        "_reconciliation_digest": reconciliation.digest,
    }
    for name, value in values.items():
        object.__setattr__(authority, name, value)
    key = id(authority)
    source_lock_key = (id(corpus), raw_sha256(authority.source_lock_bytes))

    def cleanup(reference: weakref.ReferenceType[PreparedSourceAuthorityV0]) -> None:
        with _BINDER_LOCK:
            current = _BINDER_REGISTRY.get(key)
            if current is not None and current.reference is reference:
                del _BINDER_REGISTRY[key]
            if _SOURCE_LOCK_BINDINGS.get(source_lock_key) is reference:
                del _SOURCE_LOCK_BINDINGS[source_lock_key]

    reference = weakref.ref(authority, cleanup)
    record = _BinderRecord(reference, _authority_state(authority), id(index), source_lock_key, os.getpid())
    with _BINDER_LOCK:
        if len(_BINDER_REGISTRY) >= _BINDER_LIMIT:
            raise ContractViolation(ErrorCode.CAPABILITY_MISSING, "Prepared source binder capacity is exhausted")
        _BINDER_REGISTRY[key] = record
        _SOURCE_LOCK_BINDINGS[source_lock_key] = reference
    return authority


def _prepared_source_parts_v0(
    authority: PreparedSourceAuthorityV0,
) -> PreparedSourceAuthorityV0:
    if type(authority) is not PreparedSourceAuthorityV0:
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Prepared source authority is invalid")
    with _BINDER_LOCK:
        record = _BINDER_REGISTRY.get(id(authority))
        if record is None or record.reference() is not authority or record.process_id != os.getpid():
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Prepared source authority is not bound in this process")
        if record.segment_index_id != id(authority._segment_index) or record.state != _authority_state(authority):
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Prepared source authority was tampered")
    return authority


def _incident_prepared_relation_bytes_v0(
    branch_ids: set[str],
    logical_ids: set[tuple[str, ...]],
    relations_by_branch: Mapping[str, tuple[PreparedSourceRelationV0, ...]],
    relations_by_logical: Mapping[tuple[str, ...], tuple[PreparedSourceRelationV0, ...]],
) -> tuple[bytes, ...]:
    selected: dict[str, PreparedSourceRelationV0] = {}
    for stable_id in branch_ids:
        for relation in relations_by_branch.get(stable_id, ()):
            selected.setdefault(relation.digest, relation)
    for logical_id in logical_ids:
        for relation in relations_by_logical.get(logical_id, ()):
            selected.setdefault(relation.digest, relation)
    return tuple(selected[digest].envelope_bytes for digest in sorted(selected))


def _bound_source_lock_v0(payload: bytes, corpus: LoadedSourceCorpusV0) -> object | None:
    source_lock_key = (id(corpus), raw_sha256(payload))
    with _BINDER_LOCK:
        reference = _SOURCE_LOCK_BINDINGS.get(source_lock_key)
        authority = None if reference is None else reference()
        record = None if authority is None else _BINDER_REGISTRY.get(id(authority))
        if (
            authority is not None
            and record is not None
            and record.process_id == os.getpid()
            and authority.corpus is corpus
            and authority.source_lock_bytes == payload
        ):
            return corpus.lock
    return None
