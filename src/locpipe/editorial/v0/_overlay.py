from __future__ import annotations

from locpipe.contracts.v0 import BranchIdentity, ContractViolation, ErrorCode, display_id, parse_canonical_json, raw_sha256

from ._evidence import CorrectionOverlayV0
from ._models import EditorialCandidateSetV0, candidate_raw_sha


def _logical_key(payload: bytes) -> tuple[tuple[str, ...], tuple[str, ...]]:
    identity = BranchIdentity.from_dict(parse_canonical_json(payload)["data"]["identity"])
    return identity.logical_id, identity.selector_path


def apply_correction_overlay_v0(
    parent: EditorialCandidateSetV0,
    overlay: CorrectionOverlayV0,
    *,
    job_id: str,
    ready: bool,
    disposition: str,
    unresolved_ids: tuple[str, ...],
) -> EditorialCandidateSetV0:
    if overlay.parent_candidate_sha256 != candidate_raw_sha(parent):
        raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Correction overlay parent candidate drift")
    targets = {_logical_key(payload): payload for payload in parent._target_bytes}
    if len(targets) != len(parent._target_bytes):
        raise ContractViolation(ErrorCode.DUPLICATE_IDENTITY, "Editorial parent target logical collision")
    for entry in overlay.entries:
        key = (entry.source_identity.logical_id, entry.source_identity.selector_path)
        current = targets.get(key)
        if current is None:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Correction overlay target is outside candidate")
        if raw_sha256(current) != entry.preimage_target_sha256:
            raise ContractViolation(ErrorCode.HASH_MISMATCH, "Correction overlay target preimage drift")
        if raw_sha256(entry._replacement_bytes) == entry.preimage_target_sha256:
            raise ContractViolation(ErrorCode.BINDING_MISMATCH, "Correction overlay cannot contain no-op replacement")
        targets[key] = entry._replacement_bytes
    ordered = tuple(sorted(
        targets.values(),
        key=lambda payload: display_id(BranchIdentity.from_dict(parse_canonical_json(payload)["data"]["identity"])),
    ))
    return EditorialCandidateSetV0(
        job_id,
        parent.target_locale,
        ready,
        disposition,
        parent.base_target_set_sha256,
        candidate_raw_sha(parent),
        parent.overlay_sha256s + (overlay.raw_digest,),
        unresolved_ids,
        ordered,
    )
