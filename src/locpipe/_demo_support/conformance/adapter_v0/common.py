from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from locpipe.contracts.v0 import (
    AdapterDescriptorV0,
    BranchIdentity,
    CONTRACT_VERSION,
    KIND_TO_SCHEMA,
    display_id,
    semantic_sha256,
    source_revision_sha,
)


def descriptor_data(descriptor: AdapterDescriptorV0) -> dict[str, object]:
    return {
        "adapter_id": descriptor.adapter_id,
        "version": descriptor.version,
        "digest": descriptor.digest,
        "capabilities": [capability.value for capability in descriptor.capabilities],
    }


def source_envelope(
    identity: BranchIdentity,
    payload: str,
    *,
    locator: Mapping[str, Any],
    constraints: Mapping[str, Any] | None = None,
) -> dict[str, object]:
    effective_constraints = dict(constraints or {"placeholder": "none"})
    return {
        "schema_id": KIND_TO_SCHEMA["source_branch"],
        "schema_version": CONTRACT_VERSION,
        "kind": "source_branch",
        "data": {
            "identity": identity.as_dict(),
            "content_type": "plain_text",
            "payload": payload,
            "constraints": effective_constraints,
            "source_revision_sha": source_revision_sha(
                identity=identity,
                content_type="plain_text",
                payload=payload,
                constraints=effective_constraints,
            ),
            "locator": dict(locator),
        },
    }


def snapshot_envelope(
    descriptor: AdapterDescriptorV0,
    source_sha256: str,
    source_version: str,
    identities: tuple[BranchIdentity, ...],
    *,
    snapshot_id: str,
) -> dict[str, object]:
    return {
        "schema_id": KIND_TO_SCHEMA["source_snapshot"],
        "schema_version": CONTRACT_VERSION,
        "kind": "source_snapshot",
        "data": {
            "snapshot_id": snapshot_id,
            "source_locale": identities[0].locale,
            "source_version": source_version,
            "source_raw_sha256": source_sha256,
            "adapter": descriptor_data(descriptor),
            "branch_ids": sorted(display_id(identity) for identity in identities),
        },
    }


def relation_envelope(
    relation_type: str,
    identity: BranchIdentity,
) -> dict[str, object]:
    return {
        "schema_id": KIND_TO_SCHEMA["relation"],
        "schema_version": CONTRACT_VERSION,
        "kind": "relation",
        "data": {
            "relation_type": relation_type,
            "from_ref": {"kind": "branch", "identity": identity.as_dict()},
            "to_ref": {"kind": "logical_message", "logical_id": list(identity.logical_id)},
        },
    }


def directory_manifest_sha256(root) -> str:
    rows = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]
    return semantic_sha256(rows)
