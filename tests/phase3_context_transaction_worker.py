from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from locpipe.contracts.v0 import ArtifactHashV0, WorkflowProfile  # noqa: E402
from locpipe.kernel.v0.context import (  # noqa: E402
    ProjectContextV0,
    acquire_context_write_lease,
    initialize_project_context,
)
from locpipe.kernel.v0.context_transactions import (  # noqa: E402
    create_context_staging,
    inspect_context_file_recovery,
    inspect_context_group_recovery,
    publish_context_file,
    publish_context_group,
    rollback_context_file,
    rollback_context_group,
)
from locpipe.kernel.v0.transactions import (  # noqa: E402
    NamespaceV0,
    PublicationEntryV0,
    PublicationGroupSpecV0,
    PublicationSpecV0,
    SyntheticTransactionStoreV0,
)


OWNER = "7" * 32
CONTEXT = ProjectContextV0(
    NamespaceV0("workspace", "project", "release"),
    WorkflowProfile.CONTENT_ONLY,
    "a" * 64,
)


def raw_sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def terminate_at(boundary: str, exit_code: int):
    def hook(point: str) -> None:
        if point == boundary:
            os._exit(exit_code)

    return hook


def single_fixture(store: SyntheticTransactionStoreV0):
    paths = initialize_project_context(store, CONTEXT)
    target = paths.outputs_root / "result.bin"
    target.write_bytes(b"old\n")
    lease = acquire_context_write_lease(
        store, CONTEXT, "single-crash", owner_token_factory=lambda: OWNER
    )
    staging = create_context_staging(store, CONTEXT, "single-crash")
    payload = b"new\n"
    (staging / "result.bin").write_bytes(payload)
    spec = PublicationSpecV0(
        CONTEXT.namespace,
        "single-crash",
        "result.bin",
        ArtifactHashV0("result.bin", "raw", raw_sha(payload)),
        raw_sha(b"old\n"),
    )
    return lease, spec


def group_fixture(store: SyntheticTransactionStoreV0):
    paths = initialize_project_context(store, CONTEXT)
    (paths.outputs_root / "a.bin").write_bytes(b"old-a\n")
    lease = acquire_context_write_lease(
        store, CONTEXT, "group-crash", owner_token_factory=lambda: OWNER
    )
    staging = create_context_staging(store, CONTEXT, "group-crash")
    payloads = {"a.bin": b"new-a\n", "b.bin": b"new-b\n"}
    entries = []
    for name, payload in payloads.items():
        (staging / name).write_bytes(payload)
        entries.append(PublicationEntryV0(
            ArtifactHashV0(name, "raw", raw_sha(payload)),
            raw_sha(b"old-a\n") if name == "a.bin" else None,
        ))
    return lease, PublicationGroupSpecV0(CONTEXT.namespace, "group-crash", tuple(entries))


def main() -> int:
    mode, root_text, boundary = sys.argv[1:4]
    store = SyntheticTransactionStoreV0(Path(root_text))
    if mode == "single-publish":
        lease, spec = single_fixture(store)
        publish_context_file(store, CONTEXT, spec, lease, _failure_hook=terminate_at(boundary, 81))
    elif mode == "single-rollback":
        lease, spec = single_fixture(store)

        def interrupt(point: str) -> None:
            if point == "AFTER_RECEIPT_BEFORE_VERIFIED":
                raise RuntimeError(point)

        try:
            publish_context_file(store, CONTEXT, spec, lease, _failure_hook=interrupt)
        except RuntimeError:
            pass
        rollback_context_file(
            store,
            CONTEXT,
            inspect_context_file_recovery(store, CONTEXT, spec.operation_id),
            lease,
            _failure_hook=terminate_at(boundary, 82),
        )
    elif mode == "group-publish":
        lease, spec = group_fixture(store)
        publish_context_group(store, CONTEXT, spec, lease, _failure_hook=terminate_at(boundary, 83))
    elif mode == "group-rollback":
        lease, spec = group_fixture(store)

        def interrupt(point: str) -> None:
            if point == "AFTER_GROUP_RECEIPT_BEFORE_VERIFIED":
                raise RuntimeError(point)

        try:
            publish_context_group(store, CONTEXT, spec, lease, _failure_hook=interrupt)
        except RuntimeError:
            pass
        rollback_context_group(
            store,
            CONTEXT,
            inspect_context_group_recovery(store, CONTEXT, spec.operation_id),
            lease,
            _failure_hook=terminate_at(boundary, 84),
        )
    else:
        raise ValueError(mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
