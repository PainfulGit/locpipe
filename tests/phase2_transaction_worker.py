from __future__ import annotations

import hashlib
import os
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from locpipe.contracts.v0 import ArtifactHashV0  # noqa: E402
from locpipe.kernel.v0.transactions import (  # noqa: E402
    NamespaceV0,
    PublicationEntryV0,
    PublicationGroupSpecV0,
    PublicationSpecV0,
    SyntheticTransactionStoreV0,
    acquire_write_lease,
    inspect_group_recovery,
    publish_verified_file,
    publish_verified_group,
    release_write_lease,
    rollback_publication_group,
)


OWNER = "a" * 32
NAMESPACE = NamespaceV0("workspace", "project", "release")
GROUP_NAMESPACE = NamespaceV0("workspace", "project", "group-release")


def hold(root: Path, ready: Path, release: Path) -> int:
    store = SyntheticTransactionStoreV0(root)
    lease = acquire_write_lease(store, NAMESPACE, "op-hold", owner_token_factory=lambda: OWNER)
    ready.write_text("ready", encoding="ascii")
    deadline = time.monotonic() + 15
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    if not release.exists():
        return 3
    release_write_lease(store, lease)
    return 0


def crash(root: Path, boundary: str) -> int:
    store = SyntheticTransactionStoreV0(root)
    lease = acquire_write_lease(store, NAMESPACE, "op-crash", owner_token_factory=lambda: OWNER)
    staging = store.create_staging("op-crash")
    artifact = staging / "result.bin"
    payload = b"process postimage"
    artifact.write_bytes(payload)
    spec = PublicationSpecV0(
        NAMESPACE,
        "op-crash",
        "result.bin",
        ArtifactHashV0("result.bin", "raw", hashlib.sha256(payload).hexdigest()),
        None,
    )

    def terminate(point: str) -> None:
        if point == boundary:
            os._exit(71)

    publish_verified_file(store, spec, lease, staging, _failure_hook=terminate)
    return 0


def group_crash(root: Path, boundary: str) -> int:
    store = SyntheticTransactionStoreV0(root)
    preimages = {
        "delta.csv": b"old-delta\r\n",
        "tables/a.csv": b"old-a\n",
        "tables/c.bin": b"old-c\x00",
    }
    postimages = {
        "delta.csv": b"new-delta\n",
        "manifest.json": b'{"state":"new"}\n',
        "tables/a.csv": b"new-a\n",
        "tables/b.csv": b"new-b\n",
        "tables/c.bin": b"new-c\x00",
    }
    target_root = store.target_root(GROUP_NAMESPACE, create=True)
    for relative, payload in preimages.items():
        target = target_root / Path(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    lease = acquire_write_lease(
        store, GROUP_NAMESPACE, "op-group-crash", owner_token_factory=lambda: "e" * 32
    )
    staging = store.create_staging("op-group-crash")
    entries = []
    for relative in sorted(postimages):
        artifact = staging / Path(*relative.split("/"))
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(postimages[relative])
        entries.append(PublicationEntryV0(
            ArtifactHashV0(relative, "raw", hashlib.sha256(postimages[relative]).hexdigest()),
            hashlib.sha256(preimages[relative]).hexdigest() if relative in preimages else None,
        ))
    spec = PublicationGroupSpecV0(GROUP_NAMESPACE, "op-group-crash", tuple(entries))

    def terminate(point: str) -> None:
        if point == boundary:
            os._exit(72)

    publish_verified_group(store, spec, lease, staging, _failure_hook=terminate)
    return 0


def group_rollback_crash(root: Path, boundary: str) -> int:
    class StopPublish(RuntimeError):
        pass

    store = SyntheticTransactionStoreV0(root)
    preimages = {
        "delta.csv": b"old-delta\r\n",
        "tables/a.csv": b"old-a\n",
        "tables/c.bin": b"old-c\x00",
    }
    postimages = {
        "delta.csv": b"new-delta\n",
        "manifest.json": b'{"state":"new"}\n',
        "tables/a.csv": b"new-a\n",
        "tables/b.csv": b"new-b\n",
        "tables/c.bin": b"new-c\x00",
    }
    target_root = store.target_root(GROUP_NAMESPACE, create=True)
    for relative, payload in preimages.items():
        target = target_root / Path(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    lease = acquire_write_lease(
        store, GROUP_NAMESPACE, "op-group-crash", owner_token_factory=lambda: "e" * 32
    )
    staging = store.create_staging("op-group-crash")
    entries = []
    for relative in sorted(postimages):
        artifact = staging / Path(*relative.split("/"))
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(postimages[relative])
        entries.append(PublicationEntryV0(
            ArtifactHashV0(relative, "raw", hashlib.sha256(postimages[relative]).hexdigest()),
            hashlib.sha256(preimages[relative]).hexdigest() if relative in preimages else None,
        ))
    spec = PublicationGroupSpecV0(GROUP_NAMESPACE, "op-group-crash", tuple(entries))

    def stop_publish(point: str) -> None:
        if point == "AFTER_GROUP_RECEIPT_BEFORE_VERIFIED":
            raise StopPublish(point)

    try:
        publish_verified_group(store, spec, lease, staging, _failure_hook=stop_publish)
    except StopPublish:
        pass
    plan = inspect_group_recovery(store, "op-group-crash")

    def terminate(point: str) -> None:
        if point == boundary:
            os._exit(73)

    rollback_publication_group(store, plan, lease, _failure_hook=terminate)
    return 0


def main() -> int:
    if len(sys.argv) < 3:
        return 2
    mode = sys.argv[1]
    root = Path(sys.argv[2])
    if mode == "hold" and len(sys.argv) == 5:
        return hold(root, Path(sys.argv[3]), Path(sys.argv[4]))
    if mode == "crash" and len(sys.argv) == 4:
        return crash(root, sys.argv[3])
    if mode == "group-crash" and len(sys.argv) == 4:
        return group_crash(root, sys.argv[3])
    if mode == "group-rollback-crash" and len(sys.argv) == 4:
        return group_rollback_crash(root, sys.argv[3])
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
