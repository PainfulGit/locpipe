from __future__ import annotations

import os
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from locpipe.contracts.v0 import WorkflowProfile  # noqa: E402
from locpipe.kernel.v0.context import (  # noqa: E402
    ProjectContextV0,
    acquire_context_write_lease,
    initialize_project_context,
    release_context_write_lease,
)
from locpipe.kernel.v0.transactions import NamespaceV0, SyntheticTransactionStoreV0  # noqa: E402


OWNER = "c" * 32
CONFIG_SHA = "a" * 64


def context() -> ProjectContextV0:
    return ProjectContextV0(
        NamespaceV0("workspace", "project", "release"),
        WorkflowProfile.CONTENT_ONLY,
        CONFIG_SHA,
    )


def hold(root: Path, ready: Path, release: Path) -> int:
    store = SyntheticTransactionStoreV0(root)
    selected = context()
    lease = acquire_context_write_lease(
        store,
        selected,
        "context-hold",
        owner_token_factory=lambda: OWNER,
    )
    ready.write_text("ready", encoding="ascii")
    deadline = time.monotonic() + 20
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    if not release.exists():
        return 3
    release_context_write_lease(store, selected, lease)
    return 0


def init_crash(root: Path, boundary: str) -> int:
    store = SyntheticTransactionStoreV0(root)

    def terminate(point: str) -> None:
        if point == boundary:
            os._exit(81)

    initialize_project_context(store, context(), _failure_hook=terminate)
    return 0


def main() -> int:
    if len(sys.argv) < 4:
        return 2
    mode = sys.argv[1]
    root = Path(sys.argv[2])
    if mode == "hold" and len(sys.argv) == 5:
        return hold(root, Path(sys.argv[3]), Path(sys.argv[4]))
    if mode == "init-crash" and len(sys.argv) == 4:
        return init_crash(root, sys.argv[3])
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
