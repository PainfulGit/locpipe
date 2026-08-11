from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from locpipe.contracts.v0 import ContractViolation, ErrorCategory, ErrorCode
from locpipe.contracts.v0.artifacts import has_reparse_component

from ._context_models import ProjectContextV0, ProjectPathsV0
from ._transaction_storage import (
    SyntheticTransactionStoreV0,
    _assert_store_layout,
    _canonical_document,
    _read_object,
)


CONTEXTS_DIRECTORY = "contexts"
CONTEXT_MARKER = "context.json"
CONTEXT_KIND = "project_context_v0"
CONTEXT_DIRECTORIES = ("cache", "outputs", "receipts", "staging", "state", "transactions")


def _context_violation(detail: str) -> ContractViolation:
    return ContractViolation(
        ErrorCode.BINDING_MISMATCH,
        detail,
        category=ErrorCategory.CONFIGURATION,
    )


def _paths(store: SyntheticTransactionStoreV0, context: ProjectContextV0) -> ProjectPathsV0:
    namespace_root = (store.root / CONTEXTS_DIRECTORY / context.namespace.token).absolute()
    return ProjectPathsV0(
        namespace_root=namespace_root,
        state_root=namespace_root / "state",
        cache_root=namespace_root / "cache",
        staging_root=namespace_root / "staging",
        transactions_root=namespace_root / "transactions",
        receipts_root=namespace_root / "receipts",
        outputs_root=namespace_root / "outputs",
    )


def _marker(context: ProjectContextV0) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": CONTEXT_KIND,
        "context": context.as_dict(),
        "context_digest": context.context_digest,
    }


def _assert_safe_directory(store: SyntheticTransactionStoreV0, path: Path, name: str) -> None:
    if not path.is_dir() or path.is_symlink() or has_reparse_component(store.root, path):
        raise ContractViolation(ErrorCode.PATH_ESCAPE, f"Unsafe project context {name}")


def _assert_root_entries(paths: ProjectPathsV0, *, marker_required: bool) -> None:
    expected = set(CONTEXT_DIRECTORIES)
    if marker_required:
        expected.add(CONTEXT_MARKER)
    actual = {path.name for path in paths.namespace_root.iterdir()}
    unknown = actual - expected
    if unknown:
        raise _context_violation(f"Unknown project context entries: {sorted(unknown)}")


def _validate_marker(store: SyntheticTransactionStoreV0, context: ProjectContextV0, path: Path) -> None:
    if not path.is_file() or path.is_symlink() or has_reparse_component(store.root, path):
        raise _context_violation("Project context marker is missing or unsafe")
    try:
        value = _read_object(path, "project context marker")
    except Exception as error:
        raise _context_violation("Project context marker is malformed") from error
    if value != _marker(context):
        raise _context_violation("Project context marker binding drift")


def _write_marker_exclusive(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    marker_path: Path,
) -> None:
    payload = _canonical_document(_marker(context))
    try:
        descriptor = os.open(marker_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        _validate_marker(store, context, marker_path)
        return
    try:
        remaining = memoryview(payload)
        while remaining:
            remaining = remaining[os.write(descriptor, remaining) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _assert_empty_partial_directories(
    store: SyntheticTransactionStoreV0,
    paths: ProjectPathsV0,
) -> None:
    for name in CONTEXT_DIRECTORIES:
        directory = paths.namespace_root / name
        if directory.exists():
            _assert_safe_directory(store, directory, name)
            if any(directory.iterdir()):
                raise _context_violation(f"Unbound partial context directory is not empty: {name}")


def resolve_project_paths(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
) -> ProjectPathsV0:
    if not isinstance(store, SyntheticTransactionStoreV0) or not isinstance(context, ProjectContextV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid project context binding")
    _assert_store_layout(store)
    contexts_root = store.root / CONTEXTS_DIRECTORY
    _assert_safe_directory(store, contexts_root, "root")
    paths = _paths(store, context)
    _assert_safe_directory(store, paths.namespace_root, "namespace")
    _assert_root_entries(paths, marker_required=True)
    _validate_marker(store, context, paths.namespace_root / CONTEXT_MARKER)
    for name in CONTEXT_DIRECTORIES:
        _assert_safe_directory(store, paths.namespace_root / name, name)
    return paths


def initialize_project_context(
    store: SyntheticTransactionStoreV0,
    context: ProjectContextV0,
    *,
    _failure_hook: Callable[[str], None] | None = None,
) -> ProjectPathsV0:
    if not isinstance(store, SyntheticTransactionStoreV0) or not isinstance(context, ProjectContextV0):
        raise ContractViolation(ErrorCode.MALFORMED_ARTIFACT, "Invalid project context binding")
    _assert_store_layout(store)
    contexts_root = store.root / CONTEXTS_DIRECTORY
    contexts_root.mkdir(exist_ok=True)
    _assert_safe_directory(store, contexts_root, "root")
    paths = _paths(store, context)
    paths.namespace_root.mkdir(exist_ok=True)
    _assert_safe_directory(store, paths.namespace_root, "namespace")
    marker_path = paths.namespace_root / CONTEXT_MARKER
    if marker_path.exists():
        return resolve_project_paths(store, context)
    _assert_root_entries(paths, marker_required=False)
    _assert_empty_partial_directories(store, paths)
    for name in CONTEXT_DIRECTORIES:
        directory = paths.namespace_root / name
        if directory.exists():
            _assert_safe_directory(store, directory, name)
        else:
            directory.mkdir(exist_ok=True)
            _assert_safe_directory(store, directory, name)
        if _failure_hook:
            _failure_hook(f"AFTER_CONTEXT_DIRECTORY:{name}")
    _assert_root_entries(paths, marker_required=False)
    _assert_empty_partial_directories(store, paths)
    _write_marker_exclusive(store, context, marker_path)
    if _failure_hook:
        _failure_hook("AFTER_CONTEXT_MARKER")
    return resolve_project_paths(store, context)
