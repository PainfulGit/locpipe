from __future__ import annotations

import hashlib
import json
import posixpath
import re
import subprocess
from pathlib import Path
from typing import Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "PUBLIC_EXPORT_MANIFEST.json"
TEXT_SUFFIXES = {".cfg", ".csv", ".json", ".jsonl", ".lock", ".md", ".py", ".toml", ".txt", ".yml", ".yaml"}
WINDOWS_ABSOLUTE = re.compile(rb"(?<![A-Za-z0-9+.-])[A-Za-z]:[\\/](?![\\/])")
UNC_ABSOLUTE = re.compile(rb"(?<![\\/])\\\\(?![?.])[A-Za-z0-9._$ -]+\\[A-Za-z0-9._$ -]+")
WINDOWS_DEVICE_ABSOLUTE = re.compile(rb"(?<![\\/])\\\\[?.]\\[^\\/\r\n]+(?:\\[^\\/\r\n]+)*")
POSIX_ABSOLUTE = re.compile(rb"(?<![A-Za-z0-9+.:/#\-}])/(?:home|Users|tmp|var|opt|private|etc|root|mnt)(?:/[A-Za-z0-9._~ -]+)*")
DENY_TOKENS = (
    ("Citizen" + " Sleeper").encode(),
    ("Suze" + "rain").encode(),
    ("Unity" + "Py").encode(),
    ("work/localization" + "_pipeline").encode(),
    ("private" + "_fixtures").encode(),
    ("steamapps" + "/common").encode(),
)
ALLOWED_GIT_IDENTITIES = {
    ("PainfulGit", "258659461+PainfulGit@users.noreply.github.com"),
}
MANIFEST_KEYS = frozenset({"classification", "files", "schema_version", "tree_sha256"})
MANIFEST_ROW_KEYS = frozenset({"path", "sha256", "size"})
MANIFEST_CLASSIFICATION = "PUBLIC_EXPORT"
MANIFEST_SCHEMA_VERSION = 1
TREE_CONTRACT = "locpipe.public-export-tree/v1"
SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_public_path(path: object) -> str:
    if not isinstance(path, str) or not path:
        raise SystemExit("public export manifest path is malformed")
    if (
        path.startswith("/")
        or "\\" in path
        or ":" in path
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise SystemExit(f"unsafe public export path rejected: {path}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts) or posixpath.normpath(path) != path:
        raise SystemExit(f"unsafe public export path rejected: {path}")
    return path


def _validated_manifest_rows(rows: object) -> tuple[dict[str, object], ...]:
    if not isinstance(rows, list):
        raise SystemExit("public export manifest files are malformed")
    validated: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != MANIFEST_ROW_KEYS:
            raise SystemExit("public export manifest row is malformed")
        path = _canonical_public_path(row["path"])
        sha256 = row["sha256"]
        size = row["size"]
        if not isinstance(sha256, str) or SHA256_HEX.fullmatch(sha256) is None:
            raise SystemExit(f"public export manifest sha256 is malformed: {path}")
        if type(size) is not int or size < 0:
            raise SystemExit(f"public export manifest size is malformed: {path}")
        validated.append({"path": path, "sha256": sha256, "size": size})
    paths = tuple(row["path"] for row in validated)
    if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
        raise SystemExit("public export manifest paths are not sorted and unique")
    return tuple(validated)


def _manifest_tree_sha256(rows: Sequence[Mapping[str, object]]) -> str:
    projection = {"contract": TREE_CONTRACT, "files": list(rows)}
    return hashlib.sha256(_canonical_json_bytes(projection)).hexdigest()


def _manifest_bytes(rows: Sequence[Mapping[str, object]]) -> bytes:
    value = {
        "classification": MANIFEST_CLASSIFICATION,
        "files": list(rows),
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "tree_sha256": _manifest_tree_sha256(rows),
    }
    return _canonical_json_bytes(value) + b"\n"


def _strict_json_loads(payload: bytes) -> object:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit("public export manifest is malformed") from exc


def _is_text(path: str) -> bool:
    value = Path(path)
    return value.suffix.lower() in TEXT_SUFFIXES or value.name in {"LICENSE", ".gitignore", ".gitattributes"}


def _scan_payload(path: str, payload: bytes) -> None:
    if not _is_text(path):
        return
    if any(pattern.search(payload) for pattern in (WINDOWS_ABSOLUTE, UNC_ABSOLUTE, WINDOWS_DEVICE_ABSOLUTE, POSIX_ABSOLUTE)):
        raise SystemExit(f"absolute path rejected: {path}")
    folded = payload.lower()
    if any(token.lower() in folded for token in DENY_TOKENS):
        raise SystemExit(f"private token rejected: {path}")


def _tracked_files(*, root: Path = ROOT) -> tuple[str, ...]:
    output = subprocess.check_output(
        ("git", "ls-tree", "-r", "--name-only", "-z", "HEAD"),
        cwd=root,
    )
    paths = tuple(sorted(row.decode("utf-8") for row in output.split(b"\0") if row))
    for path in paths:
        _canonical_public_path(path)
    return paths


def _validate_commit_metadata(rows: tuple[tuple[str, str, str, str, str], ...]) -> None:
    if not rows:
        raise SystemExit("public history is empty")
    for commit, author_name, author_email, committer_name, committer_email in rows:
        if (author_name, author_email) not in ALLOWED_GIT_IDENTITIES:
            raise SystemExit(f"unapproved author identity rejected: {commit}")
        if (committer_name, committer_email) not in ALLOWED_GIT_IDENTITIES:
            raise SystemExit(f"unapproved committer identity rejected: {commit}")


def _scan_commit_metadata() -> int:
    payload = subprocess.check_output(
        ("git", "log", "--all", "-z", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce"),
        cwd=ROOT,
    )
    values = tuple(value.decode("utf-8") for value in payload.split(b"\0") if value)
    if len(values) % 5:
        raise SystemExit("public history metadata is malformed")
    rows = tuple(tuple(values[index:index + 5]) for index in range(0, len(values), 5))
    _validate_commit_metadata(rows)
    return len(rows)


def _validate_manifest_value(
    value: object,
    paths: tuple[str, ...],
    read_blob: Callable[[str], bytes],
    *,
    manifest_name: str = MANIFEST.name,
) -> None:
    if not isinstance(value, dict) or set(value) != MANIFEST_KEYS:
        raise SystemExit("public export manifest top-level shape is malformed")
    if value["classification"] != MANIFEST_CLASSIFICATION:
        raise SystemExit("public export manifest classification is invalid")
    if type(value["schema_version"]) is not int or value["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise SystemExit("public export manifest schema version is invalid")
    tree_sha256 = value["tree_sha256"]
    if not isinstance(tree_sha256, str) or SHA256_HEX.fullmatch(tree_sha256) is None:
        raise SystemExit("public export manifest tree sha256 is malformed")
    rows = _validated_manifest_rows(value["files"])
    expected = tuple(path for path in paths if path != manifest_name)
    actual = tuple(row["path"] for row in rows)
    if actual != expected:
        raise SystemExit("public export manifest path set drift")
    for row in rows:
        payload = read_blob(str(row["path"]))
        if row["size"] != len(payload) or row["sha256"] != hashlib.sha256(payload).hexdigest():
            raise SystemExit(f"public export manifest hash drift: {row['path']}")
    if tree_sha256 != _manifest_tree_sha256(rows):
        raise SystemExit("public export manifest tree sha256 drift")


def _validate_manifest(paths: tuple[str, ...], *, root: Path = ROOT) -> None:
    payload = subprocess.check_output(("git", "show", f"HEAD:{MANIFEST.name}"), cwd=root)
    value = _strict_json_loads(payload)
    _validate_manifest_value(
        value,
        paths,
        lambda path: subprocess.check_output(("git", "show", f"HEAD:{path}"), cwd=root),
    )


def _scan_history() -> int:
    commits = subprocess.check_output(("git", "rev-list", "--all"), cwd=ROOT, text=True).splitlines()
    seen: set[tuple[str, str]] = set()
    for commit in commits:
        paths = subprocess.check_output(("git", "ls-tree", "-r", "--name-only", commit), cwd=ROOT, text=True).splitlines()
        for path in paths:
            key = (commit, path)
            if key in seen:
                continue
            seen.add(key)
            payload = subprocess.check_output(("git", "show", f"{commit}:{path}"), cwd=ROOT)
            _scan_payload(path, payload)
    return len(commits)


def main() -> int:
    paths = _tracked_files()
    for path in paths:
        _scan_payload(path, (ROOT / path).read_bytes())
    _validate_manifest(paths)
    metadata_commits = _scan_commit_metadata()
    commits = _scan_history()
    if commits != metadata_commits:
        raise SystemExit("history and metadata commit counts differ")
    print(json.dumps({"status": "PASS", "tracked_files": len(paths), "history_commits": commits, "private_hits": 0, "absolute_paths": 0, "unapproved_git_identities": 0}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
