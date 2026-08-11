from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path


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


def _tracked_files() -> tuple[str, ...]:
    output = subprocess.check_output(("git", "ls-files", "-z"), cwd=ROOT)
    return tuple(sorted(row.decode("utf-8") for row in output.split(b"\0") if row))


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


def _validate_manifest(paths: tuple[str, ...]) -> None:
    value = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = value.get("files")
    if not isinstance(rows, list):
        raise SystemExit("public export manifest is malformed")
    expected = tuple(path for path in paths if path != MANIFEST.name)
    actual = tuple(row.get("path") for row in rows)
    if actual != expected:
        raise SystemExit("public export manifest path set drift")
    for row in rows:
        payload = (ROOT / row["path"]).read_bytes()
        if row.get("size") != len(payload) or row.get("sha256") != hashlib.sha256(payload).hexdigest():
            raise SystemExit(f"public export manifest hash drift: {row['path']}")


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
