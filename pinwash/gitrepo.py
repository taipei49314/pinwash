"""Read git trees. Failures are engine errors (exit 2), never blocks."""

from __future__ import annotations

import errno
import subprocess
from pathlib import Path

# A worktree read that fails with one of these finds no file, exactly as
# pathlib's is_file() decides (a path that vanished, a broken symlink).
_ABSENT_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP})
# What a worktree file the engine cannot read is recorded as: bytes that are
# not UTF-8. Every surface parse starts from UTF-8 text (SPEC §3, §3.2), so
# such a file is unparseable, a finding (§8), and a path that is no surface
# is ignored as before. The worktree is subject data (§1.1), not git.
UNREADABLE = b"\xff"


class GitError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _run(repo: Path, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        check=False,
    )


def require_repo(repo: Path) -> None:
    proc = _run(repo, ["rev-parse", "--is-inside-work-tree"])
    if proc.returncode != 0 or proc.stdout.strip() != b"true":
        raise GitError("unreadable git repository")


def resolve_range(repo: Path, range_arg: str | None) -> tuple[str, str, str, str]:
    """Return (base_spec, head_spec, base_label, head_label).

    head_spec is a git tree-ish, or the token WORKTREE.
    """
    require_repo(repo)
    if not range_arg:
        proc = _run(repo, ["rev-parse", "--verify", "HEAD"])
        if proc.returncode != 0:
            raise GitError("unreadable git repository")
        head = proc.stdout.decode("ascii", "replace").strip()
        return head, "WORKTREE", "HEAD", "WORKTREE"
    raw = range_arg.strip()
    if "..." in raw:
        left, right = raw.split("...", 1)
        if not left or not right:
            raise GitError("invalid range")
        mb = _run(repo, ["merge-base", left, right])
        if mb.returncode != 0:
            raise GitError("unreadable git repository")
        base = mb.stdout.decode("ascii", "replace").strip()
        return base, right, left, right
    if ".." in raw:
        left, right = raw.split("..", 1)
        if not left or not right:
            raise GitError("invalid range")
        return left, right, left, right
    raise GitError("invalid range")


def ls_tree(repo: Path, spec: str) -> dict[str, bytes]:
    if spec == "WORKTREE":
        return _ls_worktree(repo)
    proc = _run(repo, ["ls-tree", "-r", "-z", spec])
    if proc.returncode != 0:
        raise GitError("unreadable git repository")
    entries: list[tuple[str, bytes]] = []
    for entry in proc.stdout.split(b"\0"):
        if not entry:
            continue
        metadata, separator, name = entry.partition(b"\t")
        parts = metadata.split()
        if not separator or len(parts) != 3:
            raise GitError("unreadable git repository")
        if parts[1] != b"blob":
            # A gitlink (submodule, type commit) names a commit of another
            # repository, absent from this object store. It is a directory
            # in a checkout, never file bytes, so no surface can be one.
            continue
        # -z preserves literal names, including Git-quoted Unicode and
        # whitespace. Batch requests use object IDs so a filename cannot
        # become part of cat-file's newline-delimited request protocol.
        entries.append((name.decode("utf-8", "surrogateescape"), parts[2]))
    return _cat_file_batch(repo, entries)


def _cat_file_batch(
    repo: Path, entries: list[tuple[str, bytes]]
) -> dict[str, bytes]:
    """One cat-file --batch round trip instead of one `git show` per blob."""
    if not entries:
        return {}
    request = b"".join(oid + b"\n" for _path, oid in entries)
    proc = _run_input(repo, ["cat-file", "--batch"], request)
    if proc.returncode != 0:
        raise GitError("unreadable git repository")
    out = proc.stdout
    out_len = len(out)
    result: dict[str, bytes] = {}
    pos = 0
    for p, _oid in entries:
        nl = out.find(b"\n", pos)
        if nl < 0:
            raise GitError("unreadable git repository")
        header = out[pos:nl]
        pos = nl + 1
        parts = header.split()
        if len(parts) != 3 or not parts[2].isdigit():
            raise GitError("unreadable git repository")
        size = int(parts[2])
        if pos + size + 1 > out_len:
            raise GitError("unreadable git repository")
        result[p] = out[pos:pos + size]
        pos += size + 1
    return result


def _run_input(
    repo: Path, args: list[str], input_bytes: bytes
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        input=input_bytes,
        capture_output=True,
        check=False,
    )


def _ls_worktree(repo: Path) -> dict[str, bytes]:
    proc = _run(repo, ["ls-files", "-z", "-co", "--exclude-standard"])
    if proc.returncode != 0:
        raise GitError("unreadable git repository")
    out: dict[str, bytes] = {}
    for name in proc.stdout.split(b"\0"):
        if not name:
            continue
        path = name.decode("utf-8", "surrogateescape")
        full = repo.joinpath(*path.split("/"))
        try:
            if not full.is_file():
                continue
            data = full.read_bytes()
        except OSError as exc:
            if exc.errno in _ABSENT_ERRNOS:
                continue
            data = UNREADABLE
        out[path] = data
    return out
