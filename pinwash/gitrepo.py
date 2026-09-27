"""Read git trees. Failures are engine errors (exit 2), never blocks."""

from __future__ import annotations

import subprocess
from pathlib import Path


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
    proc = _run(repo, ["ls-tree", "-r", "--name-only", spec])
    if proc.returncode != 0:
        raise GitError("unreadable git repository")
    names = proc.stdout.decode("utf-8", "replace").replace("\r\n", "\n").split("\n")
    out: dict[str, bytes] = {}
    for name in names:
        path = name.replace("\\", "/").strip()
        if not path:
            continue
        show = _run(repo, ["show", f"{spec}:{path}"])
        if show.returncode != 0:
            raise GitError("unreadable git repository")
        out[path] = show.stdout
    return out


def _ls_worktree(repo: Path) -> dict[str, bytes]:
    proc = _run(repo, ["ls-files", "-co", "--exclude-standard"])
    if proc.returncode != 0:
        raise GitError("unreadable git repository")
    names = proc.stdout.decode("utf-8", "replace").replace("\r\n", "\n").split("\n")
    out: dict[str, bytes] = {}
    for name in names:
        path = name.replace("\\", "/").strip()
        if not path:
            continue
        full = repo.joinpath(*path.split("/"))
        if full.is_file():
            out[path] = full.read_bytes()
    return out
