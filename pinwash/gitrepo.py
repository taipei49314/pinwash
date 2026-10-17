"""Read git trees. Failures are engine errors (exit 2), never blocks.

SPEC §1.1 makes the head tree, and in worktree mode the whole working tree,
subject data. That includes the repository's own .git: its config, refs,
hooks, info/ files and object store are writable by the agent under
judgement. SPEC §1.3 says pinwash never executes subject code, so every git
call runs as _GIT with _env(), which switch off each repository-controlled
program and object substitution pinwash's plumbing can reach, and every
object read from the store is rehashed against its id before its bytes count
(_Store). A mismatch is an unreadable git tree (§8, exit 2), never a pass.
ARCHITECTURE §2 lists the vectors, what neutralises each, and what is left.
"""

from __future__ import annotations

import errno
import hashlib
import heapq
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import Callable

# A worktree read that fails with one of these finds no file, exactly as
# pathlib's is_file() decides (a path that vanished, a broken symlink).
_ABSENT_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP})
# What a worktree file the engine cannot read is recorded as: bytes that are
# not UTF-8. Every surface parse starts from UTF-8 text (SPEC §3, §3.2), so
# such a file is unparseable, a finding (§8), and a path that is no surface
# is ignored as before. The worktree is subject data (§1.1), not git.
UNREADABLE = b"\xff"
# SPEC §2 (spec 16, AI-assisted ruling on #17): the reserved range token for
# the working tree, valid only on the right of `..`. The working tree is
# head-side data (§1.1) and never a base, whose allowlist and contexts govern
# the run (§1.2). Any ref git resolves by the name WORKTREE is spelled in
# full (refs/heads/WORKTREE, refs/tags/WORKTREE).
WORKTREE = "WORKTREE"
# SPEC §2 / R21 (spec 16): the §3 surface paths as literal pathspecs, each
# exact path and the fixed directory every surface glob sits under. git
# prunes each directory no pathspec reaches, so an ignored node_modules is
# walked only inside a fixed surface directory. Only `**/SKILL.md` under no
# fixed surface directory has no fixed prefix, and it is not listed (a glob
# pathspec walks every ignored tree).
SURFACE_PREFIXES = (
    ".agents/skills/",
    ".checkwash/config.toml",
    ".claude/hooks/",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".clinerules",
    ".cursor/hooks.json",
    ".cursor/mcp.json",
    ".cursor/rules/",
    ".cursor/skills/",
    ".cursorrules",
    ".gemini/settings.json",
    ".github/copilot-instructions.md",
    ".github/required-ruleset.json",
    ".github/rulesets/",
    ".github/workflows/",
    ".greenwash/config.toml",
    ".mcp.json",
    ".pinwash/allow.toml",
    ".pinwash/pins.json",
    ".windsurfrules",
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "QWEN.md",
    "SKILL.md",
    "opencode.json",
)


def _surface_dirs() -> frozenset[str]:
    """Every directory a fixed surface path sits in or under."""
    dirs: set[str] = set()
    for path in SURFACE_PREFIXES:
        parts = path.rstrip("/").split("/")
        upto = len(parts) if path.endswith("/") else len(parts) - 1
        for i in range(1, upto + 1):
            dirs.add("/".join(parts[:i]))
    return frozenset(dirs)


_SURFACE_DIRS = _surface_dirs()
_SURFACE_DIR_PREFIXES = tuple(p for p in SURFACE_PREFIXES if p.endswith("/"))


def _at_surface_dir(bare: str) -> bool:
    """SPEC §2 (spec 16): a fixed surface directory, or a path below one."""
    return bare in _SURFACE_DIRS or bare.startswith(_SURFACE_DIR_PREFIXES)


def _symlink(full: Path) -> bool:
    """lstat says symlink. An lstat that fails says nothing: below a
    directory the judge cannot open, git lists nothing either (R21)."""
    try:
        return full.is_symlink()
    except OSError:
        return False


def _undescended(repo: Path, path: str) -> bool:
    """A listed entry git does not descend: a nested repository (listed as
    `dir/`), a symlink at a fixed surface directory, or a symlink to a
    directory below one (a symlink to a file is read through it)."""
    if path.endswith("/"):
        return True
    full = repo.joinpath(*path.split("/"))
    if not _symlink(full):
        return False
    if path in _SURFACE_DIRS:
        return True
    try:
        return full.is_dir()
    except OSError:
        return True

# A path no file can occupy (below the null device). As the graft, shallow
# and hooks locations it makes git read none of .git/info/grafts,
# .git/shallow or a hooks directory, without a warning.
_NO_FILE = os.path.join(os.devnull, "pinwash-none")

_GIT = (
    "git",
    # refs/replace/* never substitutes a commit, tree or blob.
    "--no-replace-objects",
    # ls-files never runs the program core.fsmonitor names (worktree mode).
    "-c", "core.fsmonitor=false",
    # Parents come from commit objects, never from a commit-graph file.
    "-c", "core.commitGraph=false",
    # Defence in depth, no change on git 2.43: its ls-files never reads the
    # index's untracked cache, and none of these commands runs a hook.
    "-c", "core.untrackedCache=false",
    "-c", f"core.hooksPath={_NO_FILE}",
    # ls-files matches untracked names to the index byte for byte, as every
    # surface predicate does: with core.ignoreCase=true a case-variant decoy
    # in the index (.cursor/MCP.json) hid a new .cursor/mcp.json from the
    # worktree read on a case-sensitive filesystem (SPEC §2, spec 16).
    "-c", "core.ignoreCase=false",
)


def _env() -> dict[str, str]:
    env = dict(os.environ)
    # A missing object is missing: no lazy fetch from a promisor remote,
    # where git knows this variable (the 2024-05 security releases on; this
    # host's 2.43.0 build has it).
    env["GIT_NO_LAZY_FETCH"] = "1"
    # No transport at all, on any git version: a lazy fetch, or anything
    # else, cannot run ext::, a local upload-pack, ssh or a remote helper.
    env["GIT_ALLOW_PROTOCOL"] = ""
    # .git/info/grafts and .git/shallow rewrite parents; read neither.
    env["GIT_GRAFT_FILE"] = _NO_FILE
    env["GIT_SHALLOW_FILE"] = _NO_FILE
    return env


class GitError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class _Missing(GitError):
    """An object the store does not have: a partial clone without lazy
    fetch, a shallow clone's cut, or a deleted object."""

    def __init__(self, oid: str) -> None:
        super().__init__(
            f"git object {oid} is not in the object store"
            " (a partial or shallow clone? fetch it before judging)"
        )
        self.oid = oid


# Commits read one at a time before the walk prefetches ahead (_Store.miss),
# and how many the first prefetch asks for.
_READAHEAD_AFTER = 64
_READAHEAD_FIRST = 1024

_UNREADABLE_GIT = "unreadable git repository"
_MISMATCH = "git object does not match its id"
_MOVED = (
    "git work tree is not the directory that holds .git"
    " (a judge that means another work tree sets GIT_WORK_TREE)"
)


def _run(repo: Path, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [*_GIT, *args],
        cwd=repo,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        env=_env(),
    )


class _Format:
    """The repository's object format: hash function and id length."""

    def __init__(self, name: bytes) -> None:
        if name == b"sha1":
            self.rawsz = 20
        elif name == b"sha256":
            self.rawsz = 32
        else:
            raise GitError(_UNREADABLE_GIT)
        self.name = name.decode("ascii")
        self.hexsz = 2 * self.rawsz
        self._hash = getattr(hashlib, self.name)
        # get_oid_hex() reads exactly hexsz hex digits, either case.
        self._hexid = re.compile(rb"[0-9a-fA-F]{%d}" % self.hexsz)

    def oid(self, raw: bytes) -> str:
        """A hex object id as git prints it, or GitError."""
        text = raw.decode("ascii", "replace")
        if len(text) != self.hexsz or text.strip("0123456789abcdef"):
            raise GitError(_UNREADABLE_GIT)
        return text

    def parse_hex(self, raw: bytes) -> str:
        """An object id field of a commit or tag, as git's get_oid_hex()
        reads it (either case), in the lower case git prints."""
        if self._hexid.fullmatch(raw) is None:
            raise GitError(_UNREADABLE_GIT)
        return raw.decode("ascii").lower()

    def matches(self, oid: str, kind: bytes, data: bytes) -> bool:
        """The object's bytes rehash to its id."""
        h = self._hash(usedforsecurity=False)
        h.update(kind + b" %d\0" % len(data))
        h.update(data)
        return h.hexdigest() == oid


def _layout(repo: Path) -> tuple[_Format, bytes]:
    """Object format and the cwd prefix, after the work tree checks.

    The prefix scopes every listing as `git ls-tree` and `git ls-files` do
    from a subdirectory. Git takes the work tree from core.worktree, which
    the repository's config sets, so a `core.worktree = ../..` would move
    the work tree above the checkout and scope both trees to a subtree that
    does not exist: every range would read empty and pass (_check_work_tree).

    --show-cdup prints only "../" segments and the object format names no
    path, so the one path git prints (the prefix) comes last and keeps any
    newline in a directory name.
    """
    proc = _run(
        repo,
        [
            "rev-parse",
            "--is-inside-work-tree",
            "--show-object-format",
            "--show-cdup",
            "--show-prefix",
        ],
    )
    parts = proc.stdout.split(b"\n", 3)
    if proc.returncode != 0 or len(parts) != 4 or parts[0] != b"true":
        raise GitError(_UNREADABLE_GIT)
    if not parts[3].endswith(b"\n") or parts[2].replace(b"../", b""):
        raise GitError(_UNREADABLE_GIT)
    fmt = _Format(parts[1])
    if not os.environ.get("GIT_WORK_TREE"):
        _check_work_tree(repo, parts[2])
    return fmt, parts[3][:-1]


def _check_work_tree(repo: Path, cdup: bytes) -> None:
    """The work tree git uses is one the judge chose, not core.worktree.

    Without GIT_DIR, git finds the .git nearest above the cwd, and the work
    tree must be the directory that holds it. With GIT_DIR (a hook, yadm,
    vcsh), git's own default is the cwd as the top, which is accepted too.
    A judge that means any other work tree names it in GIT_WORK_TREE.
    """
    cwd = os.path.realpath(repo)
    top = os.path.normcase(os.path.realpath(os.path.join(cwd, os.fsdecode(cdup))))
    allowed = []
    here = cwd
    while True:
        if os.path.lexists(os.path.join(here, ".git")):
            allowed.append(os.path.normcase(here))
            break
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    if os.environ.get("GIT_DIR"):
        allowed.append(os.path.normcase(cwd))
    if top not in allowed:
        raise GitError(_MOVED)


def require_repo(repo: Path) -> None:
    _layout(repo)


def _rev(repo: Path, fmt: _Format, spec: str) -> str:
    proc = _run(repo, ["rev-parse", "--verify", "--end-of-options", spec])
    if proc.returncode != 0 or not proc.stdout.endswith(b"\n"):
        raise GitError(_UNREADABLE_GIT)
    return fmt.oid(proc.stdout[:-1])


class _Store:
    """Objects read from a single long-lived `git cat-file --batch`.

    Every object is rehashed against the id it was asked for: a forged loose
    object, a pack or index that maps an id to other bytes, or an alternate
    store cannot change what pinwash reads, only make it exit 2. Requests
    are object ids, never names, and many ids go out in one write (from a
    thread, so neither pipe can fill up and block both processes).
    """

    def __init__(self, repo: Path, fmt: _Format) -> None:
        self.fmt = fmt
        self._repo = repo
        self._proc: subprocess.Popen[bytes] | None = None
        self._open()
        self._commits: dict[str, tuple[list[str], int]] = {}
        self._trees: dict[str, list[tuple[bytes, bytes, str]]] = {}
        self._misses = 0
        self._readahead = _READAHEAD_FIRST

    def __enter__(self) -> _Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _open(self) -> None:
        self._proc = subprocess.Popen(
            [*_GIT, "cat-file", "--batch"],
            cwd=self._repo,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_env(),
        )

    def close(self, kill: bool = False) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        if kill:
            proc.kill()
        for stream in (proc.stdin, proc.stdout):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # -- raw reads -------------------------------------------------------

    def _fetch(self, oids: list[str]) -> list[tuple[bytes, bytes] | None]:
        """(kind, bytes) per id as the store has it, None where missing.
        Not yet rehashed: get() checks each one."""
        proc = self._proc
        if proc is None or proc.stdin is None or proc.stdout is None:
            raise GitError(_UNREADABLE_GIT)
        if not oids:
            return []
        stdin, stdout = proc.stdin, proc.stdout
        request = b"".join(oid.encode("ascii") + b"\n" for oid in oids)

        def send() -> None:
            try:
                stdin.write(request)
                stdin.flush()
            except (OSError, ValueError):
                pass  # git is gone; the reads below fail

        writer = None
        if len(oids) == 1:
            send()
        else:
            writer = threading.Thread(target=send, daemon=True)
            writer.start()
        try:
            found: list[tuple[bytes, bytes] | None] = []
            for oid in oids:
                key = oid.encode("ascii")
                header = stdout.readline()
                if header == key + b" missing\n":
                    found.append(None)
                    continue
                if not header and self._absent(oid):
                    # In a partial clone cat-file dies on an object that
                    # only the promisor remote has, where it would fetch:
                    # start another for the reads that follow.
                    self.close(kill=True)
                    self._open()
                    raise _Missing(oid)
                parts = header.split()
                if len(parts) != 3 or parts[0] != key or not parts[2].isdigit():
                    raise GitError(_UNREADABLE_GIT)
                size = int(parts[2])
                data = stdout.read(size)
                if len(data) != size or stdout.read(1) != b"\n":
                    raise GitError(_UNREADABLE_GIT)
                found.append((parts[1], data))
        except _Missing:
            raise
        except BaseException:
            self.close(kill=True)
            raise
        finally:
            if writer is not None:
                writer.join()
        return found

    def _absent(self, oid: str) -> bool:
        """After cat-file died: the store has no such object."""
        return _run(self._repo, ["cat-file", "-e", oid]).returncode != 0

    def get(self, oids: list[str]) -> list[tuple[bytes, bytes]]:
        """(kind, bytes) per id, each rehashed; missing or forged is
        GitError (SPEC §8)."""
        out: list[tuple[bytes, bytes]] = []
        for oid, got in zip(oids, self._fetch(oids)):
            if got is None:
                raise _Missing(oid)
            if not self.fmt.matches(oid, got[0], got[1]):
                raise GitError(_MISMATCH)
            out.append(got)
        return out

    def read(self, oid: str) -> tuple[bytes, bytes]:
        return self.get([oid])[0]

    def blobs(self, oids: list[str]) -> list[bytes]:
        out: list[bytes] = []
        for kind, data in self.get(oids):
            if kind != b"blob":
                raise GitError(_UNREADABLE_GIT)
            out.append(data)
        return out

    # -- commits and tags ----------------------------------------------

    def peel(self, oid: str, want: bytes) -> str:
        """Follow tags (and a commit to its tree when want is b"tree")."""
        while True:
            kind, data = self.read(oid)
            if kind == want:
                return oid
            if kind == b"tag":
                oid = self._header_oid(data, b"object ")
            elif kind == b"commit" and want == b"tree":
                # The tree named by the verified commit body itself, never
                # a commit-graph entry or a rev-parse ^{tree} shortcut.
                oid = self._header_oid(data, b"tree ")
            else:
                raise GitError(_UNREADABLE_GIT)

    def _header_oid(self, data: bytes, key: bytes) -> str:
        end = len(key) + self.fmt.hexsz
        if data[: len(key)] != key or data[end : end + 1] != b"\n":
            raise GitError(_UNREADABLE_GIT)
        return self.fmt.parse_hex(data[len(key) : end])

    def _parse_commit(self, data: bytes) -> tuple[list[str], int]:
        """Parents and committer date as git's parse_commit_buffer() reads
        them (grafts, shallow, replace refs and commit-graph are off, so git
        reads the same)."""
        hexsz = self.fmt.hexsz
        if len(data) <= hexsz + 6 or data[:5] != b"tree " or data[hexsz + 5] != 0x0A:
            raise GitError(_UNREADABLE_GIT)
        self.fmt.parse_hex(data[5 : hexsz + 5])
        pos = hexsz + 6
        entry = hexsz + 7
        end = len(data)
        parents: list[str] = []
        while pos + entry < end and data.startswith(b"parent ", pos):
            if pos + entry + 1 >= end or data[pos + entry] != 0x0A:
                raise GitError(_UNREADABLE_GIT)
            parents.append(self.fmt.parse_hex(data[pos + 7 : pos + entry]))
            pos += entry + 1
        return parents, _commit_date(data, pos)

    def commit(self, oid: str) -> tuple[list[str], int]:
        """Parents and committer date from the verified commit object."""
        cached = self._commits.get(oid)
        if cached is not None:
            return cached
        kind, data = self.read(oid)
        if kind != b"commit":
            raise GitError(_UNREADABLE_GIT)
        result = self._commits[oid] = self._parse_commit(data)
        return result

    def has_commit(self, oid: str) -> bool:
        """False only when the store has no such object (cat-file says
        missing); a forged or malformed one is GitError when it is read."""
        if oid in self._commits:
            return True
        try:
            self.commit(oid)
        except _Missing:
            return False
        return True

    def miss(self, frontier: Callable[[], list[str]]) -> None:
        """Count a commit the walk reads on demand. After _READAHEAD_AFTER
        of them, prefetch the next commits a date-ordered walk from the
        frontier reaches, twice as many each time."""
        self._misses += 1
        if self._misses < _READAHEAD_AFTER:
            return
        self._misses = 0
        count, self._readahead = self._readahead, min(2 * self._readahead, 1 << 16)
        self._prefetch(count, frontier())

    def _prefetch(self, count: int, frontier: list[str]) -> None:
        """Batch-read the first count commits `git rev-list` walks from the
        frontier, newest committer date first, as the merge-base walk does.

        rev-list's output goes straight into one `cat-file --batch
        --buffer`. It is a hint only: git reads unverified objects for it,
        so _cache_commits() keeps only commits that rehash, and a failure (a
        shallow clone's cut) leaves the walk to read on demand.
        """
        env = _env()
        revs = subprocess.Popen(
            [*_GIT, "rev-list", f"--max-count={count}", "--stdin"],
            cwd=self._repo,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        try:
            cat = subprocess.Popen(
                [*_GIT, "cat-file", "--batch", "--buffer"],
                cwd=self._repo,
                stdin=revs.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=env,
            )
        except OSError:
            revs.kill()
            revs.wait()
            raise
        finally:
            if revs.stdout is not None:
                revs.stdout.close()
        if revs.stdin is not None:
            # rev-list --stdin reads every line before it writes any.
            try:
                revs.stdin.write(b"".join(oid.encode("ascii") + b"\n" for oid in frontier))
                revs.stdin.close()
            except OSError:
                pass
        out, _err = cat.communicate()
        revs.wait()
        self._cache_commits(out)

    def cached(self, oid: str) -> bool:
        return oid in self._commits

    def _cache_commits(self, out: bytes) -> None:
        """Keep the commits of a `cat-file --batch` answer.

        Only a cache: an object that is missing, forged, malformed or no
        commit is left out, and commit() reads it again if the walk needs
        it, so the answer cannot change what the walk sees.
        """
        pos, end = 0, len(out)
        while pos < end:
            nl = out.find(b"\n", pos)
            if nl < 0:
                return
            parts = out[pos:nl].split()
            pos = nl + 1
            if len(parts) == 2 and parts[1] == b"missing":
                continue
            if len(parts) != 3 or not parts[2].isdigit():
                return
            size = int(parts[2])
            data = out[pos : pos + size]
            pos += size + 1
            if len(data) != size or parts[1] != b"commit":
                continue
            oid = parts[0].decode("ascii", "replace")
            if oid in self._commits or not self.fmt.matches(oid, b"commit", data):
                continue
            try:
                self._commits[oid] = self._parse_commit(data)
            except GitError:
                continue

    # -- trees -----------------------------------------------------------

    def load_trees(self, oids: list[str]) -> None:
        """Read every tree not yet read, in one batch."""
        todo = [oid for oid in dict.fromkeys(oids) if oid not in self._trees]
        for oid, (kind, data) in zip(todo, self.get(todo)):
            if kind != b"tree":
                raise GitError(_UNREADABLE_GIT)
            self._trees[oid] = self._parse_tree(data)

    def tree(self, oid: str) -> list[tuple[bytes, bytes, str]]:
        """(kind, name, id) per entry, in stored order, as `git ls-tree`
        reads them: a canonical directory mode is a tree, a regular file or
        symlink mode a blob, every other mode a gitlink (commit)."""
        if oid not in self._trees:
            self.load_trees([oid])
        return self._trees[oid]

    def _parse_tree(self, data: bytes) -> list[tuple[bytes, bytes, str]]:
        rawsz = self.fmt.rawsz
        entries: list[tuple[bytes, bytes, str]] = []
        pos, end = 0, len(data)
        while pos < end:
            sp = data.find(b" ", pos)
            nul = data.find(b"\0", sp + 1) if sp > pos else -1
            if nul < 0 or nul + 1 + rawsz > end:
                raise GitError(_UNREADABLE_GIT)
            mode = 0
            for digit in data[pos:sp]:
                if not 0x30 <= digit <= 0x37:
                    raise GitError(_UNREADABLE_GIT)
                mode = ((mode << 3) + digit - 0x30) & 0xFFFFFFFF
            name = data[sp + 1 : nul]
            if not name:
                raise GitError(_UNREADABLE_GIT)
            child = data[nul + 1 : nul + 1 + rawsz].hex()
            pos = nul + 1 + rawsz
            fmt_bits = mode & 0o170000
            if fmt_bits in (0o100000, 0o120000):
                entries.append((b"blob", name, child))
            elif fmt_bits == 0o040000:
                entries.append((b"tree", name, child))
            else:
                entries.append((b"commit", name, child))
        # git fsck rejects a tree that lists one name twice (duplicateEntries)
        # or out of git's order, where a directory sorts as its name plus
        # "/" (treeNotSorted). git itself then reads such a tree in ways
        # that disagree (ls-tree -r lists both entries, diff-tree and show
        # take the first), so no single content is the tree's: it is a
        # malformed object, exit 2 like a hash mismatch, never a pass.
        seen: set[bytes] = set()
        prev_key = b""
        for kind, name, _child in entries:
            key = name + b"/" if kind == b"tree" else name
            if name in seen or (prev_key and key <= prev_key):
                raise GitError(_UNREADABLE_GIT)
            seen.add(name)
            prev_key = key
        return entries


_SPACE = b" \t\n\r"  # git's isspace() (ctype.c), not C's: no \v or \f


def _commit_date(buf: bytes, start: int) -> int:
    """git's parse_commit_date() on buf[start:]: the committer timestamp,
    0 if malformed, read as strtoumax() reads it."""
    end = len(buf)
    if start + 6 >= end or not buf.startswith(b"author", start):
        return 0
    nl = buf.find(b"\n", start)
    if nl < 0:
        return 0
    line = nl + 1
    if line + 9 >= end or not buf.startswith(b"committer", line):
        return 0
    eol = buf.find(b"\n", line)
    if eol < 0:
        return 0
    pos = buf.rfind(b">", line, eol) + 1
    if pos == 0:
        return 0
    while pos < eol and buf[pos] in _SPACE:
        pos += 1
    negative = buf[pos] == 0x2D  # "-"
    first = pos + negative
    digits = first
    while 0x30 <= buf[digits] <= 0x39:  # stops at eol at the latest
        digits += 1
    if digits == first:
        return 0
    value = int(buf[first:digits])
    top = (1 << 64) - 1
    if value > top:
        return top
    return (-value) & top if negative else value


# paint_down_to_common() flags (commit-reach.c).
_P1, _P2, _STALE, _RESULT = 1, 2, 4, 8


def _insert_by_date(store: _Store, items: list[str], oid: str) -> None:
    date = store.commit(oid)[1]
    for i, other in enumerate(items):
        if store.commit(other)[1] < date:
            items.insert(i, oid)
            return
    items.append(oid)


def _paint(
    store: _Store, one: str, twos: list[str], flags: dict[str, int]
) -> list[str]:
    """git's paint_down_to_common() without generation numbers, over
    verified commit objects: same queue order (newest committer date first,
    first in first out on ties), same flags, same results.

    One departure: a parent the store does not have (a shallow clone's cut)
    is skipped when the walk would only mark it STALE. Such a commit and its
    ancestors are ancestors of a common ancestor, so none is a merge base;
    the skip can only leave some of them unmarked. One of those that both
    sides then reach is an extra candidate below a true merge base, which
    remove_redundant discards, or reaches only through the missing commit,
    which is GitError. Any other missing commit is GitError. The answer is
    git's on the full history, or exit 2, never another base.
    """
    queue: list[tuple[int, int, str]] = []
    queued: dict[str, int] = {}  # queue entries per commit
    live = 0  # queue entries whose commit is not STALE
    counter = 0

    def put(oid: str, mark: int) -> None:
        nonlocal counter, live
        old = flags.get(oid, 0)
        new = flags[oid] = old | mark
        if new & _STALE and not old & _STALE:
            live -= queued.get(oid, 0)
        if not new & _STALE:
            live += 1
        queued[oid] = queued.get(oid, 0) + 1
        heapq.heappush(queue, (-store.commit(oid)[1], counter, oid))
        counter += 1

    flags[one] = flags.get(one, 0) | _P1
    if not twos:
        return [one]
    put(one, _P1)
    for two in twos:
        put(two, _P2)
    result: list[str] = []
    while live:  # git's queue_has_nonstale()
        _date, _ctr, oid = heapq.heappop(queue)
        queued[oid] -= 1
        if not flags[oid] & _STALE:
            live -= 1
        mark = flags[oid] & (_P1 | _P2 | _STALE)
        if mark == _P1 | _P2:
            if not flags[oid] & _RESULT:
                flags[oid] |= _RESULT
                _insert_by_date(store, result, oid)
            mark |= _STALE
        for parent in store.commit(oid)[0]:
            if flags.get(parent, 0) & mark == mark:
                continue
            if not store.cached(parent):
                store.miss(lambda first=parent: [first, *(entry[2] for entry in queue)])
            if mark & _STALE and not store.has_commit(parent):
                continue
            put(parent, mark)
    return result


def _merge_bases(store: _Store, one: str, two: str) -> list[str]:
    """git's get_merge_bases_many_0() for one pair, without commit-graph."""
    if one == two:
        return [one]
    flags: dict[str, int] = {}
    painted = _paint(store, one, [two], flags)
    found: list[str] = []
    for oid in painted:
        if not flags[oid] & _STALE:
            _insert_by_date(store, found, oid)
    if len(found) < 2:
        return found
    redundant = [False] * len(found)
    for i, cand in enumerate(found):
        if redundant[i]:
            continue
        index = [j for j in range(len(found)) if j != i and not redundant[j]]
        flags = {}
        _paint(store, cand, [found[j] for j in index], flags)
        if flags[cand] & _P2:
            redundant[i] = True
        for j in index:
            if flags[found[j]] & _P1:
                redundant[j] = True
    best: list[str] = []
    for i, oid in enumerate(found):
        if not redundant[i]:
            _insert_by_date(store, best, oid)
    return best


def repository_root(repo: Path) -> Path:
    """Validated worktree root for consumers that always review the whole repo."""
    _fmt, prefix = _layout(repo)
    return repo.resolve().joinpath(*([".."] * prefix.count(b"/"))).resolve()


def resolve_commit(repo: Path, ref: str = "HEAD") -> str:
    """Freeze a ref to a rehashed commit, without replacements or lazy fetch."""
    fmt, _prefix = _layout(repo)
    oid = _rev(repo, fmt, ref)
    with _Store(repo, fmt) as store:
        return store.peel(oid, b"commit")


def resolve_range(repo: Path, range_arg: str | None) -> tuple[str, str, str, str]:
    """Return (base_spec, head_spec, base_label, head_label).

    head_spec is a git tree-ish, or the token WORKTREE.
    """
    fmt, _prefix = _layout(repo)
    if not range_arg:
        head = _rev(repo, fmt, "HEAD")
        return head, WORKTREE, "HEAD", WORKTREE
    raw = range_arg.strip()
    if "..." in raw:
        left, right = raw.split("...", 1)
        if not left or not right or WORKTREE in (left, right):
            # SPEC §2 (spec 16): WORKTREE has no merge base.
            raise GitError("invalid range")
        left_oid = _rev(repo, fmt, left)
        right_oid = _rev(repo, fmt, right)
        # SPEC §2: the base is merge-base(BASE, HEAD), computed from
        # rehashed commit objects with git's algorithm. `git merge-base` is
        # not asked: it reads unverified objects, and the walk is the answer.
        with _Store(repo, fmt) as store:
            one = store.peel(left_oid, b"commit")
            two = store.peel(right_oid, b"commit")
            verified = _merge_bases(store, one, two)
        if not verified:
            raise GitError("the range's two commits have no merge base")
        return verified[0], right_oid, left, right
    if ".." in raw:
        left, right = raw.split("..", 1)
        if not left or not right or left == WORKTREE:
            # SPEC §2 (spec 16): the working tree is never a base.
            raise GitError("invalid range")
        return left, right, left, right
    raise GitError("invalid range")


def ls_tree(repo: Path, spec: str) -> dict[str, bytes]:
    fmt, prefix = _layout(repo)
    if spec == WORKTREE:
        return ls_worktree(repo)[0]
    oid = _rev(repo, fmt, spec)
    with _Store(repo, fmt) as store:
        roots = [store.peel(oid, b"tree")]
        # From a subdirectory `git ls-tree -r` lists that subtree with
        # paths relative to it; the listing keeps that scope.
        for part in prefix.split(b"/")[:-1]:
            roots = [
                child
                for root in roots
                for kind, name, child in store.tree(root)
                if kind == b"tree" and name == part
            ]
        entries = _blobs(store, roots)
        oids = list(dict.fromkeys(blob for _path, blob in entries))
        data = dict(zip(oids, store.blobs(oids)))
    return {path: data[blob] for path, blob in entries}


def _blobs(store: _Store, roots: list[str]) -> list[tuple[str, str]]:
    """Blob entries in `git ls-tree -r` order, from verified tree objects.

    The trees are read one depth at a time, each depth in one batch.
    """
    level = list(dict.fromkeys(roots))
    seen = set(level)
    while level:
        store.load_trees(level)
        children: list[str] = []
        for oid in level:
            for kind, _name, child in store.tree(oid):
                if kind == b"tree" and child not in seen:
                    seen.add(child)
                    children.append(child)
        level = children
    found: list[tuple[str, str]] = []
    for root in roots:
        stack = [(b"", iter(store.tree(root)))]
        while stack:
            base, it = stack[-1]
            entry = next(it, None)
            if entry is None:
                stack.pop()
                continue
            kind, name, child = entry
            if kind == b"tree":
                stack.append((base + name + b"/", iter(store.tree(child))))
            elif kind == b"blob":
                # Names keep their literal bytes, Git-quoted Unicode and
                # whitespace included. A gitlink (submodule, kind commit)
                # names a commit of another repository, absent from this
                # object store. It is a directory in a checkout, never
                # file bytes, so no surface can be one; a gitlink at a
                # fixed surface directory hides that directory's surfaces
                # (SPEC §11 R23).
                found.append(((base + name).decode("utf-8", "surrogateescape"), child))
    return found


def _index_paths(repo: Path) -> frozenset[str]:
    proc = _run(repo, ["ls-files", "-z", "-c"])
    if proc.returncode != 0:
        raise GitError(_UNREADABLE_GIT)
    return frozenset(
        name.decode("utf-8", "surrogateescape") for name in proc.stdout.split(b"\0") if name
    )


# SPEC §3.2 (spec 19 review): the paths config_rule.CONFIG_ORDER names.
_CHECKWASH_CONFIGS = frozenset({".checkwash/config.toml", ".greenwash/config.toml"})


def worktree_link_targets(repo: Path) -> dict[str, bytes]:
    """Link nodes for consumer readiness/custody; do not follow their targets.

    This does not extend the scanner's supported surfaces or change ls_worktree.
    """
    proc = _run(repo, ["ls-files", "-z", "-co", "--exclude-standard"])
    if proc.returncode != 0:
        raise GitError(_UNREADABLE_GIT)
    links = {}
    for name in proc.stdout.split(b"\0"):
        if not name:
            continue
        path = name.decode("utf-8", "surrogateescape").rstrip("/")
        full = repo.joinpath(*path.split("/"))
        if full.is_symlink():
            links[path] = os.fsencode(os.readlink(full))
    return links


def ls_worktree(repo: Path) -> tuple[dict[str, bytes], list[str]]:
    """The working tree's tracked and not-ignored untracked files, and (SPEC
    §2, R21, spec 16) each untracked entry at or below a fixed surface
    directory that git does not descend: a nested repository or a symlinked
    directory, ignored or not. Those are names only, never read. A tracked
    gitlink or symlink is not listed (R23)."""
    tracked = _index_paths(repo)
    proc = _run(repo, ["ls-files", "-z", "-co", "--exclude-standard"])
    if proc.returncode != 0:
        raise GitError(_UNREADABLE_GIT)
    out: dict[str, bytes] = {}
    unread: set[str] = set()
    for name in proc.stdout.split(b"\0"):
        if not name:
            continue
        path = name.decode("utf-8", "surrogateescape")
        bare = path.rstrip("/")
        if bare not in tracked and _at_surface_dir(bare) and _undescended(repo, path):
            unread.add(bare)
            continue
        full = repo.joinpath(*path.split("/"))
        try:
            if path in _CHECKWASH_CONFIGS and full.is_symlink():
                # SPEC §3.2: checkwash reads its config from git, where a
                # symlink is stored as its link text.
                data = os.fsencode(os.readlink(full))
            elif not full.is_file():
                continue
            else:
                data = full.read_bytes()
        except OSError as exc:
            if exc.errno in _ABSENT_ERRNOS:
                continue
            data = UNREADABLE
        out[path] = data
    # An ignored symlink at a fixed surface directory is in no listing: no
    # surface pathspec names the link itself. A directory reached through
    # a tracked or symlinked ancestor is that ancestor's (R23, or its row).
    for bare in sorted(_SURFACE_DIRS):
        parts = bare.split("/")
        ancestors = ["/".join(parts[:i]) for i in range(1, len(parts))]
        if bare in tracked or any(
            a in tracked or _symlink(repo.joinpath(*a.split("/"))) for a in ancestors
        ):
            continue
        if _symlink(repo.joinpath(*parts)):
            unread.add(bare)
    return out, sorted(unread)


def _ignored_group(path: str) -> str:
    """The directory directly below a fixed surface directory that holds
    `path`, or `path` itself when it sits directly in one or is exact."""
    for prefix in _SURFACE_DIR_PREFIXES:
        if path.startswith(prefix):
            rest = path[len(prefix):]
            if "/" in rest:
                return prefix + rest.split("/", 1)[0]
    return path


def ignored_surface_paths(repo: Path) -> tuple[list[str], list[str], list[str]]:
    """SPEC §2, R21 (spec 16): what an ignore rule hides at the fixed-prefix
    surface paths, names only (the worktree read never opens them): the
    ignored surface files, the ignored entries at or below a fixed surface
    directory that git does not descend, and, in place of its entries, each
    directory directly below a fixed surface directory that holds more than
    one of them. Literal pathspecs keep git out of every ignored tree
    outside the fixed surface directories."""
    from pinwash.surfaces import is_surface

    proc = _run(
        repo,
        [
            "ls-files", "-z", "-o", "-i", "--exclude-standard", "--",
            *(":(literal)" + p for p in SURFACE_PREFIXES),
        ],
    )
    if proc.returncode != 0:
        raise GitError(_UNREADABLE_GIT)
    # True: not descended; False: a surface file, or a symlinked directory
    # that only an lstat tells apart, done for an entry left alone in its
    # group (a tree collapsed into one row needs none).
    entries: dict[str, bool] = {}
    for name in proc.stdout.split(b"\0"):
        if not name:
            continue
        path = name.decode("utf-8", "surrogateescape")
        bare = path.rstrip("/")
        if path.endswith("/"):
            if _at_surface_dir(bare):
                entries[bare] = True
        elif is_surface(path):
            entries[path] = False
        elif _at_surface_dir(path) and _undescended(repo, path):
            entries[path] = True
    groups: dict[str, list[str]] = {}
    for path in sorted(entries):
        groups.setdefault(_ignored_group(path), []).append(path)
    files: list[str] = []
    directories: list[str] = []
    undescended: list[str] = []
    for group, members in groups.items():
        if len(members) > 1:
            directories.append(group)
            continue
        path = members[0]
        if entries[path] or (_at_surface_dir(path) and _undescended(repo, path)):
            undescended.append(path)
        else:
            files.append(path)
    return sorted(files), sorted(directories), sorted(undescended)
