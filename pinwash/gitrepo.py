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
WORKTREE = "WORKTREE"

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


_UNREADABLE_GIT = "unreadable git repository"
_MISMATCH = "git object does not match its id"


def _run(repo: Path, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [*_GIT, *args],
        cwd=repo,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        env=_env(),
    )


def _run_input(
    repo: Path, args: list[str], input_bytes: bytes
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [*_GIT, *args],
        cwd=repo,
        input=input_bytes,
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

    def oid(self, raw: bytes) -> str:
        """A hex object id as git prints it, or GitError."""
        text = raw.decode("ascii", "replace")
        if len(text) != self.hexsz or text.strip("0123456789abcdef"):
            raise GitError(_UNREADABLE_GIT)
        return text

    def check(self, oid: str, kind: bytes, data: bytes) -> None:
        """The object's bytes rehash to its id, or GitError (SPEC §8)."""
        h = hashlib.new(self.name, usedforsecurity=False)
        h.update(kind + b" %d\0" % len(data))
        h.update(data)
        if h.hexdigest() != oid:
            raise GitError(_MISMATCH)


def _layout(repo: Path) -> tuple[_Format, bytes]:
    """Object format and the cwd prefix, after the work tree checks.

    The prefix scopes every listing as `git ls-tree` and `git ls-files` do
    from a subdirectory. Git takes the work tree from core.worktree, which
    the repository's config sets, so a `core.worktree = ../..` would move
    the work tree above the checkout and scope both trees to a subtree that
    does not exist: every range would read empty and pass. The work tree
    must be the directory that holds the .git git found, unless the judge
    named it in GIT_WORK_TREE.
    """
    proc = _run(
        repo,
        [
            "rev-parse",
            "--is-inside-work-tree",
            "--show-object-format",
            "--show-toplevel",
            "--show-prefix",
        ],
    )
    parts = proc.stdout.split(b"\n", 3)
    if proc.returncode != 0 or len(parts) != 4 or parts[0] != b"true":
        raise GitError(_UNREADABLE_GIT)
    if not parts[3].endswith(b"\n"):
        raise GitError(_UNREADABLE_GIT)
    fmt = _Format(parts[1])
    if not os.environ.get("GIT_WORK_TREE"):
        _check_work_tree(repo, parts[2])
    return fmt, parts[3][:-1]


def _check_work_tree(repo: Path, toplevel: bytes) -> None:
    here = os.path.realpath(repo)
    while not os.path.lexists(os.path.join(here, ".git")):
        parent = os.path.dirname(here)
        if parent == here:
            raise GitError("git work tree is not the directory that holds .git")
        here = parent
    top = os.path.realpath(os.fsdecode(toplevel))
    if os.path.normcase(top) != os.path.normcase(here):
        raise GitError("git work tree is not the directory that holds .git")


def require_repo(repo: Path) -> None:
    _layout(repo)


def _rev(repo: Path, fmt: _Format, spec: str) -> str:
    proc = _run(repo, ["rev-parse", "--verify", "--end-of-options", spec])
    if proc.returncode != 0 or not proc.stdout.endswith(b"\n"):
        raise GitError(_UNREADABLE_GIT)
    return fmt.oid(proc.stdout[:-1])


class _Store:
    """Objects read one at a time from a single `git cat-file --batch`.

    Every object is rehashed against the id it was asked for: a forged loose
    object, a pack or index that maps an id to other bytes, or an alternate
    store cannot change what pinwash reads, only make it exit 2.
    """

    def __init__(self, repo: Path, fmt: _Format) -> None:
        self.fmt = fmt
        self._proc: subprocess.Popen[bytes] | None = subprocess.Popen(
            [*_GIT, "cat-file", "--batch"],
            cwd=repo,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_env(),
        )
        self._commits: dict[str, tuple[list[str], int]] = {}

    def __enter__(self) -> _Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
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

    def read(self, oid: str) -> tuple[bytes, bytes]:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.stdout is None:
            raise GitError(_UNREADABLE_GIT)
        try:
            proc.stdin.write(oid.encode("ascii") + b"\n")
            proc.stdin.flush()
            header = proc.stdout.readline()
            parts = header.split()
            if (
                len(parts) != 3
                or parts[0] != oid.encode("ascii")
                or not parts[2].isdigit()
            ):
                raise GitError(_UNREADABLE_GIT)
            size = int(parts[2])
            body = proc.stdout.read(size + 1)
        except OSError:
            raise GitError(_UNREADABLE_GIT) from None
        if len(body) != size + 1 or body[-1:] != b"\n":
            raise GitError(_UNREADABLE_GIT)
        data = body[:-1]
        self.fmt.check(oid, parts[1], data)
        return parts[1], data

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
        return self._hex(data[len(key) : end])

    def _hex(self, raw: bytes) -> str:
        try:
            return bytes.fromhex(raw.decode("ascii")).hex()
        except (UnicodeDecodeError, ValueError):
            raise GitError(_UNREADABLE_GIT) from None

    def tree(self, oid: str) -> list[tuple[bytes, bytes, str]]:
        """(kind, name, id) per entry, in stored order, as `git ls-tree`
        reads them: a canonical directory mode is a tree, a regular file or
        symlink mode a blob, every other mode a gitlink (commit)."""
        kind, data = self.read(oid)
        if kind != b"tree":
            raise GitError(_UNREADABLE_GIT)
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
        return entries

    def commit(self, oid: str) -> tuple[list[str], int]:
        """Parents and committer date from the verified commit body, read as
        git's parse_commit_buffer() reads them (grafts, shallow, replace
        refs and commit-graph are off, so git reads the same)."""
        cached = self._commits.get(oid)
        if cached is not None:
            return cached
        kind, data = self.read(oid)
        if kind != b"commit":
            raise GitError(_UNREADABLE_GIT)
        hexsz = self.fmt.hexsz
        if len(data) <= hexsz + 6 or data[:5] != b"tree " or data[hexsz + 5] != 0x0A:
            raise GitError(_UNREADABLE_GIT)
        self._hex(data[5 : hexsz + 5])
        pos = hexsz + 6
        parents: list[str] = []
        while pos + hexsz + 7 < len(data) and data[pos : pos + 7] == b"parent ":
            if pos + hexsz + 8 >= len(data) or data[pos + hexsz + 7] != 0x0A:
                raise GitError(_UNREADABLE_GIT)
            parents.append(self._hex(data[pos + 7 : pos + hexsz + 7]))
            pos += hexsz + 8
        result = (parents, _commit_date(data[pos:]))
        self._commits[oid] = result
        return result


def _commit_date(buf: bytes) -> int:
    """git's parse_commit_date(): the committer timestamp, 0 if malformed."""
    if len(buf) <= 6 or buf[:6] != b"author":
        return 0
    nl = buf.find(b"\n")
    if nl < 0:
        return 0
    buf = buf[nl + 1 :]
    if len(buf) <= 9 or buf[:9] != b"committer":
        return 0
    eol = buf.find(b"\n")
    if eol < 0:
        return 0
    line = buf[:eol]
    pos = line.rfind(b">") + 1
    if pos == 0:
        return 0
    while pos < eol and line[pos] in b" \t\n\v\f\r":
        pos += 1
    negative = line[pos : pos + 1] == b"-"
    if not negative and not line[pos : pos + 1].isdigit():
        return 0
    pos += negative
    digits = pos
    while digits < eol and line[digits : digits + 1].isdigit():
        digits += 1
    if digits == pos:
        return 0
    value = int(line[pos:digits])
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
    first in first out on ties), same flags, same results."""
    flags[one] = flags.get(one, 0) | _P1
    if not twos:
        return [one]
    queue: list[tuple[int, int, str]] = []
    counter = 0

    def put(oid: str) -> None:
        nonlocal counter
        heapq.heappush(queue, (-store.commit(oid)[1], counter, oid))
        counter += 1

    put(one)
    for two in twos:
        flags[two] = flags.get(two, 0) | _P2
        put(two)
    result: list[str] = []
    while any(not flags[oid] & _STALE for _d, _c, oid in queue):
        _date, _ctr, oid = heapq.heappop(queue)
        mark = flags[oid] & (_P1 | _P2 | _STALE)
        if mark == _P1 | _P2:
            if not flags[oid] & _RESULT:
                flags[oid] |= _RESULT
                _insert_by_date(store, result, oid)
            mark |= _STALE
        for parent in store.commit(oid)[0]:
            if flags.get(parent, 0) & mark == mark:
                continue
            flags[parent] = flags.get(parent, 0) | mark
            put(parent)
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
        if not left or not right:
            raise GitError("invalid range")
        left_oid = _rev(repo, fmt, left)
        right_oid = _rev(repo, fmt, right)
        mb = _run(repo, ["merge-base", "--end-of-options", left_oid, right_oid])
        if mb.returncode != 0 or not mb.stdout.endswith(b"\n"):
            raise GitError(_UNREADABLE_GIT)
        base = fmt.oid(mb.stdout[:-1])
        # SPEC §2: the base is merge-base(BASE, HEAD), recomputed from
        # rehashed commit objects; a git answer that differs (a forged
        # commit object steered it) is exit 2, never a pass.
        with _Store(repo, fmt) as store:
            one = store.peel(left_oid, b"commit")
            two = store.peel(right_oid, b"commit")
            verified = _merge_bases(store, one, two)
        if not verified or verified[0] != base:
            raise GitError("merge base does not verify against commit objects")
        return base, right_oid, left, right
    if ".." in raw:
        left, right = raw.split("..", 1)
        if not left or not right:
            raise GitError("invalid range")
        return left, right, left, right
    raise GitError("invalid range")


def ls_tree(repo: Path, spec: str) -> dict[str, bytes]:
    fmt, prefix = _layout(repo)
    if spec == WORKTREE:
        return _ls_worktree(repo)
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
    return _cat_file_batch(repo, fmt, entries)


def _blobs(store: _Store, roots: list[str]) -> list[tuple[str, str]]:
    """Blob entries in `git ls-tree -r` order, from verified tree objects."""
    cache: dict[str, list[tuple[bytes, bytes, str]]] = {}

    def entries(oid: str) -> list[tuple[bytes, bytes, str]]:
        if oid not in cache:
            cache[oid] = store.tree(oid)
        return cache[oid]

    found: list[tuple[str, str]] = []
    for root in roots:
        stack = [(b"", iter(entries(root)))]
        while stack:
            base, it = stack[-1]
            entry = next(it, None)
            if entry is None:
                stack.pop()
                continue
            kind, name, child = entry
            if kind == b"tree":
                stack.append((base + name + b"/", iter(entries(child))))
            elif kind == b"blob":
                # Names keep their literal bytes, Git-quoted Unicode and
                # whitespace included. A gitlink (submodule, kind commit)
                # names a commit of another repository, absent from this
                # object store. It is a directory in a checkout, never
                # file bytes, so no surface can be one.
                found.append(((base + name).decode("utf-8", "surrogateescape"), child))
    return found


def _cat_file_batch(
    repo: Path, fmt: _Format, entries: list[tuple[str, str]]
) -> dict[str, bytes]:
    """One cat-file --batch round trip for every blob, each rehashed.

    Requests are object ids, so a filename cannot become part of cat-file's
    newline-delimited request protocol.
    """
    if not entries:
        return {}
    oids = list(dict.fromkeys(oid for _path, oid in entries))
    request = b"".join(oid.encode("ascii") + b"\n" for oid in oids)
    proc = _run_input(repo, ["cat-file", "--batch"], request)
    if proc.returncode != 0:
        raise GitError(_UNREADABLE_GIT)
    out = proc.stdout
    out_len = len(out)
    blobs: dict[str, bytes] = {}
    pos = 0
    for oid in oids:
        nl = out.find(b"\n", pos)
        if nl < 0:
            raise GitError(_UNREADABLE_GIT)
        parts = out[pos:nl].split()
        pos = nl + 1
        if (
            len(parts) != 3
            or parts[0] != oid.encode("ascii")
            or parts[1] != b"blob"
            or not parts[2].isdigit()
        ):
            raise GitError(_UNREADABLE_GIT)
        size = int(parts[2])
        if pos + size + 1 > out_len or out[pos + size : pos + size + 1] != b"\n":
            raise GitError(_UNREADABLE_GIT)
        data = out[pos : pos + size]
        fmt.check(oid, b"blob", data)
        blobs[oid] = data
        pos += size + 1
    return {path: blobs[oid] for path, oid in entries}


def _ls_worktree(repo: Path) -> dict[str, bytes]:
    proc = _run(repo, ["ls-files", "-z", "-co", "--exclude-standard"])
    if proc.returncode != 0:
        raise GitError(_UNREADABLE_GIT)
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
