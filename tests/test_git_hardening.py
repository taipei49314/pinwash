"""SPEC §1.3 and §8: the subject repository's .git never runs a program and
never rewrites what the base reads.

The agent under judgement can write the repository's config, refs, info/
files and object store (SPEC §1.1). Each test builds a real repository with
one such vector and runs the public CLI's main() in this process, with the
cwd and a scrubbed environment set as a consumer would (or, for merge-base
agreement, the git adapter); CliSpawned runs `python -P -m pinwash` once per
mode. A marker program only appends a line to a file inside the test's
temporary directory, and every test that plants one asserts that the file
does not exist afterwards. No test runs subject code itself.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from typing import Any
from unittest import mock

from pinwash import cli, gitrepo

ROOT = Path(__file__).resolve().parents[1]
TODAY = "2026-10-09"
SETTINGS = ".claude/settings.json"
STOP = json.dumps(
    {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python hooks/judge.py"}]}]}}
)
EMPTY = json.dumps({"hooks": {}})
JUDGE = "import json\nprint(json.dumps({'decision': 'block'}))\n"
BLOCK = [("HOOK_REMOVED", "critical")]
MISSING = "is not in the object store (a partial or shallow clone? fetch it before judging)"
POSIX = os.name == "posix"
HOOK_NAMES = (
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit",
    "pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-commit",
    "pre-rebase", "post-checkout", "post-merge", "pre-push", "pre-receive",
    "update", "proc-receive", "post-receive", "post-update",
    "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite",
    "sendemail-validate", "fsmonitor-watchman", "p4-changelist",
    "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit",
    "post-index-change",
)


def _git_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_AUTHOR_DATE="1760000000 +0000",
        GIT_COMMITTER_DATE="1760000000 +0000",
    )
    env.update(extra or {})
    return env


def _sha256_supported() -> bool:
    with tempfile.TemporaryDirectory(prefix="pinwash-sha256-") as tmp:
        proc = subprocess.run(
            ["git", "init", "-q", "--object-format=sha256", tmp],
            env=_git_env(), capture_output=True, check=False,
        )
        return proc.returncode == 0


class _Lab(unittest.TestCase):
    """Real repositories with isolated git config, and the public CLI."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="pinwash-harden-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def git(self, repo: Path, *args: str, env: dict[str, str] | None = None,
            stdin: bytes | None = None) -> str:
        proc = subprocess.run(
            ["git", "-c", "user.name=pinwash", "-c", "user.email=pinwash@test",
             "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
            cwd=repo, env=_git_env(env), input=stdin, capture_output=True,
            check=False, timeout=60,
        )
        if proc.returncode != 0:
            self.fail(f"git {args}: {proc.stderr.decode('utf-8', 'replace')}")
        return proc.stdout.decode("utf-8", "replace").strip()

    def new_repo(self, name: str = "repo", fmt: str | None = None) -> Path:
        repo = self.root / name
        repo.mkdir(parents=True)
        self.git(repo, "init", "-q", "-b", "main",
                 *([f"--object-format={fmt}"] if fmt else []))
        return repo

    def write(self, repo: Path, files: dict[str, str]) -> None:
        for rel, text in files.items():
            full = repo / rel
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(text, encoding="utf-8")

    def commit(self, repo: Path, files: dict[str, str], message: str = "c",
               date: int = 1760000000) -> str:
        self.write(repo, files)
        stamp = {"GIT_AUTHOR_DATE": f"{date} +0000", "GIT_COMMITTER_DATE": f"{date} +0000"}
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-q", "--allow-empty", "-m", message, env=stamp)
        return self.git(repo, "rev-parse", "HEAD")

    def weakened(self, name: str = "repo", fmt: str | None = None) -> tuple[Path, str]:
        """BASE holds a Stop judge; HEAD (committed) and the worktree drop it."""
        repo = self.new_repo(name, fmt)
        base = self.commit(repo, {SETTINGS: STOP, "hooks/judge.py": JUDGE}, "base")
        self.commit(repo, {SETTINGS: EMPTY}, "weaken")
        return repo, base

    def check(self, repo: Path, *args: str, cwd: Path | None = None,
              env: dict[str, str] | None = None,
              spawn: bool = False) -> tuple[int, dict[str, Any] | None, str]:
        """`pinwash check ARGS` from cwd (default: repo), with no GIT_*
        variable but env's: cli.main() in this process, or with spawn the
        consumer recipe `python -P -m pinwash` in a child process."""
        environ = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        environ.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       PINWASH_TODAY=TODAY)
        environ.update(env or {})
        where = cwd or repo
        if spawn:
            environ["PYTHONPATH"] = str(ROOT)
            proc = subprocess.run(
                [sys.executable, "-P", "-m", "pinwash", "check", *args],
                cwd=where, env=environ, capture_output=True, timeout=120,
            )
            code, out, err = proc.returncode, proc.stdout, proc.stderr.decode("utf-8", "replace")
        else:
            stdout = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
            stderr = io.StringIO()
            with mock.patch.dict(os.environ, environ, clear=True), \
                    contextlib.chdir(where), contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr):
                code = cli.main(["check", *args])
            stdout.flush()
            out, err = stdout.buffer.getvalue(), stderr.getvalue()
        payload = json.loads(out.decode("utf-8")) if out else None
        return code, payload, err

    def rules(self, payload: dict[str, Any] | None) -> list[tuple[str, str]]:
        assert payload is not None
        return sorted((f["rule"], f["severity"]) for f in payload["findings"])

    def assertBlocks(self, result: tuple[int, dict[str, Any] | None, str]) -> None:
        code, payload, err = result
        self.assertEqual(code, 1, err)
        self.assertEqual(self.rules(payload), BLOCK)

    def assertPasses(self, result: tuple[int, dict[str, Any] | None, str]) -> None:
        code, payload, err = result
        self.assertEqual(code, 0, err)
        self.assertEqual(self.rules(payload), [])

    def assertExit2(self, result: tuple[int, dict[str, Any] | None, str],
                    message: str = "") -> None:
        code, payload, err = result
        self.assertEqual(code, 2, err)
        self.assertIsNone(payload)
        self.assertIn(message, err)

    def marker(self, name: str) -> tuple[Path, Path]:
        """A program that only appends to a marker file in the temp dir."""
        mark = self.root / f"{name}.ran"
        prog = self.root / f"{name}.sh"
        prog.write_text(f"#!/bin/sh\necho ran >> '{mark}'\nexit 0\n", encoding="utf-8")
        prog.chmod(0o755)
        return prog, mark

    def every_mode(self, repo: Path, base: str, env: dict[str, str] | None = None,
                   ) -> list[tuple[int, dict[str, Any] | None, str]]:
        """BASE..HEAD, BASE...HEAD, BASE..WORKTREE and the plain check."""
        return [
            self.check(repo, f"{base}..HEAD", env=env),
            self.check(repo, f"{base}...HEAD", env=env),
            self.check(repo, f"{base}..WORKTREE", env=env),
            self.check(repo, env=env),
        ]

    def assertJudged(self, results: list[tuple[int, dict[str, Any] | None, str]]) -> None:
        """every_mode() on weakened(): three blocks, and HEAD vs worktree passes."""
        for result in results[:3]:
            self.assertBlocks(result)
        self.assertPasses(results[3])

    def object_path(self, repo: Path, oid: str) -> Path:
        return repo / ".git" / "objects" / oid[:2] / oid[2:]

    def forge(self, repo: Path, oid: str, kind: str, body: bytes) -> None:
        """Overwrite the loose object at oid with other bytes (no git call)."""
        path = self.object_path(repo, oid)
        self.assertTrue(path.exists(), path)
        path.chmod(0o644)
        path.write_bytes(zlib.compress(kind.encode() + b" %d\0" % len(body) + body))


@unittest.skipUnless(POSIX, "marker programs are POSIX shell scripts")
class FsmonitorNeverRuns(_Lab):
    """core.fsmonitor names a program that `git ls-files` runs in worktree
    mode. The spec 12 engine ran it; every git call now sets it false."""

    def test_marker_never_runs_in_any_mode(self) -> None:
        repo, base = self.weakened()
        prog, mark = self.marker("fsmonitor")
        self.git(repo, "config", "core.fsmonitor", str(prog))
        self.git(repo, "config", "core.fsmonitorHookVersion", "2")
        self.write(repo, {"untracked.txt": "x\n"})
        self.assertJudged(self.every_mode(repo, base))
        self.assertFalse(mark.exists())

    def test_marker_never_runs_through_config_indirection(self) -> None:
        repo, base = self.weakened()
        prog, mark = self.marker("fsmonitor-include")
        included = self.root / "included.cfg"
        included.write_text(f"[core]\n\tfsmonitor = {prog}\n", encoding="utf-8")
        self.git(repo, "config", "include.path", str(included))
        self.assertJudged(self.every_mode(repo, base))
        self.git(repo, "config", "--unset", "include.path")
        self.git(repo, "config", f"includeIf.gitdir:{repo}/.git.path", str(included))
        self.assertJudged(self.every_mode(repo, base))
        self.git(repo, "config", "--unset", f"includeIf.gitdir:{repo}/.git.path")
        self.git(repo, "config", "core.repositoryformatversion", "1")
        self.git(repo, "config", "extensions.worktreeConfig", "true")
        self.git(repo, "config", "--worktree", "core.fsmonitor", str(prog))
        self.assertJudged(self.every_mode(repo, base))
        self.assertFalse(mark.exists())


@unittest.skipUnless(POSIX, "marker programs are POSIX shell scripts")
class CliSpawned(_Lab):
    """The consumer recipe end to end, `python -P -m pinwash check` in a
    child process, against a repository that sets core.fsmonitor."""

    def test_every_mode_in_a_child_process(self) -> None:
        repo, base = self.weakened()
        prog, mark = self.marker("spawned")
        self.git(repo, "config", "core.fsmonitor", str(prog))
        self.write(repo, {"untracked.txt": "x\n"})
        self.assertJudged([
            self.check(repo, f"{base}..HEAD", spawn=True),
            self.check(repo, f"{base}...HEAD", spawn=True),
            self.check(repo, f"{base}..WORKTREE", spawn=True),
            self.check(repo, spawn=True),
        ])
        self.assertFalse(mark.exists())


@unittest.skipUnless(POSIX, "marker programs are POSIX shell scripts")
class HooksAndDriversNeverRun(_Lab):
    """No hook, filter, textconv, diff or merge driver, pager, credential or
    signing program named by the repository runs: pinwash's plumbing calls
    none of them (core.hooksPath is also pointed at no directory)."""

    def test_every_hook_name_in_both_hook_locations(self) -> None:
        repo, base = self.weakened()
        prog, mark = self.marker("hooks")
        hooks_dir = self.root / "hooksdir"
        hooks_dir.mkdir()
        for name in HOOK_NAMES:
            for where in (hooks_dir, repo / ".git" / "hooks"):
                (where / name).write_text(f"#!/bin/sh\n'{prog}' {name}\n", encoding="utf-8")
                (where / name).chmod(0o755)
        self.assertJudged(self.every_mode(repo, base))
        self.git(repo, "config", "core.hooksPath", str(hooks_dir))
        self.git(repo, "config", "core.splitIndex", "true")
        self.git(repo, "config", "core.untrackedCache", "true")
        self.assertJudged(self.every_mode(repo, base))
        self.assertFalse(mark.exists())

    def test_filters_drivers_pager_credentials_signing(self) -> None:
        repo, base = self.weakened()
        prog, mark = self.marker("drivers")
        self.write(repo, {".gitattributes": "* filter=pw diff=pw merge=pw\n"})
        for key in ("filter.pw.clean", "filter.pw.smudge", "filter.pw.process",
                    "diff.pw.textconv", "diff.pw.command", "merge.pw.driver",
                    "core.pager", "core.askPass", "credential.helper", "gpg.program",
                    "core.editor", "sequence.editor", "core.alternateRefsCommand",
                    "core.sshCommand", "diff.external"):
            self.git(repo, "config", key, f"{prog} {key}")
        self.git(repo, "config", "filter.pw.required", "true")
        for cmd in ("ls-files", "ls-tree", "cat-file", "rev-parse", "merge-base"):
            self.git(repo, "config", f"pager.{cmd}", "true")
        self.write(repo, {SETTINGS: EMPTY + "\n"})  # a dirty tracked surface
        self.assertJudged(self.every_mode(repo, base))
        self.assertFalse(mark.exists())


class ReplaceRefsIgnored(_Lab):
    """refs/replace (`git replace`) rewrote what BASE read: the spec 12
    engine passed a removed Stop hook. Every git call now runs with
    --no-replace-objects."""

    def test_replaced_base_blob(self) -> None:
        repo, base = self.weakened()
        base_blob = self.git(repo, "rev-parse", f"{base}:{SETTINGS}")
        weak_blob = self.git(repo, "rev-parse", f"HEAD:{SETTINGS}")
        self.git(repo, "replace", base_blob, weak_blob)
        self.assertEqual(self.git(repo, "cat-file", "-p", f"{base}:{SETTINGS}"), EMPTY)
        self.assertJudged(self.every_mode(repo, base))

    def test_replaced_base_commit(self) -> None:
        repo, base = self.weakened()
        fake = self.git(repo, "commit-tree", self.git(repo, "rev-parse", "HEAD^{tree}"),
                        "-m", "fake base")
        self.git(repo, "replace", base, fake)
        self.assertJudged(self.every_mode(repo, base))

    def test_replace_graft_does_not_move_the_merge_base(self) -> None:
        repo, c0, c1, f1 = _stitch(self)
        self.git(repo, "replace", "--graft", f1, c0)
        self.assertEqual(self.git(repo, "merge-base", c1, "HEAD"), c0)
        self.assertEqual(self.git(repo, "rev-parse", "HEAD~2"), c0)
        self.assertBlocks(self.check(repo, f"{c1}...HEAD"))
        self.assertBlocks(self.check(repo, "HEAD~2..HEAD"))


class ForgedObjectsExit2(_Lab):
    """Objects are rehashed against their ids. A loose object rewritten in
    place (no ref, no config: git itself reads the forged bytes) made the
    spec 12 engine pass; it is now an unreadable git tree, exit 2."""

    MISMATCH = "git object does not match its id"

    def test_forged_base_blob(self) -> None:
        repo, base = self.weakened()
        self.forge(repo, self.git(repo, "rev-parse", f"{base}:{SETTINGS}"), "blob",
                   EMPTY.encode())
        self.assertEqual(self.git(repo, "cat-file", "-p", f"{base}:{SETTINGS}"), EMPTY)
        self.assertExit2(self.check(repo, f"{base}..HEAD"), self.MISMATCH)
        self.assertExit2(self.check(repo, f"{base}..WORKTREE"), self.MISMATCH)

    def test_forged_base_subtree_and_root_tree(self) -> None:
        repo, base = self.weakened()
        for spec in (f"{base}:.claude", f"{base}^{{tree}}"):
            sub = self.git(repo, "rev-parse", spec)
            weak = spec.replace(base, "HEAD")
            body = subprocess.run(
                ["git", "cat-file", "tree", self.git(repo, "rev-parse", weak)],
                cwd=repo, env=_git_env(), capture_output=True, check=True,
            ).stdout
            saved = self.object_path(repo, sub).read_bytes()
            self.forge(repo, sub, "tree", body)
            self.assertExit2(self.check(repo, f"{base}..HEAD"), self.MISMATCH)
            self.object_path(repo, sub).write_bytes(saved)
            self.assertBlocks(self.check(repo, f"{base}..HEAD"))

    def test_forged_base_commit(self) -> None:
        repo, base = self.weakened()
        body = subprocess.run(
            ["git", "cat-file", "commit", "HEAD"], cwd=repo, env=_git_env(),
            capture_output=True, check=True,
        ).stdout
        self.forge(repo, base, "commit", body)
        self.assertExit2(self.check(repo, f"{base}..HEAD"), self.MISMATCH)

    def test_forged_commit_steers_the_merge_base(self) -> None:
        repo, c0, c1, f1 = _stitch(self)
        tree = self.git(repo, "rev-parse", f"{f1}^{{tree}}")
        body = (f"tree {tree}\nparent {c0}\nauthor a <a@a> 1760000000 +0000\n"
                f"committer a <a@a> 1760000000 +0000\n\nweaken\n").encode()
        self.forge(repo, f1, "commit", body)
        self.assertEqual(self.git(repo, "merge-base", c1, "HEAD"), c0)
        self.assertExit2(self.check(repo, f"{c1}...HEAD"), self.MISMATCH)

    def test_forged_object_in_an_alternate_store(self) -> None:
        repo, base = self.weakened()
        blob = self.git(repo, "rev-parse", f"{base}:{SETTINGS}")
        other = self.new_repo("alternate")
        (other / ".git" / "objects" / blob[:2]).mkdir()
        self.object_path(repo, blob).rename(self.object_path(other, blob))
        self.forge(other, blob, "blob", EMPTY.encode())
        alternates = repo / ".git" / "objects" / "info" / "alternates"
        alternates.write_bytes(((other / ".git" / "objects").as_posix() + "\n").encode("utf-8"))
        # Prove that native Git actually reaches the forged alternate;
        # a missing object is not a successful hash-mismatch regression.
        forged = subprocess.run(
            ["git", "cat-file", "blob", blob], cwd=repo, env=_git_env(),
            capture_output=True, check=True,
        )
        self.assertEqual(forged.stdout, EMPTY.encode())
        self.assertExit2(self.check(repo, f"{base}..HEAD"), self.MISMATCH)


class MalformedTreesExit2(_Lab):
    """A tree that git fsck rejects has no single content: ls-tree -r lists
    a duplicated name twice, diff-tree and show take the first entry. The
    reader kept the last one, so a committed Stop removal whose head tree
    lists `settings.json` twice (removed first, live last) passed BASE..HEAD.
    A duplicated name or an entry out of git's order is now exit 2."""

    def head_with_claude_tree(self, repo: Path, base: str, raw: bytes) -> None:
        sub = self.git(repo, "hash-object", "-t", "tree", "-w", "--literally",
                       "--stdin", stdin=raw)
        hooks = self.git(repo, "rev-parse", f"{base}:hooks")
        root = self.git(repo, "mktree", stdin=(
            f"040000 tree {sub}\t.claude\n040000 tree {hooks}\thooks\n").encode())
        head = self.git(repo, "commit-tree", root, "-p", base, "-m", "weaken")
        self.git(repo, "update-ref", "HEAD", head)

    def entry(self, repo: Path, name: str, text: str) -> bytes:
        oid = self.git(repo, "hash-object", "-w", "--stdin", stdin=text.encode())
        return b"100644 " + name.encode() + b"\0" + bytes.fromhex(oid)

    def test_duplicate_name(self) -> None:
        repo, base = self.weakened()
        raw = self.entry(repo, "settings.json", EMPTY) + self.entry(repo, "settings.json", STOP)
        self.head_with_claude_tree(repo, base, raw)
        fsck = subprocess.run(["git", "fsck", "--no-dangling"], cwd=repo,
                              env=_git_env(), capture_output=True)
        self.assertIn(b"duplicateEntries", fsck.stdout + fsck.stderr)
        self.assertExit2(self.check(repo, f"{base}..HEAD"))
        self.assertExit2(self.check(repo, f"{base}...HEAD"))

    def test_entries_out_of_order(self) -> None:
        repo, base = self.weakened()
        raw = self.entry(repo, "settings.json", EMPTY) + self.entry(repo, "aaa.json", "{}")
        self.head_with_claude_tree(repo, base, raw)
        self.assertExit2(self.check(repo, f"{base}..HEAD"))

    def test_git_ordered_tree_with_a_directory_is_judged(self) -> None:
        """Control: git sorts a directory as its name plus "/", so `a.b`
        before `a/` is git's order, not a malformed tree."""
        repo, base = self.weakened()
        self.commit(repo, {"a.b": "x", "a/c": "y"}, "control")
        self.assertBlocks(self.check(repo, f"{base}..HEAD"))


@unittest.skipUnless(POSIX, "marker programs are POSIX shell scripts")
class PromisorRemoteNeverFetches(_Lab):
    """A partial-clone promisor remote made git lazily fetch a missing BASE
    object by running a program (ext::, a local upload-pack, ssh). The
    spec 12 engine ran it; now no lazy fetch and no transport happen, and a
    missing object is an unreadable git tree that says so."""

    def test_no_transport_program_runs(self) -> None:
        for kind in ("ext", "uploadpack", "ssh"):
            repo, base = self.weakened(kind)
            blob = self.git(repo, "rev-parse", f"{base}:{SETTINGS}")
            self.object_path(repo, blob).unlink()
            self.git(repo, "config", "core.repositoryformatversion", "1")
            self.git(repo, "config", "extensions.partialClone", "origin")
            self.git(repo, "config", "remote.origin.promisor", "true")
            self.git(repo, "config", "protocol.allow", "always")
            prog, mark = self.marker(kind)
            if kind == "ext":
                self.git(repo, "config", "remote.origin.url", f"ext::{prog} %s")
            elif kind == "uploadpack":
                self.git(repo, "config", "remote.origin.url", str(self.new_repo(f"{kind}-up")))
                self.git(repo, "config", "remote.origin.uploadpack", str(prog))
            else:
                self.git(repo, "config", "remote.origin.url", "ssh://pinwash.invalid/x.git")
                self.git(repo, "config", "core.sshCommand", str(prog))
            self.assertExit2(self.check(repo, f"{base}..HEAD"), f"git object {blob} {MISSING}")
            self.assertExit2(self.check(repo, f"{base}..WORKTREE"), MISSING)
            self.assertPasses(self.check(repo))  # HEAD vs worktree reads no base blob
            self.assertFalse(mark.exists(), kind)

    def test_read_ahead_never_fetches(self) -> None:
        # The merge-base walk's batched read-ahead (git rev-list) meets a
        # commit only the promisor remote has.
        repo = self.new_repo()
        commits = _history(self, repo, 300, None, window=1, dates=(60,), files={
            10: {SETTINGS: STOP, "hooks/judge.py": JUDGE}, 299: {SETTINGS: EMPTY}})
        _unpack(self, repo)
        self.git(repo, "reset", "-q", "--hard", commits[-1])
        self.object_path(repo, commits[100]).unlink()
        prog, mark = self.marker("read-ahead")
        self.git(repo, "config", "core.repositoryformatversion", "1")
        self.git(repo, "config", "extensions.partialClone", "origin")
        self.git(repo, "config", "remote.origin.promisor", "true")
        self.git(repo, "config", "protocol.allow", "always")
        self.git(repo, "config", "remote.origin.url", f"ext::{prog} %s")
        self.assertExit2(self.check(repo, f"{commits[10]}...HEAD"),
                         f"git object {commits[100]} {MISSING}")
        self.assertFalse(mark.exists())


class ParentRewritesIgnored(_Lab):
    """info/grafts, .git/shallow and a commit-graph file rewrite parents
    without touching a commit object; they moved `BASE...HEAD` (and
    `HEAD~n`) to a base without the judge, a silent pass. git now reads none
    of them, and the merge base is recomputed from rehashed commits."""

    def test_grafts(self) -> None:
        repo, c0, c1, f1 = _stitch(self)
        (repo / ".git" / "info").mkdir(exist_ok=True)
        (repo / ".git" / "info" / "grafts").write_text(f"{f1} {c0}\n", encoding="utf-8")
        self.assertEqual(self.git(repo, "merge-base", c1, "HEAD"), c0)
        self.assertEqual(self.git(repo, "rev-parse", "HEAD~2"), c0)
        self.assertBlocks(self.check(repo, f"{c1}...HEAD"))
        self.assertBlocks(self.check(repo, "HEAD~2..HEAD"))

    def test_shallow(self) -> None:
        repo = self.new_repo()
        c0 = self.commit(repo, {"README": "r\n"}, "c0", 1760000000)
        c1 = self.commit(repo, {SETTINGS: STOP, "hooks/judge.py": JUDGE}, "c1", 1760000100)
        self.git(repo, "checkout", "-q", "-b", "side", c0)
        side = self.commit(repo, {"side.txt": "s\n"}, "side", 1760000200)
        self.git(repo, "checkout", "-q", "-b", "work", c1)
        s = self.commit(repo, {SETTINGS: EMPTY}, "weaken", 1760000300)
        self.git(repo, "merge", "-q", "--no-edit", side, env={
            "GIT_AUTHOR_DATE": "1760000400 +0000", "GIT_COMMITTER_DATE": "1760000400 +0000"})
        (repo / ".git" / "shallow").write_text(f"{s}\n", encoding="utf-8")
        self.assertEqual(self.git(repo, "merge-base", c1, "HEAD"), c0)
        self.assertBlocks(self.check(repo, f"{c1}...HEAD"))

    def test_commit_graph(self) -> None:
        repo, c0, c1, f1 = _stitch(self)
        self.git(repo, "commit-graph", "write", "--reachable")
        graph = repo / ".git" / "objects" / "info" / "commit-graph"
        _patch_commit_graph(graph, f1, parent=c0)
        # The graph's tree id for the base commit names the weakened tree;
        # the base tree is read from the verified commit body instead.
        _patch_commit_graph(graph, c1, tree=self.git(repo, "rev-parse", f"{f1}^{{tree}}"))
        self.assertEqual(self.git(repo, "merge-base", c1, "HEAD"), c0)
        self.assertEqual(self.git(repo, "rev-parse", "HEAD~2"), c0)
        self.assertBlocks(self.check(repo, f"{c1}...HEAD"))
        self.assertBlocks(self.check(repo, "HEAD~2..HEAD"))
        self.assertBlocks(self.check(repo, f"{c1}..HEAD"))


class WorkTreeLocation(_Lab):
    """`core.worktree = ../..` in .git/config moved the work tree above the
    checkout: both trees were listed for a subtree that does not exist, so
    every range and the worktree check passed. The work tree must be the
    directory that holds the .git git found."""

    MOVED = "git work tree is not the directory that holds .git"

    def test_work_tree_moved_above_the_checkout(self) -> None:
        repo, base = self.weakened("outer/repo")
        self.git(repo, "config", "core.worktree", "../..")
        for result in self.every_mode(repo, base):
            self.assertExit2(result, self.MOVED)

    def test_work_tree_moved_elsewhere_or_bare(self) -> None:
        repo, base = self.weakened()
        self.git(repo, "config", "core.worktree", str(self.new_repo("elsewhere")))
        self.assertExit2(self.check(repo, f"{base}..HEAD"))
        self.git(repo, "config", "--unset", "core.worktree")
        self.git(repo, "config", "core.bare", "true")
        self.assertExit2(self.check(repo, f"{base}..HEAD"))

    def test_gitdir_file_linked_worktree_and_subdirectory_are_judged(self) -> None:
        # A .git file naming a separate git dir whose core.worktree names
        # the checkout back (the submodule layout).
        repo, base = self.weakened()
        gitdir = self.root / "separate.git"
        (repo / ".git").rename(gitdir)
        (repo / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
        self.git(repo, "config", "core.worktree", str(repo))
        self.assertJudged(self.every_mode(repo, base))
        # A linked worktree.
        linked = self.root / "linked"
        self.git(repo, "worktree", "add", "-q", str(linked), "HEAD")
        self.assertJudged(self.every_mode(linked, base))
        # From a subdirectory both trees are that subtree, as `git ls-tree`
        # and `git ls-files` list them there.
        mono = self.new_repo("mono")
        base = self.commit(mono, {f"pkg/{SETTINGS}": STOP, "pkg/hooks/judge.py": JUDGE,
                                  SETTINGS: STOP, "hooks/judge.py": JUDGE}, "base")
        self.commit(mono, {f"pkg/{SETTINGS}": EMPTY}, "weaken")
        self.assertPasses(self.check(mono, f"{base}..HEAD"))
        self.assertBlocks(self.check(mono, f"{base}..HEAD", cwd=mono / "pkg"))
        self.assertBlocks(self.check(mono, f"{base}...HEAD", cwd=mono / "pkg"))
        self.assertBlocks(self.check(mono, f"{base}..WORKTREE", cwd=mono / "pkg"))


    def test_git_dir_layouts_are_judged(self) -> None:
        # yadm / vcsh: GIT_DIR names a git dir kept apart from its work
        # tree, whose core.worktree is the cwd (git's default with GIT_DIR).
        home = self.root / "home"
        home.mkdir()
        gitdir = self.root / "repo.git"
        self.git(self.root, "init", "-q", "-b", "main", "--bare", str(gitdir))
        env = {"GIT_DIR": str(gitdir)}
        self.git(home, "config", "core.bare", "false", env=env)
        self.git(home, "config", "core.worktree", str(home), env=env)
        self.write(home, {SETTINGS: STOP, "hooks/judge.py": JUDGE})
        self.git(home, "add", "-A", env=env)
        self.git(home, "commit", "-q", "-m", "base", env=env)
        base = self.git(home, "rev-parse", "HEAD", env=env)
        self.write(home, {SETTINGS: EMPTY})
        self.git(home, "commit", "-q", "-am", "weaken", env=env)
        for result in self.every_mode(home, base, env=env)[:3]:
            self.assertBlocks(result)
        self.assertPasses(self.check(home, env=env))
        # GIT_DIR exported and run from a subdirectory: git takes the cwd
        # as the top of the work tree, and so does pinwash.
        repo, base = self.weakened("sub-run")
        (repo / "sub").mkdir()
        env = {"GIT_DIR": str(repo / ".git")}
        self.assertBlocks(self.check(repo, f"{base}..HEAD", cwd=repo / "sub", env=env))
        # GIT_DIR does not let core.worktree move the work tree away.
        repo, base = self.weakened("outer/hooked")
        self.git(repo, "config", "core.worktree", "../..")
        for result in self.every_mode(repo, base, env={"GIT_DIR": str(repo / ".git")}):
            self.assertExit2(result, self.MOVED)

    @unittest.skipUnless(POSIX, "a newline in a directory name")
    def test_newline_in_the_repository_path(self) -> None:
        repo, base = self.weakened("new\nline")
        self.assertJudged(self.every_mode(repo, base))
        # The prefix keeps a newline too: from that subdirectory the
        # analysis unit is its subtree.
        base = self.commit(repo, {f"pkg\nx/{SETTINGS}": STOP, "pkg\nx/hooks/judge.py": JUDGE})
        self.commit(repo, {f"pkg\nx/{SETTINGS}": EMPTY})
        self.assertPasses(self.check(repo, f"{base}..HEAD"))
        self.assertBlocks(self.check(repo, f"{base}..HEAD", cwd=repo / "pkg\nx"))


class ShallowClones(_Lab):
    """.git/shallow is subject-writable and git reads none of it, so the
    merge-base walk reads parents from commit objects. An honest shallow
    clone whose merge base is the cut is judged: the walk only marks the
    cut parents stale. One that needs a cut parent to find the base is
    exit 2 and names the missing object."""

    def upstream(self) -> Path:
        """main c1..c8 (c2 adds the Stop judge); feature forks at c6 and
        weakens it."""
        up = self.new_repo("up")
        for i in range(1, 9):
            files = {SETTINGS: STOP, "hooks/judge.py": JUDGE} if i == 2 else {"n.txt": f"{i}\n"}
            self.commit(up, files, f"c{i}", 1760000000 + 100 * i)
            if i == 6:
                self.git(up, "branch", "feature")
        self.git(up, "checkout", "-q", "feature")
        self.commit(up, {SETTINGS: EMPTY}, "f1", 1760001000)
        self.commit(up, {"f.txt": "f\n"}, "f2", 1760001100)
        self.git(up, "checkout", "-q", "main")
        return up

    def clone(self, up: Path, name: str, main_depth: int, feature_depth: int) -> Path:
        url = up.resolve().as_uri()
        self.git(self.root, "-c", "protocol.file.allow=always", "clone", "-q",
                 f"--depth={main_depth}", "-b", "main", url, name)
        repo = self.root / name
        self.git(repo, "-c", "protocol.file.allow=always", "fetch", "-q",
                 f"--depth={feature_depth}", "origin",
                 "feature:refs/remotes/origin/feature")
        return repo

    def test_merge_base_at_the_cut_is_judged(self) -> None:
        up = self.upstream()
        repo = self.clone(up, "shallow", 3, 3)
        cut = self.git(up, "rev-parse", "main~2")
        self.assertIn(cut, (repo / ".git" / "shallow").read_text(encoding="utf-8"))
        self.assertBlocks(self.check(repo, "origin/main...origin/feature"))

    def test_a_cut_the_walk_needs_names_the_object(self) -> None:
        up = self.upstream()
        repo = self.clone(up, "shallower", 2, 1)
        self.assertExit2(self.check(repo, "origin/main...origin/feature"), MISSING)

    def test_deleted_commits_give_git_s_answer_or_exit_2(self) -> None:
        # The agent can delete any object. Whatever it deletes, the walk's
        # answer is the full history's merge base, or GitError.
        repo = self.new_repo()
        rnd = random.Random(77)
        commits = _history(self, repo, 160, rnd, window=8, dates=(0, 5, 20, 20))
        _unpack(self, repo)
        pairs = [(rnd.choice(commits[80:]), rnd.choice(commits[80:])) for _ in range(40)]
        truth = {
            pair: subprocess.run(
                ["git", "-c", "core.commitGraph=false", "merge-base", "--all", *pair],
                cwd=repo, env=_git_env(), capture_output=True, check=True,
            ).stdout.decode().split()
            for pair in pairs
        }
        answered = refused = 0
        for trial in range(6):
            gone = rnd.sample(commits[:150], 12)
            saved = {oid: self.object_path(repo, oid).read_bytes() for oid in gone}
            for oid in gone:
                path = self.object_path(repo, oid)
                path.chmod(0o644)  # Git's owned fixture objects are readonly on Windows.
                path.unlink()
            with gitrepo._Store(repo, gitrepo._Format(b"sha1")) as store:
                for pair in pairs:
                    try:
                        mine = gitrepo._merge_bases(store, *pair)
                    except gitrepo.GitError as exc:
                        self.assertIn(MISSING, exc.message)
                        refused += 1
                        continue
                    self.assertEqual(mine, truth[pair], (trial, pair))
                    answered += 1
            for oid, data in saved.items():
                self.object_path(repo, oid).write_bytes(data)
        self.assertGreater(answered, 0)
        self.assertGreater(refused, 0)


@unittest.skipUnless(_sha256_supported(), "git without --object-format=sha256")
class Sha256Repository(_Lab):
    """Objects of a sha256 repository rehash with sha256."""

    def test_judged_and_forgery_exits_2(self) -> None:
        repo, base = self.weakened(fmt="sha256")
        self.assertEqual(len(base), 64)
        self.assertJudged(self.every_mode(repo, base))
        self.forge(repo, self.git(repo, "rev-parse", f"{base}:{SETTINGS}"), "blob",
                   EMPTY.encode())
        self.assertExit2(self.check(repo, f"{base}..HEAD"), ForgedObjectsExit2.MISMATCH)


class MergeBaseAgreesWithGit(_Lab):
    """The merge base is computed from verified commit objects with git's
    algorithm, and equals git's merge-base (commit-graph off) on honest
    histories, including several best bases with equal dates, and on long
    ones where the walk reads ahead in batches."""

    def compare(self, repo: Path, commits: list[str], pairs: int,
                rnd: random.Random) -> int:
        several = 0
        with gitrepo._Store(repo, gitrepo._Format(b"sha1")) as store:
            for _ in range(pairs):
                one, two = rnd.choice(commits), rnd.choice(commits)
                proc = subprocess.run(
                    ["git", "-c", "core.commitGraph=false", "merge-base", "--all", one, two],
                    cwd=repo, env=_git_env(), capture_output=True, check=False,
                )
                mine = gitrepo._merge_bases(store, one, two)
                self.assertEqual(mine, proc.stdout.decode().split(), (one, two))
                several += len(mine) > 1
        return several

    def test_criss_cross_and_random_histories(self) -> None:
        repo = self.new_repo()
        rnd = random.Random(20261009)
        commits = _history(self, repo, 48, rnd, window=6, dates=(0, 0, 10))
        self.assertGreater(self.compare(repo, commits, 60, rnd), 0)
        self.git(repo, "update-ref", "HEAD", commits[-1])
        self.git(repo, "read-tree", "HEAD")
        self.assertEqual(gitrepo.resolve_range(repo, f"{commits[20]}...HEAD")[0],
                         self.git(repo, "merge-base", commits[20], "HEAD"))

    def test_long_history_reads_ahead(self) -> None:
        repo = self.new_repo()
        rnd = random.Random(1009)
        commits = _history(self, repo, 900, rnd, window=12, dates=(0, 7, 30, 30))
        calls: list[int] = []
        real = gitrepo._Store._prefetch

        def counted(store: gitrepo._Store, count: int, frontier: list[str]) -> None:
            calls.append(count)
            real(store, count, frontier)

        with mock.patch.object(gitrepo._Store, "_prefetch", counted):
            self.assertGreater(self.compare(repo, commits, 30, rnd), 0)
        self.assertGreater(len(calls), 0)

    def test_read_ahead_never_caches_a_forged_commit(self) -> None:
        # main: 300 commits, c10 adds the Stop judge, the tip weakens it.
        # A forged c150 whose parent is c5 makes git's merge-base(c10, tip)
        # c5, a pass; the walk reads c150 ahead in a batch, rejects it, and
        # its own read of c150 is exit 2.
        repo = self.new_repo()
        commits = _history(self, repo, 300, None, window=1, dates=(60,), files={
            10: {SETTINGS: STOP, "hooks/judge.py": JUDGE}, 299: {SETTINGS: EMPTY}})
        _unpack(self, repo)
        body = subprocess.run(
            ["git", "cat-file", "commit", commits[150]], cwd=repo, env=_git_env(),
            capture_output=True, check=True,
        ).stdout.replace(commits[149].encode(), commits[5].encode())
        self.forge(repo, commits[150], "commit", body)
        self.git(repo, "reset", "-q", "--hard", commits[-1])
        self.assertEqual(self.git(repo, "merge-base", commits[10], "HEAD"), commits[5])
        calls: list[int] = []
        real = gitrepo._Store._prefetch

        def counted(store: gitrepo._Store, count: int, frontier: list[str]) -> None:
            calls.append(count)
            real(store, count, frontier)

        with mock.patch.object(gitrepo._Store, "_prefetch", counted):
            self.assertExit2(self.check(repo, f"{commits[10]}...HEAD"),
                             ForgedObjectsExit2.MISMATCH)
        self.assertGreater(len(calls), 0)


class CommitDates(_Lab):
    """Keep Git's queue dates where old/new parsers agree; fail closed
    on ambiguous metadata. The native Git remains an oracle for agreed cases."""

    def test_committer_dates_read_as_git_reads_them(self) -> None:
        repo = self.new_repo()
        tree = self.git(repo, "mktree", stdin=b"").encode()
        top = (1 << 64) - 1
        cases = {
            b" 1760000500": 1760000500, b"  \t\r1760000500": 1760000500,
            b" 1760000500x": 1760000500, b" 017": 17, b" -5": top - 4,
            b" - 5": 0, b" 99999999999999999999999": top,
            b" -18446744073709551615": 1,
        }
        for raw, want in cases.items():
            body = (b"tree " + tree + b"\nauthor a <a@a> 1 +0000\ncommitter c <c@c>"
                    + raw + b" +0000\n\nm\n")
            self.assertEqual(gitrepo._commit_date(body, body.index(b"author")), want, raw)
            oid = self.git(repo, "hash-object", "-t", "commit", "-w", "--literally",
                           "--stdin", stdin=body)
            since = self.git(repo, "rev-list", "--no-walk", "--since=@1760000400", oid)
            self.assertEqual(bool(since), want >= 1760000400, raw)
        ambiguous = [
            b"committer c <c@c>" + raw + b" +0000\n\nm\n"
            for raw in (
                b"\v1760000500", b"\f1760000500", b" +1760000500", b"", b" \xff1760000500",
                b" -18446744073709551616", b" -18446744073709551617",
                b" -99999999999999999999999",
            )
        ] + [
            b"committer c <c@c> \n\n1760000500\n",
            b"committer c <c@c> 1760000500 +0000\n",
            b"committer c c@c 1760000500 +0000\n\n>1760000500\n",
            b"committer c >0 <c@c> 1760000500 +0000\n\nm\n",
        ]
        for committer in ambiguous:
            with self.subTest(committer=committer):
                body = b"tree " + tree + b"\nauthor a <a@a> 1 +0000\n" + committer
                with self.assertRaisesRegex(gitrepo.GitError, "ambiguous across Git parsers"):
                    gitrepo._commit_date(body, body.index(b"author"))
                oid = self.git(repo, "hash-object", "-t", "commit", "-w", "--literally", "--stdin", stdin=body)
                # Distinct OIDs prevent the same-commit merge-base fast path
                # from avoiding the date parser this regression must cover.
                child_body = (b"tree " + tree + b"\nparent " + oid.encode()
                              + b"\nauthor a <a@a> 1 +0000\ncommitter c <c@c> 1760000600 +0000\n\nchild\n")
                child = self.git(repo, "hash-object", "-t", "commit", "-w", "--literally", "--stdin", stdin=child_body)
                self.assertExit2(self.check(repo, f"{oid}...{child}"), "ambiguous across Git parsers")


def _stitch(lab: _Lab) -> tuple[Path, str, str, str]:
    """main: c0 (no judge) -> c1 (Stop judge); work: c1 -> f1 (weakened) ->
    HEAD. merge-base(c1, HEAD) and HEAD~2 are c1; a parent rewrite of f1 to
    c0 makes both c0, against which the weakened settings file is new: a
    pass."""
    repo = lab.new_repo()
    c0 = lab.commit(repo, {"README": "r\n"}, "c0", 1760000000)
    c1 = lab.commit(repo, {SETTINGS: STOP, "hooks/judge.py": JUDGE}, "c1", 1760000100)
    lab.git(repo, "checkout", "-q", "-b", "work")
    f1 = lab.commit(repo, {SETTINGS: EMPTY}, "weaken", 1760000200)
    lab.commit(repo, {"notes.txt": "n\n"}, "more", 1760000300)
    return repo, c0, c1, f1


def _patch_commit_graph(path: Path, commit: str, *, parent: str | None = None,
                        tree: str | None = None) -> None:
    """Rewrite one commit's first parent or tree id in a commit-graph file."""
    data = bytearray(path.read_bytes())
    rawsz = 20 if data[5] == 1 else 32
    chunks = {}
    for i in range(data[6] + 1):
        entry = 8 + 12 * i
        chunks[bytes(data[entry:entry + 4])] = struct.unpack(">Q", data[entry + 4:entry + 12])[0]
    oidl, cdat = chunks[b"OIDL"], chunks[b"CDAT"]
    oids = [bytes(data[oidl + i * rawsz:oidl + (i + 1) * rawsz]).hex()
            for i in range((cdat - oidl) // rawsz)]
    entry = cdat + oids.index(commit) * (rawsz + 16)
    if tree is not None:
        data[entry:entry + rawsz] = bytes.fromhex(tree)
    if parent is not None:
        data[entry + rawsz:entry + rawsz + 4] = struct.pack(">I", oids.index(parent))
    path.chmod(0o644)
    path.write_bytes(bytes(data))


def _history(lab: _Lab, repo: Path, count: int, rnd: random.Random | None, *,
             window: int, dates: tuple[int, ...],
             files: dict[int, dict[str, str]] | None = None) -> list[str]:
    """count commits on refs/heads/main through one `git fast-import`.

    Commit i takes one to three parents among the window commits before it
    (with rnd; without, only i-1), and a committer date that many seconds
    after commit i-1's (rnd's choice of dates, or dates[0]). files[i] are
    files commit i writes."""
    lines: list[bytes] = []
    stamp = 1760000000
    for i in range(count):
        if rnd is None:
            parents = [i - 1] if i else []
            stamp += dates[0]
        else:
            pool = list(range(max(0, i - window), i))
            parents = rnd.sample(pool, min(rnd.choice((1, 2, 2, 3)), len(pool)))
            stamp += rnd.choice(dates)
        message = b"c%d" % i
        lines.append(b"commit refs/heads/main\nmark :%d\n" % (i + 1))
        lines.append(b"committer t <t@t> %d +0000\ndata %d\n%s\n" % (stamp, len(message), message))
        for n, parent in enumerate(parents):
            lines.append(b"%s :%d\n" % (b"from" if n == 0 else b"merge", parent + 1))
        for path, text in (files or {}).get(i, {}).items():
            data = text.encode("utf-8")
            lines.append(b"M 100644 inline %s\ndata %d\n%s\n" % (path.encode(), len(data), data))
        lines.append(b"\n")
    marks = lab.root / f"{repo.name}.marks"
    lab.git(repo, "fast-import", "--quiet", f"--export-marks={marks}", stdin=b"".join(lines))
    by_mark = dict(line.split() for line in marks.read_text(encoding="ascii").splitlines())
    return [by_mark[f":{i + 1}"] for i in range(count)]


def _unpack(lab: _Lab, repo: Path) -> None:
    """Turn the packs fast-import wrote into loose objects (forge() rewrites
    loose objects only)."""
    pack_dir = repo / ".git" / "objects" / "pack"
    for pack in sorted(pack_dir.glob("*.pack")):
        data = pack.read_bytes()
        for part in pack_dir.glob(pack.stem + ".*"):
            part.chmod(0o644)
            part.unlink()
        lab.git(repo, "unpack-objects", "-q", stdin=data)


if __name__ == "__main__":
    unittest.main()
