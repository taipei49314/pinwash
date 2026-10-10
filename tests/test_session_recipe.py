"""SPEC §2 / §13: the WORKTREE range token and the session recipe (#17 S4)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from tests.test_alpha2_git_cli import (
    EMPTY_SETTINGS,
    ROOT,
    SETTINGS_PATH,
    STOP_SETTINGS,
    TODAY,
    _CLIIntegration,
    _environment,
)

RULESET_PATH = ".github/required-ruleset.json"
WORKFLOW_PATH = ".github/workflows/ci.yml"


def _ruleset(*contexts: str) -> str:
    return json.dumps(
        {"rules": [{"type": "required_status_checks", "parameters": {
            "required_status_checks": [{"context": c} for c in contexts]}}]}
    )


TWO_JOBS = (
    "on:\n  push:\n  pull_request:\njobs:\n"
    "  unit:\n    name: unit\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n"
    "  lint:\n    name: lint\n    runs-on: ubuntu-latest\n    steps:\n      - run: make lint\n"
)
ONE_JOB = TWO_JOBS.split("  lint:\n")[0]


class WorktreeRangeToken(_CLIIntegration):
    def _raw(self, repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [sys.executable, "-m", "pinwash", "check", *args],
            cwd=repo,
            env=_environment(ROOT, TODAY),
            capture_output=True,
            timeout=60,
        )

    def _rev(self, repo: Path, rev: str = "HEAD") -> str:
        return self._git(repo, "rev-parse", rev).stdout.decode("ascii").strip()

    def _session_plant(self) -> tuple[Path, str]:
        """#17 S4: the session commits a record, leaves the weakening uncommitted."""
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        base = self._rev(repo)
        fingerprint = self._removal_fingerprint(repo)
        self._commit_allow(repo, self._allow_record(fingerprint))
        return repo, base

    def test_base_to_worktree_reads_the_allowlist_from_base(self) -> None:
        repo, base = self._session_plant()
        committed, committed_payload = self._check(repo, f"{base}..HEAD")
        self._assert_exit(committed, committed_payload, 0)
        self.assertEqual(
            [(f["rule"], f["severity"]) for f in committed_payload["findings"]],
            [("EXEMPTION_ADDED", "warn")],
        )
        # Plain check compares against HEAD and reads HEAD's allowlist: R18.
        plain, plain_payload = self._check(repo)
        self._assert_exit(plain, plain_payload, 0)
        self.assertEqual(plain_payload["findings"], [])
        pinned, pinned_payload = self._check(repo, f"{base}..WORKTREE")
        self._assert_exit(pinned, pinned_payload, 1)
        self.assertEqual(pinned_payload["run"]["head"], "WORKTREE")
        self.assertEqual(
            sorted((f["rule"], f["severity"]) for f in pinned_payload["findings"]),
            [("EXEMPTION_ADDED", "warn"), ("HOOK_REMOVED", "critical")],
        )

    def test_head_to_worktree_is_check_without_a_range(self) -> None:
        repo, _base = self._session_plant()
        self.assertEqual(self._raw(repo).stdout, self._raw(repo, "HEAD..WORKTREE").stdout)

    def test_worktree_is_never_a_base(self) -> None:
        repo, base = self._session_plant()
        for range_arg in (
            "WORKTREE..HEAD",
            f"WORKTREE..{base}",
            "WORKTREE..WORKTREE",
            f"{base}...WORKTREE",
            "WORKTREE...HEAD",
            "WORKTREE",
        ):
            with self.subTest(range_arg=range_arg):
                proc = self._raw(repo, range_arg)
                self.assertEqual(proc.returncode, 2, proc.stdout)
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr, b"pinwash: invalid range\n")

    def test_a_ref_named_worktree_is_spelled_in_full(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        base = self._rev(repo)
        self._git(repo, "checkout", "-q", "-b", "WORKTREE")
        self._write(repo, SETTINGS_PATH, EMPTY_SETTINGS)
        self._commit(repo, "weaken on a branch named WORKTREE")
        self._git(repo, "checkout", "-q", "main")
        token, token_payload = self._check(repo, f"{base}..WORKTREE")
        self._assert_exit(token, token_payload, 0)
        self.assertEqual(token_payload["findings"], [])
        ref, ref_payload = self._check(repo, f"{base}..refs/heads/WORKTREE")
        self._assert_exit(ref, ref_payload, 1)
        # With the ref present a three-dot range naming WORKTREE is invalid
        # too (it resolved the ref before spec 16); the full name works.
        for range_arg in (f"{base}...WORKTREE", "WORKTREE...main"):
            with self.subTest(range_arg=range_arg):
                proc = self._raw(repo, range_arg)
                self.assertEqual(proc.returncode, 2, proc.stdout)
                self.assertEqual(proc.stderr, b"pinwash: invalid range\n")
        full, full_payload = self._check(repo, f"{base}...refs/heads/WORKTREE")
        self._assert_exit(full, full_payload, 1)

    def test_required_check_split_across_commit_and_worktree(self) -> None:
        # The commit drops a ruleset context (ruleset side, warn); the
        # worktree deletes its producer, which HEAD no longer requires.
        repo = self._repo({RULESET_PATH: _ruleset("unit", "lint"), WORKFLOW_PATH: TWO_JOBS})
        base = self._rev(repo)
        self._write(repo, RULESET_PATH, _ruleset("unit"))
        self._commit(repo, "drop lint from the ruleset")
        self._write(repo, WORKFLOW_PATH, ONE_JOB)
        committed, committed_payload = self._check(repo, f"{base}..HEAD")
        self._assert_exit(committed, committed_payload, 0)
        plain, plain_payload = self._check(repo)
        self._assert_exit(plain, plain_payload, 0)
        self.assertEqual(plain_payload["findings"], [])
        pinned, pinned_payload = self._check(repo, f"{base}..WORKTREE")
        self._assert_exit(pinned, pinned_payload, 1)
        self.assertIn(
            ("REQUIRED_CHECK_DROPPED", "high"),
            [(f["rule"], f["severity"]) for f in pinned_payload["findings"]],
        )


if __name__ == "__main__":
    unittest.main()
