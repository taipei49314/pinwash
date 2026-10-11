"""SPEC §2 / §7 (spec 16): ignored surface files in the working tree
are listed in unknown_coverage, names only, verdict unchanged (R21)."""

from __future__ import annotations

import json
import os
import unittest
from unittest import mock

from tests.test_alpha2_git_cli import SETTINGS_PATH, STOP_SETTINGS, _CLIIntegration

REASON = "untracked surface file matched by an ignore rule, not read"
DIR_REASON = "untracked surface files under this directory matched by an ignore rule, not read"
UNREAD_DIR = "untracked surface directory git does not descend (nested repository or symlink), not read"
WIDE_MCP = json.dumps({"mcpServers": {"x": {"command": "x", "autoApprove": ["*"]}}})


class IgnoredSurfaceRouting(_CLIIntegration):
    def _exclude(self, repo, line: str) -> None:
        path = repo / ".git" / "info" / "exclude"
        path.write_text(path.read_text(encoding="utf-8") + line + "\n", encoding="utf-8")

    def test_hidden_mcp_is_listed_and_the_verdict_is_unchanged(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        base = self._git(repo, "rev-parse", "HEAD").stdout.decode().strip()
        self._exclude(repo, ".mcp.json")
        self._write(repo, ".mcp.json", WIDE_MCP)
        for range_arg in (None, f"{base}..WORKTREE"):
            with self.subTest(range_arg=range_arg):
                proc, payload = self._check(repo, range_arg)
                self._assert_exit(proc, payload, 0)
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["unknown_coverage"], [{"path": ".mcp.json", "reason": REASON}])
        committed, committed_payload = self._check(repo, f"{base}..HEAD")
        self._assert_exit(committed, committed_payload, 0)
        self.assertEqual(committed_payload["unknown_coverage"], [])

    def test_unignored_untracked_surface_is_read_not_listed(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        self._write(repo, ".mcp.json", WIDE_MCP)
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 1)
        self.assertEqual(payload["unknown_coverage"], [])

    def test_tracked_file_matching_an_ignore_rule_is_still_read(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        self._write(repo, ".gitignore", ".claude/\n")
        self._commit(repo, "ignore .claude/ after tracking settings")
        self._write(repo, SETTINGS_PATH, json.dumps({"hooks": {}}))
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 1)
        self.assertEqual(payload["unknown_coverage"], [])

    def test_untracking_and_ignoring_a_surface_reads_as_deleted(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        self._git(repo, "rm", "-q", "--cached", SETTINGS_PATH)
        self._exclude(repo, ".claude/")
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 1)
        self.assertEqual(self._findings(payload, "HOOK_REMOVED")[0]["severity"], "critical")
        self.assertEqual(payload["unknown_coverage"], [{"path": SETTINGS_PATH, "reason": REASON}])

    def test_paths_under_ignored_dependency_trees_are_not_listed(self) -> None:
        repo = self._repo({"README.md": "x\n", ".gitignore": "node_modules/\n"})
        self._write(repo, "node_modules/pkg/SKILL.md", "skip tripwire\n")
        self._write(repo, "node_modules/pkg/.mcp.json", WIDE_MCP)
        self._write(repo, "node_modules/pkg/.github/workflows/ci.yml", "on: push\n")
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        self.assertEqual(payload["unknown_coverage"], [])
        self.assertEqual(payload["findings"], [])

    def test_listing_is_sorted_and_limited_to_surface_paths(self) -> None:
        repo = self._repo({"README.md": "x\n"})
        self._exclude(repo, ".claude/")
        self._exclude(repo, ".github/")
        self._exclude(repo, "SKILL.md")
        self._write(repo, ".claude/settings.local.json", "{}")
        self._write(repo, ".claude/hooks/judge.py", "print('block')\n")
        self._write(repo, ".claude/notes.txt", "not a surface\n")
        self._write(repo, ".github/workflows/ci.yml", "on: push\n")
        self._write(repo, ".github/workflows/nested/x.yml", "on: push\n")
        self._write(repo, "SKILL.md", "x\n")
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        self.assertEqual(
            [u["path"] for u in payload["unknown_coverage"]],
            [".claude/hooks/judge.py", ".claude/settings.local.json", ".github/workflows/ci.yml", "SKILL.md"],
        )


    def test_any_ignore_source_lists_the_file(self) -> None:
        # The user-level excludes file is one more ignore source: the file
        # is not read, and it is listed (review of 2026-10-10).
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        xdg = self._temporary_root()
        (xdg / "git").mkdir()
        (xdg / "git" / "ignore").write_text(".mcp.json\n", encoding="utf-8")
        self._write(repo, ".mcp.json", WIDE_MCP)
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg)}):
            proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        self.assertEqual(payload["unknown_coverage"], [{"path": ".mcp.json", "reason": REASON}])

    def test_ignored_trees_below_a_fixed_directory_are_one_row_each(self) -> None:
        # An ignored dependency tree inside `.claude/hooks/` is walked; the
        # files of each directory directly below a fixed surface directory
        # are one row when there are several (review of 2026-10-10).
        repo = self._repo({
            SETTINGS_PATH: STOP_SETTINGS,
            ".claude/hooks/package.json": "{}\n",
            ".gitignore": "node_modules/\n__pycache__/\n*.log\n.claude/*.local.json\n",
        })
        for i in range(40):
            self._write(repo, f".claude/hooks/node_modules/p{i % 4}/f{i}.js", "x\n")
        (repo / ".claude" / "hooks" / "node_modules" / "link").symlink_to("p1")
        self._write(repo, ".claude/hooks/__pycache__/judge.cpython-312.pyc", "x")
        self._write(repo, ".claude/hooks/guard.log", "x\n")
        self._write(repo, ".claude/hooks/logs/1.log", "x\n")
        self._write(repo, ".claude/hooks/logs/2.log", "x\n")
        self._write(repo, ".claude/settings.local.json", "{}")
        self._write(repo, ".cursor/rules/team/a.mdc", "x\n")
        self._exclude(repo, ".cursor/rules/team/")
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        self.assertEqual(payload["unknown_coverage"], [
            {"path": ".claude/hooks/__pycache__/judge.cpython-312.pyc", "reason": REASON},
            {"path": ".claude/hooks/guard.log", "reason": REASON},
            {"path": ".claude/hooks/logs", "reason": DIR_REASON},
            {"path": ".claude/hooks/node_modules", "reason": DIR_REASON},
            {"path": ".claude/settings.local.json", "reason": REASON},
            {"path": ".cursor/rules/team/a.mdc", "reason": REASON},
        ])


class UndescendedSurfaceDirectories(_CLIIntegration):
    """R21 (spec 16, the challenger's amendment): a nested repository or a
    symlink at a fixed surface directory is listed by name, never read."""

    def test_nested_repository_at_a_surface_directory(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        self._write(repo, ".cursor/mcp.json", WIDE_MCP)
        self._git(repo / ".cursor", "init", "-q")
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["unknown_coverage"], [{"path": ".cursor", "reason": UNREAD_DIR}])

    def test_symlinked_surface_directories(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        outside = self._repo({"mcp.json": WIDE_MCP, "settings.json": json.dumps({"autoAccept": True})})
        (repo / ".cursor").symlink_to(outside)
        (repo / ".gemini").symlink_to(outside)
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["unknown_coverage"], [
            {"path": ".cursor", "reason": UNREAD_DIR}, {"path": ".gemini", "reason": UNREAD_DIR}])

    def _exclude(self, repo, line: str) -> None:
        path = repo / ".git" / "info" / "exclude"
        path.write_text(path.read_text(encoding="utf-8") + line + "\n", encoding="utf-8")

    def test_ignored_nested_repositories_and_symlinks_are_listed(self) -> None:
        # Review of 2026-10-10: an ignore rule hid these entirely.
        outside = self._repo({"mcp.json": WIDE_MCP, "settings.json": json.dumps({"autoAccept": True})})
        for name, pattern, expected in (
            ("nested", ".cursor/", ".cursor"),
            ("nested", ".cursor", ".cursor"),
            ("nested", ".claude/", ".claude"),
            ("nested", ".cursor/rules/", ".cursor/rules"),
            ("symlink", ".cursor", ".cursor"),
            ("symlink", ".gemini", ".gemini"),
        ):
            with self.subTest(kind=name, pattern=pattern):
                repo = self._repo({"README.md": "x\n"})
                if name == "nested":
                    self._write(repo, expected + "/mcp.json", WIDE_MCP)
                    self._git(repo / expected, "init", "-q")
                else:
                    (repo / expected).symlink_to(outside)
                self._exclude(repo, pattern)
                proc, payload = self._check(repo)
                self._assert_exit(proc, payload, 0)
                self.assertEqual(payload["unknown_coverage"], [{"path": expected, "reason": UNREAD_DIR}])

    def test_a_plain_ignored_directory_is_not_an_undescended_one(self) -> None:
        for pattern, files, expected in (
            (".cursor/", {".cursor/mcp.json": WIDE_MCP}, [{"path": ".cursor/mcp.json", "reason": REASON}]),
            (".cursor/", {".cursor/notes.txt": "x\n"}, []),
            (".claude/", {".claude/notes.txt": "x\n"}, []),
        ):
            with self.subTest(pattern=pattern, files=sorted(files)):
                repo = self._repo({"README.md": "x\n"})
                for path, content in files.items():
                    self._write(repo, path, content)
                self._exclude(repo, pattern)
                proc, payload = self._check(repo)
                self._assert_exit(proc, payload, 0)
                self.assertEqual(payload["unknown_coverage"], expected)

    def test_entries_below_a_fixed_surface_directory(self) -> None:
        # A nested repository or symlinked directory below a fixed surface
        # directory hides its surfaces the same way, ignored or not; a
        # symlink to a file is read through.
        outside = self._repo({"x/SKILL.md": "skip tripwire\n", "mcp.json": WIDE_MCP})
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        self._write(repo, ".agents/skills/evil/SKILL.md", "skip tripwire\n")
        self._git(repo / ".agents" / "skills" / "evil", "init", "-q")
        (repo / ".agents" / "skills" / "linked").symlink_to(outside / "x")
        (repo / ".claude" / "hooks").mkdir()
        (repo / ".claude" / "hooks" / "lib").symlink_to(outside)
        (repo / ".claude" / "hooks" / "file.json").symlink_to(outside / "mcp.json")
        expected = [
            {"path": ".agents/skills/evil", "reason": UNREAD_DIR},
            {"path": ".agents/skills/linked", "reason": UNREAD_DIR},
            {"path": ".claude/hooks/lib", "reason": UNREAD_DIR},
        ]
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        self.assertEqual(payload["unknown_coverage"], expected)
        self._exclude(repo, ".agents/skills/evil/")
        self._exclude(repo, ".agents/skills/linked")
        self._exclude(repo, ".claude/hooks/lib")
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        self.assertEqual(payload["unknown_coverage"], expected)

    def test_tracked_symlinks_and_gitlinks_are_not_listed(self) -> None:
        # Review of 2026-10-10: the row is for untracked entries; a
        # committed symlink or gitlink at a surface directory is R23.
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        (repo / ".agents").mkdir()
        (repo / ".agents" / "skills").symlink_to("../.claude")
        (repo / ".cursor").mkdir()
        (repo / ".cursor" / "rules").symlink_to("../.claude")
        self._write(repo, ".gemini/settings.json", json.dumps({"autoAccept": True}))
        self._git(repo / ".gemini", "init", "-q")
        self._git(repo / ".gemini", "-c", "user.name=p", "-c", "user.email=p@t", "add", "-A")
        self._git(repo / ".gemini", "-c", "user.name=p", "-c", "user.email=p@t", "commit", "-qm", "inner")
        self._commit(repo, "commit symlinks and a gitlink")
        modes = self._git(repo, "ls-files", "-s").stdout.decode()
        self.assertIn("120000", modes)
        self.assertIn("160000", modes)
        for range_arg in (None, "HEAD~1..WORKTREE", "HEAD~1..HEAD"):
            with self.subTest(range_arg=range_arg):
                proc, payload = self._check(repo, range_arg)
                self._assert_exit(proc, payload, 0)
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["unknown_coverage"], [])

    def test_a_tracked_symlink_chain_is_not_listed(self) -> None:
        # Second review of 2026-10-10: `.claude/hooks` reached through a
        # tracked `.claude` link was listed as untracked.
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS, "impl/hooks/judge.sh": "exit 2\n"})
        self._git(repo, "mv", ".claude", "vendor-claude")
        (repo / "vendor-claude" / "hooks").symlink_to("../impl/hooks")
        (repo / ".claude").symlink_to("vendor-claude")
        self._commit(repo, "link .claude and its hooks")
        self.assertEqual(self._git(repo, "status", "--porcelain").stdout, b"")
        for range_arg in (None, "HEAD..WORKTREE"):
            with self.subTest(range_arg=range_arg):
                proc, payload = self._check(repo, range_arg)
                self._assert_exit(proc, payload, 0)
                self.assertEqual(payload["unknown_coverage"], [])

    def test_an_untracked_symlinked_parent_is_one_row(self) -> None:
        repo = self._repo({"README.md": "x\n"})
        outside = self._repo({"settings.json": "{}", "hooks/judge.sh": "exit 2\n"})
        (repo / ".claude").symlink_to(outside)
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        self.assertEqual(payload["unknown_coverage"], [{"path": ".claude", "reason": UNREAD_DIR}])

    def test_other_untracked_directories_and_committed_ranges_are_not_listed(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        base = self._git(repo, "rev-parse", "HEAD").stdout.decode().strip()
        self._write(repo, "vendor/x.txt", "x\n")
        self._git(repo / "vendor", "init", "-q")
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        self.assertEqual(payload["unknown_coverage"], [])
        self._write(repo, ".claude/hooks/x.py", "print('x')\n")
        self._git(repo / ".claude" / "hooks", "init", "-q")
        committed, committed_payload = self._check(repo, f"{base}..HEAD")
        self._assert_exit(committed, committed_payload, 0)
        self.assertEqual(committed_payload["unknown_coverage"], [])


class CaseFoldedIndexNames(_CLIIntegration):
    """Second review of 2026-10-10: git runs with core.ignoreCase=false, so
    a case-variant decoy in the index cannot hide a new surface file."""

    def test_a_case_variant_decoy_does_not_hide_a_new_surface(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        base = self._git(repo, "rev-parse", "HEAD").stdout.decode().strip()
        self._write(repo, ".cursor/MCP.json", "{}")
        self._git(repo, "add", ".cursor/MCP.json")
        (repo / ".cursor" / "MCP.json").unlink()
        self._git(repo, "config", "core.ignorecase", "true")
        self._write(repo, ".cursor/mcp.json", WIDE_MCP)
        for range_arg in (None, f"{base}..WORKTREE"):
            with self.subTest(range_arg=range_arg):
                proc, payload = self._check(repo, range_arg)
                self._assert_exit(proc, payload, 1)
                self.assertEqual(
                    {f["rule"] for f in payload["findings"]}, {"PERMISSION_WIDENED"})


class UnobservableEntries(unittest.TestCase):
    def test_a_failed_lstat_is_no_symlink(self) -> None:
        # An lstat that fails (a directory the judge cannot open) names no
        # entry; git skips that directory too (R21).
        from pathlib import Path
        from pinwash import gitrepo

        with mock.patch.object(Path, "is_symlink", side_effect=PermissionError(13, "denied")):
            self.assertFalse(gitrepo._symlink(Path("x")))


class SurfacePathspecs(unittest.TestCase):
    def test_the_pathspecs_cover_every_surface_rule(self) -> None:
        from pinwash.gitrepo import SURFACE_PREFIXES
        from pinwash.surfaces import EXACT, is_surface

        for path in EXACT:
            with self.subTest(path=path):
                self.assertIn(path, SURFACE_PREFIXES)
        for sample in (".claude/hooks/a.py", ".github/rulesets/a.json", ".github/workflows/a.yml",
                       ".cursor/rules/a.mdc", ".agents/skills/x/SKILL.md", ".cursor/skills/x/SKILL.md",
                       "SKILL.md"):
            with self.subTest(sample=sample):
                self.assertTrue(is_surface(sample))
                self.assertTrue(any(sample == p or (p.endswith("/") and sample.startswith(p))
                                    for p in SURFACE_PREFIXES))


if __name__ == "__main__":
    unittest.main()
