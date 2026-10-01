"""Alpha 2 integration: real Git trees, worktrees, and the public CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TODAY = "2026-09-30"
SETTINGS_PATH = ".claude/settings.json"
STOP_SETTINGS = json.dumps(
    {"hooks": {"Stop": [{"hooks": [
        {"type": "command", "command": "python hooks/judge.py"}
    ]}]}}
)
EMPTY_SETTINGS = json.dumps({"hooks": {}})
REAL_BODY = (
    "import json\n"
    "from pathlib import Path\n"
    'Path("subject-executed").write_text("executed", encoding="utf-8")\n'
    'print(json.dumps({"decision": "block", "reason": "fixture"}))\n'
)
STUB_BODY = "import sys\nsys.exit(0)\n"
WORKFLOW = (
    "on: push\n"
    "jobs:\n"
    "  ci:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: org/judge@v1.2.3\n"
)


def _environment(
    package_root: Path = ROOT,
    today: str = TODAY,
    overrides: dict[str, str | None] | None = None,
) -> dict[str, str]:
    env = os.environ.copy()
    # Test repos must not inherit another checkout's Git state or hooks.
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["PYTHONPATH"] = str(package_root)
    env["PINWASH_TODAY"] = today
    for key, value in (overrides or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env


class _CLIIntegration(unittest.TestCase):
    def _temporary_root(self) -> Path:
        tmp = tempfile.TemporaryDirectory(prefix="pinwash-alpha2-")
        self.addCleanup(tmp.cleanup)
        return Path(tmp.name)

    def _git(self, repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                "git",
                "-c", "user.name=pinwash",
                "-c", "user.email=pinwash@test",
                "-c", "core.autocrlf=false",
                "-c", "core.eol=lf",
                "-c", "core.quotePath=true",
                "-c", "commit.gpgsign=false",
                *args,
            ],
            cwd=repo,
            env=_environment(),
            capture_output=True,
            check=True,
            timeout=60,
        )

    def _write(self, repo: Path, rel: str, content: str) -> None:
        path = repo.joinpath(*rel.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))

    def _commit(self, repo: Path, message: str) -> None:
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-m", message)

    def _repo(self, files: dict[str, str]) -> Path:
        repo = self._temporary_root()
        self._git(repo, "init", "-b", "main")
        for path, content in files.items():
            self._write(repo, path, content)
        self._commit(repo, "base")
        return repo

    def _cli(
        self,
        repo: Path,
        *args: str,
        package_root: Path = ROOT,
        today: str = TODAY,
        overrides: dict[str, str | None] | None = None,
    ) -> tuple[subprocess.CompletedProcess[bytes], dict]:
        proc = subprocess.run(
            [sys.executable, "-m", "pinwash", *args],
            cwd=repo,
            env=_environment(package_root, today, overrides),
            capture_output=True,
            timeout=60,
        )
        self.assertTrue(proc.stdout, proc.stderr.decode("utf-8", "replace"))
        return proc, json.loads(proc.stdout.decode("utf-8"))

    def _check(
        self, repo: Path, range_arg: str | None = None, *, today: str = TODAY
    ) -> tuple[subprocess.CompletedProcess[bytes], dict]:
        args = ["check"] + ([range_arg] if range_arg is not None else [])
        return self._cli(repo, *args, today=today)

    def _assert_exit(
        self, proc: subprocess.CompletedProcess[bytes], payload: dict, code: int
    ) -> None:
        self.assertEqual(
            proc.returncode,
            code,
            f"{proc.stderr.decode('utf-8', 'replace')} {payload}",
        )

    def _findings(self, payload: dict, rule: str) -> list[dict]:
        return [finding for finding in payload["findings"] if finding["rule"] == rule]

    def _removal_fingerprint(self, repo: Path) -> str:
        self._write(repo, SETTINGS_PATH, EMPTY_SETTINGS)
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 1)
        removed = self._findings(payload, "HOOK_REMOVED")
        self.assertEqual(len(removed), 1, payload)
        return removed[0]["fingerprint"]

    def _allow_record(
        self,
        fingerprint: str,
        *,
        created: str = "2026-09-01",
        expires: str = TODAY,
        rule: str = "HOOK_REMOVED",
    ) -> str:
        return (
            "[[allow]]\n"
            f'fingerprint = "{fingerprint}"\n'
            f'rule = "{rule}"\n'
            'reason = "planned hook migration"\n'
            'author = "integration fixture"\n'
            f'created = "{created}"\n'
            f'expires = "{expires}"\n'
        )

    def _commit_allow(self, repo: Path, record: str) -> None:
        self._write(repo, SETTINGS_PATH, STOP_SETTINGS)
        self._write(repo, ".pinwash/allow.toml", record)
        self._commit(repo, "authorize exact finding at base")
        self._write(repo, SETTINGS_PATH, EMPTY_SETTINGS)


class WorktreeAndRanges(_CLIIntegration):
    def test_raw_unicode_findings_are_identical_across_process_hash_seeds(self) -> None:
        path = ".github/workflows/驗證.yml"
        repo = self._repo({path: WORKFLOW})
        self._write(repo, path, WORKFLOW.replace("@v1.2.3", "@main"))
        self._commit(repo, "float pin for replay")
        first, first_payload = self._cli(
            repo, "check", "HEAD~1..HEAD", overrides={"PYTHONHASHSEED": "1"},
        )
        second, second_payload = self._cli(
            repo, "check", "HEAD~1..HEAD", overrides={"PYTHONHASHSEED": "17"},
        )
        self._assert_exit(first, first_payload, 1)
        self._assert_exit(second, second_payload, 1)
        self.assertEqual(first.stdout, second.stdout)
        self.assertIn("驗證".encode("utf-8"), first.stdout)

    def test_worktree_modified_stop_hook_blocks(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        self._write(repo, SETTINGS_PATH, EMPTY_SETTINGS)
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 1)
        self.assertEqual(payload["run"]["base"], "HEAD")
        self.assertEqual(payload["run"]["head"], "WORKTREE")
        self.assertEqual(self._findings(payload, "HOOK_REMOVED")[0]["severity"], "critical")

    def test_worktree_untracked_skill_is_observed(self) -> None:
        repo = self._repo({"README.md": "base\n"})
        path = "new-skill/SKILL.md"
        self._write(repo, path, "skip tripwire\n")
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        skills = self._findings(payload, "SKILL_BYPASS")
        self.assertEqual([(f["path"], f["severity"]) for f in skills], [(path, "warn")])

    def test_worktree_deleted_stop_settings_blocks(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        (repo / SETTINGS_PATH).unlink()
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 1)
        self.assertEqual(self._findings(payload, "HOOK_REMOVED")[0]["severity"], "critical")

    def test_three_dot_uses_merge_base_instead_of_left_tree(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        self._git(repo, "branch", "topic")
        self._write(repo, SETTINGS_PATH, EMPTY_SETTINGS)
        self._commit(repo, "left branch removes Stop")
        self._git(repo, "checkout", "topic")
        self._write(repo, SETTINGS_PATH, EMPTY_SETTINGS)
        self._write(repo, "README.md", "independent topic change\n")
        self._commit(repo, "topic branch removes Stop")

        two_proc, two_payload = self._check(repo, "main..topic")
        self._assert_exit(two_proc, two_payload, 0)
        self.assertEqual(two_payload["findings"], [])
        three_proc, three_payload = self._check(repo, "main...topic")
        self._assert_exit(three_proc, three_payload, 1)
        self.assertEqual(
            self._findings(three_payload, "HOOK_REMOVED")[0]["severity"], "critical"
        )

    def test_unicode_workflow_path_is_loaded_from_committed_trees(self) -> None:
        path = ".github/workflows/驗證.yml"
        repo = self._repo({path: WORKFLOW})
        self._write(repo, path, WORKFLOW.replace("@v1.2.3", "@main"))
        self._commit(repo, "float Unicode-named workflow pin")
        proc, payload = self._check(repo, "HEAD~1..HEAD")
        self._assert_exit(proc, payload, 1)
        self.assertEqual(self._findings(payload, "JUDGE_UNPINNED")[0]["path"], path)

    def test_unicode_untracked_skill_path_is_loaded_from_worktree(self) -> None:
        repo = self._repo({"README.md": "base\n"})
        path = "能力/SKILL.md"
        self._write(repo, path, "skip tripwire\n")
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        self.assertEqual(self._findings(payload, "SKILL_BYPASS")[0]["path"], path)

    def test_leading_space_in_skill_path_is_preserved(self) -> None:
        path = " skills/SKILL.md"
        repo = self._repo({path: "ordinary guidance\n"})
        self._write(repo, path, "ordinary guidance\nskip tripwire\n")
        work_proc, work_payload = self._check(repo)
        self._assert_exit(work_proc, work_payload, 0)
        self.assertEqual(self._findings(work_payload, "SKILL_BYPASS")[0]["path"], path)
        self._commit(repo, "edit space-prefixed path")
        tree_proc, tree_payload = self._check(repo, "HEAD~1..HEAD")
        self._assert_exit(tree_proc, tree_payload, 0)
        self.assertEqual(self._findings(tree_payload, "SKILL_BYPASS")[0]["path"], path)


class ExemptionsThroughCLI(_CLIIntegration):
    def test_head_only_exact_exemption_cannot_hide_current_finding(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        fingerprint = self._removal_fingerprint(repo)
        self._write(repo, ".pinwash/allow.toml", self._allow_record(fingerprint))
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 1)
        self.assertEqual(self._findings(payload, "HOOK_REMOVED")[0]["fingerprint"], fingerprint)
        self.assertEqual(self._findings(payload, "EXEMPTION_ADDED")[0]["severity"], "warn")

    def test_base_exact_fingerprint_exemption_suppresses_finding(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        fingerprint = self._removal_fingerprint(repo)
        self._commit_allow(repo, self._allow_record(fingerprint))
        proc, payload = self._check(repo)
        self._assert_exit(proc, payload, 0)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["config_errors"], [])

    def test_base_exemption_requires_matching_rule_and_fingerprint(self) -> None:
        for mismatch in ("fingerprint", "rule"):
            with self.subTest(mismatch=mismatch):
                repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
                fingerprint = self._removal_fingerprint(repo)
                record = self._allow_record(
                    fingerprint if mismatch == "rule" else fingerprint[:-1] + (
                        "0" if fingerprint[-1] != "0" else "1"
                    ),
                    rule="GATE_STUBBED" if mismatch == "rule" else "HOOK_REMOVED",
                )
                self._commit_allow(repo, record)
                proc, payload = self._check(repo)
                self._assert_exit(proc, payload, 1)
                self.assertEqual(
                    self._findings(payload, "HOOK_REMOVED")[0]["fingerprint"], fingerprint
                )

    def test_exemption_is_valid_on_expiry_date_and_invalid_next_day(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
        fingerprint = self._removal_fingerprint(repo)
        self._commit_allow(repo, self._allow_record(fingerprint))
        on_proc, on_payload = self._check(repo, today=TODAY)
        self._assert_exit(on_proc, on_payload, 0)
        self.assertEqual(on_payload["findings"], [])
        after_proc, after_payload = self._check(repo, today="2026-10-01")
        self._assert_exit(after_proc, after_payload, 1)
        self.assertEqual(
            self._findings(after_payload, "HOOK_REMOVED")[0]["fingerprint"], fingerprint
        )

    def test_exemption_duration_allows_180_days_but_rejects_181(self) -> None:
        for duration, exit_code in ((180, 0), (181, 1)):
            with self.subTest(duration=duration):
                repo = self._repo({SETTINGS_PATH: STOP_SETTINGS})
                fingerprint = self._removal_fingerprint(repo)
                created = (date.fromisoformat(TODAY) - timedelta(days=duration)).isoformat()
                self._commit_allow(repo, self._allow_record(fingerprint, created=created))
                proc, payload = self._check(repo)
                self._assert_exit(proc, payload, exit_code)
                removed = self._findings(payload, "HOOK_REMOVED")
                self.assertEqual(len(removed), 0 if duration == 180 else 1, payload)


class HookBodyIntegration(_CLIIntegration):
    def test_resolved_hook_body_stub_blocks_from_worktree_and_commits(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS, "hooks/judge.py": REAL_BODY})
        self._write(repo, "hooks/judge.py", STUB_BODY)
        work_proc, work_payload = self._check(repo)
        self._assert_exit(work_proc, work_payload, 1)
        self.assertEqual(self._findings(work_payload, "GATE_STUBBED")[0]["severity"], "critical")
        self._commit(repo, "stub resolved hook body")
        tree_proc, tree_payload = self._check(repo, "HEAD~1..HEAD")
        self._assert_exit(tree_proc, tree_payload, 1)
        self.assertEqual(self._findings(tree_payload, "GATE_STUBBED")[0]["severity"], "critical")
        self.assertFalse((repo / "subject-executed").exists())

    def test_benign_hook_body_edit_stays_silent_and_subject_is_not_executed(self) -> None:
        repo = self._repo({SETTINGS_PATH: STOP_SETTINGS, "hooks/judge.py": REAL_BODY})
        self._write(repo, "hooks/judge.py", REAL_BODY.replace('"fixture"', '"updated reason"'))
        work_proc, work_payload = self._check(repo)
        self._assert_exit(work_proc, work_payload, 0)
        self.assertEqual(work_payload["findings"], [])
        self._commit(repo, "change hook reason")
        tree_proc, tree_payload = self._check(repo, "HEAD~1..HEAD")
        self._assert_exit(tree_proc, tree_payload, 0)
        self.assertEqual(tree_payload["findings"], [])
        self.assertFalse((repo / "subject-executed").exists())


class DoctorAvailability(_CLIIntegration):
    def test_empty_or_skipped_own_suite_is_not_a_successful_self_test(self) -> None:
        for skip_suite in (False, True):
            with self.subTest(skip_suite=skip_suite):
                root = self._temporary_root()
                shutil.copytree(ROOT / "pinwash", root / "pinwash",
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
                shutil.copyfile(ROOT / "SPEC.md", root / "SPEC.md")
                (root / "tests").mkdir()
                (root / "tests" / "__init__.py").write_text("", encoding="utf-8")
                if skip_suite:
                    (root / "tests" / "test_skipped.py").write_text(
                        "import unittest\n"
                        "class Skipped(unittest.TestCase):\n"
                        "    @unittest.skip('fixture')\n"
                        "    def test_not_run(self):\n"
                        "        self.fail('must not execute')\n",
                        encoding="utf-8",
                    )
                proc, payload = self._cli(
                    root, "doctor", package_root=root,
                    overrides={"PINWASH_DOCTOR_SELFTEST": None},
                )
                self._assert_exit(proc, payload, 2)
                self.assertIs(payload["self_tests"]["available"], True)
                self.assertIs(payload["self_tests"]["ok"], False)
                self.assertEqual(payload["self_tests"]["tests_run"], 1 if skip_suite else 0)
                self.assertEqual(payload["self_tests"]["skipped_count"], 1 if skip_suite else 0)

    def test_missing_own_tests_reports_unavailable_and_exit_two(self) -> None:
        root = self._temporary_root()
        shutil.copytree(ROOT / "pinwash", root / "pinwash",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copyfile(ROOT / "SPEC.md", root / "SPEC.md")
        for guard in (None, "1"):
            with self.subTest(nested_guard=guard):
                proc, payload = self._cli(
                    root, "doctor", package_root=root,
                    overrides={"PINWASH_DOCTOR_SELFTEST": guard},
                )
                self._assert_exit(proc, payload, 2)
                self.assertIs(payload["self_tests"]["available"], False)
                self.assertIs(payload["self_tests"]["ok"], False)
                self.assertEqual(payload["self_tests"]["tests_run"], 0)
                self.assertIs(payload["subject_judged"], False)
                self.assertEqual(len(payload["spec_sha256"]), 64)

    def _fake_package(self, test_body: str) -> Path:
        root = self._temporary_root()
        shutil.copytree(ROOT / "pinwash", root / "pinwash",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copyfile(ROOT / "SPEC.md", root / "SPEC.md")
        (root / "tests").mkdir()
        (root / "tests" / "__init__.py").write_text("", encoding="utf-8")
        (root / "tests" / "test_fixture.py").write_text(test_body, encoding="utf-8")
        return root

    def test_preset_guard_still_runs_and_judges_own_tests(self) -> None:
        """#3: a preset guard is a nested run of real tests, never a free pass."""
        suites = (
            ("passing", "self.assertTrue(True)", 0, True, 0),
            ("failing", "self.fail('fixture')", 2, False, 1),
        )
        for guard in ("1", "0", "yes"):
            for label, body, code, ok, failures in suites:
                with self.subTest(guard=guard, suite=label):
                    root = self._fake_package(
                        "import unittest\n"
                        "class Fixture(unittest.TestCase):\n"
                        "    def test_fixture(self):\n"
                        f"        {body}\n"
                    )
                    proc, payload = self._cli(
                        root, "doctor", package_root=root,
                        overrides={"PINWASH_DOCTOR_SELFTEST": guard},
                    )
                    self._assert_exit(proc, payload, code)
                    tests = payload["self_tests"]
                    self.assertIs(tests["available"], True)
                    self.assertIs(tests["ok"], ok)
                    self.assertEqual(tests["tests_run"], 1)
                    self.assertEqual(tests["failures"], failures)
                    self.assertEqual(tests["nested_depth"], 1)
                    self.assertEqual(tests["excluded"], [])
                    self.assertNotIn("skipped", tests)
                    self.assertIs(payload["subject_judged"], False)

    def test_deeper_nesting_is_refused_not_passed(self) -> None:
        root = self._fake_package(
            "import unittest\n"
            "class Fixture(unittest.TestCase):\n"
            "    def test_fixture(self):\n"
            "        self.assertTrue(True)\n"
        )
        for guard in ("2", "17"):
            with self.subTest(guard=guard):
                proc, payload = self._cli(
                    root, "doctor", package_root=root,
                    overrides={"PINWASH_DOCTOR_SELFTEST": guard},
                )
                self._assert_exit(proc, payload, 2)
                tests = payload["self_tests"]
                self.assertIs(tests["ok"], False)
                self.assertEqual(tests["tests_run"], 0)
                self.assertEqual(tests["nested_depth"], int(guard))
                self.assertIn("refused", tests)

    def test_expected_failure_is_not_a_passing_own_test(self) -> None:
        root = self._fake_package(
            "import unittest\n"
            "class Fixture(unittest.TestCase):\n"
            "    @unittest.expectedFailure\n"
            "    def test_fixture(self):\n"
            "        self.fail('fixture')\n"
        )
        proc, payload = self._cli(
            root, "doctor", package_root=root,
            overrides={"PINWASH_DOCTOR_SELFTEST": None},
        )
        self._assert_exit(proc, payload, 2)
        tests = payload["self_tests"]
        self.assertIs(tests["ok"], False)
        self.assertEqual(tests["tests_run"], 1)
        self.assertEqual(tests["expected_failures"], 1)
        self.assertEqual(tests["nested_depth"], 0)
        self.assertNotIn("excluded", tests)


class DoctorNestedExclusion(unittest.TestCase):
    def test_nested_run_drops_exactly_the_doctor_spawning_gate(self) -> None:
        """#3: the nested suite differs from the full one by the spawner only."""
        from pinwash import cli

        suite = unittest.defaultTestLoader.loadTestsFromName(
            "tests.gates.test_v0_acceptance"
        )
        full = [test.id() for test in cli._flatten(suite)]
        kept_suite, excluded = cli._without_nested_spawners(suite)
        kept = [test.id() for test in cli._flatten(kept_suite)]
        self.assertEqual(excluded, sorted(cli._NESTED_EXCLUDED))
        self.assertEqual(sorted(kept + excluded), sorted(full))
        self.assertEqual(len(kept), len(full) - len(excluded))


if __name__ == "__main__":
    unittest.main()
