"""Consumer contracts: baseline custody, real session diffs and honest reporting."""
from __future__ import annotations

import json
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pinwash.consumer import ConsumerError, _inspect, collect, invoke, summarize, validate_result
from pinwash.findings import envelope, make_finding
from pinwash.report import render
from pinwash.session import _read, _write
from tests.test_alpha2_git_cli import _CLIIntegration, _environment, STOP_SETTINGS, EMPTY_SETTINGS, REAL_BODY, SETTINGS_PATH


class SessionIntegration(_CLIIntegration):
    def _cli(self, repo, *args):
        # The consumer's own launcher is trusted too; do not let this test
        # helper import a fixture's json.py before the consumer starts.
        proc = subprocess.run([sys.executable, "-P", "-B", "-m", "pinwash", *args],
                              cwd=repo, env=_environment(), capture_output=True, timeout=60)
        self.assertTrue(proc.stdout, proc.stderr.decode("utf-8", "replace"))
        return proc, json.loads(proc.stdout)

    def setUp(self):
        self.repo = self._repo({SETTINGS_PATH: STOP_SETTINGS, "hooks/judge.py": REAL_BODY})
        self.state_dir = self._temporary_root() / "state"

    def command(self, action, *args, repo=None):
        return self._cli(repo or self.repo, "session", action, "--json", "--state-dir", str(self.state_dir), *args)

    def test_two_step_honest_session_and_repeated_review(self):
        proc, state = self.command("start")
        self.assertEqual(proc.returncode, 0, state)
        self.assertEqual(len(state["base"]), 40)
        self._write(self.repo, "README.md", "ordinary product work\n")
        proc, report = self.command("review", "--stopped")
        self.assertEqual(proc.returncode, 0, report)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(len(report["runs"]), 3)
        self.assertTrue(report["execution_complete"])
        self.assertEqual(json.loads(Path(report["report_path"]).read_text()), report)
        self.assertFalse(Path(report["report_path"]).is_relative_to(self.repo))
        proc, second = self.command("review", "--stopped")
        self.assertEqual(proc.returncode, 0, second)
        self.assertNotEqual(second["report_path"], report["report_path"])

    def test_commit_does_not_move_original_baseline(self):
        _, state = self.command("start")
        self._write(self.repo, SETTINGS_PATH, EMPTY_SETTINGS)
        self._commit(self.repo, "remove guard")
        proc, report = self.command("review", "--stopped")
        self.assertEqual(proc.returncode, 1, report)
        self.assertEqual(report["base"], state["base"])
        self.assertNotEqual(report["head"], state["base"])
        self.assertTrue(any(f["rule"] == "HOOK_REMOVED" for f in report["findings"]))
        self.assertFalse((self.repo / "subject-executed").exists())

    def test_uncommitted_guard_removal_is_reported_once_with_provenance(self):
        self.command("start")
        self._write(self.repo, SETTINGS_PATH, EMPTY_SETTINGS)
        proc, report = self.command("review", "--stopped")
        self.assertEqual(proc.returncode, 1, report)
        hooks = [f for f in report["findings"] if f["rule"] == "HOOK_REMOVED"]
        self.assertEqual(len(hooks), 1)
        self.assertEqual(len(hooks[0]["observations"]), 2)

    def test_start_rejects_existing_edits_without_stashing(self):
        self._write(self.repo, "existing.txt", "do not lose\n")
        proc, report = self.command("start")
        self.assertEqual(proc.returncode, 2, report)
        self.assertIn("clean worktree", " ".join(report["errors"]))
        self.assertEqual((self.repo / "existing.txt").read_text(), "do not lose\n")
        self.assertFalse(self.state_dir.exists())

    def test_crlf_checkout_is_ready_without_executing_clean_filters(self):
        self._write(self.repo, "tracked.txt", "one\ntwo\n")
        self._commit(self.repo, "text baseline")
        (self.repo / "tracked.txt").write_bytes(b"one\r\ntwo\r\n")
        proc, state = self.command("start")
        self.assertEqual(proc.returncode, 0, state)

    def test_corrupt_state_does_not_fall_back_to_current_head(self):
        _, state = self.command("start")
        Path(state["state_path"]).write_text('{"schema_version":1,"schema_version":1}')
        proc, report = self.command("review", "--stopped")
        self.assertEqual(proc.returncode, 2, report)
        self.assertIn("No fallback", " ".join(report["errors"]))

    def test_duplicate_start_does_not_erase_baseline(self):
        _, first = self.command("start")
        self._write(self.repo, "README.md", "next\n")
        self._commit(self.repo, "next")
        proc, report = self.command("start")
        self.assertEqual(proc.returncode, 2, report)
        self.assertEqual(json.loads(Path(first["state_path"]).read_text())["base"], first["base"])
        proc, second = self.command("start", "--replace")
        self.assertEqual(proc.returncode, 0, second)
        self.assertNotEqual(first["base"], second["base"])
        self.assertTrue((self.state_dir / "sessions" / f"{first['id']}.json").is_file())

    def test_subdirectory_reviews_root_settings(self):
        directory = self.repo / "src"
        directory.mkdir()
        proc, state = self.command("start", repo=directory)
        self.assertEqual(proc.returncode, 0, state)
        self.assertEqual(Path(state["repo"]), self.repo.resolve())
        self._write(self.repo, SETTINGS_PATH, EMPTY_SETTINGS)
        proc, report = self.command("review", "--stopped", repo=directory)
        self.assertEqual(proc.returncode, 1, report)

    def test_missing_baseline_and_missing_attestation_are_not_passes(self):
        proc, report = self.command("review", "--stopped")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(report["status"], "not_judged")
        self.command("start")
        proc, report = self.command("review")
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(report["execution_complete"])

    def test_changed_judge_is_rejected_without_resetting_base(self):
        _, state = self.command("start")
        path = Path(state["state_path"])
        saved = json.loads(path.read_text())
        saved["judge"]["source_sha256"] = "0" * 64
        path.write_text(json.dumps(saved))
        proc, report = self.command("review", "--stopped")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("PinWash changed", " ".join(report["errors"]))
        self.assertEqual(json.loads(path.read_text())["base"], state["base"])

    def test_state_inside_subject_is_rejected(self):
        proc, report = self._cli(self.repo, "session", "start", "--json", "--state-dir", str(self.repo / ".pinwash" / "state"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("outside", " ".join(report["errors"]))

    def test_unknown_coverage_remains_visible(self):
        self._write(self.repo, ".gitignore", ".claude/*.local.json\n")
        self._commit(self.repo, "ignore local config")
        self.command("start")
        self._write(self.repo, ".claude/settings.local.json", "{}")
        proc, report = self.command("review", "--stopped")
        self.assertEqual(proc.returncode, 0, report)
        self.assertTrue(report["unknown_coverage"])
        text = render(report)
        self.assertIn("Not assessed (these are not passes)", text)
        self.assertIn(".claude/settings.local.json", text)

    def test_added_exemption_is_held_even_when_engine_exits_zero(self):
        self.command("start")
        self._write(self.repo, ".pinwash/allow.toml", '\n'.join([
            '[[allow]]', 'fingerprint = "HOOK_REMOVED/.claude/settings.json/v1:' + 'a' * 64 + '"',
            'rule = "HOOK_REMOVED"', 'reason = "planned migration"', 'author = "reviewer"',
            'created = "2026-09-30"', 'expires = "2026-10-01"', '',
        ]))
        proc, report = self.command("review", "--stopped")
        self.assertEqual(proc.returncode, 3, report)
        self.assertEqual(report["status"], "held")
        self.assertTrue(all(run["exit_code"] == 0 for run in report["runs"]))

    def test_repository_python_shadow_is_not_executed(self):
        self.command("start")
        self._write(self.repo, "json.py", "raise RuntimeError('subject imported')\n")
        self._write(self.repo, SETTINGS_PATH, EMPTY_SETTINGS)
        proc, report = self.command("review", "--stopped")
        self.assertEqual(proc.returncode, 1, report)

    def test_one_diff_report_and_check_json_remain_distinct(self):
        self._write(self.repo, SETTINGS_PATH, EMPTY_SETTINGS)
        proc, original = self._cli(self.repo, "check")
        self.assertEqual(proc.returncode, 1)
        proc, report = self._cli(self.repo, "review", "--json")
        self.assertEqual(proc.returncode, 1, report)
        self.assertEqual(report["runs"][0]["payload"], original)
        self.assertNotIn("consumer_schema_version", original)

    def test_status_from_subdirectory_keeps_baseline_and_historical_result(self):
        proc, state = self.command("start")
        self.assertEqual(proc.returncode, 0, state)
        _, saved = self.command("review", "--stopped")
        self._write(self.repo, SETTINGS_PATH, EMPTY_SETTINGS)
        directory = self.repo / "src"
        directory.mkdir()
        before = Path(state["state_path"]).read_bytes()
        proc, result = self.command("status", repo=directory)
        self.assertEqual(proc.returncode, 0, result)
        self.assertEqual(result["repo"], str(self.repo.resolve()))
        self.assertEqual(result["session"]["base"], state["base"])
        self.assertEqual(result["latest_review"]["report_path"], saved["report_path"])
        self.assertEqual(result["latest_review"]["status"], "pass")
        self.assertEqual(result["current_changes"], "not_reviewed")
        self.assertEqual(Path(state["state_path"]).read_bytes(), before)
        proc, reviewed = self.command("review", "--stopped")
        self.assertEqual(proc.returncode, 1, reviewed)
        proc, result = self.command("status")
        self.assertEqual(proc.returncode, 0, result)
        self.assertEqual(result["latest_review"]["status"], "block")

    def test_status_without_session_does_not_initialize_or_import_subject(self):
        self._write(self.repo, "json.py", "raise RuntimeError('subject imported')\n")
        proc, result = self.command("status")
        self.assertEqual(proc.returncode, 0, result)
        self.assertEqual(result["status"], "no_session")
        self.assertFalse(self.state_dir.exists())


class ReportContracts(unittest.TestCase):
    def result(self, findings=None, unknown=None):
        return envelope(base_label="a", head_label="b", findings=findings or [],
                        config_errors=[], unknown_coverage=unknown or [])

    def finding(self, severity="high"):
        return make_finding(rule="HOOK_REMOVED", severity=severity, path=".claude/settings.json",
                            message="hook removed", before="run judge", after="")

    def test_partial_failure_keeps_block_and_exits_engine_error(self):
        report = summarize([{"range": "a..b", "exit_code": 1, "payload": self.result([self.finding()])},
                            {"range": "a..WORKTREE", "exit_code": 2, "error": "timed out"}])
        self.assertEqual(report["status"], "block")
        self.assertEqual(report["exit_code"], 2)
        self.assertFalse(report["execution_complete"])
        self.assertEqual(len(report["findings"]), 1)

    def test_dedup_uses_highest_severity_and_preserves_both_observations(self):
        report = summarize([{"range": "a..b", "exit_code": 0, "payload": self.result([self.finding("warn")])},
                            {"range": "a..c", "exit_code": 1, "payload": self.result([self.finding("critical")])}])
        self.assertEqual(report["findings"][0]["severity"], "critical")
        self.assertEqual([x["severity"] for x in report["findings"][0]["observations"]], ["warn", "critical"])

    def test_terminal_controls_are_escaped(self):
        finding = self.finding()
        finding.update(path="evil\x1b[2J\u202e.txt", before="x\nFAKE PASS\r")
        report = summarize([{"range": "a..b", "exit_code": 1, "payload": self.result([finding])}])
        text = render(report)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertIn("\\u001b", text)
        self.assertIn("\\u000a", text)

    def test_invalid_json_and_timeout_are_not_success(self):
        with patch("pinwash.consumer.invoke", side_effect=ConsumerError("invalid JSON")):
            report = summarize(collect(Path("."), ["a..b", "a..WORKTREE"], 1))
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["status"], "not_judged")

    def test_inconsistent_engine_status_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_result(self.result(), 1)

    def test_malformed_nested_shapes_are_rejected(self):
        for key, value in (("run", None), ("findings", [None]), ("unknown_coverage", [None])):
            payload = self.result()
            payload[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_result(payload, 0)

    def test_child_timeout_is_a_consumer_error(self):
        with patch("pinwash.consumer.subprocess.run", side_effect=subprocess.TimeoutExpired("judge", 1)):
            with self.assertRaisesRegex(ConsumerError, "not judged"):
                invoke(Path.cwd(), "check", None, 1)

    def test_fixed_identity_update_is_not_called_a_weaker_pin(self):
        finding = self.finding("warn")
        finding.update(rule="JUDGE_UNPINNED", message="declared pin judge value changed")
        text = render(summarize([{"range": "a..b", "exit_code": 0, "payload": self.result([finding])}]))
        self.assertIn("pin changed", text)
        self.assertNotIn("less tightly", text)


class InstalledDoctorRouting(unittest.TestCase):
    def test_own_bundle_wins_over_unrelated_parent_spec(self):
        from pinwash import cli
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "pinwash"
            (package / "_verification").mkdir(parents=True)
            (root / "SPEC.md").write_text("unrelated distribution")
            with patch.object(cli, "__file__", str(package / "cli.py")), patch("pinwash.verification.installed_doctor", return_value=2) as bundled:
                self.assertEqual(cli.doctor(), 2)
                bundled.assert_called_once_with(package)

    def test_missing_installed_resources_fail_closed(self):
        from pinwash.verification import installed_doctor
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "pinwash"
            package.mkdir()
            with patch("pinwash.verification.subprocess.run") as child:
                self.assertEqual(installed_doctor(package), 2)
                child.assert_not_called()


class LateConsumerFailures(unittest.TestCase):
    def setUp(self):
        self.root = Path.cwd().resolve()
        self.judge = {"source_sha256": "a" * 64}
        self.observation = {"repo": str(self.root), "head": "b" * 40, "tree_digest": "c" * 64}
        self.finding = make_finding(rule="HOOK_REMOVED", severity="high", path=".claude/settings.json",
                                    message="hook removed", before="run judge", after="")
        payload = envelope(base_label="a", head_label="b", findings=[self.finding],
                           config_errors=[], unknown_coverage=[])
        self.runs = [{"range": "a..b", "exit_code": 1, "payload": payload}]
        self.state = {"id": "d" * 32, "repo": str(self.root), "base": "e" * 40, "judge": self.judge}

    def command(self, args):
        from pinwash import human_cli
        output = io.BytesIO()
        stdout = io.TextIOWrapper(output, encoding="utf-8")
        with patch("pinwash.human_cli.sys.stdout", stdout):
            code = human_cli.main(args)
            report = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["status"], "block")
        self.assertFalse(report["execution_complete"])
        self.assertEqual(report["runs"], self.runs)
        self.assertEqual(report["findings"][0]["fingerprint"], self.finding["fingerprint"])
        return report

    def test_single_diff_late_inspection_failure_keeps_completed_block(self):
        for error in (ConsumerError("final inspection timed out"), OSError("final inspection unreadable")):
            with self.subTest(error=type(error).__name__), \
                    patch("pinwash.human_cli.inspect", side_effect=[self.observation, error]), \
                    patch("pinwash.human_cli.identity", return_value=self.judge), \
                    patch("pinwash.human_cli.collect", return_value=self.runs):
                report = self.command(["review", "--json"])
                self.assertEqual(report["judge"], self.judge)
                self.assertIn(str(error), report["errors"])

    def test_session_failed_save_keeps_completed_runs_without_saved_path(self):
        self.runs = self.runs * 3
        for error in (OSError("disk full"), ConsumerError("report publication failed")):
            with self.subTest(error=type(error).__name__), \
                    patch("pinwash.session.inspect", return_value=self.observation), \
                    patch("pinwash.session.identity", return_value=self.judge), \
                    patch("pinwash.session._paths", return_value=(self.root.parent / "state", self.root.parent / "active.json")), \
                    patch("pinwash.session._read", return_value=self.state), \
                    patch("pinwash.session.collect", return_value=self.runs), \
                    patch("pinwash.session._write", side_effect=error):
                report = self.command(["session", "review", "--stopped", "--json"])
                self.assertNotIn("report_path", report)
                self.assertIn("Could not save report", " ".join(report["errors"]))
                self.assertNotIn("Saved report:", render(report))

    def test_session_late_judge_read_error_retains_prior_comparison_error(self):
        self.runs += [{"range": "a..WORKTREE", "exit_code": 2, "error": "comparison timed out"}]
        with patch("pinwash.session.inspect", return_value=self.observation), \
                patch("pinwash.session.identity", side_effect=[self.judge, OSError("judge file unreadable")]), \
                patch("pinwash.session._paths", return_value=(self.root.parent / "state", self.root.parent / "active.json")), \
                patch("pinwash.session._read", return_value=self.state), \
                patch("pinwash.session.collect", return_value=self.runs), \
                patch("pinwash.session._write") as write:
            report = self.command(["session", "review", "--stopped", "--json"])
            self.assertIn("judge file unreadable", report["errors"])
            self.assertIn("a..WORKTREE: comparison timed out", report["errors"])
            self.assertEqual(write.call_args.args[1], report)


class ConsumerReadinessAndStreams(unittest.TestCase):
    def test_link_nodes_not_followed_for_readiness_or_custody(self):
        root = Path.cwd()
        links = {"directory-link": b"some-directory", "dangling-link": b"absent"}
        with patch("pinwash.gitrepo.repository_root", return_value=root), \
                patch("pinwash.gitrepo.resolve_commit", return_value="a" * 40), \
                patch("pinwash.gitrepo.ls_tree", return_value=links), \
                patch("pinwash.gitrepo.ls_worktree", return_value=({}, [])), \
                patch("pinwash.gitrepo.ignored_surface_paths", return_value=([], [], [])), \
                patch("pinwash.gitrepo.worktree_link_targets", return_value=links) as observed:
            first = _inspect(str(root))
            self.assertTrue(first["clean"])
            observed.return_value = dict(links, **{"dangling-link": b"other-absent"})
            second = _inspect(str(root))
            self.assertFalse(second["clean"])
            self.assertNotEqual(first["tree_digest"], second["tree_digest"])
            observed.return_value = dict(links, **{"untracked-link": b"absent"})
            self.assertFalse(_inspect(str(root))["clean"])

    def test_link_listing_reads_link_text_without_opening_target(self):
        from pinwash.gitrepo import worktree_link_targets
        listing = subprocess.CompletedProcess([], 0, b"directory-link/\0dangling-link\0regular\0", b"")
        with patch("pinwash.gitrepo._run", return_value=listing), \
                patch.object(Path, "is_symlink", side_effect=[True, True, False]), \
                patch("pinwash.gitrepo.os.readlink", side_effect=["directory", "absent"]), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("must not follow target")):
            self.assertEqual(worktree_link_targets(Path.cwd()),
                             {"directory-link": b"directory", "dangling-link": b"absent"})

    def test_interactive_json_prompt_never_pollutes_stdout(self):
        from pinwash import human_cli
        output = io.BytesIO()
        stdout = io.TextIOWrapper(output, encoding="utf-8")
        report = summarize([])
        with patch("pinwash.human_cli.sys.stdout", stdout), \
                patch("pinwash.human_cli.sys.stderr", new_callable=io.StringIO) as stderr, \
                patch("pinwash.human_cli.sys.stdin.isatty", return_value=True), \
                patch("builtins.input", return_value="yes") as answer, \
                patch("pinwash.human_cli.review", return_value=report) as review:
            self.assertEqual(human_cli.main(["session", "review", "--json"]), 0)
            self.assertEqual(json.loads(output.getvalue()), report)
            self.assertIn("stopped writing", stderr.getvalue())
            answer.assert_called_once_with()
            self.assertTrue(review.call_args.kwargs["stopped"])

    def test_interactive_eof_returns_json_without_attesting_or_reading_state(self):
        from pinwash import human_cli
        output = io.BytesIO()
        stdout = io.TextIOWrapper(output, encoding="utf-8")
        with patch("pinwash.human_cli.sys.stdout", stdout), \
                patch("pinwash.human_cli.sys.stderr", new_callable=io.StringIO) as stderr, \
                patch("pinwash.human_cli.sys.stdin.isatty", return_value=True), \
                patch("builtins.input", side_effect=EOFError), \
                patch("pinwash.session.inspect") as inspect, \
                patch("pinwash.session._read") as read:
            self.assertEqual(human_cli.main(["session", "review", "--json"]), 2)
            report = json.loads(output.getvalue())
            self.assertEqual(report["exit_code"], 2)
            self.assertIn("Stop the agent", str(report["errors"]))
            self.assertIn("stopped writing", stderr.getvalue())
            inspect.assert_not_called()
            read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
