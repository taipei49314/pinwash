"""Status reports historical facts without scanning or accepting new changes."""
from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from pinwash.consumer import ConsumerError, summarize
from pinwash.findings import envelope, make_finding
from pinwash.report import render
from pinwash.session import _paths
from pinwash.session_status import render_status, status


class SavedSessionStatus(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.directory, self.active = _paths(self.repo, str(self.root / "state"))
        self.judge = {"version": "0.0.0", "spec_version": 27, "python": "trusted runtime", "source_sha256": "a" * 64}
        self.state = {"schema_version": 1, "id": "b" * 32, "repo": str(self.repo),
                      "base": "c" * 40, "judge": self.judge, "created_at": "2026-10-18T01:00:00+00:00"}

    def save_state(self):
        self.directory.mkdir(exist_ok=True)
        self.active.write_text(json.dumps(self.state), encoding="utf-8")

    def save_report(self, suffix="d", when="2026-10-18T02:00:00+00:00", state=None, errors=None):
        state = state or self.state
        base, head = state["base"], "e" * 40
        runs = [{"range": r, "exit_code": 0,
                 "payload": envelope(base_label="a", head_label="b", findings=[], config_errors=[], unknown_coverage=[])}
                for r in (f"{base}..{head}", f"{base}..WORKTREE", f"{head}..WORKTREE")]
        report = summarize(runs, errors)
        report.update(session_id=state["id"], repo=state["repo"], base=base, head=head,
                      judge=state["judge"], reviewed_at=when, report_path="/do/not/follow.json")
        path = self.directory / "reports" / f"{state['id']}-{suffix * 32}.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def read_status(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file() and not p.is_symlink()}
        with ExitStack() as stack:
            stack.enter_context(patch("pinwash.session_status.locate", return_value=self.repo))
            stack.enter_context(patch("pinwash.session_status.identity", return_value=self.judge))
            for name in ("pinwash.session.inspect", "pinwash.session.collect", "pinwash.session._write",
                         "pinwash.consumer.inspect", "pinwash.consumer.collect", "pinwash.engine.scan_repo"):
                stack.enter_context(patch(name, side_effect=AssertionError("status must not scan or write")))
            result = status(self.repo, state_dir=str(self.directory))
        after = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file() and not p.is_symlink()}
        self.assertEqual(after, before)
        self.assertEqual(result["current_changes"], "not_reviewed")
        return result

    def test_no_session_does_not_create_state_or_claim_review_pass(self):
        result = self.read_status()
        self.assertEqual((result["status"], result["exit_code"]), ("no_session", 0))
        self.assertFalse(self.directory.exists())
        self.assertIn("NOT REVIEWED", render_status(result))

    def test_active_without_review_shows_original_baseline(self):
        self.save_state()
        (self.repo / "new-work.txt").write_text("not scanned")
        result = self.read_status()
        self.assertEqual(result["status"], "active")
        self.assertEqual(result["session"]["base"], self.state["base"])
        self.assertTrue(result["judge_matches"])
        self.assertIsNone(result["latest_review"])
        self.assertIn("none for this session", render_status(result))

    def test_latest_same_session_is_selected_by_time_and_actual_path(self):
        self.save_state()
        self.save_report("f", "2026-10-18T02:00:00+00:00")
        latest = self.save_report("d", "2026-10-18T11:30:00+09:00", errors=["final inspection failed"])
        other = dict(self.state, id="0" * 32)
        self.save_report("a", "2026-10-18T04:00:00+00:00", state=other)
        result = self.read_status()
        self.assertEqual(result["latest_review"]["status"], "not_judged")
        self.assertEqual(result["latest_review"]["report_path"], str(latest))
        self.assertEqual(result["exit_code"], 0)  # metadata read, not historical verdict
        self.assertIn("historical", render_status(result))

    def test_replaced_session_does_not_inherit_old_pass(self):
        self.save_state()
        self.save_report()
        self.state["id"] = "f" * 32
        self.save_state()
        self.assertIsNone(self.read_status()["latest_review"])

    def test_damaged_candidate_never_falls_back_to_older_pass(self):
        self.save_state()
        self.save_report("d")
        damaged = self.save_report("f", "2026-10-18T03:00:00+00:00")
        original = json.loads(damaged.read_text())
        variants = ["{", '{"consumer_schema_version":1,"consumer_schema_version":1}', "[" * 2000]
        for key, value in (("session_id", "0" * 32), ("repo", "elsewhere"), ("base", "0" * 40),
                           ("judge", {}), ("reviewed_at", "2026-10-18T03:00:00"),
                           ("reviewed_at", "2026-10-17T03:00:00+00:00"), ("exit_code", 1),
                           ("runs", []), ("findings", [{}])):
            variants.append(json.dumps(dict(original, **{key: value})))
        bad_run = copy.deepcopy(original)
        bad_run["runs"][0]["payload"] = []
        variants.append(json.dumps(bad_run))
        for value in variants:
            with self.subTest(value=value[:100]):
                damaged.write_text(value)
                result = self.read_status()
                self.assertEqual((result["status"], result["exit_code"]), ("unavailable", 2))
                self.assertIsNone(result["latest_review"])

    def test_bounded_history_reads_fail_explicitly(self):
        self.save_state()
        self.save_report()
        for name in ("_REPORT_LIMIT", "_TOTAL_LIMIT", "_ENTRY_LIMIT"):
            with self.subTest(limit=name), patch("pinwash.session_status." + name, 1):
                if name == "_ENTRY_LIMIT":
                    (self.directory / "reports" / "other-session.json").write_text("{}")
                result = self.read_status()
                self.assertEqual(result["exit_code"], 2)
                self.assertIsNone(result["latest_review"])

    def test_state_damage_and_missing_identity_are_errors(self):
        self.save_state()
        for value in ("{", '{"schema_version":1,"schema_version":1}',
                      json.dumps(dict(self.state, created_at="2026-10-18T01:00:00")),
                      json.dumps(dict(self.state, judge={})), " " * 65537):
            with self.subTest(value=value[:70]):
                self.active.write_text(value)
                self.assertEqual(self.read_status()["exit_code"], 2)

    def test_changed_judge_is_visible_without_resetting_baseline(self):
        self.save_state()
        self.state["judge"] = dict(self.judge, source_sha256="f" * 64)
        self.save_state()
        result = self.read_status()
        self.assertFalse(result["judge_matches"])
        self.assertEqual(result["exit_code"], 2)
        self.assertIn("Restore that installation", " ".join(result["errors"]))

    def test_symlink_report_is_not_followed(self):
        self.save_state()
        original = self.save_report("d")
        link = original.with_name(f"{self.state['id']}-{'f' * 32}.json")
        link.symlink_to(original)
        result = self.read_status()
        self.assertEqual(result["exit_code"], 2)
        self.assertIsNone(result["latest_review"])

    def test_symlink_report_directory_and_state_are_not_followed(self):
        self.save_state()
        reports = self.directory / "reports"
        reports.symlink_to(self.repo, target_is_directory=True)
        self.assertEqual(self.read_status()["exit_code"], 2)
        reports.unlink()
        saved = self.directory / "original.json"
        self.active.rename(saved)
        self.active.symlink_to(saved)
        self.assertEqual(self.read_status()["exit_code"], 2)

    def test_non_repository_error_uses_status_schema(self):
        with patch("pinwash.session_status.locate", side_effect=ConsumerError("not a Git repository")):
            result = status(self.repo)
        self.assertEqual(result["session_status_schema_version"], 1)
        self.assertEqual(result["exit_code"], 2)
        self.assertIn("not a Git repository", " ".join(result["errors"]))

    def test_final_state_read_failure_discards_unconfirmed_history(self):
        self.save_state()
        self.save_report()
        for error in (ConsumerError("state disappeared"), ConsumerError("state is damaged"), OSError("unreadable state")):
            with self.subTest(error=str(error)), \
                    patch("pinwash.session_status._read", side_effect=[self.state, error]):
                result = self.read_status()
                self.assertEqual(result["exit_code"], 2)
                self.assertIsNone(result["latest_review"])

    def test_unreadable_judge_is_unknown_rather_than_changed(self):
        self.save_state()
        with patch("pinwash.session_status.locate", return_value=self.repo), \
                patch("pinwash.session_status.identity", side_effect=OSError("unreadable installation")):
            result = status(self.repo, state_dir=str(self.directory))
        self.assertEqual(result["exit_code"], 2)
        self.assertIsNone(result["judge_matches"])
        self.assertIn("Installed judge: UNKNOWN", render_status(result))
        self.assertNotIn("Installed judge: CHANGED", render_status(result))

    def test_cli_status_json_never_prompts_or_reviews(self):
        from pinwash import human_cli
        expected = self.read_status()
        output = io.BytesIO()
        stdout = io.TextIOWrapper(output, encoding="utf-8")
        with patch("pinwash.human_cli.status", return_value=expected), \
                patch("pinwash.human_cli.sys.stdout", stdout), \
                patch("pinwash.human_cli.review", side_effect=AssertionError("review called")), \
                patch("builtins.input", side_effect=AssertionError("prompted")):
            self.assertEqual(human_cli.main(["session", "status", "--json"]), 0)
            self.assertEqual(json.loads(output.getvalue()), expected)


class PrioritySummary(unittest.TestCase):
    def report(self, *, errors=None, coverage=None, config=None, held=False):
        finding = make_finding(rule="EXEMPTION_ADDED" if held else "HOOK_REMOVED",
                               severity="warn" if held else "high", path=".claude/settings.json",
                               message="changed", before="check", after="")
        payload = envelope(base_label="a", head_label="b", findings=[finding],
                           config_errors=config or [], unknown_coverage=coverage or [])
        return summarize([{"range": "a..b", "exit_code": 0 if held else 1, "payload": payload}], errors)

    def test_unfinished_comes_before_block_without_losing_evidence(self):
        report = self.report(errors=["timed out"])
        original = copy.deepcopy(report)
        text = render(report)
        self.assertLess(text.index("Review unfinished"), text.index("Blocking result"))
        self.assertLess(text.index("Finish the review"), text.index("Blocking result"))
        self.assertIn("HOOK_REMOVED", text)
        self.assertIn("Unfinished: timed out", text)
        self.assertEqual(report, original)

    def test_exemption_then_configuration_then_coverage(self):
        text = render(self.report(held=True, config=["invalid config"],
                                  coverage=[{"path": "ignored", "reason": "not read"}]))
        self.assertLess(text.index("Human decision:"), text.index("Configuration:"))
        self.assertLess(text.index("Configuration:"), text.index("Coverage:"))
        self.assertNotIn("start --replace", text)
        self.assertIn("none is automatically approved", text)

    def test_summary_is_limited_and_severity_sorted_but_full_details_remain(self):
        report = self.report()
        for severity, path in (("warn", "a"), ("critical", "z"), ("info", "b")):
            report["findings"].append(make_finding(rule="HOOK_REMOVED", severity=severity, path=path,
                                                   message="changed", before="check", after=""))
        before = copy.deepcopy(report)
        text = render(report)
        summary = text.split("Priority summary:")[1].split("\n\n")[0]
        self.assertLess(summary.index("[critical]"), summary.index("[high]"))
        self.assertIn("1 more finding(s)", summary)
        self.assertNotIn("[info]", summary)
        self.assertIn("[info] b", text)
        self.assertEqual(report, before)

    def test_coverage_only_pass_still_demands_manual_assessment(self):
        report = summarize([])
        report["unknown_coverage"] = [{"path": "ignored", "reason": "not read"}]
        text = render(report)
        self.assertIn("manually assess 1", text)
        self.assertNotIn("No in-scope issue was reported", text)
        self.assertEqual(report["exit_code"], 0)

    def test_clean_summary_sets_scope_and_session_next_step_keeps_baseline(self):
        self.assertIn("normal code review and product checks", render(summarize([])))
        report = self.report()
        report["session_id"] = "a" * 32
        self.assertIn("same state directory and baseline", render(report))


if __name__ == "__main__":
    unittest.main()
