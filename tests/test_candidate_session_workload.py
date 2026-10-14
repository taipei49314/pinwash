"""Fail-closed checks for the candidate workload, executed on EC pool only."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("candidate_workload", ROOT / "workloads/candidate_sessions/run.py")
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)


class CandidateWorkload(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads((ROOT / "workloads/candidate_sessions/cases.json").read_bytes())
        self.expected = {"exit_code": 0, "findings": [], "unknown_coverage": []}
        self.payload = {"run": {"base": "base", "head": "HEAD", "spec_version": 36,
                                "pinwash_version": "0.0.0"}, "pinwash_findings_version": 1,
                        "findings": [], "unknown_coverage": [], "config_errors": [],
                        "summary": {s: 0 for s in ("critical", "high", "info", "warn")}, "verdict": "pass"}

    def check(self, payload, code=0):
        return entry.check_payload(json.dumps(payload).encode(), code, self.expected, self.plan, "base", "HEAD")

    def test_preregistered_manifest_is_complete_and_hash_pinned(self):
        entry.validate_manifest(self.plan)
        self.assertEqual(entry.digest(entry.MANIFEST.read_bytes()), entry.MANIFEST_SHA256)

    def test_wrong_judge_identity_cannot_match(self):
        self.payload["run"]["spec_version"] = 27
        self.assertIn("wrong run or judge identity", self.check(self.payload)[1])

    def test_unexpected_finding_is_not_discarded(self):
        finding = {"rule": "HOOK_REMOVED", "severity": "critical", "path": "x", "before": "Stop", "after": ""}
        finding["fingerprint"] = entry.spec_fingerprint(finding)
        self.payload["findings"] = [finding]
        self.payload["summary"]["critical"] = 1
        self.payload["verdict"] = "block"
        self.assertIn("findings differ from preregistered rule/severity/path/locator multiset", self.check(self.payload, 1)[1])

    def test_unknown_rows_are_exactly_checked(self):
        self.payload["unknown_coverage"] = [{"path": "x", "reason": "unobserved"}]
        self.assertIn("unknown coverage differs from preregistration", self.check(self.payload)[1])

    def test_malformed_or_missing_json_is_not_judged(self):
        for raw in (b"", b"not json", b"[]", b"{}", b"\xff"):
            with self.subTest(raw=raw):
                payload, problems = entry.check_payload(raw, 0, self.expected, self.plan, "base", "HEAD")
                self.assertIsNone(payload)
                self.assertTrue(problems)

    def test_duplicate_case_or_traversal_is_rejected(self):
        plan = copy.deepcopy(self.plan)
        plan["cases"][1]["id"] = plan["cases"][0]["id"]
        with self.assertRaises(ValueError):
            entry.validate_manifest(plan)
        for path in ("../outside", "/abs", "C:/abs", ".git/config", "a\\b", "a//b"):
            with self.subTest(path=path):
                self.assertFalse(entry.safe_path(path))

    def test_session_needs_three_valid_scans(self):
        scan = {"state": "COMPLETED", "exit_code": 0, "payload": self.payload}
        self.assertEqual(entry.session_outcome([scan] * 2), "not-judged")
        for override in ({"payload": None}, {"state": "TIMED_OUT"}, {"exit_code": 2}):
            self.assertEqual(entry.session_outcome([scan, scan, {**scan, **override}]), "not-judged")

    def test_session_holds_zero_exit_exemption_and_blocks_exit_one(self):
        scan = {"state": "COMPLETED", "exit_code": 0, "payload": self.payload}
        held = {**scan, "payload": {**self.payload, "findings": [{"rule": "EXEMPTION_ADDED"}]}}
        self.assertEqual(entry.session_outcome([scan, held, scan]), "held")
        self.assertEqual(entry.session_outcome([scan, held, {**scan, "exit_code": 1}]), "block")

    def test_seed17_invalid_output_cannot_aggregate_as_complete(self):
        good = {"state": "COMPLETED", "exit_code": 0}
        self.assertEqual(entry.aggregate_seed_state([(good, self.payload), (good, None)]), "NOT_JUDGED")
        self.assertEqual(entry.aggregate_seed_state([(good, self.payload), ({**good, "state": "TIMED_OUT"}, None)]), "TIMED_OUT")
        self.assertEqual(entry.aggregate_seed_state([(good, self.payload), ({**good, "exit_code": 2}, self.payload)]), "NOT_JUDGED")

    def test_fingerprint_is_independent_of_severity(self):
        base = {"rule": "HOOK_BYPASSED", "path": ".claude/settings.json", "locator": "Stop:async",
                "before": "synchronous", "after": "async:true", "severity": "critical"}
        changed = {**base, "severity": "warn"}
        self.assertEqual(entry.fingerprint_identity(base), entry.fingerprint_identity(changed))
        self.assertEqual(entry.spec_fingerprint(base), entry.spec_fingerprint(changed))

    def test_expired_budget_never_starts_a_process(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(entry.subprocess, "Popen") as spawn:
            commands = entry.Commands(Path(tmp), {}, mock.Mock())
            commands.deadline = 0
            step = commands.run("expired", ["unused"], ROOT)
            self.assertEqual(step["state"], "NOT_RUN")
            spawn.assert_not_called()

    def test_unconfirmed_timeout_cleanup_stops_later_launches(self):
        process = mock.Mock()
        process.communicate.side_effect = subprocess.TimeoutExpired(["unused"], 1)
        cleanup = mock.Mock(return_value=(b"partial", b"", {"confirmed": False, "errors": ["test cleanup"]}))
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(entry.subprocess, "Popen", return_value=process) as spawn:
            commands = entry.Commands(Path(tmp), {}, cleanup)
            first = commands.run("timeout", ["unused"], ROOT)
            second = commands.run("later", ["unused"], ROOT)
            self.assertEqual(first["state"], "TIMED_OUT")
            self.assertEqual(second["state"], "NOT_RUN")
            self.assertEqual(spawn.call_count, 1)
            cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
