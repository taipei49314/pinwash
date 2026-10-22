"""Harness contract tests. Execute on the approved pool only."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sessions", HERE / "run.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
common = runner.common
IDENTITY = {"engine_version": "0.1.1", "spec_version": 37}


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.expected = {"exit_code": 0, "findings": [], "unknown_coverage": []}
        self.payload = runner.expected_payload(self.expected, IDENTITY, "BASE", "HEAD")

    def test_valid_full_payload(self):
        self.assertEqual(common.check_payload(common.canonical(self.payload).encode(), 0, IDENTITY, "BASE", "HEAD"), self.payload)

    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError):
            common.decode(b'{"run": 1, "run": 2}')

    def test_metadata_not_normalized_away(self):
        for field, value in (("pinwash_version", "0.0.0"), ("spec_version", 29), ("head", "WORKTREE")):
            p = copy.deepcopy(self.payload)
            p["run"][field] = value
            with self.assertRaises(ValueError):
                common.check_payload(common.canonical(p).encode(), 0, IDENTITY, "BASE", "HEAD")

    def test_full_finding_message_and_multiplicity(self):
        f = {"rule": "EXEMPTION_ADDED", "severity": "warn", "path": ".pinwash/allow.toml",
             "message": "fixture", "before": "", "after": ""}
        f["fingerprint"] = common.spec_fingerprint(f)
        p = copy.deepcopy(self.payload)
        p["findings"] = [f, f]
        expected = {**self.expected, "findings": [f]}
        self.assertFalse(common.matches_oracle(p, 0, expected))
        expected["findings"] = [copy.deepcopy(f), copy.deepcopy(f)]
        self.assertTrue(common.matches_oracle(p, 0, expected))
        expected["findings"][0]["message"] = "silently changed"
        self.assertFalse(common.matches_oracle(p, 0, expected))

    def test_unknown_public_pass_acceptance_hold(self):
        self.payload["unknown_coverage"] = [{"path": "settings", "reason": "unresolved"}]
        scans = [{"state": "COMPLETED", "exit_code": 0, "payload": self.payload}] * 3
        self.assertEqual(common.session_outcome(scans), "pass")
        self.assertEqual(common.session_outcome(scans, conservative=True), "HELD")

    def test_incomplete_session_never_accepted(self):
        scans = [{"state": "COMPLETED", "exit_code": 1, "payload": self.payload},
                 {"state": "NOT_RUN", "exit_code": None, "payload": None}]
        self.assertEqual(common.session_outcome(scans), "block")
        self.assertEqual(common.session_outcome(scans, conservative=True), "NOT_JUDGED")

    def test_exact_tuple_matrix_rejects_duplicate_and_missing(self):
        wanted = common.expected_tuples([{"id": "fixture"}], ["baseline", "candidate"])
        rows = [{"tuple": list(k), "state": "COMPLETED", "exit_code": 0, "payload": self.payload,
                 "stdout_sha256": "a" * 64, "stderr_sha256": "b" * 64, "oracle_matched": True} for k in sorted(wanted)]
        self.assertTrue(common.matrix_status(rows, wanted)["matrix_complete"])
        rows[-1] = rows[0]
        status = common.matrix_status(rows, wanted)
        self.assertFalse(status["matrix_complete"])
        self.assertEqual(status["semantic_status"], "NOT_JUDGED")

    def test_stderr_is_part_of_determinism(self):
        wanted = common.expected_tuples([{"id": "fixture"}], ["baseline", "candidate"])
        rows = [{"tuple": list(k), "state": "COMPLETED", "exit_code": 0, "payload": self.payload,
                 "stdout_sha256": "a" * 64, "stderr_sha256": "b" * 64, "oracle_matched": True} for k in sorted(wanted)]
        rows[0]["stderr_sha256"] = "c" * 64
        status = common.matrix_status(rows, wanted)
        self.assertEqual(status["execution_status"], "COMPLETE")
        self.assertEqual(status["determinism_status"], "FAIL")

    def test_unfrozen_engine_is_not_dispatchable(self):
        plan = common.decode((HERE / "cases.json").read_bytes())
        runner.validate_manifest(plan)
        wrong_ref = copy.deepcopy(plan)
        wrong_ref["engines_bundle"]["refs"]["candidate"] = "refs/heads/codex/reconcile-candidates-20261022"
        with self.assertRaisesRegex(ValueError, "engine bundle identity drift"):
            runner.validate_manifest(wrong_ref)
        plan["engines"]["candidate"]["revision"] = "UNFROZEN"
        with self.assertRaises(ValueError):
            common.validate_engines(plan["engines"])

    def test_spawn_failure_has_no_synthetic_output_or_exit(self):
        with tempfile.TemporaryDirectory() as folder:
            commands = common.Commands(Path(folder), {})
            with mock.patch.object(common.subprocess, "Popen", side_effect=OSError("fixture failure")):
                step = commands.run("spawn", ["absent"], Path(folder))
            self.assertEqual(step["state"], "START_FAILED")
            self.assertIsNone(step["exit_code"])
            self.assertEqual(step["stderr"], b"")
            self.assertIn("fixture failure", step["wrapper_error"])
            next_step = commands.run("not-run", ["absent"], Path(folder))
            self.assertEqual(next_step["state"], "NOT_RUN")
            self.assertIsNone(next_step["exit_code"])

    def test_only_current_owned_scratch_can_be_removed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            alien = root / "unrelated"
            alien.mkdir()
            with self.assertRaises(ValueError):
                common.remove_owned_tree(alien, root)
            self.assertTrue(alien.exists())

    def test_prompt_controls_keep_critical_without_command_refusal(self):
        plan = common.decode((HERE / "cases.json").read_bytes())
        cases = {c["id"]: c for c in plan["cases"]}
        for name in ("prompt-retained-command-removed", "prompt-retained-command-async", "prompt-retained-env-bypass", "prompt-command-holder-retyped"):
            for exp in cases[name]["expected"]["candidate"][1:]:
                self.assertEqual(exp["exit_code"], 1)
                self.assertTrue(any(f["severity"] == "critical" for f in exp["findings"]))


if __name__ == "__main__":
    unittest.main()
