"""Negative replay-contract checks. Execute this source only on the EC pool."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_entry(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def encoded(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")


def fingerprint(finding: dict) -> str:
    """Independent SPEC identity for a literal test finding, without product imports."""
    sha = lambda data: hashlib.sha256(data).hexdigest()
    identity = {
        "rule": finding["rule"], "path": finding["path"], "locator": finding.get("locator", ""),
        "before_digest": sha(finding["before"].encode("utf-8", "surrogatepass")),
        "after_digest": sha(finding["after"].encode("utf-8", "surrogatepass")),
    }
    raw = json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "surrogatepass")
    return finding["rule"] + "/" + finding["path"] + "/v1:" + sha(raw)


class CandidateHistoryReplayWorkload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry = load_entry("history_replay_contract", ROOT / "workloads/candidate_history_replay/run.py")
        cls.support = load_entry("history_replay_cleanup_contract", ROOT / "workloads/candidate_sessions/run.py")
        cls.original_plan = json.loads((ROOT / "workloads/candidate_history_replay/manifest.json").read_bytes())

    def setUp(self):
        self.plan = copy.deepcopy(self.original_plan)

    def payload(self, engine="baseline", range_name="BASE..HEAD", *, finding=False):
        result = {
            "pinwash_findings_version": 1,
            "run": {"pinwash_version": "0.0.0", "spec_version": 27 if engine == "baseline" else 36,
                    "base": "HEAD" if range_name == "HEAD..WORKTREE" else self.entry.BASE,
                    "head": "HEAD" if range_name == "BASE..HEAD" else "WORKTREE"},
            "findings": [], "summary": {s: 0 for s in ("critical", "high", "info", "warn")},
            "verdict": "pass", "unknown_coverage": [], "config_errors": [],
        }
        if finding:
            row = {"rule": "HOOK_REMOVED", "severity": "critical", "path": ".claude/settings.json",
                   "locator": "Stop", "message": "literal contract finding", "before": "hook", "after": ""}
            row["fingerprint"] = fingerprint(row)
            result["findings"] = [row]
            result["summary"]["critical"] = 1
            result["verdict"] = "block"
        return result

    def checked(self, payload, code=0, engine="baseline", range_name="BASE..HEAD"):
        return self.entry.check_payload(encoded(payload), code, engine, range_name)

    def test_manifest_missing_or_duplicate_case_is_rejected(self):
        self.entry.validate_manifest(self.plan)
        manifest_bytes = (ROOT / "workloads/candidate_history_replay/manifest.json").read_bytes()
        self.assertEqual(hashlib.sha256(manifest_bytes).hexdigest(), self.entry.MANIFEST_SHA256)
        missing = copy.deepcopy(self.plan)
        missing["cases"].pop()
        duplicate = copy.deepcopy(self.plan)
        duplicate["cases"][1] = copy.deepcopy(duplicate["cases"][0])
        for changed in (missing, duplicate):
            with self.subTest(cases=len(changed["cases"])), self.assertRaises(ValueError):
                self.entry.validate_manifest(changed)

    def test_first_launch_cannot_be_promoted_to_formal(self):
        first = next(c for c in self.plan["cases"] if c["id"] == self.entry.FIRST)
        first["role"] = "formal"
        with self.assertRaises(ValueError):
            self.entry.validate_manifest(self.plan)

    def test_manifest_engine_identity_drift_is_rejected(self):
        for field in ("revision", "tree", "spec_sha256"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.plan)
                changed["engines"]["candidate"][field] = "0" * len(changed["engines"]["candidate"][field])
                with self.assertRaises(ValueError):
                    self.entry.validate_manifest(changed)

    def test_manifest_bad_worktree_hash_is_rejected(self):
        case = self.plan["cases"][0]
        case["files"][next(iter(case["files"]))] = "not-a-file-hash"
        with self.assertRaises(ValueError):
            self.entry.validate_manifest(self.plan)
        drifted = copy.deepcopy(self.original_plan)
        files = drifted["cases"][0]["files"]
        files[next(iter(files))] = "0" * 64
        self.entry.validate_manifest(drifted)
        with self.assertRaisesRegex(ValueError, "case inventory differs from original worktree identities"):
            self.entry.validate_inputs(drifted)

    def test_manifest_cannot_widen_predicted_delta(self):
        case = self.plan["cases"][0]
        case["unknown_added"]["BASE..HEAD"] = [{"path": "other", "reason": "unregistered visibility loss"}]
        with self.assertRaises(ValueError):
            self.entry.validate_manifest(self.plan)

    def test_duplicate_json_keys_are_rejected_at_every_level(self):
        for raw in (b'{"x":1,"x":2}', b'{"outer":{"x":1,"x":2}}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.entry.decode(raw)

    def test_patch_rejects_escape_and_windows_path_aliases(self):
        for name in ("../outside", "/outside", "C:/outside", "a\\b", ".git/config", "a/.GiT/config",
                     "nul", "aux.txt", "a/COM1.txt", "a/trailing.", "a/trailing "):
            raw = ("diff --git a/" + name + " b/" + name + "\n").encode()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.entry.patch_paths(raw)
        self.assertEqual(self.entry.patch_paths(b"diff --git a/normal.txt b/normal.txt\n"), {"normal.txt"})

    def test_patch_rejects_nonregular_modes(self):
        for mode in (b"120000", b"160000", b"040000"):
            raw = b"diff --git a/link b/link\nnew file mode " + mode + b"\n"
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.entry.patch_paths(raw)

    def test_payload_malformed_or_extra_envelope_is_rejected(self):
        for raw in (b"", b"not JSON", b"[]", b"{}", b"\xff"):
            with self.subTest(raw=raw), self.assertRaises((ValueError, TypeError, KeyError)):
                self.entry.check_payload(raw, 0, "baseline", "BASE..HEAD")
        value = self.payload()
        value["unregistered_field"] = True
        with self.assertRaises(ValueError):
            self.checked(value)

    def test_payload_wrong_engine_or_range_identity_is_rejected(self):
        for field, replacement in (("spec_version", 36), ("base", "wrong-base"), ("head", "WORKTREE")):
            value = self.payload()
            value["run"][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.checked(value)

    def test_payload_exit_summary_and_unknown_rows_are_checked(self):
        self.checked(self.payload())
        for change, code in (({"verdict": "block"}, 0), ({}, 1), ({}, 2),
                             ({"summary": {"critical": 0, "high": 0, "info": 0, "warn": True}}, 0),
                             ({"unknown_coverage": [{"path": "a", "reason": "x"}] * 2}, 0)):
            value = self.payload()
            value.update(change)
            with self.subTest(change=change, code=code), self.assertRaises(ValueError):
                self.checked(value, code)

    def test_payload_corrupt_fingerprint_is_rejected(self):
        value = self.payload(finding=True)
        self.checked(value, 1)
        value["findings"][0]["fingerprint"] += "0"
        with self.assertRaises(ValueError):
            self.checked(value, 1)

    def test_cross_version_comparison_keeps_message_and_fingerprint(self):
        baseline, candidate = self.payload(finding=True), self.payload("candidate", finding=True)
        self.assertTrue(self.entry.compare_payloads(baseline, candidate, [], (1, 1)))
        for field in ("message", "fingerprint", "severity", "locator"):
            changed = copy.deepcopy(candidate)
            changed["findings"][0][field] += "-unpredicted"
            with self.subTest(field=field):
                self.assertFalse(self.entry.compare_payloads(baseline, changed, [], (1, 1)))

    def test_cross_version_exception_is_exact_and_nonmutating(self):
        baseline, candidate = self.payload(), self.payload("candidate")
        addition = dict(self.entry.EVENT_ROW)
        candidate["unknown_coverage"] = [addition]
        original = copy.deepcopy(candidate)
        self.assertTrue(self.entry.compare_payloads(baseline, candidate, [addition], (0, 0)))
        self.assertEqual(candidate, original)
        for changed in (self.payload("candidate"),
                        {**candidate, "unknown_coverage": [addition, {"path": "z", "reason": "extra"}]},
                        {**candidate, "unknown_coverage": [addition, addition]}):
            self.assertFalse(self.entry.compare_payloads(baseline, changed, [addition], (0, 0)))
        self.assertFalse(self.entry.compare_payloads(baseline, candidate, [addition], (0, 1)))

    def test_incomplete_session_is_not_judged_even_with_a_block(self):
        good = {"state": "COMPLETED", "exit_code": 0, "payload": self.payload()}
        block = {"state": "COMPLETED", "exit_code": 1, "payload": self.payload(finding=True)}
        self.assertEqual(self.entry.session_outcome([good, block]), "not-judged")
        for override in ({"state": "TIMED_OUT"}, {"payload": None}, {"exit_code": 2}):
            with self.subTest(override=override):
                self.assertEqual(self.entry.session_outcome([good, block, {**good, **override}]), "not-judged")

    def test_zero_exit_unknown_is_held_and_block_has_priority(self):
        good = {"state": "COMPLETED", "exit_code": 0, "payload": self.payload()}
        held = {**good, "payload": {**self.payload(), "unknown_coverage": [dict(self.entry.EVENT_ROW)]}}
        block = {"state": "COMPLETED", "exit_code": 1, "payload": self.payload(finding=True)}
        self.assertEqual(self.entry.session_outcome([good] * 3), "pass")
        self.assertEqual(self.entry.session_outcome([good, held, good]), "held")
        self.assertEqual(self.entry.session_outcome([good, held, block]), "block")

    def test_plain_scan_argv_has_no_synthetic_range_argument(self):
        prefix = [sys.executable, "-P", "-s", "-X", "utf8", "-B", "-m", "pinwash", "check"]
        self.assertEqual(self.entry.make_scan_argv("HEAD..WORKTREE"), prefix)
        self.assertEqual(self.entry.make_scan_argv("BASE..HEAD"), prefix + [self.entry.BASE + "..HEAD"])
        self.assertEqual(self.entry.make_scan_argv("BASE..WORKTREE"), prefix + [self.entry.BASE + "..WORKTREE"])
        with self.assertRaises(ValueError):
            self.entry.make_scan_argv("unregistered-range")

    def test_parameters_are_a_fixed_real_file_containing_only_empty_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            source = parent / "source"
            source.mkdir()
            params = parent / "parameters.json"
            params.write_bytes(b"{}\n")
            with mock.patch.object(self.entry, "ROOT", source):
                accepted = self.entry.validate_parameters(str(params), self.support)
                self.assertEqual(accepted["value"], {})
                self.assertEqual(accepted["sha256"], hashlib.sha256(b"{}\n").hexdigest())
                for raw in (b'{"extra":1}', b"[]", b'{"x":1,"x":2}', b"{"):
                    params.write_bytes(raw)
                    with self.subTest(raw=raw), self.assertRaises(ValueError):
                        self.entry.validate_parameters(str(params), self.support)
                params.write_bytes(b"{}\n")
                other = parent / "other.json"
                other.write_bytes(b"{}\n")
                for path in (str(other), "parameters.json", "{}"):
                    with self.subTest(path=path), self.assertRaises(ValueError):
                        self.entry.validate_parameters(path, self.support)
                linked = parent / "linked.json"
                os.link(params, linked)
                try:
                    with self.assertRaises(ValueError):
                        self.entry.validate_parameters(str(params), self.support)
                finally:
                    linked.unlink()
            generation = parent / "8b1bcfb4b5dc0588.1"
            generation.mkdir()
            self.assertEqual(self.entry.validate_generation(str(generation))["id"], "8b1bcfb4b5dc0588.1")
            malformed = parent / "unregistered-generation"
            malformed.mkdir()
            for path in (str(malformed), str(parent / "8b1bcfb4b5dc0588.2"), "8b1bcfb4b5dc0588.1", ""):
                with self.subTest(generation=path), self.assertRaises((ValueError, FileNotFoundError)):
                    self.entry.validate_generation(path)

    def test_timeout_retains_raw_evidence_and_refuses_later_launch(self):
        process = mock.Mock()
        process.communicate.side_effect = subprocess.TimeoutExpired(["unused"], 1, output=b"partial")
        stop = mock.Mock(return_value=(b"partial", b"cleanup-log", {"confirmed": True, "errors": []}))
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(self.entry.subprocess, "Popen", return_value=process) as spawn:
            commands = self.entry.Commands(Path(tmp), {}, stop, self.entry.time.monotonic())
            first = commands.run("timeout", ["unused"], ROOT)
            later = commands.run("later", ["unused"], ROOT)
            self.assertEqual(first["state"], "TIMED_OUT")
            self.assertTrue(first["timed_out"])
            self.assertEqual((Path(tmp) / "timeout.stdout").read_bytes(), b"partial")
            self.assertEqual(first["stdout_sha256"], hashlib.sha256(b"partial").hexdigest())
            self.assertEqual(later["state"], "NOT_RUN")
            spawn.assert_called_once()
            stop.assert_called_once()

    def test_unconfirmed_termination_refuses_even_final_readback(self):
        process = mock.Mock()
        process.communicate.side_effect = subprocess.TimeoutExpired(["unused"], 1)
        stop = mock.Mock(return_value=(b"", b"", {"confirmed": False, "errors": ["uncertain"]}))
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(self.entry.subprocess, "Popen", return_value=process) as spawn:
            commands = self.entry.Commands(Path(tmp), {}, stop, self.entry.time.monotonic())
            commands.run("timeout", ["unused"], ROOT)
            final = commands.run("final", ["unused"], ROOT, final=True)
            self.assertTrue(commands.uncertain())
            self.assertEqual(final["state"], "NOT_RUN")
            spawn.assert_called_once()

    def test_not_run_inventory_retains_every_recipe_without_fake_evidence(self):
        reports = self.entry.not_run_reports(self.plan)
        self.assertEqual({r["id"] for r in reports}, {c["id"] for c in self.plan["cases"]})
        for report in reports:
            self.assertEqual(report["state"], "NOT_RUN")
            self.assertEqual(set(report["engines"]), {"baseline", "candidate"})
            for rows in report["engines"].values():
                self.assertEqual([r["range"] for r in rows], ["BASE..HEAD", "BASE..WORKTREE", "HEAD..WORKTREE"])
                for row in rows:
                    self.assertEqual(row["state"], "NOT_RUN")
                    self.assertIsNone(row["payload"])
                    self.assertEqual([s["seed"] for s in row["seeds"]], ["1", "17"])
                    for seed in row["seeds"]:
                        self.assertEqual(seed["state"], "NOT_RUN")
                        self.assertIsNone(seed["payload"])
                        self.assertNotIn("stdout_sha256", seed)

    def test_acceptance_refuses_incomplete_execution_and_semantic_failure(self):
        # Literal state fixtures exercise receipt acceptance only. These are
        # neither product findings nor synthetic replacements for pool scans.
        reports = self.entry.not_run_reports(self.plan)
        steps = []
        for index, report in enumerate(reports):
            report["state"] = "COMPLETED"
            report["comparisons"] = [{"range": name, "prediction_matched": True}
                                     for name in ("BASE..HEAD", "BASE..WORKTREE", "HEAD..WORKTREE")]
            for engine, rows in report["engines"].items():
                for scan_index, row in enumerate(rows):
                    row.update(state="COMPLETED", raw_json_equal=True, exit_code=0,
                               payload=self.payload(engine, row["range"]))
                    for seed in row["seeds"]:
                        seed.update(state="COMPLETED", exit_code=0, payload=copy.deepcopy(row["payload"]))
                        steps.append({"name": f"scan-{engine}-{index}-{scan_index}-seed{seed['seed']}",
                                      "state": "COMPLETED"})
        baseline = {"reports": reports, "steps": steps, "cleanup": {"state": "REMOVED"},
                    "final_source": {"state": "VERIFIED_CLEAN"}, "problems": []}
        self.assertEqual(self.entry.acceptance_status(**baseline), (True, True))
        for defect in ("missing-command", "unequal-seed", "not-run", "missing-range",
                       "incomplete-cell", "cleanup-failed", "source-failed", "identity-problem",
                       "semantic-prediction-failed"):
            changed = copy.deepcopy(baseline)
            if defect == "missing-command":
                changed["steps"].pop()
            elif defect == "unequal-seed":
                changed["reports"][0]["engines"]["baseline"][0]["raw_json_equal"] = False
            elif defect == "not-run":
                changed["steps"][0]["state"] = "NOT_RUN"
            elif defect == "missing-range":
                changed["reports"][0]["engines"]["baseline"].pop()
            elif defect == "incomplete-cell":
                changed["reports"][-1]["state"] = "NOT_RUN"
            elif defect == "cleanup-failed":
                changed["cleanup"]["state"] = "FAILED"
            elif defect == "source-failed":
                changed["final_source"]["state"] = "FAILED"
            elif defect == "identity-problem":
                changed["problems"].append("fixed input identity failed")
            else:
                formal = next(r for r in changed["reports"] if r["role"] == "formal")
                formal["comparisons"][0]["prediction_matched"] = False
            with self.subTest(defect=defect):
                execution, semantic = self.entry.acceptance_status(**changed)
                self.assertFalse(execution and semantic)
                if defect == "semantic-prediction-failed":
                    self.assertEqual((execution, semantic), (True, False))

    def test_owned_cleanup_rejects_wrong_parent_hardlinks_and_reparse(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            root = Path(tempfile.mkdtemp(prefix="pinwash-candidate-history-", dir=parent))
            marker = root / "keep"
            marker.write_bytes(b"preserve")
            wrong_parent = parent / "other"
            wrong_parent.mkdir()
            with self.assertRaises(ValueError):
                self.support.remove_owned_tree(root, wrong_parent)
            linked = parent / "linked"
            os.link(marker, linked)
            try:
                with self.assertRaises(ValueError):
                    self.support.remove_owned_tree(root, parent)
                self.assertEqual(marker.read_bytes(), b"preserve")
            finally:
                linked.unlink()
            original_lstat = Path.lstat
            info = mock.Mock(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
            for redirected in (root, parent):
                with self.subTest(redirected=redirected), mock.patch.object(
                        Path, "lstat", autospec=True,
                        side_effect=lambda p, *a, **kw: info if p == redirected else original_lstat(p, *a, **kw)):
                    with self.assertRaises(ValueError):
                        self.support.remove_owned_tree(root, parent)
                self.assertEqual(marker.read_bytes(), b"preserve")
            self.support.remove_owned_tree(root, parent)

    def test_owned_readonly_git_object_cleanup_is_confirmed_by_absence(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            root = Path(tempfile.mkdtemp(prefix="pinwash-candidate-history-", dir=parent))
            target = root / ".git" / "objects" / "aa" / "object"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"owned Git object")
            os.chmod(target, stat.S_IREAD)
            try:
                self.support.remove_owned_tree(root, parent)
                self.assertFalse(os.path.lexists(root))
            finally:
                if target.exists():
                    os.chmod(target, stat.S_IREAD | stat.S_IWRITE)


if __name__ == "__main__":
    unittest.main()
