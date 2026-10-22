"""Supplementary runner controls; never import or execute the PinWash product."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from workloads.alpha2_verify import run as runner


SHA = "1" * 40


class RunnerFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "tests").mkdir()
        (self.root / "tests" / "test_fixture.py").write_text("# source hash fixture\n")
        (self.root / "SPEC.md").write_bytes(b"fixture spec\n")
        self.out = self.base / "out"
        self.out.mkdir()
        self.work = self.base / "work"
        self.work.mkdir()
        self.env = {"PINWASH_TODAY": "2026-09-30"}
        self.root_patch = mock.patch.object(runner, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.platform_patch = mock.patch.object(runner.platform, "platform", return_value="mock-runtime")
        self.platform_patch.start()
        self.addCleanup(self.platform_patch.stop)

    def process(self, stdout=b"", stderr=b"", code=0):
        process = mock.Mock(pid=123, returncode=code)
        process.communicate.return_value = stdout, stderr
        return process

    def doctor(self):
        return {
            "subject_judged": False,
            "self_tests": {"available": True, "ok": True, "tests_run": 100,
                           "failures": 0, "errors": 0, "skipped_count": 0,
                           "nested_depth": 0},
            "spec_sha256": runner.sha256((self.root / "SPEC.md").read_bytes()),
        }

    def processes(self, doctor=None):
        return [
            self.process(SHA.encode()), self.process(),
            self.process(stderr=b"Ran 9 tests in 0.1s\n\nOK\n"),
            self.process(stderr=b"Ran 100 tests in 0.1s\n\nOK\n"),
            self.process(json.dumps(self.doctor() if doctor is None else doctor).encode()),
            self.process(b'{"same_tree":true}\n'), self.process(b'{"same_tree":true}\n'),
            self.process(SHA.encode()), self.process(),
        ]

    def collect(self, processes, deadline=1140):
        with mock.patch.object(runner.subprocess, "Popen", side_effect=processes) as launch, \
                mock.patch.object(runner.time, "monotonic", return_value=0):
            result = runner.collect(SHA, self.out, self.env, deadline)
        return result, launch

    def main_env(self):
        return {
            "EC_WORKLOAD_SOURCE": str(self.root), "EC_WORKLOAD_OUT": str(self.out),
            "EC_WORKLOAD_WORK": str(self.work), "EC_WORKLOAD_SHA": SHA,
            "EC_WORKLOAD_REPOSITORY": "taipei49314/pinwash", "EC_WORKLOAD_NAME": "alpha2-verify",
            "PINWASH_DOCTOR_SELFTEST": "99",
        }

    def minimal_result(self, *, children=True):
        return {"passed": True, "actual_sha": SHA, "tests_run": 100, "raw_json_equal": True,
                "workload_tests": {"tests_run": 9, "ok": True}, "problems": [],
                "child_cleanup_confirmed": children}


class OwnedProcessCleanup(unittest.TestCase):
    def process(self):
        process = mock.Mock(pid=123, returncode=-9)
        process.communicate.return_value = b"retained stdout", b"retained stderr"
        return process

    def test_windows_cleanup_requires_tree_kill_and_pipe_completion(self):
        process = self.process()
        with mock.patch.dict(os.environ, {"SystemRoot": "C:/Windows"}), \
                mock.patch.object(runner.subprocess, "run", return_value=mock.Mock(
                    returncode=0, stdout=b"terminated", stderr=b"")) as kill:
            stdout, stderr, cleanup = runner.stop_owned(process, RuntimeError(), windows=True)
        self.assertTrue(cleanup["confirmed"])
        self.assertEqual((stdout, stderr), (b"retained stdout", b"retained stderr"))
        self.assertEqual(kill.call_args.args[0], [str(Path("C:/Windows") / "System32" / "taskkill.exe"),
                                                "/PID", "123", "/T", "/F"])
        self.assertEqual(kill.call_args.kwargs["timeout"], 15)
        process.communicate.assert_called_once_with(timeout=15)

    def test_kill_failures_do_not_certify_cleanup(self):
        for failure in (OSError("cannot launch"), subprocess.TimeoutExpired("taskkill", 15), None):
            with self.subTest(failure=failure), \
                    mock.patch.dict(os.environ, {"SystemRoot": "C:/Windows"}), \
                    mock.patch.object(runner.subprocess, "run", side_effect=failure,
                                      return_value=mock.Mock(returncode=1, stdout=b"", stderr=b"denied")):
                _, _, cleanup = runner.stop_owned(self.process(), RuntimeError(), windows=True)
            self.assertFalse(cleanup["confirmed"])
            self.assertTrue(cleanup["errors"])

    def test_drain_timeout_preserves_partial_raw_streams(self):
        process = self.process()
        process.communicate.side_effect = subprocess.TimeoutExpired("child", 15)
        expired = subprocess.TimeoutExpired("child", 570, output=b"partial out", stderr=b"partial err")
        with mock.patch.dict(os.environ, {"SystemRoot": "C:/Windows"}), \
                mock.patch.object(runner.subprocess, "run", return_value=mock.Mock(
                    returncode=0, stdout=b"", stderr=b"")):
            stdout, stderr, cleanup = runner.stop_owned(process, expired, windows=True)
        self.assertEqual((stdout, stderr), (b"partial out", b"partial err"))
        self.assertFalse(cleanup["confirmed"])

    def test_missing_terminal_parent_code_is_unconfirmed(self):
        process = self.process()
        process.returncode = None
        with mock.patch.dict(os.environ, {"SystemRoot": "C:/Windows"}), \
                mock.patch.object(runner.subprocess, "run", return_value=mock.Mock(
                    returncode=0, stdout=b"", stderr=b"")):
            _, _, cleanup = runner.stop_owned(process, RuntimeError(), windows=True)
        self.assertFalse(cleanup["confirmed"])


class EntryControls(RunnerFixture):
    def test_success_keeps_supplementary_counts_and_suite_depth_separate(self):
        processes = self.processes()
        result, launch = self.collect(processes)
        self.assertTrue(result["passed"], result["problems"])
        self.assertEqual(result["workload_tests"], {"tests_run": 9, "ok": True})
        self.assertEqual(result["tests_run"], 100)
        self.assertEqual(len(result["test_sources_sha256"]), 1)
        self.assertEqual(launch.call_count, 9)
        self.assertEqual(launch.call_args_list[3].kwargs["env"]["PINWASH_DOCTOR_SELFTEST"], "1")
        for index in (0, 1, 2, 4, 5, 6, 7, 8):
            self.assertNotIn("PINWASH_DOCTOR_SELFTEST", launch.call_args_list[index].kwargs["env"])
        for index, process in enumerate(processes):
            process.communicate.assert_called_once_with(timeout=570 if index in (3, 4) else 30)
        self.assertEqual([step["actual_exit_code"] for step in result["steps"]], [0] * 9)

    def test_expired_budget_launches_nothing(self):
        result, launch = self.collect([], deadline=-1)
        launch.assert_not_called()
        self.assertFalse(result["passed"])
        self.assertTrue(result["child_cleanup_confirmed"])
        self.assertTrue(all(step["state"] == "NOT_RUN" for step in result["steps"]))
        self.assertTrue(all(step["actual_exit_code"] is None for step in result["steps"]))

    def test_timeout_blocks_all_later_commands_even_after_confirmed_cleanup(self):
        for confirmed in (True, False):
            with self.subTest(confirmed=confirmed):
                processes = self.processes()[:4]
                processes[-1].returncode = -9
                processes[-1].communicate.side_effect = subprocess.TimeoutExpired("suite", 570)
                with mock.patch.object(runner, "stop_owned", return_value=(
                        b"partial out", b"partial err", {"confirmed": confirmed, "errors": []})):
                    result, launch = self.collect(processes)
                self.assertEqual(launch.call_count, 4)
                self.assertFalse(result["passed"])
                self.assertEqual(result["child_cleanup_confirmed"], confirmed)
                suite = result["steps"][3]
                self.assertEqual((suite["state"], suite["exit_code"], suite["actual_exit_code"]),
                                 ("TIMED_OUT", 2, -9))
                self.assertEqual((self.out / "suite.stdout").read_bytes(), b"partial out")
                self.assertEqual((self.out / "suite.stderr").read_bytes(), b"partial err")
                self.assertTrue(all(step["state"] == "NOT_RUN" for step in result["steps"][4:]))
                self.assertTrue(all(step["actual_exit_code"] is None for step in result["steps"][4:]))

    def test_start_failure_records_error_separately_from_raw_stderr(self):
        result, launch = self.collect([OSError("cannot launch")])
        self.assertEqual(launch.call_count, 1)
        self.assertFalse(result["passed"])
        self.assertEqual(result["steps"][0]["state"], "START_FAILED")
        self.assertIn("cannot launch", result["steps"][0]["error"])
        self.assertIsNone(result["steps"][0]["actual_exit_code"])
        self.assertEqual((self.out / "source.stderr").read_bytes(), b"")

    def test_failed_supplementary_tests_block_product_execution(self):
        processes = self.processes()[:3]
        processes[-1].returncode = 1
        result, launch = self.collect(processes)
        self.assertEqual(launch.call_count, 3)
        self.assertFalse(result["workload_tests"]["ok"])
        self.assertFalse(result["passed"])
        self.assertTrue(all(step["state"] == "NOT_RUN" for step in result["steps"][3:]))

    def test_public_doctor_rejects_nested_or_excluded_suite(self):
        for change in ({"nested_depth": 1}, {"excluded": []}, {"skipped_count": 1},
                       {"tests_run": 99}, {"skipped": "nested"}):
            with self.subTest(change=change):
                doctor = self.doctor()
                doctor["self_tests"].update(change)
                result, _ = self.collect(self.processes(doctor))
                self.assertFalse(result["passed"])
                self.assertIn("doctor did not verify the same nonzero test suite and spec", result["problems"])

    def test_remaining_budget_caps_long_command(self):
        processes = self.processes()
        result, _ = self.collect(processes, deadline=42)
        self.assertTrue(result["passed"])
        processes[3].communicate.assert_called_once_with(timeout=42)
        processes[4].communicate.assert_called_once_with(timeout=42)

    def test_main_uses_fresh_owned_temp_and_preserves_old_temp(self):
        old = self.work / "alpha2-old"
        old.mkdir()
        (old / "keep.txt").write_text("unrelated old contents")
        owned_paths = []

        def collect(expected, out, env, deadline):
            self.assertEqual(expected, SHA)
            self.assertEqual(out, self.out)
            owned = Path(env["TEMP"])
            owned_paths.append(owned)
            self.assertEqual(owned.parent, self.work)
            self.assertNotEqual(owned, old)
            self.assertEqual(env["TMP"], str(owned))
            self.assertEqual(env["TMPDIR"], str(owned))
            self.assertNotIn("PINWASH_DOCTOR_SELFTEST", env)
            (owned / "nested").mkdir()
            (owned / "nested" / "scratch").write_text("owned")
            return self.minimal_result()

        with mock.patch.dict(os.environ, self.main_env()), mock.patch.object(runner, "collect", side_effect=collect):
            self.assertEqual(runner.main(), 0)
        self.assertFalse(owned_paths[0].exists())
        self.assertEqual((old / "keep.txt").read_text(), "unrelated old contents")
        result = json.loads((self.out / "result.json").read_text())
        self.assertEqual(result["temporary_cleanup"]["retained"], False)
        self.assertTrue(result["temporary_cleanup"]["confirmed"])
        self.assertEqual(result["budget_seconds"], {"commands": 1140, "cleanup_deadline": 1170, "outer": 1200})

    def test_main_retains_owned_temp_when_child_cleanup_unconfirmed(self):
        owned_paths = []

        def collect(expected, out, env, deadline):
            owned = Path(env["TEMP"])
            owned_paths.append(owned)
            (owned / "partial").write_text("retain")
            return self.minimal_result(children=False)

        with mock.patch.dict(os.environ, self.main_env()), mock.patch.object(runner, "collect", side_effect=collect):
            self.assertEqual(runner.main(), 1)
        self.assertEqual((owned_paths[0] / "partial").read_text(), "retain")
        result = json.loads((self.out / "result.json").read_text())
        self.assertFalse(result["passed"])
        self.assertTrue(result["temporary_cleanup"]["retained"])

    def test_main_rejects_wrong_work_parent_before_collect(self):
        wrong = self.base / "other"
        wrong.mkdir()
        env = dict(self.main_env(), EC_WORKLOAD_WORK=str(wrong))
        with mock.patch.dict(os.environ, env), mock.patch.object(runner, "collect") as collect:
            with self.assertRaisesRegex(RuntimeError, "EC job sibling"):
                runner.main()
        collect.assert_not_called()

    def test_main_rejects_output_inside_source_or_work(self):
        for out in (self.root / "result", self.work / "result", self.base):
            with self.subTest(out=out):
                env = dict(self.main_env(), EC_WORKLOAD_OUT=str(out))
                with mock.patch.dict(os.environ, env), mock.patch.object(runner, "collect") as collect:
                    with self.assertRaisesRegex(RuntimeError, "intersects"):
                        runner.main()
                collect.assert_not_called()


class OwnedTemporaryCleanup(RunnerFixture):
    def test_rejects_outside_direct_parent_without_removing_anything(self):
        outside = self.base / "alpha2-unowned"
        outside.mkdir()
        (outside / "keep").write_text("keep")
        with self.assertRaisesRegex(ValueError, "owned child"):
            runner.remove_owned_temp(outside, self.work, float("inf"))
        self.assertEqual((outside / "keep").read_text(), "keep")

    def test_expired_cleanup_budget_preserves_tree(self):
        owned = self.work / "alpha2-owned"
        owned.mkdir()
        (owned / "keep").write_text("keep")
        with mock.patch.object(runner.time, "monotonic", return_value=10):
            with self.assertRaises(TimeoutError):
                runner.remove_owned_temp(owned, self.work, 10)
        self.assertEqual((owned / "keep").read_text(), "keep")

    def test_hardlink_refuses_entire_cleanup_before_deleting_files(self):
        owned = self.work / "alpha2-owned"
        owned.mkdir()
        (owned / "ordinary").write_text("ordinary")
        outside = self.work / "outside"
        outside.write_text("keep both links")
        os.link(outside, owned / "linked")
        with self.assertRaisesRegex(ValueError, "hardlinked"):
            runner.remove_owned_temp(owned, self.work, float("inf"))
        self.assertEqual((owned / "ordinary").read_text(), "ordinary")
        self.assertEqual((owned / "linked").read_text(), "keep both links")
        self.assertEqual(outside.read_text(), "keep both links")


if __name__ == "__main__":
    unittest.main()
