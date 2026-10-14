"""Pool-only mocks for evidence retention when owned command cleanup fails."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from workloads.alpha2_verify.run import main, stop_owned


class OwnedCleanup(unittest.TestCase):
    def process(self):
        process = Mock(pid=123, returncode=-1)
        process.communicate.return_value = (b"out", b"err")
        return process

    def expired(self):
        return subprocess.TimeoutExpired(["owned"], 1, output=b"partial", stderr=b"partial-err")

    @patch.dict("os.environ", {"SystemRoot": "C:/Windows"})
    def test_success_requires_killer_success_and_completed_pipe_drainage(self):
        with patch("subprocess.run", return_value=Mock(returncode=0, stdout=b"killed", stderr=b"")) as kill:
            stdout, stderr, cleanup = stop_owned(self.process(), self.expired(), windows=True)
        self.assertTrue(cleanup["confirmed"])
        self.assertEqual((stdout, stderr), (b"out", b"err"))
        self.assertEqual(kill.call_args.args[0][1:], ["/PID", "123", "/T", "/F"])

    @patch.dict("os.environ", {"SystemRoot": "C:/Windows"})
    def test_killer_errors_and_nonzero_are_not_confirmation(self):
        cases = [OSError("missing"), subprocess.TimeoutExpired(["taskkill"], 15),
                 Mock(returncode=1, stdout=b"", stderr=b"not killed")]
        for case in cases:
            kwargs = {"side_effect": case} if isinstance(case, Exception) else {"return_value": case}
            with self.subTest(case=case), patch("subprocess.run", **kwargs):
                _, _, cleanup = stop_owned(self.process(), self.expired(), windows=True)
            self.assertFalse(cleanup["confirmed"])
            self.assertTrue(cleanup["errors"])

    @patch.dict("os.environ", {"SystemRoot": "C:/Windows"})
    def test_incomplete_pipe_drainage_retains_partial_output_and_fails(self):
        process = self.process()
        process.communicate.side_effect = subprocess.TimeoutExpired(["owned"], 15)
        with patch("subprocess.run", return_value=Mock(returncode=0, stdout=b"", stderr=b"")):
            stdout, stderr, cleanup = stop_owned(process, self.expired(), windows=True)
        self.assertEqual((stdout, stderr), (b"partial", b"partial-err"))
        self.assertFalse(cleanup["confirmed"])
        self.assertTrue(cleanup["errors"])


class EntryFailClosed(unittest.TestCase):
    def fixture(self, root):
        (root / "tests").mkdir()
        (root / "SPEC.md").write_bytes(b"fixture spec")
        return {"EC_WORKLOAD_SOURCE": str(root), "EC_WORKLOAD_OUT": str(root / "out"),
                "EC_WORKLOAD_SHA": "1" * 40, "EC_WORKLOAD_REPOSITORY": "taipei49314/pinwash",
                "EC_WORKLOAD_NAME": "alpha2-verify"}

    def test_expired_budget_launches_nothing_and_writes_failure_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with patch.dict("os.environ", self.fixture(root)), \
                 patch("workloads.alpha2_verify.run.ROOT", root), \
                 patch("time.monotonic", side_effect=[0, 1141, 1141, 1141, 1141]), \
                 patch("subprocess.Popen") as launch:
                self.assertEqual(main(), 1)
            launch.assert_not_called()
            result = json.loads((root / "out" / "result.json").read_text(encoding="utf-8"))
            self.assertFalse(result["passed"])
            self.assertEqual([step["state"] for step in result["steps"]], ["NOT_RUN", "NOT_RUN"])

    def test_unconfirmed_cleanup_blocks_all_later_commands_and_writes_receipt(self):
        source, clean, suite = Mock(), Mock(), Mock()
        source.returncode = clean.returncode = 0
        source.communicate.return_value = (b"1" * 40 + b"\n", b"")
        clean.communicate.return_value = (b"", b"")
        suite.communicate.side_effect = subprocess.TimeoutExpired(["suite"], 570)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with patch.dict("os.environ", self.fixture(root)), \
                 patch("workloads.alpha2_verify.run.ROOT", root), \
                 patch("time.monotonic", return_value=0), \
                 patch("subprocess.Popen", side_effect=[source, clean, suite]) as launch, \
                 patch("workloads.alpha2_verify.run.stop_owned", return_value=(b"", b"partial", {"confirmed": False})):
                self.assertEqual(main(), 1)
            self.assertEqual(launch.call_count, 3)
            result = json.loads((root / "out" / "result.json").read_text(encoding="utf-8"))
            self.assertFalse(result["passed"])
            self.assertEqual(result["steps"][2]["state"], "TIMED_OUT")
            self.assertTrue(all(step["state"] == "NOT_RUN" for step in result["steps"][3:]))
