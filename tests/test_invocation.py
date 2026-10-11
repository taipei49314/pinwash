"""SPEC §1.3 for the judge's own process: the README recipe imports nothing
from the subject's directory.

`pinwash check` judges the directory it runs in, which the agent wrote.
`python -m` puts that directory first on sys.path, so a module or package
planted there runs before any pinwash code (runpy itself imports importlib
from sys.path) and can print any verdict; no code in pinwash can guard
against it. The recipe is `python -P -m pinwash` (or PYTHONSAFEPATH=1).
Each planted module only appends to a marker file in the test's temporary
directory, and the tests assert that the file does not exist afterwards.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SETTINGS = ".claude/settings.json"
STOP = json.dumps(
    {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python hooks/judge.py"}]}]}}
)
EMPTY = json.dumps({"hooks": {}})
# Imported by runpy, by pinwash, or both, before or while it judges.
PLANTED = ("importlib", "heapq", "json", "subprocess", "hashlib", "threading", "re")


class RecipeImportsNothingFromTheSubject(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="pinwash-invocation-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.mark = self.root / "planted.ran"
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("GIT_", "PYTHON"))}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        PINWASH_TODAY="2026-10-09", PYTHONPATH=str(ROOT))

    def git(self, repo: Path, *args: str) -> str:
        proc = subprocess.run(
            ["git", "-c", "user.name=pinwash", "-c", "user.email=pinwash@test",
             "-c", "commit.gpgsign=false", *args],
            cwd=repo, env=self.env, capture_output=True, check=True, timeout=60,
        )
        return proc.stdout.decode("utf-8").strip()

    def subject(self) -> tuple[Path, str]:
        """BASE holds a Stop judge, HEAD drops it, and the worktree holds
        planted modules and a planted pinwash package."""
        repo = self.root / "repo"
        (repo / ".claude").mkdir(parents=True)
        self.git(repo, "init", "-q", "-b", "main")
        (repo / SETTINGS).write_text(STOP, encoding="utf-8")
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-q", "-m", "base")
        base = self.git(repo, "rev-parse", "HEAD")
        (repo / SETTINGS).write_text(EMPTY, encoding="utf-8")
        self.git(repo, "commit", "-q", "-am", "weaken")
        body = f"open({str(self.mark)!r}, 'a').write(__name__ + '\\n')\n"
        for name in PLANTED:
            (repo / f"{name}.py").write_text(body, encoding="utf-8")
        (repo / "pinwash").mkdir()
        (repo / "pinwash" / "__init__.py").write_text(body, encoding="utf-8")
        (repo / "pinwash" / "__main__.py").write_text(
            body + "print('{\"verdict\": \"pass\"}')\n", encoding="utf-8")
        return repo, base

    def run_check(self, repo: Path, flags: list[str], *args: str,
                  extra: dict[str, str] | None = None) -> tuple[int, dict]:
        proc = subprocess.run(
            [sys.executable, *flags, "-m", "pinwash", "check", *args],
            cwd=repo, env={**self.env, **(extra or {})}, capture_output=True, timeout=120,
        )
        self.assertEqual(proc.stderr, b"")
        return proc.returncode, json.loads(proc.stdout.decode("utf-8"))

    def test_safe_path_flag_and_variable(self) -> None:
        repo, base = self.subject()
        for flags, extra in ((["-P"], None), ([], {"PYTHONSAFEPATH": "1"})):
            code, payload = self.run_check(repo, flags, f"{base}..HEAD", extra=extra)
            self.assertEqual(code, 1)
            self.assertEqual([f["rule"] for f in payload["findings"]], ["HOOK_REMOVED"])
            code, payload = self.run_check(repo, flags, extra=extra)
            self.assertEqual((code, payload["verdict"]), (0, "pass"))
            self.assertEqual(payload["run"]["head"], "WORKTREE")
        self.assertFalse(self.mark.exists())


if __name__ == "__main__":
    unittest.main()
