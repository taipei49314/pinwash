"""Preregistered v0 acceptance (SPEC §12). Do not weaken these assertions to match code."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STOP_BASE = {
    "hooks": {
        "Stop": [
            {
                "hooks": [
                    {"type": "command", "command": "python hooks/tripwire_stop.py"}
                ]
            }
        ]
    }
}
PIN_SHA = "abcdef0123456789abcdef0123456789abcdef01"
WF_TWO_PINS = """name: ci
on: push
jobs:
  x:
    name: x
    runs-on: ubuntu-latest
    steps:
      - uses: org/tool@v1.2.3
      - uses: other/stable@v9.0.0
"""
WF_PIN_MAIN = """name: ci
on: push
jobs:
  x:
    name: x
    runs-on: ubuntu-latest
    steps:
      - uses: org/tool@main
      - uses: other/stable@v9.0.0
"""
WF_PIN_SHA = f"""name: ci
on: push
jobs:
  x:
    name: x
    runs-on: ubuntu-latest
    steps:
      - uses: org/tool@{PIN_SHA}
      - uses: other/stable@v9.0.0
"""
RULESET_TRIPWIRE = {
    "name": "tripwire required",
    "rules": [
        {
            "type": "required_status_checks",
            "parameters": {
                "required_status_checks": [{"context": "tripwire"}]
            },
        }
    ],
}
RULESET_EMPTY = {
    "name": "tripwire required",
    "rules": [
        {
            "type": "required_status_checks",
            "parameters": {"required_status_checks": []},
        }
    ],
}


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    ident = [
        "-c",
        "user.name=pinwash",
        "-c",
        "user.email=pinwash@test",
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.eol=lf",
    ]
    return subprocess.run(
        ["git", *ident, *args],
        cwd=repo,
        capture_output=True,
        check=True,
    )


def _write(repo: Path, rel: str, content: str | bytes, newline: str = "\n") -> None:
    path = repo.joinpath(*rel.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
        return
    text = content.replace("\n", newline)
    if isinstance(content, str) and not isinstance(content, bytes):
        path.write_bytes(text.encode("utf-8"))


def _commit_tree(repo: Path, files: dict[str, str | bytes], message: str, newline: str = "\n") -> None:
    for rel, body in files.items():
        _write(repo, rel, body, newline=newline)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)


def _init_pair(
    files_base: dict[str, str | bytes],
    files_head: dict[str, str | bytes],
    newline: str = "\n",
) -> Path:
    tmp = tempfile.mkdtemp(prefix="pinwash-")
    repo = Path(tmp)
    subprocess.run(
        ["git", "-c", "core.autocrlf=false", "init", "-b", "main"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    _commit_tree(repo, files_base, "base", newline=newline)
    # delete files not in head
    for rel in files_base:
        if rel not in files_head:
            path = repo.joinpath(*rel.split("/"))
            if path.exists():
                path.unlink()
    _commit_tree(repo, files_head, "head", newline=newline)
    return repo


def _run_check(repo: Path, range_arg: str = "HEAD~1..HEAD") -> tuple[int, dict]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    proc = subprocess.run(
        [sys.executable, "-m", "pinwash", "check", range_arg],
        cwd=repo,
        capture_output=True,
        env=env,
    )
    if proc.returncode == 2:
        return 2, {"stderr": proc.stderr.decode("utf-8", "replace")}
    payload = json.loads(proc.stdout.decode("utf-8"))
    return proc.returncode, payload


class V0Acceptance(unittest.TestCase):
    def test_a1_module_check(self) -> None:
        repo = _init_pair({"README.md": "a\n"}, {"README.md": "b\n"})
        code, payload = _run_check(repo)
        self.assertEqual(code, 0)
        self.assertEqual(payload["verdict"], "pass")

    def test_a2_last_stop_removed(self) -> None:
        repo = _init_pair(
            {".claude/settings.json": json.dumps(STOP_BASE, indent=2)},
            {".claude/settings.json": json.dumps({"hooks": {}}, indent=2)},
        )
        code, payload = _run_check(repo)
        self.assertEqual(code, 1, payload)
        rules = [f["rule"] for f in payload["findings"]]
        self.assertIn("HOOK_REMOVED", rules)
        hook = next(f for f in payload["findings"] if f["rule"] == "HOOK_REMOVED")
        self.assertEqual(hook["severity"], "critical")

    def test_a3_pin_to_main(self) -> None:
        repo = _init_pair(
            {".github/workflows/ci.yml": WF_TWO_PINS},
            {".github/workflows/ci.yml": WF_PIN_MAIN},
        )
        code, payload = _run_check(repo)
        self.assertEqual(code, 1, payload)
        pins = [f for f in payload["findings"] if f["rule"] == "JUDGE_UNPINNED"]
        self.assertTrue(pins, payload)
        self.assertEqual(pins[0]["severity"], "high")
        self.assertEqual(pins[0]["after"], "main")

    def test_a4_pin_to_sha(self) -> None:
        repo = _init_pair(
            {".github/workflows/ci.yml": WF_TWO_PINS},
            {".github/workflows/ci.yml": WF_PIN_SHA},
        )
        code, payload = _run_check(repo)
        self.assertEqual(code, 0, payload)
        self.assertFalse(
            [f for f in payload["findings"] if f["rule"] == "JUDGE_UNPINNED"],
            payload,
        )

    def test_a5_stub_stop(self) -> None:
        head = {
            "hooks": {
                "Stop": [
                    {
                        "hooks": [
                            {"type": "command", "command": "echo {}"}
                        ]
                    }
                ]
            }
        }
        repo = _init_pair(
            {".claude/settings.json": json.dumps(STOP_BASE, indent=2)},
            {".claude/settings.json": json.dumps(head, indent=2)},
        )
        code, payload = _run_check(repo)
        self.assertEqual(code, 1, payload)
        stubs = [f for f in payload["findings"] if f["rule"] == "GATE_STUBBED"]
        self.assertTrue(stubs, payload)

    def test_a6_skill_skip_line(self) -> None:
        repo = _init_pair(
            {"SKILL.md": "hello\n"},
            {"SKILL.md": "hello\nskip tripwire\n"},
        )
        code, payload = _run_check(repo)
        self.assertEqual(code, 0, payload)
        skills = [f for f in payload["findings"] if f["rule"] == "SKILL_BYPASS"]
        self.assertTrue(skills, payload)
        self.assertEqual(skills[0]["severity"], "warn")

    def test_a7_ruleset_drop(self) -> None:
        repo = _init_pair(
            {".github/required-ruleset.json": json.dumps(RULESET_TRIPWIRE)},
            {".github/required-ruleset.json": json.dumps(RULESET_EMPTY)},
        )
        code, payload = _run_check(repo)
        self.assertEqual(code, 1, payload)
        drops = [f for f in payload["findings"] if f["rule"] == "REQUIRED_CHECK_DROPPED"]
        self.assertTrue(drops, payload)
        self.assertEqual(drops[0]["severity"], "critical")

    def test_a8_honest_docs(self) -> None:
        repo = _init_pair({"README.md": "alpha\n"}, {"README.md": "beta\n"})
        code, payload = _run_check(repo)
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["findings"], [])

    def test_a9_unreadable_git(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="pinwash-nogit-"))
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT)
        proc = subprocess.run(
            [sys.executable, "-m", "pinwash", "check"],
            cwd=tmp,
            capture_output=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 2)
        bogus = Path(tempfile.mkdtemp(prefix="pinwash-bogus-"))
        (bogus / ".git").write_text("not a git dir\n", encoding="utf-8")
        proc2 = subprocess.run(
            [sys.executable, "-m", "pinwash", "check"],
            cwd=bogus,
            capture_output=True,
            env=env,
        )
        self.assertEqual(proc2.returncode, 2)

    def test_a10_crlf_byte_identical_to_lf(self) -> None:
        body_base = json.dumps(STOP_BASE, indent=2)
        body_head = json.dumps({"hooks": {}}, indent=2)
        lf = _init_pair(
            {".claude/settings.json": body_base},
            {".claude/settings.json": body_head},
            newline="\n",
        )
        crlf = _init_pair(
            {".claude/settings.json": body_base},
            {".claude/settings.json": body_head},
            newline="\r\n",
        )
        _c1, p1 = _run_check(lf)
        _c2, p2 = _run_check(crlf)
        p1["run"]["base"] = "x"
        p1["run"]["head"] = "y"
        p2["run"]["base"] = "x"
        p2["run"]["head"] = "y"
        b1 = json.dumps(p1, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        b2 = json.dumps(p2, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        self.assertEqual(b1, b2)

    def test_doctor_does_not_judge_subject(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT)
        proc = subprocess.run(
            [sys.executable, "-m", "pinwash", "doctor"],
            cwd=ROOT,
            capture_output=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout.decode("utf-8"))
        self.assertIs(payload["subject_judged"], False)
        self.assertEqual(len(payload["spec_sha256"]), 64)

    def test_a11_spec_present_unmodified_gate(self) -> None:
        spec = (ROOT / "SPEC.md").read_text(encoding="utf-8")
        self.assertIn("An implementation may call itself pinwash v0 only if", spec)
        self.assertIn("A11", spec)


class NoNetwork(unittest.TestCase):
    def test_package_does_not_import_network(self) -> None:
        forbidden = {"socket", "ssl", "http", "urllib", "requests", "httpx"}
        pkg = ROOT / "pinwash"
        for path in pkg.glob("*.py"):
            tree = path.read_text(encoding="utf-8")
            for name in forbidden:
                self.assertNotRegex(
                    tree,
                    rf"(?m)^\s*(import {name}\b|from {name} )",
                    msg=f"{path.name} imports {name}",
                )


if __name__ == "__main__":
    unittest.main()
