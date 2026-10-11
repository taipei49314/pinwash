"""SPEC §3.3 (spec 26, AI-assisted ruling R-18a(c), hook-project-dir Q1,
Q2, Q4): the closed project-root forms of a claude_settings hook command."""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair
from pinwash.parse.hookcmd import hook_command_targets, strip_project_root

CS = ".claude/settings.json"
CUR = ".cursor/hooks.json"
ENV = {"PINWASH_TODAY": "2026-10-09"}
J = ".claude/hooks/judge.sh"
REAL_SH = "#!/usr/bin/env bash\nif ! make test >/dev/null 2>&1; then\n  echo '{\"decision\": \"block\"}'\nfi\n"
GUT_SH = "#!/usr/bin/env bash\nexit 0\n"
FRAME_GUT = "#!/usr/bin/env bash\nmake test >/dev/null 2>&1 || true\n"
FILES = {J: b"x", "hooks/judge.py": b"x", "setenv.sh": b"x"}


def _hook(cmd: str, **extra: Any) -> dict[str, Any]:
    return dict({"type": "command", "command": cmd}, **extra)


def _settings(*hooks: dict[str, Any], event: str = "Stop", root: dict[str, Any] | None = None) -> str:
    doc: dict[str, Any] = {"hooks": {event: [{"hooks": list(hooks)}]}}
    doc.update(root or {})
    return json.dumps(doc)


def _scan(base: dict[str, str], head: dict[str, str]) -> dict[str, Any]:
    return scan_pair({k: v.encode() for k, v in base.items()}, {k: v.encode() for k, v in head.items()},
                     base_label="b", head_label="h", env=ENV)


def _targets(cmd: str) -> list[str]:
    return hook_command_targets(cmd, FILES, project_root=True)


class ClosedForms(unittest.TestCase):
    def test_each_form_resolves(self) -> None:
        for cmd in (
            '"$CLAUDE_PROJECT_DIR"/.claude/hooks/judge.sh',
            '"${CLAUDE_PROJECT_DIR}"/.claude/hooks/judge.sh',
            "$CLAUDE_PROJECT_DIR/.claude/hooks/judge.sh",
            "${CLAUDE_PROJECT_DIR}/.claude/hooks/judge.sh",
            '"$CLAUDE_PROJECT_DIR/.claude/hooks/judge.sh"',
            '"${CLAUDE_PROJECT_DIR}/.claude/hooks/judge.sh" --hook',
            'bash "$CLAUDE_PROJECT_DIR"/.claude/hooks/judge.sh',
            'uv run --script "$CLAUDE_PROJECT_DIR/.claude/hooks/judge.sh"',
            'CLAUDE_PROJECT_DIR=/tmp/decoy "$CLAUDE_PROJECT_DIR"/.claude/hooks/judge.sh',
            'exec "$CLAUDE_PROJECT_DIR"/.claude/hooks/judge.sh 2>&1',
            '"$CLAUDE_PROJECT_DIR"/.claude/hooks/judge.sh; echo done',
            '"$CLAUDE_PROJECT_DIR"/.claude/hooks/judge.sh || true',
            '"$CLAUDE_PROJECT_DIR"/./.claude/hooks/judge.sh',
        ):
            with self.subTest(cmd=cmd):
                self.assertEqual(_targets(cmd), [J])

    def test_spellings_the_shell_runs_elsewhere_or_after_a_reassignment_do_not_resolve(self) -> None:
        for cmd in (
            "'$CLAUDE_PROJECT_DIR'/.claude/hooks/judge.sh",   # a directory literally so named
            "\\$CLAUDE_PROJECT_DIR/.claude/hooks/judge.sh",   # same
            "'$CLAUDE_PROJECT_DIR/.claude/hooks/judge.sh'",
            "%CLAUDE_PROJECT_DIR%/.claude/hooks/judge.sh",    # literal on a POSIX shell
            "$env:CLAUDE_PROJECT_DIR/.claude/hooks/judge.sh",
            "CLAUDE_PROJECT_DIR=decoy; \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/judge.sh",
            "CLAUDE_PROJECT_DIR=decoy\n\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/judge.sh",
            "export CLAUDE_PROJECT_DIR=decoy && \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/judge.sh",
            "for CLAUDE_PROJECT_DIR in decoy; do \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/judge.sh; done",
            "echo $((CLAUDE_PROJECT_DIR=0)) \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/judge.sh",
            "env CLAUDE_PROJECT_DIR=decoy sh -c '\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/judge.sh'",
            "\"${CLAUDE_PROJECT_DIR:-.}\"/.claude/hooks/judge.sh",
            "\"$CLAUDE_PROJECT_DIR\"//.claude/hooks/judge.sh",
            "\"$CLAUDE_PROJECT_DIR\"/x/../.claude/hooks/judge.sh",
            "\"$CLAUDE_PROJECT_DIR/my dir/../.claude/hooks/judge.sh\"",
            "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/judge.sh.bak",
            # a redirection glued to the path: §3.3's tokenizer does not split
            # at `>`, for a plain path as for a rewritten one
            "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/judge.sh>/dev/null",
        ):
            with self.subTest(cmd=cmd):
                self.assertEqual(_targets(cmd), [])

    def test_sourced_file_resolves_as_before_but_the_form_after_it_does_not(self) -> None:
        self.assertEqual(_targets('. ./setenv.sh && "$CLAUDE_PROJECT_DIR"/.claude/hooks/judge.sh'),
                         ["setenv.sh"])

    def test_rewrite_keeps_the_rest_of_the_command(self) -> None:
        self.assertEqual(strip_project_root('python3 "$CLAUDE_PROJECT_DIR"/hooks/judge.py --x; echo "$Y"'),
                         'python3 hooks/judge.py --x; echo "$Y"')

    def test_without_project_root_nothing_changes(self) -> None:
        self.assertEqual(hook_command_targets('"$CLAUDE_PROJECT_DIR"/.claude/hooks/judge.sh', FILES), [])


class Detection(unittest.TestCase):
    CMD = '"$CLAUDE_PROJECT_DIR"/.claude/hooks/judge.sh'

    def test_gut_behind_an_unchanged_form_blocks_on_the_last_stop(self) -> None:
        for gut, message in ((GUT_SH, "resolves to a stub body"), (FRAME_GUT, "lost block capability")):
            with self.subTest(message=message):
                payload = _scan({CS: _settings(_hook(self.CMD)), J: REAL_SH}, {CS: _settings(_hook(self.CMD)), J: gut})
                self.assertEqual(payload["verdict"], "block")
                self.assertEqual([(f["rule"], f["severity"], f["message"]) for f in payload["findings"]],
                                 [("GATE_STUBBED", "critical", f"hook command for Stop {message}")])
                self.assertEqual(payload["unknown_coverage"], [])

    def test_settings_env_does_not_stop_resolution(self) -> None:
        # Host evidence: Claude Code sets CLAUDE_PROJECT_DIR after the
        # settings env, so an env value redirects nothing.
        root = {"env": {"CLAUDE_PROJECT_DIR": "decoy"}}
        payload = _scan({CS: _settings(_hook(self.CMD), root=root), J: REAL_SH},
                        {CS: _settings(_hook(self.CMD), root=root), J: GUT_SH, "decoy/" + J: REAL_SH})
        self.assertEqual(payload["verdict"], "block")

    def test_exec_form_and_non_bash_shell_are_not_read(self) -> None:
        for extra in ({"args": []}, {"args": ["--x"]}, {"shell": "powershell"}, {"shell": None}):
            with self.subTest(extra=extra):
                payload = _scan({CS: _settings(_hook(self.CMD, **extra)), J: REAL_SH},
                                {CS: _settings(_hook(self.CMD, **extra)), J: GUT_SH})
                self.assertEqual(payload["verdict"], "pass")
                self.assertEqual(payload["findings"], [])
        payload = _scan({CS: _settings(_hook(self.CMD, shell="bash")), J: REAL_SH},
                        {CS: _settings(_hook(self.CMD, shell="bash")), J: GUT_SH})
        self.assertEqual(payload["verdict"], "block")

    def test_cursor_hooks_do_not_read_the_forms(self) -> None:
        cur = lambda: json.dumps({"version": 1, "hooks": {"stop": [{"command": self.CMD}]}})
        payload = _scan({CUR: cur(), J: REAL_SH}, {CUR: cur(), J: GUT_SH})
        self.assertEqual(payload["verdict"], "pass")
        self.assertEqual(payload["findings"], [])

    def test_honest_migration_and_body_edit_get_no_row(self) -> None:
        plain = ".claude/hooks/judge.sh"
        migrate = _scan({CS: _settings(_hook(plain)), J: REAL_SH}, {CS: _settings(_hook(self.CMD)), J: REAL_SH})
        self.assertEqual((migrate["findings"], migrate["unknown_coverage"]), ([], []))
        edit = _scan({CS: _settings(_hook(self.CMD)), J: REAL_SH},
                     {CS: _settings(_hook(self.CMD)), J: REAL_SH + "echo checked >&2\n"})
        self.assertEqual((edit["findings"], edit["unknown_coverage"], edit["verdict"]), ([], [], "pass"))

    def test_respelling_out_of_the_forms_is_a_row(self) -> None:
        payload = _scan({CS: _settings(_hook(self.CMD)), J: REAL_SH},
                        {CS: _settings(_hook('"${CLAUDE_PROJECT_DIR:-.}"/.claude/hooks/judge.sh')), J: GUT_SH})
        self.assertEqual(payload["verdict"], "pass")
        self.assertIn("hook command target no longer resolved",
                      [u["reason"] for u in payload["unknown_coverage"]])


if __name__ == "__main__":
    unittest.main()
