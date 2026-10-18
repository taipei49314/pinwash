"""Spec 29: claude_settings reads no §5.1 skip key (SPEC §3.3, §5, §5.1,
§5.2, §7, R06; taipei49314/pinwash#42), AI-assisted.

Host reading (Claude Code 2.1.42 and 2.1.296, executed in #42): a Stop hook
whose item carries `"disabled": true`, `"hookEnabled": false`,
`"continueOnError": true` or `"failOpen": true`, or whose matcher group
carries `"disabled": true`, still runs and still refuses; the other group
keys and other events are read the same way (INFERRED, SPEC §5.1). On
claude_settings the keys are therefore unknown keys:
adding one is no finding, a command that carries one is active and live,
the settings-root switch counts it, and a non-boolean value has no row.
cursor_hooks keeps the spec 10 skip flags unchanged.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair

ENV = {"PINWASH_TODAY": "2026-10-18"}
CS = ".claude/settings.json"
CH = ".cursor/hooks.json"
T = "python hooks/judge.py"
T2 = "python hooks/judge2.py"
G = "python hooks/guard.py"
N = "python hooks/noop.py"
REAL = b"import json, sys\nprint(json.dumps({'decision': 'block'}))\nsys.exit(0)\n"
GUT = (
    b"import json, sys\n"
    b"def main() -> int:\n"
    b"    print(json.dumps({\"decision\": \"approve\"}))\n"
    b"    return 0\n"
    b"sys.exit(main())\n"
)
TREE = {"hooks/judge.py": REAL, "hooks/judge2.py": REAL, "hooks/guard.py": REAL}
KEYS = (("disabled", True), ("hookEnabled", False), ("continueOnError", True), ("failOpen", True))
FLAG_ROW = "hook skip flag value not boolean"
SELECTOR_ROW = "hook selector changed (not evaluated)"


def _cmd(command: str, **extra: Any) -> dict[str, Any]:
    return {"type": "command", "command": command, **extra}


def _claude(*cmds: Any, event: str = "Stop", group: dict[str, Any] | None = None,
            root: dict[str, Any] | None = None) -> str:
    entry = dict(group or {}, hooks=[c if isinstance(c, dict) else _cmd(c) for c in cmds])
    return json.dumps(dict(root or {}, hooks={event: [entry]}))


def _cursor(*cmds: Any, event: str = "stop") -> str:
    return json.dumps({"version": 1, "hooks": {event: [c if isinstance(c, dict) else {"command": c} for c in cmds]}})


def _scan(base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    enc = lambda t: {k: v if isinstance(v, bytes) else v.encode() for k, v in {**TREE, **t}.items()}
    return scan_pair(enc(base), enc(head), base_label="base", head_label="head", env=ENV)


def _rules(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["rule"], f["severity"]) for f in payload["findings"]]


def _reasons(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(u["path"], u["reason"]) for u in payload["unknown_coverage"]]


class SkipKeysAreNotRead(unittest.TestCase):
    """Q1 (#42): no finding, no liveness effect and no row on claude_settings."""

    def test_a_key_on_the_only_stop_judge_is_no_finding(self) -> None:
        for key, value in KEYS:
            for level in ("item", "group"):
                with self.subTest(key=key, level=level):
                    if level == "item":
                        head = _claude(_cmd(T, **{key: value}))
                    else:
                        head = _claude(T, group={key: value})
                    payload = _scan({CS: _claude(T)}, {CS: head})
                    self.assertEqual((payload["findings"], payload["unknown_coverage"]), ([], []))
                    self.assertEqual(payload["verdict"], "pass")

    def test_cursor_keeps_the_skip_flags(self) -> None:
        for key, value in KEYS:
            with self.subTest(key=key):
                payload = _scan({CH: _cursor(T)}, {CH: _cursor({"command": T, key: value})})
                self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])
                self.assertEqual(payload["findings"][0]["message"], "hook event stop skip flag added")

    def test_the_list_form_reads_no_key_either(self) -> None:
        base = json.dumps({"hooks": [{"event": "Stop", "command": T}]})
        head = json.dumps({"hooks": [{"event": "Stop", "command": T, "disabled": True}]})
        payload = _scan({CS: base}, {CS: head})
        self.assertEqual((payload["findings"], payload["unknown_coverage"]), ([], []))

    def test_disable_and_replace_keeps_the_old_judge(self) -> None:
        # The host still runs the flagged judge (#42, M15/K06): nothing left.
        payload = _scan({CS: _claude(T)}, {CS: _claude(_cmd(T, disabled=True), T2)})
        self.assertEqual((payload["findings"], payload["unknown_coverage"]), ([], []))


class FlaggedCommandsAreLive(unittest.TestCase):
    """Q2 (#42): a command that carries a key counts like any other."""

    def test_a_flagged_judge_keeps_a_sibling_stub_at_warn(self) -> None:
        base = _claude(_cmd(T, disabled=True), T2)
        head = _claude(_cmd(T, disabled=True), "true")
        payload = _scan({CS: base}, {CS: head})
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "warn")])

    def test_a_flagged_judge_removed_beside_a_stub_is_hook_removed(self) -> None:
        payload = _scan({CS: _claude(_cmd(T, disabled=True), "true")}, {CS: _claude("true")})
        self.assertEqual(
            [(f["rule"], f["severity"], f["message"], f["before"]) for f in payload["findings"]],
            [("HOOK_REMOVED", "critical", "hook event Stop keeps no live command", T)],
        )

    def test_a_flagged_judge_retargeted_to_a_body_that_cannot_refuse_blocks(self) -> None:
        # Through spec 28 the flagged judge was not active, so its retarget
        # was no finding; it is the §5 retarget now (pass to block).
        payload = _scan({CS: _claude(_cmd(T, disabled=True))},
                        {CS: _claude(N), "hooks/noop.py": GUT})
        self.assertEqual(
            [(f["rule"], f["severity"], f["message"], f["before"], f["after"]) for f in payload["findings"]],
            [("GATE_STUBBED", "critical", "hook command for Stop retargeted to a body that cannot refuse", T, N)],
        )
        self.assertEqual(payload["unknown_coverage"], [])

    def test_an_added_flagged_judge_that_can_refuse_holds_a_gut_at_warn(self) -> None:
        # Through spec 28 the added flagged judge was not live, so the gut
        # was the last Stop judge gone (critical); it counts now (§6.1).
        payload = _scan({CS: _claude(T)},
                        {CS: _claude(T, _cmd(T2, disabled=True)), "hooks/judge.py": GUT})
        self.assertEqual(
            [(f["rule"], f["severity"], f["message"]) for f in payload["findings"]],
            [("GATE_STUBBED", "warn", "hook command for Stop lost block capability")],
        )
        self.assertEqual(payload["unknown_coverage"], [])

    def test_switch_over_a_flagged_only_stop_judge_is_critical(self) -> None:
        base = _claude(_cmd(T, disabled=True))
        head = _claude(_cmd(T, disabled=True), root={"disableAllHooks": True})
        payload = _scan({CS: base}, {CS: head})
        self.assertEqual(
            [(f["rule"], f["severity"], f["locator"]) for f in payload["findings"]],
            [("HOOK_BYPASSED", "critical", "disableAllHooks")],
        )
        self.assertEqual(payload["unknown_coverage"], [])


class RowsReadTheCommand(unittest.TestCase):
    """§5.1, §7 (spec 29): rows on claude_settings ignore the keys."""

    def test_a_non_boolean_value_is_a_row_on_cursor_only(self) -> None:
        for value in ("true", 1, None):
            with self.subTest(value=value):
                claude = _scan({CS: _claude(T)}, {CS: _claude(_cmd(T, disabled=value))})
                self.assertEqual((claude["findings"], claude["unknown_coverage"]), ([], []))
                cursor = _scan({CH: _cursor(T)}, {CH: _cursor({"command": T, "disabled": value})})
                self.assertEqual((cursor["findings"], _reasons(cursor)), ([], [(CH, FLAG_ROW)]))

    def test_a_selector_change_on_a_flagged_command_is_the_row(self) -> None:
        base = _claude(_cmd(G, disabled=True), event="PreToolUse", group={"matcher": "Bash"})
        head = _claude(_cmd(G, disabled=True), event="PreToolUse", group={"matcher": "NoSuchTool"})
        payload = _scan({CS: base}, {CS: head})
        self.assertEqual((payload["findings"], _reasons(payload)), ([], [(CS, SELECTOR_ROW)]))

    def test_cursor_reads_no_selector_on_a_flagged_command(self) -> None:
        base = _cursor({"command": G, "matcher": "Bash", "disabled": True}, event="preToolUse")
        head = _cursor({"command": G, "matcher": "NoSuchTool", "disabled": True}, event="preToolUse")
        payload = _scan({CH: base}, {CH: head})
        self.assertEqual((payload["findings"], payload["unknown_coverage"]), ([], []))


if __name__ == "__main__":
    unittest.main()
