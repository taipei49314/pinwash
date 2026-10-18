"""Spec 27: R12 detection (SPEC §5, §5.1, §5.2, §6.1; #10), the
hook-liveness ruling as the challenger amended it, AI-assisted.

* A Stop-like judge retargeted to a body that cannot refuse is GATE_STUBBED,
  and the new command is not live (§5.2).
* A command added to a Stop-like event keeps the §6.1 escalator off only
  when it resolves to a body that can refuse.
* An event that keeps commands but no live one, after a command live at base
  left it, is HOOK_REMOVED.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair

ENV = {"PINWASH_TODAY": "2026-10-09"}
CS = ".claude/settings.json"
CH = ".cursor/hooks.json"
T = "python hooks/judge.py"
T2 = "python hooks/judge2.py"
J, J2 = "hooks/judge.py", "hooks/judge2.py"
REAL = (
    "import json, sys\n"
    "def main() -> int:\n"
    "    if not sys.stdin.read():\n"
    '        print(json.dumps({"decision": "block", "reason": "no input"}))\n'
    "        return 0\n"
    '    print(json.dumps({"decision": "approve"}))\n'
    "    return 0\n"
    "sys.exit(main())\n"
)
GUT = (
    "import json, sys\n"
    "def main() -> int:\n"
    '    print(json.dumps({"decision": "approve"}))\n'
    "    return 0\n"
    "sys.exit(main())\n"
)
RETARGETED = "hook command for Stop retargeted to a body that cannot refuse"


def _hooks(event: str, cmds: list[Any], path: str = CS) -> str:
    items = [c if isinstance(c, dict) else {"type": "command", "command": c} for c in cmds]
    if path == CH:
        return json.dumps({"version": 1, "hooks": {event: items}})
    return json.dumps({"hooks": {event: [{"hooks": items}]}})


def _scan(base: dict[str, str], head: dict[str, str]) -> dict[str, Any]:
    return scan_pair({k: v.encode() for k, v in base.items()}, {k: v.encode() for k, v in head.items()},
                     base_label="base", head_label="head", env=ENV)


def _rules(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["rule"], f["severity"]) for f in payload["findings"]]


class Retarget(unittest.TestCase):
    def test_judge_retargeted_to_a_gutted_copy_blocks(self) -> None:
        for keep_old in (False, True):
            with self.subTest(keep_old=keep_old):
                head = {CS: _hooks("Stop", [T2]), J2: GUT}
                if keep_old:
                    head[J] = REAL
                payload = _scan({CS: _hooks("Stop", [T]), J: REAL}, head)
                self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])
                f = payload["findings"][0]
                self.assertEqual((f["message"], f["before"], f["after"], f["locator"]),
                                 (RETARGETED, T, T2, "Stop:" + T2))

    def test_cursor_stop_retarget_blocks(self) -> None:
        payload = _scan({CH: _hooks("stop", [T], CH), J: REAL}, {CH: _hooks("stop", [T2], CH), J2: GUT})
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])

    def test_retarget_beside_a_pre_existing_live_hook_is_warn(self) -> None:
        fmt = {"hooks/fmt.sh": "#!/bin/sh\nnpx prettier --check .\n"}
        payload = _scan({CS: _hooks("Stop", ["bash hooks/fmt.sh", T]), J: REAL, **fmt},
                        {CS: _hooks("Stop", ["bash hooks/fmt.sh", T2]), J2: GUT, **fmt})
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "warn")])

    def test_moves_that_keep_a_body_that_can_refuse_are_silent(self) -> None:
        for new, files in ((T2, {J2: REAL}),
                           ("python3 hooks/judge.py", {J: REAL}),
                           ("python .claude/hooks/judge.py", {".claude/hooks/judge.py": REAL}),
                           (T2, {J2: REAL.replace('"block"', '"deny"')})):
            with self.subTest(new=new):
                payload = _scan({CS: _hooks("Stop", [T]), J: REAL}, {CS: _hooks("Stop", [new]), **files})
                self.assertEqual(payload["findings"], [])

    def test_base_body_without_a_decision_literal_is_not_read_as_a_judge(self) -> None:
        # Real-world false positive the decision literal removes: a Stop
        # hook that archives the transcript loops over content blocks
        # (`for block in content`), so it mentions `block` but refuses
        # nothing; replacing it is not a retarget.
        archive = "import json, sys\nfor block in json.load(sys.stdin).get('content', []):\n    print(block)\n"
        payload = _scan({CS: _hooks("Stop", ["python hooks/archive.py"]), "hooks/archive.py": archive},
                        {CS: _hooks("Stop", ["bash hooks/stop.sh"]), "hooks/stop.sh": "#!/bin/sh\ntrue x\n"})
        self.assertEqual(payload["findings"], [])

    def test_copy_that_keeps_a_marker_is_silent_r07(self) -> None:
        kept = GUT.replace("import json, sys\n", "import json, sys\n# never block here\n")
        payload = _scan({CS: _hooks("Stop", [T]), J: REAL}, {CS: _hooks("Stop", [T2]), J2: kept})
        self.assertEqual(payload["findings"], [])

    def test_project_root_retarget_is_a_finding(self) -> None:
        # Spec 26 resolves the project-root forms, so a retarget into one
        # is read like a plain one (D09).
        payload = _scan({CS: _hooks("Stop", [T]), J: REAL},
                        {CS: _hooks("Stop", ['python "$CLAUDE_PROJECT_DIR"/hooks/judge2.py']), J2: GUT})
        self.assertEqual([(f["rule"], f["severity"], f["message"]) for f in payload["findings"]],
                         [("GATE_STUBBED", "critical", "hook command for Stop retargeted to a body that cannot refuse")])

    def test_unresolved_retarget_is_a_row_not_a_finding(self) -> None:
        payload = _scan({CS: _hooks("Stop", [T]), J: REAL},
                        {CS: _hooks("Stop", ['python "${CLAUDE_PROJECT_DIR:-.}"/hooks/judge2.py']), J2: GUT})
        self.assertEqual(payload["findings"], [])
        self.assertIn("hook command target no longer resolved",
                      [u["reason"] for u in payload["unknown_coverage"]])

    def test_other_events_are_not_read(self) -> None:
        guard = "import json, sys\nprint(json.dumps({'decision': 'block'}))\n"
        payload = _scan({CS: _hooks("PreToolUse", ["python hooks/guard.py"]), "hooks/guard.py": guard},
                        {CS: _hooks("PreToolUse", ["python hooks/guard2.py"]),
                         "hooks/guard2.py": "import json, sys\nsys.stdin.read()\nprint(json.dumps({}))\n"})
        self.assertEqual(payload["findings"], [])

    def test_commented_judge_with_a_new_sibling_is_the_comment_out_finding(self) -> None:
        payload = _scan({CS: _hooks("Stop", [T]), J: REAL},
                        {CS: _hooks("Stop", ["python hooks/ok.py", "# " + T]), J: REAL,
                         "hooks/ok.py": "print('{}')\nx = 1\n"})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])


class AddedSiblings(unittest.TestCase):
    def test_added_sibling_counts_only_when_it_can_refuse(self) -> None:
        for sibling, files, severity in (
            ("echo ok", {}, "critical"),
            ("npx tripwire-judge", {}, "critical"),
            (T2, {J2: GUT}, "critical"),
            (T2, {J2: REAL}, "warn"),
        ):
            with self.subTest(sibling=sibling, severity=severity):
                payload = _scan({CS: _hooks("Stop", [T]), J: REAL},
                                {CS: _hooks("Stop", [T, sibling]), J: GUT, **files})
                self.assertEqual(_rules(payload), [("GATE_STUBBED", severity)])

    def test_respelling_is_not_an_added_command(self) -> None:
        fmt = {"hooks/fmt.sh": "#!/bin/sh\nnpx prettier --check .\n"}
        payload = _scan({CS: _hooks("Stop", [T, "bash hooks/fmt.sh"]), J: REAL, **fmt},
                        {CS: _hooks("Stop", [T, "sh hooks/fmt.sh"]), J: GUT, **fmt})
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "warn")])

    def test_disable_and_replace_with_a_judge_that_can_refuse_is_warn(self) -> None:
        # The skip flag is read on cursor_hooks only since spec 29 (§5.1, #42).
        payload = _scan({CH: _hooks("stop", [T], CH), J: REAL},
                        {CH: _hooks("stop", [{"type": "command", "command": T, "disabled": True}, T2], CH),
                         J: REAL, J2: REAL})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "warn")])

    def test_claude_disable_and_replace_is_no_finding(self) -> None:
        # Spec 29 (§5.1, AI-assisted ruling on #42): Claude Code runs a hook
        # that carries a skip key (executed), so the old judge keeps running
        # beside the added one and the diff weakens nothing.
        payload = _scan({CS: _hooks("Stop", [T]), J: REAL},
                        {CS: _hooks("Stop", [{"type": "command", "command": T, "disabled": True}, T2]),
                         J: REAL, J2: REAL})
        self.assertEqual(payload["findings"], [])

    def test_disclosed_cost_helper_refactor_beside_an_added_formatter_blocks(self) -> None:
        # The spec 7 shape's known honest false positive (`block` moved into
        # a helper module) already blocks unshifted; an added formatter no
        # longer keeps it at warn.
        refac = "import sys\nfrom decide import verdict\nprint(verdict(sys.stdin.read()))\n"
        payload = _scan({CS: _hooks("Stop", [T]), J: REAL},
                        {CS: _hooks("Stop", ["bash hooks/fmt.sh", T]), J: refac,
                         "hooks/decide.py": "def verdict(t):\n    return {'decision': 'block'}\n",
                         "hooks/fmt.sh": "#!/bin/sh\nnpx prettier --check .\n"})
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])


class EventKeepsNoLiveCommand(unittest.TestCase):
    def test_honest_placeholder_removals_are_silent(self) -> None:
        # A skip flag marks a placeholder on cursor_hooks only since spec 29
        # (§5.1, #42); on claude_settings the flagged sibling was live, and
        # removing it beside the kept live judge is silent too.
        fmt = {"hooks/fmt.sh": "#!/bin/sh\nnpx prettier --check .\n"}
        flagged = {"type": "command", "command": "bash hooks/fmt.sh", "disabled": True}
        for path, event, sibling in ((CS, "Stop", "true"), (CH, "stop", flagged), (CS, "Stop", flagged)):
            with self.subTest(path=path, sibling=sibling):
                payload = _scan({path: _hooks(event, [sibling, T], path), J: REAL, **fmt},
                                {path: _hooks(event, [T], path), J: REAL, **fmt})
                self.assertEqual(payload["findings"], [])

    def test_other_events_follow_the_same_rule_at_warn(self) -> None:
        payload = _scan({CS: _hooks("PreToolUse", ["true", "python hooks/guard.py"]),
                         "hooks/guard.py": REAL},
                        {CS: _hooks("PreToolUse", ["true"]), "hooks/guard.py": REAL})
        self.assertEqual(_rules(payload), [("HOOK_REMOVED", "warn")])


if __name__ == "__main__":
    unittest.main()
