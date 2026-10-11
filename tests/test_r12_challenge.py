"""Spec 27: the challenger's amendments to the R12 draft (hook-liveness
ruling, AI-assisted, #10), with the residual it leaves open pinned.

* C1: on cursor_hooks, Cursor's stop output key `followup_message` counts as
  a body that can refuse and as a retarget judge's base form (INFERRED from
  Cursor's hook documentation, which SPEC §6.1 already relies on).
* C2: a `#` command at base is not a command a respelling repeats (§6.1):
  it never ran, so uncommenting a planted line is a command the diff added.
* (d): a judge that a stub-string, `#` or stub-body branch already paired
  is not reported again as retargeted (one finding per weakening).
* Booked, not detected: an added command that names a file that can refuse
  without running it (R11 verbs: `true`, `cat`, `echo`, `test -f`), the
  weakened judge's own unchanged file included, keeps the escalator off.
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
J = "hooks/judge.py"
REAL = (
    "import json, sys\n"
    "def main() -> int:\n"
    "    if not sys.stdin.read():\n"
    '        print(json.dumps({"decision": "block", "reason": "no input"}))\n'
    "        return 0\n"
    "    return 0\n"
    "sys.exit(main())\n"
)
GUT = "import json, sys\nprint(json.dumps({}))\nsys.exit(0 if sys.argv else 1)\n"
FOLLOW = (
    "import json, sys\nfrom pathlib import Path\n"
    "ev = json.loads(sys.stdin.read() or '{}')\n"
    "if ev.get('status') == 'completed' and not Path('DONE.md').exists():\n"
    "    print(json.dumps({'followup_message': 'Write DONE.md first.'}))\n"
)
OKPY = "print('{}')\nx = 1\n"


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


class CursorStopForm(unittest.TestCase):
    def test_claude_shaped_cursor_judge_moved_to_followup_form_passes(self) -> None:
        payload = _scan({CH: _hooks("stop", [T], CH), J: REAL},
                        {CH: _hooks("stop", ["python hooks/cursor_stop.py"], CH), "hooks/cursor_stop.py": FOLLOW})
        self.assertEqual(_rules(payload), [])

    def test_added_followup_judge_keeps_the_escalator_off(self) -> None:
        payload = _scan({CH: _hooks("stop", ["python hooks/a.py"], CH), "hooks/a.py": FOLLOW + "# block\n"},
                        {CH: _hooks("stop", ["# python hooks/a.py", "python hooks/b.py"], CH),
                         "hooks/a.py": FOLLOW + "# block\n", "hooks/b.py": FOLLOW})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "warn")])

    def test_followup_judge_retargeted_to_a_gutted_copy_blocks(self) -> None:
        payload = _scan({CH: _hooks("stop", ["python hooks/a.py"], CH), "hooks/a.py": FOLLOW},
                        {CH: _hooks("stop", ["python hooks/b.py"], CH), "hooks/b.py": GUT})
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])

    def test_followup_counts_only_on_cursor_hooks(self) -> None:
        payload = _scan({CS: _hooks("Stop", [T]), J: REAL},
                        {CS: _hooks("Stop", ["# " + T, "python hooks/b.py"]), J: REAL, "hooks/b.py": FOLLOW})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])


class CommentIsNotARespelling(unittest.TestCase):
    def test_uncommented_planted_line_does_not_keep_the_escalator_off(self) -> None:
        for judge in (REAL, GUT):
            with self.subTest(gut=judge == GUT):
                head_cmds = [T, "python hooks/ok.py"] if judge == GUT else ["# " + T, "python hooks/ok.py"]
                payload = _scan({CS: _hooks("Stop", [T, "# python hooks/ok.py"]), J: REAL, "hooks/ok.py": OKPY},
                                {CS: _hooks("Stop", head_cmds), J: judge, "hooks/ok.py": OKPY})
                self.assertEqual([s for _r, s in _rules(payload)], ["critical"])

    def test_python_to_python3_respelling_still_counts(self) -> None:
        payload = _scan({CS: _hooks("Stop", [T, "bash hooks/lint.sh"]), J: REAL, "hooks/lint.sh": "npx eslint .\n"},
                        {CS: _hooks("Stop", ["python3 hooks/judge.py", {"type": "command", "command": "bash hooks/lint.sh", "disabled": True}]),
                         J: REAL, "hooks/lint.sh": "npx eslint .\n"})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "warn")])


class BookedR11Decoy(unittest.TestCase):
    """Residual pins: these pass at warn (or silently) and are booked in R11."""

    def test_comment_out_beside_a_verb_naming_the_judge_stays_warn(self) -> None:
        for verb in ("true", "cat", "echo", "test -f", ":"):
            with self.subTest(verb=verb):
                payload = _scan({CS: _hooks("Stop", [T]), J: REAL},
                                {CS: _hooks("Stop", ["# " + T, f"{verb} {J}"]), J: REAL})
                self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "warn")])

    def test_a_unicode_space_names_the_judge_without_running_it(self) -> None:
        # Review of 2026-10-10: §3.3 splits on any whitespace, the shell at
        # blanks only, so `python3<NBSP>hooks/judge.py` resolves to the
        # judge and runs nothing (executed): booked in R11.
        payload = _scan({CS: _hooks("Stop", [T]), J: REAL},
                        {CS: _hooks("Stop", ["# " + T, "python3\u00a0" + J]), J: REAL})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "warn")])

    def test_retarget_beside_a_verb_naming_the_judge_is_silent(self) -> None:
        payload = _scan({CS: _hooks("Stop", [T]), J: REAL},
                        {CS: _hooks("Stop", ["python hooks/judge2.py", f"true {J}"]), J: REAL, "hooks/judge2.py": GUT})
        self.assertEqual(_rules(payload), [])


class OneFindingPerWeakening(unittest.TestCase):
    def test_a_judge_paired_by_the_stub_string_branch_is_not_also_a_retarget(self) -> None:
        payload = _scan({CS: _hooks("Stop", [T]), J: REAL},
                        {CS: _hooks("Stop", ["true", "python hooks/judge2.py"]), "hooks/judge2.py": GUT})
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])

    def test_a_judge_paired_by_the_comment_out_branch_is_not_also_a_retarget(self) -> None:
        payload = _scan({CS: _hooks("Stop", [T]), J: REAL},
                        {CS: _hooks("Stop", ["# " + T, "python hooks/judge2.py"]), "hooks/judge2.py": GUT})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])


class ReviewRetargets(unittest.TestCase):
    """Review of 2026-10-10 (AI-assisted)."""

    def test_a_hash_line_already_at_base_does_not_hide_a_retarget(self) -> None:
        # Only a `#` the diff added is the comment-out branch's.
        for order in ((T, "# " + T), ("# " + T, T)):
            with self.subTest(order=order):
                head = ["python hooks/judge2.py" if c == T else c for c in order]
                payload = _scan({CS: _hooks("Stop", list(order)), J: REAL},
                                {CS: _hooks("Stop", head), "hooks/judge2.py": GUT})
                self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])

    def test_a_second_judge_retargeted_beside_a_paired_one_is_reported(self) -> None:
        t3 = "python hooks/judge3.py"
        for first in ("true", "# paused for now"):
            with self.subTest(first=first):
                payload = _scan({CS: _hooks("Stop", [T, t3]), J: REAL, "hooks/judge3.py": REAL},
                                {CS: _hooks("Stop", [first, "python hooks/judge2.py"]), "hooks/judge2.py": GUT})
                found = [(f["rule"], f["before"]) for f in payload["findings"]]
                self.assertIn(("GATE_STUBBED", t3), found)
                self.assertEqual(len(found), 2)


if __name__ == "__main__":
    unittest.main()
