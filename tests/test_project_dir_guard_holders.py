"""SPEC §3.3 (spec 26, hook-project-dir challenger amendment to Q2): the
`args` / non-bash `shell` guard is read per command string over every hook
object that holds it, so an added object holding a judge's string with those
keys does not turn the project-root forms off for the judge. Host evidence
(EXECUTED on Claude Code 2.1.42 and 2.1.296): such an object, at the
matcher-group level, under another event or in settings.local.json, changes
nothing the host runs for the judge."""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair
from pinwash.parse.hookcmd import root_form_guard

CS = ".claude/settings.json"
CSL = ".claude/settings.local.json"
ENV = {"PINWASH_TODAY": "2026-10-09"}
J = ".claude/hooks/judge.sh"
PD = '"$CLAUDE_PROJECT_DIR"/.claude/hooks/judge.sh'
REAL = "#!/usr/bin/env bash\nif ! make test >/dev/null 2>&1; then\n  echo '{\"decision\": \"block\"}'\nfi\n"
GUT = "#!/usr/bin/env bash\nmake test >/dev/null 2>&1 || true\n"


def _h(cmd: str, **kw: Any) -> dict[str, Any]:
    return dict({"type": "command", "command": cmd}, **kw)


def _doc(groups: dict[str, Any]) -> str:
    return json.dumps({"hooks": groups})


def _scan(base: dict[str, str], head: dict[str, str]) -> dict[str, Any]:
    return scan_pair({k: v.encode() for k, v in base.items()}, {k: v.encode() for k, v in head.items()},
                     base_label="b", head_label="h", env=ENV)


BASE = {CS: _doc({"Stop": [{"hooks": [_h(PD)]}]}), J: REAL}


class GuardPerHolder(unittest.TestCase):
    def assert_blocks(self, head: dict[str, str]) -> None:
        r = _scan(BASE, head)
        self.assertEqual(r["verdict"], "block")
        self.assertIn("hook command for Stop lost block capability", [f["message"] for f in r["findings"]])

    def test_decoy_under_another_event_does_not_turn_the_forms_off(self) -> None:
        self.assert_blocks({CS: _doc({"Stop": [{"hooks": [_h(PD)]}],
                                      "Notification": [{"hooks": [_h(PD, shell="powershell")]}]}), J: GUT})

    def test_decoy_at_the_group_level_does_not_turn_the_forms_off(self) -> None:
        self.assert_blocks({CS: _doc({"Stop": [{"command": PD, "args": [], "hooks": [_h(PD)]}]}), J: GUT})

    def test_decoy_in_settings_local_does_not_turn_the_forms_off(self) -> None:
        self.assert_blocks({CS: _doc({"Stop": [{"hooks": [_h(PD)]}]}),
                            CSL: _doc({"SessionEnd": [{"hooks": [_h(PD, args=[])]}]}), J: GUT})

    def test_decoy_already_at_base_does_not_turn_the_forms_off(self) -> None:
        settings = _doc({"Stop": [{"hooks": [_h(PD)]}], "Notification": [{"hooks": [_h(PD, shell="Bash")]}]})
        r = _scan({CS: settings, J: REAL}, {CS: settings, J: GUT})
        self.assertEqual(r["verdict"], "block")

    def test_a_string_only_guarded_objects_hold_stays_unread(self) -> None:
        files = {CS: _doc({"Stop": [{"hooks": [_h(PD, args=[])]}]}).encode(), J: b"x"}
        self.assertEqual(root_form_guard(files), frozenset({PD}))
        r = _scan(BASE, {CS: _doc({"Stop": [{"hooks": [_h(PD, shell="powershell")]}]}), J: GUT})
        self.assertEqual(r["verdict"], "pass")
        self.assertIn("hook command target no longer resolved", [u["reason"] for u in r["unknown_coverage"]])

    def test_mixed_holders_read_the_forms(self) -> None:
        files = {CS: _doc({"Stop": [{"hooks": [_h(PD), _h(PD, args=[])]}]}).encode(), J: b"x"}
        self.assertEqual(root_form_guard(files), frozenset())


class ReviewHoldersAndBlanks(unittest.TestCase):
    """Review of 2026-10-10 (AI-assisted)."""

    ROWS = ["hook command target no longer resolved", "hook stop liveness rests on an unresolved command"]

    def _rows(self, head: dict[str, str]) -> list[str]:
        return sorted({u["reason"] for u in _scan(BASE, head)["unknown_coverage"]})

    def test_holders_are_the_objects_section_5_1_reads(self) -> None:
        # An object nested under an item that holds a command, or inside a
        # list in a list, runs on neither host: it does not un-guard the
        # judge's string, so moving the judge to the exec form keeps its rows.
        guarded = _h(PD, args=[])
        for name, stop in (
            ("control", [{"hooks": [guarded]}]),
            ("nested under a command item", [{"hooks": [dict(guarded, hooks=[_h(PD)])]}]),
            ("list in a list", [{"hooks": [guarded]}, [{"hooks": [_h(PD)]}]]),
        ):
            with self.subTest(name=name):
                self.assertEqual(self._rows({CS: _doc({"Stop": stop}), J: REAL}), self.ROWS)

    def test_only_shell_blanks_end_the_reading(self) -> None:
        # CR, VT, FF, NBSP and U+2028 stay in a shell word: the host runs
        # another file or none (executed), so the form is not read.
        for cmd in ("\u00a0" + PD, PD + "\r", "\v" + PD, PD + "\u00a0", "\u2028" + PD,
                    "sh\u00a0 " + PD, "sh\x1c " + PD):
            with self.subTest(cmd=repr(cmd)):
                self.assertEqual(self._rows({CS: _doc({"Stop": [{"hooks": [_h(cmd)]}]}), J: REAL}), self.ROWS)
        for cmd in (" " + PD, PD + "\t", PD + "\n", "bash\t" + PD):
            with self.subTest(cmd=repr(cmd)):
                self.assertEqual(self._rows({CS: _doc({"Stop": [{"hooks": [_h(cmd)]}]}), J: REAL}), [])


if __name__ == "__main__":
    unittest.main()
