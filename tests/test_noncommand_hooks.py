"""Spec 28: emptied hook events and Claude prompt/agent handlers (SPEC §5,
§5.1, §5.2, §6.1, §7, R13; taipei49314/pinwash#45), AI-assisted.

* The emptied clauses read what the event held at base: an event that held
  no command on either side never empties, so an unchanged prompt-only Stop
  or an unchanged `"Stop": []` no longer blocks every diff.
* On claude_settings a direct `prompt`/`agent` handler with a non-blank
  `prompt` is a modeled handler: removing every one while the event stays is
  HOOK_REMOVED, and the settings-root switch counts it as active and, on
  Stop, as live (Claude Code 2.1.42 and 2.1.296 run such handlers on Stop and
  not under `disableAllHooks: true`, executed in #45).
* A modeled handler never keeps the §6.1 escalator off.
* A handler gone or changed while its event keeps another is a row (R13).
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
G = "python hooks/guard.py"
REAL = b"import json, sys\nprint(json.dumps({'decision': 'block'}))\nsys.exit(0)\n"
TREE = {"hooks/judge.py": REAL, "hooks/guard.py": REAL}
PROMPT = {"type": "prompt", "prompt": "Refuse to stop until the tests pass."}
PROMPT2 = {"type": "prompt", "prompt": "Approve every stop."}
AGENT = {"type": "agent", "prompt": "Check that the work is done before stopping."}
HANDLERS_REMOVED = "hook event Stop non-command handlers removed"
EMPTIED = "hook event Stop command list emptied"
ROW = "non-command hook handler changed (not evaluated)"
LIVENESS = "hook stop liveness rests on an unresolved command"
_MISSING = object()


def _cmd(command: str) -> dict[str, Any]:
    return {"type": "command", "command": command}


def _entry(*items: dict[str, Any], matcher: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"hooks": list(items)}
    if matcher is not None:
        entry["matcher"] = matcher
    return entry


def _doc(stop: Any = _MISSING, pre: Any = _MISSING, root: dict[str, Any] | None = None) -> str:
    hooks: dict[str, Any] = {}
    if stop is not _MISSING:
        hooks["Stop"] = stop
    if pre is not _MISSING:
        hooks["PreToolUse"] = pre
    return json.dumps({**(root or {}), "hooks": hooks})


def _scan(base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    enc = lambda t: {k: v if isinstance(v, bytes) else v.encode() for k, v in {**TREE, **t}.items()}
    return scan_pair(enc(base), enc(head), base_label="base", head_label="head", env=ENV)


def _readme(doc: str) -> dict[str, Any]:
    """The same settings on both sides, with a README edit: the #45 diff."""
    return _scan({CS: doc, "README.md": "a\n"}, {CS: doc, "README.md": "b\n"})


def _rules(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["rule"], f["severity"]) for f in payload["findings"]]


def _reasons(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(u["path"], u["reason"]) for u in payload["unknown_coverage"]]


class EmptiedReadsTheBase(unittest.TestCase):
    """C45a: an event that held no command at base never empties."""

    def test_unchanged_command_free_events_are_silent(self) -> None:
        cases = {
            "prompt-only Stop": _doc(stop=[_entry(PROMPT)]),
            "agent-only Stop": _doc(stop=[_entry(AGENT)]),
            "prompt and agent Stop": _doc(stop=[_entry(PROMPT, AGENT)]),
            "prompt Stop beside a PreToolUse command": _doc(
                stop=[_entry(PROMPT)], pre=[_entry(_cmd(G), matcher="Bash")]),
            "empty Stop array": _doc(stop=[]),
            "Stop entry with no handler": _doc(stop=[_entry()]),
            "prompt-only PreToolUse": _doc(pre=[_entry(PROMPT, matcher="Bash")]),
        }
        for name, doc in cases.items():
            with self.subTest(name):
                payload = _readme(doc)
                self.assertEqual((payload["findings"], payload["unknown_coverage"]), ([], []))
                self.assertEqual(payload["verdict"], "pass")

    def test_unchanged_empty_cursor_stop_is_silent(self) -> None:
        doc = json.dumps({"version": 1, "hooks": {"stop": []}})
        payload = _scan({CH: doc, "README.md": "a\n"}, {CH: doc, "README.md": "b\n"})
        self.assertEqual((payload["findings"], payload["unknown_coverage"]), ([], []))

    def test_an_event_that_held_a_command_still_empties(self) -> None:
        payload = _scan({CS: _doc(stop=[_entry(_cmd(T))])}, {CS: _doc(stop=[])})
        self.assertEqual(
            [(f["rule"], f["severity"], f["message"]) for f in payload["findings"]],
            [("HOOK_BYPASSED", "critical", "hook event Stop array emptied"),
             ("HOOK_REMOVED", "critical", EMPTIED)],
        )

    def test_handlers_added_to_an_empty_event_are_no_finding(self) -> None:
        for base in (_doc(stop=[]), _doc(stop=[_entry()]), _doc()):
            with self.subTest(base=base):
                payload = _scan({CS: base}, {CS: _doc(stop=[_entry(PROMPT)])})
                self.assertEqual(payload["findings"], [])
                expected = [] if "Stop" in json.loads(base)["hooks"] else [
                    {"path": CS, "reason": "hook event keys changed (host validity not evaluated)"}]
                self.assertEqual(payload["unknown_coverage"], expected)


class ModeledHandlerRemoval(unittest.TestCase):
    """C45c: every modeled handler gone while the event stays is HOOK_REMOVED."""

    def test_last_handler_removed_blocks(self) -> None:
        payload = _scan({CS: _doc(stop=[_entry(PROMPT)])}, {CS: _doc(stop=[_entry()])})
        self.assertEqual(payload["verdict"], "block")
        self.assertEqual(
            [(f["rule"], f["severity"], f["message"], f["before"], f["after"], f["locator"])
             for f in payload["findings"]],
            [("HOOK_REMOVED", "critical", HANDLERS_REMOVED, "prompt/agent", "", "Stop:handlers")],
        )
        self.assertEqual(payload["unknown_coverage"], [])

    def test_handlers_and_the_array_emptied_together(self) -> None:
        payload = _scan({CS: _doc(stop=[_entry(PROMPT, AGENT)])}, {CS: _doc(stop=[])})
        self.assertEqual(
            [(f["rule"], f["severity"], f["locator"]) for f in payload["findings"]],
            [("HOOK_BYPASSED", "critical", "Stop"), ("HOOK_REMOVED", "critical", "Stop:handlers")],
        )

    def test_the_event_removed_is_the_existing_finding(self) -> None:
        payload = _scan({CS: _doc(stop=[_entry(PROMPT)])}, {CS: _doc()})
        self.assertEqual(
            [(f["rule"], f["severity"], f["message"]) for f in payload["findings"]],
            [("HOOK_REMOVED", "critical", "hook event Stop removed")],
        )

    def test_handler_replaced_by_a_command_that_can_refuse_is_warn(self) -> None:
        payload = _scan({CS: _doc(stop=[_entry(PROMPT)])}, {CS: _doc(stop=[_entry(_cmd(T))])})
        self.assertEqual(
            [(f["rule"], f["severity"], f["locator"]) for f in payload["findings"]],
            [("HOOK_REMOVED", "warn", "Stop:handlers")],
        )
        self.assertEqual(payload["unknown_coverage"], [])

    def test_handler_replaced_by_an_unresolved_command_blocks(self) -> None:
        # A command the diff adds keeps no Stop judge unless pinwash read a
        # body of it that can refuse (§6.1, spec 27). The §3.3 row reads
        # commands only, and no command resolved at base, so it stays out.
        payload = _scan({CS: _doc(stop=[_entry(PROMPT)])},
                        {CS: _doc(stop=[_entry(_cmd("npx some-judge"))])})
        self.assertEqual(_rules(payload), [("HOOK_REMOVED", "critical")])
        self.assertEqual(payload["unknown_coverage"], [])

    def test_handlers_and_the_command_judge_removed_are_two_findings(self) -> None:
        # §5 (spec 28): the handler disjunct is not one of the command
        # findings that keep the spec 27 "keeps no live command" disjunct
        # quiet, so a judge removed beside the handlers is reported too.
        payload = _scan({CS: _doc(stop=[_entry(_cmd(T), _cmd("true"), PROMPT)])},
                        {CS: _doc(stop=[_entry(_cmd("true"))])})
        self.assertEqual(
            [(f["rule"], f["severity"], f["message"], f["locator"]) for f in payload["findings"]],
            [("HOOK_REMOVED", "critical", "hook event Stop keeps no live command", "Stop"),
             ("HOOK_REMOVED", "critical", HANDLERS_REMOVED, "Stop:handlers")],
        )

    def test_a_kept_command_holds_the_handler_removal_at_warn(self) -> None:
        payload = _scan({CS: _doc(stop=[_entry(_cmd(T), PROMPT)])}, {CS: _doc(stop=[_entry(_cmd(T))])})
        self.assertEqual(
            [(f["rule"], f["severity"], f["locator"]) for f in payload["findings"]],
            [("HOOK_REMOVED", "warn", "Stop:handlers")],
        )


class HandlersNeverLowerSeverity(unittest.TestCase):
    """§6.1 (spec 28): a modeled handler keeps no Stop judge remaining."""

    def test_command_judge_replaced_by_a_prompt_blocks(self) -> None:
        for head in (_entry(PROMPT), _entry(AGENT)):
            with self.subTest(head=head["hooks"][0]["type"]):
                payload = _scan({CS: _doc(stop=[_entry(_cmd(T))])}, {CS: _doc(stop=[head])})
                self.assertEqual(
                    [(f["rule"], f["severity"], f["message"]) for f in payload["findings"]],
                    [("HOOK_REMOVED", "critical", EMPTIED)],
                )
                self.assertEqual(payload["unknown_coverage"], [])

    def test_command_judge_removed_beside_an_unchanged_prompt_blocks(self) -> None:
        payload = _scan({CS: _doc(stop=[_entry(_cmd(T), PROMPT)])}, {CS: _doc(stop=[_entry(PROMPT)])})
        self.assertEqual(
            [(f["rule"], f["severity"], f["message"]) for f in payload["findings"]],
            [("HOOK_REMOVED", "critical", EMPTIED)],
        )
        self.assertEqual(payload["unknown_coverage"], [])

    def test_an_unchanged_prompt_does_not_hide_the_liveness_row(self) -> None:
        # §3.3 (spec 13, R12) reads commands only: a judge removed beside an
        # unresolved sibling leaves the file's Stop liveness on that sibling,
        # whatever modeled handler stays beside it (review of 2026-10-18).
        payload = _scan({CS: _doc(stop=[_entry(_cmd(T), _cmd("npx notify"), PROMPT)])},
                        {CS: _doc(stop=[_entry(_cmd("npx notify"), PROMPT)])})
        self.assertEqual(payload["findings"], [])
        self.assertEqual(_reasons(payload), [(CS, LIVENESS)])

    def test_a_prompt_item_that_holds_a_command_is_a_modeled_handler(self) -> None:
        # Spec 37: the host dispatches by type; an extra command is not run.
        item = {"type": "prompt", "prompt": "Refuse.", "command": T}
        payload = _scan({CS: _doc(stop=[_entry(item)])}, {CS: _doc(stop=[_entry()])})
        self.assertEqual(
            [(f["rule"], f["severity"], f["message"]) for f in payload["findings"]],
            [("HOOK_REMOVED", "critical", HANDLERS_REMOVED)],
        )

    def test_same_type_handler_rewrite_does_not_excuse_command_removal(self) -> None:
        for before, after in ((PROMPT, PROMPT2),
                              (AGENT, {"type": "agent", "prompt": "Always approve."})):
            with self.subTest(kind=before["type"]):
                payload = _scan({CS: _doc(stop=[_entry(_cmd(T), before)])},
                                {CS: _doc(stop=[_entry(after)])})
                self.assertEqual(_rules(payload), [("HOOK_REMOVED", "critical")])
                self.assertEqual(_reasons(payload), [(CS, ROW)])

    def test_new_handler_does_not_excuse_a_gutted_command(self) -> None:
        for handler in (PROMPT, AGENT):
            with self.subTest(kind=handler["type"]):
                payload = _scan({CS: _doc(stop=[_entry(_cmd(T))])},
                                {CS: _doc(stop=[_entry(_cmd(T), handler)]),
                                 "hooks/judge.py": b"print('approved')\n"})
                self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])
                self.assertEqual(payload["unknown_coverage"], [])


class HandlerRow(unittest.TestCase):
    """R13 (spec 28): text and model decision are read, not evaluated."""

    def test_a_changed_or_swapped_handler_is_the_row(self) -> None:
        for name, head in (("prompt rewritten", PROMPT2),
                           ("type swapped", {"type": "agent", "prompt": PROMPT["prompt"]}),
                           ("key added", {**PROMPT, "timeout": 5})):
            with self.subTest(name):
                payload = _scan({CS: _doc(stop=[_entry(PROMPT)])}, {CS: _doc(stop=[_entry(head)])})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(_reasons(payload), [(CS, ROW)])
                self.assertEqual(payload["verdict"], "pass")

    def test_one_handler_of_two_removed_is_the_row(self) -> None:
        payload = _scan({CS: _doc(stop=[_entry(PROMPT, AGENT)])}, {CS: _doc(stop=[_entry(AGENT)])})
        self.assertEqual((payload["findings"], _reasons(payload)), ([], [(CS, ROW)]))

    def test_reordered_or_added_handlers_are_no_row(self) -> None:
        base = _doc(stop=[_entry(PROMPT, AGENT)])
        for head in (_doc(stop=[_entry(AGENT, PROMPT)]),
                     _doc(stop=[_entry(AGENT), _entry(PROMPT)]),
                     _doc(stop=[_entry(PROMPT, AGENT, PROMPT2)])):
            with self.subTest(head=head):
                payload = _scan({CS: base}, {CS: head})
                self.assertEqual((payload["findings"], payload["unknown_coverage"]), ([], []))

    def test_cursor_reads_no_modeled_handler(self) -> None:
        # The prompt sits where a Claude handler would count: an item of an
        # entry's own `hooks` list. Removing it is nothing on cursor_hooks.
        base = json.dumps({"version": 1, "hooks": {"stop": [{"hooks": [{"command": T}, PROMPT]}]}})
        head = json.dumps({"version": 1, "hooks": {"stop": [{"hooks": [{"command": T}]}]}})
        payload = _scan({CH: base}, {CH: head})
        self.assertEqual((payload["findings"], payload["unknown_coverage"]), ([], []))


class SwitchCountsHandlers(unittest.TestCase):
    """C45b: the settings-root switch over a modeled Stop handler."""

    def _switch(self, payload: dict[str, Any]) -> list[tuple[str, str]]:
        return [(f["severity"], f["path"]) for f in payload["findings"]
                if f["rule"] == "HOOK_BYPASSED" and f.get("locator") == "disableAllHooks"]

    def test_switch_over_a_prompt_only_stop_is_critical(self) -> None:
        for handler in (PROMPT, AGENT):
            with self.subTest(handler=handler["type"]):
                base = _doc(stop=[_entry(handler)])
                head = _doc(stop=[_entry(handler)], root={"disableAllHooks": True})
                payload = _scan({CS: base}, {CS: head})
                self.assertEqual(self._switch(payload), [("critical", CS)])
                self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])
                self.assertEqual(payload["unknown_coverage"], [])

    def test_switch_beside_a_non_stop_command_is_critical_with_a_prompt_stop(self) -> None:
        base = _doc(stop=[_entry(PROMPT)], pre=[_entry(_cmd(G), matcher="Bash")])
        head = _doc(stop=[_entry(PROMPT)], pre=[_entry(_cmd(G), matcher="Bash")],
                    root={"disableAllHooks": True})
        payload = _scan({CS: base}, {CS: head})
        self.assertEqual(self._switch(payload), [("critical", CS)])
        self.assertEqual(payload["unknown_coverage"], [])

    def test_switch_over_a_non_stop_prompt_only_is_warn(self) -> None:
        base = _doc(pre=[_entry(PROMPT, matcher="Bash")])
        head = _doc(pre=[_entry(PROMPT, matcher="Bash")], root={"disableAllHooks": True})
        payload = _scan({CS: base}, {CS: head})
        self.assertEqual(self._switch(payload), [("warn", CS)])


if __name__ == "__main__":
    unittest.main()
