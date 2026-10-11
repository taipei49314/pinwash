"""Engine behaviour that SPEC text states since spec 12 (#25, #26 items 3, 5),
spec 13 (#26 item 6) and spec 14 (the closed `unknown_coverage` list).

Spec 12 wrote these sentences to what the engine already did, with no
verdict change. Each class pins one of them, so the text and the engine
cannot drift apart unnoticed: a later bump that changes the behaviour
changes the sentence and this test together.
"""

from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path
from typing import Any

from pinwash.engine import scan_pair
from pinwash.parse.gha import parse_workflow

TODAY = "2026-10-09"


def _pair(base: dict[str, str], head: dict[str, str]) -> dict[str, Any]:
    return scan_pair(
        {k: v.encode("utf-8") for k, v in base.items()},
        {k: v.encode("utf-8") for k, v in head.items()},
        base_label="base",
        head_label="head",
        env={"PINWASH_TODAY": TODAY},
    )


def _rules(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["rule"], f["severity"]) for f in payload["findings"]]


class CursorMcpRow(unittest.TestCase):
    """SPEC §5.3 `cursor_mcp` row and the R17 sentence after the table."""

    PATHS = (".cursor/mcp.json", ".mcp.json")

    @staticmethod
    def _doc(servers: dict[str, Any], key: str = "mcpServers", **extra: Any) -> str:
        doc: dict[str, Any] = {key: servers}
        doc.update(extra)
        return json.dumps(doc)

    def _widened(self, path: str, base: str | None, head: str) -> list[tuple[str, str]]:
        payload = _pair({path: base} if base is not None else {}, {path: head})
        return _rules(payload)

    def test_new_server_not_disabled_true_fires(self) -> None:
        empty = self._doc({})
        for path in self.PATHS:
            for body in (
                {"command": "x"},
                {"command": "x", "disabled": False},
                {"command": "x", "disabled": 1},
                {"command": "x", "disabled": "true"},
            ):
                with self.subTest(path=path, body=body):
                    self.assertEqual(
                        self._widened(path, empty, self._doc({"s": body})),
                        [("PERMISSION_WIDENED", "high")],
                    )

    def test_server_in_a_created_file_fires(self) -> None:
        for path in self.PATHS:
            with self.subTest(path=path):
                self.assertEqual(
                    self._widened(path, None, self._doc({"s": {"command": "x"}})),
                    [("PERMISSION_WIDENED", "high")],
                )

    def test_new_server_disabled_true_is_silent(self) -> None:
        for path in self.PATHS:
            with self.subTest(path=path):
                head = self._doc({"s": {"command": "x", "disabled": True}})
                self.assertEqual(self._widened(path, self._doc({}), head), [])
                self.assertEqual(self._widened(path, None, head), [])

    def test_disabled_true_to_json_false_fires(self) -> None:
        for path in self.PATHS:
            with self.subTest(path=path):
                base = self._doc({"s": {"command": "x", "disabled": True}})
                head = self._doc({"s": {"command": "x", "disabled": False}})
                self.assertEqual(self._widened(path, base, head), [("PERMISSION_WIDENED", "high")])

    def test_disabled_true_deleted_or_not_json_false_is_silent(self) -> None:
        # Booked as R17 (#26 item 3); closing it is a later bump.
        base = self._doc({"s": {"command": "x", "disabled": True}})
        for path in self.PATHS:
            for body in ({"command": "x"}, {"command": "x", "disabled": "false"}, {"command": "x", "disabled": 0}):
                with self.subTest(path=path, body=body):
                    self.assertEqual(self._widened(path, base, self._doc({"s": body})), [])

    def test_star_gained_fires_on_existing_and_new_servers(self) -> None:
        for path in self.PATHS:
            for key in ("alwaysAllow", "autoApprove"):
                with self.subTest(path=path, key=key):
                    base = self._doc({"s": {"command": "x", key: ["read"]}})
                    head = self._doc({"s": {"command": "x", key: ["read", "*"]}})
                    self.assertEqual(self._widened(path, base, head), [("PERMISSION_WIDENED", "high")])
                    new = self._doc({"s": {"command": "x", "disabled": True, key: ["*"]}})
                    self.assertEqual(self._widened(path, self._doc({}), new), [("PERMISSION_WIDENED", "high")])

    def test_star_kept_or_not_in_an_array_is_silent(self) -> None:
        for path in self.PATHS:
            for key in ("alwaysAllow", "autoApprove"):
                with self.subTest(path=path, key=key):
                    kept = self._doc({"s": {"command": "x", key: ["*"]}})
                    self.assertEqual(self._widened(path, kept, kept), [])
                    base = self._doc({"s": {"command": "x"}})
                    head = self._doc({"s": {"command": "x", key: "*"}})
                    self.assertEqual(self._widened(path, base, head), [])

    def test_servers_key_is_read_only_when_mcpservers_is_not_an_object(self) -> None:
        for path in self.PATHS:
            with self.subTest(path=path):
                head = self._doc({"s": {"command": "x"}}, key="servers")
                self.assertEqual(
                    self._widened(path, self._doc({}, key="servers"), head),
                    [("PERMISSION_WIDENED", "high")],
                )
                shadowed = json.dumps({"mcpServers": {}, "servers": {"s": {"command": "x"}}})
                self.assertEqual(self._widened(path, self._doc({}), shadowed), [])


class WorkflowTabRule(unittest.TestCase):
    """SPEC §3.1 tab rule: a tab before a line's first `#`, or anywhere on a
    line without one, makes the workflow unparseable; lines split at LF,
    CRLF or a lone CR; a tab after the first `#` does not count."""

    WF = ".github/workflows/ci.yml"
    BASE = "on: push\njobs:\n  ci:\n    runs-on: x\n    steps:\n      - run: make\n"

    def test_tabs_the_rule_names_fail_the_file(self) -> None:
        cases = {
            "indentation": "on: push\njobs:\n  ci:\n\truns-on: x\n",
            "value": "on: push\njobs:\n  ci:\n    steps:\n      - run: printf 'a\tb'\n",
            "block-scalar content": "on: push\njobs:\n  ci:\n    steps:\n      - run: |\n          \tEOF\n",
            "before an inline comment": "on: push\njobs:\n  ci:\n    if: false\t# x\n",
            "whitespace-only line": "on: push\n  \t\njobs:\n",
            "before the # of an indented comment": "on: push\njobs:\n  \t# note\n",
            "after a lone CR": "on: push\nrun: echo hi # note\r\tmore\n",
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.assertTrue(parse_workflow(text).unparseable)
                payload = _pair({self.WF: self.BASE}, {self.WF: text})
                self.assertEqual(_rules(payload), [("SURFACE_UNPARSEABLE", "high")])

    def test_a_tab_after_the_first_hash_does_not_count(self) -> None:
        for text in (
            "on: push\njobs:\n  ci:\n    steps:\n      - uses: a/b@v1 #\tnote\n",
            "on: push\n# a\tcomment\njobs:\n",
            "on: push\njobs:\n  ci:\n    steps:\n      - run: echo a#b\tc\n",
            "on: push\nrun: echo hi # note\tmore\n",
        ):
            with self.subTest(text=text):
                self.assertFalse(parse_workflow(text).unparseable)


class WorkflowLocatorCount(unittest.TestCase):
    """SPEC §4: `#<n>` counts earlier `uses:` lines §3.1 records as pins of
    the same action, from 0."""

    def test_only_recorded_pins_are_counted(self) -> None:
        sha = "b" * 40
        text = (
            "on: push\njobs:\n  a:\n    steps:\n"
            "      - uses: org/tool@\n"
            "      - uses: ./org/tool@v1\n"
            f"      - uses: org/tool@{sha}\n"
            "      - uses: org/tool@v2\n"
        )
        self.assertEqual(parse_workflow(text).uses, [("org/tool", sha, 0), ("org/tool", "v2", 1)])


class StopLikeSet(unittest.TestCase):
    """SPEC §6.1 (spec 13, #26 item 6): the Stop-like set is closed and
    case-sensitive per surface: `Stop` on claude_settings, `stop` on
    cursor_hooks. A hook under any other name never keeps the escalator off."""

    C = ".cursor/hooks.json"
    J = "judge-stop"
    T = "npx telemetry after-response"

    def _hooks(self, **events: list[str]) -> str:
        return json.dumps({"version": 1, "hooks": {
            e: [{"command": c} for c in cmds] for e, cmds in events.items()}})

    def _rules(self, base: str, head: str) -> list[tuple[str, str]]:
        return _rules(_pair({self.C: base}, {self.C: head}))

    def test_cursor_stop_removed_or_stubbed_is_critical_whatever_else_stays(self) -> None:
        # Passes that became blocks: a non-`stop` hook no longer masks the
        # removal of the real `stop` judge.
        for other in ("afterAgentResponse", "afterAgentThought", "subagentStop", "finish", "Stop",
                      "beforeSubmitPrompt"):
            with self.subTest(other=other):
                base = self._hooks(stop=[self.J], **{other: [self.T]})
                self.assertEqual(self._rules(base, self._hooks(**{other: [self.T]})),
                                 [("HOOK_REMOVED", "critical")])
                stubbed = self._hooks(stop=["true"], **{other: [self.T]})
                self.assertEqual(self._rules(base, stubbed), [("GATE_STUBBED", "critical")])

    def test_judge_moved_out_of_cursor_stop_is_critical(self) -> None:
        for other in ("afterAgentResponse", "finish", "Stop", "subagentStop"):
            with self.subTest(other=other):
                rules = self._rules(self._hooks(stop=[self.J]), self._hooks(**{other: [self.J]}))
                self.assertEqual(rules, [("HOOK_REMOVED", "critical")])

    def test_events_outside_the_set_removed_or_stubbed_stay_warn(self) -> None:
        # Blocks that became passes: `afterAgentResponse`, `finish` and
        # `Stop` hooks on cursor_hooks are not Stop-like.
        for other in ("afterAgentResponse", "afterAgentThought", "subagentStop", "finish", "Stop"):
            with self.subTest(other=other):
                self.assertEqual(self._rules(self._hooks(**{other: [self.J]}), self._hooks()),
                                 [("HOOK_REMOVED", "warn")])
                stubbed = self._rules(self._hooks(**{other: [self.J]}), self._hooks(**{other: ["true"]}))
                self.assertEqual(stubbed, [("GATE_STUBBED", "warn")])

    def test_honest_non_gate_stop_hook_removal_now_blocks(self) -> None:
        # Disclosed cost: removing a `stop` hook that is no gate (a sound
        # notification) while an `afterAgentResponse` hook stays has the same
        # bytes as the attack, so it blocks.
        base = self._hooks(stop=["afplay done.aiff"], afterAgentResponse=[self.T])
        self.assertEqual(self._rules(base, self._hooks(afterAgentResponse=[self.T])),
                         [("HOOK_REMOVED", "critical")])

    def test_a_sibling_stop_command_still_masks_the_judge(self) -> None:
        # Open, R12: the judge removed from `stop` while another `stop`
        # command (a plugin's) stays gives no finding at all.
        base = self._hooks(stop=[self.J, "npx plugin-stop"])
        self.assertEqual(self._rules(base, self._hooks(stop=["npx plugin-stop"])), [])

    def test_claude_set_is_stop_only(self) -> None:
        def settings(**events: str) -> str:
            return json.dumps({"hooks": {
                e: [{"hooks": [{"type": "command", "command": c}]}] for e, c in events.items()}})
        path = ".claude/settings.json"
        rules = _rules(_pair({path: settings(Stop=self.J, SubagentStop=self.J)},
                             {path: settings(SubagentStop=self.J)}))
        self.assertEqual(rules, [("HOOK_REMOVED", "critical")])
        rules = _rules(_pair({path: settings(SubagentStop=self.J)}, {path: settings()}))
        self.assertEqual(rules, [("HOOK_REMOVED", "warn")])


class SpecVersionLine(unittest.TestCase):
    """The SPEC header names the engine's spec version (review of
    2026-10-10: spec 15 left it at 14)."""

    def test_header_matches_spec_version(self) -> None:
        from pinwash import SPEC_VERSION

        text = (Path(__file__).resolve().parent.parent / "SPEC.md").read_text(encoding="utf-8")
        self.assertIn(f"\nSpec version: **{SPEC_VERSION}** (", text)


class UnknownCoverageReasons(unittest.TestCase):
    """SPEC §7 (spec 13, spec 14): `reason` is fixed text from a closed list.
    The list in SPEC and the reasons the engine can emit are the same set."""

    ROOT = Path(__file__).resolve().parent.parent

    def _spec_reasons(self) -> set[str]:
        text = (self.ROOT / "SPEC.md").read_text(encoding="utf-8")
        start = text.index("\n## 7. Findings envelope")
        section = text[start:text.index("\n## 8.", start)]
        header = section.index("| Reason | Surface | Where |")
        reasons: set[str] = set()
        for line in section[header:].split("\n")[2:]:
            if not line.startswith("|"):
                break
            first = line.split("|")[1]
            # Each reason is one backticked span (spec 16 reasons hold commas).
            reasons.update(first.split("`")[1::2])
        return reasons

    def _gha_reasons(self) -> set[str]:
        path = self.ROOT / "pinwash" / "parse" / "gha.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constants = {
            node.targets[0].id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
            and isinstance(node.targets[0], ast.Name) and isinstance(node.value.value, str)
        }
        found: set[str] = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "append" and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr in ("unknown", "job_unknown")):
                arg = node.args[0]
                found.add(arg.value if isinstance(arg, ast.Constant) else constants[arg.id])
        return found

    def _required_check_reasons(self) -> set[str]:
        """Every reason `rules/required_check.py` passes to `note(...)`."""
        path = self.ROOT / "pinwash" / "rules" / "required_check.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constants = {
            node.targets[0].id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
            and isinstance(node.targets[0], ast.Name) and isinstance(node.value.value, str)
        }
        found: set[str] = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "note"):
                found.add(constants[node.args[0].id])
        return found

    def test_the_closed_list_is_what_the_engine_emits(self) -> None:
        from pinwash.rules import hook_coverage, hook_rules, hook_selector

        hook = {
            hook_rules.HOOK_LIVENESS_UNRESOLVED,
            hook_selector.REASON,
            hook_coverage.TARGET_NO_LONGER_RESOLVED,
            hook_coverage.NAMES_CHANGED_FILE,
            hook_coverage.FLAG_NOT_BOOLEAN,
            hook_coverage.DISABLE_ALL_HOOKS,
            hook_coverage.ENV_CHANGED,
        }
        gha = self._gha_reasons()
        # Spec 14: six grammar reasons (#23, #24, and the layout reason of
        # its review) join the five of spec 13, and eight producer reasons
        # (§5.5; #13, #14, #15, R03).
        self.assertEqual(len(gha), 11, gha)
        producer = self._required_check_reasons()
        self.assertEqual(len(producer), 8, producer)
        # Spec 16: the parse-status and working-tree rows (engine) and the
        # permission rows (§5.3).
        from pinwash import engine
        from pinwash.rules import permission

        spec16 = {
            engine.NEW_UNPARSEABLE,
            engine.BASE_UNPARSEABLE,
            engine.IGNORED_SURFACE,
            engine.IGNORED_SURFACE_DIR,
            engine.UNREAD_SURFACE_DIR,
            permission.MODE_CHANGED,
            permission.OFF_LATTICE,
            permission.TOOLWIDE_EDIT,
        }
        # Spec 19: a checkwash config checkwash cannot load (§3.2, R22).
        from pinwash.rules import config_rule

        self.assertEqual(self._spec_reasons(), gha | hook | producer | spec16 | {config_rule.NOT_LOADED})


if __name__ == "__main__":
    unittest.main()
