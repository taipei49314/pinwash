"""SPEC fidelity regressions for the alpha2 candidate; frozen gates stay separate."""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair


def _pair(
    base: dict[str, str | bytes], head: dict[str, str | bytes],
) -> dict[str, Any]:
    def as_bytes(files: dict[str, str | bytes]) -> dict[str, bytes]:
        return {
            path: data.encode("utf-8") if isinstance(data, str) else data
            for path, data in files.items()
        }

    return scan_pair(
        as_bytes(base), as_bytes(head), base_label="base", head_label="head",
        env={"PINWASH_TODAY": "2026-09-30"},
    )


def _rules(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(item["rule"], item["severity"]) for item in payload["findings"]]


def _hooks(event: str, entries: list[dict[str, Any]]) -> str:
    return json.dumps({"hooks": {event: entries}})


class MarkdownParseStatus(unittest.TestCase):
    """SPEC §3: the closed UTF-8 parse-status table covers markdown surfaces."""

    PATHS = (
        "AGENTS.md", "skills/review/SKILL.md", ".cursor/rules/review.mdc",
        ".github/copilot-instructions.md",
    )

    def test_valid_base_to_invalid_head_is_high_and_blocks(self) -> None:
        for path in self.PATHS:
            with self.subTest(path=path):
                payload = _pair({path: "review the change\n"}, {path: b"\xff"})
                self.assertEqual(_rules(payload), [("SURFACE_UNPARSEABLE", "high")])
                self.assertEqual(payload["findings"][0]["path"], path)
                self.assertEqual(payload["verdict"], "block")

    def test_both_sides_invalid_is_visible_warn(self) -> None:
        for path in self.PATHS:
            with self.subTest(path=path):
                payload = _pair({path: b"\xff"}, {path: b"\xfe"})
                self.assertEqual(_rules(payload), [("SURFACE_UNPARSEABLE", "warn")])
                self.assertEqual(payload["verdict"], "pass")

    def test_repair_missing_base_and_deletion_do_not_invent_parse_weakening(self) -> None:
        for path in self.PATHS:
            for base, head in (
                ({path: b"\xff"}, {path: "review the change\n"}),
                ({}, {path: b"\xff"}),
                ({path: "review the change\n"}, {}),
                ({path: "review\n"}, {path: "review carefully\n"}),
            ):
                with self.subTest(path=path, base=base, head=head):
                    payload = _pair(base, head)
                    self.assertEqual(payload["findings"], [])
                    self.assertEqual(payload["verdict"], "pass")


class LastStopSkipFlags(unittest.TestCase):
    """SPEC §5.1 / §6.1: only a remaining command that can gate is live."""

    PATH = ".claude/settings.json"

    def test_each_exact_skip_flag_on_last_stop_is_critical(self) -> None:
        cases = (
            (".cursor/hooks.json", "stop", "disabled", True),
            (".cursor/hooks.json", "stop", "hookEnabled", False),
            (self.PATH, "Stop", "continueOnError", True),
            (self.PATH, "Stop", "failOpen", True),
        )
        for path, event, flag, value in cases:
            with self.subTest(path=path, flag=flag):
                base = _hooks(event, [{"command": "judge"}])
                head = _hooks(event, [{"command": "judge", flag: value}])
                payload = _pair({path: base}, {path: head})
                self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])
                self.assertEqual(payload["verdict"], "block")

    def test_skipping_one_nested_sibling_keeps_other_command_live(self) -> None:
        base = _hooks("Stop", [{"hooks": [
            {"command": "judge-a"}, {"command": "judge-b"},
        ]}])
        head = _hooks("Stop", [{"hooks": [
            {"command": "judge-a", "failOpen": True}, {"command": "judge-b"},
        ]}])
        payload = _pair({self.PATH: base}, {self.PATH: head})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "warn")])
        self.assertEqual(payload["verdict"], "pass")

    def test_preexisting_skipped_sibling_does_not_hide_last_live_skip(self) -> None:
        base = _hooks("Stop", [{"hooks": [
            {"command": "judge-a", "failOpen": True}, {"command": "judge-b"},
        ]}])
        head = _hooks("Stop", [{"hooks": [
            {"command": "judge-a", "failOpen": True},
            {"command": "judge-b", "failOpen": True},
        ]}])
        payload = _pair({self.PATH: base}, {self.PATH: head})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])
        self.assertEqual(payload["verdict"], "block")

    def test_parent_skip_applies_to_all_nested_commands(self) -> None:
        children = [{"command": "judge-a"}, {"command": "judge-b"}]
        base = _hooks("Stop", [{"hooks": children}])
        head = _hooks("Stop", [{"hooks": children, "continueOnError": True}])
        payload = _pair({self.PATH: base}, {self.PATH: head})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])
        self.assertEqual(payload["verdict"], "block")

    def test_removing_skipped_sibling_cannot_hide_surviving_command_skip(self) -> None:
        base = _hooks("Stop", [{"hooks": [
            {"command": "judge-old", "failOpen": True},
            {"command": "judge-live"},
        ]}])
        head = _hooks("Stop", [{"hooks": [
            {"command": "judge-live", "failOpen": True},
        ]}])
        payload = _pair({self.PATH: base}, {self.PATH: head})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])
        self.assertEqual(payload["verdict"], "block")

    def test_flat_cursor_list_retains_an_active_sibling(self) -> None:
        path = ".cursor/hooks.json"
        base = json.dumps({"hooks": [
            {"event": "stop", "command": "judge-a"},
            {"event": "stop", "command": "judge-b"},
        ]})
        head = json.dumps({"hooks": [
            {"event": "stop", "command": "judge-a", "disabled": True},
            {"event": "stop", "command": "judge-b"},
        ]})
        payload = _pair({path: base}, {path: head})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "warn")])
        self.assertEqual(payload["verdict"], "pass")

    def test_another_cursor_stop_event_prevents_last_stop_escalation(self) -> None:
        path = ".cursor/hooks.json"
        base = json.dumps({"hooks": {
            "stop": [{"command": "judge-stop"}],
            "finish": [{"command": "judge-finish"}],
        }})
        head = json.dumps({"hooks": {
            "stop": [{"command": "judge-stop", "disabled": True}],
            "finish": [{"command": "judge-finish"}],
        }})
        payload = _pair({path: base}, {path: head})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "warn")])
        self.assertEqual(payload["verdict"], "pass")

    def test_unchanged_or_removed_skip_is_not_a_new_bypass(self) -> None:
        skipped = _hooks("Stop", [{"command": "judge", "failOpen": True}])
        for head in (skipped, _hooks("Stop", [{"command": "judge"}])):
            with self.subTest(head=head):
                payload = _pair({self.PATH: skipped}, {self.PATH: head})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["verdict"], "pass")

    def test_reordering_distinct_or_duplicate_siblings_is_not_a_new_skip(self) -> None:
        for other_command in ("judge-b", "judge-a"):
            with self.subTest(other_command=other_command):
                entries = [
                    {"command": "judge-a", "failOpen": True},
                    {"command": other_command},
                ]
                base = _hooks("Stop", [{"hooks": entries}])
                head = _hooks("Stop", [{"hooks": list(reversed(entries))}])
                payload = _pair({self.PATH: base}, {self.PATH: head})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["verdict"], "pass")

    def test_renaming_already_skipped_command_is_not_a_new_skip(self) -> None:
        path = ".cursor/hooks.json"
        base = _hooks("stop", [
            {"command": "judge-old", "disabled": True},
            {"command": "judge-live"},
        ])
        head = _hooks("stop", [
            {"command": "judge-new", "disabled": True},
            {"command": "judge-live"},
        ])
        payload = _pair({path: base}, {path: head})
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["verdict"], "pass")

    def test_adding_already_skipped_sibling_does_not_weaken_live_command(self) -> None:
        path = ".cursor/hooks.json"
        entries = [
            {"command": "judge-old", "disabled": True},
            {"command": "judge-live"},
        ]
        base = _hooks("stop", entries)
        head = _hooks("stop", entries + [
            {"command": "judge-new", "disabled": True},
        ])
        payload = _pair({path: base}, {path: head})
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["verdict"], "pass")

    def test_redistributed_flags_can_disable_last_duplicate_command(self) -> None:
        base = _hooks("Stop", [{"hooks": [
            {"command": "judge", "failOpen": True, "continueOnError": True},
            {"command": "judge"},
        ]}])
        head = _hooks("Stop", [{"hooks": [
            {"command": "judge", "failOpen": True},
            {"command": "judge", "continueOnError": True},
        ]}])
        payload = _pair({self.PATH: base}, {self.PATH: head})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])
        self.assertEqual(payload["verdict"], "block")

    def test_unknown_skip_key_remains_outside_closed_table(self) -> None:
        base = _hooks("Stop", [{"command": "judge"}])
        head = _hooks("Stop", [{"command": "judge", "skipJudge": True}])
        payload = _pair({self.PATH: base}, {self.PATH: head})
        self.assertEqual(payload["findings"], [])


class WorkflowMultilineIfCoverage(unittest.TestCase):
    """SPEC §3.1 / §7: multiline if scalars are unknown, not invented drops."""

    PATH = ".github/workflows/ci.yml"
    RULESET_PATH = ".github/required-ruleset.json"
    RULESET = json.dumps({"rules": [{
        "type": "required_status_checks",
        "parameters": {"required_status_checks": [{"context": "ci"}]},
    }]})

    @staticmethod
    def _workflow(condition: str = "") -> str:
        return (
            "on: push\njobs:\n  ci:\n    name: ci\n"
            "    runs-on: ubuntu-latest\n" + condition
            + "    steps:\n      - run: echo ready\n"
        )

    def _scan(self, head_workflow: str) -> dict[str, Any]:
        return _pair(
            {self.PATH: self._workflow(), self.RULESET_PATH: self.RULESET},
            {self.PATH: head_workflow, self.RULESET_PATH: self.RULESET},
        )

    def test_block_scalar_headers_are_visible_as_unknown(self) -> None:
        for header in (">", "|", ">-", "|+", ">2-", "|-2", "> # rationale"):
            with self.subTest(header=header):
                payload = self._scan(self._workflow(
                    f"    if: {header}\n      ${{{{ false }}}}\n"
                ))
                self.assertIn(
                    {"path": self.PATH, "reason": "multiline uses or scalar"},
                    payload["unknown_coverage"],
                )
                self.assertEqual(payload["findings"], [])
                # Unknown coverage does not itself block under SPEC §7.
                self.assertEqual(payload["verdict"], "pass")

    def test_step_if_block_scalar_also_exposes_residual_coverage(self) -> None:
        head = self._workflow().replace(
            "      - run: echo ready\n",
            "      - run: echo ready\n        if: |\n          ${{ false }}\n",
        )
        payload = self._scan(head)
        self.assertIn(
            {"path": self.PATH, "reason": "multiline uses or scalar"},
            payload["unknown_coverage"],
        )
        self.assertEqual(payload["findings"], [])

    def test_single_line_expressions_do_not_gain_unknown_coverage(self) -> None:
        for condition in ("true", "'|'", "${{ 3 > 2 }}"):
            with self.subTest(condition=condition):
                payload = self._scan(self._workflow(f"    if: {condition}\n"))
                self.assertEqual(payload["unknown_coverage"], [])
                self.assertEqual(payload["findings"], [])

    def test_single_line_false_keeps_existing_required_check_detection(self) -> None:
        payload = self._scan(self._workflow("    if: false # maintenance\n"))
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high")])
        self.assertEqual(payload["unknown_coverage"], [])
        self.assertEqual(payload["verdict"], "block")


if __name__ == "__main__":
    unittest.main()
