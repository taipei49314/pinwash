"""Family regressions filed after alpha 2 (issues #4, #5); frozen gates stay separate."""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair


def _pair(base: dict[str, str], head: dict[str, str]) -> dict[str, Any]:
    return scan_pair(
        {path: text.encode("utf-8") for path, text in base.items()},
        {path: text.encode("utf-8") for path, text in head.items()},
        base_label="base", head_label="head",
        env={"PINWASH_TODAY": "2026-10-01"},
    )


def _rules(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(item["rule"], item["severity"]) for item in payload["findings"]]


class WorkflowValueResiduals(unittest.TestCase):
    """#4, SPEC §3.1 / §7: a recorded value outside its closed form is
    unknown coverage, never a silent `None` or an invented literal."""

    PATH = ".github/workflows/ci.yml"
    RULESET_PATH = ".github/required-ruleset.json"
    RULESET = json.dumps({"rules": [{
        "type": "required_status_checks",
        "parameters": {"required_status_checks": [{"context": "ci"}]},
    }]})
    MULTILINE = {"path": PATH, "reason": "multiline uses or scalar"}
    CONTINUE = {"path": PATH, "reason": "continue-on-error value unresolved"}
    ON = {"path": PATH, "reason": "on triggers unresolved"}

    @staticmethod
    def _workflow(
        *, on: str = "on: push\n", name: str = "    name: ci\n",
        job: str = "", steps: str = "      - run: echo ready\n",
    ) -> str:
        return (
            on + "jobs:\n  ci:\n" + name + "    runs-on: ubuntu-latest\n"
            + job + "    steps:\n" + steps
        )

    def _scan(self, base: str, head: str) -> dict[str, Any]:
        return _pair(
            {self.PATH: base, self.RULESET_PATH: self.RULESET},
            {self.PATH: head, self.RULESET_PATH: self.RULESET},
        )

    def test_continue_on_error_block_scalar_is_unknown(self) -> None:
        for header in ("|", ">", "|-", ">2", "| # why"):
            with self.subTest(header=header):
                payload = self._scan(
                    self._workflow(),
                    self._workflow(job=f"    continue-on-error: {header}\n      true\n"),
                )
                self.assertIn(self.MULTILINE, payload["unknown_coverage"])
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["verdict"], "pass")

    def test_continue_on_error_outside_true_false_is_unresolved(self) -> None:
        for value in ("${{ true }}", "${{ matrix.experimental }}", "yes", "on"):
            with self.subTest(value=value):
                payload = self._scan(
                    self._workflow(),
                    self._workflow(job=f"    continue-on-error: {value}\n"),
                )
                self.assertIn(self.CONTINUE, payload["unknown_coverage"])
                self.assertEqual(payload["findings"], [])

    def test_continue_on_error_empty_or_comment_only_is_unknown(self) -> None:
        for line in ("    continue-on-error:\n", "    continue-on-error: # later\n"):
            with self.subTest(line=line):
                payload = self._scan(
                    self._workflow(), self._workflow(job=line + "      true\n"),
                )
                self.assertIn(self.MULTILINE, payload["unknown_coverage"])
                self.assertEqual(payload["findings"], [])

    def test_continue_on_error_true_false_keep_existing_detection(self) -> None:
        payload = self._scan(
            self._workflow(), self._workflow(job="    continue-on-error: 'true'\n"),
        )
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high")])
        self.assertEqual(payload["unknown_coverage"], [])
        payload = self._scan(
            self._workflow(), self._workflow(job="    continue-on-error: false\n"),
        )
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["unknown_coverage"], [])

    def test_head_name_block_scalar_is_unknown(self) -> None:
        payload = self._scan(
            self._workflow(), self._workflow(name="    name: >\n      ci\n"),
        )
        self.assertIn(self.MULTILINE, payload["unknown_coverage"])
        self.assertEqual(payload["findings"], [])

    def test_base_name_residual_is_visible_not_a_silent_unlinked_job(self) -> None:
        for name in ("    name: |\n      ci\n", "    name:\n      ci\n"):
            with self.subTest(name=name):
                payload = self._scan(
                    self._workflow(name=name),
                    self._workflow(name=name, job="    if: false\n"),
                )
                # The context cannot be resolved, so no linkage is guessed;
                # the base-side residual must still be reported.
                self.assertEqual(payload["findings"], [])
                self.assertIn(self.MULTILINE, payload["unknown_coverage"])

    def test_name_resolved_at_base_still_links(self) -> None:
        payload = self._scan(
            self._workflow(name="    name: ci # context\n"),
            self._workflow(name="    name: ci # context\n", job="    if: false\n"),
        )
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high")])
        self.assertEqual(payload["unknown_coverage"], [])

    def test_uses_split_across_lines_is_unknown(self) -> None:
        for step in (
            "      - uses:\n          org/judge@v1.2.3\n",
            "      - uses: # pinned below\n          org/judge@v1.2.3\n",
        ):
            with self.subTest(step=step):
                payload = self._scan(self._workflow(), self._workflow(steps=step))
                self.assertIn(self.MULTILINE, payload["unknown_coverage"])

    def test_job_if_empty_remainder_is_unknown(self) -> None:
        payload = self._scan(
            self._workflow(), self._workflow(job="    if:\n      false\n"),
        )
        self.assertIn(self.MULTILINE, payload["unknown_coverage"])
        self.assertEqual(payload["findings"], [])

    def test_first_key_step_if_block_scalar_is_unknown(self) -> None:
        payload = self._scan(
            self._workflow(),
            self._workflow(steps="      - if: |\n          false\n        run: echo ready\n"),
        )
        self.assertIn(self.MULTILINE, payload["unknown_coverage"])
        self.assertEqual(payload["findings"], [])

    def test_on_block_scalar_is_unresolved_not_an_invented_trigger_loss(self) -> None:
        payload = self._scan(self._workflow(), self._workflow(on="on: >\n  push\n"))
        self.assertIn(self.ON, payload["unknown_coverage"])
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["verdict"], "pass")

    def test_on_comment_only_remainder_reads_the_block_below(self) -> None:
        payload = self._scan(
            self._workflow(on="on: # events\n  push:\n"),
            self._workflow(on="on: # events\n  workflow_dispatch:\n"),
        )
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high")])
        self.assertEqual(payload["unknown_coverage"], [])
        self.assertEqual(payload["verdict"], "block")

    def test_base_side_residual_is_reported_once(self) -> None:
        block = self._workflow(job="    if: |\n      false\n")
        payload = self._scan(block, self._workflow(job="    if: true\n"))
        self.assertEqual(payload["unknown_coverage"], [self.MULTILINE])
        payload = self._scan(block, block)
        self.assertEqual(payload["unknown_coverage"], [self.MULTILINE])


def _hooks(event: str, entries: list[dict[str, Any]]) -> str:
    return json.dumps({"hooks": {event: entries}})


class CommandLocalSkipFlags(unittest.TestCase):
    """#5 / spec 10 §5.1: skip flags are judged per command, not per event."""

    CASES = (
        (".claude/settings.json", "Stop"),
        (".cursor/hooks.json", "stop"),
    )
    FLAGS = (
        ("disabled", True), ("hookEnabled", False),
        ("continueOnError", True), ("failOpen", True),
    )

    def test_new_flagged_sibling_beside_unchanged_commands_is_silent(self) -> None:
        for path, event in self.CASES:
            for flag, value in self.FLAGS:
                for base_entries in (
                    [{"command": "judge-live"}],
                    [{"command": "judge-live"},
                     {"command": "judge-old", "disabled": True}],
                ):
                    with self.subTest(path=path, flag=flag, siblings=len(base_entries)):
                        head_entries = base_entries + [
                            {"command": "judge-new", flag: value},
                        ]
                        payload = _pair(
                            {path: _hooks(event, base_entries)},
                            {path: _hooks(event, head_entries)},
                        )
                        self.assertEqual(payload["findings"], [])
                        self.assertEqual(payload["verdict"], "pass")

    def test_rename_plus_flag_is_caught_when_the_flag_already_exists(self) -> None:
        path, event = self.CASES[0]
        base = _hooks(event, [
            {"command": "judge"}, {"command": "other", "failOpen": True},
        ])
        head = _hooks(event, [
            {"command": "judge-v2", "failOpen": True},
            {"command": "judge-extra"},
            {"command": "other", "failOpen": True},
        ])
        payload = _pair({path: base}, {path: head})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "warn")])

    def test_flagging_an_existing_command_while_adding_a_live_one_fires(self) -> None:
        for path, event in self.CASES:
            for flag, value in self.FLAGS:
                with self.subTest(path=path, flag=flag):
                    base = _hooks(event, [{"command": "judge"}])
                    head = _hooks(event, [
                        {"command": "judge", flag: value}, {"command": "judge-extra"},
                    ])
                    payload = _pair({path: base}, {path: head})
                    self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "warn")])

    def test_rename_plus_flag_of_the_only_command_is_critical(self) -> None:
        path, event = self.CASES[0]
        base = _hooks(event, [{"command": "judge"}])
        head = _hooks(event, [{"command": "judge-v2", "failOpen": True}])
        payload = _pair({path: base}, {path: head})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])
        self.assertEqual(payload["verdict"], "block")


if __name__ == "__main__":
    unittest.main()
