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

    def test_step_continue_on_error_block_scalar_or_empty_is_unknown(self) -> None:
        # #14 / #4 parity (SPEC §3.1): a step-level `continue-on-error:` whose
        # value continues on later lines is a multiline residual, as the same
        # forms of step `if:` already are; dash-first and the starter layout
        # (step items at job indent) included. No finding, verdict unchanged.
        steps = (
            "      - run: echo ready\n        continue-on-error: |\n          true\n",
            "      - run: echo ready\n        continue-on-error: >-\n          true\n",
            "      - run: echo ready\n        continue-on-error:\n          true\n",
            "      - run: echo ready\n        continue-on-error: # later\n          true\n",
            "      - continue-on-error: |\n          true\n        run: echo ready\n",
            "    - continue-on-error: |\n        true\n      run: echo ready\n",
        )
        for step in steps:
            with self.subTest(step=step):
                payload = self._scan(self._workflow(), self._workflow(steps=step))
                self.assertIn(self.MULTILINE, payload["unknown_coverage"])
                self.assertNotIn(self.CONTINUE, payload["unknown_coverage"])
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["verdict"], "pass")

    def test_step_continue_on_error_block_scalar_needs_no_ruleset(self) -> None:
        # Like step `if: |`, the row is a §3.1 grammar hit on either side,
        # not a producer row: it does not depend on a ruleset.
        step = "      - run: echo ready\n        continue-on-error: |\n          true\n"
        payload = _pair({self.PATH: self._workflow(steps=step)}, {self.PATH: self._workflow()})
        self.assertEqual(payload["unknown_coverage"], [self.MULTILINE])
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
    # Spec 37: Claude commands are direct handlers, while Cursor stays flat.
    if event in ("Stop", "PreToolUse"):
        entries = [{"hooks": [entry]} if "command" in entry and "hooks" not in entry else entry
                   for entry in entries]
    return json.dumps({"hooks": {event: entries}})


class CommandLocalSkipFlags(unittest.TestCase):
    """#5 / spec 10 §5.1: skip flags are judged per command, not per event.
    Since spec 29 (#42) only cursor_hooks reads them: claude_settings reads
    none of the four keys (test_claude_settings_reads_no_skip_key)."""

    # Spec 29 (#42, SPEC §5.1): the claude_settings case moved off this
    # table, which pins the cursor_hooks reading, so CASES[0] is cursor_hooks.
    CASES = (
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
        # Spec 24 draft (R12, AI-assisted): judge-extra was added in the
        # diff and resolves to no body that can refuse, so it does not keep
        # the §6.1 escalator off; spec 10 to 23 held this at warn.
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])

    def test_flagging_an_existing_command_while_adding_a_live_one_fires(self) -> None:
        for path, event in self.CASES:
            for flag, value in self.FLAGS:
                with self.subTest(path=path, flag=flag):
                    base = _hooks(event, [{"command": "judge"}])
                    head = _hooks(event, [
                        {"command": "judge", flag: value}, {"command": "judge-extra"},
                    ])
                    payload = _pair({path: base}, {path: head})
                    # Spec 24 draft (R12): the added judge-extra resolves to
                    # no body that can refuse and keeps nothing off (§6.1).
                    self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])

    def test_rename_plus_flag_of_the_only_command_is_critical(self) -> None:
        path, event = self.CASES[0]
        base = _hooks(event, [{"command": "judge"}])
        head = _hooks(event, [{"command": "judge-v2", "failOpen": True}])
        payload = _pair({path: base}, {path: head})
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])
        self.assertEqual(payload["verdict"], "block")

    def test_claude_settings_reads_no_skip_key(self) -> None:
        # Spec 29 (#42, SPEC §5.1, §5.2): Claude Code 2.1.42 and 2.1.296 run
        # a hook that carries any of the four keys, so claude_settings reads
        # none of them. Each edit that fires on cursor_hooks above is, there,
        # a key added (no finding), a rename or an addition; and a command
        # that carries one stays live, so removing its sibling leaves the
        # event a live command (on cursor_hooks: HOOK_REMOVED, critical).
        path, event = ".claude/settings.json", "Stop"
        for flag, value in self.FLAGS:
            for base_entries, head_entries in (
                ([{"command": "judge"}], [{"command": "judge", flag: value}]),
                ([{"command": "judge"}],
                 [{"command": "judge", flag: value}, {"command": "judge-extra"}]),
                ([{"command": "judge"}], [{"command": "judge-v2", flag: value}]),
                ([{"command": "judge"}, {"command": "other", flag: value}],
                 [{"command": "judge-v2", flag: value}, {"command": "judge-extra"},
                  {"command": "other", flag: value}]),
                ([{"command": "judge"}, {"command": "other", flag: value}],
                 [{"command": "other", flag: value}]),
            ):
                with self.subTest(flag=flag, base=base_entries, head=head_entries):
                    payload = _pair(
                        {path: _hooks(event, base_entries)},
                        {path: _hooks(event, head_entries)},
                    )
                    self.assertEqual(payload["findings"], [])
                    self.assertEqual(payload["verdict"], "pass")


class HookCommandPairing(unittest.TestCase):
    """#10 index shift, #9 shifted comment-out (SPEC §5, §5.1, §5.2). Since
    the spec 24 draft (R12, AI-assisted) commands pair as multisets of their
    strings in every branch and never by list position, so neither an
    inserted sibling nor a reorder moves a finding; and a sibling the diff
    added keeps the §6.1 escalator off only when it resolves to a body that
    can refuse."""

    T = "python hooks/judge.py"
    JUDGE = "hooks/judge.py"
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
    STUB = "import sys\nsys.exit(0)\n"
    CASES = ((".claude/settings.json", "Stop"), (".cursor/hooks.json", "stop"))

    def _scan(self, path, event, base_cmds, head_cmds, base_body, head_body, extra=None):
        base = {path: _hooks(event, base_cmds), self.JUDGE: base_body}
        head = {path: _hooks(event, head_cmds), self.JUDGE: head_body}
        head.update(extra or {})
        return _pair(base, head)

    def test_gutted_judge_behind_an_inserted_live_sibling_fires(self) -> None:
        # Spec 24 draft (R12): the inserted `echo ok` was added in the diff
        # and resolves to no body that can refuse, so the gut is the last
        # Stop judge gone (critical); spec 13 to 23 held it at warn.
        for path, event in self.CASES:
            for body, message in ((self.GUT, "lost block capability"),
                                  (self.STUB, "resolves to a stub body")):
                with self.subTest(path=path, message=message):
                    payload = self._scan(
                        path, event, [{"command": self.T}],
                        [{"command": "echo ok"}, {"command": self.T}],
                        self.REAL, body,
                    )
                    self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])
                    self.assertIn(message, payload["findings"][0]["message"])
                    self.assertEqual(payload["verdict"], "block")

    def test_gutted_judge_beside_a_pre_existing_live_sibling_stays_warn(self) -> None:
        for path, event in self.CASES:
            with self.subTest(path=path):
                payload = self._scan(
                    path, event, [{"command": "echo ok"}, {"command": self.T}],
                    [{"command": self.T}, {"command": "echo ok"}],
                    self.REAL, self.GUT,
                )
                self.assertEqual(_rules(payload), [("GATE_STUBBED", "warn")])
                self.assertEqual(payload["verdict"], "pass")

    def test_gutted_judge_behind_an_inserted_non_live_sibling_blocks(self) -> None:
        # Spec 29 (#42, SPEC §5.1): claude_settings reads no skip key, so a
        # flagged sibling is not live only on cursor_hooks; on claude_settings
        # it is the inserted live sibling of the first test above.
        for flag, value in (("disabled", True), ("failOpen", True)):
            with self.subTest(flag=flag):
                payload = self._scan(
                    ".cursor/hooks.json", "stop", [{"command": self.T}],
                    [{"command": "echo ok", flag: value}, {"command": self.T}],
                    self.REAL, self.GUT,
                )
                self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])
                self.assertEqual(payload["verdict"], "block")

    def test_a_flagged_sibling_at_base_keeps_the_gut_warn_only_on_claude_settings(self) -> None:
        # Spec 29 (#42, SPEC §5.1, §5.2, §6.1): Claude Code runs a hook that
        # carries a skip key, so on claude_settings a flagged sibling already
        # there at base is live and keeps the gutted judge at warn, as the
        # unflagged one of the second test above does; cursor_hooks reads the
        # key, the sibling is not live and the gut is the last Stop judge gone.
        for flag, value in (("disabled", True), ("failOpen", True)):
            for path, event, severity, verdict in (
                (".claude/settings.json", "Stop", "warn", "pass"),
                (".cursor/hooks.json", "stop", "critical", "block"),
            ):
                with self.subTest(flag=flag, path=path):
                    sibling = {"command": "echo ok", flag: value}
                    payload = self._scan(
                        path, event, [sibling, {"command": self.T}],
                        [sibling, {"command": self.T}], self.REAL, self.GUT,
                    )
                    self.assertEqual(_rules(payload), [("GATE_STUBBED", severity)])
                    self.assertEqual(payload["findings"][0]["message"],
                                     f"hook command for {event} lost block capability")
                    self.assertEqual(payload["verdict"], verdict)

    def test_judge_moved_into_a_later_matcher_group_fires(self) -> None:
        base = json.dumps({"hooks": {"Stop": [{"hooks": [{"command": self.T}]}]}})
        head = json.dumps({"hooks": {"Stop": [
            {"hooks": [{"command": "echo ok"}]}, {"hooks": [{"command": self.T}]},
        ]}})
        payload = _pair(
            {".claude/settings.json": base, self.JUDGE: self.REAL},
            {".claude/settings.json": head, self.JUDGE: self.GUT},
        )
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])

    def test_comment_out_behind_an_inserted_sibling_fires(self) -> None:
        for path, event in self.CASES:
            with self.subTest(path=path):
                payload = self._scan(
                    path, event, [{"command": self.T}],
                    [{"command": "echo ok"}, {"command": "# " + self.T}],
                    self.REAL, self.REAL,
                )
                self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])
                finding = payload["findings"][0]
                self.assertEqual((finding["before"], finding["after"]), (self.T, "# " + self.T))

    def test_target_free_judge_commented_out_behind_a_stub_body_sibling_blocks(self) -> None:
        payload = _pair(
            {".claude/settings.json": _hooks("Stop", [{"command": "npx tripwire-judge"}])},
            {".claude/settings.json": _hooks("Stop", [
                {"command": "python hooks/new.py"}, {"command": "# npx tripwire-judge"},
            ]), "hooks/new.py": self.STUB},
        )
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "critical")])
        self.assertEqual(payload["verdict"], "block")

    def test_reordering_unchanged_judges_is_silent(self) -> None:
        other = "python hooks/other.py"
        payload = _pair(
            {".claude/settings.json": _hooks("Stop", [{"command": self.T}, {"command": other}]),
             self.JUDGE: self.REAL, "hooks/other.py": self.REAL},
            {".claude/settings.json": _hooks("Stop", [{"command": other}, {"command": self.T}]),
             self.JUDGE: self.REAL, "hooks/other.py": self.REAL},
        )
        self.assertEqual(payload["findings"], [])

    def test_inserting_a_formatter_before_an_unchanged_judge_is_silent(self) -> None:
        payload = self._scan(
            ".claude/settings.json", "Stop", [{"command": self.T}],
            [{"command": "bash hooks/fmt.sh"}, {"command": self.T}],
            self.REAL, self.REAL, {"hooks/fmt.sh": "#!/bin/sh\nnpx prettier --check .\n"},
        )
        self.assertEqual(payload["findings"], [])

    def test_a_comment_added_beside_the_unchanged_judge_is_silent(self) -> None:
        payload = self._scan(
            ".claude/settings.json", "Stop", [{"command": self.T}],
            [{"command": self.T}, {"command": "# " + self.T}],
            self.REAL, self.REAL,
        )
        self.assertEqual(payload["findings"], [])

    def test_judge_removed_beside_siblings_that_are_not_live_is_hook_removed(self) -> None:
        # Spec 24 draft (R12): through spec 23 the list-index pairing caught
        # these only when the sibling followed the judge, by accident of
        # position (a stub body, `true` or a `#` command moved into the
        # judge's index); with the sibling first they were silent. The
        # event keeps commands but none live after a live command left it.
        # Spec 29 (#42, SPEC §5.1): claude_settings reads no skip key, so the
        # flagged sibling, not live only where `disabled` is read, runs on
        # cursor_hooks; the stub-body, stub-string and `#` siblings stay on
        # claude_settings.
        stubby = "python hooks/stubby.py"
        for sibling in (stubby, "true", "# python hooks/old.py",
                        {"command": "bash hooks/fmt.sh", "disabled": True}):
            path, event = ((".cursor/hooks.json", "stop") if isinstance(sibling, dict)
                           else (".claude/settings.json", "Stop"))
            for order in ("after", "before"):
                with self.subTest(sibling=sibling, order=order):
                    base_cmds = [{"command": self.T}, sibling if isinstance(sibling, dict)
                                 else {"command": sibling}]
                    if order == "before":
                        base_cmds.reverse()
                    head_cmds = [c for c in base_cmds if c.get("command") != self.T]
                    payload = _pair(
                        {path: _hooks(event, base_cmds),
                         self.JUDGE: self.REAL, "hooks/stubby.py": self.STUB},
                        {path: _hooks(event, head_cmds),
                         self.JUDGE: self.REAL, "hooks/stubby.py": self.STUB},
                    )
                    self.assertEqual(_rules(payload), [("HOOK_REMOVED", "critical")])
                    finding = payload["findings"][0]
                    self.assertEqual(finding["message"], f"hook event {event} keeps no live command")
                    self.assertEqual(finding["before"], self.T)

    def test_reordering_beside_placeholders_is_silent(self) -> None:
        # Spec 24 draft (R12): the list-index pairing's warn noise on honest
        # reorders and inserted placeholders is gone.
        for placeholder in ("true", "echo {}", "# python hooks/old.py", "python hooks/stubby.py"):
            with self.subTest(placeholder=placeholder):
                extra = {"hooks/stubby.py": self.STUB}
                moved = self._scan(
                    ".claude/settings.json", "Stop",
                    [{"command": self.T}, {"command": placeholder}],
                    [{"command": placeholder}, {"command": self.T}], self.REAL, self.REAL, extra,
                )
                self.assertEqual(moved["findings"], [])
                inserted = self._scan(
                    ".claude/settings.json", "Stop", [{"command": self.T}],
                    [{"command": placeholder}, {"command": self.T}], self.REAL, self.REAL, extra,
                )
                self.assertEqual(inserted["findings"], [])

    def test_stubbed_judge_after_a_removed_sibling_reports_the_stub_body(self) -> None:
        # Disclosed fingerprint change (spec 24 draft, R12): spec 12 to 23
        # paired this judge with the removed sibling at its list index and
        # reported "lost block capability"; the multiset pairing compares it
        # with its own base body and reports the stub body, so a base
        # allow.toml record naming the old fingerprint no longer matches.
        for first in ("echo start", "npx lint-staged"):
            with self.subTest(first=first):
                payload = self._scan(
                    ".claude/settings.json", "Stop",
                    [{"command": first}, {"command": self.T}],
                    [{"command": self.T}], self.REAL, self.STUB,
                )
                self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])
                self.assertEqual(payload["findings"][0]["message"],
                                 "hook command for Stop resolves to a stub body")

    def test_shifted_twin_of_the_helper_refactor_blocks_where_nothing_live_remains(self) -> None:
        # Disclosed trade (#10): moving `block` into a helper module is the
        # spec 7 shape's known honest false positive, and the unshifted edit
        # blocks under spec 12. Behind an inserted sibling that is not live
        # it now blocks too; behind a live one it is warn.
        helper = "from hooks.policy import decide\nimport sys\nsys.exit(decide(sys.stdin.read()))\n"
        policy = {"hooks/policy.py": "def decide(text):\n    return 2 if not text else 0  # block\n"}
        # Spec 24 draft (R12): an inserted formatter was added in the diff
        # and cannot refuse, so it keeps nothing off either (critical); a
        # formatter already there at base still does (warn). Spec 29 (#42,
        # SPEC §5.1): claude_settings reads no skip key, so the flagged
        # formatter is not live only on cursor_hooks, where that row runs.
        claude, cursor = (".claude/settings.json", "Stop"), (".cursor/hooks.json", "stop")
        for (path, event), sibling, base_sibling, severity in (
            (cursor, {"command": "bash hooks/fmt.sh", "disabled": True}, False, "critical"),
            (claude, {"command": "bash hooks/fmt.sh"}, False, "critical"),
            (claude, {"command": "bash hooks/fmt.sh"}, True, "warn"),
        ):
            with self.subTest(path=path, sibling=sibling, base_sibling=base_sibling):
                payload = self._scan(
                    path, event,
                    [sibling, {"command": self.T}] if base_sibling else [{"command": self.T}],
                    [sibling, {"command": self.T}], self.REAL, helper,
                    dict(policy, **{"hooks/fmt.sh": "#!/bin/sh\nnpx prettier --check .\n"}),
                )
                self.assertEqual(_rules(payload), [("GATE_STUBBED", severity)])
                self.assertEqual(payload["findings"][0]["message"],
                                 f"hook command for {event} lost block capability")

    def test_shifted_comment_out_pairs_on_any_command_that_left(self) -> None:
        # Spec 24 draft (R12): a `#` command the diff added pairs with the
        # base command whose text it carries, else with the first command
        # that left the event, wherever either stands; through spec 23 a
        # text other than the exact command behind an inserted sibling was
        # silent (#9).
        for comment in ("# " + self.T + " (paused)", "#'" + self.T + "'"):
            with self.subTest(comment=comment):
                shifted = self._scan(
                    ".claude/settings.json", "Stop", [{"command": self.T}],
                    [{"command": "echo ok"}, {"command": comment}], self.REAL, self.REAL,
                )
                self.assertEqual(_rules(shifted), [("HOOK_BYPASSED", "critical")])
                self.assertEqual(shifted["findings"][0]["before"], self.T)
                in_place = self._scan(
                    ".claude/settings.json", "Stop", [{"command": self.T}],
                    [{"command": comment}], self.REAL, self.REAL,
                )
                self.assertEqual(_rules(in_place), [("HOOK_BYPASSED", "critical")])


if __name__ == "__main__":
    unittest.main()
