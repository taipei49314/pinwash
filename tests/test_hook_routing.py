"""Spec 13: hook-side `unknown_coverage` rows (SPEC §3.3, §5.1, §7; R06, R07,
R12, R13; #10, #12, #18) and the withdrawn §5.1 matcher row (#12 member 2).

Every row is visibility only: no test here may see a finding, a severity or a
verdict change because of a row (SPEC §7). Each reason is fixed text from
SPEC §7's closed list, reported at most once per (path, reason).
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair

ENV = {"PINWASH_TODAY": "2026-10-09"}
CS = ".claude/settings.json"
CL = ".claude/settings.local.json"
CH = ".cursor/hooks.json"
T = "python hooks/judge.py"
GUARD = "python hooks/guard.py"

REAL = (
    b"import json, sys\n"
    b"def main() -> int:\n"
    b"    if not sys.stdin.read():\n"
    b'        print(json.dumps({"decision": "block", "reason": "no input"}))\n'
    b"        return 0\n"
    b'    print(json.dumps({"decision": "approve"}))\n'
    b"    return 0\n"
    b"sys.exit(main())\n"
)
GUT = (
    b"import json, sys\n"
    b"def main() -> int:\n"
    b'    print(json.dumps({"decision": "approve"}))\n'
    b"    return 0\n"
    b"sys.exit(main())\n"
)
STUB = b"import sys\nsys.exit(0)\n"
REAL_SH = b"#!/bin/sh\necho '{\"decision\": \"block\"}'\n"
GUT_SH = b"#!/bin/sh\nexit 0\n"
FMT = b"#!/bin/sh\nnpx prettier --check .\n"

LIVENESS = "hook stop liveness rests on an unresolved command"
SELECTOR = "hook selector changed (not evaluated)"
NO_LONGER = "hook command target no longer resolved"
NAMES = "hook command names a changed file it does not resolve"
FLAG = "hook skip flag value not boolean"
DAH = "hook settings root disableAllHooks"
ENV_CHANGED = "hook command environment changed"


def _scan(base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    def enc(files: dict[str, Any]) -> dict[str, bytes]:
        return {p: v if isinstance(v, bytes) else v.encode("utf-8") for p, v in files.items()}

    return scan_pair(enc(base), enc(head), base_label="base", head_label="head", env=ENV)


def _rules(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["rule"], f["severity"]) for f in payload["findings"]]


def _reasons(payload: dict[str, Any], path: str | None = None) -> list[str]:
    return [u["reason"] for u in payload["unknown_coverage"] if path is None or u["path"] == path]


def _cmd(command: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"type": "command", "command": command}
    out.update(extra)
    return out


def _settings(*cmds: Any, event: str = "Stop", root: dict[str, Any] | None = None,
              matcher: Any = None) -> str:
    hooks = [c if isinstance(c, dict) else _cmd(c) for c in cmds]
    entry: dict[str, Any] = {"hooks": hooks}
    if matcher is not None:
        entry["matcher"] = matcher
    doc: dict[str, Any] = dict(root or {})
    doc["hooks"] = {event: [entry]}
    return json.dumps(doc)


def _events(events: dict[str, list[Any]], root: dict[str, Any] | None = None) -> str:
    doc: dict[str, Any] = dict(root or {})
    doc["hooks"] = {
        e: [{"hooks": [c if isinstance(c, dict) else _cmd(c) for c in cmds]}]
        for e, cmds in events.items()
    }
    return json.dumps(doc)


class HookStopLiveness(unittest.TestCase):
    """R-10b (T1R as amended): an unresolved command is live for §6.1 under
    §5.2's test; a Stop-like finding kept below critical only because of
    one, or a diff after which the file's Stop liveness rests only on
    unresolved commands, reports the row (§3.3, §1.6)."""

    ROW = {"path": CS, "reason": LIVENESS}

    def _gut(self, base_cmds: list[Any], head_cmds: list[Any], extra: dict[str, Any] | None = None):
        base = {CS: _settings(*base_cmds), "hooks/judge.py": REAL, **(extra or {})}
        head = {CS: _settings(*head_cmds), "hooks/judge.py": GUT, **(extra or {})}
        return _scan(base, head)

    def test_gut_beside_a_new_unresolved_sibling_reports_the_row(self) -> None:
        for sibling in ("echo ok", "python -m pkg.mod", '"$CLAUDE_PROJECT_DIR"/hooks/x.sh'):
            with self.subTest(sibling=sibling):
                payload = self._gut([T], [T, sibling])
                self.assertEqual(_rules(payload), [("GATE_STUBBED", "warn")])
                self.assertEqual(payload["verdict"], "pass")
                self.assertEqual(payload["unknown_coverage"], [self.ROW])

    def test_skip_beside_a_pre_existing_unresolved_judge_reports_the_row(self) -> None:
        base = {CS: _settings("npx tripwire-judge", "bash hooks/lint.sh"), "hooks/lint.sh": FMT}
        head = {CS: _settings("npx tripwire-judge", _cmd("bash hooks/lint.sh", disabled=True)),
                "hooks/lint.sh": FMT}
        payload = _scan(base, head)
        self.assertEqual(_rules(payload), [("HOOK_BYPASSED", "warn")])
        self.assertEqual(payload["unknown_coverage"], [self.ROW])

    def test_liveness_moved_onto_unresolved_commands_reports_the_row(self) -> None:
        # Silent passes before spec 13 (challenger's defect 1): the judge
        # replaced by, or removed beside, a command §3.3 does not resolve.
        cases = (
            ([T], ["echo ok"], {}),
            ([T, "npx notify"], ["npx notify"], {}),
            ([T], ["npx tripwire-judge"], {}),
        )
        for base_cmds, head_cmds, extra in cases:
            with self.subTest(head=head_cmds):
                payload = _scan({CS: _settings(*base_cmds), "hooks/judge.py": REAL, **extra},
                                {CS: _settings(*head_cmds), "hooks/judge.py": REAL, **extra})
                self.assertEqual(payload["verdict"], "pass")
                self.assertIn(LIVENESS, _reasons(payload))

    def test_a_resolved_live_sibling_reports_no_row(self) -> None:
        cmds = [T, "bash hooks/fmt.sh"]
        payload = self._gut(cmds, cmds, {"hooks/fmt.sh": FMT})
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "warn")])
        self.assertEqual(payload["unknown_coverage"], [])

    def test_a_new_resolved_sibling_counts_live_without_a_row(self) -> None:
        # R12 member, booked: a sibling added in the diff keeps the escalator
        # off; its body was read, so no observation is missing.
        payload = self._gut([T], [T, "python hooks/ok.py"],
                            {"hooks/ok.py": b"import json\nprint(json.dumps({}))\n"})
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "warn")])
        self.assertEqual(payload["unknown_coverage"], [])

    def test_a_critical_finding_reports_no_row(self) -> None:
        payload = self._gut([T], [T])
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])
        self.assertEqual(payload["unknown_coverage"], [])

    def test_unresolved_on_both_sides_without_a_stop_finding_reports_no_row(self) -> None:
        stop = ["npx tripwire-judge"]
        base = _events({"Stop": stop, "PreToolUse": ["npx guard"]})
        head = _events({"Stop": stop})
        payload = _scan({CS: base}, {CS: head})
        self.assertEqual(_rules(payload), [("HOOK_REMOVED", "warn")])
        self.assertEqual(payload["unknown_coverage"], [])
        unchanged = _scan({CS: head}, {CS: head})
        self.assertEqual((unchanged["findings"], unchanged["unknown_coverage"]), ([], []))


class WithdrawnMatcherRow(unittest.TestCase):
    """R-12a (#12 member 2): §5.1 has no matcher row. An event whose command
    list is emptied is HOOK_REMOVED whatever its entries' `matcher` values;
    the old `*` row never fired and its branch is gone."""

    def _only_removed(self, payload: dict[str, Any], severity: str) -> None:
        got = [(f["rule"], f["severity"], f["message"]) for f in payload["findings"]]
        self.assertEqual(len(got), 1, got)
        self.assertEqual(got[0][:2], ("HOOK_REMOVED", severity))
        self.assertTrue(got[0][2].endswith("command list emptied"))

    def test_star_removed_and_command_list_emptied_is_one_hook_removed(self) -> None:
        base = {CS: json.dumps({"hooks": {"Stop": [{"matcher": "*", "hooks": [_cmd(T)]}]}}),
                "hooks/judge.py": REAL}
        for entry in ({"matcher": "", "hooks": []}, {"hooks": []}):
            with self.subTest(entry=entry):
                head = dict(base, **{CS: json.dumps({"hooks": {"Stop": [entry]}})})
                self._only_removed(_scan(base, head), "critical")
        pre = {CS: _events({"Stop": [T]}), "hooks/judge.py": REAL}
        pre_base = dict(pre, **{CS: json.dumps({"hooks": {
            "Stop": [{"hooks": [_cmd(T)]}], "PreToolUse": [{"matcher": "*", "hooks": [_cmd(GUARD)]}]}})})
        pre_head = dict(pre, **{CS: json.dumps({"hooks": {
            "Stop": [{"hooks": [_cmd(T)]}], "PreToolUse": [{"matcher": "", "hooks": []}]}})})
        self._only_removed(_scan(pre_base, pre_head), "warn")

    def test_cursor_star_removed_and_emptied_is_one_hook_removed(self) -> None:
        base = {CH: json.dumps({"version": 1, "hooks": {"stop": [{"matcher": "*", "command": T}]}}),
                "hooks/judge.py": REAL}
        head = dict(base, **{CH: json.dumps({"version": 1, "hooks": {"stop": [{"matcher": ""}]}})})
        self._only_removed(_scan(base, head), "critical")

    def test_array_emptied_gives_its_two_findings(self) -> None:
        base = {CS: json.dumps({"hooks": {"Stop": [{"matcher": "*", "hooks": [_cmd(T)]}]}}),
                "hooks/judge.py": REAL}
        head = dict(base, **{CS: json.dumps({"hooks": {"Stop": []}})})
        payload = _scan(base, head)
        self.assertEqual(sorted((f["rule"], f["severity"], f["message"]) for f in payload["findings"]), [
            ("HOOK_BYPASSED", "critical", "hook event Stop array emptied"),
            ("HOOK_REMOVED", "critical", "hook event Stop command list emptied"),
        ])

    def test_an_entry_emptied_beside_a_sibling_entry_is_r12(self) -> None:
        for matcher in ("*", "Bash"):
            with self.subTest(matcher=matcher):
                base = {CS: json.dumps({"hooks": {"PreToolUse": [
                    {"matcher": matcher, "hooks": [_cmd(GUARD)]},
                    {"matcher": "Edit", "hooks": [_cmd("npx keep")]}]}}), "hooks/guard.py": REAL}
                head = dict(base, **{CS: json.dumps({"hooks": {"PreToolUse": [
                    {"matcher": "", "hooks": []},
                    {"matcher": "Edit", "hooks": [_cmd("npx keep")]}]}})})
                self.assertEqual(_scan(base, head)["findings"], [])


class SelectorRow(unittest.TestCase):
    """R-12b (O1 as amended): selector changes on a command live on both
    sides are a row, never a finding."""

    def _pre(self, matcher: Any, *handlers: dict[str, Any], files: dict[str, Any] | None = None):
        doc = {"hooks": {"Stop": [{"hooks": [_cmd(T)]}],
                         "PreToolUse": [dict({"hooks": list(handlers or (_cmd(GUARD),))},
                                             **({} if matcher is None else {"matcher": matcher}))]}}
        out = {CS: json.dumps(doc), "hooks/guard.py": REAL, "hooks/judge.py": REAL}
        out.update(files or {})
        return out

    def _row_only(self, base: dict[str, Any], head: dict[str, Any], path: str = CS) -> None:
        payload = _scan(base, head)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["verdict"], "pass")
        self.assertEqual(payload["unknown_coverage"], [{"path": path, "reason": SELECTOR}])

    def _silent(self, base: dict[str, Any], head: dict[str, Any]) -> None:
        payload = _scan(base, head)
        self.assertEqual((payload["findings"], payload["unknown_coverage"]), ([], []))

    def test_matcher_changes_on_a_kept_command_are_rows(self) -> None:
        for before, after in (
            ("Bash", "NoSuchTool"), ("Bash|Edit|Write", "Edit|Write"), ("Bash", "bash"),
            ("Bash", "^$"), ("Bash", "(?!)"), ("Bash", "NoSuch.*"), ("Bash", ["Bash"]),
            (None, "NoSuchTool"), ("", "Edit|Write"), ("*", "Edit|Write"),
        ):
            with self.subTest(before=before, after=after):
                self._row_only(self._pre(before), self._pre(after))

    def test_former_section_53_cursor_example_is_a_row(self) -> None:
        def cur(m: str) -> dict[str, Any]:
            return {CH: json.dumps({"version": 1, "hooks": {
                "stop": [{"command": T}], "preToolUse": [{"matcher": m, "command": GUARD}]}}),
                "hooks/guard.py": REAL, "hooks/judge.py": REAL}
        self._row_only(cur("Write|Edit|Bash"), cur("Write|Edit"), path=CH)

    def test_if_type_and_nested_matcher_are_rows(self) -> None:
        self._row_only(self._pre("Bash"), self._pre("Bash", _cmd(GUARD, **{"if": "Bash(nosuch *)"})))
        self._row_only(self._pre("Bash"), self._pre("Bash", {"type": "disabled", "command": GUARD}))
        self._row_only(self._pre("Bash"), self._pre("NoSuchTool", _cmd(GUARD, matcher="*")))

    def test_same_targets_spelled_differently_is_the_same_command(self) -> None:
        for spelled in ("python  hooks/guard.py", "python ./hooks/guard.py", "python3 hooks/guard.py"):
            with self.subTest(spelled=spelled):
                self._row_only(self._pre("Bash"), self._pre("NoSuchTool", _cmd(spelled)))

    def test_same_string_with_its_target_deleted_or_added_is_the_same_command(self) -> None:
        deleted = self._pre("NoSuchTool")
        del deleted["hooks/guard.py"]
        payload = _scan(self._pre("Bash"), deleted)
        self.assertIn(SELECTOR, _reasons(payload))
        self.assertEqual(payload["findings"], [])
        added_base = self._pre("Bash")
        del added_base["hooks/guard.py"]
        self.assertIn(SELECTOR, _reasons(_scan(added_base, self._pre("NoSuchTool"))))

    def test_name_list_superset_reorder_and_unchanged_add_no_row(self) -> None:
        for before, after in (("Bash", "Bash|PowerShell"),
                              ("Edit|Write|MultiEdit", "Edit|Write|MultiEdit|NotebookEdit"),
                              ("Edit|Write", "Write|Edit"), ("Bash", "Bash"),
                              # spec 13 review: `-` is a name character (kebab-case
                              # agent names, MCP server names), and a head matcher
                              # that matches everything (absent, "" or "*", one value;
                              # INFERRED) is a widening.
                              ("code-reviewer", "code-reviewer|test-runner"),
                              ("mcp__github-server__create_pull_request",
                               "mcp__github-server__create_pull_request|mcp__github-server__merge"),
                              ("Edit|Write", "*"), ("Edit|Write", ""), ("Edit|Write", None),
                              (None, "*"), ("", "*")):
            with self.subTest(before=before, after=after):
                self._silent(self._pre(before), self._pre(after))

    def test_dropping_a_per_hook_if_only_widens_and_adds_no_row(self) -> None:
        guarded = self._pre("Bash", _cmd(GUARD, **{"if": "Bash(git commit*)"}))
        self._silent(guarded, self._pre("Bash"))
        # Gaining or changing one still is a row.
        self._row_only(guarded, self._pre("Bash", _cmd(GUARD, **{"if": "Bash(nosuch*)"})))

    def test_narrowing_cannot_hide_behind_a_sibling_running_the_same_script(self) -> None:
        """Spec 13 review: two commands of one script swap selectors (one
        narrowed, one widened); the union over the script is unchanged, but
        each string is judged on its own, so the narrowing is a row."""
        def two(bash_m: str, edit_m: str) -> dict[str, Any]:
            doc = {"hooks": {"Stop": [{"hooks": [_cmd(T)]}], "PreToolUse": [
                {"matcher": bash_m, "hooks": [_cmd(GUARD + " --bash")]},
                {"matcher": edit_m, "hooks": [_cmd(GUARD + " --edit")]}]}}
            return {CS: json.dumps(doc), "hooks/guard.py": REAL, "hooks/judge.py": REAL}
        self._row_only(two("Bash", "Edit|Write"), two("Bash|Edit|Write", "Bash"))

    def test_commands_not_live_on_both_sides_add_no_row(self) -> None:
        def flagged(m: str) -> dict[str, Any]:
            return self._pre(m, _cmd(GUARD, disabled=True))
        self._silent(flagged("Bash"), flagged("NoSuchTool"))

        def stub(m: str) -> dict[str, Any]:
            return {CS: json.dumps({"hooks": {"Stop": [{"matcher": m, "hooks": [_cmd("true")]}]}})}
        self._silent(stub("*"), stub("NoSuchTool"))

    def test_one_row_per_file(self) -> None:
        def two(a: str, b: str) -> dict[str, Any]:
            return {CS: json.dumps({"hooks": {
                "Stop": [{"hooks": [_cmd(T)]}],
                "PreToolUse": [{"matcher": a, "hooks": [_cmd(GUARD)]}],
                "PostToolUse": [{"matcher": b, "hooks": [_cmd(GUARD)]}]}}),
                "hooks/guard.py": REAL, "hooks/judge.py": REAL}
        self._row_only(two("Bash", "Edit"), two("X", "Y"))

    def test_list_form_type_naming_the_event_is_not_a_handler_type(self) -> None:
        base = {CH: json.dumps({"hooks": [{"type": "stop", "command": T}]}), "hooks/judge.py": REAL}
        head = {CH: json.dumps({"hooks": [{"event": "stop", "type": "command", "command": T}]}),
                "hooks/judge.py": REAL}
        self._silent(base, head)

    def _raw(self, matcher_json: str) -> dict[str, Any]:
        text = ('{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"%s"}]}],'
                '"PreToolUse":[{"matcher":%s,"hooks":[{"type":"command","command":"%s"}]}]}}'
                % (T, matcher_json, GUARD))
        return {CS: text, "hooks/guard.py": REAL, "hooks/judge.py": REAL}

    def test_deep_non_string_matcher_is_a_row_not_an_engine_error(self) -> None:
        # §8 / §9: no recursion on subject values (repr() raised
        # RecursionError on 3.11 near depth 1000 and on every version past
        # 10000 in the ruling's candidate).
        for depth in (1000, 3000, 20000):
            with self.subTest(depth=depth):
                payload = _scan(self._raw('"Bash"'), self._raw("[" * depth + "]" * depth))
                self.assertEqual(payload["unknown_coverage"], [{"path": CS, "reason": SELECTOR}])
        deep = self._raw("[" * 20000 + "]" * 20000)
        self.assertEqual(_scan(deep, deep)["unknown_coverage"], [])

    def test_object_key_order_is_no_change(self) -> None:
        self._silent(self._raw('{"a":1,"b":[2,{"c":3,"d":4}]}'), self._raw('{"b":[2,{"d":4,"c":3}],"a":1}'))
        self._row_only(self._raw('{"a":1}'), self._raw('{"a":1.0}'))
        self._row_only(self._raw('{"a":true}'), self._raw('{"a":1}'))


class TargetRows(unittest.TestCase):
    """R-18a: (a) a resolved hook command moved out of §3.3's sight; (b) an
    active command names a changed file that is not one of its own §3.3
    targets on that side. Diff-scoped."""

    def test_retarget_out_of_resolution_reports_no_longer_resolved(self) -> None:
        base = {CS: _settings(T), "hooks/judge.py": REAL}
        for head_cmd in ("python -m hooks.judge", "python hooks/judge.rb", 'python "hooks/judge.py"',
                         "python -c 'import sys; sys.exit(0)'", "python hooks/judge.py.bak"):
            with self.subTest(head_cmd=head_cmd):
                head = dict(base, **{CS: _settings(head_cmd), "hooks/judge.rb": b"puts 1\n",
                                     "hooks/judge.py.bak": STUB})
                payload = _scan(base, head)
                self.assertIn(NO_LONGER, _reasons(payload))
                self.assertEqual(payload["verdict"], "pass")

    def test_target_deleted_with_the_command_unchanged(self) -> None:
        payload = _scan({CS: _settings(T), "hooks/judge.py": REAL}, {CS: _settings(T)})
        self.assertEqual(sorted(_reasons(payload)), sorted([LIVENESS, NAMES, NO_LONGER]))
        self.assertEqual(payload["findings"], [])

    def test_unchanged_unresolved_command_with_its_file_changed(self) -> None:
        for cmd, path, body, gut in (
            ('python "$CLAUDE_PROJECT_DIR"/hooks/judge.py', "hooks/judge.py", REAL, GUT),
            ('"$CLAUDE_PROJECT_DIR"/.claude/hooks/judge.sh', ".claude/hooks/judge.sh", REAL_SH, GUT_SH),
            ('"${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/judge.sh"', ".claude/hooks/judge.sh", REAL_SH, GUT_SH),
            ("./hooks/judge", "hooks/judge", REAL_SH, GUT_SH),
            ("python -m hooks.judge", "hooks/judge.py", REAL, GUT),
            ("python -m hooks.judge", "hooks/judge/__main__.py", REAL, GUT),
            ("powershell -File .claude\\hooks\\judge.ps1", ".claude/hooks/judge.ps1",
             b"Write-Output 'deny'\n", b"exit 0\n"),
        ):
            with self.subTest(cmd=cmd, path=path):
                base = {CS: _settings(cmd), path: body}
                payload = _scan(base, dict(base, **{path: gut}))
                self.assertEqual(_reasons(payload), [NAMES])
                self.assertEqual((payload["findings"], payload["verdict"]), ([], "pass"))

    def test_a_resolved_helper_does_not_hide_an_unresolved_judge(self) -> None:
        # Challenger's condition: the named changed path is not one of this
        # command's own targets (a resolved `env.sh` token no longer exempts
        # the whole command).
        cmd = 'bash .claude/hooks/env.sh && "$CLAUDE_PROJECT_DIR"/.claude/hooks/stop.sh'
        files = {CS: _settings(cmd), ".claude/hooks/env.sh": FMT, ".claude/hooks/stop.sh": REAL_SH}
        payload = _scan(files, dict(files, **{".claude/hooks/stop.sh": GUT_SH}))
        self.assertEqual(_reasons(payload), [NAMES])
        self.assertEqual(payload["verdict"], "pass")

    def test_a_resolved_target_edited_in_place_is_the_body_check_not_a_row(self) -> None:
        files = {CS: _settings("bash .claude/hooks/stop.sh"), ".claude/hooks/stop.sh": REAL_SH}
        payload = _scan(files, dict(files, **{".claude/hooks/stop.sh": GUT_SH}))
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])
        self.assertEqual(payload["unknown_coverage"], [])

    def test_module_token_must_be_an_ascii_dotted_identifier(self) -> None:
        for cmd in ("python -m hooks..judge", "python -m 1hooks.judge", "python -mhooks.judge"):
            with self.subTest(cmd=cmd):
                base = {CS: _settings(cmd), "hooks/judge.py": REAL, "1hooks/judge.py": REAL}
                head = dict(base, **{"hooks/judge.py": GUT, "1hooks/judge.py": GUT})
                self.assertEqual(_reasons(_scan(base, head)), [])

    def test_no_row_on_an_unchanged_tree_or_an_unrelated_diff(self) -> None:
        base = {CS: _settings('"$CLAUDE_PROJECT_DIR"/.claude/hooks/stop.sh', "pnpm typecheck"),
                ".claude/hooks/stop.sh": REAL_SH, "README.md": b"a\n"}
        self.assertEqual(_reasons(_scan(base, dict(base))), [])
        self.assertEqual(_reasons(_scan(base, dict(base, **{"README.md": b"b\n"}))), [])

    def test_a_line_ending_only_rewrite_is_not_a_change(self) -> None:
        base = {CS: _settings('"$CLAUDE_PROJECT_DIR"/.claude/hooks/stop.sh'), ".claude/hooks/stop.sh": REAL_SH}
        head = dict(base, **{".claude/hooks/stop.sh": REAL_SH.replace(b"\n", b"\r\n")})
        self.assertEqual(_reasons(_scan(base, head)), [])

    def test_honest_negatives(self) -> None:
        # A resolved hook dropped with no replacement.
        base = {CS: _settings("bash hooks/fmt.sh", "npx prettier --check .", event="PostToolUse"),
                "hooks/fmt.sh": FMT}
        head = dict(base, **{CS: _settings("npx prettier --check .", event="PostToolUse")})
        self.assertEqual(_reasons(_scan(base, head)), [])
        # A rename whose new command resolves, beside an unresolved sibling.
        base = {CS: _settings(T, "pnpm typecheck"), "hooks/judge.py": REAL}
        head = {CS: _settings("python hooks/stop_judge.py", "pnpm typecheck"), "hooks/stop_judge.py": REAL}
        self.assertEqual(_reasons(_scan(base, head)), [])

    def test_flagged_stub_and_commented_commands_are_not_active(self) -> None:
        for cmd in (_cmd('"$CLAUDE_PROJECT_DIR"/hooks/judge.py', disabled=True),
                    "# python hooks/judge.py", "true"):
            with self.subTest(cmd=cmd):
                base = {CS: _settings(cmd, "npx tripwire-judge"), "hooks/judge.py": REAL}
                payload = _scan(base, dict(base, **{"hooks/judge.py": GUT}))
                self.assertNotIn(NAMES, _reasons(payload))
                self.assertNotIn(NO_LONGER, _reasons(payload))


class SpecThirteenReviewRows(unittest.TestCase):
    """Rows the spec 13 review found missing; each is visibility only."""

    def test_judge_replaced_by_enabling_a_pre_staged_unresolved_sibling(self) -> None:
        base = {CS: _settings(_cmd(GUARD), _cmd("npx some-guard", disabled=True), event="PreToolUse"),
                "hooks/guard.py": REAL}
        head = {CS: _settings(_cmd("npx some-guard"), event="PreToolUse"), "hooks/guard.py": REAL}
        payload = _scan(base, head)
        self.assertEqual(payload["verdict"], "pass")
        self.assertIn(NO_LONGER, _reasons(payload))

    def test_lone_cr_rewrite_of_a_named_script_is_a_change(self) -> None:
        cmd = '"$CLAUDE_PROJECT_DIR"/.claude/hooks/judge.sh'
        base = {CS: _settings(cmd), ".claude/hooks/judge.sh": REAL_SH}
        head = {CS: _settings(cmd), ".claude/hooks/judge.sh": REAL_SH.replace(b"\n", b"\r")}
        self.assertIn(NAMES, _reasons(_scan(base, head)))
        crlf = {CS: _settings(cmd), ".claude/hooks/judge.sh": REAL_SH.replace(b"\n", b"\r\n")}
        self.assertNotIn(NAMES, _reasons(_scan(base, crlf)))

    def test_environment_a_hook_command_expands_changed(self) -> None:
        cmd = "python $JDIR/judge.py"
        for before, after in (({"JDIR": "hooks"}, {"JDIR": "decoy"}), ({}, {"JDIR": "decoy"}),
                              ({"JDIR": "hooks"}, {})):
            with self.subTest(before=before, after=after):
                base = {CS: _settings(cmd, root={"env": before} if before else None)}
                head = {CS: _settings(cmd, root={"env": after} if after else None)}
                payload = _scan(base, head)
                self.assertEqual(payload["verdict"], "pass")
                self.assertIn(ENV_CHANGED, _reasons(payload))
        braced = "python ${CLAUDE_PROJECT_DIR}/hooks/judge.py"
        self.assertIn(ENV_CHANGED, _reasons(_scan(
            {CS: _settings(braced)}, {CS: _settings(braced, root={"env": {"CLAUDE_PROJECT_DIR": "/tmp/x"}})})))

    def test_environment_change_no_command_expands_adds_no_row(self) -> None:
        base = {CS: _settings(T, root={"env": {"JDIRX": "a"}}), "hooks/judge.py": REAL}
        head = {CS: _settings(T, root={"env": {"JDIRX": "b"}}), "hooks/judge.py": REAL}
        self.assertNotIn(ENV_CHANGED, _reasons(_scan(base, head)))
        # $JDIR is not $JDIRX: the name ends where it cannot continue.
        cmd = "python $JDIRX/judge.py"
        self.assertNotIn(ENV_CHANGED, _reasons(_scan(
            {CS: _settings(cmd, root={"env": {"JDIR": "a"}})}, {CS: _settings(cmd, root={"env": {"JDIR": "b"}})})))


class LoneCrShellBody(unittest.TestCase):
    """Spec 13 review (§5.2): a shell judge rewritten with lone CRs is one
    line the shell runs as a `#!` comment, a gutted judge. It is a stub body
    now; Python reads a lone CR as a line break, so a .py body still folds."""

    def test_shell_judge_rewritten_with_lone_crs_is_a_stub(self) -> None:
        cmd = "bash .claude/hooks/judge.sh"
        base = {CS: _settings(cmd), ".claude/hooks/judge.sh": REAL_SH}
        head = {CS: _settings(cmd), ".claude/hooks/judge.sh": REAL_SH.replace(b"\n", b"\r")}
        payload = _scan(base, head)
        self.assertEqual(payload["verdict"], "block")
        self.assertIn(("GATE_STUBBED", "critical"), _rules(payload))

    def test_crlf_shell_and_lone_cr_python_bodies_are_unchanged(self) -> None:
        cmd = "bash .claude/hooks/judge.sh"
        base = {CS: _settings(cmd), ".claude/hooks/judge.sh": REAL_SH}
        crlf = {CS: _settings(cmd), ".claude/hooks/judge.sh": REAL_SH.replace(b"\n", b"\r\n")}
        self.assertEqual(_scan(base, crlf)["findings"], [])
        py_base = {CS: _settings(T), "hooks/judge.py": REAL}
        py_cr = {CS: _settings(T), "hooks/judge.py": REAL.replace(b"\n", b"\r")}
        self.assertEqual(_scan(py_base, py_cr)["findings"], [])


class FlagRow(unittest.TestCase):
    """R-18b: non-boolean §5.1 flag values, counted as a multiset of (event,
    command, key, value) occurrences, plus the finding-coupled row."""

    def test_non_boolean_flag_added_or_changed(self) -> None:
        base = {CS: _settings(T), "hooks/judge.py": REAL}
        for flags in ({"disabled": "true"}, {"disabled": 1}, {"hookEnabled": 0},
                      {"continueOnError": "yes"}, {"failOpen": None}, {"disabled": [[[True]]]}):
            with self.subTest(flags=flags):
                payload = _scan(base, dict(base, **{CS: _settings(_cmd(T, **flags))}))
                self.assertEqual(_reasons(payload), [FLAG])
                self.assertEqual((payload["findings"], payload["verdict"]), ([], "pass"))

    def test_a_second_occurrence_of_an_existing_value_is_a_row(self) -> None:
        def doc(*groups: list[dict[str, Any]]) -> str:
            return json.dumps({"hooks": {"Stop": [{"hooks": [_cmd(T)]}], "PreToolUse": [
                dict(matcher=m, hooks=h) for m, h in zip(("Bash", "Edit"), groups)]}})
        files = {"hooks/guard.py": REAL, "hooks/judge.py": REAL}
        base = dict(files, **{CS: doc([_cmd(GUARD, disabled="true")], [_cmd(GUARD)])})
        head = dict(files, **{CS: doc([_cmd(GUARD, disabled="true")], [_cmd(GUARD, disabled="true")])})
        self.assertEqual(_reasons(_scan(base, head)), [FLAG])
        # The occurrence counts are equal, so moving the value between
        # entries is no row (the tuple carries no matcher).
        swapped = dict(files, **{CS: doc([_cmd(GUARD)], [_cmd(GUARD, disabled="true")])})
        self.assertEqual(_reasons(_scan(base, swapped)), [])

    def test_unchanged_or_removed_value_without_a_hook_finding_is_silent(self) -> None:
        cmd = _cmd(T, disabled="false")
        base = {CS: _settings(cmd), "hooks/judge.py": REAL, "README.md": b"a\n"}
        self.assertEqual(_reasons(_scan(base, dict(base, **{"README.md": b"b\n"}))), [])
        self.assertEqual(_reasons(_scan(base, dict(base, **{CS: _settings(T)}))), [])

    def test_a_hook_finding_beside_an_unread_value_reports_the_row(self) -> None:
        # F07: the unread "true" sibling counts live and keeps the finding at
        # warn; the boolean control blocks.
        for value, severity in (("true", "warn"), (True, "critical")):
            with self.subTest(value=value):
                base = {CS: _settings(T, _cmd("bash hooks/notify.sh", disabled=value)),
                        "hooks/judge.py": REAL, "hooks/notify.sh": FMT}
                head = dict(base, **{"hooks/judge.py": GUT})
                payload = _scan(base, head)
                self.assertEqual(_rules(payload), [("GATE_STUBBED", severity)])
                self.assertEqual(_reasons(payload), [FLAG] if value == "true" else [])


class DisableAllHooksRow(unittest.TestCase):
    """R-18c: settings-root `disableAllHooks` set or changed by the diff to
    anything but `false`, or held while a §5 hook finding fires."""

    def test_set_or_changed_to_anything_but_false(self) -> None:
        base = {CS: _settings(T), "hooks/judge.py": REAL}
        for value in (True, "true", 1, None, {"x": [1]}):
            with self.subTest(value=value):
                payload = _scan(base, dict(base, **{CS: _settings(T, root={"disableAllHooks": value})}))
                self.assertEqual(_reasons(payload), [DAH])
                self.assertEqual((payload["findings"], payload["verdict"]), ([], "pass"))
        payload = _scan(base, dict(base, **{CS: _settings(T, root={"disableAllHooks": False})}))
        self.assertEqual(_reasons(payload), [])

    def test_local_file_and_new_file(self) -> None:
        base = {CS: _settings(T), "hooks/judge.py": REAL}
        head = dict(base, **{CL: json.dumps({"disableAllHooks": True})})
        self.assertEqual(_scan(base, head)["unknown_coverage"], [{"path": CL, "reason": DAH}])

    def test_unchanged_or_switched_off_is_silent(self) -> None:
        base = {CS: _settings(T), "hooks/judge.py": REAL}
        on = dict(base, **{CS: _settings(T, root={"disableAllHooks": True}), "README.md": b"x\n"})
        self.assertEqual(_reasons(_scan(on, dict(on, **{"README.md": b"y\n"}))), [])
        self.assertEqual(_reasons(_scan(on, base)), [])

    def test_a_hook_finding_while_hooks_are_off_reports_the_row(self) -> None:
        on = {CS: _settings(T, root={"disableAllHooks": True}), "hooks/judge.py": REAL}
        payload = _scan(on, {CS: json.dumps({"disableAllHooks": True, "hooks": {}})})
        self.assertEqual(_rules(payload), [("HOOK_REMOVED", "critical")])
        self.assertEqual(_reasons(payload), [DAH])

    def test_cursor_hooks_has_no_such_row(self) -> None:
        base = {CH: json.dumps({"version": 1, "hooks": {"stop": [{"command": T}]}}), "hooks/judge.py": REAL}
        head = dict(base, **{CH: json.dumps({"version": 1, "disableAllHooks": True,
                                             "hooks": {"stop": [{"command": T}]}})})
        self.assertEqual(_reasons(_scan(base, head)), [])


class RowsAreVisibilityOnly(unittest.TestCase):
    """SPEC §7: rows never change a finding or the verdict; each (path,
    reason) once; sorted by path, then reason."""

    def test_every_reason_at_once_is_sorted_and_verdict_neutral(self) -> None:
        base = {
            CS: json.dumps({"hooks": {
                "Stop": [{"hooks": [_cmd(T)]}],
                "PreToolUse": [{"matcher": "Bash", "hooks": [_cmd(GUARD)]}],
                "PostToolUse": [{"hooks": [_cmd('"$CLAUDE_PROJECT_DIR"/hooks/fmt.sh')]}]}}),
            "hooks/judge.py": REAL, "hooks/guard.py": REAL, "hooks/fmt.sh": FMT,
        }
        head = {
            CS: json.dumps({"disableAllHooks": "yes", "hooks": {
                "Stop": [{"hooks": [_cmd("npx tripwire-judge")]}],
                "PreToolUse": [{"matcher": "NoSuchTool", "hooks": [_cmd(GUARD, failOpen="true")]}],
                "PostToolUse": [{"hooks": [_cmd('"$CLAUDE_PROJECT_DIR"/hooks/fmt.sh')]}]}}),
            "hooks/judge.py": REAL, "hooks/guard.py": REAL, "hooks/fmt.sh": FMT + b"echo\n",
        }
        payload = _scan(base, head)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["verdict"], "pass")
        self.assertEqual(_reasons(payload), sorted([DAH, NAMES, NO_LONGER, FLAG, LIVENESS, SELECTOR]))
        reasons = [(u["path"], u["reason"]) for u in payload["unknown_coverage"]]
        self.assertEqual(reasons, sorted(set(reasons)))


if __name__ == "__main__":
    unittest.main()
