"""Spec 16: permission, parse-status and canonical-spelling rows (SPEC §3,
§5.3, §7; R17, R19; #16, #22, AI-assisted rulings).

Every row is visibility only: no test here may see a finding, a severity or
a verdict change because of a row (SPEC §7). The canonical-form suppression
only removes blocks.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair
from pinwash.rules.permission import WIDEN_ALLOW, canonical_rule

ENV = {"PINWASH_TODAY": "2026-10-09"}
CS = ".claude/settings.json"
LOCAL = ".claude/settings.local.json"
GEMINI = ".gemini/settings.json"
OPENCODE = "opencode.json"
MODE = "permission mode changed (not evaluated)"
OFF = "permission value outside the lattice"
EDIT = "tool-wide edit grant added (not evaluated)"
NEW_UNP = "new surface file unparseable"
BASE_UNP = "surface unparseable at base"
NPM = "Bash(npm test)"


def _scan(base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    def enc(files: dict[str, Any]) -> dict[str, bytes]:
        out = {}
        for k, v in files.items():
            if isinstance(v, bytes):
                out[k] = v
            elif isinstance(v, str):
                out[k] = v.encode("utf-8")
            else:
                out[k] = json.dumps(v).encode("utf-8")
        return out
    return scan_pair(enc(base), enc(head), base_label="b", head_label="h", env=ENV)


def _rows(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(u["path"], u["reason"]) for u in payload["unknown_coverage"]]


def _rules(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["rule"], f["severity"]) for f in payload["findings"]]


class StatusPairRows(unittest.TestCase):
    """R-22a (#22): the three status pairs §3's table does not report."""

    def test_new_file_pinwash_cannot_parse(self) -> None:
        for path, data in ((CS, b"{"), (".mcp.json", b"\xef\xbb\xbf{}"), (".github/workflows/ci.yml",
                           b"on: push\n\tjobs: {}\n"),
                           (".claude/hooks/sounds/done.wav", b"RIFF\xff\xfe")):
            with self.subTest(path=path):
                payload = _scan({}, {path: data})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(_rows(payload), [(path, NEW_UNP)])

    def test_corrupt_base_repaired_or_deleted(self) -> None:
        payload = _scan({CS: b"{"}, {CS: {"permissions": {"allow": [NPM]}}})
        self.assertEqual(payload["findings"], [])
        self.assertEqual(_rows(payload), [(CS, BASE_UNP)])
        payload = _scan({CS: b"{"}, {})
        self.assertEqual(payload["findings"], [])
        self.assertEqual(_rows(payload), [(CS, BASE_UNP)])

    def test_the_reported_pairs_are_unchanged(self) -> None:
        self.assertEqual(_rules(_scan({CS: {}}, {CS: b"{"})), [("SURFACE_UNPARSEABLE", "high")])
        payload = _scan({CS: b"{"}, {CS: b"["})
        self.assertEqual(_rules(payload), [("SURFACE_UNPARSEABLE", "warn")])
        self.assertEqual(payload["unknown_coverage"], [])

    # One path for each scan_pair branch that reads a status pair, each §3
    # family named (review of 2026-10-10): (ok bytes, unparseable bytes).
    JSON = (b"{}", b"{")
    TEXT = (b"x\n", b"\xff")
    BRANCHES = (
        (CS, JSON), (LOCAL, JSON), (".cursor/hooks.json", JSON),
        (".claude/hooks/guard.json", JSON), (".claude/hooks/judge.py", TEXT),
        (".github/workflows/ci.yml", (b"on: push\njobs: {}\n", b"on: push\n\tjobs: {}\n")),
        (".github/rulesets/main.json", JSON), (".github/required-ruleset.json", JSON),
        (".cursor/mcp.json", JSON), (".mcp.json", JSON),
        (GEMINI, JSON), (OPENCODE, JSON),
        (".pinwash/pins.json", (b"[]", b"[")),
        ("AGENTS.md", TEXT), ("CLAUDE.md", TEXT), (".cursorrules", TEXT),
        (".github/copilot-instructions.md", TEXT), (".cursor/rules/a.mdc", TEXT),
        ("pkg/SKILL.md", TEXT), (".agents/skills/x/SKILL.md", TEXT),
    )

    def _path_rows(self, payload: dict[str, Any], path: str) -> list[tuple[str, str]]:
        return [row for row in _rows(payload) if row[0] == path]

    def test_every_branch_reports_the_three_pairs(self) -> None:
        for path, (ok, bad) in self.BRANCHES:
            for base, head, reason in (({}, {path: bad}, NEW_UNP), ({path: bad}, {path: ok}, BASE_UNP),
                                       ({path: bad}, {}, BASE_UNP)):
                with self.subTest(path=path, base=sorted(base), head=sorted(head), reason=reason):
                    payload = _scan(base, head)
                    self.assertEqual(payload["findings"], [])
                    self.assertEqual(self._path_rows(payload, path), [(path, reason)])

    def test_a_hook_command_target_outside_the_hooks_directory(self) -> None:
        # A §3.3 target is routed by the command that names it, not by path.
        settings = {CS: {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python3 hooks/judge.py"}]}]}}}
        target = "hooks/judge.py"
        for base, head, reason in (({}, {target: b"\xff"}, NEW_UNP), ({target: b"\xff"}, {target: b"x\n"}, BASE_UNP),
                                   ({target: b"\xff"}, {}, BASE_UNP)):
            with self.subTest(base=sorted(base), head=sorted(head)):
                payload = _scan(dict(settings, **base), dict(settings, **head))
                self.assertEqual(payload["findings"], [])
                self.assertEqual(self._path_rows(payload, target), [(target, reason)])

    def test_a_corrupt_base_keeps_its_comparison(self) -> None:
        # (unparseable, ok) on a markdown surface still compares as against
        # an absent base; the row is added beside the finding.
        payload = _scan({"AGENTS.md": b"\xff"}, {"AGENTS.md": "skip tripwire\n"})
        self.assertEqual([f["rule"] for f in payload["findings"]], ["SKILL_BYPASS"])
        self.assertEqual(_rows(payload), [("AGENTS.md", BASE_UNP)])


class PermissionModeRows(unittest.TestCase):
    """R-16a (#16): mode changes the §5.3 rows do not evaluate. Since spec
    17 `permissions.defaultMode` is compared (tests/test_permission_mode.py);
    removing `default` or `acceptEdits` and the two mode switches stay
    rows."""

    def test_default_mode_removed_and_mode_switches(self) -> None:
        for base, head in (({"permissions": {"defaultMode": "default"}}, {"permissions": {}}),
                           ({"permissions": {"defaultMode": "acceptEdits"}}, {}),
                           ({"permissions": {"disableBypassPermissionsMode": "disable"}}, {"permissions": {}}),
                           ({"permissions": {"disableAutoMode": "disable"}}, {})):
            with self.subTest(base=base, head=head):
                payload = _scan({CS: base}, {CS: head})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(_rows(payload), [(CS, MODE)])

    def test_a_deleted_local_file(self) -> None:
        payload = _scan({LOCAL: {"permissions": {"defaultMode": "acceptEdits"}}}, {})
        self.assertEqual(_rows(payload), [(LOCAL, MODE)])
        self.assertEqual(_scan({}, {LOCAL: {"permissions": {"defaultMode": "default"}}})["unknown_coverage"], [])

    def test_unchanged_and_respelled_values_are_silent(self) -> None:
        doc = {"permissions": {"defaultMode": "dontAsk", "allow": [NPM]}}
        self.assertEqual(_scan({CS: doc}, {CS: dict(doc, model="x")})["unknown_coverage"], [])
        # Spec 17: a value that is not a string sets nothing.
        self.assertEqual(_scan({CS: {"permissions": {"defaultMode": 1}}},
                               {CS: {"permissions": {"defaultMode": True}}})["unknown_coverage"], [])

    def test_top_level_mode_off_the_lattice_or_removed(self) -> None:
        for base, head in (({}, {"permissionMode": "plan"}),
                           ({"permissionMode": "default"}, {"permissionMode": "auto"}),
                           ({"permissionMode": "dontAsk"}, {"permissionMode": ["dontAsk"]}),
                           ({"permissionMode": "default"}, {}), ({"permissionMode": "plan"}, {"permissionMode": "default"})):
            with self.subTest(base=base, head=head):
                payload = _scan({CS: base}, {CS: head})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(_rows(payload), [(CS, OFF)])

    def test_on_lattice_moves_keep_their_findings_and_get_no_row(self) -> None:
        payload = _scan({CS: {"permissionMode": "default"}}, {CS: {"permissionMode": "acceptEdits"}})
        self.assertEqual(_rules(payload), [("PERMISSION_WIDENED", "high")])
        self.assertEqual(payload["unknown_coverage"], [])
        self.assertEqual(_scan({CS: {"permissionMode": "dontAsk"}}, {CS: {"permissionMode": "default"}})
                         ["unknown_coverage"], [])

    def test_gemini_and_opencode_values_off_their_lattice(self) -> None:
        for path, base, head in ((GEMINI, {}, {"approvalMode": "plan"}),
                                 (GEMINI, {"approvalMode": "default"}, {}),
                                 (OPENCODE, {"permission": {"bash": "deny"}}, {"permission": {"bash": {"*": "allow"}}}),
                                 (OPENCODE, {"permission": {"edit": "deny"}}, {"permission": {}}),
                                 (OPENCODE, {}, {"permission": {"bash": "always"}})):
            with self.subTest(path=path, head=head):
                payload = _scan({path: base}, {path: head})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(_rows(payload), [(path, OFF)])
        payload = _scan({GEMINI: {"approvalMode": "default"}}, {GEMINI: {"approvalMode": "yolo"}})
        self.assertEqual(_rules(payload), [("PERMISSION_WIDENED", "high")])
        self.assertEqual(payload["unknown_coverage"], [])


class ToolWideEditGrants(unittest.TestCase):
    """R-16b (#16): tool-wide edit grants are routed, never a finding."""

    def test_tool_wide_grants_added_are_a_row(self) -> None:
        for entry in ("Edit", "Edit()", "Edit(*)", "Write", "Write(*)", "NotebookEdit", "MultiEdit()"):
            with self.subTest(entry=entry):
                payload = _scan({CS: {"permissions": {"allow": [NPM]}}},
                                {CS: {"permissions": {"allow": [NPM, entry]}}})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(_rows(payload), [(CS, EDIT)])

    def test_path_rules_kept_grants_and_respellings_are_silent(self) -> None:
        for base, head in (([NPM], [NPM, "Edit(src/**)"]), (["Edit"], ["Edit(*)"]), (["Write()"], ["Write"]),
                           (["Edit"], ["Edit"]), ([NPM], [NPM, "edit"])):
            with self.subTest(base=base, head=head):
                payload = _scan({CS: {"permissions": {"allow": base}}}, {CS: {"permissions": {"allow": head}}})
                self.assertEqual(payload["unknown_coverage"], [])


def _doc(*allow: str) -> dict[str, Any]:
    return {"permissions": {"allow": [NPM, *allow]}}


def _widened(base: dict[str, Any], head: dict[str, Any]) -> list[str]:
    payload = _scan({CS: base}, {CS: head})
    return [f["message"] for f in payload["findings"] if f["rule"] == "PERMISSION_WIDENED"]


class CanonicalSuppression(unittest.TestCase):
    """R-16b (#16, p1): a head entry whose canonical form a base entry has
    is not gained; only documented-equivalent spellings share a form."""

    NEAR = (
        "Bash", "Bash()", "Bash(*)", "Bash(**)", "Bash( * )", "Bash(*) ", " Bash(*)", "Bash (*)",
        "bash(*)", "BASH", "Bash(* *)", "Bash(*:*)", "Bash(:*)", "*", "*()", "*(*)", "**",
        "Bash(rm *)", "Bash(rm:*)", "Bash(rm*)", "Bash(rm  *)", "Bash( rm *)", "Bash(rm *:*)",
        "Bash(rm\\:*)", "Bash(rm:* )", "Bash(rm -rf *)", "Bash(rm -rf:*)", "Bash(rm -i *)",
        "Bash(rm)", "Bash(rmdir:*)", "Bash(git push --force*)", "Bash(git push --force:*)",
        "Bash(git push --force *)", "Bash(git push --force)", "Bash(git push -f*)",
        "Bash(git push:*)", "Bash(git push --force --dry-run*)", "Bash(git * push:*)",
        "Edit", "Edit(*)", "Edit()", "Write(*)", "Task(*)", "mcp__github", "Bash(*)x", "Bash((*)",
    )
    EQUIVALENT = {
        "Bash": {"Bash", "Bash()", "Bash(*)"},
        "Bash(rm *)": {"Bash(rm *)", "Bash(rm:*)"},
        "Bash(git push --force*)": {"Bash(git push --force*)"},
        "*": {"*"},
    }

    def test_only_host_equivalents_share_a_literal_canonical_form(self) -> None:
        targets = {canonical_rule(x) for x in WIDEN_ALLOW}
        self.assertEqual(targets, set(self.EQUIVALENT))
        for entry in self.NEAR:
            with self.subTest(entry=entry):
                k = canonical_rule(entry)
                if k in targets:
                    self.assertIn(entry, self.EQUIVALENT[k])
                self.assertEqual(canonical_rule(k), k)

    def test_equivalent_base_spelling_is_no_gain(self) -> None:
        for base, head in (("Bash(rm:*)", "Bash(rm *)"), ("Bash", "Bash(*)"), ("Bash()", "Bash(*)")):
            for keep in (True, False):
                with self.subTest(base=base, head=head, keep=keep):
                    h = _doc(base, head) if keep else _doc(head)
                    self.assertEqual(_widened(_doc(base), h), [])

    def test_narrower_flagged_or_malformed_base_suppresses_nothing(self) -> None:
        for base, head in (
            ("Bash(rm -i *)", "Bash(rm *)"), ("Bash(rm -rf *)", "Bash(rm *)"), ("Bash(rm -rf:*)", "Bash(rm *)"),
            ("Bash(rm*)", "Bash(rm *)"), ("Bash(rm *:*)", "Bash(rm *)"), ("Bash(rm\\:*)", "Bash(rm *)"),
            ("Bash(git push --force --dry-run*)", "Bash(git push --force*)"),
            ("Bash(git push:*)", "Bash(git push --force*)"), ("Bash(git push --force:*)", "Bash(git push --force*)"),
            (" Bash(*)", "Bash(*)"), ("Bash(*) ", "Bash(*)"), ("Bash (*)", "Bash(*)"), ("*(*)", "*"),
            ("*", "Bash(*)"), ("Bash(*)", "*"), ("Bash", "Bash(rm *)"),
        ):
            with self.subTest(base=base, head=head):
                self.assertEqual(_widened(_doc(base), _doc(base, head)), [f"permissions.allow gained {head}"])

    def test_head_side_matches_on_the_canonical_form(self) -> None:
        # Spec 18 (R-16b, the allow-spelling detection bump).
        for head in ("Bash", "Bash()", "Bash(rm:*)"):
            with self.subTest(head=head):
                self.assertEqual(_widened(_doc(), _doc(head)), [f"permissions.allow gained {head}"])


if __name__ == "__main__":
    unittest.main()
