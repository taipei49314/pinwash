"""Spec 18: the allow-spelling detection bump (SPEC §5.3; R17; #16,
AI-assisted ruling R-16b, option (c) with the challenger's refinement).

A head `permissions.allow` entry matches the §5.3 literals on its canonical
form, and no base entry may have that form. One finding per canonical class
gained: on the literal's own spelling when the head holds it, else on the
first spelling in head order.
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
NPM = "Bash(npm test)"
CLASSES = {
    "Bash": ("Bash", "Bash()", "Bash(*)"),
    "Bash(rm *)": ("Bash(rm *)", "Bash(rm:*)"),
    "Bash(git push --force*)": ("Bash(git push --force*)",),
    "*": ("*",),
}


def _doc(*allow: str) -> dict[str, Any]:
    return {"permissions": {"allow": [NPM, *allow]}}


def _gained(base: dict[str, Any] | None, head: dict[str, Any], path: str = CS) -> list[tuple[str, str]]:
    b = {} if base is None else {path: json.dumps(base).encode()}
    payload = scan_pair(b, {path: json.dumps(head).encode()}, base_label="b", head_label="h", env=ENV)
    return [(f["message"], f["after"]) for f in payload["findings"] if f["rule"] == "PERMISSION_WIDENED"]


class CanonicalClasses(unittest.TestCase):
    def test_the_classes_are_the_host_equivalents(self) -> None:
        self.assertEqual({canonical_rule(x) for x in WIDEN_ALLOW}, set(CLASSES))
        for canon, spellings in CLASSES.items():
            for spelling in spellings:
                self.assertEqual(canonical_rule(spelling), canon)

    def test_every_spelling_is_gained_on_both_paths_and_in_a_created_file(self) -> None:
        for path in (CS, LOCAL):
            for spellings in CLASSES.values():
                for spelling in spellings:
                    with self.subTest(path=path, spelling=spelling):
                        want = [(f"permissions.allow gained {spelling}", spelling)]
                        self.assertEqual(_gained(_doc(), _doc(spelling), path), want)
                        self.assertEqual(_gained(None, _doc(spelling), path), want)

    def test_any_equivalent_base_spelling_suppresses_every_head_spelling(self) -> None:
        for spellings in CLASSES.values():
            for base in spellings:
                for head in spellings:
                    with self.subTest(base=base, head=head):
                        self.assertEqual(_gained(_doc(base), _doc(head)), [])

    def test_one_finding_per_class_on_the_literal_spelling_when_present(self) -> None:
        self.assertEqual(_gained(_doc(), _doc("Bash", "Bash()", "Bash(*)")),
                         [("permissions.allow gained Bash(*)", "Bash(*)")])
        self.assertEqual(_gained(_doc(), _doc("Bash()", "Bash")),
                         [("permissions.allow gained Bash()", "Bash()")])
        self.assertEqual(_gained(_doc(), _doc("Bash(rm:*)", "Bash(rm *)", "Bash(rm *)")),
                         [("permissions.allow gained Bash(rm *)", "Bash(rm *)")])
        self.assertEqual(sorted(_gained(_doc(), _doc("Bash", "Bash(rm:*)", "*"))),
                         [("permissions.allow gained *", "*"), ("permissions.allow gained Bash", "Bash"),
                          ("permissions.allow gained Bash(rm:*)", "Bash(rm:*)")])

    def test_the_literal_fingerprint_is_unchanged(self) -> None:
        # A head that holds the literal keeps the spec 11 fingerprint.
        base = json.dumps(_doc()).encode()
        payload = scan_pair({CS: base}, {CS: json.dumps(_doc("Bash", "Bash(*)")).encode()},
                            base_label="b", head_label="h", env=ENV)
        alone = scan_pair({CS: base}, {CS: json.dumps(_doc("Bash(*)")).encode()},
                          base_label="b", head_label="h", env=ENV)
        self.assertEqual([f["fingerprint"] for f in payload["findings"]],
                         [f["fingerprint"] for f in alone["findings"]])

    def test_near_spellings_outside_the_classes_stay_silent(self) -> None:
        for head in ("Bash(**)", "Bash( * )", "Bash(*) ", " Bash(*)", "Bash (*)", "bash(*)", "BASH",
                     "Bash(* *)", "Bash(*:*)", "Bash(:*)", "*()", "*(*)", "**", "Bash(rm*)", "Bash(rm  *)",
                     "Bash( rm *)", "Bash(rm *:*)", "Bash(rm\\:*)", "Bash(rm:* )", "Bash(rm -rf *)",
                     "Bash(rm -rf:*)", "Bash(git push --force:*)", "Bash(git push --force *)",
                     "Bash(git push -f*)", "Edit", "Edit(*)", "Task(*)"):
            with self.subTest(head=head):
                self.assertEqual(_gained(_doc(), _doc(head)), [])

    def test_a_base_entry_in_either_settings_file_grants_its_class(self) -> None:
        # Review of 2026-10-10: the host merges the two allow lists, so a
        # move or respelling between the files gains nothing.
        def scan(base: dict[str, Any], head: dict[str, Any]) -> list[str]:
            enc = lambda t: {k: json.dumps(v).encode() for k, v in t.items()}
            payload = scan_pair(enc(base), enc(head), base_label="b", head_label="h", env=ENV)
            return [f["message"] for f in payload["findings"] if f["rule"] == "PERMISSION_WIDENED"]
        for spelling in ("Bash(rm:*)", "Bash", "Bash()", "Bash(rm *)", "Bash(*)"):
            with self.subTest(spelling=spelling):
                self.assertEqual(scan({CS: _doc(spelling)}, {CS: _doc(), LOCAL: _doc(spelling)}), [])
                self.assertEqual(scan({LOCAL: _doc(spelling)}, {CS: _doc(spelling)}), [])
        self.assertEqual(scan({CS: _doc("Bash(*)")}, {CS: _doc("Bash(*)"), LOCAL: _doc("Bash")}), [])
        self.assertEqual(scan({CS: _doc("Bash(rm *)")}, {CS: _doc("Bash(rm *)"), LOCAL: _doc("Bash(rm:*)")}), [])
        # A class neither base file holds still fires, in either file.
        self.assertEqual(scan({CS: _doc("Bash(rm *)")}, {CS: _doc("Bash(rm *)"), LOCAL: _doc("Bash")}),
                         ["permissions.allow gained Bash"])
        # Tool-wide edit grants are routed on the same merged base.
        enc = lambda t: {k: json.dumps(v).encode() for k, v in t.items()}
        payload = scan_pair(enc({CS: _doc("Edit")}), enc({CS: _doc(), LOCAL: _doc("Edit")}),
                            base_label="b", head_label="h", env=ENV)
        self.assertEqual(payload["unknown_coverage"], [])

    def test_a_narrower_or_flagged_base_suppresses_nothing(self) -> None:
        for base, head in (("Bash(rm -rf:*)", "Bash(rm:*)"), ("Bash(rm -i *)", "Bash(rm:*)"),
                           ("Bash(npm *)", "Bash"), ("Bash(*:*)", "Bash()")):
            with self.subTest(base=base, head=head):
                self.assertEqual(_gained(_doc(base), _doc(base, head)), [(f"permissions.allow gained {head}", head)])


if __name__ == "__main__":
    unittest.main()
