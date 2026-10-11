"""Engine behaviour that SPEC text states since spec 12 (#25, #26 items 3, 5).

Spec 12 wrote these sentences to what the engine already did, with no
verdict change. Each class pins one of them, so the text and the engine
cannot drift apart unnoticed: a later bump that changes the behaviour
changes the sentence and this test together.
"""

from __future__ import annotations

import json
import unittest
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


if __name__ == "__main__":
    unittest.main()
