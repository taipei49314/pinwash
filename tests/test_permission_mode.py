"""Spec 17: the permission-mode detection bump (SPEC §5.3; R17; #16,
AI-assisted ruling R-16a with the challenger's amendment).

The lattice is `dontAsk` > `default` > `acceptEdits` > `bypassPermissions`
(`manual` reads as `default`). `permissions.defaultMode` is compared on the
value in effect across `.claude/settings.local.json` over
`.claude/settings.json`; top-level `permissionMode`, which the host does not
read from a settings file, fires only when written as a weak value. Every
finding is `PERMISSION_WIDENED` at high (§6); rows are visibility only (§7).
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair

ENV = {"PINWASH_TODAY": "2026-10-09"}
CS = ".claude/settings.json"
LOCAL = ".claude/settings.local.json"
NPM = "Bash(npm test)"
MODE = "permission mode changed (not evaluated)"
OFF = "permission value outside the lattice"
_ABSENT = object()
MODES = (_ABSENT, "default", "manual", "dontAsk", "acceptEdits", "plan", "auto",
         "bypassPermissions", "DontAsk", 5)
OFF_VALUES = ("plan", "auto", "DontAsk")

# The ruled transitions that are findings, per key.
WIDEN_DM = (
    {(b, "acceptEdits") for b in (_ABSENT, "default", "manual", "dontAsk", 5)}
    | {("dontAsk", h) for h in ("default", "manual", _ABSENT, 5)}
    | {(b, "bypassPermissions") for b in MODES if b != "bypassPermissions"}
)
WIDEN_TOP = (
    {(b, "acceptEdits") for b in (_ABSENT, "default", "manual", "dontAsk", 5)}
    | {(b, "bypassPermissions") for b in MODES if b != "bypassPermissions"}
)


def _doc(key: str, value: Any) -> dict[str, Any]:
    if value is _ABSENT:
        return {"permissions": {"allow": [NPM]}}
    if key == "top":
        return {"permissions": {"allow": [NPM]}, "permissionMode": value}
    return {"permissions": {"allow": [NPM], "defaultMode": value}}


def _scan(base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    def enc(files: dict[str, Any]) -> dict[str, bytes]:
        return {k: v if isinstance(v, bytes) else json.dumps(v).encode() for k, v in files.items()}
    return scan_pair(enc(base), enc(head), base_label="b", head_label="h", env=ENV)


def _found(payload: dict[str, Any]) -> list[tuple[str, str, str]]:
    return [(f["path"], f.get("locator", ""), f["message"])
            for f in payload["findings"] if f["rule"] == "PERMISSION_WIDENED"]


def _rows(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(u["path"], u["reason"]) for u in payload["unknown_coverage"]]


def _equal(a: Any, b: Any) -> bool:
    return a is b or (type(a) is type(b) and a == b)


class ModeLattice(unittest.TestCase):
    """Every transition over ten values, on both keys, in one settings file."""

    def test_findings_on_both_keys(self) -> None:
        for key, widen in (("dm", WIDEN_DM), ("top", WIDEN_TOP)):
            for b in MODES:
                for h in MODES:
                    if _equal(b, h):
                        continue
                    with self.subTest(key=key, base=b, head=h):
                        payload = _scan({CS: _doc(key, b)}, {CS: _doc(key, h)})
                        self.assertEqual(len(_found(payload)), 1 if (b, h) in widen else 0)
                        self.assertEqual(payload["verdict"], "block" if (b, h) in widen else "pass")

    def test_rows_for_what_is_not_evaluated(self) -> None:
        # defaultMode: removing `default` or `acceptEdits` (interactive hosts
        # on v2.1.283+ start in `auto`), and any move to or from a value off
        # the lattice whose head is not `bypassPermissions`.
        def dm_row(b: Any, h: Any) -> str | None:
            if (b, h) in WIDEN_DM:
                return None
            if b in ("default", "manual", "acceptEdits") and (h is _ABSENT or h == 5):
                return MODE
            # Hosts from v2.1.257 on start a project `bypassPermissions` in
            # Manual (review of 2026-10-10).
            if b == "bypassPermissions" and (h is _ABSENT or h == 5 or h == "acceptEdits"):
                return MODE
            if b in OFF_VALUES or h in OFF_VALUES:
                return OFF
            return None

        # Top-level: the spec 16 row (a value moved off the lattice or
        # removed) when no finding fires.
        def top_row(b: Any, h: Any) -> str | None:
            if (b, h) in WIDEN_TOP:
                return None
            if h is _ABSENT or b in OFF_VALUES + (5,) or h in OFF_VALUES + (5,):
                return OFF
            return None

        for key, model in (("dm", dm_row), ("top", top_row)):
            for b in MODES:
                for h in MODES:
                    if _equal(b, h) or (key == "dm" and {b is _ABSENT or b == 5, h is _ABSENT or h == 5} == {True}):
                        continue
                    with self.subTest(key=key, base=b, head=h):
                        reason = model(b, h)
                        rows = _rows(_scan({CS: _doc(key, b)}, {CS: _doc(key, h)}))
                        self.assertEqual(rows, [(CS, reason)] if reason else [])

    def test_messages_and_locators(self) -> None:
        for base, head, message in (
            (_ABSENT, "acceptEdits", "permissions.defaultMode became acceptEdits"),
            ("dontAsk", "default", "permissions.defaultMode dontAsk -> default"),
            ("dontAsk", _ABSENT, "permissions.defaultMode dontAsk removed"),
            ("dontAsk", 5, "permissions.defaultMode dontAsk -> (not a string)"),
            (5, "bypassPermissions", "permissions.defaultMode became bypassPermissions"),
            ("plan", "bypassPermissions", "permissions.defaultMode plan -> bypassPermissions"),
        ):
            with self.subTest(base=base, head=head):
                payload = _scan({CS: _doc("dm", base)}, {CS: _doc("dm", head)})
                self.assertEqual(_found(payload), [(CS, "permissions.defaultMode", message)])

    def test_created_files_on_both_paths(self) -> None:
        for path in (CS, LOCAL):
            for key in ("dm", "top"):
                for head in ("acceptEdits", "bypassPermissions", "dontAsk", "default", "manual", "plan"):
                    with self.subTest(path=path, key=key, head=head):
                        got = _found(_scan({}, {path: _doc(key, head)}))
                        self.assertEqual(len(got), 1 if head in ("acceptEdits", "bypassPermissions") else 0)

    def test_both_keys_are_two_findings_with_distinct_fingerprints(self) -> None:
        head = {"permissions": {"allow": [NPM], "defaultMode": "acceptEdits"}, "permissionMode": "acceptEdits"}
        payload = _scan({CS: _doc("dm", _ABSENT)}, {CS: head})
        fs = payload["findings"]
        self.assertEqual(sorted(f.get("locator", "") for f in fs), ["", "permissions.defaultMode"])
        self.assertEqual(len({f["fingerprint"] for f in fs}), 2)

    def test_the_top_level_finding_keeps_its_spec_11_form(self) -> None:
        payload = _scan({CS: {}}, {CS: {"permissionMode": "acceptEdits"}})
        self.assertNotIn("locator", payload["findings"][0])
        self.assertEqual(payload["findings"][0]["message"], "permissionMode became acceptEdits")


class EffectiveModeAcrossFiles(unittest.TestCase):
    """The challenger's amendment: local over shared, a value that is not a
    string sets nothing, and the finding sits on the file that supplies the
    head's value (the base's, for a removal)."""

    def test_a_local_override_of_dontask_fires_on_the_local_file(self) -> None:
        payload = _scan({CS: _doc("dm", "dontAsk")}, {CS: _doc("dm", "dontAsk"), LOCAL: _doc("dm", "default")})
        self.assertEqual(_found(payload), [(LOCAL, "permissions.defaultMode", "permissions.defaultMode dontAsk -> default")])

    def test_moving_the_mode_between_files_is_silent(self) -> None:
        for value in ("dontAsk", "acceptEdits", "bypassPermissions", "plan"):
            for base, head in (({CS: _doc("dm", value)}, {CS: _doc("dm", _ABSENT), LOCAL: _doc("dm", value)}),
                               ({LOCAL: _doc("dm", value)}, {CS: _doc("dm", value)})):
                with self.subTest(value=value, base=sorted(base)):
                    payload = _scan(base, head)
                    self.assertEqual(payload["findings"], [])
                    self.assertEqual(payload["unknown_coverage"], [])

    def test_relocating_top_level_dontask_to_default_mode_is_no_finding(self) -> None:
        payload = _scan({CS: _doc("top", "dontAsk")}, {CS: _doc("dm", "dontAsk")})
        self.assertEqual(payload["findings"], [])

    def test_deleting_a_file_that_held_dontask(self) -> None:
        for path in (CS, LOCAL):
            with self.subTest(path=path):
                payload = _scan({path: _doc("dm", "dontAsk")}, {})
                self.assertEqual(_found(payload), [(path, "permissions.defaultMode", "permissions.defaultMode dontAsk removed")])

    def test_removing_the_local_override_exposes_the_shared_value(self) -> None:
        # Local `dontAsk` over a shared `acceptEdits`: deleting the local
        # file moves the value in effect down to `acceptEdits`.
        payload = _scan({CS: _doc("dm", "acceptEdits"), LOCAL: _doc("dm", "dontAsk")}, {CS: _doc("dm", "acceptEdits")})
        self.assertEqual(_found(payload), [(CS, "permissions.defaultMode", "permissions.defaultMode dontAsk -> acceptEdits")])

    def test_a_value_that_is_not_a_string_sets_nothing(self) -> None:
        payload = _scan({CS: _doc("dm", "dontAsk")}, {CS: _doc("dm", "dontAsk"), LOCAL: _doc("dm", 5)})
        self.assertEqual(payload["findings"], [])
        payload = _scan({LOCAL: _doc("dm", "dontAsk")}, {LOCAL: _doc("dm", [1])})
        self.assertEqual(_found(payload), [(LOCAL, "permissions.defaultMode", "permissions.defaultMode dontAsk -> (not a string)")])

    def test_an_unparseable_file_compares_each_readable_file_alone(self) -> None:
        # The local file goes unparseable (SURFACE_UNPARSEABLE, high); the
        # shared file is still compared on its own.
        payload = _scan({CS: _doc("dm", "dontAsk"), LOCAL: _doc("dm", _ABSENT)},
                        {CS: _doc("dm", "default"), LOCAL: b"{"})
        self.assertEqual(_found(payload), [(CS, "permissions.defaultMode", "permissions.defaultMode dontAsk -> default")])
        self.assertIn(("SURFACE_UNPARSEABLE", "high"), [(f["rule"], f["severity"]) for f in payload["findings"]])
        # A corrupt base local file: the shared file is unchanged, and the
        # local one cannot be compared (a row; R17 books the masking).
        payload = _scan({CS: _doc("dm", "dontAsk"), LOCAL: b"{"},
                        {CS: _doc("dm", "dontAsk"), LOCAL: _doc("dm", "default")})
        self.assertEqual(payload["findings"], [])
        self.assertIn((LOCAL, "surface unparseable at base"), _rows(payload))
        # A new local file pinwash cannot parse.
        payload = _scan({CS: _doc("dm", "dontAsk")}, {CS: _doc("dm", "dontAsk"), LOCAL: b"{"})
        self.assertEqual(payload["findings"], [])
        self.assertEqual(_rows(payload), [(LOCAL, "new surface file unparseable")])

    def test_a_deleted_file_next_to_an_unparseable_one_is_compared(self) -> None:
        # Review of 2026-10-10: a garbage sibling no longer silences the
        # removal; a created file is compared from absent as before.
        for base, head in (
            ({CS: _doc("dm", "dontAsk")}, {LOCAL: b"{garbage"}),
            ({CS: b"{", LOCAL: _doc("dm", "dontAsk")}, {CS: b"{"}),
            ({CS: _doc("dm", "dontAsk"), LOCAL: b"{"}, {LOCAL: b"{"}),
        ):
            with self.subTest(base=sorted(base), head=sorted(head)):
                path = next(k for k, v in base.items() if not isinstance(v, bytes))
                self.assertEqual(_found(_scan(base, head)),
                                 [(path, "permissions.defaultMode", "permissions.defaultMode dontAsk removed")])
        payload = _scan({CS: b"{"}, {CS: b"{", LOCAL: _doc("dm", "acceptEdits")})
        self.assertEqual(_found(payload), [(LOCAL, "permissions.defaultMode", "permissions.defaultMode became acceptEdits")])
        payload = _scan({CS: _doc("dm", "default")}, {LOCAL: b"{garbage"})
        self.assertIn((CS, MODE), _rows(payload))

    def test_bypass_removed_or_moved_to_accept_edits_is_a_row(self) -> None:
        for head in (_ABSENT, "acceptEdits", 5):
            with self.subTest(head=head):
                payload = _scan({CS: _doc("dm", "bypassPermissions")}, {CS: _doc("dm", head)})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(_rows(payload), [(CS, MODE)])
        payload = _scan({CS: _doc("dm", "bypassPermissions")}, {CS: _doc("dm", "default")})
        self.assertEqual(payload["unknown_coverage"], [])

    def test_removed_default_or_accept_edits_is_a_row_on_the_supplying_file(self) -> None:
        for value in ("default", "acceptEdits", "manual"):
            with self.subTest(value=value):
                payload = _scan({CS: _doc("dm", "dontAsk"), LOCAL: _doc("dm", value)}, {CS: _doc("dm", "dontAsk")})
                self.assertEqual(payload["findings"], [])
                payload = _scan({CS: _doc("dm", _ABSENT), LOCAL: _doc("dm", value)}, {CS: _doc("dm", _ABSENT)})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(_rows(payload), [(LOCAL, MODE)])


if __name__ == "__main__":
    unittest.main()
