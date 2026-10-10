"""Spec 23: the `renamed` disjunct of REQUIRED_CHECK_DROPPED (SPEC §5, §5.5;
R16; #15, AI-assisted ruling R-15 as the challenger amended it).

A linked producer, the same job key in the same workflow file, that reports
another literal context while a head ruleset still names the base one, and
that no other head job reports on the enforcement path (the orphan gate),
drops the check. A head `name:` is compared after one leading YAML anchor
token and one layer of quotes are stripped; producers are linked to
contexts with ASCII letters compared without case, so a case-only rename is
a row, and a later drop on the renamed job is still seen. The members are
the challenger's executed probes and its amendments; the review of
2026-10-10 (AI-assisted) added quoted, empty, continued and spaced names,
matrix and calling decoys, and the claimant and case rows.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair

ENV = {"PINWASH_TODAY": "2026-10-09"}
WF = ".github/workflows/ci.yml"
NW = ".github/workflows/nightly.yml"
RS = ".github/rulesets/main.json"
NAME_ROW = "producer name unresolved"
CASE_ROW = "producer name case changed"
CLAIM_ROW = "head job claims a required context"
MULTI = "multiline uses or scalar"


def _ruleset(*ctx: str) -> str:
    return json.dumps({"rules": [{"type": "required_status_checks", "parameters": {
        "required_status_checks": [{"context": c} for c in ctx]}}]})


def _wf(name: str | None = "tripwire", key: str = "tripwire", on: str = "[push, pull_request]",
        cond: str | None = None) -> str:
    s = f"on: {on}\njobs:\n  {key}:\n"
    if name is not None:
        s += f"    name: {name}\n"
    s += "    runs-on: ubuntu-latest\n"
    if cond is not None:
        s += f"    if: {cond}\n"
    return s + "    steps:\n      - run: make test\n"


def _scan(base: dict[str, str], head: dict[str, str]) -> dict[str, Any]:
    enc = lambda t: {k: v.encode() for k, v in t.items()}
    return scan_pair(enc(base), enc(head), base_label="b", head_label="h", env=ENV)


def _rename(head_name: str | None, extra: dict[str, str] | None = None,
            head_rs: tuple[str, ...] = ("tripwire",)) -> dict[str, Any]:
    head = {WF: _wf(head_name), RS: _ruleset(*head_rs)}
    head.update(extra or {})
    return _scan({WF: _wf(), RS: _ruleset("tripwire")}, head)


def _dropped(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["severity"], f["after"]) for f in payload["findings"] if f["rule"] == "REQUIRED_CHECK_DROPPED"]


def _rows(payload: dict[str, Any]) -> list[str]:
    return sorted({u["reason"] for u in payload["unknown_coverage"]})


class RenamedDisjunct(unittest.TestCase):
    def test_literal_renames_drop_the_check(self) -> None:
        for name in ("evil", "&x evil", "'evil'", "&x 'evil'", "evil # was tripwire"):
            with self.subTest(name=name):
                payload = _rename(name)
                self.assertEqual(_dropped(payload), [("high", "name: evil")])
                self.assertEqual(payload["verdict"], "block")

    def test_a_removed_name_falls_back_to_the_key(self) -> None:
        payload = _scan({WF: _wf(key="ci"), RS: _ruleset("tripwire")}, {WF: _wf(None, key="ci"), RS: _ruleset("tripwire")})
        self.assertEqual(_dropped(payload), [("high", "name: ci")])
        # The same key as the context: no rename.
        self.assertEqual(_dropped(_rename(None)), [])

    def test_names_that_are_not_literal_are_a_row(self) -> None:
        for name in ("!!str evil", "${{ 'evil' }}", "&x ${{ 'evil' }}", "*alias"):
            with self.subTest(name=name):
                payload = _rename(name)
                self.assertEqual(_dropped(payload), [])
                self.assertIn(NAME_ROW, _rows(payload))

    def test_unchanged_spellings_are_silent(self) -> None:
        for name in ("&x tripwire", "'tripwire'", "tripwire # ci"):
            with self.subTest(name=name):
                payload = _rename(name)
                self.assertEqual((payload["findings"], _rows(payload)), ([], []))


class NameSpellings(unittest.TestCase):
    """Review of 2026-10-10: names read as GitHub reads them."""

    def test_a_quoted_value_is_literal_text(self) -> None:
        for name, after in (("'&x tripwire'", "&x tripwire"), ('"&x tripwire"', "&x tripwire"),
                            ("'[ci] evil'", "[ci] evil"), ("'*evil'", "*evil")):
            with self.subTest(name=name):
                self.assertEqual(_dropped(_rename(name)), [("high", "name: " + after)])

    def test_yaml_quote_escapes(self) -> None:
        # YAML's `''` is one quote: a requote is no change.
        base = {WF: _wf("Don't merge"), RS: _ruleset("Don't merge")}
        payload = _scan(base, {WF: _wf("'Don''t merge'"), RS: _ruleset("Don't merge")})
        self.assertEqual((payload["findings"], _rows(payload)), ([], []))
        # A double-quoted escape is not decoded, behind an anchor too.
        payload = _rename('&x "trip\\x77ire"')
        self.assertEqual((_dropped(payload), _rows(payload)), ([], [NAME_ROW]))

    def test_an_empty_name_reports_the_key(self) -> None:
        for name in ("''", '""', "&x ''"):
            with self.subTest(name=name):
                payload = _rename(name)
                self.assertEqual((payload["findings"], _rows(payload)), ([], []))
        base = {WF: _wf("''"), RS: _ruleset("tripwire")}
        payload = _scan(base, {WF: _wf("''") + "  other:\n    runs-on: x\n", RS: _ruleset("tripwire")})
        self.assertEqual(payload["findings"], [])
        payload = _scan({WF: _wf(key="tw"), RS: _ruleset("tripwire")}, {WF: _wf("''", key="tw"), RS: _ruleset("tripwire")})
        self.assertEqual(_dropped(payload), [("high", "name: tw")])

    def test_a_name_continued_on_deeper_lines_is_not_read(self) -> None:
        for name in ("tripwire\n      evil", "tripwire\n\n      evil"):
            with self.subTest(name=name):
                payload = _rename(name)
                self.assertEqual(_dropped(payload), [])
                self.assertIn(MULTI, _rows(payload))

    def test_a_name_ending_in_other_whitespace_is_a_row(self) -> None:
        for name in ("tripwire\u00a0", "\u3000tripwire"):
            with self.subTest(name=repr(name)):
                payload = _rename(name)
                self.assertEqual((_dropped(payload), _rows(payload)), ([], [NAME_ROW]))


class OrphanGate(unittest.TestCase):
    AGG = "  all-green:\n    name: tripwire\n    runs-on: x\n    steps:\n      - run: true\n"

    def test_a_head_job_still_reporting_the_context_keeps_it(self) -> None:
        # An honest aggregator taking the old name, or a decoy: R16.
        head = {WF: _wf("evil") + self.AGG, RS: _ruleset("tripwire")}
        payload = _scan({WF: _wf(), RS: _ruleset("tripwire")}, head)
        self.assertEqual(_dropped(payload), [])
        payload = _rename("evil", {NW: _wf(key="decoy", cond="github.event_name == 'push'")})
        self.assertEqual(_dropped(payload), [])

    def test_a_decoy_that_cannot_report_on_the_enforcement_path_does_not(self) -> None:
        for name, decoy in (
            ("nightly", _wf(key="decoy", on="[schedule, workflow_dispatch]")),
            ("disabled", _wf(key="decoy", cond="false")),
            ("filtered off", _wf(key="decoy", cond="github.event_name == 'schedule'")),
            # Review of 2026-10-10: a matrix job reports `<name> (…)` and a
            # calling job `<name> / …`, never the bare name.
            ("matrix", _wf(key="decoy").replace("    steps:", "    strategy:\n      matrix:\n        py: [a]\n    steps:")),
            ("caller", "on: [push, pull_request]\njobs:\n  decoy:\n    name: tripwire\n    uses: ./.github/workflows/x.yml\n"),
            ("literal anchor text", _wf("'&x tripwire'", key="decoy")),
        ):
            with self.subTest(decoy=name):
                self.assertEqual(_dropped(_rename("evil", {NW: decoy})), [("high", "name: evil")])

    def test_only_while_a_head_ruleset_still_names_the_context(self) -> None:
        payload = _rename("evil", head_rs=("evil",))
        self.assertEqual([f["after"] for f in payload["findings"] if f["after"].startswith("name:")], [])
        payload = _scan({WF: _wf(), RS: _ruleset("tripwire")}, {WF: _wf("evil")})
        self.assertEqual([f["after"] for f in payload["findings"] if f["after"].startswith("name:")], [])


class ClaimantRows(unittest.TestCase):
    def test_decoys_that_close_the_gate_are_a_claimant_row(self) -> None:
        # Review of 2026-10-10: the claimant row reads names as the gate does.
        for decoy in ("tripwire", "&a tripwire", "Tripwire", "TRIPWIRE"):
            with self.subTest(decoy=decoy):
                payload = _rename("evil", {NW: _wf(decoy, key="decoy")})
                self.assertEqual(_dropped(payload), [])
                self.assertIn(CLAIM_ROW, _rows(payload))


class CaseFoldedLinkage(unittest.TestCase):
    def test_a_case_only_rename_is_a_row(self) -> None:
        for name in ("Tripwire", "&x Tripwire", "TRIPWIRE"):
            with self.subTest(name=name):
                payload = _rename(name)
                self.assertEqual(_dropped(payload), [])
                self.assertEqual(_rows(payload), [CASE_ROW])

    def test_a_case_only_rename_by_removing_the_name_is_a_row(self) -> None:
        # ripgrep 3bfa125b2e: `name: Docs` removed from the job keyed docs.
        payload = _scan({WF: _wf("Docs", key="docs"), RS: _ruleset("Docs")}, {WF: _wf(None, key="docs"), RS: _ruleset("Docs")})
        self.assertEqual((_dropped(payload), _rows(payload)), ([], [CASE_ROW]))

    def test_a_drop_after_a_case_rename_is_still_seen(self) -> None:
        # The challenger's two-step: the job reports `Tripwire` while the
        # ruleset names `tripwire`; deleting or disabling it drops the check.
        base = {WF: _wf("Tripwire") + "  other:\n    runs-on: x\n", RS: _ruleset("tripwire")}
        payload = _scan(base, {WF: "on: [push, pull_request]\njobs:\n  other:\n    runs-on: x\n", RS: _ruleset("tripwire")})
        self.assertEqual(_dropped(payload), [("high", "deleted")])
        payload = _scan(base, {WF: _wf("Tripwire", cond="false") + "  other:\n    runs-on: x\n", RS: _ruleset("tripwire")})
        self.assertEqual(_dropped(payload), [("high", "false")])

    def test_folding_is_ascii_only(self) -> None:
        # Non-ASCII letters keep their case: `TRİPWIRE` is another context.
        payload = _rename("TRİPWIRE")
        self.assertEqual(_dropped(payload), [("high", "name: TRİPWIRE")])


class Scope(unittest.TestCase):
    def test_existing_disjuncts_keep_their_findings(self) -> None:
        head = {WF: _wf("evil", cond="false"), RS: _ruleset("tripwire")}
        self.assertEqual(_dropped(_scan({WF: _wf(), RS: _ruleset("tripwire")}, head)), [("high", "false")])
        head = {WF: _wf("evil", on="schedule"), RS: _ruleset("tripwire")}
        self.assertEqual(_dropped(_scan({WF: _wf(), RS: _ruleset("tripwire")}, head)), [("high", "on: schedule")])

    def test_a_job_body_the_grammar_does_not_read_is_not_compared(self) -> None:
        deep = "on: [push, pull_request]\njobs:\n  tripwire:\n      runs-on: x\n"
        payload = _scan({WF: _wf(), RS: _ruleset("tripwire")}, {WF: deep, RS: _ruleset("tripwire")})
        self.assertEqual(_dropped(payload), [])


if __name__ == "__main__":
    unittest.main()
