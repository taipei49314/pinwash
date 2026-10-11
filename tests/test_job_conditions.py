"""Spec 22: job conditions read as false and job-scope event filters
(SPEC §5, §5.6; R14; #13, AI-assisted rulings R-13a and R-13b as the
challenger amended them).

A required-check producer whose head `if:` §5.6 reads as false, or as an
event filter naming only events off the enforcement path, no longer
reports its context on a pull request: GitHub reports a job its condition
skips as Success. The members are the challenger's executed probes; the
expected verdicts are those of its prototype; the review of 2026-10-10
(AI-assisted) added the bracket, YAML-quote, YAML-null, Unicode-case,
unbalanced and continued-line members.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair
from pinwash.parse.gha import if_event_filtered_off, if_reads_false

ENV = {"PINWASH_TODAY": "2026-10-09"}
WF = ".github/workflows/ci.yml"
NW = ".github/workflows/nightly.yml"
RS = ".github/rulesets/main.json"
ROW = "producer job if unresolved"
MULTI = "multiline uses or scalar"


def _ruleset(*ctx: str) -> str:
    return json.dumps({"rules": [{"type": "required_status_checks", "parameters": {
        "required_status_checks": [{"context": c} for c in ctx]}}]})


def _wf(cond: str | None = None, on: str = "[push, pull_request]", more: str = "") -> str:
    s = f"on: {on}\njobs:\n  ci:\n    name: ci\n    runs-on: ubuntu-latest\n"
    if cond is not None:
        s += f"    if: {cond}\n" + more
    return s + "    steps:\n      - run: make test\n"


def _scan(base: dict[str, str], head: dict[str, str]) -> dict[str, Any]:
    enc = lambda t: {k: v.encode() for k, v in t.items()}
    return scan_pair(enc(base), enc(head), base_label="b", head_label="h", env=ENV)


def _if(head: str | None, base: str | None = None, on: str = "[push, pull_request]") -> dict[str, Any]:
    return _scan({WF: _wf(base, on), RS: _ruleset("ci")}, {WF: _wf(head, on), RS: _ruleset("ci")})


def _dropped(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["severity"], f["after"]) for f in payload["findings"] if f["rule"] == "REQUIRED_CHECK_DROPPED"]


def _rows(payload: dict[str, Any]) -> list[str]:
    return sorted({u["reason"] for u in payload["unknown_coverage"]})


class ConditionsReadAsFalse(unittest.TestCase):
    def test_constant_false_conditions_drop_the_check(self) -> None:
        for cond in (
            "${{ always() && false }}", "${{ !always() }}", "${{ false && always() }}",
            "${{ always() && !true }}", "${{ always() && 0 }}", "${{ always() && null }}",
            "${{ always() && (false) }}", "${{ (always() && false) }}",
            "${{ always() && false && true }}", "${{ false || false }}", "${{ !!false }}",
            "${{ null }}", "${{ false && github.event_name == 'push' }}",
            "${{ github.event_name == 'push' && false }}", "${{ !(always()) }}",
            "${{ always() && !always() }}", "${{false}}", "'${{false}}'", "(false)",
            "${{ (false) }}", "'!true'", "${{ !true }}", "0", "${{ 0 }}", "False",
            "${{ success() && false }}", "always() && false",
        ):
            with self.subTest(cond=cond):
                payload = _if(cond)
                self.assertEqual(_dropped(payload), [("high", cond)])
                self.assertEqual(_rows(payload), [])

    def test_conditions_github_runs_are_not_read(self) -> None:
        # A string built around an expression is truthy, an unquoted `!` is
        # a YAML tag, an empty condition is success(); status functions and
        # comparisons are not evaluated (rows, R14).
        for cond, rows in (
            ("${{ cancelled() }}", [ROW]), ("${{ success() && failure() }}", [ROW]),
            ("${{ false }} && true", [ROW]), ('" ${{ false }}"', [ROW]),
            ("github.repository == 'o/r'", [ROW]), ("${{ always() }}", [ROW]),
            ("${{ !cancelled() }}", [ROW]), ("success()", [ROW]),
            ("${{ false || x }}", [ROW]), ("${{ !(false && x) }}", [ROW]),
            # Review of 2026-10-10: an operator inside an index is not
            # top-level; YAML decodes `''` in a single-quoted value; a
            # double-quoted escape is not decoded, so not read; an unquoted
            # YAML null is an empty condition (success()); unbalanced
            # parentheses are an expression GitHub rejects.
            ("${{ github['a' && false && 'b'] == null }}", [ROW]),
            ("${{ !github[true && false && 'x'] }}", [ROW]),
            ("'${{ github.event_name != ''x && false && y'' }}'", [ROW]),
            ('"${{ github.event_name != \\x27x && false && y\\x27 }}"', [ROW]),
            ("null", [ROW]), ("Null", [ROW]), ("NULL", [ROW]), ("~", [ROW]),
            ("${{ ((false) && false }}", [ROW]),
        ):
            with self.subTest(cond=cond):
                payload = _if(cond)
                self.assertEqual(_dropped(payload), [])
                self.assertEqual(_rows(payload), rows)

    def test_an_unquoted_null_is_not_disabled_at_base(self) -> None:
        self.assertEqual(_dropped(_if("false", "null")), [("high", "false")])

    def test_a_value_continued_on_deeper_lines_is_not_read(self) -> None:
        # YAML folds a plain scalar continued on deeper lines into one value;
        # its first line alone is not the condition (§3.1).
        head = _wf("github.event_name == 'schedule'", more="      || github.event_name == 'pull_request'\n")
        payload = _scan({WF: _wf(), RS: _ruleset("ci")}, {WF: head, RS: _ruleset("ci")})
        self.assertEqual((_dropped(payload), _rows(payload)), ([], [MULTI, ROW]))
        base = _wf("github.event_name == 'schedule'", more="      == false\n")
        payload = _scan({WF: base, RS: _ruleset("ci")}, {WF: _wf("false"), RS: _ruleset("ci")})
        self.assertEqual(_dropped(payload), [("high", "false")])
        payload = _scan({WF: _wf("github.actor != 'bot'"), RS: _ruleset("ci")},
                        {WF: _wf("github.actor != 'bot'", more="      && false\n"), RS: _ruleset("ci")})
        self.assertEqual((_dropped(payload), _rows(payload)), ([], [MULTI, ROW]))

    def test_a_respelt_false_is_no_change(self) -> None:
        for base, head in (("${{false}}", "false"), ("false", "${{false}}"), ("${{ always() && false }}", "0")):
            with self.subTest(base=base, head=head):
                payload = _if(head, base)
                self.assertEqual((payload["findings"], _rows(payload)), ([], []))

    def test_the_reading_is_linear_at_any_nesting(self) -> None:
        self.assertTrue(if_reads_false("${{ " + "(" * 50000 + "false" + ")" * 50000 + " }}"))
        self.assertFalse(if_reads_false("${{ " + "(x || " * 30000 + "false" + ")" * 30000 + " }}"))
        self.assertTrue(if_reads_false("${{ " + " || ".join(["(always() && false)"] * 20000) + " }}"))


class EventFilters(unittest.TestCase):
    def test_filters_off_the_enforcement_path_drop_the_check(self) -> None:
        for cond in (
            "github.event_name == 'workflow_dispatch'", "github.event_name == 'Workflow_Dispatch'",
            "github.EVENT_NAME == 'schedule'", "GitHub.event_name == 'schedule'",
            "github['event_name'] == 'schedule'", "(github.event_name == 'schedule')",
            "github.event_name == 'workflow_dispatch' || github.event_name == 'schedule'",
            "${{ github.event_name == 'release' }}", "${{ 'repository_dispatch' == github.event_name }}",
            "${{ github.event_name == 'workflow_run' || (github.event_name == 'workflow_call') }}",
            # Review of 2026-10-10: index keys and Unicode case as GitHub
            # compares them; YAML's `''` escape decoded.
            "github['EVENT_NAME'] == 'schedule'", "github.event_name == 'relea\u017fe'",
            "github.event_name == 'work\ufb02ow_dispatch'", "'github.event_name == ''schedule'''",
        ):
            with self.subTest(cond=cond):
                payload = _if(cond)
                self.assertEqual(_dropped(payload), [("high", cond)])
                self.assertEqual(_rows(payload), [])

    def test_other_filters_stay_rows(self) -> None:
        for cond in (
            "github.event_name == 'schedule' && true", "github.event_name == 'schedule' || false",
            "github.event_name != 'pull_request' && github.event_name != 'push'",
            "github.event_name == 'pull_request_target'", "github.event_name == 'issue_comment'",
            "github.event_name == 'merge_group'", "github.event_name == 'push'",
            'github.event_name == "schedule"', "contains(fromJSON('[\"schedule\"]'), github.event_name)",
        ):
            with self.subTest(cond=cond):
                payload = _if(cond)
                self.assertEqual(_dropped(payload), [])
                self.assertEqual(_rows(payload), [ROW])

    def test_only_a_workflow_on_the_enforcement_path_loses_its_check(self) -> None:
        # The base workflow ran on neither push nor pull_request, so the job
        # never reported its context on the enforcement path: a row, as for
        # any other changed condition (R14).
        payload = _if("github.event_name == 'workflow_dispatch'", on="workflow_dispatch")
        self.assertEqual((_dropped(payload), _rows(payload)), ([], [ROW]))
        nightly = lambda c=None: _wf(c, on="[schedule, workflow_dispatch]")
        payload = _scan({WF: _wf(), NW: nightly(), RS: _ruleset("ci")},
                        {WF: _wf(), NW: nightly("github.event_name == 'schedule'"), RS: _ruleset("ci")})
        self.assertEqual((_dropped(payload), _rows(payload)), ([], [ROW]))

    def test_a_job_already_filtered_off_is_already_disabled(self) -> None:
        for base, head in (("github.event_name == 'schedule'", "false"),
                           ("github.event_name == 'schedule'", "github.event_name == 'release'"),
                           ("false", "github.event_name == 'schedule'")):
            with self.subTest(base=base, head=head):
                payload = _if(head, base)
                self.assertEqual(_dropped(payload), [])

    def test_trigger_loss_keeps_its_finding(self) -> None:
        payload = _scan({WF: _wf(), RS: _ruleset("ci")},
                        {WF: _wf("github.event_name == 'schedule'", on="schedule"), RS: _ruleset("ci")})
        self.assertEqual(_dropped(payload), [("high", "on: schedule")])

    def test_the_reading_is_linear_at_any_nesting(self) -> None:
        term = "github.event_name == 'schedule'"
        self.assertTrue(if_event_filtered_off("${{ " + " || ".join(["(" + term + ")"] * 20000) + " }}"))
        self.assertTrue(if_event_filtered_off("${{ " + "(" * 50000 + term + ")" * 50000 + " }}"))


if __name__ == "__main__":
    unittest.main()
