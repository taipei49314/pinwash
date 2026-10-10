"""Spec 14: workflow-side `unknown_coverage` rows (SPEC §3.1, §5.5, §7; R03,
R14, R15, R16, R20; #13, #14, #15, #23, #24).

Every producer row is visibility only: no test here may see a finding, a
severity or a verdict change because of a row (SPEC §7). Each reason is fixed
text from SPEC §7's closed list, reported at most once per (path, reason).
The grammar rows of #23 / #24 also read a job table the grammar does not
resolve as unresolved, never as deleted; the tests that pin that trade say so.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair

ENV = {"PINWASH_TODAY": "2026-10-09"}
WF = ".github/workflows/ci.yml"
WF2 = ".github/workflows/other.yml"
INNER = ".github/workflows/inner.yml"
RS = ".github/required-ruleset.json"
SHA = "8f4b7f84864484a7bf31766abe9204da3cbe65b3"

IF_ROW = "producer job if unresolved"
NEEDS_ROW = "producer job needs changed"
TRIGGER_ROW = "producer trigger configuration changed"
STEPS_ROW = "producer step run keys changed"
NAME_ROW = "producer name unresolved"
STRATEGY_ROW = "producer job strategy changed"
CLAIM_ROW = "head job claims a required context"
REUSABLE_ROW = "reusable workflow producer unresolved"
SPELLING = "quoted or spaced key unresolved"
FLOW_JOB = "flow-style job unresolved"
FLOW_WORKFLOW = "flow-style workflow unresolved"
JOBS_INDENT = "jobs indentation unresolved"
AFTER_JOBS = "top-level key after jobs unresolved"
ON_UNRESOLVED = "on triggers unresolved"
MULTILINE = "multiline uses or scalar"
LAYOUT = "workflow layout unresolved"
ALIAS = "yaml alias"


def ruleset(*contexts: str) -> str:
    return json.dumps({"rules": [{
        "type": "required_status_checks",
        "parameters": {"required_status_checks": [{"context": c} for c in contexts]},
    }]})


def wf(
    *, on: str = "on: [push, pull_request]\n", key: str = "ci",
    name: str = "    name: ci\n", job: str = "",
    steps: str = "      - run: make test\n", extra: str = "",
) -> str:
    return (
        on + "jobs:\n  " + key + ":\n" + name + "    runs-on: ubuntu-latest\n"
        + job + "    steps:\n" + steps + extra
    )


GATE = "  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./check-paths\n"


def _scan(
    base: dict[str, str] | str, head: dict[str, str] | str,
    contexts: tuple[str, ...] | None = ("ci",),
) -> dict[str, Any]:
    b = {WF: base} if isinstance(base, str) else dict(base)
    h = {WF: head} if isinstance(head, str) else dict(head)
    if contexts is not None:
        b[RS] = ruleset(*contexts)
        h[RS] = ruleset(*contexts)
    return scan_pair(
        {p: v.encode("utf-8") for p, v in b.items()},
        {p: v.encode("utf-8") for p, v in h.items()},
        base_label="base", head_label="head", env=ENV,
    )


def _rules(payload: dict[str, Any]) -> list[tuple[str, str, str]]:
    return [(f["rule"], f["severity"], f.get("after", "")) for f in payload["findings"]]


def _reasons(payload: dict[str, Any], path: str = WF) -> list[str]:
    return [u["reason"] for u in payload["unknown_coverage"] if u["path"] == path]


class _RowCase(unittest.TestCase):
    def assertRowOnly(self, payload: dict[str, Any], reasons: list[str], path: str = WF) -> None:
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["verdict"], "pass")
        self.assertEqual(_reasons(payload, path), sorted(reasons))

    def assertSilent(self, payload: dict[str, Any]) -> None:
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["unknown_coverage"], [])
        self.assertEqual(payload["verdict"], "pass")


class ProducerJobIf(_RowCase):
    """R-13a (#13, R14): a linked producer's job `if:` changed to a value
    outside the closed forms is a row; §6's dropped-check sentence is the
    reason for the spec 9 severity, not a trigger."""

    def test_values_outside_the_closed_forms_are_a_row(self) -> None:
        for value in (
            "${{ always() && false }}", "${{false}}", "${{ !true }}", "always() && false",
            "github.repository == 'o/r'", "github.event_name == 'workflow_dispatch'",
            "'|'", "${{ 3 > 2 }}", "success()",
        ):
            with self.subTest(value=value):
                self.assertRowOnly(_scan(wf(), wf(job=f"    if: {value}\n")), [IF_ROW])

    def test_closed_true_forms_removal_and_unchanged_values_are_silent(self) -> None:
        for value in ("true", "'true'", '"true"', "${{ true }}"):
            with self.subTest(value=value):
                self.assertSilent(_scan(wf(), wf(job=f"    if: {value}\n")))
        guarded = wf(job="    if: github.repository == 'o/r'\n")
        self.assertSilent(_scan(guarded, wf()))
        self.assertSilent(_scan(guarded, guarded))

    def test_closed_false_forms_keep_the_finding_without_a_row(self) -> None:
        for value in ("false", "'false'", "${{ false }}", "FALSE"):
            with self.subTest(value=value):
                payload = _scan(wf(), wf(job=f"    if: {value}\n"))
                self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", value)])
                self.assertEqual(payload["unknown_coverage"], [])

    def test_unlinked_job_or_no_ruleset_is_silent(self) -> None:
        head = wf(job="    if: ${{ always() && false }}\n")
        self.assertSilent(_scan(wf(), head, contexts=("other",)))
        self.assertSilent(_scan(wf(), head, contexts=None))

    def test_a_row_beside_a_finding_changes_nothing(self) -> None:
        head = wf(job="    continue-on-error: true\n    if: github.actor != 'bot'\n")
        payload = _scan(wf(), head)
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "continue-on-error: true")])
        self.assertEqual(_reasons(payload), [IF_ROW])


class ProducerNeeds(_RowCase):
    """R-13a (#13, R14): `needs:` added, changed or removed on a linked
    producer, and a job it needs (same file, through head `needs:`) whose
    `if:` or `needs:` changed or which is gone."""

    def test_needs_added_changed_or_removed_is_a_row(self) -> None:
        gated = wf(job="    needs: gate\n", extra=GATE)
        self.assertRowOnly(_scan(wf(extra=GATE), gated), [NEEDS_ROW])
        self.assertRowOnly(_scan(gated, wf(extra=GATE)), [NEEDS_ROW])
        self.assertRowOnly(
            _scan(gated, wf(job="    needs: [gate, lint]\n", extra=GATE + GATE.replace("gate", "lint"))),
            [NEEDS_ROW],
        )

    def test_indent_four_sequence_items_are_read(self) -> None:
        # The verifier's member: `needs:` / `    - gate` (dash at job indent).
        before = wf(job="    needs:\n    - gate\n", extra=GATE + GATE.replace("gate", "lint"))
        after = wf(job="    needs:\n    - gate\n    - lint\n", extra=GATE + GATE.replace("gate", "lint"))
        self.assertRowOnly(_scan(before, after), [NEEDS_ROW])

    def test_respelled_needs_are_no_change(self) -> None:
        extra = GATE + GATE.replace("gate", "lint")
        for head in ("    needs:\n      - lint\n      - 'gate'\n", "    needs: [\"lint\", gate]\n",
                     "    needs:\n    - gate\n    - lint\n"):
            with self.subTest(head=head):
                self.assertSilent(_scan(wf(job="    needs: [gate, lint]\n", extra=extra),
                                        wf(job=head, extra=extra)))

    def test_gate_job_changes_are_a_row(self) -> None:
        # The two-step form: the producer's `needs:` is unchanged.
        gated = wf(job="    needs: gate\n", extra=GATE)
        for gate in (
            GATE.replace("    runs-on", "    if: false\n    runs-on"),
            GATE.replace("    runs-on", "    if: github.event_name == 'push'\n    runs-on"),
            GATE.replace("    runs-on", "    needs: lint\n    runs-on") + GATE.replace("gate", "lint"),
        ):
            with self.subTest(gate=gate):
                self.assertRowOnly(_scan(gated, wf(job="    needs: gate\n", extra=gate)), [NEEDS_ROW])

    def test_gate_of_a_gate_and_a_deleted_gate_are_a_row(self) -> None:
        chain = GATE.replace("    runs-on", "    needs: g2\n    runs-on") + GATE.replace("gate", "g2")
        base = wf(job="    needs: gate\n", extra=chain)
        head = wf(job="    needs: gate\n", extra=chain.replace(
            "  g2:\n    runs-on", "  g2:\n    if: false\n    runs-on"))
        self.assertRowOnly(_scan(base, head), [NEEDS_ROW])
        self.assertRowOnly(_scan(wf(job="    needs: gate\n", extra=GATE), wf(job="    needs: gate\n")),
                           [NEEDS_ROW])

    def test_gate_body_and_widening_gate_edits_are_silent(self) -> None:
        # A gate whose `run:` text starts failing stays in R14 without a row;
        # a gate `if:` changed to an always-running form or dropped widens.
        gated = wf(job="    needs: gate\n", extra=GATE)
        failing = wf(job="    needs: gate\n", extra=GATE.replace("./check-paths", "exit 1"))
        self.assertSilent(_scan(gated, failing))
        guarded = wf(job="    needs: gate\n", extra=GATE.replace("    runs-on", "    if: x == 'y'\n    runs-on"))
        self.assertSilent(_scan(guarded, gated))
        self.assertSilent(_scan(guarded, wf(job="    needs: gate\n", extra=GATE.replace(
            "    runs-on", "    if: true\n    runs-on"))))


class ProducerTriggerConfiguration(_RowCase):
    """R-13a (#13, R14): `push` / `pull_request` configuration of a linked
    producer's workflow, on a trigger present on both sides."""

    ON = "on:\n  push:\n  pull_request:\n"

    def test_configuration_changes_are_a_row(self) -> None:
        for on in (
            "on:\n  push:\n    paths-ignore: [hooks/**, .claude/**]\n  pull_request:\n    paths-ignore: [hooks/**]\n",
            "on:\n  push:\n    paths:\n    - no/such/**\n  pull_request:\n",
            "on:\n  push:\n    branches-ignore: ['**']\n  pull_request:\n    types: [closed]\n",
            "on:\n  push: {paths-ignore: ['**']}\n  pull_request:\n",
            "on:\n  push:\n    branches: [main]\n  pull_request:\n",
        ):
            with self.subTest(on=on):
                self.assertRowOnly(_scan(wf(on=self.ON), wf(on=on)), [TRIGGER_ROW])

    def test_trigger_set_changes_and_other_triggers_are_not_this_row(self) -> None:
        self.assertSilent(_scan(wf(on="on:\n  push:\n"), wf(on=self.ON)))
        self.assertSilent(_scan(wf(on=self.ON + "  schedule:\n    - cron: '0 0 * * *'\n"),
                                wf(on=self.ON + "  schedule:\n    - cron: '0 1 * * *'\n")))
        payload = _scan(wf(on=self.ON), wf(on="on:\n  workflow_dispatch:\n"))
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "on: workflow_dispatch")])
        self.assertEqual(payload["unknown_coverage"], [])

    def test_unlinked_workflow_is_silent(self) -> None:
        head = wf(on="on:\n  push:\n    paths: [docs/**]\n  pull_request:\n")
        self.assertSilent(_scan(wf(on=self.ON), head, contexts=("other",)))


class ProducerStepRunKeys(_RowCase):
    """R-14 (#14, R15): `if`, `continue-on-error` and `shell` added or changed
    inside a linked producer's `steps:` and `defaults:` blocks, a `- ` item at
    job indent included, never inside a step's `with:`."""

    def test_added_or_changed_step_run_keys_are_a_row(self) -> None:
        for steps in (
            "      - run: make test\n        continue-on-error: true\n",
            "      - run: make test\n        if: false\n",
            "      - if: false\n        run: make test\n",
            "      - continue-on-error: ${{ true }}\n        run: make test\n",
            "      - run: make test\n        if: failure()\n",
            "      - run: make test\n        shell: 'true {0}'\n",
        ):
            with self.subTest(steps=steps):
                self.assertRowOnly(_scan(wf(), wf(steps=steps)), [STEPS_ROW])

    def test_starter_layout_dash_at_job_indent(self) -> None:
        base = wf(steps="    - run: make test\n")
        for steps in ("    - if: false\n      run: make test\n",
                      "    - continue-on-error: true\n      run: make test\n",
                      "    - run: make test\n      if: false\n"):
            with self.subTest(steps=steps):
                self.assertRowOnly(_scan(base, wf(steps=steps)), [STEPS_ROW])

    def test_job_defaults_shell_is_a_row(self) -> None:
        head = wf(job="    defaults:\n      run:\n        shell: 'true {0}'\n")
        self.assertRowOnly(_scan(wf(), head), [STEPS_ROW])

    def test_with_inputs_matrix_entries_and_removals_are_silent(self) -> None:
        action = "      - uses: org/judge@" + SHA + "\n        with:\n          shell: bash\n          if: x\n"
        self.assertSilent(_scan(wf(steps=action), wf(steps=action.replace("bash", "pwsh").replace("x\n", "y\n"))))
        strategy = "    strategy:\n      matrix:\n        include:\n          - shell: bash\n"
        payload = _scan(wf(job=strategy), wf(job=strategy.replace("bash", "pwsh")))
        self.assertRowOnly(payload, [STRATEGY_ROW])
        optional = wf(steps="      - run: make test\n        continue-on-error: true\n")
        self.assertSilent(_scan(optional, wf()))
        two = "      - run: a\n        if: x\n      - run: b\n        shell: bash\n"
        self.assertSilent(_scan(wf(steps=two), wf(steps="      - run: b\n        shell: bash\n      - run: a\n        if: x\n")))

    def test_job_level_continue_on_error_keeps_its_finding(self) -> None:
        payload = _scan(wf(), wf(job="    continue-on-error: true\n"))
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "continue-on-error: true")])
        self.assertEqual(payload["unknown_coverage"], [])

    def test_honest_optional_step_gets_one_row(self) -> None:
        upload = wf(steps="      - run: make test\n      - uses: org/codecov@" + SHA + "\n"
                    "        continue-on-error: true\n")
        self.assertRowOnly(_scan(wf(steps="      - run: make test\n      - uses: org/codecov@" + SHA + "\n"),
                                 upload), [STEPS_ROW])


class ProducerLinkage(_RowCase):
    """R-15 (#15, R16): an expression `name:`, `strategy:` added or changed,
    and head claimants. A literal rename stays booked (R16's detection bump)."""

    def test_expression_name_is_a_row(self) -> None:
        for name in ("    name: ${{ 'verify' }}\n", "    name: ci (${{ matrix.py }})\n",
                     "    name: verify-${{ '' }}\n"):
            with self.subTest(name=name):
                self.assertRowOnly(_scan(wf(), wf(name=name)), [NAME_ROW])

    def test_literal_rename_stays_silent(self) -> None:
        for name in ("    name: verify\n", "    name: Ci\n", ""):
            with self.subTest(name=name):
                self.assertSilent(_scan(wf(), wf(name=name)))

    def test_strategy_added_or_changed_is_a_row(self) -> None:
        matrix = "    strategy:\n      matrix:\n        py: ['3.11']\n"
        self.assertRowOnly(_scan(wf(), wf(job=matrix)), [STRATEGY_ROW])
        self.assertRowOnly(_scan(wf(job=matrix), wf(job=matrix.replace("'3.11'", "'3.11', '3.12'"))),
                           [STRATEGY_ROW])
        self.assertRowOnly(_scan(wf(), wf(job="    strategy: {fail-fast: false}\n")), [STRATEGY_ROW])
        self.assertSilent(_scan(wf(job=matrix), wf()))

    def test_claimants_are_a_row_on_their_file(self) -> None:
        decoy = "  decoy:\n    name: ci\n    runs-on: x\n    steps:\n      - run: true\n"
        self.assertRowOnly(_scan(wf(), wf(name="    name: verify\n", extra=decoy)), [CLAIM_ROW])
        self.assertRowOnly(_scan(wf(), wf(extra=decoy)), [CLAIM_ROW])
        other = "on: pull_request\njobs:\n  d:\n    name: ci\n    runs-on: x\n    steps:\n      - run: true\n"
        payload = _scan({WF: wf()}, {WF: wf(name="    name: ${{ 'verify' }}\n"), WF2: other})
        self.assertEqual(payload["findings"], [])
        self.assertEqual(_reasons(payload, WF), [NAME_ROW])
        self.assertEqual(_reasons(payload, WF2), [CLAIM_ROW])
        existing = "  lint:\n    name: lint\n    runs-on: x\n"
        self.assertRowOnly(_scan(wf(extra=existing), wf(extra=existing.replace("name: lint", "name: ci"))),
                           [CLAIM_ROW])

    def test_no_claimant_without_a_change_of_reporter(self) -> None:
        self.assertSilent(_scan(wf(), wf(steps="      - run: make test --strict\n")))
        # An expression name whose literal text cannot be a base context.
        expression = "  d:\n    name: lint (${{ matrix.os }})\n    runs-on: x\n"
        self.assertSilent(_scan(wf(), wf(extra=expression)))
        decoy = "  decoy:\n    name: ci\n    runs-on: x\n"
        self.assertSilent(_scan(wf(), wf(extra=decoy), contexts=None))
        # The ruleset side is not a claim: a context added at head names
        # nothing the base ruleset required.
        payload = scan_pair(
            {WF: wf().encode(), RS: ruleset("ci").encode()},
            {WF: wf(extra=decoy.replace("name: ci", "name: new")).encode(), RS: ruleset("ci", "new").encode()},
            base_label="base", head_label="head", env=ENV,
        )
        self.assertEqual(payload["unknown_coverage"], [])


class ReusableWorkflowProducer(_RowCase):
    """§3.1 residual (R03): jobs generated by reusable workflows and
    `workflow_call` indirection, reported when the diff touches them."""

    CALLER = "on: [push, pull_request]\njobs:\n  ci:\n    uses: ./.github/workflows/inner.yml\n"
    CALLEE = "on: workflow_call\njobs:\n  test:\n    runs-on: x\n    steps:\n      - run: make test\n"

    def test_producer_converted_to_a_call_is_a_row(self) -> None:
        local = "on: [push, pull_request]\njobs:\n  ci:\n    name: ci\n    uses: ./.github/workflows/inner.yml\n"
        self.assertRowOnly(_scan(wf(), {WF: local, INNER: self.CALLEE}), [REUSABLE_ROW])
        remote = local.replace("./.github/workflows/inner.yml", "org/judges/.github/workflows/n.yml@v1.2.3")
        self.assertRowOnly(_scan(wf(), remote), [REUSABLE_ROW])

    def test_called_workflow_edit_is_a_row_on_the_caller(self) -> None:
        base = {WF: self.CALLER, INNER: self.CALLEE}
        head = {WF: self.CALLER, INNER: self.CALLEE.replace("make test", "true")}
        payload = _scan(base, head, contexts=("ci / test",))
        self.assertRowOnly(payload, [REUSABLE_ROW])
        # The called job's own file: a context ending ` / test` (review).
        self.assertEqual(_reasons(payload, INNER), [REUSABLE_ROW])
        self.assertRowOnly(_scan(base, {INNER: self.CALLEE}, contexts=("ci / test",)), [REUSABLE_ROW])

    def test_caller_job_edits_and_deletion_are_a_row(self) -> None:
        base = {WF: self.CALLER + "    with:\n      strict: true\n", INNER: self.CALLEE}
        head = {WF: self.CALLER + "    with:\n      strict: false\n", INNER: self.CALLEE}
        self.assertRowOnly(_scan(base, head, contexts=("ci / test",)), [REUSABLE_ROW])
        gone = {WF: "on: [push, pull_request]\njobs:\n  lint:\n    runs-on: x\n", INNER: self.CALLEE}
        self.assertRowOnly(_scan(base, gone, contexts=("ci / test",)), [REUSABLE_ROW])

    def test_untouched_or_unrequired_calls_are_silent(self) -> None:
        files = {WF: self.CALLER, INNER: self.CALLEE}
        self.assertSilent(_scan(files, files, contexts=("ci / test",)))
        head = {WF: self.CALLER, INNER: self.CALLEE.replace("make test", "true")}
        self.assertSilent(_scan(files, head, contexts=("other",)))
        # Another job of the caller's file changed: the producer did not.
        lint = "  lint:\n    runs-on: x\n    steps:\n      - run: lint\n"
        self.assertSilent(_scan({WF: self.CALLER + lint, INNER: self.CALLEE},
                                {WF: self.CALLER + lint.replace("run: lint", "run: lint --fix"), INNER: self.CALLEE},
                                contexts=("ci / test",)))

    def test_called_job_shape_in_a_callable_workflow_is_a_row(self) -> None:
        # Spec 14 review: a callable workflow's job links through a context
        # of the called-job shape, `<caller> / <called>`, only. A bare
        # context comes from the workflow's direct push or pull_request run,
        # which §3.1 reads in full: an edit there is no reusable row.
        on = "on: [pull_request, workflow_call]\n"
        head = wf(on=on, steps="      - run: true\n")
        self.assertRowOnly(_scan(wf(on=on), head, contexts=("build / ci",)), [REUSABLE_ROW])
        self.assertSilent(_scan(wf(on=on), head))
        self.assertSilent(_scan(wf(on=on), wf(on=on, steps="      - run: make test -x\n")))


class WorkflowSyntaxOutsideTheGrammar(_RowCase):
    """R-23/24 (#23, #24, R20): forms the bounded grammar does not read are
    rows on either side; a job table it cannot resolve is unresolved, never
    an observed deletion."""

    BASE = wf(steps="      - uses: actions/checkout@" + SHA + "\n      - run: make test\n")

    def test_quoted_or_spaced_recorded_keys_at_head_are_a_row(self) -> None:
        for line in ('    "if": false\n', "    'if': false\n", '    "if": ${{ false }}\n',
                     '    "continue-on-error": true\n', "    'continue-on-error': true\n",
                     '    "continue-on-error": ${{ true }}\n', "    if : false\n",
                     "    continue-on-error : true\n", '    "needs": gate\n', '    "name": verify\n'):
            with self.subTest(line=line):
                head = self.BASE.replace("    name: ci\n", "    name: ci\n" + line)
                self.assertRowOnly(_scan(self.BASE, head), [SPELLING])

    def test_quoted_keys_at_base_are_a_row(self) -> None:
        for base, head in (
            (self.BASE.replace("  ci:", '  "ci":'),
             self.BASE.replace("  ci:", '  "ci":').replace("    name: ci\n", "    name: ci\n    if: false\n")),
            (self.BASE.replace("jobs:", '"jobs":'),
             self.BASE.replace("jobs:", '"jobs":').replace("    name: ci\n", "    name: ci\n    if: false\n")),
            (self.BASE.replace("  ci:\n    name: ci", '  test:\n    "name": ci'),
             self.BASE.replace("  ci:\n    name: ci", '  test:\n    "name": ci\n    if: false')),
        ):
            with self.subTest(base=base):
                self.assertRowOnly(_scan(base, head), [SPELLING])

    def test_requoted_job_table_reads_unresolved_not_deleted(self) -> None:
        # Trade (stated in SPEC §16 row 14): an honest requote of a job key
        # or of `jobs:` no longer blocks as `deleted`.
        for head in (self.BASE.replace("  ci:", '  "ci":'), self.BASE.replace("  ci:", "  'ci':"),
                     self.BASE.replace("  ci:", "  ci :"), self.BASE.replace("jobs:", '"jobs":')):
            with self.subTest(head=head):
                self.assertRowOnly(_scan(self.BASE, head), [SPELLING])

    def test_a_quoted_key_hides_no_other_job(self) -> None:
        # A job key spelled outside the form leaves only that job unresolved:
        # deleting the producer beside a new quoted job still reads as deleted.
        helper = '  "helper":\n    runs-on: x\n'
        flow = "  helper: {runs-on: x}\n"
        for extra, reason in ((helper, SPELLING), (flow, FLOW_JOB)):
            with self.subTest(extra=extra):
                head = "on: [push, pull_request]\njobs:\n  lint:\n    runs-on: x\n" + extra
                payload = _scan(wf(steps="      - run: make test\n"), head)
                self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "deleted")])
                self.assertEqual(_reasons(payload), [reason])

    def test_requote_plus_weakening_no_longer_blocks_by_accident(self) -> None:
        # Trade: a requote with `if: false`, which blocked only because it
        # read as a deletion, passes with a row.
        head = self.BASE.replace("  ci:\n    name: ci\n", '  "ci":\n    name: ci\n    if: false\n')
        self.assertRowOnly(_scan(self.BASE, head), [SPELLING])

    def test_lines_after_a_quoted_job_key_are_not_the_previous_job(self) -> None:
        # #23: before spec 14 the `if: false` under `"ci":` was read as
        # `lint`'s and fired on `lint` (a false positive).
        base = ("on: [push, pull_request]\njobs:\n  lint:\n    runs-on: x\n    steps:\n      - run: lint\n"
                "  ci:\n    name: ci\n    runs-on: x\n    steps:\n      - run: make\n")
        head = base.replace("  ci:\n    name: ci\n", '  "ci":\n    name: ci\n    if: false\n')
        self.assertRowOnly(_scan(base, head, contexts=("lint",)), [SPELLING])

    def test_a_trigger_loss_beside_an_unresolved_table_still_fires(self) -> None:
        head = self.BASE.replace("  ci:", '  "ci":').replace("[push, pull_request]", "[workflow_dispatch]")
        payload = _scan(self.BASE, head)
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "on: workflow_dispatch")])
        self.assertEqual(_reasons(payload), [SPELLING])

    def test_requoted_uses_keeps_its_pin_finding(self) -> None:
        # Not ruled in spec 14 (#23): the requoted `uses:` still reads as a
        # removed pin.
        payload = _scan(self.BASE, self.BASE.replace("- uses:", '- "uses":'))
        self.assertEqual([f["rule"] for f in payload["findings"]], ["JUDGE_UNPINNED"])
        self.assertEqual(_reasons(payload), [SPELLING])

    def test_flow_style_jobs_and_documents(self) -> None:
        plain = wf()
        flow_job = "on: [push, pull_request]\njobs:\n  ci: {name: ci, runs-on: x, steps: [{run: make test}]}\n"
        self.assertRowOnly(_scan(plain, flow_job), [FLOW_JOB])
        self.assertRowOnly(_scan(plain, "on: [push, pull_request]\njobs: {ci: {name: ci, runs-on: x}}\n"),
                           [FLOW_JOB])
        self.assertRowOnly(_scan(flow_job, flow_job.replace("{name: ci,", "{name: ci, if: false,")), [FLOW_JOB])
        doc = json.dumps({"on": ["push", "pull_request"], "jobs": {"ci": {
            "name": "ci", "runs-on": "x", "steps": [{"run": "make test"}]}}}, indent=2) + "\n"
        self.assertRowOnly(_scan(plain, doc), [FLOW_WORKFLOW, ON_UNRESOLVED])
        self.assertRowOnly(_scan(doc, doc.replace('"name": "ci",', '"name": "ci",\n      "if": false,')),
                           [FLOW_WORKFLOW, ON_UNRESOLVED])

    def test_a_flow_document_still_obeys_the_tab_rule(self) -> None:
        payload = _scan(wf(), '{"on": "push",\n\t"jobs": {}}\n')
        self.assertEqual(_rules(payload), [("SURFACE_UNPARSEABLE", "high", "")])

    def test_job_tables_at_other_indentation(self) -> None:
        wide = ("on: [push, pull_request]\njobs:\n    ci:\n        name: ci\n        runs-on: x\n"
                "        steps:\n            - run: make test\n")
        for head in (wide.replace("        name: ci\n", "        name: ci\n        if: false\n"),
                     wide.replace("        name: ci\n", "        name: ci\n        continue-on-error: true\n"),
                     wide.replace("    ci:\n", "    other:\n"),
                     wide.replace("[push, pull_request]", "[workflow_dispatch]")):
            with self.subTest(head=head):
                self.assertRowOnly(_scan(wide, head), [JOBS_INDENT])
        # Trade: an honest reindent of the whole file from 2 / 4 to 4 / 8.
        self.assertRowOnly(_scan(wf(), wide), [JOBS_INDENT])

    def test_job_body_at_other_indentation(self) -> None:
        deep = "on: push\njobs:\n  ci:\n      name: ci\n      runs-on: x\n"
        payload = _scan(deep, deep.replace("      name: ci\n", "      name: ci\n      if: false\n"))
        self.assertRowOnly(payload, [JOBS_INDENT])
        # Nothing of an unread body is compared: no producer or claimant row.
        reindented = "on: push\njobs:\n  ci:\n        name: verify\n        runs-on: x\n"
        self.assertRowOnly(_scan(wf(job="    needs: gate\n", extra=GATE), reindented + GATE), [JOBS_INDENT])
        self.assertRowOnly(_scan(wf(key="ci", name="    name: build\n"), "on: push\njobs:\n  ci:\n      runs-on: x\n",
                                 contexts=("build", "ci")), [JOBS_INDENT])
        # The job key is still read: deleting it is still observed.
        payload = _scan(deep + "  other:\n    runs-on: x\n", "on: push\njobs:\n  other:\n    runs-on: x\n")
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "deleted")])
        self.assertEqual(_reasons(payload), [JOBS_INDENT])

    def test_top_level_key_after_jobs_ends_the_table(self) -> None:
        # #24: `defaults:` / `  run:` after the jobs was a phantom job `run`.
        tail = "defaults:\n  run:\n    shell: bash\n"
        payload = _scan(wf() + tail, wf(), contexts=("run",))
        self.assertRowOnly(payload, [AFTER_JOBS])
        payload = _scan(wf() + tail, wf(job="    if: false\n") + tail)
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "false")])
        self.assertEqual(_reasons(payload), [AFTER_JOBS])
        self.assertSilent(_scan(wf() + "env:\n  A: b\n", wf() + "env:\n  A: c\n"))

    def test_spaced_on_key_is_unresolved_not_a_trigger_loss(self) -> None:
        payload = _scan(wf(), wf(on="on : [push, pull_request]\n"))
        self.assertRowOnly(payload, [ON_UNRESOLVED])

    def test_job_table_rows_need_a_ruleset_and_a_changed_file(self) -> None:
        # Spec 14 review: only the §5 producer reading consumes the job
        # table, and it reads nothing without a base ruleset context; an
        # unchanged file hides nothing. A requoted `uses:` is read by §4 on
        # every workflow, so its row needs neither.
        quoted = wf(job='    "if": false\n')
        self.assertSilent(_scan(wf(), quoted, contexts=None))
        self.assertSilent(_scan(quoted, quoted))
        wide = "on: push\njobs:\n    ci:\n        runs-on: x\n"
        self.assertSilent(_scan(wide, wide))
        self.assertSilent(_scan(wide, wide + "    lint:\n        runs-on: x\n", contexts=None))
        self.assertRowOnly(_scan(wide, wide + "    lint:\n        runs-on: x\n"), [JOBS_INDENT])
        pinned = self.BASE.replace("- uses:", '- "uses":')
        self.assertEqual(_reasons(_scan(pinned, pinned, contexts=None)), [SPELLING])


class SpecFourteenReview(_RowCase):
    """Adversarial review of spec 14 (AI-assisted rulings): forms and moves
    the first reading of R-14, R-15 and R-23/24 left silent or noisy."""

    def test_document_marker_or_directive_before_a_flow_document(self) -> None:
        doc = json.dumps({"on": ["push"], "jobs": {"ci": {"name": "ci", "runs-on": "x"}}}) + "\n"
        weak = doc.replace('"name": "ci",', '"name": "ci", "if": false,')
        for prefix in ("---\n", "%YAML 1.2\n---\n", "--- # json\n", "--- "):
            with self.subTest(prefix=prefix):
                self.assertRowOnly(_scan(prefix + doc, prefix + weak), [FLOW_WORKFLOW, ON_UNRESOLVED])
                # A block workflow rewritten so is unresolved, not deleted.
                self.assertRowOnly(_scan(wf(), prefix + doc), [FLOW_WORKFLOW, ON_UNRESOLVED])
        # A marker before a block document changes nothing.
        payload = _scan("---\n" + wf(), "---\n" + wf(job="    if: false\n"))
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "false")])
        self.assertEqual(payload["unknown_coverage"], [])

    def test_top_level_layouts_outside_the_grammar(self) -> None:
        indented = "".join(" " + line + "\n" for line in wf().splitlines())
        weak = indented.replace(" name: ci\n", " name: ci\n     if: false\n")
        self.assertRowOnly(_scan(indented, weak), [LAYOUT, ON_UNRESOLVED])
        self.assertRowOnly(_scan(wf(), indented), [LAYOUT, ON_UNRESOLVED])
        explicit = wf().replace("jobs:\n", "? jobs\n:\n")
        self.assertRowOnly(_scan(explicit, explicit.replace("    name: ci\n", "    name: ci\n    if: false\n")),
                           [LAYOUT])
        self.assertRowOnly(_scan(wf(), explicit), [LAYOUT])
        # A byte order mark is reported, and the file is read past it.
        payload = _scan("\ufeff" + wf(), "\ufeff" + wf(job="    if: false\n"))
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "false")])
        self.assertEqual(_reasons(payload), [LAYOUT])
        # Document markers around one document are no layout row; content
        # after an end marker is another document.
        framed = "---\n" + wf() + "...\n"
        self.assertSilent(_scan(framed, framed.replace("make test", "make test -x")))
        self.assertRowOnly(_scan(framed, framed + "jobs:\n  ci:\n    if: false\n"), [LAYOUT])
        self.assertRowOnly(_scan(wf(), wf() + "---\njobs: {}\n"), [LAYOUT])
        # A compact sequence under `on:` is no layout row (its triggers stay
        # unresolved, as before spec 14).
        compact = wf(on="on:\n- push\n- pull_request\n")
        self.assertRowOnly(_scan(compact, wf(on="on:\n- push\n- pull_request\n", steps="      - run: x\n")),
                           [ON_UNRESOLVED])

    def test_a_step_run_key_moved_to_another_step_is_a_row(self) -> None:
        base = "      - run: make lint\n        continue-on-error: true\n      - run: make test\n"
        self.assertRowOnly(_scan(wf(steps=base), wf(steps=(
            "      - run: make lint\n      - run: make test\n        continue-on-error: true\n"))), [STEPS_ROW])
        guarded = "      - uses: ./upload\n        if: ${{ false }}\n      - run: make test\n"
        self.assertRowOnly(_scan(wf(steps=guarded), wf(steps=(
            "      - uses: ./upload\n      - run: make test\n        if: ${{ false }}\n"))), [STEPS_ROW])
        # Reordered steps keep their keys: no row.
        self.assertSilent(_scan(wf(steps=base), wf(steps=(
            "      - run: make test\n      - run: make lint\n        continue-on-error: true\n"))))
        # Trade: renaming a step that holds a key is a row.
        named = "      - name: Lint\n        run: make lint\n        if: always()\n"
        self.assertRowOnly(_scan(wf(steps=named), wf(steps=named.replace("Lint", "Style"))), [STEPS_ROW])
        # A `uses:` ref bump keeps the step's identity.
        pinned = "      - uses: org/a@" + SHA + "\n        if: always()\n"
        self.assertSilent(_scan(wf(steps=pinned), wf(steps=pinned.replace(SHA, SHA[::-1]))))

    def test_flow_style_steps_and_defaults(self) -> None:
        for head in (
            wf(steps="      - {run: make test, continue-on-error: true}\n"),
            wf(steps="      - {run: make test, if: false}\n"),
            wf(job="    defaults: {run: {shell: 'true {0}'}}\n"),
            wf(job="    defaults:\n      run: {shell: 'true {0}'}\n"),
            wf(steps="").replace("    steps:\n", "    steps: [{run: make test, if: false}]\n"),
        ):
            with self.subTest(head=head):
                self.assertRowOnly(_scan(wf(), head), [STEPS_ROW])

    def test_workflow_level_defaults_and_a_removed_shell(self) -> None:
        defaults = "defaults:\n  run:\n    shell: 'true {0}'\n"
        self.assertRowOnly(_scan(wf(), defaults + wf()), [STEPS_ROW])
        bash = "defaults:\n  run:\n    shell: bash\n"
        self.assertRowOnly(_scan(bash + wf(), wf()), [STEPS_ROW])
        self.assertSilent(_scan(bash + wf(), bash + wf()))
        self.assertSilent(_scan(wf(), defaults + wf(), contexts=("other",)))
        piped = "      - run: make test | tee log\n        shell: bash\n"
        self.assertRowOnly(_scan(wf(steps=piped), wf(steps="      - run: make test | tee log\n")), [STEPS_ROW])
        job = wf(job="    defaults:\n      run:\n        shell: bash\n")
        self.assertRowOnly(_scan(job, wf()), [STEPS_ROW])

    def test_script_bodies_and_step_env_are_not_step_keys(self) -> None:
        for head in (
            wf(steps="      - run: |\n          if: hi\n          make test\n"),
            wf(steps="      - run: make test\n        env:\n          shell: x\n          if: y\n"),
        ):
            with self.subTest(head=head):
                base = head.replace("hi", "lo").replace("shell: x", "shell: z").replace("if: y", "if: w")
                payload = _scan(base, head)
                self.assertEqual(payload["findings"], [])
                self.assertNotIn(STEPS_ROW, _reasons(payload))
        # A step run key's own block scalar body is its text.
        block = wf(steps="      - run: make test\n        if: >-\n          success()\n")
        self.assertRowOnly(_scan(block, block.replace("success()", "failure()")), [MULTILINE, STEPS_ROW])

    def test_an_alias_name_may_start_with_an_underscore_or_digit(self) -> None:
        for alias in ("*_s", "*0s", "*s"):
            with self.subTest(alias=alias):
                head = wf(steps="").replace("    steps:\n", f"    steps: {alias}\n")
                self.assertIn(ALIAS, _reasons(_scan(wf(), head)))
        self.assertSilent(_scan(wf(), wf(steps="      - run: ls *.txt src/*_x\n")))
        script = "      - run: |\n          rm -rf -- *.o\n          echo - *_x\n"
        self.assertSilent(_scan(wf(), wf(steps=script)))

    def test_multiline_job_if_is_compared(self) -> None:
        for value in (">-\n      github.event_name == 'nope'", "|\n      false", "\n      false"):
            with self.subTest(value=value):
                self.assertRowOnly(_scan(wf(), wf(job=f"    if: {value}\n")), [IF_ROW, MULTILINE])
        gated = wf(job="    needs: gate\n", extra=GATE)
        head = gated.replace("  gate:\n", "  gate:\n    if: >-\n      false\n")
        self.assertRowOnly(_scan(gated, head), [MULTILINE, NEEDS_ROW])

    def test_claimants_the_grammar_cannot_read_literally(self) -> None:
        for name in ('"c\\x69"', '"\\u0063i"', "${{ 'ci' }}", "c${{ '' }}i", "${{ '}}' && 'ci' }}"):
            with self.subTest(name=name):
                other = f"on: pull_request\njobs:\n  fake:\n    name: {name}\n    runs-on: x\n"
                payload = _scan({WF: wf()}, {WF: wf(), WF2: other})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(_reasons(payload, WF2), [CLAIM_ROW])
        # A producer renamed to an escape is `producer name unresolved`.
        self.assertRowOnly(_scan(wf(), wf(name='    name: "c\\x69"\n')), [NAME_ROW])

    def test_claimants_need_an_enforcement_trigger(self) -> None:
        for on in ("on: schedule\n", "on:\n  push:\n    tags: [v*]\n", "on: workflow_dispatch\n"):
            with self.subTest(on=on):
                other = on + "jobs:\n  test:\n    name: ci\n    runs-on: x\n"
                trusted = on.startswith("on:\n  push")
                payload = _scan({WF: wf()}, {WF: wf(), WF2: other})
                # `push:` with a tags filter still names push (R14 reads no
                # filter): a claimant.
                self.assertEqual(_reasons(payload, WF2), [CLAIM_ROW] if trusted else [])

    def test_matrix_and_caller_claimants(self) -> None:
        matrix = ("on: pull_request\njobs:\n  ci:\n    strategy:\n      matrix:\n        os: [a]\n"
                  "    runs-on: x\n")
        payload = _scan({WF: wf()}, {WF: wf(), WF2: matrix}, contexts=("ci", "ci (a)"))
        self.assertEqual(_reasons(payload, WF2), [CLAIM_ROW])
        caller = "on: pull_request\njobs:\n  ci:\n    uses: ./.github/workflows/green.yml\n"
        green = "on: workflow_call\njobs:\n  test:\n    runs-on: x\n    steps:\n      - run: echo ok\n"
        base = {WF: ReusableWorkflowProducer.CALLER, INNER: ReusableWorkflowProducer.CALLEE}
        head = dict(base, **{WF2: caller, ".github/workflows/green.yml": green})
        payload = _scan(base, head, contexts=("ci / test",))
        self.assertEqual(payload["findings"], [])
        self.assertEqual(_reasons(payload, WF2), [CLAIM_ROW])

    def test_nested_and_matrix_reusable_producers(self) -> None:
        inner = "on: workflow_call\njobs:\n  mid:\n    uses: ./.github/workflows/inner2.yml\n"
        inner2 = ".github/workflows/inner2.yml"
        callee = ReusableWorkflowProducer.CALLEE
        base = {WF: ReusableWorkflowProducer.CALLER, INNER: inner, inner2: callee}
        head = dict(base, **{inner2: callee.replace("make test", "true")})
        payload = _scan(base, head, contexts=("ci / mid / test",))
        self.assertEqual(_reasons(payload), [REUSABLE_ROW])
        cycle = {WF: ReusableWorkflowProducer.CALLER,
                 INNER: "on: workflow_call\njobs:\n  loop:\n    uses: ./.github/workflows/inner.yml\n"}
        self.assertSilent(_scan(cycle, cycle, contexts=("ci / loop",)))
        # A caller's bare context is never reported once it calls: an edit of
        # an existing caller linked only that way is no row.
        files = {WF: ReusableWorkflowProducer.CALLER, INNER: callee}
        self.assertSilent(_scan(files, dict(files, **{INNER: callee.replace("make test", "true")}),
                                contexts=("ci",)))
        matrix_caller = ReusableWorkflowProducer.CALLER + "    strategy:\n      matrix:\n        os: [a]\n"
        base = {WF: matrix_caller, INNER: callee}
        payload = _scan(base, dict(base, **{INNER: callee.replace("make test", "true")}),
                        contexts=("ci (a) / test",))
        self.assertEqual(_reasons(payload), [REUSABLE_ROW])

    def test_a_commented_job_key_takes_no_lines_from_the_job_before(self) -> None:
        base = ("on: [push, pull_request]\njobs:\n  lint:\n    runs-on: x\n    steps:\n      - run: lint\n"
                "  docs:  # best effort\n    runs-on: x\n    steps:\n      - run: docs\n")
        for head in (
            base.replace("      - run: docs\n", "      - run: docs\n        if: failure()\n"),
            base.replace("  docs:  # best effort\n", "  docs:  # best effort\n    needs: lint\n"),
            base.replace("  docs:  # best effort\n", "  docs:  # best effort\n    strategy:\n      fail-fast: false\n"),
        ):
            with self.subTest(head=head):
                self.assertSilent(_scan(base, head, contexts=("lint",)))


class SpecFourteenSecondReview(_RowCase):
    """Second adversarial review of spec 14 (AI-assisted rulings): key
    properties at any indent, values left open across lines, steps sharing
    an identity, Unicode line breaks, partly read callers, commented job
    keys and the claimant and reusable linkage."""

    def test_a_key_behind_a_tag_anchor_or_explicit_key_is_a_row(self) -> None:
        for job in ("    ? if\n    : false\n", "    !!str if: false\n", "    &k if: false\n",
                    "    ? continue-on-error\n    : true\n", "    !!str continue-on-error: true\n"):
            with self.subTest(job=job):
                self.assertRowOnly(_scan(wf(), wf(job=job)), [LAYOUT])
        for steps in ("      - run: make test\n        !!str continue-on-error: true\n",
                      "      - !!str continue-on-error: true\n        run: make test\n",
                      "      - run: make test\n        &a if: false\n"):
            with self.subTest(steps=steps):
                self.assertIn(LAYOUT, _reasons(_scan(wf(), wf(steps=steps))))
        # A plain continuation that starts with `!` is no key.
        cond = "    if: >-\n      github.event_name == 'push' &&\n      !contains(github.ref, 'x')\n"
        self.assertNotIn(LAYOUT, _reasons(_scan(wf(), wf(job=cond))))

    def test_flow_values_left_open_across_lines(self) -> None:
        for base, head in (
            ("      - {\n          name: Test, run: make test }\n",
             "      - {\n          name: Test, run: make test, continue-on-error: true }\n"),
            ("      - {run: make test,\n          name: Test}\n",
             "      - {run: make test,\n          name: Test, if: false}\n"),
        ):
            with self.subTest(head=head):
                self.assertRowOnly(_scan(wf(steps=base), wf(steps=head)), [STEPS_ROW])
        job = "    defaults: {run: {\n      working-directory: .}}\n"
        self.assertRowOnly(_scan(wf(job=job), wf(job=job.replace(".}}", ".,\n      shell: 'true {0}'}}"))),
                           [STEPS_ROW])
        top = "defaults: {run: {\n  working-directory: .}}\n"
        self.assertRowOnly(_scan(top + wf(), top.replace(".}}", ".,\n  shell: 'true {0}'}}") + wf()), [STEPS_ROW])

    def test_steps_sharing_an_identity_compare_in_order(self) -> None:
        for lint, test in (
            ("      - run: |\n          set -euo pipefail\n          make lint\n",
             "      - run: |\n          set -euo pipefail\n          make test\n"),
            ("      - uses: ./.github/actions/make\n        with:\n          target: lint\n",
             "      - uses: ./.github/actions/make\n        with:\n          target: test\n"),
            ("      - name: Run\n        run: make lint\n", "      - name: Run\n        run: make test\n"),
            ("      - uses: org/act@v1\n", "      - uses: org/act@v2\n"),
        ):
            with self.subTest(lint=lint):
                key = "        continue-on-error: true\n"
                payload = _scan(wf(steps=lint + key + test), wf(steps=lint + test + key))
                self.assertEqual(payload["findings"], [])
                self.assertIn(STEPS_ROW, _reasons(payload))

    def test_a_shell_removed_counts_over_the_block(self) -> None:
        base = "      - name: Test\n        run: make test | tee log\n        shell: bash\n"
        for head in ("      - name: Test\n        run: make test | tee log -a\n",
                     "      - name: Check\n        run: make test | tee log\n",
                     "      - id: t\n        name: Test\n        run: make test | tee log\n"):
            with self.subTest(head=head):
                self.assertRowOnly(_scan(wf(steps=base), wf(steps=head)), [STEPS_ROW])

    def test_quoted_scalars_left_open_are_text(self) -> None:
        env = "    env:\n      X: \"a b\"\n"
        for head in (
            wf(job="    env:\n      X: \"a\nb\"\n    if: false\n"),
            wf(job="    env:\n      X: \"a\n  b\"\n    if: false\n"),
            wf(job="    if: false\n    env:\n      X: \"a\n    if: true\n      \"\n"),
        ):
            with self.subTest(head=head):
                payload = _scan(wf(job=env), head)
                self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "false")])
        named = "      - name: Test\n        run: make test\n"
        sneaky = "      - name: Test\n        run: \"make test\n      env:\n          \"\n        continue-on-error: true\n"
        self.assertIn(STEPS_ROW, _reasons(_scan(wf(steps=named), wf(steps=sneaky))))
        # A recorded value left open is a multiline residual, and a job `if:`
        # compares as its lines.
        self.assertRowOnly(_scan(wf(), wf(job="    if: \"github.event_name ==\n      'nope'\"\n")),
                           [IF_ROW, MULTILINE])
        # A quote in a script body opens nothing.
        script = wf(steps="      - run: |\n          echo \"unterminated\n        if: false\n")
        self.assertIn(STEPS_ROW, _reasons(_scan(wf(), script)))

    def test_flow_collections_left_open_are_text(self) -> None:
        # A flow value left open on its line runs to its closing bracket, at
        # any indent: a continuation can no longer end the job or hide a key.
        for job in ("    env: {X: a,\nY: b}\n    if: false\n", "    env: {X: a,\n  Y: b}\n    if: false\n",
                    "    env:\n      X: [a,\n  b]\n    if: false\n", "    env: {X: a, # }\n      Y: b}\n    if: false\n"):
            with self.subTest(job=job):
                payload = _scan(wf(), wf(job=job))
                self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "false")])
        # A `needs:` list left open is read whole; an `on:` list left open is
        # unresolved, not a trigger.
        gated = wf(job="    needs: gate\n", extra=GATE)
        self.assertRowOnly(_scan(gated, gated.replace("    needs: gate\n", "    needs: [gate,\n      other]\n")),
                           [NEEDS_ROW])
        self.assertSilent(_scan(gated, gated.replace("    needs: gate\n", "    needs: [\n      gate]\n")))
        self.assertRowOnly(_scan(wf(), wf(on="on: [push,\n  pull_request]\n")), [ON_UNRESOLVED])

    def test_unicode_line_breaks_are_line_breaks(self) -> None:
        for brk in ("\u2028", "\u2029", "\x85"):
            with self.subTest(brk=repr(brk)):
                head = wf().replace("    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest" + brk + "    if: false\n")
                payload = _scan(wf(), head)
                self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "false")])
                self.assertEqual(_reasons(payload), [LAYOUT])

    def test_a_partly_read_caller_reports_when_another_workflow_changes(self) -> None:
        callee = ReusableWorkflowProducer.CALLEE
        weak = "defaults:\n  run:\n    shell: 'true {0}'\n" + callee
        for caller, reason in (
            ("on: [push, pull_request]\njobs:\n  build: {uses: ./.github/workflows/inner.yml}\n", FLOW_JOB),
            ("on: [push, pull_request]\njobs:\n  build:\n      uses: ./.github/workflows/inner.yml\n", JOBS_INDENT),
            ("on: [push, pull_request]\njobs:\n  \"build\":\n    uses: ./.github/workflows/inner.yml\n", SPELLING),
        ):
            with self.subTest(caller=caller):
                payload = _scan({WF: caller, INNER: callee}, {WF: caller, INNER: weak}, contexts=("build / test",))
                self.assertEqual(payload["findings"], [])
                self.assertEqual(_reasons(payload), [reason])
                self.assertEqual(_reasons(payload, INNER), [REUSABLE_ROW])

    def test_a_job_key_or_jobs_with_an_inline_comment_is_read(self) -> None:
        # Spec 14 review: these read as no job and fired `deleted` high.
        self.assertSilent(_scan(wf(), wf().replace("  ci:\n", "  ci:  # required check\n")))
        self.assertSilent(_scan(wf(), wf().replace("jobs:\n", "jobs:  # all\n")))
        payload = _scan(wf(), wf(job="    if: false\n").replace("  ci:\n", "  ci:  # required\n"))
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high", "false")])

    def test_a_requoted_job_level_uses_is_reported_on_every_scan(self) -> None:
        call = "on: [push]\njobs:\n  call:\n    \"uses\": ./.github/workflows/x.yml\n"
        self.assertEqual(_reasons(_scan(call, call, contexts=None)), [SPELLING])

    def test_claimant_names_and_triggers(self) -> None:
        for name in ("${{ '}}X${{' && 'ci' }}", "${{ 'x' }}}${{ 'ci' }}", "${{ 'Z}}X${{' && 'ci' }}"):
            with self.subTest(name=name):
                other = f"on: pull_request\njobs:\n  fake:\n    name: \"{name}\"\n    runs-on: x\n"
                self.assertEqual(_reasons(_scan({WF: wf()}, {WF: wf(), WF2: other}), WF2), [CLAIM_ROW])
        # Booked (R16): an expression-named matrix job already fit the
        # context at base, so a new matrix value is no claim.
        matrix = ("on: pull_request\njobs:\n  m:\n    name: ${{ matrix.n }}\n    strategy:\n      matrix:\n"
                  "        n: [lint]\n    runs-on: x\n")
        payload = _scan({WF: wf(), WF2: matrix}, {WF: wf(), WF2: matrix.replace("[lint]", "[lint, ci]")})
        self.assertEqual(_reasons(payload, WF2), [])
        # A literal-named job that gains a matrix reports `<name> (…)`.
        plain = "on: pull_request\njobs:\n  t:\n    name: test\n    runs-on: x\n"
        payload = _scan({WF: wf(), WF2: plain},
                        {WF: wf(), WF2: plain.replace("    runs-on", "    strategy:\n      matrix:\n        os: [a]\n    runs-on")},
                        contexts=("ci", "test (a)"))
        self.assertEqual(_reasons(payload, WF2), [CLAIM_ROW])
        nightly = "on: schedule\njobs:\n  test:\n    name: ci\n    runs-on: x\n"
        payload = _scan({WF: wf(), WF2: nightly}, {WF: wf(), WF2: nightly.replace("on: schedule", "on: [schedule, pull_request]")})
        self.assertEqual(_reasons(payload, WF2), [CLAIM_ROW])

    def test_an_alias_as_a_uses_value(self) -> None:
        anchor = "env:\n  ACT: &act org/act@" + SHA + "\n"
        head = anchor + wf(steps="      - run: make test\n").replace("    steps:\n", "    steps:\n      - name: a\n        uses: *act\n")
        self.assertIn(ALIAS, _reasons(_scan(head, head, contexts=None)))

    def test_called_jobs_of_a_matrix_or_expression_name(self) -> None:
        for job, context in (
            ("  test:\n    strategy:\n      matrix:\n        os: [a]\n    runs-on: x\n    steps:\n      - run: make test\n",
             "build / test (a)"),
            ("  test:\n    name: Test ${{ inputs.os }}\n    runs-on: x\n    steps:\n      - run: make test\n",
             "build / Test linux"),
        ):
            with self.subTest(context=context):
                callee = "on: workflow_call\njobs:\n" + job
                payload = _scan({INNER: callee}, {INNER: callee.replace("make test", "true")}, contexts=(context,))
                self.assertEqual(_reasons(payload, INNER), [REUSABLE_ROW])


class RowsAreReportedOnce(_RowCase):
    def test_many_members_give_one_row_per_reason(self) -> None:
        head = wf(job="    if: x == 'y'\n    needs: gate\n", steps=(
            "      - run: a\n        if: false\n      - run: b\n        continue-on-error: true\n"),
            extra=GATE)
        payload = _scan(wf(extra=GATE), head)
        self.assertRowOnly(payload, [IF_ROW, NEEDS_ROW, STEPS_ROW])


if __name__ == "__main__":
    unittest.main()
