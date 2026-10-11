"""REQUIRED_CHECK_DROPPED: ruleset contexts and their producing jobs (SPEC §5)."""

from __future__ import annotations

from typing import Any

from collections import Counter
from collections.abc import Callable

from pinwash.escalate import last_context_gone
from pinwash.parse.gha import (
    CONFIGURED_TRIGGERS,
    ON_UNRESOLVED,
    GhaFile,
    GhaJob,
    GhaStep,
    if_text,
    job_disabled,
    job_unresolved,
    needs_names,
    step_run_keys,
)
from pinwash.surfaces import norm

# SPEC §5 (spec 8): the events on which a workflow's run provides a
# required status context to merge gating. A context reported only from
# other events (schedule, workflow_dispatch, …) never gates the flow.
ENFORCEMENT_EVENTS = {"push", "pull_request"}

# SPEC §5.5 (spec 14): unknown-coverage reasons for a required-check
# producer. Fixed text from the closed SPEC §7 list; a row never adds,
# drops or changes a finding, and never changes the verdict.
PRODUCER_IF = "producer job if unresolved"
PRODUCER_NEEDS = "producer job needs changed"
PRODUCER_TRIGGER_CONFIG = "producer trigger configuration changed"
PRODUCER_STEPS = "producer step run keys changed"
PRODUCER_NAME = "producer name unresolved"
PRODUCER_STRATEGY = "producer job strategy changed"
CONTEXT_CLAIMED = "head job claims a required context"
REUSABLE_PRODUCER = "reusable workflow producer unresolved"

# SPEC §5.5 (spec 14): the single-line job `if:` values read as always
# running (with the §5 false reading, the closed forms); exact text.
IF_TRUE_FORMS = frozenset({"true", "'true'", '"true"', "${{ true }}"})


def ruleset_contexts(doc: Any) -> list[str]:
    """Every required_status_checks context, depth-first in document order.

    The walk keeps its own stack instead of recursing, so a subject
    document nested at any depth reads the same on every interpreter
    (SPEC §8 / §9). Order matches the recursive form this replaces.
    """
    found: list[str] = []
    stack: list[Any] = [doc]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "required_status_checks" in node:
                checks = node["required_status_checks"]
                if isinstance(checks, list):
                    for item in checks:
                        if isinstance(item, str):
                            found.append(item)
                        elif isinstance(item, dict) and isinstance(
                            item.get("context"), str
                        ):
                            found.append(item["context"])
            stack.extend(reversed(list(node.values())))
        elif isinstance(node, list):
            stack.extend(reversed(node))
    return found


def _display(job: GhaJob) -> str | None:
    """The job's literal status context as the grammar reads it, or None."""
    if not job.name_resolved or job.name_escaped:
        return None
    return job.name or job.key


def _called_from(display: str, context: str) -> bool:
    """A context GitHub reports for a job called by the caller `display`:
    `<caller> / <called>`, or `<caller> (<matrix values>) / <called>` for a
    matrix caller (INFERRED)."""
    if context.startswith(display + " / "):
        return True
    return context.startswith(display + " (") and " / " in context[len(display) :]


def _expression_end(text: str, start: int) -> int:
    """Index of the `}}` that ends the expression whose body starts at
    `start`, outside single-quoted literals (`''` inside one); -1 if none."""
    i = start
    in_literal = False
    while i < len(text):
        if text[i] == "'":
            if in_literal and text[i + 1 : i + 2] == "'":
                i += 2
                continue
            in_literal = not in_literal
        elif not in_literal and text.startswith("}}", i):
            return i
        i += 1
    return -1


def _may_name(name: str, context: str) -> bool:
    """Whether a `name:` holding `${{ … }}` can evaluate to `context`: its
    literal text around the expressions appears in order, the first piece as
    a prefix and the last as a suffix. An expression ends at the first `}}`
    outside its single-quoted literals; an unbounded one, or a piece holding
    a brace, matches anything (spec 14 review)."""
    pieces: list[str] = []
    rest = name
    while True:
        start = rest.find("${{")
        if start == -1:
            pieces.append(rest)
            break
        pieces.append(rest[:start])
        end = _expression_end(rest, start + 3)
        if end == -1:
            return True
        rest = rest[end + 2 :]
    if any("{" in piece or "}" in piece for piece in pieces):
        return True
    if not context.startswith(pieces[0]):
        return False
    pos = len(pieces[0])
    for piece in pieces[1:-1]:
        found = context.find(piece, pos)
        if found == -1:
            return False
        pos = found + len(piece)
    return len(context) - len(pieces[-1]) >= pos and context.endswith(pieces[-1])


def _by_identity(steps: list[GhaStep]) -> dict[str, list[list[str]]]:
    """Each step's keys, grouped by its identity in block order."""
    groups: dict[str, list[list[str]]] = {}
    for step in steps:
        groups.setdefault(step.identity(), []).append(step.keys)
    return groups


def _step_keys_changed(base_steps: list[GhaStep], head_steps: list[GhaStep]) -> bool:
    """SPEC §5.5 (R15): a step run key added or changed on a step, or a
    `shell` removed from the block (bash then runs without `-o pipefail`),
    a step that held it removed or renamed included. A step is the one with
    the same identity and, among steps sharing an identity, the same place
    in block order (spec 14 review), so a key moved to another step
    counts."""
    base_groups = _by_identity(base_steps)
    head_groups = _by_identity(head_steps)
    for ident, head_list in head_groups.items():
        base_list = base_groups.get(ident, [])
        for i, keys in enumerate(head_list):
            if Counter(keys) - Counter(base_list[i] if i < len(base_list) else []):
                return True
    # A `shell` removed is counted over the block, whatever step held it.
    base_shells = Counter(k for s in base_steps for k in s.keys if "shell" in k)
    head_shells = Counter(k for s in head_steps for k in s.keys if "shell" in k)
    return bool(base_shells - head_shells)


def _if_closed(value: str | None) -> bool:
    """Absent, or a job `if:` in the closed forms: read as false by §5, or
    one of the always-running forms."""
    if value is None or value in IF_TRUE_FORMS:
        return True
    return job_disabled(GhaJob(key="", if_value=value))


def detect_jobs(
    path: str,
    base_g: GhaFile | None,
    head_g: GhaFile | None,
    base_contexts: set[str],
    add: Any,
    note: Callable[[str], None] | None = None,
    changed: Callable[[str], bool] | None = None,
    calls_of: Callable[[str], list[str]] | None = None,
) -> None:
    note = note if note is not None else (lambda reason: None)
    changed = changed if changed is not None else (lambda p: True)
    calls_of = calls_of if calls_of is not None else (lambda p: [])
    if base_g is not None and base_g.unparseable:
        return
    if not base_contexts:
        # SPEC §5: the job-side trigger is the job that produced a required
        # status context named at base. With no named contexts there is no
        # job-side finding (rename blindness without a ruleset is R09).
        return
    head_ok = head_g is not None and not head_g.unparseable
    if head_ok and head_g is not None:
        _note_claimants(base_g, head_g, base_contexts, note)
    if base_g is None:
        return
    head_jobs = head_g.jobs if head_ok and head_g is not None else {}
    linked = False
    for key, job in base_g.jobs.items():
        if not job.name_resolved:
            # SPEC §3.1 residual (#4): the job's context name is unknown
            # coverage; a linkage guessed from the job key would be invented.
            continue
        display = job.name or key
        if display not in base_contexts:
            continue
        linked = True
        head_job = head_jobs.get(key)
        dropped = False
        after = ""
        if head_job is None and not (
            head_ok and head_g is not None and job_unresolved(head_g, key)
        ):
            dropped = True
            after = "deleted"
        elif (
            head_job is not None
            and job_disabled(head_job)
            and not job_disabled(job)
        ):
            dropped = True
            after = head_job.if_value or "if: false"
        elif (
            head_job is not None
            and head_job.continue_on_error is True
            and job.continue_on_error is not True
        ):
            dropped = True
            after = "continue-on-error: true"
        elif (
            head_g is not None
            and (base_g.triggers & ENFORCEMENT_EVENTS)
            and not (head_g.triggers & ENFORCEMENT_EVENTS)
            and ON_UNRESOLVED not in head_g.unknown
        ):
            # spec 8: the job survives, but its workflow no longer runs on
            # any enforcement-path event, so the context is never produced.
            # A head `on:` block whose forms the bounded grammar cannot
            # resolve (wholly or in part) is a residual (§3.1), not an
            # observed removal — silent here. A seen block that resolves no
            # trigger is recorded as unresolved, so it is covered too. At
            # base only the resolved triggers count: an unresolved base item
            # could only add triggers, never hide the push / pull_request
            # the base resolved. Spec 14: a job missing from a head job
            # table the grammar does not resolve (§3.1) is unresolved, not
            # deleted, and its workflow's triggers are still compared.
            dropped = True
            after = "on: " + (", ".join(sorted(head_g.triggers)) or "none")
        if dropped:
            add(
                rule="REQUIRED_CHECK_DROPPED",
                # spec 9: producer-side disjuncts (deleted / if-disabled /
                # continue-on-error / trigger-loss) base at high — a required
                # check that cannot run on any enforcement path is a dropped
                # check, and the default fail_on=high consumer must block on
                # it (round 3 live warn-gap specimen: `# on: push`).
                severity="high",
                message=f"workflow job {display} no longer a reliable required check producer",
                path=path,
                before=display,
                after=after,
                locator=key,
            )
        if (
            head_job is not None
            and head_g is not None
            and not job.body_unresolved
            and not head_job.body_unresolved
        ):
            # A body §3.1 does not read (#24) has nothing to compare; its
            # `jobs indentation unresolved` row already stands for it.
            _note_producer(job, head_job, base_g, head_g, note)
    if linked and head_ok and head_g is not None:
        # SPEC §5.5 (spec 14): push / pull_request configuration of a
        # producer's workflow, on a trigger present on both sides (a
        # trigger added or removed is the trigger set, spec 8).
        for event in CONFIGURED_TRIGGERS:
            if event not in base_g.triggers or event not in head_g.triggers:
                continue
            if base_g.trigger_config.get(event, []) != head_g.trigger_config.get(event, []):
                note(PRODUCER_TRIGGER_CONFIG)
                break
    _note_reusable(
        path, base_g, head_g if head_ok else None, base_contexts, note, changed, calls_of
    )


def _note_producer(
    job: GhaJob, head_job: GhaJob, base_g: GhaFile, head_g: GhaFile,
    note: Callable[[str], None],
) -> None:
    """SPEC §5.5 (spec 14): run conditions and linkage of a linked producer
    present at head, compared as recorded text, never evaluated."""
    head_if = if_text(head_job)
    if (
        head_if is not None
        and head_if != if_text(job)
        # A multiline value is not §5's reading, whatever its text.
        and (head_job.if_lines is not None or not _if_closed(head_if))
    ):
        note(PRODUCER_IF)
    if needs_names(head_job) != needs_names(job) or _gate_changed(head_job, base_g, head_g):
        note(PRODUCER_NEEDS)
    if head_job.strategy is not None and head_job.strategy != job.strategy:
        note(PRODUCER_STRATEGY)
    head_name = head_job.name
    if (
        head_name is not None
        and head_job.name_resolved
        and ("${{" in head_name or head_job.name_escaped)
        and head_name != (job.name or job.key)
    ):
        # An expression, or (spec 14 review) a double-quoted escape.
        note(PRODUCER_NAME)
    if _step_keys_changed(job.steps, head_job.steps) or _step_keys_changed(
        [base_g.defaults], [head_g.defaults]
    ):
        note(PRODUCER_STEPS)


def _gate_changed(head_job: GhaJob, base_g: GhaFile, head_g: GhaFile) -> bool:
    """A job of the same file that the producer needs at head, directly or
    through the head `needs:` of the jobs it needs, whose `if:` changed to a
    value other than an always-running form, whose `needs:` changed, or
    which is absent at head while present at base (spec 14, #13)."""
    seen = {head_job.key}
    queue = list(needs_names(head_job))
    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        gate_head = head_g.jobs.get(name)
        gate_base = base_g.jobs.get(name)
        if gate_head is None:
            if gate_base is not None and not job_unresolved(head_g, name):
                return True
            continue
        if gate_base is not None:
            gate_if = if_text(gate_head)
            if (
                gate_if is not None
                and gate_if != if_text(gate_base)
                and gate_if not in IF_TRUE_FORMS
            ):
                return True
            if needs_names(gate_head) != needs_names(gate_base):
                return True
        queue.extend(needs_names(gate_head))
    return False


def _reports_called(job: GhaJob, contexts: set[str]) -> bool:
    """Whether a calling job can report a context of `contexts` for a job it
    calls: `<display> / …` or `<display> (…) / …`; for a `name:` the grammar
    does not resolve to literal text, a context whose caller part it may
    evaluate to (spec 14 review)."""
    display = _display(job)
    if display is not None and "${{" not in display:
        return any(_called_from(display, c) for c in contexts)
    callers = {c.split(" / ", 1)[0] for c in contexts if " / " in c}
    if job.name is None or job.name_escaped:
        return bool(callers)
    return any(_may_name(job.name, c) for c in callers)


def _claims(job: GhaJob, base_contexts: set[str]) -> bool:
    """Whether the head job can report a context in `base_contexts`: its
    literal context; a matrix job's `<display> (…)` or a caller's
    `<display> / …` (INFERRED); or, for a `name:` the grammar does not
    resolve to literal text (an expression, a double-quoted escape, a
    multiline value), any context it may evaluate to (spec 14 review)."""
    display = _display(job)
    if display is not None and "${{" not in display:
        if display in base_contexts:
            return True
        if job.strategy is not None and any(
            c.startswith(display + " (") and c.endswith(")") for c in base_contexts
        ):
            return True
        return job.calls is not None and _reports_called(job, base_contexts)
    if job.calls is not None:
        return _reports_called(job, base_contexts)
    if job.name is None or job.name_escaped:
        return bool(base_contexts)
    return any(_may_name(job.name, c) for c in base_contexts)


def _note_claimants(
    base_g: GhaFile | None, head_g: GhaFile, base_contexts: set[str],
    note: Callable[[str], None],
) -> None:
    """SPEC §5.5 (spec 14): a head job, new or existing, in a workflow that
    runs on `push` or `pull_request` (or whose `on:` is unresolved), that can
    report a context a base ruleset names (`_claims`), while the same-key
    base job of this file is absent or had another `name:`. Whether GitHub
    then gates on it or on the producer is not decidable from the trees."""
    if not _runs_on_enforcement(head_g):
        return
    # A workflow that ran on no enforcement event at base reported nothing a
    # ruleset gates on: each of its head jobs is new (spec 14 review).
    base_jobs = base_g.jobs if base_g is not None and _runs_on_enforcement(base_g) else {}
    for key, job in head_g.jobs.items():
        if job.body_unresolved:
            continue
        base_job = base_jobs.get(key)
        if (
            base_job is not None
            and _name_record(base_job) == _name_record(job)
            and base_job.strategy == job.strategy
        ):
            # The same name and matrix report the same contexts.
            continue
        # A context the same-key base job could already report is no claim:
        # a change of a producer's own name is `producer name unresolved` or
        # R16, and an expression-named matrix job keeps the contexts its
        # name fits (spec 14 review; a new matrix value is R16).
        own = (
            {c for c in base_contexts if _claims(base_job, {c})}
            if base_job is not None
            else set()
        )
        if _claims(job, base_contexts - own):
            note(CONTEXT_CLAIMED)
            return


def _runs_on_enforcement(g: GhaFile) -> bool:
    return bool(g.triggers & ENFORCEMENT_EVENTS) or ON_UNRESOLVED in g.unknown


def _name_record(job: GhaJob) -> tuple[str | None, bool, bool]:
    return (job.name, job.name_resolved, job.name_escaped)


def _local_calls(
    calls: list[str], calls_of: Callable[[str], list[str]]
) -> list[str]:
    """The local workflows (`./…`) a job calls, followed through the job-level
    `uses:` of the workflows they call on either side, each once, so a call
    cycle ends (spec 14 review)."""
    seen: list[str] = []
    queue = [norm(c[2:]) for c in calls if c.startswith("./")]
    while queue:
        target = queue.pop(0)
        if target in seen:
            continue
        seen.append(target)
        queue.extend(norm(c[2:]) for c in calls_of(target) if c.startswith("./"))
    return seen


def _note_reusable(
    path: str, base_g: GhaFile, head_g: GhaFile | None, base_contexts: set[str],
    note: Callable[[str], None], changed: Callable[[str], bool],
    calls_of: Callable[[str], list[str]],
) -> None:
    """SPEC §5.5 (spec 14): a producer whose context comes through a
    reusable workflow (§3.1 residual). A base job is one when it calls a
    reusable workflow (job-level `uses:`) on either side and a base context
    is reported for a job it calls (`_called_from`), or is its display while
    the base job does not call (a producer converted to a call); a
    job of a workflow whose `on:` names `workflow_call` on either side is
    one when a base context ends with ` / ` and its display, the shape of a
    called job's check. Reported when the diff changes such a job's lines
    (or removes it), or a local workflow (`./…`) it calls on either side,
    directly or through the calls of the workflows it calls."""
    head_jobs = head_g.jobs if head_g is not None else {}
    callable_file = "workflow_call" in base_g.triggers or (
        head_g is not None and "workflow_call" in head_g.triggers
    )
    called_parts = {c.rsplit(" / ", 1)[1] for c in base_contexts if " / " in c}
    for key, job in base_g.jobs.items():
        display = _display(job)
        head_job = head_jobs.get(key)
        calls = [c for c in (job.calls, head_job.calls if head_job else None) if c]
        # A caller's own bare context is reported only by a base job that
        # did not call yet (a producer converted to a call); once a job
        # calls, GitHub reports `<caller> / <called>` (spec 14 review).
        if calls and (
            (display is not None and display in base_contexts and job.calls is None)
            or _reports_called(job, base_contexts)
        ):
            called = _local_calls(calls, calls_of)
        elif callable_file and job.calls is None and _claims(job, called_parts):
            # The called job's own part of `<caller> / <called>`.
            called = []
        else:
            continue
        if (
            head_job is None
            or head_job.lines != job.lines
            or any(changed(p) for p in called)
            # The workflow-level `defaults:` reaches the job (review).
            or (head_g is not None and _step_keys_changed([base_g.defaults], [head_g.defaults]))
        ):
            note(REUSABLE_PRODUCER)
            return


def detect_ruleset(
    path: str, base_ctx: list[str], head_ctx: list[str], add: Any
) -> None:
    base_set = list(dict.fromkeys(base_ctx))
    head_set = set(head_ctx)
    remaining = [c for c in base_set if c in head_set]
    for ctx in base_set:
        if ctx in head_set:
            continue
        sev = "critical" if last_context_gone(len(remaining)) else "warn"
        add(
            rule="REQUIRED_CHECK_DROPPED",
            severity=sev,
            message=f"required status context {ctx} dropped",
            path=path,
            before=ctx,
            after="",
            locator=ctx,
        )
