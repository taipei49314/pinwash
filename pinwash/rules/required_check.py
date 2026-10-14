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
    if_event_filtered_off,
    job_disabled,
    job_event_filtered_off,
    job_unresolved,
    needs_names,
    parse_workflow,
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
PRODUCER_NAME_CASE = "producer name case changed"
PRODUCER_STRATEGY = "producer job strategy changed"
CONTEXT_CLAIMED = "head job claims a required context"
REUSABLE_PRODUCER = "reusable workflow producer unresolved"

# SPEC §5.5 (spec 14): the single-line job `if:` values read as always
# running (with the §5.6 readings, spec 22, the closed forms); exact text.
IF_TRUE_FORMS = frozenset({"true", "'true'", '"true"', "${{ true }}"})


# SPEC §5 (spec 23, AI-assisted ruling R-15 on #15, as the challenger
# amended it): producers are linked to ruleset contexts with ASCII letters
# compared without case, and a head `name:` is compared after one leading
# YAML anchor token and one layer of quotes are stripped. A name that is
# then still not literal text (an expression, a tag, an alias, a flow or
# block indicator) is not compared.
_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_NOT_LITERAL = ("&", "*", "!", "{", "[", "|", ">", "%", "@", "`")


def _fold(text: str) -> str:
    return text.translate(_ASCII_FOLD)


def _name_literal(text: str) -> str | None:
    """The literal text a `name:` value as written reads as (§5, spec 23),
    or None when it is not literal: one leading anchor token of a plain
    value stripped; one layer of quotes removed, YAML's `''` decoded in a
    single-quoted value; not literal when it holds `${{`, is a double-quoted
    escape, or is a plain value starting with a YAML indicator or ending
    in whitespace YAML keeps and the grammar does not compare (review of
    2026-10-10). An empty result reports the job key."""
    v = text
    if v.startswith("&"):
        cut = v.find(" ")
        if cut == -1:
            return None
        v = v[cut:].strip(" \t")
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        inner = v[1:-1]
        if v[0] == '"' and "\\" in inner:
            return None
        if v[0] == "'":
            inner = inner.replace("''", "'")
        return None if "${{" in inner else inner
    if "${{" in v or v[:1] in _NOT_LITERAL or v != v.strip():
        return None
    return v


def _head_display(job: GhaJob) -> str | None:
    """The literal context a job reports as GitHub reads its `name:` (§5,
    spec 23): the name's literal text, or the job key when it has none or
    an empty one; None when the grammar does not read it as literal."""
    if not job.name_resolved:
        return None
    if job.name is None:
        return job.key
    literal = _name_literal(job.name_text if job.name_text is not None else job.name)
    if literal is None:
        return None
    return literal or job.key


def fold_contexts(contexts: set[str]) -> frozenset[str]:
    """The contexts with ASCII letters folded (§5, spec 23), computed once
    per run."""
    return frozenset(_fold(c) for c in contexts)


def head_reporters(texts: list[tuple[str | None, str]]) -> set[str]:
    """SPEC §5 (spec 23): the contexts, ASCII case folded, that a head job
    reports on the enforcement path: in a workflow whose `on:` includes
    `push` or `pull_request` (or the grammar does not resolve), other than
    a job §5.6 reads as skipped. `texts` are the head workflow texts with
    their load status."""
    found: set[str] = set()
    for text, status in texts:
        if status != "ok" or text is None:
            continue
        g = parse_workflow(text)
        if g.unparseable or not (g.triggers & ENFORCEMENT_EVENTS or ON_UNRESOLVED in g.unknown):
            continue
        for job in g.jobs.values():
            if job.body_unresolved or job_disabled(job) or job_event_filtered_off(job):
                continue
            if job.calls is not None or (job.strategy is not None and any("matrix" in p for p in job.strategy)):
                # A calling job reports `<name> / …` and a matrix job
                # `<name> (…)`, never its bare name (spec 23 review).
                continue
            display = _head_display(job)
            if display is not None:
                found.add(_fold(display))
    return found


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


def _if_closed(value: str | None, on_path: bool) -> bool:
    """Absent, or a job `if:` in the closed forms: read by §5.6 as false,
    or as an event filter in a workflow that ran on push or pull_request at
    base (spec 22), or one of the always-running forms."""
    if value is None or value in IF_TRUE_FORMS:
        return True
    if job_disabled(GhaJob(key="", if_value=value)):
        return True
    return on_path and if_event_filtered_off(value)


def detect_jobs(
    path: str,
    base_g: GhaFile | None,
    head_g: GhaFile | None,
    base_contexts: set[str],
    add: Any,
    note: Callable[[str], None] | None = None,
    changed: Callable[[str], bool] | None = None,
    calls_of: Callable[[str], list[str]] | None = None,
    head_contexts: frozenset[str] | None = None,
    head_reporting: set[str] | None = None,
    base_folded: frozenset[str] | None = None,
    job_matches: dict[str, str] | None = None,
    moved_workflow: bool = False,
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
    # `head_contexts` and `base_folded` arrive folded, once per run.
    folded_base = base_folded if base_folded is not None else fold_contexts(base_contexts)
    folded_head = head_contexts if head_contexts is not None else frozenset()
    for key, job in base_g.jobs.items():
        if not job.name_resolved:
            # SPEC §3.1 residual (#4): the job's context name is unknown
            # coverage; a linkage guessed from the job key would be invented.
            continue
        display = job.name or key
        if _fold(display) not in folded_base:
            # Spec 23: ASCII letters compared without case (R-15).
            continue
        linked = True
        head_job = (None if moved_workflow and key not in (job_matches or {})
                    else head_jobs.get((job_matches or {}).get(key, key)))
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
            and not job_event_filtered_off(job)
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
        elif (
            head_job is not None
            and job_event_filtered_off(head_job)
            and not (job_event_filtered_off(job) or job_disabled(job))
            and (base_g.triggers & ENFORCEMENT_EVENTS)
        ):
            # spec 22 (§5.6, #13): the job-scope counterpart of trigger
            # loss. A job its condition skips reports Success, so the
            # required check passes on every pull request. Placed after
            # trigger loss, which keeps its finding.
            dropped = True
            after = head_job.if_value or ""
        elif (
            head_job is not None
            and not job.body_unresolved
            and not head_job.body_unresolved
            and _fold(display) in folded_head
            and (renamed := _head_display(head_job)) is not None
            and _fold(renamed) != _fold(display)
            and head_reporting is not None
            and _fold(display) not in head_reporting
        ):
            # spec 23 (§5, R-15): the producer, same workflow file and job
            # key, reports another literal context while a head ruleset
            # still names the base one and no head job reports it on the
            # enforcement path (the orphan gate keeps an honest aggregator
            # that takes the old name). Placed last: existing findings keep
            # their fingerprints.
            dropped = True
            after = "name: " + renamed
        if dropped:
            add(
                rule="REQUIRED_CHECK_DROPPED",
                # spec 9: producer-side disjuncts (deleted / if-disabled /
                # continue-on-error / trigger-loss; spec 22 event filter;
                # spec 23 renamed) base at high — a required
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
        and (
            head_job.if_lines is not None
            or not _if_closed(head_if, bool(base_g.triggers & ENFORCEMENT_EVENTS))
        )
    ):
        note(PRODUCER_IF)
    if needs_names(head_job) != needs_names(job) or _gate_changed(head_job, base_g, head_g):
        note(PRODUCER_NEEDS)
    if head_job.strategy is not None and head_job.strategy != job.strategy:
        note(PRODUCER_STRATEGY)
    base_display = job.name or job.key
    head_display = _head_display(head_job)
    if head_job.name_resolved and head_display is None:
        # Compared as written, so an unchanged non-literal name is no row.
        head_written = head_job.name_text if head_job.name_text is not None else head_job.name
        base_written = job.name_text if job.name_text is not None else base_display
        if head_job.name is not None and head_written != base_written:
            # An expression, (spec 14 review) a double-quoted escape, or
            # (spec 23) a tag, an alias, a flow or block indicator.
            note(PRODUCER_NAME)
    elif head_display is not None and head_display != base_display and _fold(head_display) == _fold(base_display):
        # Spec 23 (R-15): a rename in letter case only, a `name:` removed or
        # added included, is not a block.
        note(PRODUCER_NAME_CASE)
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
    literal = _head_display(job)
    if literal is not None and job.calls is None and _fold(literal) in fold_contexts(base_contexts):
        # Spec 23 review: read as the renamed disjunct's gate reads a name
        # (one anchor and one quote layer stripped, ASCII case folded).
        return True
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
