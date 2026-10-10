"""Bounded GitHub Actions line grammar (SPEC §3.1). Not YAML 1.2."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from pinwash.pins import parse_uses
from pinwash.textutil import crlf_to_lf

# A job key, with an inline comment or not (spec 14 review: `  ci:  # x`
# was read as no job, and its lines as the job before it).
_JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):(?:\s*|\s+#.*)$")
# spec 14 (§3.1, #23): a job key with an inline value (`  ci: {…}`).
_JOB_KEY_VALUE = re.compile(r"^  ([A-Za-z0-9_-]+):\s(.*)$")
_USES = re.compile(r"^(\s*)(?:-\s+)?uses:\s*(.*)$")
_CONTINUE = re.compile(r"^(\s*)(-\s+)?continue-on-error:\s*(.*)$")
_IF = re.compile(r"^(\s*)(-\s+)?if:\s*(.*)$")
_NAME = re.compile(r"^(\s*)name:\s*(.*)$")
_JOBS = re.compile(r"^jobs:(?:\s*|\s+#.*)$")
_JOBS_VALUE = re.compile(r"^jobs:\s(.*)$")
_ON = re.compile(r"^on:\s*(.*)$")
# A quoted "on" / 'on' key, or `on :` with spaces before the colon (spec 14).
_ON_QUOTED = re.compile(r"""^(?:"on"|'on'|on) *:""")
_BLOCK_SCALAR = re.compile(r"^[>|](?:[+-][1-9]?|[1-9][+-]?)?$")
_DASH = re.compile(r"-\s+")
_BARE_KEY = re.compile(r"([A-Za-z0-9_-]+):(?:\s|$)")
_SPACED_KEY = re.compile(r"([A-Za-z0-9_-]+)\s+:(?:\s|$)")
# An alias as a line's value or sequence item, outside a block scalar's
# body (spec 14 review: an alias name may start with `_` or a digit, which
# `\*[A-Za-z]` missed).
_ALIAS = re.compile(r"(?:-\s+)?(?:[A-Za-z0-9_-]+:\s+)?\*[^\s,\[\]{}]")

MULTILINE = "multiline uses or scalar"
ON_UNRESOLVED = "on triggers unresolved"
CONTINUE_UNRESOLVED = "continue-on-error value unresolved"
# spec 14 (§3.1, #23, #24): workflow syntax outside the bounded grammar.
KEY_SPELLING = "quoted or spaced key unresolved"
FLOW_JOB = "flow-style job unresolved"
FLOW_WORKFLOW = "flow-style workflow unresolved"
JOBS_INDENT = "jobs indentation unresolved"
AFTER_JOBS = "top-level key after jobs unresolved"
# spec 14 (§3.1, review): a document form the line grammar does not read at
# its top level (a leading byte order mark, an indented document, an
# explicit `?` key, a tag, an anchor or alias, a directive or document
# marker after the first content line).
LAYOUT = "workflow layout unresolved"

# §3.1 recorded keys whose quoted or spaced spelling is reported (spec 14):
# read at any indent, and read at job indent under a recorded job.
_ANY_INDENT_KEYS = frozenset({"uses", "if", "continue-on-error"})
_JOB_INDENT_KEYS = frozenset({"name", "needs", "strategy", "steps", "defaults"})
# spec 14 (§3.1, #14): step run keys, read inside a job's `steps:` and
# `defaults:` blocks only, never inside a step's `with:`.
STEP_RUN_KEYS = frozenset({"if", "continue-on-error", "shell"})
_STEP_BLOCKS = frozenset({"steps", "defaults"})
# The keys whose deeper lines are not read inside those blocks (action
# inputs and step environment), and the keys a step is identified by.
_STEP_SKIP_KEYS = frozenset({"with", "env"})
_STEP_IDENTITY_KEYS = ("id", "name", "uses", "run")
# spec 14 (§3.1, review): column-0 starts of a line the grammar does not
# read as a top-level key (`- ` items of a compact sequence aside; document
# markers are read on their own).
_LAYOUT_STARTS = ("?", "!", "&", "*", "%")
# spec 14 review: a tag or an anchor before a key, or an explicit `?` key,
# at any indent after an optional `- `.
_KEY_PROPERTY = re.compile(
    r"""(?:[!&]\S*\s+(?:"[^"]*"|'[^']*'|[A-Za-z0-9_-]+)\s*:(?:\s|$)|\?(?:\s|$))"""
)
# spec 14 review: line breaks that YAML 1.1 parsers (PyYAML, YamlDotNet)
# read besides LF and CR: NEL, LS and PS.
_UNICODE_BREAKS = ("\x85", "\u2028", "\u2029")
# The keys whose value a multiline quoted scalar leaves unresolved.
_RECORDED_KEYS = frozenset({"uses", "if", "continue-on-error", "shell", "name"})
# spec 14 (§3.1, #13): the triggers whose configuration lines are recorded.
CONFIGURED_TRIGGERS = ("push", "pull_request")


@dataclass
class GhaStep:
    """spec 14 (§3.1): one item of a job's `steps:` block, or the job's
    `defaults:` block, as its step run keys are recorded."""

    # Identity when the step has no `id`, `name`, `uses` or `run` value:
    # its ordinal in the block (`#0`, …), or `defaults`.
    fallback: str
    # The `key: value` text of each step run key, and of a flow-style value
    # in the block (a block scalar's body lines appended to its header).
    keys: list[str] = field(default_factory=list)
    # The first `id`, `name`, `uses` and `run` values at the step's own key
    # column (a block-scalar `run:` by the first line of its body).
    names: dict[str, str] = field(default_factory=dict)
    # Later lines of a key's value, by its index in `keys`, joined into it
    # once the file is read (one join per value keeps reading linear).
    more: dict[int, list[str]] = field(default_factory=dict)

    def add_line(self, index: int, text: str) -> None:
        self.more.setdefault(index, []).append(text)

    def finish(self) -> None:
        for index, lines in self.more.items():
            self.keys[index] = "\n".join([self.keys[index], *lines])
        self.more = {}

    def identity(self) -> str:
        """The step a key belongs to, so a key moved to another step is a
        change: `id`, else `name`, else the `uses` locator without its ref,
        else the `run` text, else the fallback."""
        for key in _STEP_IDENTITY_KEYS:
            value = self.names.get(key)
            if value:
                if key == "uses" and "@" in value:
                    value = value.rsplit("@", 1)[0]
                return f"{key}: {value}"
        return self.fallback


@dataclass
class GhaJob:
    key: str
    name: str | None = None
    # False when the job's `name:` value is a residual: its status context
    # is then unknown and must not be guessed from the job key.
    name_resolved: bool = True
    # spec 14 review: a double-quoted `name:` holding a `\` escape, whose
    # context is the decoded text the grammar does not compute.
    name_escaped: bool = False
    if_value: str | None = None
    # spec 14 review: a job-level `if:` written as a block scalar or with an
    # empty value: its header and body lines as recorded (if_value is None).
    if_lines: list[str] | None = None
    continue_on_error: bool | None = None
    # spec 14 (§3.1): recorded for unknown-coverage comparison only, never
    # evaluated. `needs:` and `strategy:` hold the key's inline value and
    # the lines of its block as recorded text (None: no such key);
    # `steps` the step run keys of each step and of `defaults:`;
    # `calls` a job-level `uses:` value (a reusable-workflow call);
    # `lines` every line of the job's body as read (comment lines dropped,
    # trailing spaces stripped), to tell whether the diff changed the job.
    needs: list[str] | None = None
    strategy: list[str] | None = None
    steps: list[GhaStep] = field(default_factory=list)
    calls: str | None = None
    lines: list[str] = field(default_factory=list)
    # spec 14 (#24): the job's first body line is not at indent 4, so
    # nothing of its body is read (its key still is).
    body_unresolved: bool = False


@dataclass
class GhaFile:
    uses: list[tuple[str, str, int]]  # locator-repo, ref, occurrence
    jobs: dict[str, GhaJob] = field(default_factory=dict)
    triggers: set[str] = field(default_factory=set)
    on_seen: bool = False
    unknown: list[str] = field(default_factory=list)
    # spec 14 review: grammar rows about the job table only, which nothing
    # but the §5 producer reading consumes; the engine reports them only
    # for a changed file while a base ruleset names a context (§3.1).
    job_unknown: list[str] = field(default_factory=list)
    unparseable: bool = False
    # spec 14 (§3.1): the job table as a whole is in a form the grammar
    # does not read (a quoted, spaced or flow-style `jobs` key, a flow-style
    # document, job keys at another indent); a job missing from it is
    # unresolved, never an observed deletion.
    jobs_unresolved: bool = False
    # spec 14 (§3.1): job keys spelled outside the job-key form (quoted,
    # spaced, or with a value on their line), by their bare name; each such
    # job is unresolved, and hides no other job.
    unresolved_job_keys: set[str] = field(default_factory=set)
    # spec 14 (§3.1): recorded configuration lines of `push` /
    # `pull_request`, per trigger, in file order.
    trigger_config: dict[str, list[str]] = field(default_factory=dict)
    # spec 14 review: the step run keys of a column-0 `defaults:` block,
    # which reach every job of the file.
    defaults: GhaStep = field(default_factory=lambda: GhaStep(fallback="defaults"))

    # spec 14 review: a job-level key line in a form the grammar does not
    # read (it may be a reusable-workflow call).
    job_level_unread: bool = False

    def job_table_partial(self) -> bool:
        """A job, or a job-level key, the grammar does not read, so a call
        to another workflow may be hidden (spec 14 review)."""
        return (
            self.jobs_unresolved
            or self.job_level_unread
            or bool(self.unresolved_job_keys)
            or any(job.body_unresolved for job in self.jobs.values())
        )


def strip_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def truncate_inline_comment(value: str) -> str:
    """SPEC §3.1 (spec 5): a recorded value ends at the first ' #' sequence."""
    idx = value.find(" #")
    return value[:idx] if idx != -1 else value


def _recorded(remainder: str) -> str:
    """The §3.1 recorded value of a key's line remainder.

    The regexes consume the space after the colon, so a remainder that
    starts with `#` is a comment only: the value is empty there.
    """
    value = remainder.strip()
    if value.startswith("#"):
        return ""
    return truncate_inline_comment(value).strip()


def _continues(value: str) -> bool:
    """§3.1 residual (#4): a block-scalar header or an empty value means
    the real value is on later lines, which the line grammar does not read."""
    return not value or bool(_BLOCK_SCALAR.fullmatch(value))


def _key_spelling(text: str) -> tuple[str, bool] | None:
    """The key of a mapping line (after any indentation and `- `), and
    whether it is spelled outside the bare `key:` form the grammar reads:
    one pair of matching quotes around it, or spaces before its colon
    (spec 14, #23). None when the text is no such key line."""
    if text[:1] in ("'", '"'):
        close = text.find(text[0], 1)
        if close > 1:
            rest = text[close + 1 :].lstrip(" ")
            if rest.startswith(":") and (len(rest) == 1 or rest[1] == " "):
                return text[1:close], True
        return None
    m = _BARE_KEY.match(text)
    if m:
        return m.group(1), False
    m = _SPACED_KEY.match(text)
    if m:
        return m.group(1), True
    return None


def _split_dash(stripped: str) -> tuple[str, int]:
    """Text after an optional `- ` sequence-item prefix, and its width."""
    m = _DASH.match(stripped)
    if m:
        return stripped[m.end() :], m.end()
    return stripped, 0


def needs_names(job: GhaJob) -> tuple[str, ...]:
    """The job names a recorded `needs:` holds, sorted (order is no change).

    An inline `[a, b]` (one line, or continued over block lines) reads as
    its comma-separated items, a block sequence as its `- ` items, any other
    value as one name; one pair of matching quotes is stripped from each.
    Absent and empty both read as no names. Never evaluated further.
    """
    if not job.needs:
        return ()
    joined = " ".join(job.needs).strip()
    if joined.startswith("[") and joined.endswith("]"):
        items = joined[1:-1].split(",")
    else:
        items = [piece[2:] if piece.startswith("- ") else piece for piece in job.needs]
    return tuple(sorted(strip_quotes(item.strip()) for item in items if item.strip()))


def _flow(value: str) -> bool:
    """A value or sequence item written in flow style (`{…}` / `[…]`)."""
    return value[:1] in ("{", "[")


def _flow_depth(text: str) -> int:
    """Flow brackets opened minus closed on a line, outside quotes and
    before a comment (a `#` at the start or after a space)."""
    depth = 0
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] == " "):
            break
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
    return depth


def _value_part(stripped: str) -> str | None:
    """The value of a key line, or the item of a `- ` line, else None."""
    after, width = _split_dash(stripped)
    spelled = _key_spelling(after)
    if spelled is not None:
        rest = after
        if after[:1] in ('"', "'"):
            rest = after[after.find(after[0], 1) + 1 :]
        return rest[rest.find(":") + 1 :].lstrip(" ")
    return after if width else None


def _opens_flow(stripped: str) -> int:
    """spec 14 review: the brackets a flow collection that a key line's
    value, or a `- ` item, opens and leaves open on its line; its later
    lines, at any indent, are its text, never structure. 0 if none."""
    value = _value_part(stripped)
    if value is None or not _flow(value):
        return 0
    return max(_flow_depth(value), 0)


def _quote_end(text: str, quote: str, start: int) -> int | None:
    """Index just past the quote that closes a scalar opened with `quote`,
    searching `text` from `start` (a backslash escapes in double quotes,
    `''` is a quote in single quotes); None when it does not close there."""
    i = start
    while i < len(text):
        ch = text[i]
        if quote == '"' and ch == "\\":
            i += 2
            continue
        if ch == quote:
            if quote == "'" and text[i + 1 : i + 2] == "'":
                i += 2
                continue
            return i + 1
        i += 1
    return None


def _opens_quote(stripped: str) -> str | None:
    """spec 14 review: the quote of a quoted scalar that a key line's value,
    or a `- ` item, opens and does not close on its line; its later lines are
    the scalar's text, never structure."""
    value = _value_part(stripped)
    if value is None:
        return None
    if value[:1] in ('"', "'") and _quote_end(value, value[0], 1) is None:
        return value[0]
    return None


def _reader_sink(reader: "_StepReader") -> Callable[[str], None]:
    """Feeds the later lines of a flow value left open to the step reader
    that recorded it."""

    def feed(text: str) -> None:
        reader.line(0, text)

    return feed


def _piece_appender(target: list[str]) -> Callable[[str], None]:
    """Appends the later lines of a `needs:` / `strategy:` flow value."""

    def append(text: str) -> None:
        piece = truncate_inline_comment(text).strip()
        if piece:
            target.append(piece)

    return append


def _appender(step: GhaStep, index: int) -> Callable[[str], None]:
    """Appends a later line of a value left open to a recorded step key."""

    def append(text: str) -> None:
        step.add_line(index, text)

    return append


class _StepReader:
    """spec 14 (§3.1): the step run keys of one `steps:` or `defaults:`
    block, a job's or the workflow's column-0 `defaults:`.

    In a `steps:` block each `- ` item at the indent of the block's first
    item starts a step. A line deeper than a `with:` or `env:` key, or than
    a key whose value is a block scalar, is not read as a key: the body of a
    step run key's block scalar is appended to its text, and the first body
    line of a block-scalar `run:` names the step.
    """

    def __init__(
        self, steps: list[GhaStep] | None, single: GhaStep | None, job_unknown: list[str]
    ) -> None:
        self.steps = steps
        self.step = single
        self.dash: int | None = None
        self.col: int | None = None
        self.skip: int | None = None
        self.capture: int | None = None
        self.capture_run = False
        self.job_unknown = job_unknown
        # A flow value left open on its line (spec 14 review): the entry its
        # later lines are appended to, and the brackets still open.
        self.flow: tuple[GhaStep, int] | None = None
        self.depth = 0
        # The entry this line recorded, for a quoted value it leaves open.
        self.last: tuple[GhaStep, int] | None = None

    def _record(self, step: GhaStep, text: str) -> None:
        step.keys.append(text)
        self.last = (step, len(step.keys) - 1)
        depth = _flow_depth(text)
        if depth > 0:
            self.flow = self.last
            self.depth = depth

    def _new_step(self, col: int) -> GhaStep:
        assert self.steps is not None
        step = GhaStep(fallback=f"#{len(self.steps)}")
        self.steps.append(step)
        self.col = col
        return step

    def line(self, indent: int, stripped: str) -> None:
        self.last = None
        if self.flow is not None:
            # A line of a flow value left open: its text, whatever its keys.
            step, index = self.flow
            step.add_line(index, stripped.rstrip(" "))
            self.depth += _flow_depth(stripped)
            if self.depth <= 0:
                self.flow = None
            return
        if self.skip is not None and indent > self.skip:
            if self.step is not None:
                body = stripped.rstrip(" ")
                if self.capture is not None:
                    self.step.add_line(self.capture, body)
                if self.capture_run:
                    self.step.names["run"] = body
                    self.capture_run = False
            return
        self.skip = None
        self.capture = None
        self.capture_run = False
        text, width = _split_dash(stripped)
        if self.steps is not None:
            if width and (self.dash is None or indent == self.dash):
                self.dash = indent
                self.step = self._new_step(indent + width)
            elif self.step is None:
                # A line before the block's first `- ` item.
                self.step = self._new_step(indent)
        step = self.step
        if step is None:
            return
        if _flow(text):
            # `- {run: …, if: …}`, or a line of a flow sequence: its text.
            self._record(step, "flow: " + truncate_inline_comment(text).strip())
            return
        spelled = _key_spelling(text)
        if spelled is None:
            return
        key, odd = spelled
        key_col = indent + width
        if odd:
            if key == "shell":
                self.job_unknown.append(KEY_SPELLING)
            return
        value = _recorded(text.split(":", 1)[1])
        block = bool(_BLOCK_SCALAR.fullmatch(value))
        if key in _STEP_SKIP_KEYS:
            self.skip = key_col
            return
        if key in STEP_RUN_KEYS:
            self._record(step, f"{key}: {value}")
            if block or not value:
                # Its value continues on deeper lines (#4): they are its text.
                self.skip = key_col
                self.capture = len(step.keys) - 1
            return
        if _flow(value):
            # A flow-style value (`run: {shell: …}` under `defaults:`).
            self._record(step, f"{key}: {value}")
            return
        if key in _STEP_IDENTITY_KEYS and key_col == self.col and key not in step.names:
            if block:
                self.capture_run = key == "run"
            elif value:
                step.names[key] = strip_quotes(value)
        if block:
            self.skip = key_col


def parse_workflow(text: str) -> GhaFile:
    normalized = crlf_to_lf(text)
    result = GhaFile(uses=[])
    if normalized.startswith("\ufeff"):
        # spec 14 review: a leading byte order mark. The rest is read as
        # written; whether the host reads the file the same is not observed.
        normalized = normalized[1:]
        result.unknown.append(LAYOUT)
    if any(brk in normalized for brk in _UNICODE_BREAKS):
        # spec 14 review: read as line breaks, as YAML 1.1 parsers do, and
        # reported, since a YAML 1.2 parser reads them as text.
        for brk in _UNICODE_BREAKS:
            normalized = normalized.replace(brk, "\n")
        result.unknown.append(LAYOUT)
    # The column-0 block the current line belongs to: "on" (a block whose
    # children are triggers), "on_inline", "on_unresolved", "jobs",
    # "jobs_unresolved", "defaults", "other", or None before the first.
    top: str | None = None
    seen_jobs = False
    first_content = True
    unread_rest = False
    jobs_first_child = False
    current_job: str | None = None
    awaiting_body = False
    job_block: str | None = None
    reader: _StepReader | None = None
    current_trigger: str | None = None
    uses_n: dict[str, int] = {}
    # A column-0 `...` document end marker: content after it is another
    # document.
    ended = False
    # The key column of the block scalar whose body the current line may be
    # in: deeper lines are its text, never an alias (spec 14 review).
    scalar_col: int | None = None
    # A quoted scalar a line left open (spec 14 review): its quote, and
    # where its later lines go when they are a recorded value's text.
    quote: str | None = None
    quote_sink: Callable[[str], None] | None = None
    # A flow collection a line left open (spec 14 review): the brackets
    # still open, and where its later lines go when they are recorded text.
    flow_depth = 0
    flow_sink: Callable[[str], None] | None = None

    def unresolved_layout() -> None:
        # spec 14 review: a top-level form the grammar does not read may hold
        # a job or the triggers, so a job missing at head is not deleted and
        # an `on:` that resolves no trigger is unresolved; what was read
        # (resolved triggers, jobs) is still compared.
        result.unknown.append(LAYOUT)
        result.on_seen = True
        result.jobs_unresolved = True

    for line in normalized.split("\n"):
        stripped = line.lstrip(" ")
        if "\t" in line.split("#")[0]:
            result.unparseable = True
            return result
        if quote is not None:
            # A line of a quoted scalar left open: its text, never a key or
            # a comment, up to the quote that closes it.
            if current_job is not None and top == "jobs":
                result.jobs[current_job].lines.append(line.rstrip(" "))
            if quote_sink is not None:
                quote_sink(stripped.rstrip(" "))
            if _quote_end(stripped, quote, 0) is not None:
                quote = None
                quote_sink = None
            continue
        if stripped.startswith("#") or not stripped:
            continue
        if flow_depth > 0 and not unread_rest:
            # A line of a flow collection left open: its text, at any
            # indent, never a key, up to the bracket that closes it.
            if current_job is not None and top == "jobs":
                result.jobs[current_job].lines.append(line.rstrip(" "))
            if flow_sink is not None:
                flow_sink(stripped.rstrip(" "))
            flow_depth += _flow_depth(stripped)
            if flow_depth <= 0:
                flow_depth = 0
                flow_sink = None
            continue
        if unread_rest:
            # spec 14 (#23): nothing in a flow-style document, or (review)
            # in a second document, is read; only the tab rule above still
            # applies to every line.
            continue
        indent = len(line) - len(stripped)
        if indent == 0 and (stripped == "..." or stripped.startswith("... ")):
            ended = True
            continue
        if ended or (
            indent == 0 and not first_content and (stripped == "---" or stripped.startswith("--- "))
        ):
            # spec 14 review: another document (content after an end marker,
            # or a second start marker). Nothing from it on is read; only the
            # tab rule still applies.
            unresolved_layout()
            unread_rest = True
            continue
        if first_content:
            head = stripped
            on_marker = False
            if indent == 0 and head.startswith("%"):
                # spec 14 review: a directive (`%YAML 1.2`) before the
                # document is no content.
                continue
            if indent == 0 and (head == "---" or head.startswith("--- ")):
                # A document start marker; content may follow on its line.
                head = head[3:].strip()
                if not head or head.startswith("#"):
                    continue
                on_marker = True
            first_content = False
            if head[0] in "{[":
                # spec 14 (§3.1, #23): a workflow whose top level is a flow
                # collection (JSON syntax included; after a directive or a
                # `---` marker, on its line or not) is read as nothing: its
                # `on:` and job table are unresolved, never an observed
                # trigger loss or deletion.
                unread_rest = True
                result.on_seen = True
                result.jobs_unresolved = True
                result.unknown.append(FLOW_WORKFLOW)
                continue
            if on_marker or indent > 0:
                # Other content on the marker line (a tag, a scalar), or a
                # document indented as a whole: no column-0 key follows that
                # the grammar reads as the document's.
                unresolved_layout()
                if on_marker:
                    continue
        if "|" in line or line.rstrip().endswith(">") or line.rstrip().endswith("|"):
            if "uses:" in line or stripped.startswith("|") or stripped.startswith(">"):
                result.unknown.append("multiline uses or scalar")
        in_scalar = scalar_col is not None and indent > scalar_col
        if not in_scalar:
            scalar_col = None
            if "|" in stripped or ">" in stripped:
                text_after, width = _split_dash(stripped)
                spelled = _key_spelling(text_after)
                if spelled is not None and _BLOCK_SCALAR.fullmatch(
                    _recorded(text_after.split(":", 1)[1])
                ):
                    scalar_col = indent + width
        if "*" in stripped:
            if (not stripped.startswith("uses:") and re.search(r"\*[A-Za-z]", stripped)) or (
                not in_scalar and _ALIAS.match(stripped)
            ):
                # A `uses:` value that is an alias is one too (spec 14
                # review); `*` elsewhere in a `uses:` line is not read.
                result.unknown.append("yaml alias")
        opened: str | None = None
        if not in_scalar:
            text_after, _width = _split_dash(stripped)
            if indent > 0 and text_after[:1] in ("!", "&", "?") and _KEY_PROPERTY.match(text_after):
                # spec 14 review: a key behind a tag, an anchor or `?` is not
                # read; inside the job table only §5 would read it.
                target = result.job_unknown if top in ("jobs", "jobs_unresolved") else result.unknown
                target.append(LAYOUT)
                if top == "jobs" and indent == 4:
                    result.job_level_unread = True
            opened = _opens_quote(stripped)
            if opened is not None:
                quote = opened
                spelled = _key_spelling(text_after)
                if spelled is not None and spelled[0] in _RECORDED_KEYS:
                    result.unknown.append(MULTILINE)
            else:
                flow_depth = _opens_flow(stripped)
                flow_sink = None
        if indent == 0:
            # A top-level line starts a block and ends the one before it
            # (spec 14, #24: a top-level key after `jobs:` ends the job table).
            current_job = None
            awaiting_body = False
            job_block = None
            reader = None
            current_trigger = None
            jobs_first_child = False
            if stripped.startswith(_LAYOUT_STARTS):
                # spec 14 review: an explicit `?` key, a tag, an anchor or
                # alias, a directive or a document marker after the first
                # content line, at column 0.
                unresolved_layout()
                top = "other"
                continue
            mon = _ON.match(line)
            if not mon:
                if _ON_QUOTED.match(line):
                    # SPEC §3.1: the closed trigger forms are read from an
                    # unquoted column-0 `on:` key. A quoted "on" / 'on' key
                    # (yamllint's truthy fix), or `on :` (spec 14), is an on:
                    # block the grammar does not resolve: seen, so never an
                    # observed trigger removal, and unknown coverage; its
                    # triggers are not read.
                    top = "on_unresolved"
                    result.on_seen = True
                    result.unknown.append(ON_UNRESOLVED)
                    continue
                if _JOBS.match(line):
                    top = "jobs"
                    seen_jobs = True
                    jobs_first_child = True
                    continue
                spelled = _key_spelling(line)
                mjv = _JOBS_VALUE.match(line)
                if mjv and _recorded(mjv.group(1)):
                    # spec 14 (#23): `jobs: {…}` holds the table in flow style.
                    top = "jobs_unresolved"
                    seen_jobs = True
                    result.jobs_unresolved = True
                    result.job_unknown.append(FLOW_JOB)
                    continue
                if spelled is not None and spelled[0] == "jobs" and spelled[1]:
                    # spec 14 (#23): a quoted or spaced `jobs` key.
                    top = "jobs_unresolved"
                    seen_jobs = True
                    result.jobs_unresolved = True
                    result.job_unknown.append(KEY_SPELLING)
                    continue
                top = "other"
                if spelled is not None and spelled[0] == "defaults":
                    if spelled[1]:
                        result.job_unknown.append(KEY_SPELLING)
                        continue
                    # spec 14 review: workflow-level `defaults:` reaches
                    # every job's `run` steps, so its step run keys are read.
                    top = "defaults"
                    reader = _StepReader(None, result.defaults, result.job_unknown)
                    if _recorded(line.split(":", 1)[1]):
                        reader.line(0, stripped)
                        if flow_depth > 0 and reader.flow is not None:
                            flow_sink = _reader_sink(reader)
                continue
            top = "on"
            result.on_seen = True
            raw = _recorded(mon.group(1))
            if raw and _continues(raw):
                # #4: a block-scalar header is not a trigger name.
                top = "on_unresolved"
                result.unknown.append(ON_UNRESOLVED)
                continue
            val = strip_quotes(raw).strip()
            if val:
                # An inline value: no line below is a trigger.
                top = "on_inline"
                if val.startswith("{") or flow_depth > 0:
                    # A flow mapping, or (review) a list left open on its
                    # line, is not one of the closed forms.
                    result.unknown.append(ON_UNRESOLVED)
                elif val.startswith("[") and val.endswith("]"):
                    for item in val[1:-1].split(","):
                        t = strip_quotes(item.strip())
                        if t:
                            result.triggers.add(t)
                else:
                    result.triggers.add(val)
            continue
        if top == "on":
            # SPEC §3.1 (spec 8): direct children (indent 2) are triggers,
            # either list items or mapping keys; deeper lines are trigger
            # configuration, not triggers.
            if indent == 2:
                current_trigger = None
                is_item = stripped.startswith("- ")
                item = stripped[2:] if is_item else stripped
                key, sep, rest = item.partition(":")
                item = strip_quotes(truncate_inline_comment(key).strip())
                if "{" in item or not item:
                    result.unknown.append(ON_UNRESOLVED)
                else:
                    result.triggers.add(item)
                    if not is_item and item in CONFIGURED_TRIGGERS:
                        # spec 14 (§3.1, #13): configuration of push /
                        # pull_request is recorded as text, never read;
                        # an inline remainder (`push: {…}`) included.
                        current_trigger = item
                        config = result.trigger_config.setdefault(item, [])
                        inline = _recorded(rest) if sep else ""
                        if inline:
                            config.append(inline)
                        if flow_depth > 0:
                            flow_sink = config.append
            elif current_trigger is not None and indent > 2:
                result.trigger_config[current_trigger].append(
                    truncate_inline_comment(stripped).strip()
                )
            continue
        if top in ("other", "defaults") and seen_jobs and indent == 2 and _JOB_KEY.match(line):
            # spec 14 (#24): before spec 14 a top-level key after `jobs:`
            # did not end the job table, and this line was read as a job.
            result.job_unknown.append(AFTER_JOBS)
            continue
        if top == "defaults" and reader is not None:
            reader.line(indent, stripped)
            if flow_depth > 0 and reader.flow is not None:
                flow_sink = _reader_sink(reader)
        if top == "jobs":
            if jobs_first_child:
                jobs_first_child = False
                if indent != 2:
                    # spec 14 (#24): job keys at another indentation; the
                    # table is unresolved, never read as deleted.
                    top = "jobs_unresolved"
                    result.jobs_unresolved = True
                    result.job_unknown.append(JOBS_INDENT)
            if top == "jobs" and indent == 2:
                awaiting_body = False
                job_block = None
                reader = None
                mjob = _JOB_KEY.match(line)
                if mjob:
                    current_job = mjob.group(1)
                    result.jobs[current_job] = GhaJob(key=current_job)
                    awaiting_body = True
                    continue
                # Any other indent-2 line is outside the job-key form: the
                # lines below it are not read as the job before it (spec 14
                # review).
                current_job = None
                spelled = _key_spelling(stripped)
                mvalue = _JOB_KEY_VALUE.match(line)
                if spelled is not None and spelled[1]:
                    # spec 14 (#23): a quoted or spaced job key. That job is
                    # not read.
                    result.unresolved_job_keys.add(spelled[0])
                    result.job_unknown.append(KEY_SPELLING)
                    continue
                if mvalue and _recorded(mvalue.group(2)):
                    # spec 14 (#23): a flow-style job body (`  ci: {…}`).
                    result.unresolved_job_keys.add(mvalue.group(1))
                    result.job_unknown.append(FLOW_JOB)
                    continue
            if current_job is not None and awaiting_body:
                awaiting_body = False
                if indent != 4:
                    # spec 14 (#24): a job body at another indentation is
                    # not read; nothing below is read as this job's.
                    result.jobs[current_job].body_unresolved = True
                    current_job = None
                    result.job_unknown.append(JOBS_INDENT)
        if current_job is not None and top == "jobs" and indent >= 4:
            job = result.jobs[current_job]
            job.lines.append(line.rstrip(" "))
            if reader is not None and reader.flow is not None:
                # A line of a flow value left open in `steps:` / `defaults:`.
                reader.line(indent, stripped)
                continue
            if indent == 4 and not stripped.startswith("- "):
                # A job-level key: it opens the block its deeper lines (and
                # `- ` items at job indent) belong to.
                reader = None
                spelled = _key_spelling(stripped)
                job_block = spelled[0] if spelled is not None and not spelled[1] else None
                if spelled is not None:
                    key = spelled[0]
                    rest = stripped.split(":", 1)[1] if ":" in stripped else ""
                    if spelled[1] and (key in _JOB_INDENT_KEYS or key in _ANY_INDENT_KEYS):
                        # A job-level `uses:` is also a §4 pin, read on every
                        # workflow (spec 14 review).
                        target = result.unknown if key == "uses" else result.job_unknown
                        target.append(KEY_SPELLING)
                        result.job_level_unread = True
                        continue
                    value = _recorded(rest)
                    if key == "needs":
                        job.needs = [value] if value else []
                        if flow_depth > 0:
                            flow_sink = _piece_appender(job.needs)
                    elif key == "strategy":
                        job.strategy = [value] if value else []
                        if flow_depth > 0:
                            flow_sink = _piece_appender(job.strategy)
                    elif key == "uses":
                        job.calls = strip_quotes(value)
                    elif key == "steps":
                        reader = _StepReader(job.steps, None, result.job_unknown)
                        if value:
                            # A flow-style `steps:` value, recorded as text.
                            reader.line(indent, value)
                            if flow_depth > 0 and reader.flow is not None:
                                flow_sink = _reader_sink(reader)
                    elif key == "defaults":
                        defaults = GhaStep(fallback="defaults")
                        job.steps.append(defaults)
                        reader = _StepReader(None, defaults, result.job_unknown)
                        if value:
                            reader.line(indent, stripped)
                            if flow_depth > 0 and reader.flow is not None:
                                flow_sink = _reader_sink(reader)
                    elif key == "if" and (_continues(value) or opened is not None):
                        # spec 14 review: a multiline job `if:` is recorded
                        # as its header and its later lines.
                        job.if_lines = [value]
                        if opened is not None:
                            quote_sink = job.if_lines.append
            elif job_block == "if" and job.if_lines is not None:
                job.if_lines.append(stripped.rstrip(" "))
            elif job_block in ("needs", "strategy"):
                piece = truncate_inline_comment(stripped).strip()
                target = job.needs if job_block == "needs" else job.strategy
                if piece and target is not None:
                    target.append(piece)
            elif job_block in _STEP_BLOCKS and reader is not None:
                reader.line(indent, stripped)
                if flow_depth > 0 and reader.flow is not None:
                    flow_sink = _reader_sink(reader)
                if opened is not None and reader.last is not None:
                    # A step run key's quoted value left open: its later
                    # lines are its text.
                    quote_sink = _appender(*reader.last)
        if top not in ("on", "on_unresolved") and (
            '"' in stripped or "'" in stripped or " :" in stripped
        ):
            # Only a quote or a space before a colon can spell a key oddly.
            text_after, _width = _split_dash(stripped)
            spelled = _key_spelling(text_after)
            if spelled is not None and spelled[1] and spelled[0] in _ANY_INDENT_KEYS:
                # spec 14 (#23): `"if": false`, `uses :` and the like are
                # not read; the line is reported, never taken as absent. A
                # `uses` pin is read by §4 on every workflow; `if` and
                # `continue-on-error` only by the §5 producer reading.
                target = result.unknown if spelled[0] == "uses" else result.job_unknown
                target.append(KEY_SPELLING)
                continue
        mu = _USES.match(line)
        if mu:
            raw = _recorded(mu.group(2))
            if _continues(raw) or opened is not None:
                # §3.1 residual: `uses` split across lines (#4).
                result.unknown.append(MULTILINE)
                continue
            val = strip_quotes(raw)
            parsed = parse_uses(val)
            if parsed:
                loc, ref = parsed
                n = uses_n.get(loc, 0)
                uses_n[loc] = n + 1
                result.uses.append((loc, ref, n))
            elif val.startswith("docker://"):
                result.unknown.append("docker uses")
            continue
        mc = _CONTINUE.match(line)
        if mc:
            raw = _recorded(mc.group(3))
            if current_job is not None and indent == 4 and mc.group(2) is None:
                flag = strip_quotes(raw).lower()
                if flag == "true":
                    result.jobs[current_job].continue_on_error = True
                elif flag == "false":
                    result.jobs[current_job].continue_on_error = False
                elif _continues(raw):
                    result.unknown.append(MULTILINE)
                else:
                    # §3.1 records `true` / `false` only; an expression or a
                    # YAML 1.1 boolean is unresolved, never a silent `None` (#4).
                    result.unknown.append(CONTINUE_UNRESOLVED)
                continue
            if _continues(raw):
                # SPEC §3.1 lists multiline scalars as residuals at any
                # indent: a step-level block scalar or empty value (`- `
                # first included) is unknown coverage, as the same forms of
                # step `if:` already are (#14, #4 parity). Its value is not
                # otherwise recorded.
                result.unknown.append(MULTILINE)
            continue
        mi = _IF.match(line)
        if mi:
            if_value = _recorded(mi.group(3))
            # SPEC §3.1: multiline scalars stay residuals, but must be
            # visible as unknown coverage rather than a silent clean scan.
            unresolved = _continues(if_value) or opened is not None
            if unresolved:
                result.unknown.append(MULTILINE)
            if current_job is not None and indent == 4 and mi.group(2) is None:
                result.jobs[current_job].if_value = None if unresolved else if_value
                continue
        mn = _NAME.match(line)
        if mn and current_job is not None and indent == 4:
            job = result.jobs[current_job]
            if job.name is None and job.name_resolved:
                raw = _recorded(mn.group(2))
                if _continues(raw) or opened is not None:
                    job.name_resolved = False
                    result.unknown.append(MULTILINE)
                else:
                    job.name = strip_quotes(raw)
                    # spec 14 review: a double-quoted escape is decoded by
                    # YAML; the grammar does not decode it.
                    job.name_escaped = raw.startswith('"') and "\\" in raw
            continue
    if result.on_seen and not result.triggers:
        if ON_UNRESOLVED not in result.unknown:
            result.unknown.append(ON_UNRESOLVED)
    result.defaults.finish()
    for job in result.jobs.values():
        for step in job.steps:
            step.finish()
    return result


def job_unresolved(g: GhaFile, key: str) -> bool:
    """spec 14 (§3.1): a job missing from `g` is unresolved rather than
    deleted when the whole job table, or that job's own key, is in a form
    the grammar does not read."""
    return g.jobs_unresolved or key in g.unresolved_job_keys


def if_text(job: GhaJob) -> str | None:
    """The job `if:` as recorded: its single-line value, or a multiline
    value's header and body lines (spec 14 review); None when absent."""
    if job.if_lines is not None:
        return "\n".join(job.if_lines)
    return job.if_value


def step_run_keys(job: GhaJob) -> list[tuple[str, str]]:
    """Each recorded step run key with the identity of its step (§3.1)."""
    return [(step.identity(), key) for step in job.steps for key in step.keys]


def job_disabled(job: GhaJob) -> bool:
    if job.if_value is None:
        return False
    raw = job.if_value.strip().strip("\"'")
    return raw.lower() in {"false", "${{ false }}"}
