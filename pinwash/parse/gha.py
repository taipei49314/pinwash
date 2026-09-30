"""Bounded GitHub Actions line grammar (SPEC §3.1). Not YAML 1.2."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pinwash.pins import parse_uses
from pinwash.textutil import crlf_to_lf

_JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
_USES = re.compile(r"^(\s*)(?:-\s+)?uses:\s*(.*)$")
_CONTINUE = re.compile(r"^(\s*)continue-on-error:\s*(.*)$")
_IF = re.compile(r"^(\s*)if:\s*(.*)$")
_NAME = re.compile(r"^(\s*)name:\s*(.*)$")
_JOBS = re.compile(r"^jobs:\s*$")
_ON = re.compile(r"^on:\s*(.*)$")
_BLOCK_SCALAR = re.compile(r"^[>|](?:[+-][1-9]?|[1-9][+-]?)?$")


@dataclass
class GhaJob:
    key: str
    name: str | None = None
    if_value: str | None = None
    continue_on_error: bool | None = None


@dataclass
class GhaFile:
    uses: list[tuple[str, str, int]]  # locator-repo, ref, occurrence
    jobs: dict[str, GhaJob] = field(default_factory=dict)
    triggers: set[str] = field(default_factory=set)
    on_seen: bool = False
    unknown: list[str] = field(default_factory=list)
    unparseable: bool = False


def strip_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def truncate_inline_comment(value: str) -> str:
    """SPEC §3.1 (spec 5): a recorded value ends at the first ' #' sequence."""
    idx = value.find(" #")
    return value[:idx] if idx != -1 else value


def parse_workflow(text: str) -> GhaFile:
    normalized = crlf_to_lf(text)
    result = GhaFile(uses=[])
    in_jobs = False
    in_on = False
    current_job: str | None = None
    uses_n: dict[str, int] = {}
    for line in normalized.split("\n"):
        stripped = line.lstrip(" ")
        if "\t" in line.split("#")[0]:
            result.unparseable = True
            return result
        if stripped.startswith("#") or not stripped:
            continue
        indent = len(line) - len(line.lstrip(" "))
        if "|" in line or line.rstrip().endswith(">") or line.rstrip().endswith("|"):
            if "uses:" in line or stripped.startswith("|") or stripped.startswith(">"):
                result.unknown.append("multiline uses or scalar")
        if "*" in stripped and not stripped.startswith("uses:"):
            if re.search(r"\*[A-Za-z]", stripped):
                result.unknown.append("yaml alias")
        mon = _ON.match(line)
        if indent == 0:
            # a top-level line starts the `on:` block or ends it
            in_on = bool(mon)
            if not mon:
                if _JOBS.match(line):
                    in_jobs = True
                    current_job = None
                    continue
                continue
            result.on_seen = True
            val = strip_quotes(truncate_inline_comment(mon.group(1))).strip()
            if val:
                in_on = False
                if val.startswith("{"):
                    result.unknown.append("on triggers unresolved")
                elif val.startswith("[") and val.endswith("]"):
                    for item in val[1:-1].split(","):
                        t = strip_quotes(item.strip())
                        if t:
                            result.triggers.add(t)
                else:
                    result.triggers.add(val)
            continue
        if in_on:
            # SPEC §3.1 (spec 8): direct children (indent 2) are triggers,
            # either list items or mapping keys; deeper lines are trigger
            # configuration, not triggers.
            if indent == 2:
                item = stripped[2:] if stripped.startswith("- ") else stripped
                item = strip_quotes(
                    truncate_inline_comment(item.split(":")[0]).strip()
                )
                if "{" in item or not item:
                    result.unknown.append("on triggers unresolved")
                else:
                    result.triggers.add(item)
            continue
        if in_jobs:
            mjob = _JOB_KEY.match(line)
            if mjob:
                current_job = mjob.group(1)
                result.jobs[current_job] = GhaJob(key=current_job)
                continue
        mu = _USES.match(line)
        if mu:
            val = strip_quotes(truncate_inline_comment(mu.group(2)))
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
        if mc and current_job is not None and indent == 4:
            flag = strip_quotes(truncate_inline_comment(mc.group(2))).lower()
            if flag == "true":
                result.jobs[current_job].continue_on_error = True
            elif flag == "false":
                result.jobs[current_job].continue_on_error = False
            continue
        mi = _IF.match(line)
        if mi:
            if_value = truncate_inline_comment(mi.group(2)).strip()
            # SPEC §3.1: multiline scalars stay residuals, but must be
            # visible as unknown coverage rather than a silent clean scan.
            if _BLOCK_SCALAR.fullmatch(if_value):
                result.unknown.append("multiline uses or scalar")
            if current_job is not None and indent == 4:
                result.jobs[current_job].if_value = if_value
                continue
        mn = _NAME.match(line)
        if mn and current_job is not None and indent == 4:
            if result.jobs[current_job].name is None:
                result.jobs[current_job].name = strip_quotes(
                    truncate_inline_comment(mn.group(2))
                )
            continue
    if result.on_seen and not result.triggers:
        if "on triggers unresolved" not in result.unknown:
            result.unknown.append("on triggers unresolved")
    return result


def job_disabled(job: GhaJob) -> bool:
    if job.if_value is None:
        return False
    raw = job.if_value.strip().strip("\"'")
    return raw.lower() in {"false", "${{ false }}"}
