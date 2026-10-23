"""Spec 37: narrow syntactic producer rekeys/moves, not semantic proof."""
from __future__ import annotations
import re
from pinwash.parse.gha import needs_names, parse_workflow
from pinwash.rules.required_check import _name_literal
from pinwash.surfaces import is_gha_workflow

# A closed syntactic match cannot prove context-property independence. Reject
# the context name itself, including grouped/indexed/whitespace property forms.
_DYNAMIC = re.compile(r"\bgithub\b|GITHUB_(?:JOB|WORKFLOW|WORKFLOW_REF)", re.I)

def text(data):
    if data is None:
        return None
    try:
        return data.decode("utf-8", "strict").replace("\r\n", "\n")
    except UnicodeError:
        return None

def admissible(job, jobs):
    name = job.name
    if (not name or not job.name_resolved or job.body_unresolved or job.calls is not None
            or job.strategy is not None or getattr(job, "needs", None)
            or job.name_text != name or _name_literal(name) != name):
        return False
    return sum((j.name or j.key).casefold() == name.casefold() for j in jobs.values()) == 1

def matches(base, head):
    result = {}
    base_paths = {p for p in base if is_gha_workflow(p)}
    head_paths = {p for p in head if is_gha_workflow(p)}
    for path in sorted(base_paths):
        b, h = text(base[path]), text(head.get(path))
        if b is None or _DYNAMIC.search(b):
            continue
        bg = parse_workflow(b)
        if bg.unparseable or bg.job_table_partial():
            continue
        if path in head_paths and h is not None:
            hg = parse_workflow(h)
            if hg.unparseable or hg.job_table_partial():
                continue
            old = set(bg.jobs) - set(hg.jobs)
            new = set(hg.jobs) - set(bg.jobs)
            if len(old) != 1 or len(new) != 1:
                continue
            bk, hk = next(iter(old)), next(iter(new))
            bj, hj = bg.jobs[bk], hg.jobs[hk]
            if not admissible(bj, bg.jobs) or not admissible(hj, hg.jobs) or bj.name != hj.name:
                continue
            # The complete document, including raw run lines/comments and
            # workflow-level settings, must differ by this header only.
            before, after = "  " + bk + ":", "  " + hk + ":"
            lines = b.split("\n")
            positions = [i for i, line in enumerate(lines) if line == before]
            if len(positions) != 1:
                continue
            i = positions[0]
            rest = "\n".join(lines[:i] + lines[i+1:])
            # Explicit dependencies/expressions are not admitted. The
            # name line is stable literal identity, not a key reference.
            keys = "(?:" + re.escape(bk) + "|" + re.escape(hk) + ")"
            context_reference = (r"\b(?:needs|jobs)(?:\s*\))*\s*(?:\.\s*" + keys
                                 + r"(?![A-Za-z0-9_-])|\[\s*['\"]" + keys + r"['\"]\s*\])")
            if (any(set(needs_names(j)) & {bk, hk} for j in bg.jobs.values())
                    or re.search(context_reference, rest)):
                continue
            lines[i] = after
            if "\n".join(lines) == h:
                result[path] = (path, hg, {bk: hk})
        elif path not in head_paths:
            possible = [p for p in sorted(head_paths - base_paths) if text(head[p]) == b]
            if len(possible) != 1 or path in b:
                continue
            destination = possible[0]
            if destination in b:
                continue
            # Another removed copy makes the identity ambiguous as well.
            if sum(text(base[p]) == b for p in base_paths - head_paths) != 1:
                continue
            mapping = {k: k for k, j in bg.jobs.items() if admissible(j, bg.jobs)}
            if mapping:
                result[path] = (destination, parse_workflow(b), mapping)
    return result
