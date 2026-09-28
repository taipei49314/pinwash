"""REQUIRED_CHECK_DROPPED: ruleset contexts and their producing jobs (SPEC §5)."""

from __future__ import annotations

from typing import Any

from pinwash.escalate import last_context_gone
from pinwash.parse.gha import job_disabled

# SPEC §5 (spec 8): the events on which a workflow's run provides a
# required status context to merge gating. A context reported only from
# other events (schedule, workflow_dispatch, …) never gates the flow.
ENFORCEMENT_EVENTS = {"push", "pull_request"}


def ruleset_contexts(doc: Any) -> list[str]:
    found: list[str] = []

    def walk(node: Any) -> None:
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
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(doc)
    return found


def detect_jobs(
    path: str,
    base_g: Any,
    head_g: Any,
    base_contexts: set[str],
    add: Any,
) -> None:
    if base_g is None or getattr(base_g, "unparseable", False):
        return
    if not base_contexts:
        # SPEC §5: the job-side trigger is the job that produced a required
        # status context named at base. With no named contexts there is no
        # job-side finding (rename blindness without a ruleset is R09).
        return
    head_jobs = (
        head_g.jobs if head_g is not None and not head_g.unparseable else {}
    )
    for key, job in base_g.jobs.items():
        display = job.name or key
        if display not in base_contexts:
            continue
        head_job = head_jobs.get(key)
        dropped = False
        after = ""
        if head_job is None:
            dropped = True
            after = "deleted"
        elif job_disabled(head_job) and not job_disabled(job):
            dropped = True
            after = head_job.if_value or "if: false"
        elif head_job.continue_on_error is True and job.continue_on_error is not True:
            dropped = True
            after = "continue-on-error: true"
        elif (base_g.triggers & ENFORCEMENT_EVENTS) and not (
            head_g.triggers & ENFORCEMENT_EVENTS
        ) and (not head_g.on_seen or head_g.triggers):
            # spec 8: the job survives, but its workflow no longer runs on
            # any enforcement-path event, so the context is never produced.
            # An `on:` block whose forms the bounded grammar cannot resolve
            # is a residual (§3.1), not an observed removal — silent here.
            dropped = True
            after = "on: " + (", ".join(sorted(head_g.triggers)) or "none")
        if dropped:
            add(
                rule="REQUIRED_CHECK_DROPPED",
                severity="warn",
                message=f"workflow job {display} no longer a reliable required check producer",
                path=path,
                before=display,
                after=after,
                locator=key,
            )


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
