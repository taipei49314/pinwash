"""Severity escalators (SPEC §6). Order fixed, deterministic, no scores."""

from __future__ import annotations

SEVERITY_RANK = {"info": 0, "warn": 1, "high": 2, "critical": 3}

HOOK_RULES = frozenset({"HOOK_REMOVED", "HOOK_BYPASSED", "GATE_STUBBED"})


def stop_last_resort(head_live_stops: int) -> bool:
    """§6.1: escalate when the last remaining Stop-like hook is gone."""
    return head_live_stops == 0


def last_context_gone(remaining: int) -> bool:
    """§6.2: escalate when the last remaining required context is dropped."""
    return remaining == 0


def pin_float_severity(base_kind: str, head_kind: str, head_non_floating: int) -> str:
    """§6.3 (spec 15): a non-floating workflow pin moved to floating is high,
    critical when the head file keeps no non-floating pin. A floating ref
    changed to another floating ref (`@v3` -> `@v4`) was never pinned and
    stays warn, and so does a kind drop that does not float (`git_sha` ->
    `git_tag`)."""
    if head_kind == "floating" and base_kind != "floating":
        return "critical" if head_non_floating == 0 else "high"
    return "warn"


def pin_removed_severity(base_kind: str, head_non_floating: int) -> str:
    """§6.3 (spec 15): a non-floating workflow pin removed while its workflow
    remains is critical when the head file then keeps no non-floating pin,
    and warn otherwise; a floating ref removed unpins nothing (warn)."""
    if base_kind == "floating":
        return "warn"
    return "critical" if head_non_floating == 0 else "warn"
