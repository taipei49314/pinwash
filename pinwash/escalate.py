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


def pin_float_severity(head_kind: str, head_non_floating: int) -> str:
    """§6.3: a floated pin is high; critical if last non-floating on the file."""
    if head_kind == "floating":
        return "critical" if head_non_floating == 0 else "high"
    return "warn"


def pin_removed_severity(head_non_floating: int) -> str:
    """§6.3: a pin removed while the workflow remains starts at high."""
    return "critical" if head_non_floating == 0 else "high"
