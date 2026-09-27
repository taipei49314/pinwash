"""HOOK_REMOVED / HOOK_BYPASSED / GATE_STUBBED (SPEC §5, §5.1, §5.2)."""

from __future__ import annotations

from typing import Any

from pinwash.escalate import HOOK_RULES, stop_last_resort
from pinwash.hooks import stub_command


def _non_stub_stop_count(
    events: dict[str, dict[str, Any]],
    names: frozenset[str],
    body_map: dict[str, tuple[bool, bool, str]],
) -> int:
    n = 0
    for name in names:
        info = events.get(name)
        if not info:
            continue
        live = [
            c
            for c in info["commands"]
            if not stub_command(c)
            and not c.lstrip().startswith("#")
            and not (c in body_map and (body_map[c][0] or body_map[c][1]))
        ]
        if live:
            n += 1
        elif info["array_len"] > 0 and not info["commands"]:
            n += 0
    return n


def detect(
    path: str,
    base_ev: dict[str, dict[str, Any]],
    head_ev: dict[str, dict[str, Any]],
    stop_names: frozenset[str],
    add: Any,
    body_base: dict[str, tuple[bool, bool, str]],
    body_head: dict[str, tuple[bool, bool, str]],
) -> None:
    head_stop = _non_stub_stop_count(head_ev, stop_names, body_head)

    def escalate_stop(rule: str, event: str, severity: str) -> str:
        if event in stop_names and stop_last_resort(head_stop) and rule in HOOK_RULES:
            return "critical"
        return severity


    for event, info in base_ev.items():
        head_info = head_ev.get(event)
        if head_info is None:
            sev = escalate_stop("HOOK_REMOVED", event, "warn")
            add(
                rule="HOOK_REMOVED",
                severity=sev,
                message=f"hook event {event} removed",
                path=path,
                before=event,
                after="",
                locator=event,
            )
            continue
        if head_info["array_len"] == 0 or not head_info["commands"]:
            if head_info["array_len"] == 0:
                sev = escalate_stop("HOOK_BYPASSED", event, "warn")
                add(
                    rule="HOOK_BYPASSED",
                    severity=sev,
                    message=f"hook event {event} array emptied",
                    path=path,
                    locator=event,
                )
            if not head_info["commands"]:
                sev = escalate_stop("HOOK_REMOVED", event, "warn")
                add(
                    rule="HOOK_REMOVED",
                    severity=sev,
                    message=f"hook event {event} command list emptied",
                    path=path,
                    locator=event,
                )
            continue
        bf, hf = info["flags"], head_info["flags"]
        if (not bf["disabled"] and hf["disabled"]) or (
            not bf["hookEnabled_false"] and hf["hookEnabled_false"]
        ) or (not bf["continueOnError"] and hf["continueOnError"]) or (
            not bf["failOpen"] and hf["failOpen"]
        ):
            sev = escalate_stop("HOOK_BYPASSED", event, "warn")
            add(
                rule="HOOK_BYPASSED",
                severity=sev,
                message=f"hook event {event} skip flag added",
                path=path,
                locator=event,
            )
        base_cmds = info["commands"]
        head_cmds = head_info["commands"]
        for i, cmd in enumerate(head_cmds):
            prev = base_cmds[i] if i < len(base_cmds) else ""
            if stub_command(cmd) and not stub_command(prev):
                sev = escalate_stop("GATE_STUBBED", event, "warn")
                add(
                    rule="GATE_STUBBED",
                    severity=sev,
                    message=f"hook command for {event} replaced with a v0 stub",
                    path=path,
                    before=prev,
                    after=cmd,
                    locator=event,
                )
            if (
                i < len(base_cmds)
                and prev.strip()
                and not prev.lstrip().startswith("#")
                and cmd.lstrip().startswith("#")
            ):
                # SPEC §5 HOOK_BYPASSED: command prefixed with a no-op. The
                # v0 closed shape for that prefix is a shell comment.
                sev = escalate_stop("HOOK_BYPASSED", event, "warn")
                add(
                    rule="HOOK_BYPASSED",
                    severity=sev,
                    message=f"hook command for {event} commented out",
                    path=path,
                    before=prev,
                    after=cmd,
                    locator=event,
                )
            if (
                i < len(base_cmds)
                and cmd in body_head
                and body_head[cmd][0]
                and prev in body_base
                and not body_base[prev][0]
            ):
                # SPEC §5 GATE_STUBBED, body form: the command resolves
                # (§3.3) to a stub body while the base resolved to a real one.
                sev = escalate_stop("GATE_STUBBED", event, "warn")
                add(
                    rule="GATE_STUBBED",
                    severity=sev,
                    message=f"hook command for {event} resolves to a stub body",
                    path=path,
                    before=body_base[prev][2],
                    after=body_head[cmd][2],
                    locator=f"{event}:{cmd}",
                )
            elif i < len(base_cmds) and cmd in body_head and body_head[cmd][1]:
                # SPEC §5.2 (spec 7): shape-preserving gut job — the judge
                # body can no longer refuse anything.
                sev = escalate_stop("GATE_STUBBED", event, "warn")
                add(
                    rule="GATE_STUBBED",
                    severity=sev,
                    message=f"hook command for {event} lost block capability",
                    path=path,
                    before="block-capable",
                    after="no block/deny",
                    locator=f"{event}:{cmd}",
                )
        if (
            "*" in info["matchers"]
            and "*" not in head_info["matchers"]
            and not head_info["commands"]
        ):
            sev = escalate_stop("HOOK_BYPASSED", event, "warn")
            add(
                rule="HOOK_BYPASSED",
                severity=sev,
                message=f"hook event {event} matcher * removed and commands emptied",
                path=path,
                locator=event,
            )
