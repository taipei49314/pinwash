"""HOOK_REMOVED / HOOK_BYPASSED / GATE_STUBBED (SPEC §5, §5.1, §5.2)."""

from __future__ import annotations

from collections import Counter
from typing import Any

from pinwash.escalate import HOOK_RULES, stop_last_resort
from pinwash.hooks import stub_command


HOOK_LIVENESS_UNRESOLVED = "hook stop liveness rests on an unresolved command"


def _non_stub_stop_count(
    events: dict[str, dict[str, Any]],
    names: frozenset[str],
    body_map: dict[str, tuple[bool, bool, str]],
    resolved_only: bool = False,
) -> int:
    """SPEC §5.2 / §6.1: the Stop-like events of one file that keep a live
    command. A command is live unless it is a §5.2 stub string, carries a
    §5.1 skip flag (its own or inherited), starts with `#`, resolves (§3.3)
    only to stub bodies, or lost block capability; nothing else is read.

    With resolved_only, a command §3.3 does not resolve does not count: the
    count the escalator would see if no unread judge body were credited.
    """
    n = 0
    for name in names:
        info = events.get(name)
        if not info:
            continue
        live = [
            c
            for c, flags in info["command_states"]
            if not any(flags.values())
            and not stub_command(c)
            and not c.lstrip().startswith("#")
            and not (c in body_map and (body_map[c][0] or body_map[c][1]))
            and (c in body_map or not resolved_only)
        ]
        if live:
            n += 1
        elif info["array_len"] > 0 and not info["commands"]:
            n += 0
    return n


def live_stop_events(
    events: dict[str, dict[str, Any]],
    names: frozenset[str],
    body_map: dict[str, tuple[bool, bool, str]],
) -> int:
    """SPEC §6.1: the Stop-like events of one file that keep a live command."""
    return _non_stub_stop_count(events, names, body_map)


def _is_comment(command: str) -> bool:
    return command.lstrip().startswith("#")


def _lost_by_text(
    base_cmds: list[str], base_count: Counter[str], head_count: Counter[str]
) -> dict[str, str]:
    """Stripped text -> the first base command with that text that is not a
    comment and lost an occurrence at head. Built once per event, so pairing
    every head comment costs one lookup, not a scan of the base list."""
    out: dict[str, str] = {}
    for b in base_cmds:
        text = b.strip()
        if text and text not in out and not _is_comment(b) and head_count[b] < base_count[b]:
            out[text] = b
    return out


def _commented_base(cmd: str, prev: str | None, lost_by_text: dict[str, str]) -> str | None:
    """SPEC §5 HOOK_BYPASSED, "command prefixed with a no-op" (§5.1: its v0
    closed form is a shell comment): the base command a `#` head command
    comments out, or None.

    The base command at the same list index pairs first, as since the
    first engine, so every finding that fired before keeps its fields. Then
    the base command whose string the comment prefixes, wherever it stood,
    when that command lost an occurrence: §5.1 compares commands as
    multisets of their strings, so an inserted sibling cannot move a
    comment-out out of view (#9, #10).
    """
    if not _is_comment(cmd):
        return None
    if prev is not None and prev.strip() and not _is_comment(prev):
        return prev
    return lost_by_text.get(cmd.lstrip().lstrip("#").strip())


def _stub_body_base(
    cmd: str,
    prev: str | None,
    base_count: Counter[str],
    body_base: dict[str, tuple[bool, bool, str]],
    body_head: dict[str, tuple[bool, bool, str]],
) -> str | None:
    """SPEC §5 GATE_STUBBED body form: the base command whose non-stub body
    the head command's stub body replaced, or None.

    The base command at the same list index pairs first (spec 4), then the
    same command string wherever it stood at base: §5.2 compares bodies per
    resolved target, and an unchanged command is its own base command (#10).
    """
    if cmd not in body_head or not body_head[cmd][0]:
        return None

    def real(command: str) -> bool:
        return command in body_base and not body_base[command][0]

    if prev is not None and real(prev):
        return prev
    if base_count[cmd] and real(cmd):
        return cmd
    return None


def _tally(states: list[tuple[str, dict[str, bool]]]) -> tuple[dict[str, int], dict[str, int]]:
    """Per command string: (active occurrences, skipped occurrences)."""
    active: dict[str, int] = {}
    skipped: dict[str, int] = {}
    for command, flags in states:
        bucket = skipped if any(flags.values()) else active
        bucket[command] = bucket.get(command, 0) + 1
    return active, skipped


def _command_skip_added(base: dict[str, Any], head: dict[str, Any]) -> bool:
    """SPEC §5.1 (spec 10): a skip flag judged per command, not per event.

    A flag weakens an existing hook when (1) a command present on both
    sides lost active occurrences and gained skipped ones; (2) fewer
    commands stay active while more are skipped overall (a removal paired
    with a skip); or (3) an active base command disappeared while a new,
    already skipped command appeared (rename plus skip). Adding a new
    flagged command next to unchanged ones weakens nothing, whatever flag
    name it carries, and reordering is not a change.
    """
    base_active, base_skipped = _tally(base["command_states"])
    head_active, head_skipped = _tally(head["command_states"])
    base_names = base_active.keys() | base_skipped.keys()
    head_names = head_active.keys() | head_skipped.keys()
    for command in base_names:
        if head_active.get(command, 0) < base_active.get(command, 0) and (
            head_skipped.get(command, 0) > base_skipped.get(command, 0)
        ):
            return True
    if sum(head_active.values()) < sum(base_active.values()) and (
        sum(head_skipped.values()) > sum(base_skipped.values())
    ):
        return True
    vanished_active = any(command not in head_names for command in base_active)
    new_skipped = any(command not in base_names for command in head_skipped)
    return vanished_active and new_skipped


def detect(
    path: str,
    base_ev: dict[str, dict[str, Any]],
    head_ev: dict[str, dict[str, Any]],
    stop_names: frozenset[str],
    add: Any,
    body_base: dict[str, tuple[bool, bool, str]],
    body_head: dict[str, tuple[bool, bool, str]],
    note_unknown: Any = None,
) -> None:
    head_stop = _non_stub_stop_count(head_ev, stop_names, body_head)
    kept_below_critical = False

    def escalate_stop(rule: str, event: str, severity: str) -> str:
        nonlocal kept_below_critical
        if event in stop_names and rule in HOOK_RULES:
            if stop_last_resort(head_stop):
                return "critical"
            kept_below_critical = True
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
        if _command_skip_added(info, head_info):
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
        base_count = Counter(base_cmds)
        head_count = Counter(head_cmds)
        lost_by_text = _lost_by_text(base_cmds, base_count, head_count)
        for i, cmd in enumerate(head_cmds):
            at_index = base_cmds[i] if i < len(base_cmds) else None
            prev = at_index if at_index is not None else ""
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
            commented = _commented_base(cmd, at_index, lost_by_text)
            if commented is not None:
                # SPEC §5 HOOK_BYPASSED: command prefixed with a no-op. The
                # v0 closed shape for that prefix is a shell comment.
                sev = escalate_stop("HOOK_BYPASSED", event, "warn")
                add(
                    rule="HOOK_BYPASSED",
                    severity=sev,
                    message=f"hook command for {event} commented out",
                    path=path,
                    before=commented,
                    after=cmd,
                    locator=event,
                )
            stubbed = _stub_body_base(cmd, at_index, base_count, body_base, body_head)
            lost = cmd in body_head and body_head[cmd][1]
            if stubbed is not None and stubbed != at_index and lost and at_index is not None:
                # Spec 12 emitted "lost block capability" here (no list-index
                # stub-body pairing, base command at this index): keep that
                # finding and its fingerprint, so base exemptions keep matching.
                stubbed = None
            if stubbed is not None:
                # SPEC §5 GATE_STUBBED, body form: the command resolves
                # (§3.3) to a stub body while the base resolved to a real one.
                sev = escalate_stop("GATE_STUBBED", event, "warn")
                add(
                    rule="GATE_STUBBED",
                    severity=sev,
                    message=f"hook command for {event} resolves to a stub body",
                    path=path,
                    before=body_base[stubbed][2],
                    after=body_head[cmd][2],
                    locator=f"{event}:{cmd}",
                )
            elif lost:
                # SPEC §5.2 (spec 7): shape-preserving gut job — the judge
                # body can no longer refuse anything. The comparison is per
                # target path (§3.3), so it needs no command pairing and no
                # list position (#10).
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
    # SPEC §3.3 / §1.6 (spec 13, R12): the §6.1 count credits a command
    # §3.3 does not resolve as live, although no body was read for it.
    # Report when a Stop-like finding was kept below critical only because
    # of such a command, or when the diff left the file's Stop liveness
    # resting only on such commands. Visibility only (§7).
    if note_unknown is not None:
        head_resolved = _non_stub_stop_count(
            head_ev, stop_names, body_head, resolved_only=True
        )
        moved = (
            head_stop >= 1
            and _non_stub_stop_count(base_ev, stop_names, body_base, resolved_only=True) >= 1
        )
        if head_resolved == 0 and (kept_below_critical or moved):
            note_unknown(HOOK_LIVENESS_UNRESOLVED)
