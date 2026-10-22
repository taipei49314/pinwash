"""HOOK_REMOVED / HOOK_BYPASSED / GATE_STUBBED (SPEC §5, §5.1, §5.2).

Spec 27 (R12 detection bump, AI-assisted hook-liveness ruling, #10):
commands pair as multisets of their strings in every branch (no list-index
pairing); a Stop-like judge retargeted to a body that cannot refuse is
`GATE_STUBBED`; an event that keeps commands but no live one after a live
command left it is `HOOK_REMOVED`; and a command new to a Stop-like event
keeps the §6.1 escalator off only when it resolves to a body that can refuse.

Spec 28 (AI-assisted ruling on #45): the emptied clauses read what the event
held at base, and a claude_settings prompt/agent handler is a hook a diff can
remove, never a judge that keeps the §6.1 escalator off.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from pinwash.escalate import HOOK_RULES, stop_last_resort
from pinwash.hooks import stub_command


HOOK_LIVENESS_UNRESOLVED = "hook stop liveness rests on an unresolved command"

# command -> (all targets stub bodies, lost block capability, evidence,
# some target can refuse, target paths, some target holds a decision
# literal); see pinwash.parse.hookcmd.command_body_map.
Bodies = dict[str, tuple[Any, ...]]


def _is_comment(command: str) -> bool:
    return command.lstrip().startswith("#")


def _active(command: str, flags: dict[str, bool]) -> bool:
    """No §5.1 skip flag (own or inherited), not a §5.2 stub string, not
    commented out."""
    return (not any(v for k, v in flags.items() if k != "async")
            and not stub_command(command) and not _is_comment(command))


def _live(command: str, flags: dict[str, bool], bodies: Bodies, retargeted: set[str]) -> bool:
    """SPEC §5.2: live unless a stub string, skip-flagged, commented out,
    an async Claude Stop command, resolving only to stub bodies, lost block
    capability, or retargeted (§5) to a body that cannot refuse. Nothing else
    is read: a command §3.3
    does not resolve is live."""
    if not _active(command, flags) or flags.get("async", False):
        return False
    if command in bodies and (bodies[command][0] or bodies[command][1]):
        return False
    return command not in retargeted


def _base_identity(
    base_info: dict[str, Any] | None, body_base: Bodies
) -> tuple[set[str], set[frozenset[str]]]:
    """The command strings of an event at base and the §3.3 target sets they
    resolved to there, read once per event (§9: linear in the document)."""
    if base_info is None:
        return set(), set()
    strings = set(base_info["commands"])
    return strings, {frozenset(body_base[b][4]) for b in strings if b in body_base and not _is_comment(b)}


def _new_to_event(
    command: str, identity: tuple[set[str], set[frozenset[str]]], body_head: Bodies
) -> bool:
    """SPEC §6.1 (spec 27): the diff added the command to the event:
    its string was not in the event at base and, when it resolves at head,
    no command of the event resolved at base to the same target set (a
    respelling, such as `python` -> `python3`, is not new)."""
    strings, target_sets = identity
    if command in strings:
        return False
    return not (command in body_head and frozenset(body_head[command][4]) in target_sets)


def _stop_count(
    events: dict[str, dict[str, Any]],
    names: frozenset[str],
    bodies: Bodies,
    retargeted: dict[str, set[str]],
    *,
    resolved_only: bool = False,
    base_ev: dict[str, dict[str, Any]] | None = None,
    body_base: Bodies | None = None,
    handlers: bool = False,
) -> int:
    """The Stop-like events of one file that keep a live command (§5.2).

    With handlers (the spec 24 switch only, spec 28), an event that holds a
    modeled prompt/agent handler counts too. With base_ev (the §6.1
    escalator, spec 27), a command new to its
    event counts only when it resolves to a target that can refuse. With
    resolved_only, a command §3.3 does not resolve does not count: the count
    the escalator would see if no unread judge body were credited (§3.3 row).
    """
    n = 0
    for name in names:
        info = events.get(name)
        if not info:
            continue
        # SPEC §5.1 / §6.1 (spec 28, AI-assisted ruling on #45): a modeled
        # prompt/agent handler is a Stop-like hook the switch turns off, so
        # the switch's count credits it. No other count does: pinwash reads
        # no decision of a model (R13), so a handler never keeps the
        # escalator off and never stands in for a command in the §3.3 row.
        if handlers and info.get("non_commands"):
            n += 1
            continue
        gone = retargeted.get(name, set())
        identity = None
        if base_ev is not None:
            identity = _base_identity(base_ev.get(name), body_base or {})
        for c, flags in info["command_states"]:
            if not _live(c, flags, bodies, gone):
                continue
            if resolved_only and c not in bodies:
                continue
            if (
                identity is not None
                and _new_to_event(c, identity, bodies)
                and not (c in bodies and bodies[c][3])
            ):
                continue
            n += 1
            break
    return n


def live_stop_events(
    events: dict[str, dict[str, Any]],
    names: frozenset[str],
    body_map: Bodies,
) -> int:
    """SPEC §6.1: the Stop-like events of one file that keep a live command
    (§5.2) or a modeled prompt/agent handler (spec 28), read on one side
    (the spec 24 `disableAllHooks` finding)."""
    return _stop_count(events, names, body_map, {}, handlers=True)


def live_command_stop_events(
    events: dict[str, dict[str, Any]],
    names: frozenset[str],
    body_map: Bodies,
    *,
    base_events: dict[str, dict[str, Any]] | None = None,
    body_base: Bodies | None = None,
) -> int:
    """Command-only synchronous refusal count; handlers never lower severity.

    With base_events, apply §6.1's ordinary added-command trust rule to
    the retained head commands: a new unresolved command gives no credit.
    """
    return _stop_count(events, names, body_map, {},
                       base_ev=base_events, body_base=body_base)


def _retargets(
    info: dict[str, Any],
    head_info: dict[str, Any],
    body_base: Bodies,
    body_head: Bodies,
) -> tuple[list[str], list[str]]:
    """SPEC §5 GATE_STUBBED, retarget (spec 27, R12): in a Stop-like
    event, the left judges and the new commands, which pair one to one.
    Async commands are excluded from both sides. `left` was active at base
    and resolved there
    to a target holding a decision literal; at head its string is gone from
    the event, no `#` command of the event carries its text (that is the
    comment-out branch's), and no active command of the event resolves to
    its base target set. `new` gained active occurrences, resolves at head
    to a target set no active base command of the event resolved to, and
    resolves only to targets that mention neither `block` nor `deny`; a new
    command that lost block capability on a same path is the spec 7
    branch's. Left commands (base order) and new commands (head order) pair
    one to one."""
    b_act = Counter(c for c, f in info["command_states"] if _active(c, f) and not f.get("async", False))
    h_act = Counter(c for c, f in head_info["command_states"] if _active(c, f) and not f.get("async", False))
    head_strings = set(head_info["commands"])
    # Only a `#` command the diff added is the comment-out branch's; one
    # already at base pairs with nothing (review of 2026-10-10).
    b_all, h_all = Counter(info["commands"]), Counter(head_info["commands"])
    commented = {
        c.lstrip().lstrip("#").strip() for c in head_strings if _is_comment(c) and h_all[c] > b_all[c]
    }
    base_sets = {frozenset(body_base[c][4]) for c in b_act if c in body_base}
    head_sets = {frozenset(body_head[c][4]) for c in h_act if c in body_head}
    left = [
        c for c in dict.fromkeys(info["commands"])
        if b_act[c] and c not in head_strings and c.strip() not in commented
        and c in body_base and body_base[c][5]
        and frozenset(body_base[c][4]) not in head_sets
    ]
    if not left:
        return [], []
    new = [
        c for c in dict.fromkeys(head_info["commands"])
        if h_act[c] > b_act[c] and c in body_head and not body_head[c][1]
        and not body_head[c][3] and frozenset(body_head[c][4]) not in base_sets
    ]
    return left, new


def _tally(states: list[tuple[str, dict[str, bool]]]) -> tuple[dict[str, int], dict[str, int]]:
    """Per command string: (active occurrences, skipped occurrences)."""
    active: dict[str, int] = {}
    skipped: dict[str, int] = {}
    for command, flags in states:
        bucket = skipped if any(v for k, v in flags.items() if k != "async") else active
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
    body_base: Bodies,
    body_head: Bodies,
    note_unknown: Any = None,
) -> None:
    # SPEC §5 (spec 27): retargets are read first, because a
    # retargeted command is not live (§5.2) for the §6.1 count below.
    retargets: dict[str, tuple[list[str], list[str]]] = {}
    for event in stop_names:
        info, head_info = base_ev.get(event), head_ev.get(event)
        if info is None or head_info is None or not head_info["commands"]:
            continue
        lists = _retargets(info, head_info, body_base, body_head)
        if lists[0] and lists[1]:
            retargets[event] = lists
    retargeted = {event: {new for _left, new in zip(*lists)} for event, lists in retargets.items()}
    head_stop = _stop_count(
        head_ev, stop_names, body_head, retargeted, base_ev=base_ev, body_base=body_base
    )
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
        # SPEC §5 HOOK_REMOVED (spec 28, AI-assisted ruling on #45): every
        # modeled prompt/agent handler the event held at base is gone.
        if info.get("non_commands") and not head_info.get("non_commands"):
            sev = escalate_stop("HOOK_REMOVED", event, "warn")
            add(
                rule="HOOK_REMOVED",
                severity=sev,
                message=f"hook event {event} non-command handlers removed",
                path=path,
                before="prompt/agent",
                after="",
                locator=f"{event}:handlers",
            )
        # SPEC §5 / §5.1 (spec 28, #45): only what the event held at base can
        # be emptied, so an event that never held a command (or an entry)
        # reads the same on every diff and never empties.
        if head_info["array_len"] == 0 or not head_info["commands"]:
            if info["array_len"] > 0 and head_info["array_len"] == 0:
                sev = escalate_stop("HOOK_BYPASSED", event, "warn")
                add(
                    rule="HOOK_BYPASSED",
                    severity=sev,
                    message=f"hook event {event} array emptied",
                    path=path,
                    locator=event,
                )
            if info["commands"] and not head_info["commands"]:
                sev = escalate_stop("HOOK_REMOVED", event, "warn")
                add(
                    rule="HOOK_REMOVED",
                    severity=sev,
                    message=f"hook event {event} command list emptied",
                    path=path,
                    locator=event,
                )
            continue
        fired = False
        # Spec 37: async commands still execute, but lose refusal capability.
        # Match occurrences by command string; adding a notifier is no bypass.
        base_sync = Counter(c for c, f in info["command_states"] if _active(c, f) and not f.get("async", False))
        head_sync = Counter(c for c, f in head_info["command_states"] if _active(c, f) and not f.get("async", False))
        base_async = Counter(c for c, f in info["command_states"] if _active(c, f) and f.get("async", False))
        head_async = Counter(c for c, f in head_info["command_states"] if _active(c, f) and f.get("async", False))
        if any(head_sync[c] < n and head_async[c] > base_async[c] for c, n in base_sync.items()):
            fired = True
            add(rule="HOOK_BYPASSED", severity=escalate_stop("HOOK_BYPASSED", event, "warn"),
                message=f"hook command for {event} made asynchronous", path=path,
                before="synchronous", after="async:true", locator=f"{event}:async")
        if _command_skip_added(info, head_info):
            fired = True
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
        # SPEC §5.1 (spec 27): commands are compared as multisets of
        # their strings in every branch. A head command the diff added (its
        # string gained occurrences) is compared with a base command that
        # left (its string lost occurrences), so neither an inserted sibling
        # nor a reorder moves a finding, and nothing pairs by list position.
        left = [
            b for b in dict.fromkeys(base_cmds)
            if head_count[b] < base_count[b] and b.strip() and not _is_comment(b)
        ]
        left_by_text = {b.strip(): b for b in reversed(left)}
        # Each occurrence a base string lost pairs once (one to one, as the
        # list index paired); the fallback takes the first unpaired one in
        # base order: not a stub string for the stub-string and comment-out
        # forms, with a non-stub base body for the body form.
        unpaired = Counter({b: base_count[b] - head_count[b] for b in left})
        queues = {
            "plain": [b for b in left if not stub_command(b)],
            "body": [b for b in left if b in body_base and not body_base[b][0]],
        }
        heads = {"plain": 0, "body": 0}
        # A `#` command whose text is a command that left pairs with it
        # before any fallback pairing takes that command.
        reserved: Counter[str] = Counter()
        gained_left = Counter({c: head_count[c] - base_count[c] for c in head_count})
        for cmd in head_cmds:
            if _is_comment(cmd) and gained_left[cmd] > 0:
                gained_left[cmd] -= 1
                was = left_by_text.get(cmd.lstrip().lstrip("#").strip())
                if was is not None and unpaired[was]:
                    unpaired[was] -= 1
                    reserved[cmd] += 1

        def take(kind: str) -> str | None:
            queue = queues[kind]
            while heads[kind] < len(queue) and not unpaired[queue[heads[kind]]]:
                heads[kind] += 1
            if heads[kind] == len(queue):
                return None
            unpaired[queue[heads[kind]]] -= 1
            return queue[heads[kind]]
        body_fired: set[str] = set()
        # Base commands a branch below already paired: a retarget of the same
        # judge is not reported again (one finding per weakening).
        paired_left: set[str] = set()
        # Each head occurrence is read, as before; an added string pairs as
        # many times as it gained occurrences, not once per occurrence.
        added: Counter[str] = Counter()
        for cmd in head_cmds:
            gained = added[cmd] < head_count[cmd] - base_count[cmd]
            if gained:
                added[cmd] += 1
            # §5 GATE_STUBBED, string form: a new stub string replaced a base
            # command that was not one.
            if gained and stub_command(cmd):
                was = take("plain")
                if was is not None:
                    fired = True
                    paired_left.add(was)
                    sev = escalate_stop("GATE_STUBBED", event, "warn")
                    add(
                        rule="GATE_STUBBED",
                        severity=sev,
                        message=f"hook command for {event} replaced with a v0 stub",
                        path=path,
                        before=was,
                        after=cmd,
                        locator=event,
                    )
            # §5 HOOK_BYPASSED: command prefixed with a no-op, its v0 closed
            # form a shell comment. The base command whose text the comment
            # carries pairs first, then the first command that left.
            if gained and _is_comment(cmd):
                if reserved[cmd]:
                    reserved[cmd] -= 1
                    was = left_by_text[cmd.lstrip().lstrip("#").strip()]
                else:
                    was = take("plain")
                if was is not None:
                    fired = True
                    paired_left.add(was)
                    sev = escalate_stop("HOOK_BYPASSED", event, "warn")
                    add(
                        rule="HOOK_BYPASSED",
                        severity=sev,
                        message=f"hook command for {event} commented out",
                        path=path,
                        before=was,
                        after=cmd,
                        locator=event,
                    )
            # §5 GATE_STUBBED, body form: the command resolves (§3.3) to stub
            # bodies while the base command resolved to a non-stub body; the
            # same string pairs first, then (for an added command) the first
            # command that left with a non-stub body.
            stubbed = None
            if cmd in body_head and body_head[cmd][0]:
                if base_count[cmd] and cmd in body_base and not body_base[cmd][0]:
                    stubbed = cmd
                elif gained:
                    stubbed = take("body")
            if stubbed is not None:
                fired = True
                body_fired.add(cmd)
                paired_left.add(stubbed)
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
            elif cmd in body_head and body_head[cmd][1]:
                # §5.2 (spec 7): shape-preserving gut job, compared per target
                # path (§3.3), so no command pairing is needed.
                fired = True
                body_fired.add(cmd)
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
        # §5 GATE_STUBBED, retarget (spec 27, R12): a Stop-like judge
        # whose base body holds a decision literal left, and a command new to
        # the event resolves only to bodies that cannot refuse.
        # A judge another branch paired is not reported again, and a new
        # command such a branch read is not paired with another judge: the
        # remaining ones pair one to one (one finding per weakening).
        r_left, r_new = retargets.get(event, ([], []))
        for was, new in zip(
            [w for w in r_left if w not in paired_left], [n for n in r_new if n not in body_fired]
        ):
            fired = True
            sev = escalate_stop("GATE_STUBBED", event, "warn")
            add(
                rule="GATE_STUBBED",
                severity=sev,
                message=f"hook command for {event} retargeted to a body that cannot refuse",
                path=path,
                before=was,
                after=new,
                locator=f"{event}:{new}",
            )
        # §5 HOOK_REMOVED (spec 27): the event keeps commands but none
        # is live (§5.2) after a command live at base left it, and no other
        # finding above explains the event.
        if not fired:
            gone = [
                c for c, f in info["command_states"]
                if head_count[c] == 0 and _live(c, f, body_base, set())
            ]
            if gone and not any(
                _live(c, f, body_head, retargeted.get(event, set()))
                for c, f in head_info["command_states"]
            ):
                sev = escalate_stop("HOOK_REMOVED", event, "warn")
                add(
                    rule="HOOK_REMOVED",
                    severity=sev,
                    message=f"hook event {event} keeps no live command",
                    path=path,
                    before=gone[0],
                    after="",
                    locator=event,
                )
    # SPEC §3.3 / §1.6 (spec 13, R12): the §6.1 count credits a command
    # §3.3 does not resolve as live, although no body was read for it.
    # Report when a Stop-like finding was kept below critical only because
    # of such a command, or when the diff left the file's Stop liveness
    # (§5.2) resting only on such commands. Visibility only (§7).
    if note_unknown is not None:
        kept_unread = kept_below_critical and _stop_count(
            head_ev, stop_names, body_head, retargeted, resolved_only=True,
            base_ev=base_ev, body_base=body_base,
        ) == 0
        moved = (
            _stop_count(head_ev, stop_names, body_head, retargeted) >= 1
            and _stop_count(head_ev, stop_names, body_head, retargeted, resolved_only=True) == 0
            and _stop_count(base_ev, stop_names, body_base, {}, resolved_only=True) >= 1
        )
        if kept_unread or moved:
            note_unknown(HOOK_LIVENESS_UNRESOLVED)
