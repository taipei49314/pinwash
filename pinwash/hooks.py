"""Extract hook commands from Claude / Cursor JSON (v0)."""

from __future__ import annotations

from typing import Any

CLAUDE_STOP_EVENTS = frozenset({"Stop"})
# SPEC §6.1 (spec 13, #26 item 6): the Stop-like set is closed and
# case-sensitive per surface. On cursor_hooks it is `stop`, the event that
# runs when the agent loop ends and can submit a follow-up message;
# observe-only events (`afterAgentResponse`, `afterAgentThought`), the
# subagent's `subagentStop`, and `finish` / `Stop` (no Cursor event) never
# keep the escalator off.
CURSOR_STOP_EVENTS = frozenset({"stop"})


def _as_dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _hook_items(obj: dict[str, Any]) -> list[Any]:
    inner = obj.get("hooks")
    return inner if isinstance(inner, list) else []


def _commands_from_hook_object(obj: dict[str, Any]) -> list[str]:
    """Commands under a hook object: each item's command, or the commands of
    an item without one (its nested "hooks"), then the object's own command.

    A depth-first walk on an explicit stack, not recursion, so a subject
    document nested at any depth reads the same on every interpreter
    (SPEC §8 / §9). Order matches the recursive form this replaces.
    """
    found: list[str] = []
    # One frame per object whose nested items are being read: [obj, next item].
    stack: list[list[Any]] = [[obj, 0]]
    while stack:
        frame = stack[-1]
        node, items = frame[0], _hook_items(frame[0])
        if frame[1] < len(items):
            item = items[frame[1]]
            frame[1] += 1
            if isinstance(item, dict) and isinstance(item.get("command"), str):
                found.append(item["command"])
            elif isinstance(item, dict):
                stack.append([item, 0])
            continue
        stack.pop()
        if isinstance(node.get("command"), str):
            found.append(node["command"])
    return found


def _direct_flags_from_obj(obj: dict[str, Any]) -> dict[str, bool]:
    return {
        "disabled": obj.get("disabled") is True,
        "hookEnabled_false": obj.get("hookEnabled") is False,
        "continueOnError": obj.get("continueOnError") is True,
        "failOpen": obj.get("failOpen") is True,
    }


def _merged_flags(
    obj: dict[str, Any], inherited: dict[str, bool] | None
) -> dict[str, bool]:
    flags = _direct_flags_from_obj(obj)
    if inherited is None:
        return flags
    return {key: val or inherited[key] for key, val in flags.items()}


def _command_states_from_hook_object(
    obj: dict[str, Any], inherited: dict[str, bool] | None = None,
) -> list[tuple[str, dict[str, bool]]]:
    """Keep command-local skip state for the SPEC §6.1 live-Stop count.

    A matcher object's skip applies to its children; a skipped child must
    not make its still-active siblings non-live. Command ordering matches
    _commands_from_hook_object, and so does the explicit-stack walk.
    """
    found: list[tuple[str, dict[str, bool]]] = []
    # [obj, its effective flags, next item]
    stack: list[list[Any]] = [[obj, _merged_flags(obj, inherited), 0]]
    while stack:
        frame = stack[-1]
        node, flags, items = frame[0], frame[1], _hook_items(frame[0])
        if frame[2] < len(items):
            item = items[frame[2]]
            frame[2] += 1
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("command"), str):
                found.append((item["command"], _merged_flags(item, flags)))
            else:
                stack.append([item, _merged_flags(item, flags), 0])
            continue
        stack.pop()
        if isinstance(node.get("command"), str):
            found.append((node["command"], flags))
    return found


def extract_event_hooks(doc: Any) -> dict[str, dict[str, Any]]:
    """Map event name -> commands, command states, matchers, array_len.

    Skip flags live only in the command-local states (SPEC §5.1, spec 10);
    there is no per-event aggregate.
    """
    root = _as_dict(doc)
    if root is None:
        return {}
    hooks = root.get("hooks")
    out: dict[str, dict[str, Any]] = {}
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            if not isinstance(event, str):
                continue
            if not isinstance(entries, list):
                continue
            commands: list[str] = []
            command_states: list[tuple[str, dict[str, bool]]] = []
            matchers: list[str] = []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                if isinstance(entry.get("matcher"), str):
                    matchers.append(entry["matcher"])
                commands.extend(_commands_from_hook_object(entry))
                command_states.extend(_command_states_from_hook_object(entry))
            out[event] = {
                "array_len": len(entries),
                "commands": commands,
                "command_states": command_states,
                "matchers": matchers,
            }
        return out
    if isinstance(hooks, list):
        grouped: dict[str, list[dict[str, Any]]] = {}
        for entry in hooks:
            if not isinstance(entry, dict):
                continue
            event = entry.get("event") or entry.get("type") or "unknown"
            if not isinstance(event, str):
                continue
            grouped.setdefault(event, []).append(entry)
        for event, entries in grouped.items():
            commands: list[str] = []
            command_states: list[tuple[str, dict[str, bool]]] = []
            matchers: list[str] = []
            for entry in entries:
                if isinstance(entry.get("matcher"), str):
                    matchers.append(entry["matcher"])
                commands.extend(_commands_from_hook_object(entry))
                command_states.extend(_command_states_from_hook_object(entry))
            out[event] = {
                "array_len": len(entries),
                "commands": commands,
                "command_states": command_states,
                "matchers": matchers,
            }
    return out


def _command_objects(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """The objects whose `command` _commands_from_hook_object reads, in the
    same walk: each item that holds a string command, the items of an item
    that holds none, then the object itself."""
    found: list[dict[str, Any]] = []
    stack: list[list[Any]] = [[obj, 0]]
    while stack:
        frame = stack[-1]
        node, items = frame[0], _hook_items(frame[0])
        if frame[1] < len(items):
            item = items[frame[1]]
            frame[1] += 1
            if isinstance(item, dict) and isinstance(item.get("command"), str):
                found.append(item)
            elif isinstance(item, dict):
                stack.append([item, 0])
            continue
        stack.pop()
        if isinstance(node.get("command"), str):
            found.append(node)
    return found


def command_holders(doc: Any) -> tuple[set[str], set[str]]:
    """(command strings some hook object holds with an `args` key (Claude
    Code 2.1.296's exec form) or a `shell` key whose value is not the string
    "bash"; command strings some hook object holds with neither). §3.3
    (spec 26): the project-root forms are not read for a string that only
    the first kind of object holds, so an added object cannot turn them off
    for a string another object runs through the shell. The objects are
    exactly those §5.1 reads a `command` from (extract_event_hooks), which
    are the ones the host runs (review of 2026-10-10)."""
    guarded: set[str] = set()
    plain: set[str] = set()
    root = _as_dict(doc)
    if root is None:
        return guarded, plain
    hooks = root.get("hooks")
    entries: list[dict[str, Any]] = []
    if isinstance(hooks, dict):
        for event, lst in hooks.items():
            if isinstance(event, str) and isinstance(lst, list):
                entries.extend(e for e in lst if isinstance(e, dict))
    elif isinstance(hooks, list):
        for e in hooks:
            if isinstance(e, dict) and isinstance(e.get("event") or e.get("type") or "unknown", str):
                entries.append(e)
    for entry in entries:
        for node in _command_objects(entry):
            if "args" in node or ("shell" in node and node["shell"] != "bash"):
                guarded.add(node["command"])
            else:
                plain.add(node["command"])
    return guarded, plain


STUB_COMMANDS = frozenset(
    {
        "true",
        ":",
        "exit 0",
        "exit 0;",
        "echo {}",
        'echo "{}"',
        "python -c \"print('{}')\"",
        'python -c "print(\\"{}\\")"',
        "cmd /c exit 0",
        "",
    }
)


def stub_command(command: str) -> bool:
    return command.strip() in STUB_COMMANDS


def stop_events_present(events: dict[str, dict[str, Any]], names: frozenset[str]) -> int:
    count = 0
    for name in names:
        info = events.get(name)
        if not info:
            continue
        if info["commands"] and not all(stub_command(c) for c in info["commands"]):
            count += 1
        elif info["commands"]:
            continue
        elif info["array_len"] > 0:
            count += 1
    return count
