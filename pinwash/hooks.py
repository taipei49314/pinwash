"""Extract hook commands from Claude / Cursor JSON (v0)."""

from __future__ import annotations

from typing import Any

CLAUDE_STOP_EVENTS = frozenset({"Stop"})
CURSOR_STOP_EVENTS = frozenset({"stop", "Stop", "finish", "afterAgentResponse"})


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
