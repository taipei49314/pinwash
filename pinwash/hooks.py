"""Extract hook commands from Claude / Cursor JSON (v0)."""

from __future__ import annotations

from typing import Any

CLAUDE_STOP_EVENTS = frozenset({"Stop"})
CURSOR_STOP_EVENTS = frozenset({"stop", "Stop", "finish", "afterAgentResponse"})


def _as_dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _commands_from_hook_object(obj: dict[str, Any]) -> list[str]:
    found: list[str] = []
    inner = obj.get("hooks")
    if isinstance(inner, list):
        for item in inner:
            if isinstance(item, dict) and isinstance(item.get("command"), str):
                found.append(item["command"])
            elif isinstance(item, dict):
                found.extend(_commands_from_hook_object(item))
    if isinstance(obj.get("command"), str):
        found.append(obj["command"])
    return found


def _direct_flags_from_obj(obj: dict[str, Any]) -> dict[str, bool]:
    return {
        "disabled": obj.get("disabled") is True,
        "hookEnabled_false": obj.get("hookEnabled") is False,
        "continueOnError": obj.get("continueOnError") is True,
        "failOpen": obj.get("failOpen") is True,
    }


def _command_states_from_hook_object(
    obj: dict[str, Any], inherited: dict[str, bool] | None = None,
) -> list[tuple[str, dict[str, bool]]]:
    """Keep command-local skip state for the SPEC §6.1 live-Stop count.

    A matcher object's skip applies to its children; a skipped child must
    not make its still-active siblings non-live. Command ordering matches
    _commands_from_hook_object, including its bounded nested shape.
    """
    flags = _direct_flags_from_obj(obj)
    if inherited is not None:
        flags = {key: val or inherited[key] for key, val in flags.items()}
    found: list[tuple[str, dict[str, bool]]] = []
    inner = obj.get("hooks")
    if isinstance(inner, list):
        for item in inner:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("command"), str):
                child_flags = _direct_flags_from_obj(item)
                effective = {
                    key: val or flags[key] for key, val in child_flags.items()
                }
                found.append((item["command"], effective))
            else:
                found.extend(_command_states_from_hook_object(item, flags))
    if isinstance(obj.get("command"), str):
        found.append((obj["command"], flags))
    return found


def _flags_from_obj(obj: dict[str, Any]) -> dict[str, bool]:
    flags = _direct_flags_from_obj(obj)
    inner = obj.get("hooks")
    if isinstance(inner, list):
        for item in inner:
            if isinstance(item, dict):
                child = _flags_from_obj(item)
                for key, val in child.items():
                    flags[key] = flags[key] or val
    return flags


def extract_event_hooks(doc: Any) -> dict[str, dict[str, Any]]:
    """Map event name -> commands, command states, matchers, flags, array_len."""
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
            flags = {
                "disabled": False,
                "hookEnabled_false": False,
                "continueOnError": False,
                "failOpen": False,
            }
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                if isinstance(entry.get("matcher"), str):
                    matchers.append(entry["matcher"])
                commands.extend(_commands_from_hook_object(entry))
                command_states.extend(_command_states_from_hook_object(entry))
                child = _flags_from_obj(entry)
                for key, val in child.items():
                    flags[key] = flags[key] or val
            out[event] = {
                "array_len": len(entries),
                "commands": commands,
                "command_states": command_states,
                "flags": flags,
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
            flags = {
                "disabled": False,
                "hookEnabled_false": False,
                "continueOnError": False,
                "failOpen": False,
            }
            for entry in entries:
                if isinstance(entry.get("matcher"), str):
                    matchers.append(entry["matcher"])
                commands.extend(_commands_from_hook_object(entry))
                command_states.extend(_command_states_from_hook_object(entry))
                child = _flags_from_obj(entry)
                for key, val in child.items():
                    flags[key] = flags[key] or val
            out[event] = {
                "array_len": len(entries),
                "commands": commands,
                "command_states": command_states,
                "flags": flags,
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
