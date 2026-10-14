"""Bounded global hook environment visibility; never execute a subject."""
from __future__ import annotations
import re
from typing import Any
from pinwash.hooks import CLAUDE_STOP_EVENTS, extract_event_hooks, stub_command
from pinwash.rules.hook_rules import live_stop_events
from pinwash.textutil import canonical_text

GLOBAL_ENV = "hook global environment changed (not evaluated)"
BASH_SOURCE = "hook BASH_ENV source changed (not evaluated)"
KEYS = ("CLAUDE_CODE_SHELL_PREFIX", "BASH_ENV", "PATH")
_MISSING = object()

def handlers(doc: Any):
    hooks = doc.get("hooks") if isinstance(doc, dict) else None
    if not isinstance(hooks, dict):
        return
    for event, groups in hooks.items():
        if not isinstance(event, str) or not isinstance(groups, list):
            continue
        for group in groups:
            items = group.get("hooks") if isinstance(group, dict) else None
            for item in items if isinstance(items, list) else []:
                if isinstance(item, dict):
                    yield event, item

def environment(doc: Any) -> dict[str, Any]:
    value = doc.get("env") if isinstance(doc, dict) else None
    return value if isinstance(value, dict) else {}

def bash_events(doc: Any):
    events = extract_event_hooks(doc, claude=True)
    admitted: dict[str, list[tuple[str, dict[str, bool]]]] = {}
    retained: dict[str, list[tuple[str, dict[str, bool]]]] = {}
    for event, item in handlers(doc):
        c = item.get("command")
        if item.get("type", "command") != "command" or not isinstance(c, str):
            continue
        flags = {"async": event == "Stop" and item.get("async") is True}
        is_bash = "args" not in item and item.get("shell", "bash") == "bash" and not flags["async"]
        bucket = admitted if is_bash else retained
        bucket.setdefault(event, []).append((c, flags))
    selected, remaining = {}, {}
    for event, info in events.items():
        selected[event] = {**info, "non_commands": [], "command_states": admitted.get(event, [])}
        remaining[event] = {**info, "command_states": retained.get(event, [])}
    return selected, remaining

def source_path(value: Any) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.(?:sh|bash)", value):
        return None
    if any(part in (".", "..") for part in value.split("/")):
        return None
    return value

def exits_zero(value: Any, files: dict[str, bytes]) -> bool:
    path = source_path(value)
    if path is None or path not in files:
        return False
    try:
        text = files[path].decode("utf-8", "strict").replace("\r\n", "\n")
    except UnicodeError:
        return False
    lines = []
    for raw in text.split("\n"):
        line = raw.strip(" \t")
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return "exit 0" in lines and all(line in ("true", ":", "exit 0") for line in lines)

def detect(files, base_files, head_files, body_base, add, note_unknown):
    # Rows include cross-file hooks; findings use one unambiguous own-file
    # source only until environment merge precedence has executable evidence.
    activity = any(any(info["commands"] or info.get("non_commands") for info in extract_event_hooks(doc, claude=True).values())
                   for _path, b, h in files.values() for doc in (b, h))
    if not activity:
        return
    for key in sorted(files):
        path, bdoc, hdoc = files[key]
        b, h = environment(bdoc), environment(hdoc)
        for env_key in KEYS:
            bv, hv = b.get(env_key, _MISSING), h.get(env_key, _MISSING)
            changed = ((bv is _MISSING) != (hv is _MISSING) or
                       (bv is not _MISSING and hv is not _MISSING and canonical_text(bv) != canonical_text(hv)))
            if changed:
                note_unknown(path, GLOBAL_ENV)
            if env_key == "BASH_ENV":
                named = {p for p in (source_path(bv), source_path(hv)) if p is not None}
                if any(base_files.get(p, b"").replace(b"\r\n", b"\n") != head_files.get(p, b"").replace(b"\r\n", b"\n") for p in named):
                    note_unknown(path, BASH_SOURCE)
            # The other repo settings file can shadow this key; no invented
            # priority or cross-file execution assumption is made.
            if any(env_key in environment(doc) for other, (_p, bd, hd) in files.items() if other != key for doc in (bd, hd)):
                continue
            selected, remaining = bash_events(bdoc)
            active = any(not stub_command(c) and not c.lstrip().startswith("#")
                         for info in selected.values() for c, _f in info["command_states"])
            if not active:
                continue
            bypass = (env_key == "CLAUDE_CODE_SHELL_PREFIX" and hv == "true" and (bv is _MISSING or bv == ""))
            bypass = bypass or (env_key == "BASH_ENV" and exits_zero(hv, head_files) and not exits_zero(bv, base_files))
            if not bypass:
                continue
            critical = live_stop_events(selected, CLAUDE_STOP_EVENTS, body_base) > 0 and live_stop_events(remaining, CLAUDE_STOP_EVENTS, body_base) == 0
            add(rule="HOOK_BYPASSED", severity="critical" if critical else "warn",
                message=f"settings root env {env_key} disables bash-run hooks in a closed form",
                path=path, before="" if bv is _MISSING else canonical_text(bv),
                after=canonical_text(hv), locator=f"env.{env_key}")
