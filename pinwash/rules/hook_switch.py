"""HOOK_BYPASSED for the settings-root `disableAllHooks` switch (SPEC §5.1, spec 24).

Claude Code (2.1.42 and 2.1.296, executed) takes the value in effect from the
last settings source that defines it: user, then `.claude/settings.json`,
then `.claude/settings.local.json`, then a `--settings` file, then managed
settings. A JSON `true` in effect runs no hook from the user, project, local
or `--settings` sources, Stop hooks included. A value that is not a JSON
boolean makes the host reject that whole settings file (R24), so that file
defines no value. pinwash reads the two repository files two ways: the
value in effect (local over project), and the shared file alone.
"""

from __future__ import annotations

from typing import Any

from pinwash.hooks import CLAUDE_STOP_EVENTS, extract_event_hooks, stub_command

SWITCH = "disableAllHooks"
MESSAGE = "settings root disableAllHooks switches off every hook"
SHARED = ".claude/settings.json"
LOCAL = ".claude/settings.local.json"


def file_switch(doc: Any) -> bool | None:
    """The file's own boolean, or None: no such key, a file the host does
    not load (missing, unparseable, a root that is not an object), or a
    value that is not a JSON boolean (the host rejects the whole file)."""
    if not isinstance(doc, dict) or SWITCH not in doc:
        return None
    value = doc[SWITCH]
    return value if isinstance(value, bool) else None


def in_effect(docs: dict[str, Any]) -> tuple[bool | None, str | None]:
    """(value in effect, SHARED or LOCAL: the file that supplies it)."""
    for key in (LOCAL, SHARED):
        value = file_switch(docs.get(key))
        if value is not None:
            return value, key
    return None, None


def flipped_in_effect(files: dict[str, tuple[str, Any, Any]]) -> str | None:
    """The path of the file that supplies a head `true` in effect (reading
    (i)) when the base value in effect was not `true`, else None. The
    engine reports the row there when no switch finding fired (spec 24): a
    `false` removed from the local file under an unchanged shared `true`
    changes no file's own value to a switch, yet switches hooks off."""
    base_val, _ = in_effect({k: f[1] for k, f in files.items()})
    head_val, head_key = in_effect({k: f[2] for k, f in files.items()})
    if head_val is True and base_val is not True and head_key is not None:
        return files[head_key][0]
    return None


def _active(command: str, flags: dict[str, bool]) -> bool:
    """SPEC §3.3: no §5.1 skip flag, not a §5.2 stub string, no leading `#`."""
    if any(flags.values()) or stub_command(command):
        return False
    return not command.lstrip().startswith("#")


def detect(
    files: dict[str, tuple[str, Any, Any]],
    body_base: dict[str, tuple[bool, bool, str]],
    live_stop_events: Any,
    add: Any,
) -> str | None:
    """`files` maps SHARED / LOCAL to (path, base doc, head doc), a doc being
    None where the host does not load that side. Emits the finding on the
    file that supplies the head's value and returns its path, or None."""
    base_val, _ = in_effect({k: f[1] for k, f in files.items()})
    head_val, head_key = in_effect({k: f[2] for k, f in files.items()})
    if head_val is not True or base_val is True or head_key is None:
        # Reading (ii): the shared file alone, as a host reads it when it
        # loads project settings without the local file (`--setting-sources
        # project`) or rejects the local file (R24), both executed. A local
        # `false` keeps a shared `true` out of effect only while the host
        # loads that local file.
        shared = files.get(SHARED)
        if shared is None:
            return None
        p_base, p_head = file_switch(shared[1]), file_switch(shared[2])
        if p_head is not True or p_base is True:
            return None
        base_val, head_key = p_base, SHARED
    active = False
    live_stop = False
    for key in sorted(files):
        b_doc = files[key][1]
        if not isinstance(b_doc, dict):
            continue
        events = extract_event_hooks(b_doc)
        active = active or any(
            _active(command, flags)
            for info in events.values()
            for command, flags in info["command_states"]
        )
        live_stop = live_stop or live_stop_events(events, CLAUDE_STOP_EVENTS, body_base) >= 1
    if not active:
        return None
    path = files[head_key][0]
    add(
        rule="HOOK_BYPASSED",
        severity="critical" if live_stop else "warn",
        message=MESSAGE,
        path=path,
        before="false" if base_val is False else "",
        after="true",
        locator=SWITCH,
    )
    return path
