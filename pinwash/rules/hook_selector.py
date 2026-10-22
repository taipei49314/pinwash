"""Hook selector changes with the command kept (SPEC §5.1, R13; #12).

Visibility only (SPEC §7): this module never emits a finding. It reports the
`unknown_coverage` reason "hook selector changed (not evaluated)" for a hook
surface file when a command live on both sides of an event changed its
selector:

* its entry's `matcher` value, unless both values are closed name lists
  (names joined by `|`, each of ASCII letters, digits, `_` and `-`) and the
  head names include every base name, or the head matcher matches everything
  (absent, `""` or `*`, one value here; INFERRED from host docs). That exemption reads `|` as alternation,
  where adding a name can only add matches; that reading is INFERRED host
  semantics (under exact-string matching, `Bash` -> `Bash|PowerShell`
  would narrow), kept because it removes most of the rows honest edits
  would otherwise get;
* its per-hook `if`, gained or changed (dropping one only widens when the
  hook runs, so it is no row);
* its handler `type` (an absent `type` reads as `command`; in the list form,
  a `type` that names the hook's event is that event, not a handler type);
* a `matcher` key below its entry (handler or nested group), gained, lost or
  changed.

"Live" is unflagged (§5.1; on cursor_hooks only since spec 29, #42), not a
§5.2 stub string and not commented out.
A command is the same on both sides when its string is the same (each such
string is judged on its own, so one command's narrowing cannot hide behind a
sibling's widening of the same script), else when it resolves (§3.3) to the
same target set on each side. A command whose string and targets both change
in the same edit is R12, not this row.

pinwash does not evaluate which tools or events a selector governs on a
host; that is host semantics (INFERRED), so no change here is a finding.
Selector values are compared through textutil.canonical_text: no recursion
on subject values, object key order is no change (§8, §9).
"""

from __future__ import annotations

from typing import Any

from pinwash.hooks import is_claude_command_handler, stub_command
from pinwash.parse.hookcmd import hook_command_targets
from pinwash.textutil import canonical_text

REASON = "hook selector changed (not evaluated)"
_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
# Absent, "" and "*" all match every tool or agent name (host docs; INFERRED).
_MATCH_ALL = "<all>"
_ABSENT = "<absent>"
_COMMAND_TYPE = canonical_text("command")


def _flagged(obj: dict[str, Any]) -> bool:
    return (
        obj.get("disabled") is True
        or obj.get("hookEnabled") is False
        or obj.get("continueOnError") is True
        or obj.get("failOpen") is True
    )


def _names(raw: Any) -> frozenset[str] | None:
    """A closed name list, or None."""
    if not isinstance(raw, str) or not raw:
        return None
    names = raw.split("|")
    for name in names:
        if not name or any(ch not in _NAME_CHARS for ch in name):
            return None
    return frozenset(names)


def _entry_commands(entry: dict[str, Any], event: str | None, *, claude: bool = False) -> list[dict[str, Any]]:
    """Commands under one entry, depth-first on an explicit stack (§9).

    `event` is the event name when the entry comes from the list form, where
    a `type` equal to it names the event rather than a handler type.
    """
    out: list[dict[str, Any]] = []
    if claude:
        items = entry.get("hooks")
        for node in items if isinstance(items, list) else []:
            if not is_claude_command_handler(node):
                continue
            out.append({"command": node["command"], "flagged": False,
                        "if": canonical_text(node["if"]) if "if" in node else _ABSENT,
                        "type": _COMMAND_TYPE,
                        "nested": canonical_text(node["matcher"]) if "matcher" in node else ""})
        return out
    nested: list[str] = []
    stack: list[tuple[dict[str, Any], bool, bool]] = [(entry, _flagged(entry), True)]
    while stack:
        node, flagged, is_entry = stack.pop()
        if not is_entry and "matcher" in node:
            nested.append(canonical_text(node["matcher"]))
        items = node.get("hooks")
        if isinstance(items, list):
            for item in reversed(items):
                if isinstance(item, dict):
                    stack.append((item, flagged or _flagged(item), False))
        if isinstance(node.get("command"), str):
            if "type" not in node or (event is not None and node["type"] == event):
                handler_type = _COMMAND_TYPE
            else:
                handler_type = canonical_text(node["type"])
            out.append(
                {
                    "command": node["command"],
                    "flagged": flagged,
                    "if": canonical_text(node["if"]) if "if" in node else _ABSENT,
                    "type": handler_type,
                }
            )
    # One string (canonical texts are self-delimiting), so comparing records
    # hashes it once, however many commands share it.
    nested_key = "".join(sorted(nested))
    for rec in out:
        rec["nested"] = nested_key
    return out


def _events(doc: Any, *, claude: bool = False) -> dict[str, list[dict[str, Any]]]:
    """event -> command records, for the dict and list forms hooks.py reads."""
    if not isinstance(doc, dict):
        return {}
    hooks = doc.get("hooks")
    grouped: dict[str, list[dict[str, Any]]] = {}
    list_form = False
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            if isinstance(event, str) and isinstance(entries, list):
                grouped[event] = [e for e in entries if isinstance(e, dict)]
    elif isinstance(hooks, list) and not claude:
        list_form = True
        for entry in hooks:
            if not isinstance(entry, dict):
                continue
            event = entry.get("event") or entry.get("type") or "unknown"
            if isinstance(event, str):
                grouped.setdefault(event, []).append(entry)
    out: dict[str, list[dict[str, Any]]] = {}
    for event, entries in grouped.items():
        recs: list[dict[str, Any]] = []
        for entry in entries:
            raw = entry["matcher"] if "matcher" in entry else None
            if raw is None or raw in ("", "*"):
                raw_key = _MATCH_ALL
            else:
                raw_key = canonical_text(raw)
            for rec in _entry_commands(entry, event if list_form else None, claude=claude):
                rec["matcher"] = raw_key
                rec["names"] = None if raw_key == _MATCH_ALL else _names(raw)
                recs.append(rec)
        out[event] = recs
    return out


def _live(rec: dict[str, Any]) -> bool:
    cmd = rec["command"]
    return not rec["flagged"] and not stub_command(cmd) and not cmd.lstrip().startswith("#")


def _key(command: str, files: dict[str, bytes], resolve: Any = None) -> tuple[str, ...]:
    targets = resolve(command) if resolve is not None else hook_command_targets(command, files)
    return ("targets",) + tuple(sorted(set(targets))) if targets else ("command", command)


def _by_key(
    recs: list[dict[str, Any]], files: dict[str, bytes], resolve: Any = None
) -> dict[tuple[str, ...], list[dict[str, Any]]]:
    out: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for rec in recs:
        if _live(rec):
            out.setdefault(_key(rec["command"], files, resolve), []).append(rec)
    return out


def _matcher_changed(base: list[dict[str, Any]], head: list[dict[str, Any]]) -> bool:
    b_raw = {r["matcher"] for r in base}
    h_raw = {r["matcher"] for r in head}
    if b_raw == h_raw or h_raw == {_MATCH_ALL}:
        return False
    if _MATCH_ALL in b_raw:
        return True
    b_names = [r["names"] for r in base]
    h_names = [r["names"] for r in head]
    if all(n is not None for n in b_names) and all(n is not None for n in h_names):
        b_union = frozenset().union(*b_names)
        h_union = frozenset().union(*h_names)
        if b_union <= h_union:
            return False
    return True


def _fields_changed(base: list[dict[str, Any]], head: list[dict[str, Any]]) -> bool:
    if _matcher_changed(base, head):
        return True
    # A per-hook `if` that is dropped only widens when the hook runs: a head
    # `if` value the base does not hold is a change, removing one is not.
    if {r["if"] for r in head} - {r["if"] for r in base} - {_ABSENT}:
        return True
    return any({r[f] for r in base} != {r[f] for r in head} for f in ("type", "nested"))


def selector_changed(
    base_doc: Any,
    head_doc: Any,
    base_files: dict[str, bytes],
    head_files: dict[str, bytes],
    targets: Any = (None, None),
    *,
    claude: bool = False,
) -> bool:
    """Pair active commands by string first, so each string's selector is
    judged on its own (a narrowing of one command cannot hide behind a
    sibling's widening when both run the same script); commands whose
    string changed pair by their §3.3 target set. With `claude` (a
    claude_settings file) no command is flagged (§5.1, spec 29, #42)."""
    base_ev = _events(base_doc, claude=claude)
    head_ev = _events(head_doc, claude=claude)
    if claude:
        for events in (base_ev, head_ev):
            for recs in events.values():
                for rec in recs:
                    rec["flagged"] = False
    for event in sorted(set(base_ev) & set(head_ev)):
        b_s: dict[str, list[dict[str, Any]]] = {}
        h_s: dict[str, list[dict[str, Any]]] = {}
        for rec in base_ev[event]:
            if _live(rec):
                b_s.setdefault(rec["command"], []).append(rec)
        for rec in head_ev[event]:
            if _live(rec):
                h_s.setdefault(rec["command"], []).append(rec)
        common = set(b_s) & set(h_s)
        for cmd in sorted(common):
            if _fields_changed(b_s[cmd], h_s[cmd]):
                return True
        b_rest = [r for c in sorted(set(b_s) - common) for r in b_s[c]]
        h_rest = [r for c in sorted(set(h_s) - common) for r in h_s[c]]
        b_key = _by_key(b_rest, base_files, targets[0])
        h_key = _by_key(h_rest, head_files, targets[1])
        for k in sorted(set(b_key) & set(h_key)):
            if _fields_changed(b_key[k], h_key[k]):
                return True
    return False


def detect(
    path: str,
    base_doc: Any,
    head_doc: Any,
    base_files: dict[str, bytes],
    head_files: dict[str, bytes],
    note_unknown: Any,
    targets: Any = (None, None),
    claude: bool = False,
) -> None:
    if selector_changed(base_doc, head_doc, base_files, head_files, targets, claude=claude):
        note_unknown(REASON)
