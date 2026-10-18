"""Hook-side unknown coverage rows for inputs a diff touched (SPEC §3.3, §5.1).

Visibility only (SPEC §7): nothing here emits a finding or changes a
verdict. Each function answers whether one closed `unknown_coverage` reason
applies to a hook surface file; the engine reports each (path, reason) once.

* "hook command target no longer resolved" (§3.3, R07, #18): in an event
  present on both sides, an active command that resolved at base is active
  at head with the same string and resolves to nothing there; or an active
  command that resolved at base left the event while a command active at
  head and not active in the base event (new, or flagged or commented out
  at base) resolves to nothing at head.
* "hook command names a changed file it does not resolve" (§3.3, R07, #18):
  an active command, on either side, names a path whose bytes the diff
  changed (added, edited or deleted; compared after CRLF->LF, a lone CR
  kept) and that is
  not one of that command's own §3.3 targets on that side.
* "hook skip flag value not boolean" (§5.1, R06, #18): an (event, command,
  key, value) occurrence of a §5.1 flag key whose value is not a JSON
  boolean, counted as a multiset, is more frequent at head than at base; or
  a §5 hook finding fired in the file while either side holds one.
* "hook settings root disableAllHooks" (§5.1, R06, #18; claude_settings):
  the root `disableAllHooks` value at head differs from base and is neither
  absent nor the JSON `false`, unless it is the JSON `true` in a file that
  carries the spec 24 `HOOK_BYPASSED` finding for it; or a root
  `__proto__` object's `disableAllHooks` is present at head and differs
  from base (spec 24: Claude Code 2.1.42 reads it, R24); or a §5 hook
  finding other than the switch finding fired in the file while a switch
  value (neither absent nor `false`, or a JS-truthy `__proto__` value) is
  held by either settings file on either side (spec 24). The engine also
  reports it on the file that supplies a head `true` in effect when no
  switch finding fired (spec 24).
* "hook command environment changed" (§3.3, R07, #18; claude_settings): a
  root `env` key the diff adds, changes or removes is expanded (`$K`,
  `${K...`) by an active hook command of the same file on either side.
* "non-command hook handler changed (not evaluated)" (§5.1, R13, #45;
  claude_settings, spec 28): a modeled prompt/agent handler the event held
  at base is gone or changed at head while the event keeps another.

"Active" means no §5.1 skip flag (own or inherited), not a §5.2 stub string
and not starting with `#`: flagged, stub and commented-out commands are
judged by findings and run nothing pinwash would need to read.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from pinwash.hooks import stub_command
from pinwash.parse.hookcmd import hook_command_targets
from pinwash.textutil import canonical_text

TARGET_NO_LONGER_RESOLVED = "hook command target no longer resolved"
NAMES_CHANGED_FILE = "hook command names a changed file it does not resolve"
FLAG_NOT_BOOLEAN = "hook skip flag value not boolean"
DISABLE_ALL_HOOKS = "hook settings root disableAllHooks"
ENV_CHANGED = "hook command environment changed"
HANDLER_CHANGED = "non-command hook handler changed (not evaluated)"

FLAG_KEYS = ("disabled", "hookEnabled", "continueOnError", "failOpen")
_FALSE = canonical_text(False)
_TRUE = canonical_text(True)

# Closed boundary sets: a changed repo path counts as named by a command
# only where it stands as a whole token or as the tail of a longer path.
_REF_LEFT = frozenset(" \t\n\r\"'/=;&|(`")
_REF_RIGHT = frozenset(" \t\n\r\"';&|)<>`")
_IDENT_START = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_")
_IDENT_REST = _IDENT_START | frozenset("0123456789")


def _active(command: str, flags: dict[str, bool]) -> bool:
    if any(flags.values()) or stub_command(command):
        return False
    return not command.lstrip().startswith("#")


def no_longer_resolved(
    base_ev: dict[str, dict[str, Any]],
    head_ev: dict[str, dict[str, Any]],
    base_files: dict[str, bytes],
    head_files: dict[str, bytes],
    targets: Any = (None, None),
) -> bool:
    """A diff moved a resolved hook command out of §3.3's sight.

    No row for a command dropped with no replacement, for a replacement
    that resolves, or for a removed event (HOOK_REMOVED's case).
    """
    t_base = targets[0] or (lambda c: hook_command_targets(c, base_files))
    t_head = targets[1] or (lambda c: hook_command_targets(c, head_files))
    for event, b_info in base_ev.items():
        h_info = head_ev.get(event)
        if h_info is None:
            continue
        b_active = {c for c, f in b_info["command_states"] if _active(c, f)}
        h_names = {c for c, _ in h_info["command_states"]}
        h_active = {c for c, f in h_info["command_states"] if _active(c, f)}
        b_resolved = {
            c
            for c, f in b_info["command_states"]
            if _active(c, f) and t_base(c)
        }
        if any(c in h_active and not t_head(c) for c in b_resolved):
            return True
        left = any(c not in h_names for c in b_resolved)
        new_unresolved = any(
            c not in b_active and not t_head(c) for c in h_active
        )
        if left and new_unresolved:
            return True
    return False


def changed_paths(base_files: dict[str, bytes], head_files: dict[str, bytes]) -> list[str]:
    """Paths whose bytes differ between the sides after CRLF->LF (§2), sorted.

    Raw bytes are compared first; only a raw difference is normalized, so a
    line-ending-only rewrite (a Windows worktree against LF blobs) is no change.
    """
    out: list[str] = []
    for path in sorted(set(base_files) | set(head_files)):
        b = base_files.get(path)
        h = head_files.get(path)
        if b == h:
            continue
        if b is not None and h is not None and _lf(b) == _lf(h):
            continue
        out.append(path)
    return out


def _lf(data: bytes) -> bytes:
    # CRLF only (§2), not a lone CR: rewriting every LF of a shell judge to a
    # lone CR leaves one comment line that sh runs as nothing, so folding a
    # lone CR would read a gutted judge as unchanged.
    return data.replace(b"\r\n", b"\n")


def _dotted_identifier(token: str) -> bool:
    """ASCII dotted identifier: `a`, `a.b`, `_a.b2` (no regex, §5.2 style)."""
    for part in token.split("."):
        if not part or part[0] not in _IDENT_START:
            return False
        if any(ch not in _IDENT_REST for ch in part[1:]):
            return False
    return True


def _module_paths(command: str) -> set[str]:
    """The closed module form: a `-m` token followed by the ASCII dotted
    identifier `a.b` names `a/b.py`, `a/b/__init__.py` and `a/b/__main__.py`."""
    text = command
    for ch in ";&|":
        text = text.replace(ch, " ")
    toks = text.split()
    out: set[str] = set()
    for i in range(len(toks) - 1):
        if toks[i] == "-m" and _dotted_identifier(toks[i + 1]):
            stem = toks[i + 1].replace(".", "/")
            out.update((stem + ".py", stem + "/__init__.py", stem + "/__main__.py"))
    return out


def _names_path(command: str, modules: set[str], path: str) -> bool:
    """`command` (with `\\` already read as `/`) names `path`."""
    if path in modules:
        return True
    start = command.find(path)
    while start != -1:
        end = start + len(path)
        left_ok = start == 0 or command[start - 1] in _REF_LEFT
        right_ok = end == len(command) or command[end] in _REF_RIGHT
        if left_ok and right_ok:
            return True
        start = command.find(path, start + 1)
    return False


def _named_paths(command: str, plain: set[str], maxlen: int) -> set[str]:
    """Paths of `plain` that `command` names at token or path boundaries.

    A match ends where a _REF_RIGHT character or the command ends, and no
    `plain` path holds a _REF_RIGHT character, so every match is a suffix
    of one run between such characters that starts at the run's start or
    after a _REF_LEFT character. Each candidate is looked up once, so the
    cost is linear in the command's length times the longest changed path,
    not in the number of changed paths."""
    found: set[str] = set()
    n = len(command)
    run = 0
    for i in range(n + 1):
        if i < n and command[i] not in _REF_RIGHT:
            continue
        starts = [run] if run == 0 or command[run - 1] in _REF_LEFT else []
        starts.extend(j + 1 for j in range(run, i) if command[j] in _REF_LEFT)
        for s in starts:
            if s < i and i - s <= maxlen:
                cand = command[s:i]
                if cand in plain:
                    found.add(cand)
        run = i + 1
    return found


def names_changed_file(
    base_ev: dict[str, dict[str, Any]],
    head_ev: dict[str, dict[str, Any]],
    base_files: dict[str, bytes],
    head_files: dict[str, bytes],
    changed: list[str],
    targets: Any = (None, None),
) -> bool:
    """An active command names a changed path that is not one of its own
    §3.3 targets on that side. Diff-scoped: on an unchanged tree no path
    changed."""
    if not changed:
        return False
    changed_set = set(changed)
    # A path holding a _REF_RIGHT character (a space, a quote) cannot be a
    # single run; it keeps the direct boundary check, one find per command.
    odd = [p for p in changed if any(ch in _REF_RIGHT for ch in p)]
    plain = changed_set.difference(odd)
    maxlen = max((len(p) for p in plain), default=0)
    t_base = targets[0] or (lambda c: hook_command_targets(c, base_files))
    t_head = targets[1] or (lambda c: hook_command_targets(c, head_files))
    for events, resolve in ((base_ev, t_base), (head_ev, t_head)):
        seen: set[str] = set()
        for info in events.values():
            for command, flags in info["command_states"]:
                if command in seen or not _active(command, flags):
                    continue
                seen.add(command)
                slashed = command.replace("\\", "/")
                named = _module_paths(slashed) & changed_set
                named |= _named_paths(slashed, plain, maxlen)
                named.update(p for p in odd if _names_path(slashed, set(), p))
                if named - set(resolve(command)):
                    return True
    return False


def _expands(command: str, key: str) -> bool:
    """`command` expands the environment variable `key` as `$key` or
    `${key...` (the name ends at a character that cannot continue it)."""
    for opener in ("${" + key, "$" + key):
        start = command.find(opener)
        while start != -1:
            end = start + len(opener)
            if end == len(command) or command[end] not in _IDENT_REST:
                return True
            start = command.find(opener, start + 1)
    return False


def _env(doc: Any) -> dict[str, str]:
    if not isinstance(doc, dict) or not isinstance(doc.get("env"), dict):
        return {}
    return {k: canonical_text(v) for k, v in doc["env"].items() if isinstance(k, str)}


def environment_changed(
    base_doc: Any,
    head_doc: Any,
    base_ev: dict[str, dict[str, Any]],
    head_ev: dict[str, dict[str, Any]],
) -> bool:
    """A root `env` key the diff adds, changes or removes is expanded by an
    active hook command of the same file on either side: the command may now
    run something else, which §3.3 does not resolve."""
    base, head = _env(base_doc), _env(head_doc)
    keys = sorted(k for k in set(base) | set(head) if base.get(k) != head.get(k))
    if not keys:
        return False
    for events in (base_ev, head_ev):
        for info in events.values():
            for command, flags in info["command_states"]:
                if _active(command, flags) and any(_expands(command, k) for k in keys):
                    return True
    return False


def handler_changed(
    base_ev: dict[str, dict[str, Any]], head_ev: dict[str, dict[str, Any]]
) -> bool:
    """SPEC §5.1 (spec 28, AI-assisted ruling on #45): an event lost a
    modeled prompt/agent handler it held at base (the handler is gone or
    its text changed, compared as a multiset of canonical texts, so key and
    handler order are no change) and still holds one at head. An added
    handler is no row, as an added command is none; a head event left with
    no handler is HOOK_REMOVED's case, not this row."""
    for event, h_info in head_ev.items():
        after = h_info.get("non_commands", [])
        if not after:
            continue
        before = (base_ev.get(event) or {}).get("non_commands", [])
        if Counter(map(canonical_text, before)) - Counter(map(canonical_text, after)):
            return True
    return False


def _flag_values(obj: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """(key, canonical text) for each §5.1 flag key on this object whose
    value is not a JSON boolean. Read, never interpreted."""
    return tuple(
        (key, canonical_text(obj[key]))
        for key in FLAG_KEYS
        if key in obj and not isinstance(obj[key], bool)
    )


def nonboolean_flags(doc: Any) -> Counter[tuple[str, str, str, str]]:
    """(event, command, key, value) occurrences of §5.1 flag keys whose value
    is not a JSON boolean, as a multiset.

    Every hook object that carries such a value gives one occurrence per
    command it holds itself or that a hook item directly under it holds (a
    handler, under a Claude matcher entry), or one with command '' when it
    holds none. On the host shapes (a Cursor hook object; a Claude entry and
    its handlers) that is every command the value applies to. Deeper nesting,
    which no host defines, attributes the value to the object's direct
    commands or to '' rather than to every command below it, which keeps the
    walk linear in the document (an every-descendant count grows with the
    square of the depth). Explicit-stack walk (§9)."""
    out: Counter[tuple[str, str, str, str]] = Counter()
    if not isinstance(doc, dict):
        return out
    hooks = doc.get("hooks")
    groups: list[tuple[str, dict[str, Any]]] = []
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            if isinstance(event, str) and isinstance(entries, list):
                groups.extend((event, e) for e in entries if isinstance(e, dict))
    elif isinstance(hooks, list):
        for entry in hooks:
            if isinstance(entry, dict):
                event = entry.get("event") or entry.get("type") or "unknown"
                if isinstance(event, str):
                    groups.append((event, entry))
    for event, entry in groups:
        stack: list[dict[str, Any]] = [entry]
        while stack:
            node = stack.pop()
            items = node.get("hooks")
            items = [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []
            stack.extend(items)
            pairs = _flag_values(node)
            if not pairs:
                continue
            commands = [c for c in [node.get("command")] + [i.get("command") for i in items]
                        if isinstance(c, str)]
            for command in commands or [""]:
                for key, value in pairs:
                    out[(event, command, key, value)] += 1
    return out


def flag_not_boolean(base_doc: Any, head_doc: Any, hook_finding: bool) -> bool:
    head = nonboolean_flags(head_doc)
    base = nonboolean_flags(base_doc)
    if head - base:
        return True
    return hook_finding and bool(head or base)


def _root_value(doc: Any, key: str) -> str | None:
    if not isinstance(doc, dict) or key not in doc:
        return None
    return canonical_text(doc[key])


# JavaScript's falsy JSON values: Claude Code 2.1.42 reads a root
# `__proto__` object's members as inherited settings and tests the switch
# for truthiness there (executed: `"false"`, `1` and `[]` switch hooks off).
_JS_FALSY = frozenset({_FALSE, canonical_text(0), canonical_text(""), canonical_text(None)})


def _proto_value(doc: Any) -> str | None:
    if not isinstance(doc, dict):
        return None
    return _root_value(doc.get("__proto__"), "disableAllHooks")


def switch_set(doc: Any) -> bool:
    """The root `disableAllHooks` is neither absent nor the JSON `false`, or
    a root `__proto__` object holds a JS-truthy one (spec 24)."""
    if _root_value(doc, "disableAllHooks") not in (None, _FALSE):
        return True
    return _proto_value(doc) not in (None, *_JS_FALSY)


def disable_all_hooks(
    base_doc: Any, head_doc: Any, hook_finding: bool, switch_finding: bool = False,
    switch_anywhere: bool = False,
) -> bool:
    base = _root_value(base_doc, "disableAllHooks")
    head = _root_value(head_doc, "disableAllHooks")
    if head != base and head not in (None, _FALSE) and not (switch_finding and head == _TRUE):
        return True
    proto_head = _proto_value(head_doc)
    if proto_head is not None and proto_head != _proto_value(base_doc):
        return True
    # Spec 24: beside a hook finding, the switch of either settings file on
    # either side marks it (`switch_anywhere`).
    return hook_finding and (
        switch_set(base_doc) or switch_set(head_doc) or switch_anywhere
    )


def detect(
    *,
    claude_settings: bool,
    base_doc: Any,
    head_doc: Any,
    base_ev: dict[str, dict[str, Any]],
    head_ev: dict[str, dict[str, Any]],
    base_files: dict[str, bytes],
    head_files: dict[str, bytes],
    changed: Any,
    hook_finding: bool,
    note_unknown: Any,
    switch_finding: bool = False,
    switch_anywhere: bool = False,
    targets: Any = (None, None),
) -> None:
    """Report the reasons above for one hook surface file. `changed` is a
    callable returning the diff's changed paths, computed once per run."""
    if no_longer_resolved(base_ev, head_ev, base_files, head_files, targets):
        note_unknown(TARGET_NO_LONGER_RESOLVED)
    if names_changed_file(base_ev, head_ev, base_files, head_files, changed(), targets):
        note_unknown(NAMES_CHANGED_FILE)
    if flag_not_boolean(base_doc, head_doc, hook_finding):
        note_unknown(FLAG_NOT_BOOLEAN)
    if claude_settings and disable_all_hooks(base_doc, head_doc, hook_finding, switch_finding, switch_anywhere):
        note_unknown(DISABLE_ALL_HOOKS)
    if claude_settings and environment_changed(base_doc, head_doc, base_ev, head_ev):
        note_unknown(ENV_CHANGED)
    if claude_settings and handler_changed(base_ev, head_ev):
        note_unknown(HANDLER_CHANGED)
