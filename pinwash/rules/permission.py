"""PERMISSION_WIDENED (SPEC §5.3): closed comparisons, escalates to high (§6)."""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

WIDEN_ALLOW = frozenset(
    {"Bash(*)", "Bash(rm *)", "Bash(git push --force*)", "*"}
)
# SPEC §5.3 (spec 17, AI-assisted ruling R-16a on #16): the permission-mode
# lattice, stricter = larger. `dontAsk` denies every call `default` would
# ask about, as `deny` stands above `ask` for opencode; `bypassPermissions`
# is the weakest and widens from any other value; `manual` is the host's
# alias for `default`.
PM_RANK = {"dontAsk": 3, "default": 2, "acceptEdits": 1}
PM_ALIAS = {"manual": "default"}
PM_BYPASS = "bypassPermissions"
PM_LATTICE = frozenset(PM_RANK) | frozenset(PM_ALIAS) | {PM_BYPASS}
# The two settings files the host merges, local over shared (precedence is
# documented; a list merges, a single value is overridden).
SHARED = ".claude/settings.json"
LOCAL = ".claude/settings.local.json"
_DEFAULT_MODE = ("permissions", "defaultMode")

# SPEC §5.3 / §7 (spec 16, AI-assisted rulings on #16): permission changes
# the closed comparisons do not evaluate, reported as unknown_coverage rows.
MODE_CHANGED = "permission mode changed (not evaluated)"
OFF_LATTICE = "permission value outside the lattice"
TOOLWIDE_EDIT = "tool-wide edit grant added (not evaluated)"
# The host tools whose rules apply to file edits (R17).
_EDIT_TOOLS = frozenset({"Edit", "Write", "NotebookEdit", "MultiEdit"})
# `permissions` keys that switch a host mode off (their change is routed).
_MODE_SWITCHES = ("disableBypassPermissionsMode", "disableAutoMode")
_ABSENT = object()


def canonical_rule(entry: str) -> str:
    """SPEC §5.3 canonical form of a `permissions.allow` entry (spec 16).

    Only two rewrites, both spellings the host documents as equivalent:
    `Tool()` / `Tool(*)` -> `Tool` (a tool name holding neither `)` nor
    `*`), and the legacy `Bash(X:*)` -> `Bash(X *)` when X is non-empty and
    holds no `*`. Nothing is trimmed, case-folded, collapsed or unescaped;
    any other entry is returned unchanged.
    """
    q = entry.find("(")
    if q <= 0 or not entry.endswith(")"):
        return entry
    tool, content = entry[:q], entry[q + 1 : -1]
    if ")" in tool:
        return entry
    if content in ("", "*") and "*" not in tool:
        return tool
    if tool == "Bash" and len(content) > 2 and content.endswith(":*") and "*" not in content[:-2]:
        return f"Bash({content[:-2]} *)"
    return entry
GM_APPROVAL_RANK = {"default": 2, "auto_edit": 1, "yolo": 0}
OC_RANK = {"deny": 2, "ask": 1, "allow": 0}


def _mcp_servers(doc: Any) -> dict[str, dict[str, Any]]:
    root = doc if isinstance(doc, dict) else {}
    servers = root.get("mcpServers")
    if not isinstance(servers, dict):
        servers = root.get("servers")
    if not isinstance(servers, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for name, body in servers.items():
        if isinstance(name, str) and isinstance(body, dict):
            out[name] = body
    return out


def _allow_star(body: dict[str, Any], key: str) -> bool:
    arr = body.get(key)
    if isinstance(arr, list):
        return "*" in arr
    return False


def _perm_allow_list(doc: Any) -> list[str]:
    if not isinstance(doc, dict):
        return []
    perm = doc.get("permissions")
    if not isinstance(perm, dict):
        return []
    allow = perm.get("allow")
    if isinstance(allow, list):
        return [x for x in allow if isinstance(x, str)]
    return []


def detect_claude_settings(
    path: str, base_doc: Any, head_doc: Any, add: Any
) -> None:
    if head_doc is None:
        return
    # A base entry with the same canonical form already grants the head
    # entry (an equivalence, never a coverage test: a narrower or flagged
    # base entry suppresses nothing; spec 16, #16).
    base_canon = {canonical_rule(x) for x in _perm_allow_list(base_doc)}
    head_allow = _perm_allow_list(head_doc)
    for item in head_allow:
        if canonical_rule(item) in base_canon:
            continue
        if item in WIDEN_ALLOW:
            add(
                rule="PERMISSION_WIDENED",
                severity="high",
                message=f"permissions.allow gained {item}",
                path=path,
                after=item,
            )
    base_mode = _lookup(base_doc, "permissionMode")
    head_mode = _lookup(head_doc, "permissionMode")
    if _top_level_widened(base_mode, head_mode):
        if isinstance(base_mode, str):
            add(
                rule="PERMISSION_WIDENED",
                severity="high",
                message=f"permissionMode {base_mode} -> {head_mode}",
                path=path,
                before=base_mode,
                after=head_mode,
            )
        else:
            add(
                rule="PERMISSION_WIDENED",
                severity="high",
                message=f"permissionMode became {head_mode}",
                path=path,
                after=head_mode,
            )


def _mode_key(value: Any) -> Any:
    """A mode value on the lattice's terms: `manual` is `default`, and a
    value that is not a string sets nothing (`_ABSENT`)."""
    if not isinstance(value, str):
        return _ABSENT
    return PM_ALIAS.get(value, value)


def _top_level_widened(base: Any, head: Any) -> bool:
    """SPEC §5.3 (spec 17): top-level `permissionMode`, which the host does
    not read from a settings file, fires only when written as a weak value:
    `acceptEdits` from absent, `default`, `manual`, `dontAsk` or a value
    that is not a string, or `bypassPermissions` from any other value. It
    has no removal and no relax rule."""
    if head == "acceptEdits" and isinstance(head, str):
        return _mode_key(base) in (_ABSENT, "default", "dontAsk")
    if head == PM_BYPASS and isinstance(head, str):
        return not _same(base, head)
    return False


def _mode_widened(base: Any, head: Any) -> bool:
    """SPEC §5.3 (spec 17): `permissions.defaultMode` moves down the lattice
    (an absent key compared as `default`), is removed from `dontAsk`, or
    becomes `bypassPermissions` from any other value."""
    b, h = _mode_key(base), _mode_key(head)
    if h == PM_BYPASS:
        return b != PM_BYPASS
    if h is _ABSENT:
        return b == "dontAsk"
    if h in PM_RANK:
        rank = PM_RANK["default"] if b is _ABSENT else PM_RANK.get(b)
        return rank is not None and PM_RANK[h] < rank
    return False


def _mode_route(base: Any, head: Any) -> str | None:
    """SPEC §5.3 / §7 (spec 17, R17): the row for a `permissions.defaultMode`
    change the comparison does not evaluate. Removing `default` or
    `acceptEdits` is routed because interactive sessions on v2.1.283+
    start in `auto`; `bypassPermissions` removed or moved to `acceptEdits`
    is routed because hosts from v2.1.257 on start it in Manual (review of
    2026-10-10); a move to or from a value off the lattice is routed
    unless the head is `bypassPermissions`."""
    b, h = _mode_key(base), _mode_key(head)
    if b == h or h == PM_BYPASS:
        return None
    if b == PM_BYPASS and (h is _ABSENT or h == "acceptEdits"):
        return MODE_CHANGED
    if h is _ABSENT:
        if b in ("default", "acceptEdits"):
            return MODE_CHANGED
        return None if b in (PM_BYPASS, "dontAsk") else OFF_LATTICE
    if (b is not _ABSENT and b not in PM_LATTICE) or h not in PM_LATTICE:
        return OFF_LATTICE
    return None


def _report_mode(path: str, base: Any, head: Any, not_a_string: bool, add: Any, note: Any) -> None:
    """One `permissions.defaultMode` comparison: a finding, a row, or neither."""
    locator = "permissions.defaultMode"
    if not _mode_widened(base, head):
        reason = _mode_route(base, head)
        if reason:
            note(path, reason)
        return
    if not isinstance(head, str):
        shown = "(not a string)" if not_a_string else "removed"
        sep = " -> " if not_a_string else " "
        add(
            rule="PERMISSION_WIDENED",
            severity="high",
            message=f"permissions.defaultMode {base}{sep}{shown}",
            path=path,
            before=base,
            locator=locator,
        )
    elif isinstance(base, str):
        add(
            rule="PERMISSION_WIDENED",
            severity="high",
            message=f"permissions.defaultMode {base} -> {head}",
            path=path,
            before=base,
            after=head,
            locator=locator,
        )
    else:
        add(
            rule="PERMISSION_WIDENED",
            severity="high",
            message=f"permissions.defaultMode became {head}",
            path=path,
            after=head,
            locator=locator,
        )


def _effective_mode(docs: dict[str, Any]) -> tuple[Any, str | None]:
    """The `permissions.defaultMode` in effect and the file that supplies it:
    `.claude/settings.local.json` over `.claude/settings.json`; a value that
    is not a string sets nothing."""
    for key in (LOCAL, SHARED):
        value = _lookup(docs.get(key), *_DEFAULT_MODE)
        if isinstance(value, str):
            return value, key
    return _ABSENT, None


def detect_claude_mode(
    files: dict[str, tuple[str, Any, str, Any, str]], add: Any, note: Any
) -> None:
    """SPEC §5.3 (spec 17, AI-assisted ruling R-16a on #16, the challenger's
    amendment): `permissions.defaultMode` compared on the value in effect
    across the two settings files. `files` maps `SHARED` / `LOCAL` to
    (path, base doc, base status, head doc, head status). The finding or
    row goes on the file that supplies the head's value, or, for a removal,
    the base's. When a settings file on either side cannot be parsed, each
    file that parses (or is absent) on both sides is compared on its own,
    a file created or deleted compared against the absent side."""
    if any("unparseable" in (f[2], f[4]) for f in files.values()):
        for key in (SHARED, LOCAL):
            if key not in files:
                continue
            path, b_doc, b_st, h_doc, h_st = files[key]
            if "unparseable" in (b_st, h_st):
                continue
            head = _lookup(h_doc, *_DEFAULT_MODE)
            _report_mode(
                path, _lookup(b_doc, *_DEFAULT_MODE), head,
                head is not _ABSENT and not isinstance(head, str), add, note,
            )
        return
    base_mode, base_key = _effective_mode({k: f[1] for k, f in files.items()})
    head_docs = {k: f[3] for k, f in files.items()}
    head_mode, head_key = _effective_mode(head_docs)
    key = head_key or base_key
    if key is None:
        return
    not_a_string = False
    if head_key is None:
        value = _lookup(head_docs.get(key), *_DEFAULT_MODE)
        not_a_string = value is not _ABSENT
    _report_mode(files[key][0], base_mode, head_mode, not_a_string, add, note)


def detect_mcp(path: str, base_doc: Any, head_doc: Any, add: Any) -> None:
    if head_doc is None:
        return
    base_s = _mcp_servers(base_doc)
    head_s = _mcp_servers(head_doc)
    for name, body in head_s.items():
        prev = base_s.get(name)
        if prev is None and body.get("disabled") is not True:
            add(
                rule="PERMISSION_WIDENED",
                severity="high",
                message=f"mcp server {name} enabled",
                path=path,
                locator=name,
            )
        if prev is not None and prev.get("disabled") is True and body.get("disabled") is False:
            add(
                rule="PERMISSION_WIDENED",
                severity="high",
                message=f"mcp server {name} disabled:false added",
                path=path,
                locator=name,
            )
        for key in ("alwaysAllow", "autoApprove"):
            if _allow_star(body, key) and not _allow_star(prev or {}, key):
                add(
                    rule="PERMISSION_WIDENED",
                    severity="high",
                    message=f"mcp server {name} {key} gained *",
                    path=path,
                    locator=f"{name}.{key}",
                )


def detect_gemini_settings(
    path: str, base_doc: Any, head_doc: Any, add: Any
) -> None:
    if head_doc is None:
        return
    b = base_doc if isinstance(base_doc, dict) else {}
    h = head_doc if isinstance(head_doc, dict) else {}
    if h.get("autoAccept") is True and b.get("autoAccept") is not True:
        add(
            rule="PERMISSION_WIDENED",
            severity="high",
            message="gemini autoAccept enabled",
            path=path,
            after="autoAccept: true",
        )
    bm, hm = b.get("approvalMode"), h.get("approvalMode")
    # §5.3: only a string can sit on the lattice; any other JSON value is an
    # unknown value (no finding), and a list or object must not reach the
    # dict lookup, where it would raise instead (unhashable).
    if isinstance(hm, str) and hm in GM_APPROVAL_RANK:
        if bm is None and hm in {"yolo", "auto_edit"}:
            add(
                rule="PERMISSION_WIDENED",
                severity="high",
                message=f"gemini approvalMode became {hm}",
                path=path,
                after=hm,
            )
        elif (
            isinstance(bm, str)
            and bm in GM_APPROVAL_RANK
            and GM_APPROVAL_RANK[hm] < GM_APPROVAL_RANK[bm]
        ):
            add(
                rule="PERMISSION_WIDENED",
                severity="high",
                message=f"gemini approvalMode {bm} -> {hm}",
                path=path,
                before=bm,
                after=hm,
            )
    base_servers = b.get("mcpServers") if isinstance(b.get("mcpServers"), dict) else {}
    head_servers = h.get("mcpServers") if isinstance(h.get("mcpServers"), dict) else {}
    for name, body in head_servers.items():
        if not isinstance(body, dict) or body.get("trust") is not True:
            continue
        prev = base_servers.get(name)
        prev_trust = prev.get("trust") if isinstance(prev, dict) else None
        if prev_trust is not True:
            add(
                rule="PERMISSION_WIDENED",
                severity="high",
                message=f"gemini mcp server {name} trust enabled",
                path=path,
                locator=f"mcpServers.{name}.trust",
            )


def detect_opencode_config(
    path: str, base_doc: Any, head_doc: Any, add: Any
) -> None:
    if head_doc is None:
        return
    b = base_doc if isinstance(base_doc, dict) else {}
    h = head_doc if isinstance(head_doc, dict) else {}
    base_perm = b.get("permission") if isinstance(b.get("permission"), dict) else {}
    head_perm = h.get("permission") if isinstance(h.get("permission"), dict) else {}
    for key, val in head_perm.items():
        # Object-form bash patterns are a §5.3 residual; strings only in v0.
        if not isinstance(val, str) or val not in OC_RANK:
            continue
        prev = base_perm.get(key)
        if prev is None:
            if val == "allow":
                add(
                    rule="PERMISSION_WIDENED",
                    severity="high",
                    message=f"opencode permission {key} added as allow",
                    path=path,
                    after=f"{key}: allow",
                )
            continue
        if isinstance(prev, str) and prev in OC_RANK and OC_RANK[val] < OC_RANK[prev]:
            add(
                rule="PERMISSION_WIDENED",
                severity="high",
                message=f"opencode permission {key} {prev} -> {val}",
                path=path,
                before=prev,
                after=val,
            )


def _lookup(doc: Any, *keys: str) -> Any:
    """The value at `keys` in nested objects, or `_ABSENT`."""
    node = doc
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            return _ABSENT
        node = node[key]
    return node


def _off_lattice(value: Any, lattice: Collection[str]) -> bool:
    """A present value that is not a string on the lattice."""
    return value is not _ABSENT and not (isinstance(value, str) and value in lattice)


def _lattice_routed(base: Any, head: Any, lattice: Collection[str]) -> bool:
    """SPEC §5.3 (spec 16): a lattice key whose value changed while either
    side is off its lattice (another string, or not a string), or which was
    removed; the closed comparisons read neither."""
    if _same(base, head):
        return False
    if head is _ABSENT:
        return True
    return _off_lattice(base, lattice) or _off_lattice(head, lattice)


def _same(a: Any, b: Any) -> bool:
    """Equal JSON values of the same type (`1` is not `true`)."""
    return a is b or (type(a) is type(b) and a == b)


def route_claude_settings(base_doc: Any, head_doc: Any, note: Any) -> None:
    """SPEC §5.3 / §7 (spec 16, R17): rows for a `claude_settings` file whose
    sides both parse or are absent. Never a finding."""
    for key in _MODE_SWITCHES:
        b = _lookup(base_doc, "permissions", key)
        h = _lookup(head_doc, "permissions", key)
        if not _same(b, h):
            note(MODE_CHANGED)
            break
    base_mode = _lookup(base_doc, "permissionMode")
    head_mode = _lookup(head_doc, "permissionMode")
    if not _top_level_widened(base_mode, head_mode) and _lattice_routed(
        base_mode, head_mode, PM_LATTICE
    ):
        note(OFF_LATTICE)
    base_canon = {canonical_rule(x) for x in _perm_allow_list(base_doc)}
    for item in _perm_allow_list(head_doc):
        canon = canonical_rule(item)
        if canon in _EDIT_TOOLS and canon not in base_canon:
            note(TOOLWIDE_EDIT)
            break


def route_gemini_settings(base_doc: Any, head_doc: Any, note: Any) -> None:
    """SPEC §5.3 / §7 (spec 16, R17): `approvalMode` off its lattice."""
    if _lattice_routed(
        _lookup(base_doc, "approvalMode"), _lookup(head_doc, "approvalMode"), GM_APPROVAL_RANK
    ):
        note(OFF_LATTICE)


def route_opencode_config(base_doc: Any, head_doc: Any, note: Any) -> None:
    """SPEC §5.3 / §7 (spec 16, R17): a `permission.<tool>` value off its
    lattice (an object-form pattern included) or removed."""
    b = _lookup(base_doc, "permission")
    h = _lookup(head_doc, "permission")
    b = b if isinstance(b, dict) else {}
    h = h if isinstance(h, dict) else {}
    for key in sorted(set(b) | set(h)):
        if _lattice_routed(b.get(key, _ABSENT), h.get(key, _ABSENT), OC_RANK):
            note(OFF_LATTICE)
            return
