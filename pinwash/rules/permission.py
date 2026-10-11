"""PERMISSION_WIDENED (SPEC §5.3): closed comparisons, escalates to high (§6)."""

from __future__ import annotations

from typing import Any

WIDEN_ALLOW = frozenset(
    {"Bash(*)", "Bash(rm *)", "Bash(git push --force*)", "*"}
)
PM_RANK = {"default": 2, "acceptEdits": 1, "dontAsk": 0}

# SPEC §5.3 / §7 (spec 16, AI-assisted rulings on #16): permission changes
# the closed comparisons do not evaluate, reported as unknown_coverage rows.
MODE_CHANGED = "permission mode changed (not evaluated)"
OFF_LATTICE = "permission value outside the lattice"
TOOLWIDE_EDIT = "tool-wide edit grant added (not evaluated)"
# The host tools whose rules apply to file edits (R17).
_EDIT_TOOLS = frozenset({"Edit", "Write", "NotebookEdit", "MultiEdit"})
# `permissions` keys that switch a host mode off (their change is routed).
_MODE_SWITCHES = ("defaultMode", "disableBypassPermissionsMode", "disableAutoMode")
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


def _perm_mode(doc: Any) -> str | None:
    if not isinstance(doc, dict):
        return None
    mode = doc.get("permissionMode")
    return mode if isinstance(mode, str) else None


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
    base_mode = _perm_mode(base_doc)
    head_mode = _perm_mode(head_doc)
    if head_mode in PM_RANK:
        if base_mode is None and head_mode in {"dontAsk", "acceptEdits"}:
            add(
                rule="PERMISSION_WIDENED",
                severity="high",
                message=f"permissionMode became {head_mode}",
                path=path,
                after=head_mode,
            )
        elif base_mode in PM_RANK and PM_RANK[head_mode] < PM_RANK[base_mode]:
            add(
                rule="PERMISSION_WIDENED",
                severity="high",
                message=f"permissionMode {base_mode} -> {head_mode}",
                path=path,
                before=base_mode,
                after=head_mode,
            )


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


def _off_lattice(value: Any, lattice: dict[str, int]) -> bool:
    """A present value that is not a string on the lattice."""
    return value is not _ABSENT and not (isinstance(value, str) and value in lattice)


def _lattice_routed(base: Any, head: Any, lattice: dict[str, int]) -> bool:
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
    if _lattice_routed(
        _lookup(base_doc, "permissionMode"), _lookup(head_doc, "permissionMode"), PM_RANK
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
