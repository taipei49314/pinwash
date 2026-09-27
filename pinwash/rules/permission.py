"""PERMISSION_WIDENED (SPEC §5.3): closed comparisons, escalates to high (§6)."""

from __future__ import annotations

from typing import Any

WIDEN_ALLOW = frozenset(
    {"Bash(*)", "Bash(rm *)", "Bash(git push --force*)", "*"}
)
PM_RANK = {"default": 2, "acceptEdits": 1, "dontAsk": 0}
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
    base_allow = set(_perm_allow_list(base_doc))
    head_allow = _perm_allow_list(head_doc)
    for item in head_allow:
        if item in base_allow:
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
    if hm in GM_APPROVAL_RANK:
        if bm is None and hm in {"yolo", "auto_edit"}:
            add(
                rule="PERMISSION_WIDENED",
                severity="high",
                message=f"gemini approvalMode became {hm}",
                path=path,
                after=hm,
            )
        elif bm in GM_APPROVAL_RANK and GM_APPROVAL_RANK[hm] < GM_APPROVAL_RANK[bm]:
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
