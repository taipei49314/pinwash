"""PERMISSION_WIDENED (SPEC §5.3): closed comparisons, escalates to high (§6)."""

from __future__ import annotations

from typing import Any

WIDEN_ALLOW = frozenset(
    {"Bash(*)", "Bash(rm *)", "Bash(git push --force*)", "*"}
)
PM_RANK = {"default": 2, "acceptEdits": 1, "dontAsk": 0}


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
