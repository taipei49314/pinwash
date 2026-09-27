"""Diff scan: apply every v0 rule. Never executes subject code. Never uses the network."""

from __future__ import annotations

import json
import os
from difflib import SequenceMatcher
from typing import Any

from pinwash.findings import envelope, make_finding
from pinwash.gha import job_disabled, parse_workflow
from pinwash.gitrepo import GitError, ls_tree, resolve_range
from pinwash.hooks import (
    CLAUDE_STOP_EVENTS,
    CURSOR_STOP_EVENTS,
    extract_event_hooks,
    stub_command,
)
from pinwash.pins import classify_action_ref, kind_rank, record_rank
from pinwash.surfaces import (
    is_agent_markdown,
    is_checkwash_config,
    is_claude_hooks_file,
    is_claude_settings,
    is_cursor_hooks,
    is_cursor_mcp,
    is_declared_pins,
    is_gha_ruleset,
    is_gha_workflow,
    is_surface,
    skill_bypass_excluded,
    glob_skill,
    norm,
)
from pinwash.textutil import crlf_to_lf, decode_utf8
from pinwash.tomlsub import (
    SEVERITY_RANK,
    allow_valid,
    parse_allow_toml,
    parse_checkwash_config,
    pinwash_today,
)

PHRASES = (
    "--no-verify",
    "skip tripwire",
    "skip checkwash",
    "skip greenwash",
    "disable the hook",
    "disable the stop hook",
    "bypass the hook",
    "do not run the hook",
    "alwaysapprove",
)

WIDEN_ALLOW = frozenset(
    {"Bash(*)", "Bash(rm *)", "Bash(git push --force*)", "*"}
)
PM_RANK = {"default": 2, "acceptEdits": 1, "dontAsk": 0}


def _json_load(data: bytes | None) -> tuple[Any | None, str]:
    """Return (obj, status) where status is ok|missing|unparseable."""
    if data is None:
        return None, "missing"
    text = decode_utf8(data)
    if text is None:
        return None, "unparseable"
    try:
        return json.loads(crlf_to_lf(text)), "ok"
    except json.JSONDecodeError:
        return None, "unparseable"


def _text(data: bytes | None) -> tuple[str | None, str]:
    if data is None:
        return None, "missing"
    text = decode_utf8(data)
    if text is None:
        return None, "unparseable"
    return crlf_to_lf(text), "ok"


def _surface_unparseable(b_st: str, h_st: str) -> tuple[str, str] | None:
    """SPEC §3 closed table.

    (ok, unparseable) -> high; (unparseable, unparseable) -> warn.
    Every other status pair emits nothing: a file absent at base never
    weakens, and a head that parses is not a weakening of a corrupt base.
    """
    if b_st == "ok" and h_st == "unparseable":
        return "high", "surface file parsed at base and is unparseable at head"
    if b_st == "unparseable" and h_st == "unparseable":
        return "warn", "surface file unparseable on both sides"
    return None


def _workflow_status(st: str, parsed: Any) -> str:
    """Effective parse status for a workflow: tabs are unparseable (§3.1)."""
    if st in ("missing", "unparseable"):
        return st
    if parsed is not None and parsed.unparseable:
        return "unparseable"
    return "ok"


def _union_paths(base: dict[str, bytes], head: dict[str, bytes]) -> list[str]:
    names = set(base) | set(head)
    return sorted(norm(p) for p in names if is_surface(p))


def _added_lines(base_text: str, head_text: str) -> list[str]:
    b = base_text.split("\n")
    h = head_text.split("\n")
    added: list[str] = []
    matcher = SequenceMatcher(a=b, b=h, autojunk=False)
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ("insert", "replace"):
            added.extend(h[j1:j2])
    return added


def _phrase_hit(line: str) -> bool:
    folded = line.casefold()
    for phrase in PHRASES:
        if phrase in folded:
            return True
    if "chmod +x" in folded and "hook" in folded:
        return True
    if "required status check" in folded and any(
        word in folded for word in ("remove", "delete", "drop")
    ):
        return True
    return False


def _ruleset_contexts(doc: Any) -> list[str]:
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if "required_status_checks" in node:
                checks = node["required_status_checks"]
                if isinstance(checks, list):
                    for item in checks:
                        if isinstance(item, str):
                            found.append(item)
                        elif isinstance(item, dict) and isinstance(
                            item.get("context"), str
                        ):
                            found.append(item["context"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(doc)
    return found


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


def scan_pair(
    base_files: dict[str, bytes],
    head_files: dict[str, bytes],
    *,
    base_label: str,
    head_label: str,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = env if env is not None else dict(os.environ)
    findings: list[dict[str, Any]] = []
    unknown: list[dict[str, str]] = []
    config_errors: list[str] = []
    today = pinwash_today(env)

    def add(**kwargs: Any) -> None:
        findings.append(make_finding(**kwargs))

    paths = _union_paths(base_files, head_files)

    # SPEC §5: the job-side REQUIRED_CHECK_DROPPED trigger is the workflow
    # job that produced a required status context named at base in
    # gha_ruleset. No base-named contexts -> no job-side findings.
    base_contexts: set[str] = set()
    for path in paths:
        if not is_gha_ruleset(path):
            continue
        b_obj, b_st = _json_load(base_files.get(path))
        if b_st == "ok":
            base_contexts.update(_ruleset_contexts(b_obj))

    for path in paths:
        if is_claude_settings(path) or is_cursor_hooks(path):
            b_obj, b_st = _json_load(base_files.get(path))
            h_obj, h_st = _json_load(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            stop_names = (
                CLAUDE_STOP_EVENTS if is_claude_settings(path) else CURSOR_STOP_EVENTS
            )
            base_ev = extract_event_hooks(b_obj) if b_st == "ok" else {}
            head_ev = extract_event_hooks(h_obj) if h_st == "ok" else {}
            _detect_hooks(path, base_ev, head_ev, stop_names, add)
            if is_claude_settings(path) and h_st == "ok" and b_st != "unparseable":
                _detect_permissions(
                    path,
                    b_obj if b_st == "ok" else None,
                    h_obj,
                    add,
                )
        elif is_claude_hooks_file(path):
            # Surface membership only: v0 does not parse hook file bodies
            # (R07). It still honors SPEC §3 — do not skip the file.
            if path.endswith(".json"):
                _bobj, b_st = _json_load(base_files.get(path))
                _hobj, h_st = _json_load(head_files.get(path))
            else:
                _btxt, b_st = _text(base_files.get(path))
                _htxt, h_st = _text(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
        elif is_gha_workflow(path):
            b_txt, b_st = _text(base_files.get(path))
            h_txt, h_st = _text(head_files.get(path))
            base_g = parse_workflow(b_txt) if b_st == "ok" and b_txt is not None else None
            head_g = parse_workflow(h_txt) if h_st == "ok" and h_txt is not None else None
            b_eff = _workflow_status(b_st, base_g)
            h_eff = _workflow_status(h_st, head_g)
            unp = _surface_unparseable(b_eff, h_eff)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            if head_g is not None and not head_g.unparseable:
                for reason in head_g.unknown:
                    unknown.append({"path": path, "reason": reason})
            _detect_pins(path, base_g, head_g, add)
            _detect_jobs(path, base_g, head_g, base_contexts, add)
        elif is_gha_ruleset(path):
            b_obj, b_st = _json_load(base_files.get(path))
            h_obj, h_st = _json_load(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            base_ctx = _ruleset_contexts(b_obj) if b_st == "ok" else []
            head_ctx = _ruleset_contexts(h_obj) if h_st == "ok" else []
            _detect_ruleset(path, base_ctx, head_ctx, add)
        elif is_cursor_mcp(path):
            b_obj, b_st = _json_load(base_files.get(path))
            h_obj, h_st = _json_load(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            if b_st != "unparseable" and h_st == "ok":
                _detect_mcp(
                    path,
                    b_obj if b_st == "ok" else None,
                    h_obj,
                    add,
                )
        elif is_declared_pins(path):
            b_obj, b_st = _json_load(base_files.get(path))
            h_obj, h_st = _json_load(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            if b_st != "ok":
                continue
            _detect_declared_pins(path, b_obj, h_obj if h_st == "ok" else None, add)
        elif is_checkwash_config(path):
            b_txt, b_st = _text(base_files.get(path))
            h_txt, h_st = _text(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            _detect_config(
                path,
                b_txt if b_st == "ok" else None,
                h_txt if h_st == "ok" else None,
                add,
            )
        elif glob_skill(path) or is_agent_markdown(path):
            if skill_bypass_excluded(path):
                continue
            b_txt, b_st = _text(base_files.get(path))
            h_txt, h_st = _text(head_files.get(path))
            if h_st != "ok" or h_txt is None:
                continue
            base_s = b_txt if b_st == "ok" and b_txt is not None else ""
            for line in _added_lines(base_s, h_txt):
                if _phrase_hit(line):
                    add(
                        rule="SKILL_BYPASS",
                        severity="warn",
                        message="added or edited line matches a v0 bypass phrase",
                        path=path,
                        before="",
                        after=line[:200],
                    )

    _detect_allow(base_files, head_files, today, add, config_errors)

    findings = _apply_allow(findings, base_files, today)
    return envelope(
        base_label=base_label,
        head_label=head_label,
        findings=findings,
        config_errors=config_errors,
        unknown_coverage=unknown,
    )


def _non_stub_stop_count(events: dict[str, dict[str, Any]], names: frozenset[str]) -> int:
    n = 0
    for name in names:
        info = events.get(name)
        if not info:
            continue
        live = [
            c
            for c in info["commands"]
            if not stub_command(c) and not c.lstrip().startswith("#")
        ]
        if live:
            n += 1
        elif info["array_len"] > 0 and not info["commands"]:
            n += 0
    return n


def _detect_hooks(
    path: str,
    base_ev: dict[str, dict[str, Any]],
    head_ev: dict[str, dict[str, Any]],
    stop_names: frozenset[str],
    add: Any,
) -> None:
    head_stop = _non_stub_stop_count(head_ev, stop_names)

    def escalate_stop(rule: str, event: str, severity: str) -> str:
        if event in stop_names and head_stop == 0 and rule in {
            "HOOK_REMOVED",
            "HOOK_BYPASSED",
            "GATE_STUBBED",
        }:
            return "critical"
        return severity

    for event, info in base_ev.items():
        head_info = head_ev.get(event)
        if head_info is None:
            sev = escalate_stop("HOOK_REMOVED", event, "warn")
            add(
                rule="HOOK_REMOVED",
                severity=sev,
                message=f"hook event {event} removed",
                path=path,
                before=event,
                after="",
                locator=event,
            )
            continue
        if head_info["array_len"] == 0 or not head_info["commands"]:
            if head_info["array_len"] == 0:
                sev = escalate_stop("HOOK_BYPASSED", event, "warn")
                add(
                    rule="HOOK_BYPASSED",
                    severity=sev,
                    message=f"hook event {event} array emptied",
                    path=path,
                    locator=event,
                )
            if not head_info["commands"]:
                sev = escalate_stop("HOOK_REMOVED", event, "warn")
                add(
                    rule="HOOK_REMOVED",
                    severity=sev,
                    message=f"hook event {event} command list emptied",
                    path=path,
                    locator=event,
                )
            continue
        bf, hf = info["flags"], head_info["flags"]
        if (not bf["disabled"] and hf["disabled"]) or (
            not bf["hookEnabled_false"] and hf["hookEnabled_false"]
        ) or (not bf["continueOnError"] and hf["continueOnError"]) or (
            not bf["failOpen"] and hf["failOpen"]
        ):
            sev = escalate_stop("HOOK_BYPASSED", event, "warn")
            add(
                rule="HOOK_BYPASSED",
                severity=sev,
                message=f"hook event {event} skip flag added",
                path=path,
                locator=event,
            )
        base_cmds = info["commands"]
        head_cmds = head_info["commands"]
        for i, cmd in enumerate(head_cmds):
            prev = base_cmds[i] if i < len(base_cmds) else ""
            if stub_command(cmd) and not stub_command(prev):
                sev = escalate_stop("GATE_STUBBED", event, "warn")
                add(
                    rule="GATE_STUBBED",
                    severity=sev,
                    message=f"hook command for {event} replaced with a v0 stub",
                    path=path,
                    before=prev,
                    after=cmd,
                    locator=event,
                )
            if (
                i < len(base_cmds)
                and prev.strip()
                and not prev.lstrip().startswith("#")
                and cmd.lstrip().startswith("#")
            ):
                # SPEC §5 HOOK_BYPASSED: command prefixed with a no-op. The
                # v0 closed shape for that prefix is a shell comment.
                sev = escalate_stop("HOOK_BYPASSED", event, "warn")
                add(
                    rule="HOOK_BYPASSED",
                    severity=sev,
                    message=f"hook command for {event} commented out",
                    path=path,
                    before=prev,
                    after=cmd,
                    locator=event,
                )
        if (
            "*" in info["matchers"]
            and "*" not in head_info["matchers"]
            and not head_info["commands"]
        ):
            sev = escalate_stop("HOOK_BYPASSED", event, "warn")
            add(
                rule="HOOK_BYPASSED",
                severity=sev,
                message=f"hook event {event} matcher * removed and commands emptied",
                path=path,
                locator=event,
            )


def _detect_pins(path: str, base_g: Any, head_g: Any, add: Any) -> None:
    if base_g is None:
        return
    if getattr(base_g, "unparseable", False):
        return
    base_uses = {(loc, n): ref for loc, ref, n in base_g.uses}
    head_uses = (
        {(loc, n): ref for loc, ref, n in head_g.uses}
        if head_g is not None and not head_g.unparseable
        else {}
    )
    head_non_floating = 0
    if head_g is not None and not head_g.unparseable:
        for loc, ref, _n in head_g.uses:
            if classify_action_ref(ref) != "floating":
                head_non_floating += 1
    consumer_exists = head_g is not None and not getattr(head_g, "unparseable", False)

    for key, ref in base_uses.items():
        loc, n = key
        locator = f"gha_workflow:{path}:uses:{loc}#{n}"
        base_kind = classify_action_ref(ref)
        head_ref = head_uses.get(key)
        if head_ref is None:
            if consumer_exists:
                sev = "high"
                if head_non_floating == 0:
                    sev = "critical"
                add(
                    rule="JUDGE_UNPINNED",
                    severity=sev,
                    message="action pin removed while workflow remains",
                    path=path,
                    before=ref,
                    after="",
                    locator=locator,
                )
            continue
        head_kind = classify_action_ref(head_ref)
        unpinned = False
        if kind_rank(head_kind) < kind_rank(base_kind):
            unpinned = True
        if head_ref != ref and head_kind == "floating":
            unpinned = True
        if base_kind == "git_sha" and head_kind == "git_sha" and len(head_ref) < 40:
            unpinned = True
        if not unpinned:
            continue
        sev = "warn"
        if head_kind == "floating":
            sev = "high"
        if head_kind == "floating" and head_non_floating == 0:
            sev = "critical"
        add(
            rule="JUDGE_UNPINNED",
            severity=sev,
            message="action pin weakened",
            path=path,
            before=ref,
            after=head_ref,
            locator=locator,
        )


def _detect_jobs(
    path: str,
    base_g: Any,
    head_g: Any,
    base_contexts: set[str],
    add: Any,
) -> None:
    if base_g is None or getattr(base_g, "unparseable", False):
        return
    if not base_contexts:
        # SPEC §5: the job-side trigger is the job that produced a required
        # status context named at base. With no named contexts there is no
        # job-side finding (rename blindness without a ruleset is R09).
        return
    head_jobs = (
        head_g.jobs if head_g is not None and not head_g.unparseable else {}
    )
    for key, job in base_g.jobs.items():
        display = job.name or key
        if display not in base_contexts:
            continue
        head_job = head_jobs.get(key)
        dropped = False
        after = ""
        if head_job is None:
            dropped = True
            after = "deleted"
        elif job_disabled(head_job) and not job_disabled(job):
            dropped = True
            after = head_job.if_value or "if: false"
        elif head_job.continue_on_error is True and job.continue_on_error is not True:
            dropped = True
            after = "continue-on-error: true"
        if dropped:
            add(
                rule="REQUIRED_CHECK_DROPPED",
                severity="warn",
                message=f"workflow job {display} no longer a reliable required check producer",
                path=path,
                before=display,
                after=after,
                locator=key,
            )


def _detect_ruleset(
    path: str, base_ctx: list[str], head_ctx: list[str], add: Any
) -> None:
    base_set = list(dict.fromkeys(base_ctx))
    head_set = set(head_ctx)
    remaining = [c for c in base_set if c in head_set]
    for ctx in base_set:
        if ctx in head_set:
            continue
        sev = "critical" if not remaining else "warn"
        add(
            rule="REQUIRED_CHECK_DROPPED",
            severity=sev,
            message=f"required status context {ctx} dropped",
            path=path,
            before=ctx,
            after="",
            locator=ctx,
        )


def _detect_mcp(path: str, base_doc: Any, head_doc: Any, add: Any) -> None:
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


def _detect_permissions(path: str, base_doc: Any, head_doc: Any, add: Any) -> None:
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


def _pin_records(doc: Any) -> dict[str, dict[str, str]]:
    if not isinstance(doc, list):
        return {}
    out: dict[str, dict[str, str]] = {}
    for item in doc:
        if not isinstance(item, dict):
            continue
        loc = item.get("locator")
        kind = item.get("kind")
        value = item.get("value")
        if isinstance(loc, str) and isinstance(kind, str) and isinstance(value, str):
            out[loc] = {"kind": kind, "value": value}
    return out


def _detect_declared_pins(path: str, base_doc: Any, head_doc: Any, add: Any) -> None:
    base_pins = _pin_records(base_doc)
    head_pins = _pin_records(head_doc) if head_doc is not None else {}
    for loc, rec in base_pins.items():
        head = head_pins.get(loc)
        if head is None:
            add(
                rule="JUDGE_UNPINNED",
                severity="high",
                message=f"declared pin {loc} removed",
                path=path,
                locator=f"declared_pins:{loc}",
                before=rec["value"],
            )
            continue
        base_kind = rec["kind"]
        head_kind = head["kind"]
        if base_kind == "digest_sha256" and head_kind != "digest_sha256":
            add(
                rule="JUDGE_UNPINNED",
                severity="high",
                message=f"declared pin {loc} lost digest",
                path=path,
                locator=f"declared_pins:{loc}",
            )
            continue
        if rec["value"] != head["value"] and classify_action_ref(head["value"]) == "floating":
            add(
                rule="JUDGE_UNPINNED",
                severity="high",
                message=f"declared pin {loc} value floated",
                path=path,
                locator=f"declared_pins:{loc}",
                before=rec["value"],
                after=head["value"],
            )
            continue
        if record_rank(head_kind, head["value"]) < record_rank(base_kind, rec["value"]):
            add(
                rule="JUDGE_UNPINNED",
                severity="high",
                message=f"declared pin {loc} kind weakened",
                path=path,
                locator=f"declared_pins:{loc}",
                before=base_kind,
                after=head_kind,
            )


def _detect_config(path: str, base_txt: str | None, head_txt: str | None, add: Any) -> None:
    if head_txt is None:
        return
    head_c = parse_checkwash_config(head_txt)
    base_c = parse_checkwash_config(base_txt) if base_txt is not None else {
        "disabled": [],
        "fail_on": None,
    }
    base_fail = base_c["fail_on"] or "high"
    head_fail = head_c["fail_on"]
    if head_fail and SEVERITY_RANK[head_fail] > SEVERITY_RANK[base_fail]:
        add(
            rule="CONFIG_RELAXED",
            severity="high",
            message=f"fail_on raised {base_fail} -> {head_fail}",
            path=path,
            before=base_fail,
            after=head_fail,
        )
    base_dis = set(base_c["disabled"])
    for name in head_c["disabled"]:
        if name not in base_dis:
            add(
                rule="CONFIG_RELAXED",
                severity="high",
                message=f"detector {name} disabled",
                path=path,
                after=name,
            )


def _detect_allow(
    base_files: dict[str, bytes],
    head_files: dict[str, bytes],
    today: Any,
    add: Any,
    config_errors: list[str],
) -> None:
    path = ".pinwash/allow.toml"
    b_txt, b_st = _text(base_files.get(path))
    h_txt, h_st = _text(head_files.get(path))
    if b_st == "unparseable":
        config_errors.append("base allow.toml unreadable as utf-8")
    if b_st != "ok":
        return
    base_recs = parse_allow_toml(b_txt) if b_txt else []
    # A head file that is missing or unparseable cannot confirm that a base
    # exemption still stands; SPEC §10 makes deleting/rewriting one
    # CONFIG_RELAXED at critical, so the check is fail-closed here.
    head_recs = parse_allow_toml(h_txt) if h_st == "ok" and h_txt else []
    base_fps = {r.get("fingerprint", "") for r in base_recs if r.get("fingerprint")}
    head_fps = {r.get("fingerprint", "") for r in head_recs if r.get("fingerprint")}
    if base_fps and not head_fps.issuperset(base_fps):
        add(
            rule="CONFIG_RELAXED",
            severity="critical",
            message="base exemption deleted or rewritten",
            path=path,
        )
    elif head_fps - base_fps:
        add(
            rule="EXEMPTION_ADDED",
            severity="warn",
            message="head allow.toml append-only additions are visible, not trusted for this run",
            path=path,
        )


def _apply_allow(
    findings: list[dict[str, Any]],
    base_files: dict[str, bytes],
    today: Any,
) -> list[dict[str, Any]]:
    path = ".pinwash/allow.toml"
    text, status = _text(base_files.get(path))
    if status != "ok" or text is None:
        return findings
    allowed = set()
    for rec in parse_allow_toml(text):
        if allow_valid(rec, today) and rec.get("fingerprint"):
            allowed.add((rec["fingerprint"], rec.get("rule", "")))
    kept: list[dict[str, Any]] = []
    for item in findings:
        key = (item["fingerprint"], item["rule"])
        if key in allowed:
            continue
        kept.append(item)
    return kept


def scan_repo(repo_path: str, range_arg: str | None) -> tuple[dict[str, Any], int]:
    from pathlib import Path

    repo = Path(repo_path)
    try:
        base_spec, head_spec, base_label, head_label = resolve_range(repo, range_arg)
        base_files = ls_tree(repo, base_spec)
        head_files = ls_tree(repo, head_spec)
    except GitError as exc:
        return {"error": exc.message}, 2
    payload = scan_pair(
        base_files,
        head_files,
        base_label=base_label,
        head_label=head_label,
    )
    code = 1 if payload["verdict"] == "block" else 0
    return payload, code
