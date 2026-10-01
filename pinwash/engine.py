"""Orchestration: git trees -> surface dispatch -> rules -> allow -> envelope.

Never executes subject code. Never uses the network. Detectors live in
pinwash/rules, parsers in pinwash/parse, escalators in pinwash/escalate,
the exemption channel in pinwash/allow.
"""

from __future__ import annotations

import os
from typing import Any

from pinwash.allow import apply_allow, detect_allow
from pinwash.findings import envelope, make_finding
from pinwash.parse.gha import parse_workflow
from pinwash.parse.hookcmd import command_body_map
from pinwash.parse.jsonsurf import json_load, text_load
from pinwash.parse.tomlsub import pinwash_today
from pinwash.gitrepo import GitError, ls_tree, resolve_range
from pinwash.hooks import CLAUDE_STOP_EVENTS, CURSOR_STOP_EVENTS, extract_event_hooks
from pinwash.rules import (
    config_rule,
    hook_rules,
    permission,
    pin_rules,
    required_check,
    skill_bypass,
)
from pinwash.rules.required_check import ruleset_contexts
from pinwash.surfaces import (
    is_agent_markdown,
    is_checkwash_config,
    is_claude_hooks_file,
    is_claude_settings,
    is_cursor_hooks,
    is_cursor_mcp,
    is_declared_pins,
    is_gemini_settings,
    is_gha_ruleset,
    is_gha_workflow,
    is_opencode_config,
    is_surface,
    skill_bypass_excluded,
    glob_skill,
    norm,
)


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

    # SPEC §3.3 / §5.2: resolve hook command targets per side, then scan
    # their bodies. Targets become claude_hooks surface members. The head
    # side compares against base bodies for the block-capability shape.
    body_base, targets_base = command_body_map(base_files)
    body_head, targets_head = command_body_map(head_files, base_files=base_files)
    paths = sorted(set(paths) | targets_base | targets_head)

    # SPEC §5: the job-side REQUIRED_CHECK_DROPPED trigger is the workflow
    # job that produced a required status context named at base in
    # gha_ruleset. No base-named contexts -> no job-side findings.
    base_contexts: set[str] = set()
    for path in paths:
        if not is_gha_ruleset(path):
            continue
        b_obj, b_st = json_load(base_files.get(path))
        if b_st == "ok":
            base_contexts.update(ruleset_contexts(b_obj))

    for path in paths:
        if is_claude_settings(path) or is_cursor_hooks(path):
            b_obj, b_st = json_load(base_files.get(path))
            h_obj, h_st = json_load(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            stop_names = (
                CLAUDE_STOP_EVENTS if is_claude_settings(path) else CURSOR_STOP_EVENTS
            )
            base_ev = extract_event_hooks(b_obj) if b_st == "ok" else {}
            head_ev = extract_event_hooks(h_obj) if h_st == "ok" else {}
            hook_rules.detect(
                path, base_ev, head_ev, stop_names, add, body_base, body_head
            )
            if is_claude_settings(path) and h_st == "ok" and b_st != "unparseable":
                permission.detect_claude_settings(
                    path,
                    b_obj if b_st == "ok" else None,
                    h_obj,
                    add,
                )
        elif is_claude_hooks_file(path) or path in targets_base or path in targets_head:
            # Surface membership for .claude/hooks/** and §3.3 targets: the
            # §3 parse-status check applies — do not skip the file.
            if path.endswith(".json"):
                _bobj, b_st = json_load(base_files.get(path))
                _hobj, h_st = json_load(head_files.get(path))
            else:
                _btxt, b_st = text_load(base_files.get(path))
                _htxt, h_st = text_load(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
        elif is_gha_workflow(path):
            b_txt, b_st = text_load(base_files.get(path))
            h_txt, h_st = text_load(head_files.get(path))
            base_g = parse_workflow(b_txt) if b_st == "ok" and b_txt is not None else None
            head_g = parse_workflow(h_txt) if h_st == "ok" and h_txt is not None else None
            b_eff = _workflow_status(b_st, base_g)
            h_eff = _workflow_status(h_st, head_g)
            unp = _surface_unparseable(b_eff, h_eff)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            # #4: a base-side residual can hide a comparison as well as a
            # head-side one; each (path, reason) is reported once.
            reasons: list[str] = []
            for side in (head_g, base_g):
                if side is None or side.unparseable:
                    continue
                for reason in side.unknown:
                    if reason not in reasons:
                        reasons.append(reason)
            for reason in reasons:
                unknown.append({"path": path, "reason": reason})
            pin_rules.detect_workflow_pins(path, base_g, head_g, add)
            required_check.detect_jobs(path, base_g, head_g, base_contexts, add)
        elif is_gha_ruleset(path):
            b_obj, b_st = json_load(base_files.get(path))
            h_obj, h_st = json_load(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            base_ctx = ruleset_contexts(b_obj) if b_st == "ok" else []
            head_ctx = ruleset_contexts(h_obj) if h_st == "ok" else []
            required_check.detect_ruleset(path, base_ctx, head_ctx, add)
        elif is_cursor_mcp(path):
            b_obj, b_st = json_load(base_files.get(path))
            h_obj, h_st = json_load(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            if b_st != "unparseable" and h_st == "ok":
                permission.detect_mcp(
                    path,
                    b_obj if b_st == "ok" else None,
                    h_obj,
                    add,
                )
        elif is_gemini_settings(path) or is_opencode_config(path):
            b_obj, b_st = json_load(base_files.get(path))
            h_obj, h_st = json_load(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            if b_st != "unparseable" and h_st == "ok":
                base_doc = b_obj if b_st == "ok" else None
                if is_gemini_settings(path):
                    permission.detect_gemini_settings(path, base_doc, h_obj, add)
                else:
                    permission.detect_opencode_config(path, base_doc, h_obj, add)
        elif is_declared_pins(path):
            b_obj, b_st = json_load(base_files.get(path))
            h_obj, h_st = json_load(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            if b_st != "ok":
                continue
            pin_rules.detect_declared_pins(path, b_obj, h_obj if h_st == "ok" else None, add)
        elif is_checkwash_config(path):
            b_txt, b_st = text_load(base_files.get(path))
            h_txt, h_st = text_load(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            config_rule.detect(
                path,
                b_txt if b_st == "ok" else None,
                h_txt if h_st == "ok" else None,
                add,
            )
        elif glob_skill(path) or is_agent_markdown(path):
            if skill_bypass_excluded(path):
                continue
            b_txt, b_st = text_load(base_files.get(path))
            h_txt, h_st = text_load(head_files.get(path))
            unp = _surface_unparseable(b_st, h_st)
            if unp:
                add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
                continue
            if h_st != "ok" or h_txt is None:
                continue
            base_s = b_txt if b_st == "ok" and b_txt is not None else ""
            skill_bypass.detect(path, base_s, h_txt, add)

    detect_allow(base_files, head_files, today, add, config_errors)

    findings = apply_allow(findings, base_files, today)
    return envelope(
        base_label=base_label,
        head_label=head_label,
        findings=findings,
        config_errors=config_errors,
        unknown_coverage=unknown,
    )


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
