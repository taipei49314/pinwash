"""Orchestration: git trees -> surface dispatch -> rules -> allow -> envelope.

Never executes subject code. Never uses the network. Detectors live in
pinwash/rules, parsers in pinwash/parse, escalators in pinwash/escalate,
the exemption channel in pinwash/allow.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Any

from pinwash.allow import apply_allow, detect_allow
from pinwash.textutil import canonical_text
from pinwash.findings import envelope, make_finding
from pinwash.parse.gha import parse_workflow
from pinwash.parse.hookcmd import command_body_map, resolver, root_form_guard
from pinwash.parse.jsonsurf import json_load, text_load
from pinwash.parse.tomlsub import pinwash_today
from pinwash.gitrepo import (
    WORKTREE,
    GitError,
    ignored_surface_paths,
    ls_tree,
    ls_worktree,
    resolve_range,
)
from pinwash.hooks import CLAUDE_STOP_EVENTS, CURSOR_STOP_EVENTS, extract_event_hooks
from pinwash.rules import (
    config_rule,
    hook_coverage,
    hook_env,
    hook_rules,
    hook_switch,
    hook_selector,
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
    glob_skill,
    norm,
)


# SPEC §3 / §7 (spec 16, AI-assisted ruling on #22): the status pairs the
# closed table below does not report are unknown_coverage rows, never
# findings.
NEW_UNPARSEABLE = "new surface file unparseable"
BASE_UNPARSEABLE = "surface unparseable at base"
NONCOMMAND_HANDLER = "non-command hook handler changed (not evaluated)"
ASYNC_UNKNOWN = "hook async value not boolean"
EVENT_KEYS = "hook event keys changed (host validity not evaluated)"
# SPEC §2 / §7 (spec 16, AI-assisted ruling on #17, R21): working-tree
# entries at surface paths that the worktree read does not open.
IGNORED_SURFACE = "untracked surface file matched by an ignore rule, not read"
IGNORED_SURFACE_DIR = "untracked surface files under this directory matched by an ignore rule, not read"
UNREAD_SURFACE_DIR = (
    "untracked surface directory git does not descend (nested repository or symlink), not read"
)


def _surface_unparseable(b_st: str, h_st: str) -> tuple[str, str] | None:
    """SPEC §3 closed table.

    (ok, unparseable) -> high; (unparseable, unparseable) -> warn.
    No other status pair is a finding: a file absent at base never weakens,
    and a head that parses is not a weakening of a corrupt base. Since spec
    16, (missing, unparseable), (unparseable, ok) and (unparseable, missing)
    are rows (`status_gate` in `scan_pair`).
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


# SPEC §3 (spec 20, AI-assisted ruling R-22a on #22, the challenger's
# amendment): these surfaces are decoded as their host decodes them before
# the JSON parse. Claude Code reads its settings as UTF-16LE when the file
# starts FF FE (a trailing odd byte dropped, as Node's decoder drops it),
# else as UTF-8 with U+FFFD for bad bytes, and drops one leading byte order
# mark; `.mcp.json` the same without UTF-16; gemini-cli
# (Node, UTF-8) replaces bad bytes and keeps a byte order mark.
_CLAUDE_SETTINGS = frozenset({".claude/settings.json", ".claude/settings.local.json"})


def _host_decoded(path: str, data: bytes) -> bytes:
    p = norm(path)
    if p in _CLAUDE_SETTINGS and data[:2] == b"\xff\xfe":
        text = data[: len(data) - len(data) % 2].decode("utf-16-le", errors="replace")
    elif p in _CLAUDE_SETTINGS or p in (".mcp.json", ".gemini/settings.json"):
        text = data.decode("utf-8", errors="replace")
    else:
        return data
    if text.startswith("\ufeff") and p != ".gemini/settings.json":
        text = text[1:]
    return text.encode("utf-8", "surrogatepass")


def _host_view(files: dict[str, bytes]) -> dict[str, bytes]:
    return {path: _host_decoded(path, data) for path, data in files.items()}


def scan_pair(
    base_files: dict[str, bytes],
    head_files: dict[str, bytes],
    *,
    base_label: str,
    head_label: str,
    env: dict[str, str] | None = None,
    unobserved: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    env = env if env is not None else dict(os.environ)
    findings: list[dict[str, Any]] = []
    # Inputs the caller could not observe (SPEC §1.6): working-tree entries
    # the read does not open (§2, R21; spec 16). Visibility only (§7).
    unknown: list[dict[str, str]] = list(unobserved or [])
    config_errors: list[str] = []
    today = pinwash_today(env)
    base_files = _host_view(base_files)
    head_files = _host_view(head_files)

    def add(**kwargs: Any) -> None:
        findings.append(make_finding(**kwargs))

    def note_unknown(path: str, reason: str) -> None:
        """SPEC §7: each (path, reason) row is reported once."""
        row = {"path": path, "reason": reason}
        if row not in unknown:
            unknown.append(row)

    def status_gate(path: str, b_st: str, h_st: str) -> bool:
        """SPEC §3: the parse-status pair of `path`. True when it ends the
        comparison: a `SURFACE_UNPARSEABLE` finding, or a new file pinwash
        cannot parse (a row). A corrupt base is a row, and the comparison
        goes on as before (spec 16, #22)."""
        unp = _surface_unparseable(b_st, h_st)
        if unp:
            add(rule="SURFACE_UNPARSEABLE", severity=unp[0], message=unp[1], path=path)
            return True
        if b_st == "missing" and h_st == "unparseable":
            note_unknown(path, NEW_UNPARSEABLE)
            return True
        if b_st == "unparseable":
            note_unknown(path, BASE_UNPARSEABLE)
        return False

    changed_cache: list[list[str]] = []

    def changed() -> list[str]:
        """Paths the diff changed (§3.3 rows), computed once per run."""
        if not changed_cache:
            changed_cache.append(hook_coverage.changed_paths(base_files, head_files))
        return changed_cache[0]

    changed_set_cache: list[set[str]] = []

    def changed_set() -> set[str]:
        if not changed_set_cache:
            changed_set_cache.append(set(changed()))
        return changed_set_cache[0]

    paths = _union_paths(base_files, head_files)

    calls_cache: dict[str, tuple[list[str], bool]] = {}

    def _calls_and_callable(path: str) -> tuple[list[str], bool]:
        """Job-level `uses:` values of a workflow file on either side, and
        whether its `on:` names `workflow_call` on either side (§5.5
        reusable-workflow producers; spec 14 review), parsed once per run."""
        if path not in calls_cache:
            found: list[str] = []
            callable_wf = False
            if is_gha_workflow(path):
                for files in (base_files, head_files):
                    txt, st = text_load(files.get(path))
                    if st == "ok" and txt is not None:
                        g = parse_workflow(txt)
                        if not g.unparseable:
                            found.extend(j.calls for j in g.jobs.values() if j.calls)
                            callable_wf = callable_wf or "workflow_call" in g.triggers
            calls_cache[path] = (found, callable_wf)
        return calls_cache[path]

    def calls_of(path: str) -> list[str]:
        return _calls_and_callable(path)[0]

    # SPEC §3.3 / §5.2: resolve hook command targets per side, then scan
    # their bodies. Targets become claude_hooks surface members. The head
    # side compares against base bodies for the block-capability shape.
    # SPEC §3.3 (spec 26): claude_settings commands also resolve the closed
    # project-root forms, unless only hook objects holding `args` or a
    # `shell` other than "bash" hold the string; cursor_hooks commands do not. Each kind has its own
    # body map, so a string both surfaces hold resolves per surface.
    guard_base = root_form_guard(base_files)
    guard_head = root_form_guard(head_files)
    kind_bodies: dict[bool, tuple[Any, Any]] = {}
    kind_resolvers: dict[bool, tuple[Any, Any]] = {}
    targets_base: set[str] = set()
    targets_head: set[str] = set()
    for claude_kind in (True, False):
        g_b = guard_base if claude_kind else frozenset()
        g_h = guard_head if claude_kind else frozenset()
        bb, tb = command_body_map(base_files, claude=claude_kind, guard=g_b)
        bh, th = command_body_map(head_files, base_files=base_files, claude=claude_kind, guard=g_h)
        kind_bodies[claude_kind] = (bb, bh)
        kind_resolvers[claude_kind] = (
            resolver(base_files, claude=claude_kind, guard=g_b),
            resolver(head_files, claude=claude_kind, guard=g_h),
        )
        targets_base |= tb
        targets_head |= th
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
    # SPEC §5 (spec 23, R16): the head side of a rename, the contexts a head
    # ruleset names and those a head job reports on the enforcement path.
    head_contexts: set[str] = set()
    for path in paths:
        if is_gha_ruleset(path):
            h_obj, h_st = json_load(head_files.get(path))
            if h_st == "ok":
                head_contexts.update(ruleset_contexts(h_obj))
    head_reporting = required_check.head_reporters(
        [text_load(head_files.get(path)) for path in paths if is_gha_workflow(path)]
        if base_contexts else []
    )
    base_folded = required_check.fold_contexts(base_contexts)
    head_folded = required_check.fold_contexts(head_contexts)

    # SPEC §5.3 (spec 18): the host merges the allow lists of both settings
    # files, so a base entry in either one grants its class.
    base_allow = permission.base_allow_union([
        obj for obj, st in (json_load(base_files.get(path)) for path in paths if is_claude_settings(path))
        if st == "ok"
    ])

    # SPEC §5.3 (spec 17): `permissions.defaultMode` is compared on the
    # value in effect across both settings files, not per file.
    mode_files: dict[str, tuple[str, Any, str, Any, str]] = {}
    for path in paths:
        if is_claude_settings(path) and norm(path) not in mode_files:
            b_obj, b_st = json_load(base_files.get(path))
            h_obj, h_st = json_load(head_files.get(path))
            if b_st == "unparseable":
                # Spec 20: the host ran without a base it could not parse.
                b_obj, b_st = None, "missing"
            mode_files[norm(path)] = (path, b_obj, b_st, h_obj, h_st)
    if mode_files:
        permission.detect_claude_mode(mode_files, add, note_unknown)

    # SPEC §5.1 (spec 24): the settings-root `disableAllHooks`, read on the
    # value in effect across the two settings files (local over project) and
    # on the shared file alone, as Claude Code may load them: a side it
    # cannot parse defines nothing.
    switch_files = {
        key: (path, b_obj if b_st == "ok" else None, h_obj if h_st == "ok" else None)
        for key, (path, b_obj, b_st, h_obj, h_st) in mode_files.items()
    }
    switch_path = hook_switch.detect(switch_files, kind_bodies[True][0], hook_rules.live_stop_events, add)
    hook_env.detect(switch_files, base_files, head_files, kind_bodies[True][0], add, note_unknown)
    if switch_path is None:
        # No command was active at base, yet the value in effect became
        # `true` (a local `false` removed under a shared `true`): the row.
        flipped = hook_switch.flipped_in_effect(switch_files)
        if flipped is not None:
            note_unknown(flipped, hook_coverage.DISABLE_ALL_HOOKS)

    switch_anywhere = any(
        hook_coverage.switch_set(doc)
        for (_p, b_obj, b_st, h_obj, h_st) in mode_files.values()
        for doc, st in ((b_obj, b_st), (h_obj, h_st))
        if st == "ok"
    )
    for path in paths:
        if is_claude_settings(path) or is_cursor_hooks(path):
            b_obj, b_st = json_load(base_files.get(path))
            h_obj, h_st = json_load(head_files.get(path))
            if status_gate(path, b_st, h_st):
                continue
            stop_names = (
                CLAUDE_STOP_EVENTS if is_claude_settings(path) else CURSOR_STOP_EVENTS
            )
            base_ev = extract_event_hooks(b_obj, claude=is_claude_settings(path)) if b_st == "ok" else {}
            head_ev = extract_event_hooks(h_obj, claude=is_claude_settings(path)) if h_st == "ok" else {}
            base_doc = b_obj if b_st == "ok" else None
            head_doc = h_obj if h_st == "ok" else None

            def note(reason: str, _path: str = path) -> None:
                note_unknown(_path, reason)

            n_before = len(findings)
            claude_kind = is_claude_settings(path)
            if claude_kind:
                for event in sorted(set(base_ev) | set(head_ev)):
                    before_handlers = base_ev.get(event, {}).get("non_commands", [])
                    after_handlers = head_ev.get(event, {}).get("non_commands", [])
                    if after_handlers and canonical_text(before_handlers) != canonical_text(after_handlers):
                        note(NONCOMMAND_HANDLER)
                b_hooks = base_doc.get("hooks") if isinstance(base_doc, dict) else None
                h_hooks = head_doc.get("hooks") if isinstance(head_doc, dict) else None
                b_keys = {k for k in b_hooks if isinstance(k, str)} if isinstance(b_hooks, dict) else set()
                h_keys = {k for k in h_hooks if isinstance(k, str)} if isinstance(h_hooks, dict) else set()
                if h_keys != b_keys:
                    note(EVENT_KEYS)
                def opaque_async(doc: Any) -> Counter:
                    return Counter((e, h.get("command"), canonical_text(h["async"]))
                                   for e, h in hook_env.handlers(doc)
                                   if e == "Stop" and h.get("type", "command") == "command"
                                   and isinstance(h.get("command"), str) and "async" in h
                                   and not isinstance(h["async"], bool))
                if opaque_async(head_doc) - opaque_async(base_doc):
                    note(ASYNC_UNKNOWN)
            body_base, body_head = kind_bodies[claude_kind]
            res_base, res_head = kind_resolvers[claude_kind]
            hook_rules.detect(
                path, base_ev, head_ev, stop_names, add, body_base, body_head,
                note_unknown=note,
            )
            # SPEC §3.3 / §5.1 / §7 (spec 13): hook-side unknown coverage.
            # Rows never add, drop or change a finding, so never the verdict.
            hook_selector.detect(
                path, base_doc, head_doc, base_files, head_files, note,
                targets=(res_base, res_head),
            )
            hook_coverage.detect(
                claude_settings=is_claude_settings(path),
                base_doc=base_doc,
                head_doc=head_doc,
                base_ev=base_ev,
                head_ev=head_ev,
                base_files=base_files,
                head_files=head_files,
                changed=changed,
                hook_finding=len(findings) > n_before,
                note_unknown=note,
                switch_finding=path == switch_path,
                switch_anywhere=is_claude_settings(path) and switch_anywhere,
                targets=(res_base, res_head),
            )
            # SPEC §3 (spec 20): Claude Code rejects a settings file it
            # cannot parse, so a head that parses is compared against an
            # absent base when the base does not parse.
            if is_claude_settings(path) and h_st == "ok":
                permission.detect_claude_settings(
                    path,
                    b_obj if b_st == "ok" else None,
                    h_obj,
                    add,
                    base_union=base_allow,
                )
            if is_claude_settings(path) and h_st != "unparseable":
                # SPEC §5.3 / §7 (spec 16, R17): permission changes the closed
                # comparisons do not evaluate, a deleted file included; an
                # unparseable base reads as absent (spec 20).
                permission.route_claude_settings(base_doc, head_doc, note, base_union=base_allow)
        elif is_claude_hooks_file(path) or path in targets_base or path in targets_head:
            # Surface membership for .claude/hooks/** and §3.3 targets: the
            # §3 parse-status check applies — do not skip the file.
            if path.endswith(".json"):
                _bobj, b_st = json_load(base_files.get(path))
                _hobj, h_st = json_load(head_files.get(path))
                status_gate(path, b_st, h_st)
                continue
            b_txt, b_st = text_load(base_files.get(path))
            h_txt, h_st = text_load(head_files.get(path))
            if status_gate(path, b_st, h_st):
                continue
            if glob_skill(path) and h_st == "ok" and h_txt is not None:
                # SPEC §5.4 (spec 21): a SKILL.md under .claude/hooks/ is a
                # skill_md path too, so the phrase table reads it.
                base_s = b_txt if b_st == "ok" and b_txt is not None else ""
                skill_bypass.detect(path, base_s, h_txt, add)
        elif is_gha_workflow(path):
            b_txt, b_st = text_load(base_files.get(path))
            h_txt, h_st = text_load(head_files.get(path))
            base_g = parse_workflow(b_txt) if b_st == "ok" and b_txt is not None else None
            head_g = parse_workflow(h_txt) if h_st == "ok" and h_txt is not None else None
            b_eff = _workflow_status(b_st, base_g)
            h_eff = _workflow_status(h_st, head_g)
            if status_gate(path, b_eff, h_eff):
                continue
            # #4: a base-side residual can hide a comparison as well as a
            # head-side one; each (path, reason) is reported once.
            # Spec 14 review: the job-table grammar rows hide only what the
            # §5 producer reading consumes, so they are reported for a file
            # the diff changed while a base ruleset names a context; or, for
            # a job table read only in part, while the diff changes another
            # workflow that can be called, which a job it does not read may
            # call.
            job_rows = bool(base_contexts) and (
                b_txt != h_txt
                or (
                    any(
                        side is not None and not side.unparseable and side.job_table_partial()
                        for side in (base_g, head_g)
                    )
                    and any(
                        p != path and is_gha_workflow(p) and _calls_and_callable(p)[1]
                        for p in changed_set()
                    )
                )
            )
            reasons: list[str] = []
            for side in (head_g, base_g):
                if side is None or side.unparseable:
                    continue
                for reason in side.unknown + (side.job_unknown if job_rows else []):
                    if reason not in reasons:
                        reasons.append(reason)
            for reason in reasons:
                note_unknown(path, reason)

            def note_gha(reason: str, _path: str = path) -> None:
                note_unknown(_path, reason)

            pin_rules.detect_workflow_pins(path, base_g, head_g, add)
            # SPEC §5 findings and the §5.5 producer rows (spec 14); a row
            # never adds, drops or changes a finding, so never the verdict.
            required_check.detect_jobs(
                path, base_g, head_g, base_contexts, add,
                note=note_gha, changed=lambda p: p in changed_set(),
                calls_of=calls_of, head_contexts=head_folded,
                head_reporting=head_reporting, base_folded=base_folded,
            )
        elif is_gha_ruleset(path):
            b_obj, b_st = json_load(base_files.get(path))
            h_obj, h_st = json_load(head_files.get(path))
            if status_gate(path, b_st, h_st):
                continue
            base_ctx = ruleset_contexts(b_obj) if b_st == "ok" else []
            head_ctx = ruleset_contexts(h_obj) if h_st == "ok" else []
            required_check.detect_ruleset(path, base_ctx, head_ctx, add)
        elif is_cursor_mcp(path):
            b_obj, b_st = json_load(base_files.get(path))
            h_obj, h_st = json_load(head_files.get(path))
            if status_gate(path, b_st, h_st):
                continue
            # SPEC §3 (spec 20): Claude Code reads `.mcp.json` strictly, so
            # its head is compared against an absent base when the base does
            # not parse; Cursor's reader is not evidenced (R19).
            if h_st == "ok" and (b_st != "unparseable" or norm(path) == ".mcp.json"):
                permission.detect_mcp(
                    path,
                    b_obj if b_st == "ok" else None,
                    h_obj,
                    add,
                )
        elif is_gemini_settings(path) or is_opencode_config(path):
            b_obj, b_st = json_load(base_files.get(path))
            h_obj, h_st = json_load(head_files.get(path))
            if status_gate(path, b_st, h_st):
                continue
            if b_st != "unparseable" and h_st == "ok":
                base_doc = b_obj if b_st == "ok" else None
                if is_gemini_settings(path):
                    permission.detect_gemini_settings(path, base_doc, h_obj, add)
                else:
                    permission.detect_opencode_config(path, base_doc, h_obj, add)
            if "unparseable" not in (b_st, h_st):
                # SPEC §5.3 / §7 (spec 16, R17): values off their lattice.
                route = (
                    permission.route_gemini_settings
                    if is_gemini_settings(path)
                    else permission.route_opencode_config
                )
                route(
                    b_obj if b_st == "ok" else None,
                    h_obj if h_st == "ok" else None,
                    lambda reason, _path=path: note_unknown(_path, reason),
                )
        elif is_declared_pins(path):
            b_obj, b_st = json_load(base_files.get(path))
            h_obj, h_st = json_load(head_files.get(path))
            if status_gate(path, b_st, h_st):
                continue
            if b_st != "ok":
                continue
            pin_rules.detect_declared_pins(path, b_obj, h_obj if h_st == "ok" else None, add)
        elif is_checkwash_config(path):
            # SPEC §3.2 / §5 (spec 19): read as checkwash reads it, so a
            # config is never unparseable; the configs in force are
            # compared once, after this loop.
            continue
        elif glob_skill(path) or is_agent_markdown(path):
            b_txt, b_st = text_load(base_files.get(path))
            h_txt, h_st = text_load(head_files.get(path))
            if status_gate(path, b_st, h_st):
                continue
            if h_st != "ok" or h_txt is None:
                continue
            base_s = b_txt if b_st == "ok" and b_txt is not None else ""
            skill_bypass.detect(path, base_s, h_txt, add)

    # SPEC §3.2: checkwash reads each path with `git show`, spelled exactly,
    # so no other spelling of it (`.checkwash\config.toml`) is its config.
    config_rule.detect(
        {p: d for p, d in base_files.items() if p in config_rule.CONFIG_ORDER},
        {p: d for p, d in head_files.items() if p in config_rule.CONFIG_ORDER},
        add,
        note_unknown,
    )

    detect_allow(base_files, head_files, today, add, config_errors)

    findings = apply_allow(findings, base_files, today)
    if switch_path is not None and not any(
        f["rule"] == "HOOK_BYPASSED" and f["path"] == switch_path
        and f.get("locator") == hook_switch.SWITCH and f["message"] == hook_switch.MESSAGE
        for f in findings
    ):
        # SPEC §5.1 (spec 24): an exempted switch finding leaves its row, so a
        # record pre-seeded at base (R18) never makes the switch silent.
        note_unknown(switch_path, hook_coverage.DISABLE_ALL_HOOKS)
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
        unobserved: list[dict[str, str]] = []
        if head_spec == WORKTREE:
            head_files, unread = ls_worktree(repo)
            ignored, ignored_dirs, ignored_unread = ignored_surface_paths(repo)
            unobserved = (
                [{"path": p, "reason": IGNORED_SURFACE} for p in ignored]
                + [{"path": p, "reason": IGNORED_SURFACE_DIR} for p in ignored_dirs]
                + [
                    {"path": p, "reason": UNREAD_SURFACE_DIR}
                    for p in sorted(set(unread) | set(ignored_unread))
                ]
            )
        else:
            head_files = ls_tree(repo, head_spec)
    except GitError as exc:
        return {"error": exc.message}, 2
    payload = scan_pair(
        base_files,
        head_files,
        base_label=base_label,
        head_label=head_label,
        unobserved=unobserved,
    )
    code = 1 if payload["verdict"] == "block" else 0
    return payload, code
