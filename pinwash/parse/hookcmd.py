"""Hook command strings: closed target resolution (§3.3) and body stub sets (§5.2)."""

from __future__ import annotations

import re

from pinwash.hooks import extract_event_hooks
from pinwash.parse.jsonsurf import json_load
from pinwash.surfaces import is_claude_settings, is_cursor_hooks, norm
from pinwash.textutil import crlf_to_lf, decode_utf8

_HOOK_TARGET_RE = re.compile(r"[A-Za-z0-9_./-]+\.(?:py|sh|bash|js|mjs|cjs|ps1)")

# §5.2 body stub sets: a body whose every non-blank, non-comment line is in
# the extension's set is a stub. Real judges have work lines.
_BODY_LINES: dict[str, frozenset[str]] = {
    "py": frozenset(
        {
            "pass",
            "import sys",
            "import os",
            'if __name__ == "__main__":',
            "sys.exit(0)",
            "os._exit(0)",
            "exit(0)",
            "quit()",
            "raise SystemExit",
            "raise SystemExit(0)",
            "print('{}')",
            'print("{}")',
        }
    ),
    "sh": frozenset({"exit 0", "true", ":"}),
    "bash": frozenset({"exit 0", "true", ":"}),
    "js": frozenset({"process.exit(0)", "process.exit(0);"}),
    "mjs": frozenset({"process.exit(0)", "process.exit(0);"}),
    "cjs": frozenset({"process.exit(0)", "process.exit(0);"}),
    "ps1": frozenset({"exit 0"}),
}

_PY_PURE_INERT = frozenset(
    {"pass", "import sys", "import os", 'if __name__ == "__main__":'}
)

_BLOCK_MARKERS = ("block", "deny")
# SPEC §5.2 (spec 25, AI-assisted ruling, #11): the closed exit-2 forms.
# Claude Code reads a hook's exit status 2 as a blocking error, as it reads
# {"decision": "block"} (executed on 2.1.42 and 2.1.296 for Stop). `exit 2`,
# `exitcode = 2` and `exitcode=2` count where the character after them is
# not an ASCII digit, `>` or `<`, or the text ends there, so `exit 2` is not
# `exit 20` and not the redirection `exit 2>/dev/null`; `exit(2)` counts
# wherever it occurs (its `)` closes the argument: `process.exit(2)>0`
# refuses, executed), inside `sys.exit(2)`, `os._exit(2)`,
# `process.exit(2)`, `[Environment]::Exit(2)` and `SetShouldExit(2)` too
# (texts are casefolded first).
_EXIT2_FORMS = ("exit 2", "exit(2)", "exitcode = 2", "exitcode=2")
_NOT_AFTER = frozenset("0123456789<>")


def exit2_count(folded: str) -> int:
    """Occurrences of the closed exit-2 forms in casefolded text."""
    n = 0
    for form in _EXIT2_FORMS:
        start = folded.find(form)
        while start != -1:
            end = start + len(form)
            if form.endswith(")") or end == len(folded) or folded[end] not in _NOT_AFTER:
                n += 1
            start = folded.find(form, start + 1)
    return n


def body_lost_block_capability(base_data: bytes, head_data: bytes) -> bool:
    """SPEC §5.2 (spec 7): a block-capable judge that can no longer refuse.

    Shape-preserving gut jobs keep the function frame and drop every
    block/deny path; the closed-line stub list cannot see them, this
    shape can. Since spec 25 a head body that mentions the closed exit-2
    forms more often than the base body keeps block capability: a refactor
    that moved refusal from `block` to exit status 2. Exit-2 forms the base
    already held do not count, so boilerplate such as `|| exit 2` left
    behind by a gut does not hide it.
    """
    def folded_of(data: bytes) -> str | None:
        text = decode_utf8(data)
        if text is None:
            return None
        return crlf_to_lf(text).casefold()

    base_f = folded_of(base_data)
    if base_f is None or not any(m in base_f for m in _BLOCK_MARKERS):
        return False
    head_f = folded_of(head_data)
    if head_f is None:
        return True
    if any(m in head_f for m in _BLOCK_MARKERS):
        return False
    return exit2_count(head_f) <= exit2_count(base_f)


def hook_command_targets(command: str, files: dict[str, bytes]) -> list[str]:
    """§3.3 closed resolution: command string -> repo-relative target paths."""
    text = command.strip().strip("\"'")
    for ch in ";&|":
        text = text.replace(ch, " ")
    out: list[str] = []
    for tok in text.split():
        if not _HOOK_TARGET_RE.fullmatch(tok):
            continue
        if tok.startswith(("/", "-", "~")):
            continue
        p = norm(tok)
        if p in files:
            out.append(p)
    return out


def body_scan(path: str, data: bytes) -> tuple[bool, str]:
    """Return (is_stub, evidence) for a resolved hook body (§5.2)."""
    text = decode_utf8(data)
    if text is None:
        return False, ""
    allowed = _BODY_LINES.get(path.rsplit(".", 1)[-1])
    if allowed is None:
        return False, ""
    ext = path.rsplit(".", 1)[-1]
    # §2 folds CRLF to LF. A shell reads a lone CR as an ordinary character,
    # not a line break: a judge rewritten with lone CRs is one line, and when
    # it starts with `#!` the shell runs it as a comment. Python, JavaScript
    # and PowerShell read a lone CR as a line break, so for them it folds.
    unfolded = text.replace("\r\n", "\n") if ext in ("sh", "bash") else crlf_to_lf(text)
    lines = [
        ln.strip()
        for ln in unfolded.split("\n")
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if not lines:
        return True, ""
    if all(ln in allowed for ln in lines):
        action = next((ln for ln in lines if ln not in _PY_PURE_INERT), lines[0])
        return True, action
    return False, next((ln for ln in lines if ln not in allowed), "")


def command_body_map(
    files: dict[str, bytes],
    base_files: dict[str, bytes] | None = None,
) -> tuple[dict[str, tuple[bool, bool, str]], set[str]]:
    """Per side: command -> (all targets stub, lost block capability,
    evidence), plus target paths. The block-capability shape compares each
    target's head body against the same path at base (§5.2, spec 7)."""
    bodies: dict[str, tuple[bool, bool, str]] = {}
    targets_all: set[str] = set()
    # Each body is read once per side, however many commands name it.
    scan_cache: dict[str, tuple[bool, str]] = {}
    lost_cache: dict[str, bool] = {}
    for path in sorted(files):
        if not (is_claude_settings(path) or is_cursor_hooks(path)):
            continue
        obj, st = json_load(files.get(path))
        if st != "ok":
            continue
        for info in extract_event_hooks(obj).values():
            for cmd in info["commands"]:
                if cmd in bodies:
                    continue
                targets = hook_command_targets(cmd, files)
                if not targets:
                    continue
                targets_all.update(targets)
                for t in targets:
                    if t not in scan_cache:
                        scan_cache[t] = body_scan(t, files[t])
                scans = [scan_cache[t] for t in targets]
                all_stub = all(s[0] for s in scans)
                lost_block = False
                if base_files is not None:
                    for t in targets:
                        if t not in lost_cache:
                            b = base_files.get(t)
                            lost_cache[t] = b is not None and body_lost_block_capability(b, files[t])
                        if lost_cache[t]:
                            lost_block = True
                            break
                evidence = next((s[1] for s in scans if s[1]), "")
                if lost_block and not evidence:
                    evidence = "block capability removed"
                bodies[cmd] = (all_stub, lost_block, evidence)
    return bodies, targets_all
