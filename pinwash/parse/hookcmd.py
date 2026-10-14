"""Hook command strings: closed target resolution (§3.3) and body stub sets (§5.2)."""

from __future__ import annotations

import re
from typing import Callable

from pinwash.hooks import command_holders, extract_event_hooks
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


# SPEC §3.3 (spec 26, AI-assisted ruling R-18a(c), #18): the closed
# project-root forms of a claude_settings command. Claude Code runs a hook
# with CLAUDE_PROJECT_DIR set to the project root whose settings it reads
# (the launch directory, or 2.1.296's --project-config-root), after the
# settings `env` and the launching environment (executed on 2.1.42 and
# 2.1.296: neither redirects it).
_ROOT_FORMS = (
    '"$CLAUDE_PROJECT_DIR"/',
    '"${CLAUDE_PROJECT_DIR}"/',
    "$CLAUDE_PROJECT_DIR/",
    "${CLAUDE_PROJECT_DIR}/",
)
# Quoted to the end of the path: the closing `"` ends the path.
_ROOT_FORMS_QUOTED = ('"$CLAUDE_PROJECT_DIR/', '"${CLAUDE_PROJECT_DIR}/')
_PATH_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-"
)
# What may follow a path inside its word: the start of an operator or a
# redirection. The run of read words ends there.
_WORD_END = frozenset(";&|<>")
# A plain word (an interpreter, a flag, an assignment) is printable ASCII
# (`!` to `~`) without any of these: nothing in it parameter-expands,
# quotes, runs, groups, redirects or comments (review of 2026-10-10: a
# character the shell does not split at, such as CR or NBSP, ends the run).
_PLAIN_FORBIDDEN = frozenset("$`\"'\\;&|()<>{}#")


def _root_word(word: str) -> tuple[str, bool] | None:
    """(the repo-relative path a root-form word names, with any operator or
    redirection after it; whether the run of read words goes on), or None."""
    for form in _ROOT_FORMS_QUOTED:
        if word.startswith(form):
            rest = word[len(form):]
            end = rest.find('"')
            if end <= 0:
                return None
            path, tail = rest[:end], rest[end + 1:]
            if tail and tail[0] not in _WORD_END:
                return None
            if path.startswith("/") or any(ch not in _PATH_CHARS for ch in path):
                return None
            return path + tail, not tail
    for form in _ROOT_FORMS:
        if word.startswith(form):
            rest = word[len(form):]
            n = 0
            while n < len(rest) and rest[n] in _PATH_CHARS:
                n += 1
            path, tail = rest[:n], rest[n:]
            if not path or path.startswith("/"):
                return None
            if tail and tail[0] not in _WORD_END:
                return None
            return path + tail, not tail
    return None


def strip_project_root(command: str) -> str:
    """SPEC §3.3 (spec 26): rewrite the closed project-root forms that stand
    in the command's leading run of words, before anything that could
    expand, quote, group, run or redirect; the rest is kept as written.

    Words split at spaces and tabs. The run goes on over plain words and
    root-form words, and stops at the first other word, or after a root-form
    word whose path an operator or a redirection follows."""
    # Only the blanks the shell splits at (review of 2026-10-10: Python's
    # strip() also took CR, VT, FF and NBSP, which the shell keeps in a word).
    text = command.strip(" \t\n")
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        j = i
        while j < n and text[j] not in " \t":
            j += 1
        word = text[i:j]
        root = _root_word(word)
        if root is not None:
            out.append(root[0])
            if not root[1]:
                out.append(text[j:])
                return "".join(out)
        elif all("!" <= ch <= "~" and ch not in _PLAIN_FORBIDDEN for ch in word):
            out.append(word)
        else:
            out.append(text[i:])
            return "".join(out)
        k = j
        while k < n and text[k] in " \t":
            k += 1
        out.append(text[j:k])
        i = k
    return "".join(out)


def hook_command_targets(
    command: str, files: dict[str, bytes], *, project_root: bool = False
) -> list[str]:
    """§3.3 closed resolution: command string -> repo-relative target paths.

    `project_root` reads the closed project-root forms (a claude_settings
    command some hook object holds without `args` or a non-bash `shell`)."""
    if project_root:
        command = strip_project_root(command)
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


def root_form_guard(files: dict[str, bytes]) -> frozenset[str]:
    """SPEC §3.3 (spec 26): the commands of this side's claude_settings files
    that only hook objects holding `args` (the exec form) or a `shell` other
    than "bash" hold. Claude Code 2.1.296 does not run those through a POSIX
    shell, so the project-root forms need not name a repo path there
    (EXECUTED: the exec form with `$CLAUDE_PROJECT_DIR/` runs a directory so
    named, and `shell: "powershell"` does not run the file). A string that
    any other hook object holds is read: that object runs it through the
    shell (EXECUTED: an added same-string object with `args` or `shell`
    changes nothing the host runs for the other)."""
    guarded: set[str] = set()
    plain: set[str] = set()
    for path in sorted(files):
        if not is_claude_settings(path):
            continue
        obj, st = json_load(files.get(path))
        if st == "ok":
            g, p = command_holders(obj)
            guarded |= g
            plain |= p
    return frozenset(guarded - plain)


def resolver(
    files: dict[str, bytes], *, claude: bool, guard: frozenset[str] = frozenset()
) -> Callable[[str], list[str]]:
    """command -> §3.3 targets on one side, for one hook surface kind."""
    cache: dict[str, list[str]] = {}

    def targets(cmd: str) -> list[str]:
        got = cache.get(cmd)
        if got is None:
            got = hook_command_targets(cmd, files, project_root=claude and cmd not in guard)
            cache[cmd] = got
        return got

    return targets


def command_body_map(
    files: dict[str, bytes],
    base_files: dict[str, bytes] | None = None,
    *,
    claude: bool,
    guard: frozenset[str] = frozenset(),
) -> tuple[dict[str, tuple[bool, bool, str]], set[str]]:
    """Per side and hook surface kind (claude_settings when `claude`, else
    cursor_hooks): command -> (all targets stub, lost block capability,
    evidence), plus target paths. The block-capability shape compares each
    target's head body against the same path at base (§5.2, spec 7)."""
    bodies: dict[str, tuple[bool, bool, str]] = {}
    targets_all: set[str] = set()
    # Each body is read once per side, however many commands name it.
    scan_cache: dict[str, tuple[bool, str]] = {}
    lost_cache: dict[str, bool] = {}
    refuse_cache: dict[str, tuple[bool, bool]] = {}
    resolve = resolver(files, claude=claude, guard=guard)
    for path in sorted(files):
        if not (is_claude_settings(path) if claude else is_cursor_hooks(path)):
            continue
        obj, st = json_load(files.get(path))
        if st != "ok":
            continue
        for info in extract_event_hooks(obj, claude=claude).values():
            for cmd in info["commands"]:
                if cmd in bodies:
                    continue
                targets = resolve(cmd)
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
                for t in targets:
                    if t not in refuse_cache:
                        refuse_cache[t] = (
                            body_can_refuse(files[t], not claude),
                            body_has_decision_literal(files[t], not claude),
                        )
                bodies[cmd] = (
                    all_stub,
                    lost_block,
                    evidence,
                    any(refuse_cache[t][0] for t in targets),
                    tuple(targets),
                    any(refuse_cache[t][1] for t in targets),
                )
    return bodies, targets_all


# SPEC §5.2 / §6.1 (spec 27, R12, #10): a body *can refuse* when it
# mentions `block` or `deny` (the spec 7 marker) or holds a spec 25 exit-2
# form; on cursor_hooks also when it holds Cursor's stop output key
# `followup_message`. The retarget disjunct (§5) needs a quoted decision
# literal in the base body, the values Claude Code reads from a hook's JSON
# output, or `followup_message` on cursor_hooks.
_DECISION_LITERALS = ('"block"', "'block'", '\\"block\\"', '"deny"', "'deny'", '\\"deny\\"')


def _folded(data: bytes) -> str | None:
    text = decode_utf8(data)
    return None if text is None else crlf_to_lf(text).casefold()


def body_can_refuse(data: bytes, cursor: bool = False) -> bool:
    f = _folded(data)
    return f is not None and (any(m in f for m in _BLOCK_MARKERS) or exit2_count(f) > 0
                              or (cursor and "followup_message" in f))


def body_has_decision_literal(data: bytes, cursor: bool = False) -> bool:
    f = _folded(data)
    return f is not None and (any(m in f for m in _DECISION_LITERALS) or (cursor and "followup_message" in f))
