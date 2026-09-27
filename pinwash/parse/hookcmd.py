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


def body_lost_block_capability(base_data: bytes, head_data: bytes) -> bool:
    """SPEC §5.2 (spec 7): a block-capable judge that can no longer refuse.

    Shape-preserving gut jobs keep the function frame and drop every
    block/deny path; the closed-line stub list cannot see them, this
    shape can.
    """
    def marker(data: bytes) -> str | None:
        text = decode_utf8(data)
        if text is None:
            return None
        folded = crlf_to_lf(text).casefold()
        for m in _BLOCK_MARKERS:
            if m in folded:
                return m
        return None

    base_marker = marker(base_data)
    if base_marker is None:
        return False
    return marker(head_data) is None


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
    lines = [
        ln.strip()
        for ln in crlf_to_lf(text).split("\n")
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
                scans = [body_scan(t, files[t]) for t in targets]
                all_stub = all(s[0] for s in scans)
                lost_block = False
                if base_files is not None:
                    for t in targets:
                        b = base_files.get(t)
                        if b is not None and body_lost_block_capability(
                            b, files[t]
                        ):
                            lost_block = True
                            break
                evidence = next((s[1] for s in scans if s[1]), "")
                if lost_block and not evidence:
                    evidence = "block capability removed"
                bodies[cmd] = (all_stub, lost_block, evidence)
    return bodies, targets_all
