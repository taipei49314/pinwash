"""SKILL_BYPASS (SPEC §5.4): closed phrase table over added or edited lines."""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Any

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


def added_lines(base_text: str, head_text: str) -> list[str]:
    b = base_text.split("\n")
    h = head_text.split("\n")
    added: list[str] = []
    matcher = SequenceMatcher(a=b, b=h, autojunk=False)
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ("insert", "replace"):
            added.extend(h[j1:j2])
    return added


def phrase_hit(line: str) -> bool:
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


def detect(
    path: str, base_text: str, head_text: str, add: Any
) -> None:
    for line in added_lines(base_text, head_text):
        if phrase_hit(line):
            add(
                rule="SKILL_BYPASS",
                severity="warn",
                message="added or edited line matches a v0 bypass phrase",
                path=path,
                before="",
                after=line[:200],
            )
