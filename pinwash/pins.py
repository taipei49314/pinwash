"""Pin identity lattice (SPEC §4)."""

from __future__ import annotations

import re

KIND_RANK = {
    "digest_sha256": 4,
    "git_sha": 3,
    "git_tag": 2,
    "action_ref": 1,
    "floating": 0,
}

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_TAG = re.compile(r"^v?[0-9]+\.[0-9].*$")
_FLOATING_WORDS = frozenset({"main", "master", "HEAD", "latest", "*", ""})


def classify_action_ref(value: str) -> str:
    r = value.strip()
    if _SHA40.fullmatch(r):
        return "git_sha"
    if "/" not in r and _TAG.fullmatch(r):
        return "git_tag"
    if r in _FLOATING_WORDS:
        return "floating"
    return "floating"


def is_floating(kind: str, value: str) -> bool:
    if kind == "floating":
        return True
    return classify_action_ref(value) == "floating" and kind != "digest_sha256"


def kind_rank(kind: str) -> int:
    return KIND_RANK.get(kind, 0)


def record_rank(kind: str, value: str) -> int:
    """Lattice rank for a declared pin record (SPEC §4).

    The lattice level is "action_ref-that-is-tag": an action_ref record
    ranks by its value — tag-valued sits between git_tag and floating,
    branch-valued is floating.
    """
    if kind == "action_ref":
        return 1 if classify_action_ref(value) == "git_tag" else 0
    return kind_rank(kind)


def parse_uses(value: str) -> tuple[str, str] | None:
    """Return (owner/repo-or-path, ref) from a GitHub Actions uses value."""
    raw = value.strip().strip("\"'")
    if raw.startswith("docker://"):
        return None
    if raw.startswith("./") or raw.startswith(".\\"):
        return None
    if "@" not in raw:
        return None
    loc, ref = raw.rsplit("@", 1)
    loc = loc.strip()
    ref = ref.strip()
    if not loc or not ref:
        return None
    return loc, ref
