"""Bounded single-line TOML subset for `.pinwash/allow.toml` (SPEC §10); the
checkwash config is read as checkwash reads it (rules/config_rule.py, §3.2)."""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any

from pinwash.textutil import crlf_to_lf

_STR = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*)"\s*$')


def parse_allow_toml(text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in crlf_to_lf(text).split("\n"):
        raw = line.strip()
        if raw == "[[allow]]":
            if current is not None:
                records.append(current)
            current = {}
            continue
        if current is None:
            continue
        m = _STR.match(raw)
        if m:
            current[m.group(1)] = m.group(2)
    if current is not None:
        records.append(current)
    return records


def allow_valid(record: dict[str, str], today: date, *, in_force: bool = False) -> bool:
    """SPEC §10 validity. Without in_force: the record is visible to the
    add/edit/delete checks. With in_force: it may also exempt a finding today."""
    required = ("fingerprint", "rule", "reason", "author", "created", "expires")
    if any(not record.get(key) for key in required):
        return False
    try:
        created = date.fromisoformat(record["created"])
        expires = date.fromisoformat(record["expires"])
    except ValueError:
        return False
    # Day differences, not date + timedelta: a created date near 9999-12-31
    # must not overflow into an engine error.
    if (expires - created).days > 180:
        return False
    if expires < today:
        return False
    # SPEC §10 (spec 11): the 180 days run from the earlier of created and
    # today, so a self-declared future created cannot lengthen the window.
    if in_force and (expires - min(created, today)).days > 180:
        return False
    return True


def pinwash_today(env: dict[str, str]) -> date:
    raw = env.get("PINWASH_TODAY")
    if raw:
        return date.fromisoformat(raw)
    return datetime.now().date()
