"""Bounded single-line TOML subset for checkwash config and allow.toml."""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta
from typing import Any

from pinwash.textutil import crlf_to_lf

_FAIL_ON = re.compile(
    r'^fail_on\s*=\s*["\']?(info|warn|high|critical)["\']?\s*$',
    re.IGNORECASE,
)
_FALSE_ASSIGN = re.compile(
    r"^(detect_[A-Za-z0-9_]+|[A-Z][A-Z0-9_]+)\s*=\s*false\s*$"
)
_DISABLE_LIST = re.compile(r"^disable\s*=\s*\[(.*)\]\s*$")
_STR = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*)"\s*$')

SEVERITY_RANK = {"info": 0, "warn": 1, "high": 2, "critical": 3}


def parse_checkwash_config(text: str) -> dict[str, Any]:
    disabled: list[str] = []
    fail_on: str | None = None
    for line in crlf_to_lf(text).split("\n"):
        raw = line.strip()
        if not raw or raw.startswith("#") or raw.startswith("["):
            continue
        m = _FAIL_ON.match(raw)
        if m:
            fail_on = m.group(1).lower()
            continue
        m = _FALSE_ASSIGN.match(raw)
        if m:
            disabled.append(m.group(1))
            continue
        m = _DISABLE_LIST.match(raw)
        if m:
            inner = m.group(1)
            for part in inner.split(","):
                token = part.strip().strip("\"'")
                if token:
                    disabled.append(token)
    return {"disabled": disabled, "fail_on": fail_on}


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


def allow_valid(record: dict[str, str], today: date) -> bool:
    required = ("fingerprint", "rule", "reason", "author", "created", "expires")
    if any(not record.get(key) for key in required):
        return False
    try:
        created = date.fromisoformat(record["created"])
        expires = date.fromisoformat(record["expires"])
    except ValueError:
        return False
    if expires > created + timedelta(days=180):
        return False
    if expires < today:
        return False
    return True


def pinwash_today(env: dict[str, str]) -> date:
    raw = env.get("PINWASH_TODAY")
    if raw:
        return date.fromisoformat(raw)
    return datetime.now().date()
