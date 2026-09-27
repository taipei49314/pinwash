"""JSON/text surface loading with the closed status tri-state (SPEC §3)."""

from __future__ import annotations

import json
from typing import Any

from pinwash.textutil import crlf_to_lf, decode_utf8


def json_load(data: bytes | None) -> tuple[Any | None, str]:
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


def text_load(data: bytes | None) -> tuple[str | None, str]:
    if data is None:
        return None, "missing"
    text = decode_utf8(data)
    if text is None:
        return None, "unparseable"
    return crlf_to_lf(text), "ok"
