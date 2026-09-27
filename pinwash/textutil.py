"""Deterministic text helpers. No timestamps, no locale-dependent encodes."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def crlf_to_lf(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def decode_utf8(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dump_json(obj: Any) -> bytes:
    text = json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2)
    return (text + "\n").encode("utf-8")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
