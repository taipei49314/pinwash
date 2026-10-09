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
    # surrogatepass encodes every str that strict UTF-8 can encode to the
    # same bytes, so existing fingerprints are unchanged. It also encodes
    # the lone surrogates that subject data can carry (a non-UTF-8 path
    # name decoded with surrogateescape, a JSON \ud800 escape), and it
    # stays injective, so distinct strings keep distinct digests.
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dump_json(obj: Any) -> bytes:
    text = json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2)
    # A lone surrogate has no UTF-8 form. json.dumps leaves it inside its
    # JSON string, where backslashreplace writes it as the escape \udXXX:
    # the output stays valid UTF-8 and json.loads returns the same str.
    # Every other character is encoded exactly as before.
    return (text + "\n").encode("utf-8", "backslashreplace")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
