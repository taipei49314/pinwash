"""Deterministic text helpers. No timestamps, no locale-dependent encodes."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
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


def canonical_text(value: Any) -> str:
    """A canonical text of a parsed JSON value, for equality only (SPEC §8/§9).

    Built on an explicit stack, so a value nested at any depth reads the same
    on every interpreter (repr() and json.dumps recurse once per level, and
    their limits differ between 3.11 and 3.13). Object keys are sorted, so
    key order is no change. No repr(): every token is a fixed spelling, a
    length-prefixed string, or a number in a base that int_max_str_digits
    does not limit (hex), so one value has one text under any process
    setting. Never printed; distinct values give distinct texts.
    """
    parts: list[str] = []
    # (is_token, payload): a token is appended as is; anything else is a value.
    stack: list[tuple[bool, Any]] = [(False, value)]
    while stack:
        is_token, item = stack.pop()
        if is_token:
            parts.append(item)
        elif isinstance(item, dict):
            parts.append("{")
            stack.append((True, "}"))
            for key in sorted(item, reverse=True):
                stack.append((False, item[key]))
                stack.append((True, f"k{len(key)}:{key}"))
        elif isinstance(item, list):
            parts.append("[")
            stack.append((True, "]"))
            for element in reversed(item):
                stack.append((False, element))
        elif isinstance(item, str):
            parts.append(f"s{len(item)}:{item}")
        elif item is True:
            parts.append("true;")
        elif item is False:
            parts.append("false;")
        elif item is None:
            parts.append("null;")
        elif isinstance(item, int):
            parts.append(f"i{hex(item)};")
        elif isinstance(item, float):
            parts.append(f"f{item.hex()};")
        elif isinstance(item, Decimal):
            parts.append(f"d{item};")
        else:
            parts.append(f"?{type(item).__name__};")
    return "".join(parts)
