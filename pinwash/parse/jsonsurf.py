"""JSON/text surface loading with the closed status tri-state (SPEC §3)."""

from __future__ import annotations

import json
import re
from decimal import Decimal
from json.decoder import scanstring
from typing import Any

from pinwash.textutil import crlf_to_lf, decode_utf8

# SPEC §8 / §9: subject bytes are a parse result (ok or SURFACE_UNPARSEABLE),
# never an engine error, and the result must not depend on the interpreter.
# json.loads recurses once per nesting level: 3.11 raises RecursionError
# near 990 levels (fewer when the caller's stack is deeper), 3.12/3.13 near
# 10000. Depth is therefore no part of whether a surface parses. A document
# nested at most _C_PARSER_DEPTH deep (every real surface file: a Claude
# hook command and a ruleset context sit at depth 6) goes to json.loads
# exactly as before; a deeper one goes to _loads_iterative, which reads the
# same grammar with an explicit stack. The hook and ruleset walkers are
# iterative as well, so a deep document is judged like any other.
_C_PARSER_DEPTH = 128

# int() refuses a literal longer than the process's int_max_str_digits
# (4300 by default; a host may lower it to 640 or lift it) with ValueError.
# Literals up to 640 digits never reach that check; up to CPython's default
# 4300 they convert through Decimal, which no process setting limits, to the
# int json.loads returned before. A longer literal, which json.loads refused
# on every interpreter, stays an exact Decimal: int() on it is quadratic, and
# no rule reads JSON numbers (they are only ever compared with strings and
# booleans, which a Decimal never equals except as an int would).
_INT_UNCHECKED_DIGITS = 640
_INT_DEFAULT_DIGITS = 4300

# One token per JSON string (its closing quote optional, so an unterminated
# string cannot make the scan backtrack) or per bracket outside strings.
_TOKEN = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"?|[\[\]{}]', re.DOTALL)

# The grammar of CPython's json scanner (json/scanner.py, _json.c). Numbers
# take ASCII digits only, as the C scanner does.
_WS = re.compile(r"[ \t\n\r]*")
_NUMBER = re.compile(r"(-?(?:0|[1-9][0-9]*))(\.[0-9]+)?([eE][-+]?[0-9]+)?")
_CONSTANTS = {
    "NaN": float("nan"),
    "Infinity": float("inf"),
    "-Infinity": float("-inf"),
}


def _within_depth(text: str, limit: int) -> bool:
    """Linear pre-scan: no point outside strings is nested deeper than limit."""
    depth = 0
    for match in _TOKEN.finditer(text):
        token = match.group()
        if token == "[" or token == "{":
            depth += 1
            if depth > limit:
                return False
        elif token == "]" or token == "}":
            depth -= 1
    return True


def _json_int(literal: str) -> int | Decimal:
    digits = len(literal) - literal.startswith("-")
    if digits <= _INT_UNCHECKED_DIGITS:
        return int(literal)
    value = Decimal(literal)
    return int(value) if digits <= _INT_DEFAULT_DIGITS else value


def _scalar(s: str, idx: int) -> tuple[Any, int]:
    """One value that is not a container, at idx (json.scanner.scan_once)."""
    nextchar = s[idx:idx + 1]
    if nextchar == '"':
        return scanstring(s, idx + 1, True)
    if nextchar == "n" and s.startswith("null", idx):
        return None, idx + 4
    if nextchar == "t" and s.startswith("true", idx):
        return True, idx + 4
    if nextchar == "f" and s.startswith("false", idx):
        return False, idx + 5
    m = _NUMBER.match(s, idx)
    if m is not None:
        integer, frac, exp = m.groups()
        if frac or exp:
            return float(m.group()), m.end()
        return _json_int(integer), m.end()
    for name in ("NaN", "Infinity", "-Infinity"):
        if s.startswith(name, idx):
            return _CONSTANTS[name], idx + len(name)
    raise ValueError("Expecting value")


def _key(s: str, idx: int) -> tuple[str, int]:
    """An object key and its colon, at idx; returns the value's start."""
    if s[idx:idx + 1] != '"':
        raise ValueError("Expecting property name enclosed in double quotes")
    key, idx = scanstring(s, idx + 1, True)
    idx = _WS.match(s, idx).end()
    if s[idx:idx + 1] != ":":
        raise ValueError("Expecting ':' delimiter")
    return key, _WS.match(s, idx + 1).end()


def _loads_iterative(s: str) -> Any:
    """json.loads(s) with the engine's integers, without recursion.

    Accepts and rejects exactly what json.loads does, and builds the same
    value: an object keeps its first key order and last duplicate value.
    """
    if s.startswith("\ufeff"):
        raise ValueError("Unexpected UTF-8 BOM")
    ws = _WS.match
    idx = ws(s, 0).end()
    # One frame per open container: [container, key awaiting its value].
    stack: list[list[Any]] = []
    while True:
        nextchar = s[idx:idx + 1]
        if nextchar == "{":
            idx = ws(s, idx + 1).end()
            if s[idx:idx + 1] == "}":
                value, idx = {}, idx + 1
            else:
                key, idx = _key(s, idx)
                stack.append([{}, key])
                continue
        elif nextchar == "[":
            idx = ws(s, idx + 1).end()
            if s[idx:idx + 1] == "]":
                value, idx = [], idx + 1
            else:
                stack.append([[], None])
                continue
        else:
            value, idx = _scalar(s, idx)
        # A value is complete: store it, then close every container it ends.
        while stack:
            frame = stack[-1]
            container = frame[0]
            is_list = isinstance(container, list)
            if is_list:
                container.append(value)
            else:
                container[frame[1]] = value
            idx = ws(s, idx).end()
            nextchar = s[idx:idx + 1]
            if nextchar == ",":
                idx = ws(s, idx + 1).end()
                if not is_list:
                    frame[1], idx = _key(s, idx)
                break
            if nextchar != ("]" if is_list else "}"):
                raise ValueError("Expecting ',' delimiter")
            stack.pop()
            value, idx = container, idx + 1
        else:
            if ws(s, idx).end() != len(s):
                raise ValueError("Extra data")
            return value


def json_load(data: bytes | None) -> tuple[Any | None, str]:
    """Return (obj, status) where status is ok|missing|unparseable."""
    if data is None:
        return None, "missing"
    text = decode_utf8(data)
    if text is None:
        return None, "unparseable"
    text = crlf_to_lf(text)
    try:
        if _within_depth(text, _C_PARSER_DEPTH):
            return json.loads(text, parse_int=_json_int), "ok"
        return _loads_iterative(text), "ok"
    except ValueError:
        # JSONDecodeError is a ValueError, as is every _loads_iterative error.
        return None, "unparseable"


def text_load(data: bytes | None) -> tuple[str | None, str]:
    if data is None:
        return None, "missing"
    text = decode_utf8(data)
    if text is None:
        return None, "unparseable"
    return crlf_to_lf(text), "ok"
