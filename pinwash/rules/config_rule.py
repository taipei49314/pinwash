"""CONFIG_RELAXED (SPEC §5): the checkwash config in force, read as checkwash
reads it (§3.2, spec 19), high per §6."""

from __future__ import annotations

import sys
import tomllib
from typing import Any

from pinwash.escalate import SEVERITY_RANK
from pinwash.findings import FAIL_ON_DEFAULT

# SPEC §3.2 (spec 19, AI-assisted ruling R-22b on #22): checkwash reads one
# config per side, the first of these paths that exists (its CONFIG_DIRS and
# read_base_config_file); an empty file exists and runs on the defaults.
CONFIG_ORDER = (".checkwash/config.toml", ".greenwash/config.toml")

# SPEC §7 / R22: a config checkwash cannot load (it exits 2 on it) is not
# compared, and this row says so.
NOT_LOADED = "checkwash config checkwash cannot load (not compared)"

# SPEC §3.2 (spec 19 review, AI-assisted): fixed bounds, so the reading
# depends on neither the interpreter nor the caller's stack. checkwash runs
# tomllib under Python's default recursion limit of 1000 frames, and every
# array or inline-table level costs tomllib at least two, so no config
# nested past 500 levels loads; 3.11's and 3.13's tomllib refuse a key of
# more than 1000 parts (3.12.3's does not check); Python refuses a decimal
# integer of more than 4300 digits unless the environment says otherwise.
MAX_NESTING = 500
MAX_KEY_PARTS = 1000
INT_DIGITS = 4300
# Frames tomllib may use above its caller: three per level at most.
_HEADROOM = 2000


def _skip_string(text: str, i: int) -> int:
    """The index after the TOML string that starts at `i`."""
    q = text[i]
    n = len(text)
    if text.startswith(q * 3, i):
        j = i + 3
        while j < n:
            if q == '"' and text[j] == "\\":
                j += 2
            elif text.startswith(q * 3, j):
                j += 3
                # Up to two more quotes end the content (TOML 1.0).
                for _ in range(2):
                    if j < n and text[j] == q:
                        j += 1
                return j
            else:
                j += 1
        return n
    j = i + 1
    while j < n:
        c = text[j]
        if q == '"' and c == "\\":
            j += 2
        elif c == q:
            return j + 1
        elif c == "\n":
            return j
        else:
            j += 1
    return n


def _overflow(text: str) -> int:
    """SPEC §3.2: the index of the first character, outside strings and
    comments, at which an array or inline table opens past MAX_NESTING
    levels or a key reaches MAX_KEY_PARTS + 1 parts; -1 when none does."""
    stack: list[str] = []
    key = True  # a key: at a statement start, in a table header, in an inline table
    header = False
    parts = 1
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c in "\"'":
            i = _skip_string(text, i)
            continue
        if c == "\n":
            if not stack:
                key, header, parts = True, False, 1
        elif key or header:
            if c == ".":
                parts += 1
                if parts > MAX_KEY_PARTS:
                    return i
            elif c == "=" and not header:
                key = False
            elif c == "[" and not stack:
                header = True
            elif c == "]" and header:
                key = header = False
            elif c == "}" and stack and stack[-1] == "{":
                stack.pop()
                key = False
        elif c in "[{":
            stack.append(c)
            if len(stack) > MAX_NESTING:
                return i
            if c == "{":
                key, parts = True, 1
        elif c == "]" and stack and stack[-1] == "[":
            stack.pop()
        elif c == "}" and stack and stack[-1] == "{":
            stack.pop()
        elif c == "," and stack and stack[-1] == "{":
            key, parts = True, 1
        i += 1
    return -1


def _toml(text: str) -> dict[str, Any]:
    """tomllib with _HEADROOM frames above this call and Python's default
    integer-digit limit, whatever the stack and the environment."""
    depth = 0
    frame = sys._getframe()
    while frame is not None:
        depth += 1
        frame = frame.f_back
    limit = sys.getrecursionlimit()
    digits = sys.get_int_max_str_digits()
    sys.setrecursionlimit(max(limit, depth + _HEADROOM))
    sys.set_int_max_str_digits(INT_DIGITS)
    try:
        return tomllib.loads(text)
    finally:
        sys.set_int_max_str_digits(digits)
        sys.setrecursionlimit(limit)


def checkwash_read(data: bytes | None) -> tuple[str, list[str]] | None:
    """(fail_on, disabled detectors) as checkwash's load_config reads them:
    UTF-8 with a leading BOM dropped and bad bytes replaced, then tomllib; a
    text tomllib rejects is the defaults; only `gate.fail_on` (a severity,
    else the default) and `detectors.disable` (a list of strings, else none)
    are read. None for a config checkwash cannot load and exits 2 on (R22):
    tomllib reaches nesting past MAX_NESTING or a key past MAX_KEY_PARTS
    parts before any error, raises on an integer past INT_DIGITS digits, or
    `gate.fail_on` is an array or a table (its `in` test raises)."""
    if not data:
        return FAIL_ON_DEFAULT, []
    text = data.decode("utf-8-sig", errors="replace")
    at = _overflow(text)
    try:
        # Past a bound only the prefix through it is parsed: an error
        # inside the prefix is checkwash's too, and is met first.
        raw = _toml(text if at < 0 else text[: at + 1])
    except tomllib.TOMLDecodeError as exc:
        if at >= 0 and str(exc).endswith("(at end of document)"):
            return None
        return FAIL_ON_DEFAULT, []
    except (RecursionError, ValueError):
        return None
    if at >= 0:
        return None
    fail_on = FAIL_ON_DEFAULT
    gate = raw.get("gate", {})
    if isinstance(gate, dict):
        value = gate.get("fail_on")
        if isinstance(value, (list, dict)):
            return None
        if isinstance(value, str) and value in SEVERITY_RANK:
            fail_on = value
    disabled: list[str] = []
    detectors = raw.get("detectors", {})
    if isinstance(detectors, dict):
        value = detectors.get("disable")
        if isinstance(value, list) and all(isinstance(d, str) for d in value):
            disabled = list(value)
    return fail_on, disabled


def _in_force(files: dict[str, bytes]) -> tuple[str | None, bytes | None]:
    for path in CONFIG_ORDER:
        if path in files:
            return path, files[path]
    return None, None


def detect(
    base_files: dict[str, bytes], head_files: dict[str, bytes], add: Any, note: Any
) -> None:
    """SPEC §5 (spec 19): compare the configs in force. `*_files` map each
    side's files at the CONFIG_ORDER paths, spelled exactly, to their bytes.
    Deleting, renaming or newly shadowing a config is compared like an edit;
    the finding sits on the head's config in force, or the base's when the
    head has none. A config checkwash cannot load is a row: at head it is
    not compared (checkwash exits 2 on every run under it); at base the head
    is compared against the defaults, as if it created its config."""
    base_path, base_data = _in_force(base_files)
    head_path, head_data = _in_force(head_files)
    path = head_path or base_path
    if path is None:
        return
    base_c = checkwash_read(base_data)
    head_c = checkwash_read(head_data)
    if base_c is None:
        note(base_path, NOT_LOADED)
        base_c = (FAIL_ON_DEFAULT, [])
    if head_c is None:
        note(head_path, NOT_LOADED)
        return
    (base_fail, base_dis), (head_fail, head_dis) = base_c, head_c
    if SEVERITY_RANK[head_fail] > SEVERITY_RANK[base_fail]:
        add(
            rule="CONFIG_RELAXED",
            severity="high",
            message=f"fail_on raised {base_fail} -> {head_fail}",
            path=path,
            before=base_fail,
            after=head_fail,
        )
    seen: set[str] = set()
    for name in head_dis:
        if name not in base_dis and name not in seen:
            seen.add(name)
            add(
                rule="CONFIG_RELAXED",
                severity="high",
                message=f"detector {name} disabled",
                path=path,
                after=name,
            )
