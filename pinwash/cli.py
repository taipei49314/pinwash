"""CLI. Unexpected exceptions become exit 2, never 1."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from pinwash import SPEC_VERSION, __version__
from pinwash.engine import scan_repo
from pinwash.textutil import dump_json, sha256_bytes

HELP = """pinwash — flag harness-weakening git diffs

  python -m pinwash check [RANGE]
  python -m pinwash check              # HEAD vs worktree
  python -m pinwash --version
  python -m pinwash doctor
"""

_SELFTEST_ENV = "PINWASH_DOCTOR_SELFTEST"
# The frozen gate spawns `pinwash doctor` from inside the suite. A nested
# doctor runs the same suite without that one test, so it cannot recurse and
# still runs real tests whatever value the environment carries (#3).
_NESTED_EXCLUDED = frozenset(
    {"tests.gates.test_v0_acceptance.V0Acceptance.test_doctor_does_not_judge_subject"}
)
_MAX_NESTED_DEPTH = 1


def _nested_depth() -> int:
    """0 for a public invocation; any other value counts as nested."""
    raw = os.environ.get(_SELFTEST_ENV)
    if not raw:
        return 0
    try:
        depth = int(raw)
    except ValueError:
        return 1
    return max(depth, 1)


def _flatten(suite: Any) -> list[Any]:
    import unittest

    found: list[Any] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            found.extend(_flatten(item))
        else:
            found.append(item)
    return found


def _without_nested_spawners(suite: Any) -> tuple[Any, list[str]]:
    """Drop the doctor-spawning tests; return the kept suite and dropped ids."""
    import unittest

    kept: list[Any] = []
    excluded: list[str] = []
    for test in _flatten(suite):
        if test.id() in _NESTED_EXCLUDED:
            excluded.append(test.id())
        else:
            kept.append(test)
    return unittest.TestSuite(kept), sorted(excluded)


def _suite_passed(result: Any) -> bool:
    """One predicate: every own test ran and really passed (#3)."""
    return (
        result.testsRun > 0
        and not result.failures
        and not result.errors
        and not result.skipped
        and not result.expectedFailures
        and not result.unexpectedSuccesses
    )


def _self_tests() -> dict[str, Any]:
    """SPEC §13: doctor covers own tests as well as the spec hash.

    The gate suite spawns `pinwash doctor`, so a doctor running inside its
    own test run is nested: it runs the suite minus the spawning test. A
    deeper nesting is refused rather than recursing or reporting success.
    """
    root = Path(__file__).resolve().parent.parent
    tests_dir = root / "tests"
    if not tests_dir.is_dir():
        return {"available": False, "ok": False, "tests_run": 0}
    depth = _nested_depth()
    if depth > _MAX_NESTED_DEPTH:
        return {
            "available": True,
            "ok": False,
            "tests_run": 0,
            "nested_depth": depth,
            "refused": f"nested doctor depth above {_MAX_NESTED_DEPTH}",
        }
    import unittest

    previous = os.environ.get(_SELFTEST_ENV)
    os.environ[_SELFTEST_ENV] = str(depth + 1)
    try:
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        suite = unittest.defaultTestLoader.discover(
            start_dir=str(tests_dir), top_level_dir=str(root)
        )
        excluded: list[str] = []
        if depth:
            suite, excluded = _without_nested_spawners(suite)
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=0).run(suite)
    finally:
        if previous is None:
            os.environ.pop(_SELFTEST_ENV, None)
        else:
            os.environ[_SELFTEST_ENV] = previous
    tests: dict[str, Any] = {
        "available": True,
        "ok": _suite_passed(result),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped_count": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
        "nested_depth": depth,
    }
    if depth:
        tests["excluded"] = excluded
    return tests


def doctor() -> int:
    root = Path(__file__).resolve().parent.parent
    spec = root / "SPEC.md"
    if not spec.is_file():
        sys.stderr.write("pinwash doctor: SPEC.md missing\n")
        return 2
    tests = _self_tests()
    payload = {
        "pinwash_version": __version__,
        "self_tests": tests,
        "spec_sha256": sha256_bytes(spec.read_bytes()),
        "spec_version": SPEC_VERSION,
        "subject_judged": False,
    }
    sys.stdout.buffer.write(dump_json(payload))
    return 0 if tests["ok"] else 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        return _dispatch(args)
    except Exception as exc:  # noqa: BLE001 — spec: crash is exit 2
        sys.stderr.write(f"pinwash engine error: {exc}\n")
        return 2


def _dispatch(args: list[str]) -> int:
    if not args or args[0] in {"-h", "--help", "help"}:
        sys.stdout.write(HELP)
        return 0
    if args[0] in {"-V", "--version", "version"}:
        sys.stdout.write(f"pinwash {__version__} spec {SPEC_VERSION}\n")
        return 0
    if args[0] == "doctor":
        return doctor()
    if args[0] != "check":
        sys.stderr.write("pinwash: unknown command\n")
        return 2
    range_arg = args[1] if len(args) > 1 else None
    payload, code = scan_repo(os.getcwd(), range_arg)
    if code == 2:
        sys.stderr.write(f"pinwash: {payload.get('error', 'unreadable git repository')}\n")
        return 2
    sys.stdout.buffer.write(dump_json(payload))
    return code
