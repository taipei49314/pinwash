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


def _self_tests() -> dict[str, Any]:
    """SPEC §13: doctor covers own tests as well as the spec hash.

    The gate suite spawns `pinwash doctor`, so the guard keeps a doctor
    running inside its own test run from recursing.
    """
    root = Path(__file__).resolve().parent.parent
    tests_dir = root / "tests"
    if not tests_dir.is_dir():
        return {"available": False, "ok": True, "tests_run": 0}
    if os.environ.get(_SELFTEST_ENV):
        return {
            "available": True,
            "ok": True,
            "tests_run": 0,
            "skipped": "nested doctor invocation",
        }
    import unittest

    os.environ[_SELFTEST_ENV] = "1"
    try:
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        suite = unittest.defaultTestLoader.discover(
            start_dir=str(tests_dir), top_level_dir=str(root)
        )
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=0).run(suite)
    finally:
        os.environ.pop(_SELFTEST_ENV, None)
    return {
        "available": True,
        "ok": result.wasSuccessful(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
    }


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
