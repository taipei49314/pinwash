"""Collect alpha-round-2 validation evidence on an approved EC pool job."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, sort_keys=True, ensure_ascii=False, indent=2)
        handle.write("\n")


def main() -> int:
    required = ("EC_WORKLOAD_SOURCE", "EC_WORKLOAD_OUT", "EC_WORKLOAD_SHA")
    if any(not os.environ.get(key) for key in required):
        raise RuntimeError("run only through the approved EC pool workload")
    if os.environ.get("EC_WORKLOAD_REPOSITORY") != "taipei49314/pinwash":
        raise RuntimeError("unexpected workload repository")
    if os.environ.get("EC_WORKLOAD_NAME") != "alpha2-verify":
        raise RuntimeError("unexpected workload name")
    if Path(os.environ["EC_WORKLOAD_SOURCE"]).resolve() != ROOT:
        raise RuntimeError("workload source does not match this entry point")
    expected = os.environ["EC_WORKLOAD_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise RuntimeError("an exact source SHA is required")
    out = Path(os.environ["EC_WORKLOAD_OUT"]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update(PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT))
    # The pool date is not an exemption oracle; pin it explicitly for replay.
    env["PINWASH_TODAY"] = "2026-09-30"
    env.pop("PINWASH_DOCTOR_SELFTEST", None)
    steps: list[dict[str, object]] = []

    def run(name: str, command: list[str], *, seed: str = "1") -> tuple[int, bytes, bytes]:
        started = time.monotonic()
        step_env = dict(env, PYTHONHASHSEED=seed)
        timed_out = False
        try:
            process = subprocess.run(
                command, cwd=ROOT, env=step_env, capture_output=True,
                timeout=300, check=False,
            )
            code, stdout, stderr = process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired as exc:
            code, timed_out = 2, True
            stdout, stderr = exc.stdout or b"", exc.stderr or b""
        except OSError as exc:
            code, stdout, stderr = 2, b"", str(exc).encode("utf-8")
        (out / f"{name}.stdout").write_bytes(stdout)
        (out / f"{name}.stderr").write_bytes(stderr)
        steps.append({
            "name": name, "command": command, "exit_code": code,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "timed_out": timed_out, "pythonhashseed": seed,
            "stdout_sha256": sha256(stdout), "stderr_sha256": sha256(stderr),
        })
        return code, stdout, stderr

    problems: list[str] = []
    code, source, _ = run("source", ["git", "rev-parse", "--verify", "HEAD"])
    actual = source.decode("ascii", "replace").strip()
    if code or actual != expected:
        problems.append("source SHA mismatch or unreadable source")
    code, status, _ = run("clean-source", ["git", "status", "--porcelain", "-z"])
    if code or status:
        problems.append("source checkout is not clean")

    count = 0
    doctor_payload: object = None
    deterministic: bool | None = None
    if not problems:
        python = [sys.executable, "-X", "utf8", "-B"]
        code, _, stderr = run(
            "suite", python + ["-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
        )
        text = stderr.decode("utf-8", "replace")
        counts = re.findall(r"(?m)^Ran (\d+) tests? in ", text)
        count = int(counts[-1]) if counts else 0
        if code or count == 0 or re.search(r"(?m)^OK \(.*skipped=", text):
            problems.append("suite failed, ran zero tests, or skipped tests")
        code, stdout, doctor_stderr = run("doctor", python + ["-m", "pinwash", "doctor"])
        try:
            doctor_payload = json.loads(stdout)
            tests = doctor_payload["self_tests"]
            verified = (
                code == 0 and doctor_payload["subject_judged"] is False
                and tests["available"] is True and tests["ok"] is True
                and tests["tests_run"] == count and count > 0
                and tests["failures"] == 0 and tests["errors"] == 0
                and tests["skipped_count"] == 0
                and "skipped" not in tests
                and not re.search(r"(?m)^OK \(.*skipped=", doctor_stderr.decode("utf-8", "replace"))
                and doctor_payload["spec_sha256"] == sha256((ROOT / "SPEC.md").read_bytes())
            )
        except (ValueError, KeyError, TypeError):
            verified = False
        if not verified:
            problems.append("doctor did not verify the same nonzero test suite and spec")
        command = python + ["-m", "pinwash", "check", f"{expected}..{expected}"]
        code1, first, _ = run("determinism-seed1", command, seed="1")
        code2, second, _ = run("determinism-seed17", command, seed="17")
        deterministic = code1 == code2 == 0 and bool(first) and first == second
        if not deterministic:
            problems.append("independent process findings JSON differs or scan failed")
        code, final_source, _ = run("final-source", ["git", "rev-parse", "--verify", "HEAD"])
        if code or final_source.decode("ascii", "replace").strip() != expected:
            problems.append("validation changed the source SHA")
        code, final_status, _ = run("final-source-status", ["git", "status", "--porcelain", "-z"])
        if code or final_status:
            problems.append("validation changed the source checkout")

    tests_manifest = {
        path.relative_to(ROOT).as_posix(): sha256(path.read_bytes())
        for path in sorted((ROOT / "tests").rglob("*.py"))
    }
    result = {
        "schema_version": 1, "milestone": "alpha-round-2",
        "requested_sha": expected, "actual_sha": actual,
        "runtime": {"python": sys.version, "platform": platform.platform()},
        "pinwash_today": env["PINWASH_TODAY"], "steps": steps,
        "tests_run": count, "test_sources_sha256": tests_manifest,
        "doctor": doctor_payload, "raw_json_equal": deterministic,
        "passed": not problems, "problems": problems,
        "limitations": [
            "one EC Windows pool runtime; no cross-OS or Python matrix claim",
            "determinism probe compares a same-tree scan across hash seeds",
            "seeded regressions; no independent held-out agent accuracy claim",
        ],
    }
    write_json(out / "result.json", result)
    lines = [
        "# pinwash alpha round 2 validation", "",
        f"Result: {'PASS' if not problems else 'FAIL'}", "",
        f"Source: `{actual}` (requested `{expected}`)",
        f"Tests run: {count}; raw JSON equality: {deterministic}", "",
        "Commands, exits, log hashes and test-source hashes: `result.json`.", "",
    ]
    lines.extend(f"- {problem}" for problem in problems)
    lines.extend(["", "Coverage is one EC Windows runtime and seeded regression cases.",
                  "Cross-platform determinism and held-out agent accuracy are not assessed.", ""])
    (out / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
