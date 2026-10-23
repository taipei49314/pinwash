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
import signal
import stat
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def plain_directory(path: Path) -> Path:
    """Require existing plain directory ancestors before creating owned scratch."""
    absolute = path.absolute()
    for item in (*reversed(absolute.parents), absolute):
        info = item.lstat()
        if (not stat.S_ISDIR(info.st_mode) or item.is_symlink()
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("temporary parent is not an existing plain directory")
    return absolute


def remove_owned_temp(root: Path, parent: Path, deadline: float) -> None:
    """Remove only this invocation's direct child, without following redirects."""
    parent = plain_directory(parent)
    if root.absolute().parent != parent or not root.name.startswith("alpha2-"):
        raise ValueError("temporary root is not this invocation's owned child")
    plain_directory(root)
    files: list[Path] = []
    directories = [root]
    pending = [root]
    while pending:
        if time.monotonic() >= deadline:
            raise TimeoutError("temporary cleanup budget expired")
        current = pending.pop()
        for child in current.iterdir():
            info = child.lstat()
            if child.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("owned temporary tree contains a redirect; retained")
            if stat.S_ISDIR(info.st_mode):
                directories.append(child)
                pending.append(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                files.append(child)
            else:
                raise ValueError("owned temporary tree contains a nonregular or hardlinked file; retained")
    # Validate the entire tree before deleting anything. Child execution has
    # ended; timeout cleanup uncertainty never reaches this function.
    for child in files:
        if time.monotonic() >= deadline:
            raise TimeoutError("temporary cleanup budget expired")
        info = child.lstat()
        if child.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("owned temporary file changed during cleanup")
        if getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("owned temporary file became a redirect")
        if not info.st_mode & stat.S_IWRITE or getattr(info, "st_file_attributes", 0) & 1:
            child.chmod(info.st_mode | stat.S_IWRITE)
        child.unlink()
    for child in reversed(directories):
        if time.monotonic() >= deadline:
            raise TimeoutError("temporary cleanup budget expired")
        plain_directory(child)
        child.rmdir()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, sort_keys=True, ensure_ascii=False, indent=2)
        handle.write("\n")


def stop_owned(process, expired, *, windows: bool) -> tuple[bytes, bytes, dict[str, object]]:
    """Bound cleanup and retain evidence; uncertainty prevents further steps."""
    cleanup: dict[str, object] = {"confirmed": False, "errors": []}
    errors = cleanup["errors"]
    killed = False
    try:
        if windows:
            killer = Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"
            result = subprocess.run([str(killer), "/PID", str(process.pid), "/T", "/F"],
                                    capture_output=True, timeout=15, check=False)
            cleanup.update(exit_code=result.returncode,
                           stdout=result.stdout.decode("utf-8", "replace"),
                           stderr=result.stderr.decode("utf-8", "replace"))
            killed = result.returncode == 0
            if not killed:
                errors.append("owned-tree termination returned nonzero")
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # group already gone; pipe drainage must still complete
            killed = True
    except (OSError, KeyError, subprocess.TimeoutExpired) as exc:
        errors.append(f"owned-tree termination failed: {type(exc).__name__}: {exc}")
    try:
        stdout, stderr = process.communicate(timeout=15)
        reaped = process.returncode is not None
        if not reaped:
            errors.append("owned parent has no terminal return code")
    except (OSError, subprocess.TimeoutExpired) as exc:
        stdout = getattr(exc, "stdout", None) or getattr(expired, "stdout", None) or b""
        stderr = getattr(exc, "stderr", None) or getattr(expired, "stderr", None) or b""
        reaped = False
        errors.append(f"owned pipe drainage failed: {type(exc).__name__}: {exc}")
    cleanup["confirmed"] = killed and reaped
    return stdout, stderr, cleanup


def main() -> int:
    required = ("EC_WORKLOAD_SOURCE", "EC_WORKLOAD_OUT", "EC_WORKLOAD_SHA", "EC_WORKLOAD_WORK")
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
    parent = plain_directory(Path(os.environ["EC_WORKLOAD_WORK"]))
    if parent != ROOT.parent / "work":
        raise RuntimeError("workload work directory is not the EC job sibling")
    requested_out = Path(os.environ["EC_WORKLOAD_OUT"]).absolute()
    plain_directory(requested_out.parent)
    try:
        plain_directory(requested_out)
    except FileNotFoundError:
        pass  # Its parent already exists and was checked without following links.
    out = requested_out.resolve()
    if (out.is_relative_to(ROOT) or ROOT.is_relative_to(out)
            or out.is_relative_to(parent) or parent.is_relative_to(out)):
        raise RuntimeError("workload output intersects source or work")
    out.mkdir(parents=True, exist_ok=True)
    plain_directory(out)
    env = dict(os.environ)
    env.update(PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT))
    # The pool date is not an exemption oracle; pin it explicitly for replay.
    env["PINWASH_TODAY"] = "2026-09-30"
    env.pop("PINWASH_DOCTOR_SELFTEST", None)
    started = time.monotonic()
    owned = Path(tempfile.mkdtemp(prefix="alpha2-", dir=parent))
    env.update(TEMP=str(owned), TMP=str(owned), TMPDIR=str(owned))
    result: dict[str, object] = {}
    temp_cleanup: dict[str, object] = {"path": str(owned), "confirmed": False, "retained": True}
    try:
        result = collect(expected, out, env, started + 1140)
    except Exception as exc:
        # Keep every raw file already written; an unexpected harness error
        # cannot certify children stopped, so its scratch is retained.
        result = {"passed": False, "requested_sha": expected, "actual_sha": None,
                  "tests_run": 0, "raw_json_equal": None, "steps": [],
                  "child_cleanup_confirmed": False,
                  "problems": [f"harness exception: {type(exc).__name__}: {exc}"]}
    finally:
        if result.get("child_cleanup_confirmed") is True:
            try:
                remove_owned_temp(owned, parent, started + 1170)
                temp_cleanup.update(confirmed=True, retained=False)
            except (OSError, ValueError) as exc:
                temp_cleanup["error"] = f"{type(exc).__name__}: {exc}"
        else:
            temp_cleanup["error"] = "child cleanup unconfirmed; owned temporary tree retained"
    result["temporary_cleanup"] = temp_cleanup
    result["budget_seconds"] = {"commands": 1140, "cleanup_deadline": 1170, "outer": 1200}
    if not temp_cleanup["confirmed"]:
        result["passed"] = False
        result["problems"].append("owned temporary cleanup not confirmed")
    write_json(out / "result.json", result)
    lines = [
        "# pinwash alpha round 2 validation", "",
        f"Result: {'PASS' if result['passed'] else 'FAIL'}", "",
        f"Source: `{result['actual_sha']}` (requested `{expected}`)",
        f"Tests run: {result['tests_run']}; raw JSON equality: {result['raw_json_equal']}", "",
        f"Supplementary workload tests: {result.get('workload_tests', {}).get('tests_run', 0)}; "
        f"passed: {result.get('workload_tests', {}).get('ok', False)}", "",
        "Supplementary workload tests are separate from the complete product suite and doctor.",
        "Commands, exits, raw streams, cleanup and test-source hashes: `result.json`.", "",
    ]
    lines.extend(f"- {problem}" for problem in result["problems"])
    lines.extend(["", "Coverage is one EC Windows runtime and seeded regression cases.",
                  "Cross-platform determinism and held-out agent accuracy are not assessed.", ""])
    (out / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return 0 if result["passed"] else 1


def collect(expected: str, out: Path, env: dict[str, str], deadline: float) -> dict[str, object]:
    steps: list[dict[str, object]] = []
    # The outer declaration stays at 20 minutes. Commands end by 1140s;
    # owned-child/temp cleanup shares the next 30s, leaving 30s for receipts.
    blocked: str | None = None
    child_cleanup_confirmed = True

    def run(name: str, command: list[str], *, seed: str = "1", depth: str | None = None) -> tuple[int, bytes, bytes]:
        nonlocal blocked, child_cleanup_confirmed
        started = time.monotonic()
        step_env = dict(env, PYTHONHASHSEED=seed)
        if depth is not None:
            step_env["PINWASH_DOCTOR_SELFTEST"] = depth
        timed_out = False
        cleanup = None
        error = None
        actual_exit_code = None
        remaining = deadline - started
        if remaining <= 0 and blocked is None:
            blocked = "command budget expired; cleanup and receipt reserve retained"
        if blocked is not None:
            code, stdout, stderr = 2, b"", b""
            error = blocked
            state = "NOT_RUN"
        else:
            state = "COMPLETED"
            process = None
            try:
                process = subprocess.Popen(command, cwd=ROOT, env=step_env,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           start_new_session=os.name != "nt")
                bound = 570 if name in ("suite", "doctor") else 30
                stdout, stderr = process.communicate(timeout=min(bound, remaining))
                code = process.returncode
                actual_exit_code = process.returncode
            except subprocess.TimeoutExpired as exc:
                code, timed_out, state = 2, True, "TIMED_OUT"
                stdout, stderr, cleanup = stop_owned(process, exc, windows=os.name == "nt")
                actual_exit_code = process.returncode
                blocked = "command timed out; further commands NOT_RUN"
                if not cleanup["confirmed"]:
                    child_cleanup_confirmed = False
                    blocked = "owned command cleanup unconfirmed; further commands NOT_RUN"
            except OSError as exc:
                code, stdout, stderr = 2, b"", b""
                error = f"{type(exc).__name__}: {exc}"
                state = "START_FAILED"
                blocked = "command failed to start or communicate; further commands NOT_RUN"
                if process is not None:
                    stdout, stderr, cleanup = stop_owned(process, exc, windows=os.name == "nt")
                    actual_exit_code = process.returncode
                    state = "IO_FAILED"
                    if not cleanup["confirmed"]:
                        child_cleanup_confirmed = False
                        blocked = "owned command cleanup unconfirmed; further commands NOT_RUN"
        (out / f"{name}.stdout").write_bytes(stdout)
        (out / f"{name}.stderr").write_bytes(stderr)
        steps.append({
            "name": name, "command": command, "exit_code": code,
            "actual_exit_code": actual_exit_code,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "timed_out": timed_out, "pythonhashseed": seed,
            "state": state, "cleanup": cleanup, "error": error,
            "doctor_selftest_depth": depth,
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
    harness_count = 0
    harness_ok = False
    doctor_payload: object = None
    deterministic: bool | None = None
    if not problems:
        python = [sys.executable, "-X", "utf8", "-B"]
        code, _, harness_stderr = run(
            "workload-tests", python + ["-m", "unittest", "discover", "-s",
                                       "workloads/alpha2_verify/tests", "-p", "test_*.py", "-v"],
        )
        harness_text = harness_stderr.decode("utf-8", "replace")
        harness_counts = re.findall(r"(?m)^Ran (\d+) tests? in ", harness_text)
        harness_count = int(harness_counts[-1]) if harness_counts else 0
        harness_ok = (code == 0 and harness_count > 0
                      and not re.search(r"(?m)^OK \(.*skipped=", harness_text))
        if not harness_ok:
            problems.append("supplementary workload tests failed, ran zero tests, or skipped tests")
            blocked = blocked or "supplementary workload tests did not pass; further commands NOT_RUN"
        code, _, stderr = run(
            "suite", python + ["-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"], depth="1",
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
                and tests["nested_depth"] == 0
                and "skipped" not in tests
                and "excluded" not in tests
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
    return {
        "schema_version": 1, "milestone": "alpha-round-2",
        "requested_sha": expected, "actual_sha": actual,
        "runtime": {"python": sys.version, "platform": platform.platform()},
        "pinwash_today": env["PINWASH_TODAY"], "steps": steps,
        "workload_tests": {"tests_run": harness_count, "ok": harness_ok},
        "child_cleanup_confirmed": child_cleanup_confirmed,
        "child_cleanup_scope": "spawned parent and pipe completion; timeout subtree termination; no native EC Job census",
        "tests_run": count, "test_sources_sha256": tests_manifest,
        "doctor": doctor_payload, "raw_json_equal": deterministic,
        "passed": not problems, "problems": problems,
        "limitations": [
            "one EC Windows pool runtime; no cross-OS or Python matrix claim",
            "determinism probe compares a same-tree scan across hash seeds",
            "seeded regressions; no independent held-out agent accuracy claim",
        ],
    }


if __name__ == "__main__":
    raise SystemExit(main())
