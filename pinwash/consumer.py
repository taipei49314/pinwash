"""Bounded, isolated invocations of the installed judge for human consumers.

The runtime, installation and caller's environment are trusted. The repository
is data. Neither an external state file nor a digest authenticates its owner.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any

from pinwash import FINDINGS_VERSION, SPEC_VERSION, __version__

PACKAGE = Path(__file__).resolve().parent


class ConsumerError(Exception):
    pass


def identity() -> dict[str, Any]:
    digest = hashlib.sha256()
    for path in sorted(PACKAGE.rglob("*.py")):
        if "_verification" in path.relative_to(PACKAGE).parts:
            continue
        name = path.relative_to(PACKAGE).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(name).to_bytes(8, "big") + name)
        digest.update(len(data).to_bytes(8, "big") + data)
    return {"version": __version__, "spec_version": SPEC_VERSION, "python": sys.version,
            "source_sha256": digest.hexdigest()}


def _inspect(repo_path: str) -> dict[str, Any]:
    """Runs in a bounded child; no subject programs, filters or hooks run."""
    from pinwash.gitrepo import (
        ignored_surface_paths, ls_tree, ls_worktree, repository_root, resolve_commit,
    )
    repo = repository_root(Path(repo_path))
    head = resolve_commit(repo)
    files, unread = ls_worktree(repo)
    ignored = ignored_surface_paths(repo)
    digest = hashlib.sha256()
    for name, data in sorted(files.items()):
        encoded = os.fsencode(name)
        digest.update(len(encoded).to_bytes(8, "big") + encoded)
        digest.update(len(data).to_bytes(8, "big") + data)
    digest.update(json.dumps([unread, ignored], ensure_ascii=True, sort_keys=True).encode())
    baseline = ls_tree(repo, head)
    def same(path: str, data: bytes) -> bool:
        target = repo.joinpath(*path.split("/"))
        if target.is_symlink():
            return os.fsencode(os.readlink(target)) == baseline[path]
        if data == baseline[path]:
            return True
        try:
            return data.decode("utf-8").replace("\r\n", "\n") == baseline[path].decode("utf-8").replace("\r\n", "\n")
        except UnicodeError:
            return False
    clean = not unread and files.keys() == baseline.keys() and all(same(p, d) for p, d in files.items())
    return {"repo": str(repo), "head": head, "tree_digest": digest.hexdigest(), "clean": clean}


def invoke(repo: Path, operation: str, argument: str | None, timeout: float,
           today: str | None = None) -> tuple[dict[str, Any], int]:
    # -I ignores PYTHONPATH and the subject's implicit cwd. Only this installation
    # is inserted, before changing directory. The child cannot select a judge
    # from the subject. Git redirection env vars are not consumer input.
    bootstrap = """import os, sys, json
sys.path.insert(0, sys.argv[1])
from pinwash.consumer import _inspect
from pinwash.cli import main
repo, op, arg = sys.argv[2:5]
try:
    os.chdir(repo)
    if op == 'inspect':
        print(json.dumps(_inspect(repo), ensure_ascii=True))
    else:
        sys.exit(main(['check'] + ([arg] if arg else [])))
except Exception as exc:
    sys.stderr.write(str(exc) + '\\n')
    sys.exit(2)
"""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    if today is not None:
        env["PINWASH_TODAY"] = today
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-B", "-c", bootstrap, str(PACKAGE.parent),
             str(repo), operation, argument or ""],
            cwd=PACKAGE.parent, env=env, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ConsumerError(f"Timed out after {timeout:g}s; this comparison was not judged.") from exc
    except OSError as exc:
        raise ConsumerError(f"Could not start the judge: {exc}") from exc
    if proc.returncode not in (0, 1) or (operation == "inspect" and proc.returncode != 0):
        message = proc.stderr.decode("utf-8", "replace").strip()
        raise ConsumerError(message or f"Judge exited {proc.returncode}; not judged.")
    try:
        payload = json.loads(proc.stdout)
        if not isinstance(payload, dict):
            raise ValueError("expected an object")
        if operation == "check":
            validate_result(payload, proc.returncode)
    except (ValueError, TypeError, KeyError) as exc:
        raise ConsumerError(f"Invalid judge output; not judged: {exc}") from exc
    return payload, proc.returncode


def validate_result(payload: dict[str, Any], code: int) -> None:
    if payload.get("pinwash_findings_version") != FINDINGS_VERSION:
        raise ValueError("unsupported findings schema")
    if payload.get("verdict") != ("block" if code == 1 else "pass"):
        raise ValueError("verdict and exit code disagree")
    if not isinstance(payload.get("run"), dict) or payload["run"].get("spec_version") != SPEC_VERSION:
        raise ValueError("judge spec changed")
    for key in ("findings", "unknown_coverage", "config_errors"):
        if not isinstance(payload.get(key), list):
            raise ValueError(f"missing {key}")
    for finding in payload["findings"]:
        if not isinstance(finding, dict):
            raise ValueError("invalid finding object")
        for key in ("rule", "path", "severity", "message", "before", "after", "fingerprint"):
            if not isinstance(finding.get(key), str):
                raise ValueError(f"invalid finding {key}")
        if finding["severity"] not in ("info", "warn", "high", "critical"):
            raise ValueError("invalid severity")
    for row in payload["unknown_coverage"]:
        if not isinstance(row, dict) or not all(isinstance(row.get(k), str) for k in ("path", "reason")):
            raise ValueError("invalid coverage row")
    if not all(isinstance(x, str) for x in payload["config_errors"]):
        raise ValueError("invalid configuration error")


def inspect(repo: Path, timeout: float) -> dict[str, Any]:
    result, _ = invoke(repo.resolve(), "inspect", None, timeout)
    root = Path(result["repo"])
    if PACKAGE.is_relative_to(root):
        raise ConsumerError("Install PinWash outside the repository being reviewed.")
    return result


def collect(repo: Path, ranges: list[str | None], timeout: float) -> list[dict[str, Any]]:
    runs = []
    today = os.environ.get("PINWASH_TODAY") or date.today().isoformat()
    for range_arg in ranges:
        row: dict[str, Any] = {"range": range_arg or "HEAD..WORKTREE", "requested_date": today}
        try:
            payload, code = invoke(repo, "check", range_arg, timeout, today=today)
            row.update(payload=payload, exit_code=code)
        except ConsumerError as exc:
            row.update(error=str(exc), exit_code=2)
        runs.append(row)
    return runs


def summarize(runs: list[dict[str, Any]], errors: list[str] | None = None) -> dict[str, Any]:
    errors = list(errors or [])
    findings: dict[str, dict[str, Any]] = {}
    coverage: dict[tuple[str, str], dict[str, Any]] = {}
    config_errors: set[str] = set()
    held = blocked = False
    ranks = {"info": 0, "warn": 1, "high": 2, "critical": 3}
    for run in runs:
        if "error" in run:
            errors.append(f"{run['range']}: {run['error']}")
            continue
        payload = run["payload"]
        blocked |= run["exit_code"] == 1
        config_errors.update(payload["config_errors"])
        for f in payload["findings"]:
            held |= f["rule"] == "EXEMPTION_ADDED"
            key = f["fingerprint"]
            if key not in findings:
                findings[key] = dict(f, observations=[])
            item = findings[key]
            item["observations"].append({"range": run["range"], "severity": f["severity"]})
            if ranks[f["severity"]] > ranks[item["severity"]]:
                item["severity"] = f["severity"]
        for row in payload["unknown_coverage"]:
            key = row["path"], row["reason"]
            coverage.setdefault(key, dict(row, ranges=[]))["ranges"].append(run["range"])
    status = "block" if blocked else "not_judged" if errors else "held" if held else "pass"
    # Consumer codes: 3 is a human-review hold. Errors take exit 2 even if a
    # completed comparison blocked; its blocking findings remain in the report.
    code = 2 if errors else 1 if blocked else 3 if held else 0
    return {"consumer_schema_version": 1, "status": status, "exit_code": code,
            "execution_complete": not errors, "errors": errors,
            "findings": sorted(findings.values(), key=lambda f: (f["path"], f["rule"], f["fingerprint"])),
            "unknown_coverage": [coverage[k] for k in sorted(coverage)],
            "config_errors": sorted(config_errors), "runs": runs}
