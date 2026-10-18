"""Read local session metadata and historical reports; never scan or write."""
from __future__ import annotations

import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from pinwash.consumer import ConsumerError, identity, locate, record_error, summarize, validate_result
from pinwash.report import safe
from pinwash.session import _paths, _plain_file, _read, _read_json

_SHA = r"[0-9a-f]{40}|[0-9a-f]{64}"
_REPORT_LIMIT = 4 * 1024 * 1024
_TOTAL_LIMIT = 16 * 1024 * 1024
_ENTRY_LIMIT = 5000


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("missing timestamp")
    stamp = datetime.fromisoformat(value)
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError("timestamp needs a timezone")
    return stamp


def _latest(directory: Path, state: dict[str, Any]) -> dict[str, Any] | None:
    reports = directory / "reports"
    try:
        info = reports.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("reports directory is a link or not a directory")
    selected = None
    selected_key = None
    budget = _TOTAL_LIMIT
    # Validate every candidate for this session. A damaged candidate means we
    # cannot identify the latest result; never silently fall back to an old pass.
    with os.scandir(reports) as entries:
        for count, entry in enumerate(entries, 1):
            if count > _ENTRY_LIMIT:
                raise ValueError("too many report directory entries to determine the latest review")
            if not entry.name.startswith(state["id"] + "-"):
                continue
            if not re.fullmatch(state["id"] + r"-[0-9a-f]{32}\.json", entry.name):
                raise ValueError("unexpected filename for this session's report")
            path = reports / entry.name
            size = _plain_file(path).st_size
            if size > budget:
                raise ValueError("report history exceeds the status read budget")
            budget -= size
            report = _read_json(path, min(_REPORT_LIMIT, budget + size))
            if not isinstance(report, dict) or report.get("consumer_schema_version") != 1:
                raise ValueError("unsupported report schema")
            for key, expected in (("session_id", state["id"]), ("repo", state["repo"]),
                                  ("base", state["base"]), ("judge", state["judge"])):
                if report.get(key) != expected:
                    raise ValueError(f"report {key} does not match the active session")
            stamp = _timestamp(report.get("reviewed_at"))
            if stamp < _timestamp(state["created_at"]):
                raise ValueError("review predates the session")
            if not re.fullmatch(_SHA, report.get("head", "")):
                raise ValueError("invalid reviewed HEAD")
            runs, errors = report.get("runs"), report.get("errors")
            ranges = [f"{state['base']}..{report['head']}",
                      f"{state['base']}..WORKTREE", f"{report['head']}..WORKTREE"]
            if not isinstance(runs, list) or len(runs) != 3:
                raise ValueError("incomplete report structure")
            if not isinstance(errors, list) or not all(isinstance(e, str) for e in errors):
                raise ValueError("invalid report errors")
            for run, expected_range in zip(runs, ranges):
                if not isinstance(run, dict) or run.get("range") != expected_range:
                    raise ValueError("report comparison does not match the session")
                if "error" in run:
                    if not isinstance(run["error"], str) or run.get("exit_code") != 2:
                        raise ValueError("invalid failed comparison")
                else:
                    if run.get("exit_code") not in (0, 1):
                        raise ValueError("invalid comparison exit code")
                    if not isinstance(run.get("payload"), dict):
                        raise ValueError("invalid comparison payload")
                    validate_result(run["payload"], run["exit_code"])
            expected = summarize(runs)
            if any(error not in errors for error in expected["errors"]):
                raise ValueError("report omitted a comparison error")
            for error in errors:
                if error not in expected["errors"]:
                    record_error(expected, error)
            for key in ("status", "exit_code", "execution_complete", "findings",
                        "unknown_coverage", "config_errors"):
                if report.get(key) != expected[key]:
                    raise ValueError(f"inconsistent report {key}")
            candidate_key = (stamp, entry.name)
            if selected_key is None or candidate_key > selected_key:
                selected_key = candidate_key
                selected = {"reviewed_at": report["reviewed_at"], "status": report["status"],
                            "exit_code": report["exit_code"], "execution_complete": report["execution_complete"],
                            "findings": len(report["findings"]), "unassessed": len(report["unknown_coverage"]),
                            "configuration_errors": len(report["config_errors"]),
                            "report_path": str(path), "head": report["head"]}
    return selected


def status(repo: Path, *, state_dir: str | None = None, timeout: float = 60) -> dict[str, Any]:
    result: dict[str, Any] = {
        "session_status_schema_version": 1, "status": "unavailable", "exit_code": 2,
        "current_changes": "not_reviewed", "session": None, "judge_matches": None,
        "latest_review": None, "errors": [],
        "next_step": "Resolve the status error; preserve the original baseline and reports.",
    }
    try:
        root = locate(repo, timeout)
        directory, active = _paths(root, state_dir)
        result.update(repo=str(root), state_path=str(active))
        try:
            active.lstat()
        except FileNotFoundError:
            result.update(status="no_session", exit_code=0,
                          next_step="Before editing, run pinwash session start from a clean worktree.")
            return result
        state = _read(active)
        if state["repo"] != str(root):
            raise ValueError("session belongs to a different repository")
        _timestamp(state.get("created_at"))
        judge = state["judge"]
        if (not all(isinstance(judge.get(k), str) for k in ("version", "python", "source_sha256"))
                or not re.fullmatch(r"[0-9a-f]{64}", judge["source_sha256"])
                or type(judge.get("spec_version")) is not int):
            raise ValueError("invalid saved judge identity")
        result["session"] = {key: state[key] for key in ("id", "base", "created_at", "judge")}
        result["judge_matches"] = judge == identity()
        if not result["judge_matches"]:
            result["errors"].append("PinWash changed since session start. Restore that installation; do not reset the baseline.")
        result["latest_review"] = _latest(directory, state)
        if _read(active) != state:
            result["latest_review"] = None
            raise ValueError("session changed while reading status; try status again")
        if not result["errors"]:
            result.update(status="active", exit_code=0,
                          next_step="When the agent and all its writers have stopped, run pinwash session review.")
    except (ConsumerError, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        result["latest_review"] = None
        result["errors"].append(f"Cannot read session status: {exc}")
    return result


def render_status(result: dict[str, Any]) -> str:
    lines = ["PinWash session status", f"Session: {safe(result['status'])}",
             "Current changes: NOT REVIEWED (status does not scan the worktree)."]
    if result.get("repo"):
        lines += [f"Repository: {safe(result['repo'])}", f"State: {safe(result['state_path'])}"]
    state = result["session"]
    if state:
        match = {True: "matches baseline", False: "CHANGED", None: "UNKNOWN (identity could not be read)"}[result["judge_matches"]]
        lines += [f"Session ID: {safe(state['id'])}", f"Baseline: {safe(state['base'])}",
                  f"Started: {safe(state['created_at'])}",
                  f"Installed judge: {match}"]
    last = result["latest_review"]
    if last:
        lines += [f"Last saved review (historical): {safe(last['status'])}; exit {last['exit_code']}",
                  f"Reviewed at: {safe(last['reviewed_at'])}",
                  f"Findings: {last['findings']} | Unassessed: {last['unassessed']} | Configuration errors: {last['configuration_errors']}",
                  f"Saved report: {safe(last['report_path'])}"]
    elif result["status"] == "active":
        lines.append("Last saved review: none for this session.")
    else:
        lines.append("Last saved review: not determined.")
    lines += [f"Needs attention: {safe(e)}" for e in result["errors"]]
    lines += [f"Next: {safe(result['next_step'])}",
              "Use the same --state-dir if you selected a custom directory.",
              "Historical reports do not judge current changes. Local records are not authenticated."]
    return "\n".join(lines) + "\n"
