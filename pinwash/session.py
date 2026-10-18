"""Two-step session consumer; no state is written into the subject repository."""
from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pinwash.consumer import ConsumerError, collect, identity, inspect, record_error, summarize


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_directory(override: str | None = None) -> Path:
    if override:
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        parent = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        parent = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return (parent / "pinwash").resolve()


def _paths(repo: Path, override: str | None) -> tuple[Path, Path]:
    import hashlib
    directory = state_directory(override)
    if directory.is_relative_to(repo):
        raise ConsumerError("Session state must be outside the repository being reviewed.")
    key = hashlib.sha256(os.fsencode(os.path.normcase(str(repo)))).hexdigest()
    return directory, directory / f"{key}.json"


def _read(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or path.stat().st_size > 65536:
            raise ValueError("unsafe or oversized state")
        def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate state key")
                result[key] = value
            return result
        state = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
        if not isinstance(state, dict) or state.get("schema_version") != 1:
            raise ValueError("unsupported state schema")
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", state.get("base", "")):
            raise ValueError("invalid baseline")
        if not re.fullmatch(r"[0-9a-f]{32}", state.get("id", "")):
            raise ValueError("invalid session identity")
        if not isinstance(state.get("repo"), str) or not isinstance(state.get("judge"), dict):
            raise ValueError("missing repository or judge identity")
        return state
    except FileNotFoundError as exc:
        raise ConsumerError("No session baseline. Run 'pinwash session start' before the agent edits.") from exc
    except (OSError, ValueError, TypeError) as exc:
        raise ConsumerError(f"Cannot read session state: {exc}. No fallback to HEAD.") from exc


def _write(path: Path, data: dict[str, Any], replace: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".pinwash-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, ensure_ascii=True, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            # Publish an intact file without overwriting an existing session.
            os.link(temporary, path)
    except FileExistsError as exc:
        raise ConsumerError("A session already exists. Review it first; use start --replace only to explicitly choose a new baseline.") from exc
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def start(repo: Path, *, state_dir: str | None = None, replace: bool = False,
          timeout: float = 60) -> dict[str, Any]:
    judge = identity()
    observation = inspect(repo, timeout)
    root = Path(observation["repo"])
    if not observation["clean"]:
        raise ConsumerError("Start needs a clean worktree. Commit or stash existing edits before starting; nothing was changed.")
    directory, active = _paths(root, state_dir)
    if active.exists() and not replace:
        raise ConsumerError("A session already exists. Review it first; start --replace explicitly accepts the current HEAD as a new baseline.")
    if identity() != judge:
        raise ConsumerError("The PinWash installation changed while starting. Start again with a fixed installation.")
    state = {"schema_version": 1, "id": uuid.uuid4().hex, "repo": str(root),
             "base": observation["head"], "judge": judge, "created_at": _now()}
    # Keep an immutable-by-convention original even when the active pointer is
    # explicitly replaced. These local files are not authenticated evidence.
    _write(directory / "sessions" / f"{state['id']}.json", state)
    _write(active, state, replace=replace)
    return dict(state, state_path=str(active))


def review(repo: Path, *, stopped: bool, state_dir: str | None = None,
           timeout: float = 60) -> dict[str, Any]:
    if not stopped:
        raise ConsumerError("Stop the agent and every process it started before review. Confirm interactively or pass --stopped from a trusted controller.")
    before = inspect(repo, timeout)
    root = Path(before["repo"])
    directory, active = _paths(root, state_dir)
    state = _read(active)
    if state["repo"] != str(root):
        raise ConsumerError("Session belongs to a different repository. No fallback to HEAD.")
    judge = identity()
    if state["judge"] != judge:
        raise ConsumerError("PinWash changed since session start. Restore that installation; do not silently reset the baseline.")
    base, head = state["base"], before["head"]
    runs = collect(root, [f"{base}..{head}", f"{base}..WORKTREE", f"{head}..WORKTREE"], timeout)
    errors = []
    try:
        after = inspect(root, timeout)
        if after != before:
            errors.append("Repository changed during review. Stop all writers and review again.")
        if identity() != judge or _read(active) != state:
            errors.append("Judge or session state changed during review.")
    except (ConsumerError, OSError) as exc:
        errors.append(str(exc))
    report = summarize(runs, errors)
    report.update(session_id=state["id"], repo=str(root), base=base, head=head,
                  judge=judge, reviewed_at=_now(), quiescence="caller_attested",
                  custody="local state; not protected against same-user modification")
    report_path = directory / "reports" / f"{state['id']}-{uuid.uuid4().hex}.json"
    report["report_path"] = str(report_path)
    try:
        _write(report_path, report)
    except (ConsumerError, OSError) as exc:
        report.pop("report_path")
        record_error(report, f"Could not save report: {exc}")
    # Review never changes the baseline or accepts exemptions. Repeated reviews
    # are allowed; a new session requires an explicit start --replace.
    return report
