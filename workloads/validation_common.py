"""Narrow workload support; no product imports and no previous-run cleanup authority.

Owned scratch validation and process termination were carried forward from reviewed
91c9796/a5af21c sources. Only this dispatch's freshly-created scratch may be deleted.
"""
from __future__ import annotations
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

SEEDS = ["1", "17"]
RANGES = ["BASE..HEAD", "BASE..WORKTREE", "HEAD..WORKTREE"]

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, sort_keys=True, ensure_ascii=False, indent=2)
        handle.write("\n")


def safe_path(path: str) -> bool:
    if not isinstance(path, str) or not path or path.startswith("/") or any(c in path for c in "\\:\x00\r\n\t"):
        return False
    reserved = {"con", "prn", "aux", "nul", *("com" + str(i) for i in range(1, 10)), *("lpt" + str(i) for i in range(1, 10))}
    return all(p not in ("", ".", "..") and p.casefold() != ".git" and p == p.rstrip(" .")
               and p.split(".")[0].casefold() not in reserved for p in path.split("/"))


def fingerprint_identity(f: dict) -> tuple:
    return f["rule"], f["path"], f.get("locator", ""), f["before"], f["after"]


def spec_fingerprint(f: dict) -> str:
    # Independent SPEC §7 oracle; do not import the candidate implementation.
    identity = {"rule": f["rule"], "path": f["path"], "locator": f.get("locator", ""),
                "before_digest": digest(f["before"].encode("utf-8", "surrogatepass")),
                "after_digest": digest(f["after"].encode("utf-8", "surrogatepass"))}
    encoded = json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "surrogatepass")
    return f["rule"] + "/" + f["path"] + "/v1:" + digest(encoded)


def reject_redirected_ancestors(path: Path) -> None:
    if not path.is_absolute():
        raise ValueError("scratch path must be absolute")
    for ancestor in reversed([path, *path.parents]):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            if ancestor == path:
                continue
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("scratch ancestor is a symlink/reparse point")


def owned_tree_files(root: Path, parent: Path, *, directories: list[Path] | None = None) -> list[Path]:
    # Validate the absolute deletion target and every entry before removing
    # anything. Only a direct, real, named scratch directory is admitted.
    reject_redirected_ancestors(parent)
    reject_redirected_ancestors(root)
    if (root.is_symlink() or root.resolve() != root or parent.resolve() != parent
            or root.resolve().parent != parent.resolve()
            or not root.name.startswith("pinwash-candidate-") or not root.is_dir()):
        raise ValueError("scratch ownership/path check failed")
    found, stack = [], [root]
    while stack:
        path = stack.pop()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("scratch contains a symlink/reparse point")
        if stat.S_ISDIR(info.st_mode):
            if directories is not None and path != root:
                directories.append(path)
            stack.extend(path.iterdir())
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise ValueError("scratch contains a hardlinked file")
            found.append(path)
        else:
            raise ValueError("scratch contains a nonregular entry")
    return found


def remove_owned_tree(root: Path, parent: Path) -> None:
    owned_tree_files(root, parent)
    absolute = root.resolve()

    def clear_readonly(operation, target, error):
        exc = error[1] if isinstance(error, tuple) else error
        path = Path(target)
        reject_redirected_ancestors(path.parent)
        info = path.lstat()
        if (not isinstance(exc, PermissionError) or operation is not os.unlink
                or absolute not in path.resolve().parents
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or getattr(info, "st_file_attributes", 0) & 0x400
                or path.is_symlink()
                or (info.st_mode & stat.S_IWRITE and not getattr(info, "st_file_attributes", 0) & 1)):
            raise exc
        # Clear only the read-only bit on this owned ordinary file. ACLs,
        # directories, security settings and unrelated user files are untouched.
        os.chmod(path, info.st_mode | stat.S_IWRITE)
        operation(path)

    if sys.version_info >= (3, 12):
        shutil.rmtree(absolute, onexc=clear_readonly)
    else:
        shutil.rmtree(absolute, onerror=clear_readonly)
    if os.path.lexists(absolute):
        raise OSError("owned scratch still exists after cleanup")


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


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def decode(raw: bytes):
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def check_payload(raw: bytes, code, identity: dict, base: str, head: str) -> dict:
    value = decode(raw)
    if not isinstance(value, dict) or set(value) != {
        "pinwash_findings_version", "run", "findings", "summary", "verdict", "unknown_coverage", "config_errors"
    }:
        raise ValueError("unexpected findings envelope")
    wanted = {"pinwash_version": identity["engine_version"], "spec_version": identity["spec_version"],
              "base": base, "head": head}
    if (value["run"] != wanted or type(value["run"]["spec_version"]) is not int
            or type(value["pinwash_findings_version"]) is not int or value["pinwash_findings_version"] != 1):
        raise ValueError("wrong exact public CLI metadata")
    if type(code) is not int or code not in (0, 1) or value["config_errors"] != []:
        raise ValueError("engine errors cannot be accepted as a pass")
    if not isinstance(value["findings"], list) or not isinstance(value["unknown_coverage"], list):
        raise ValueError("invalid finding or visibility collection")
    counts = dict.fromkeys(("critical", "high", "info", "warn"), 0)
    for f in value["findings"]:
        fields = {"rule", "severity", "path", "message", "before", "after", "fingerprint"}
        if (not isinstance(f, dict) or set(f) not in (fields, fields | {"locator"})
                or any(not isinstance(v, str) for v in f.values()) or f["severity"] not in counts
                or f["fingerprint"] != spec_fingerprint(f)):
            raise ValueError("invalid complete finding or SPEC fingerprint")
        counts[f["severity"]] += 1
    rows = []
    for row in value["unknown_coverage"]:
        if (not isinstance(row, dict) or set(row) != {"path", "reason"}
                or any(not isinstance(v, str) for v in row.values())):
            raise ValueError("invalid unknown coverage row")
        rows.append((row["path"], row["reason"]))
    if rows != sorted(set(rows)) or value["summary"] != counts or any(type(n) is not int for n in value["summary"].values()):
        raise ValueError("summary or unique sorted visibility inconsistent")
    blocking = bool(counts["critical"] or counts["high"])
    if code != int(blocking) or value["verdict"] != ("block" if blocking else "pass"):
        raise ValueError("exit/verdict disagrees with findings")
    return value


def matches_oracle(payload: dict, code, expected: dict) -> bool:
    # Counter, not a set: two equal findings remain two expected occurrences.
    return (code == expected["exit_code"]
            and Counter(map(canonical, payload["findings"])) == Counter(map(canonical, expected["findings"]))
            and Counter(map(canonical, payload["unknown_coverage"])) == Counter(map(canonical, expected["unknown_coverage"])))


def session_outcome(scans: list[dict], *, conservative=False) -> str:
    """Public consumer outcome and independent acceptance state stay separate.

    Public status has block precedence, then not_judged, exemption-held, pass.
    Conservative acceptance additionally holds unknown coverage and never accepts
    an incomplete session, including one with a blocking sibling scan.
    """
    bad = len(scans) != 3 or any(s.get("state") != "COMPLETED" or s.get("payload") is None
                              or s.get("exit_code") not in (0, 1) for s in scans)
    blocked = any(s.get("payload") is not None and s.get("exit_code") == 1 for s in scans)
    if conservative and bad:
        return "NOT_JUDGED"
    if blocked:
        return "BLOCK" if conservative else "block"
    if bad:
        return "NOT_JUDGED" if conservative else "not_judged"
    held = any(f["rule"] == "EXEMPTION_ADDED" for s in scans for f in s["payload"]["findings"])
    if conservative:
        held = held or any(s["payload"]["unknown_coverage"] for s in scans)
    return ("HELD" if held else "PASS") if conservative else ("held" if held else "pass")


def expected_tuples(cases, engines):
    return {(c["id"], engine, range_name, seed) for c in cases for engine in engines
            for range_name in RANGES for seed in SEEDS}


def matrix_status(rows, wanted):
    keys = [tuple(row["tuple"]) for row in rows]
    complete = len(keys) == len(wanted) and len(set(keys)) == len(keys) and set(keys) == wanted
    execution = complete and all(r["state"] == "COMPLETED" and r["payload"] is not None
                                 and type(r["exit_code"]) is int and r["exit_code"] in (0, 1)
                                 and all(isinstance(r.get(k), str) and re.fullmatch(r"[0-9a-f]{64}", r[k])
                                         for k in ("stdout_sha256", "stderr_sha256")) for r in rows)
    grouped = {}
    for row in rows:
        grouped.setdefault(tuple(row["tuple"][:-1]), []).append(row)
    deterministic = execution and all(len(pair) == 2 and all(
        pair[0][k] == pair[1][k] for k in ("exit_code", "stdout_sha256", "stderr_sha256")) for pair in grouped.values())
    semantics = execution and all(r.get("oracle_matched") is True for r in rows)
    return {"matrix_complete": complete, "execution_status": "COMPLETE" if execution else "INCOMPLETE",
            "determinism_status": "PASS" if deterministic else "FAIL" if execution else "NOT_JUDGED",
            "semantic_status": "PASS" if semantics else "FAIL" if execution else "NOT_JUDGED"}


class Commands:
    def __init__(self, out: Path, env: dict, stop=stop_owned, *, budget_seconds=1140):
        self.out, self.env, self.stop_owned = out, env, stop
        self.deadline, self.blocked, self.steps = time.monotonic() + budget_seconds, None, []
        self.names = set()

    def run(self, name, args, cwd, *, seed="1", pythonpath=None):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", name) or name in self.names:
            raise ValueError("duplicate or unsafe command log identity")
        self.names.add(name)
        started = time.monotonic()
        remaining = self.deadline - started
        if remaining <= 0:
            self.blocked = "command budget expired; cleanup and receipt reserve retained"
        process = None
        state, code, stdout, stderr, cleanup, error = "NOT_RUN", None, b"", b"", None, self.blocked
        timed_out = False
        if not self.blocked:
            env = dict(self.env, PYTHONHASHSEED=seed)
            if pythonpath is not None:
                env["PYTHONPATH"] = str(pythonpath)
            try:
                process = subprocess.Popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, start_new_session=os.name != "nt")
                stdout, stderr = process.communicate(timeout=min(60, remaining))
                state, code = "COMPLETED", process.returncode
            except subprocess.TimeoutExpired as exc:
                state, timed_out = "TIMED_OUT", True
                stdout, stderr, cleanup = self.stop_owned(process, exc, windows=os.name == "nt")
                code, error = process.returncode, "command timed out"
                self.blocked = "owned command timed out; remaining work NOT_RUN"
            except OSError as exc:
                state, error = "START_FAILED", f"{type(exc).__name__}: {exc}"
                if process is not None:
                    state = "IO_FAILED"
                    stdout, stderr, cleanup = self.stop_owned(process, exc, windows=os.name == "nt")
                    code = process.returncode
                self.blocked = "command start/IO failed; remaining work NOT_RUN"
        # Raw channels contain only actual child bytes. Wrapper diagnostics have
        # their own field and a nonexistent process has no invented exit code.
        record = {"name": name, "command": args, "cwd": str(cwd), "state": state,
                  "exit_code": code, "timed_out": timed_out, "cleanup": cleanup,
                  "wrapper_error": error, "pythonhashseed": seed,
                  "elapsed_seconds": round(time.monotonic() - started, 3),
                  "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)}
        self.steps.append(record)
        for suffix, raw in (("stdout", stdout), ("stderr", stderr)):
            with (self.out / (name + "." + suffix)).open("xb") as handle:
                handle.write(raw)
        return {**record, "stdout": stdout, "stderr": stderr}


def export_engine(require, git, source: Path, target: Path, identity: dict, *, revision=None):
    """Export exact reviewed Git blobs; no installation or source-tree imports."""
    revision = revision or identity["revision"]
    if require("engine-tree-" + target.name, git + ["rev-parse", revision + ":pinwash"], source).strip() != identity["tree"]:
        raise ValueError("engine package tree differs from frozen identity")
    names = require("engine-files-" + target.name, git + ["ls-tree", "-r", "--name-only", revision, "pinwash", "SPEC.md"], source).splitlines()
    for index, name in enumerate(names):
        if not safe_path(name):
            raise ValueError("unsafe exported engine path")
        data = require("engine-blob-" + target.name + "-" + str(index), git + ["show", revision + ":" + name], source, raw=True)
        path = target.joinpath(*name.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    if digest((target / "SPEC.md").read_bytes()) != identity["spec_sha256"]:
        raise ValueError("engine SPEC differs from frozen identity")


def validate_engines(engines):
    if set(engines) != {"baseline", "candidate"}:
        raise ValueError("exactly two engines required")
    for name, value in engines.items():
        if (set(value) != {"revision", "tree", "spec_sha256", "engine_version", "spec_version"}
                or not re.fullmatch(r"[0-9a-f]{40}", value["revision"])
                or not re.fullmatch(r"[0-9a-f]{40}", value["tree"])
                or not re.fullmatch(r"[0-9a-f]{64}", value["spec_sha256"])
                or value["engine_version"] != "0.1.1"
                or value["spec_version"] != (29 if name == "baseline" else 37)):
            raise ValueError("engine identities must be frozen before dispatch")
    if engines["baseline"]["revision"] != "ea185125565f2ef5b5b023c02039d1b00e40b462":
        raise ValueError("baseline revision drift")


