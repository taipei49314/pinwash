"""Offline, preregistered candidate CLI integration; execute only via EC pool."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("cases.json")
MANIFEST_SHA256 = "0532ad3347d7563e1f29a3fda3515ca412bcc6cbb677f0aa62922907b0702292"
CASE_COUNT = 27
SEEDS = ["1", "17"]
RANGES = ["BASE..HEAD", "BASE..WORKTREE", "HEAD..WORKTREE"]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, sort_keys=True, ensure_ascii=False, indent=2)
        handle.write("\n")


def safe_path(path: str) -> bool:
    return (isinstance(path, str) and bool(path) and not path.startswith("/")
            and "\\" not in path and ":" not in path and "\x00" not in path
            and all(p not in ("", ".", "..", ".git") for p in path.split("/")))


def validate_manifest(plan: dict) -> None:
    if (plan["schema_version"] != 1 or plan["seeds"] != SEEDS
            or plan["ranges"] != RANGES or len(plan["cases"]) != CASE_COUNT):
        raise ValueError("manifest schema, seeds, ranges or case count changed")
    if not re.fullmatch(r"[0-9a-f]{40}", plan["candidate_revision"]):
        raise ValueError("candidate must be an exact revision")
    ids = set()
    for case in plan["cases"]:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,60}", case["id"]) or case["id"] in ids:
            raise ValueError("unsafe or duplicate case id")
        ids.add(case["id"])
        for stage in ("base", "commit", "worktree"):
            if not isinstance(case[stage], dict):
                raise ValueError("fixture stage must be a literal file mapping")
            for path, content in case[stage].items():
                if not safe_path(path) or not (isinstance(content, str) or content is None):
                    raise ValueError("unsafe fixture path or content")
                if stage == "base" and content is None:
                    raise ValueError("base files cannot be deletions")
        if len(case["expected"]) != 3:
            raise ValueError("each case must preregister all three scans")
        codes = []
        for expected in case["expected"]:
            if expected["exit_code"] not in (0, 1):
                raise ValueError("an engine error is never an expected pass")
            codes.append(expected["exit_code"])
            blocking = any(f["severity"] in ("high", "critical") for f in expected["findings"])
            if bool(expected["exit_code"]) != blocking:
                raise ValueError("expected finding severity contradicts expected exit")
        predicted = "block" if 1 in codes else "held" if any(
            f["rule"] == "EXEMPTION_ADDED" for e in case["expected"] for f in e["findings"]
        ) else "pass"
        if case["session_expected"] != predicted:
            raise ValueError("session prediction contradicts the three scan predictions")


def finding_key(f: dict) -> tuple:
    return f["rule"], f["severity"], f["path"], f.get("locator", "")


def fingerprint_identity(f: dict) -> tuple:
    return f["rule"], f["path"], f.get("locator", ""), f["before"], f["after"]


def spec_fingerprint(f: dict) -> str:
    # Independent SPEC §7 oracle; do not import the candidate implementation.
    identity = {"rule": f["rule"], "path": f["path"], "locator": f.get("locator", ""),
                "before_digest": digest(f["before"].encode("utf-8", "surrogatepass")),
                "after_digest": digest(f["after"].encode("utf-8", "surrogatepass"))}
    encoded = json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "surrogatepass")
    return f["rule"] + "/" + f["path"] + "/v1:" + digest(encoded)


def check_payload(raw: bytes, code: int, expected: dict, plan: dict,
                  base: str, head: str) -> tuple[dict | None, list[str]]:
    problems = []
    try:
        payload = json.loads(raw.decode("utf-8", "strict"))
        if not isinstance(payload, dict):
            raise ValueError("output is not an object")
        run = payload["run"]
        if (run["base"] != base or run["head"] != head
                or run["spec_version"] != plan["spec_version"]
                or run["pinwash_version"] != plan["engine_version"]
                or payload["pinwash_findings_version"] != 1):
            return None, ["wrong run or judge identity"]
        findings = payload["findings"]
        if sorted(map(finding_key, findings)) != sorted(map(finding_key, expected["findings"])):
            problems.append("findings differ from preregistered rule/severity/path/locator multiset")
        for f in findings:
            pattern = re.escape(f["rule"] + "/" + f["path"] + "/v1:") + r"[0-9a-f]{64}"
            if not re.fullmatch(pattern, f["fingerprint"]):
                return None, ["invalid finding fingerprint"]
            if f["fingerprint"] != spec_fingerprint(f):
                return None, ["fingerprint differs from SPEC formula"]
        if sorted((u["path"], u["reason"]) for u in payload["unknown_coverage"]) != sorted(
                (u["path"], u["reason"]) for u in expected["unknown_coverage"]):
            problems.append("unknown coverage differs from preregistration")
        if payload["config_errors"] != []:
            problems.append("unexpected config error")
        summary = {s: sum(f["severity"] == s for f in findings) for s in ("critical", "high", "info", "warn")}
        if payload["summary"] != summary:
            return None, ["summary does not match findings"]
        if payload["verdict"] != ("block" if expected["exit_code"] == 1 else "pass"):
            problems.append("wrong verdict")
        if code != expected["exit_code"]:
            problems.append("wrong exit code")
        return payload, problems
    except (ValueError, KeyError, TypeError, UnicodeError, AttributeError) as exc:
        return None, [f"unjudged output: {type(exc).__name__}: {exc}"]


def session_outcome(scans: list[dict]) -> str:
    # Incomplete or invalid JSON must never become pass/held, even if another
    # scan blocks. Every session report retains its individual scan results.
    if len(scans) != 3 or any(s["state"] != "COMPLETED" or s["payload"] is None
                              or s["exit_code"] not in (0, 1) for s in scans):
        return "not-judged"
    if any(s["exit_code"] == 1 for s in scans):
        return "block"
    return "held" if any(f["rule"] == "EXEMPTION_ADDED"
                         for s in scans for f in s["payload"]["findings"]) else "pass"


def fixture_snapshot(repo: Path) -> dict:
    return {p.relative_to(repo).as_posix(): digest(p.read_bytes())
            for p in sorted(repo.rglob("*")) if p.is_file() and ".git" not in p.relative_to(repo).parts}


def aggregate_seed_state(pair: list[tuple[dict, dict | None]]) -> str:
    for step, payload in pair:
        if step["state"] != "COMPLETED":
            return step["state"]
        if step["exit_code"] not in (0, 1) or payload is None:
            return "NOT_JUDGED"
    return "COMPLETED"


class Commands:
    def __init__(self, out: Path, env: dict, stop_owned):
        self.out, self.env, self.stop_owned = out, env, stop_owned
        self.deadline = time.monotonic() + 1140  # 60 seconds reserved for cleanup/receipt
        self.blocked = None
        self.steps = []

    def run(self, name: str, args: list[str], cwd: Path, *, seed="1") -> dict:
        started = time.monotonic()
        remaining = self.deadline - started
        if remaining <= 0:
            self.blocked = "command budget expired; cleanup and receipt reserve retained"
        cleanup, timed_out = None, False
        process = None
        if self.blocked:
            state, code, stdout, stderr = "NOT_RUN", 2, b"", self.blocked.encode()
        else:
            try:
                process = subprocess.Popen(args, cwd=cwd, env=dict(self.env, PYTHONHASHSEED=seed),
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           start_new_session=os.name != "nt")
                stdout, stderr = process.communicate(timeout=min(60, remaining))
                state, code = "COMPLETED", process.returncode
            except subprocess.TimeoutExpired as exc:
                state, code, timed_out = "TIMED_OUT", 2, True
                stdout, stderr, cleanup = self.stop_owned(process, exc, windows=os.name == "nt")
                self.blocked = "owned command timed out; remaining work NOT_RUN"
                if not cleanup["confirmed"]:
                    self.blocked += "; owned-tree cleanup unconfirmed"
            except OSError as exc:
                state, code, stdout, stderr = "START_FAILED", 2, b"", str(exc).encode()
                if process is not None:
                    state = "IO_FAILED"
                    stdout, drained, cleanup = self.stop_owned(process, exc, windows=os.name == "nt")
                    stderr += drained
                self.blocked = "command start/IO failed; remaining work NOT_RUN"
        (self.out / f"{name}.stdout").write_bytes(stdout)
        (self.out / f"{name}.stderr").write_bytes(stderr)
        record = {"name": name, "command": args, "cwd": str(cwd), "state": state,
                  "exit_code": code, "timed_out": timed_out, "cleanup": cleanup,
                  "elapsed_seconds": round(time.monotonic() - started, 3),
                  "pythonhashseed": seed, "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)}
        self.steps.append(record)
        return {**record, "stdout": stdout, "stderr": stderr}


def main() -> int:
    expected = os.environ.get("EC_WORKLOAD_SHA", "")
    if (os.environ.get("EC_WORKLOAD_REPOSITORY") != "taipei49314/pinwash"
            or os.environ.get("EC_WORKLOAD_NAME") != "candidate-sessions"
            or os.environ.get("EC_WORKLOAD_PROFILE") != "profile-ec-integrity"
            or not re.fullmatch(r"[0-9a-f]{40}", expected)
            or Path(os.environ["EC_WORKLOAD_SOURCE"]).resolve() != ROOT):
        raise RuntimeError("requires exact reviewed EC candidate-sessions dispatch")
    out = Path(os.environ["EC_WORKLOAD_OUT"]).resolve()
    if out == ROOT or ROOT in out.parents or out in ROOT.parents:
        raise RuntimeError("output and source must be separate")
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise RuntimeError("refusing nonempty output directory; existing evidence remains untouched")
    try:
        return run_verified(out, expected)
    except Exception as exc:
        # Even a bad manifest/import or unexpected runner failure gets a
        # failure receipt. Preserve any logs from commands already run.
        started = any(out.glob("*.stdout"))
        failure = {"schema_version": 1, "passed": False, "requested_sha": expected,
                   "cases_expected": CASE_COUNT, "cases_completed": None if started else 0, "cases_matched": None if started else 0,
                   "state": "INCOMPLETE" if started else "NOT_RUN", "problems": [f"preflight/runner failure: {type(exc).__name__}: {exc}"],
                   "limitations": ["no acceptance result; inspect any retained command evidence"]}
        target = out / ("runner-failure.json" if (out / "result.json").exists() else "result.json")
        write_json(target, failure)
        if not (out / "SUMMARY.md").exists():
            (out / "SUMMARY.md").write_text(f"# Candidate session integration\n\nFAIL / {failure['state']}. See result.json.\n", encoding="utf-8")
        return 1


def run_verified(out: Path, expected: str) -> int:
    raw_manifest = MANIFEST.read_bytes()
    if digest(raw_manifest) != MANIFEST_SHA256:
        raise RuntimeError("preregistered manifest hash mismatch")
    plan = json.loads(raw_manifest)
    validate_manifest(plan)
    (out / "cases.json").write_bytes(raw_manifest)
    helper = ROOT / "workloads/alpha2_verify/run.py"
    spec = importlib.util.spec_from_file_location("trusted_cleanup", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    env = {k: v for k, v in os.environ.items() if k.upper() in
           {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATH", "PATHEXT", "TEMP", "TMP"}}
    neutral = out / "neutral-home"
    neutral.mkdir()
    env.update(HOME=str(neutral), USERPROFILE=str(neutral), XDG_CONFIG_HOME=str(neutral),
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM="1",
               GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0",
               GIT_AUTHOR_DATE="2026-10-14T00:00:00Z", GIT_COMMITTER_DATE="2026-10-14T00:00:00Z",
               PYTHONPATH=str(ROOT), PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1", PYTHONSAFEPATH="1",
               PINWASH_TODAY=plan["today"])
    commands = Commands(out, env, module.stop_owned)
    python = [sys.executable, "-P", "-s", "-X", "utf8", "-B"]
    problems, reports, identities = [], [], {}
    scratch = None
    scratch_cleanup = {"state": "NOT_CREATED"}
    git = ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "core.autocrlf=false",
           "-c", "core.eol=lf", "-c", "core.fsmonitor=false", "-c", "core.attributesFile=" + os.devnull,
           "-c", "credential.helper=", "-c", "commit.gpgsign=false",
           "-c", "user.name=pinwash-fixture", "-c", "user.email=fixture@invalid"]

    def require(name, args, cwd=ROOT):
        step = commands.run(name, args, cwd)
        if step["state"] != "COMPLETED" or step["exit_code"] != 0:
            raise RuntimeError(f"{name}: {step['state']} exit {step['exit_code']}")
        return step["stdout"].decode("utf-8", "strict").strip()

    def patch(repo, files):
        for rel, content in files.items():
            path = repo.joinpath(*rel.split("/"))
            if content is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content.encode("utf-8"))

    actual = None
    try:
        actual = require("source", git + ["rev-parse", "HEAD"])
        if actual != expected or require("source-status", git + ["status", "--porcelain", "-z"]):
            raise RuntimeError("source identity/cleanliness mismatch")
        if require("judge-tree", git + ["rev-parse", "HEAD:pinwash"]) != plan["candidate_pinwash_tree"]:
            raise RuntimeError("candidate engine tree changed")
        if digest((ROOT / "SPEC.md").read_bytes()) != plan["spec_sha256"]:
            raise RuntimeError("candidate spec changed")
        require("runtime-git", git + ["--version"])
        require("harness-tests", python + ["-m", "unittest", "tests.test_candidate_session_workload", "-v"])
        stderr = (out / "harness-tests.stderr").read_text(encoding="utf-8", errors="replace")
        counts = re.findall(r"(?m)^Ran (\d+) tests? in ", stderr)
        if not counts or int(counts[-1]) == 0 or not re.search(r"(?m)^OK$", stderr):
            raise RuntimeError("harness tests missing, skipped or not successful")
        try:
            scratch = Path(tempfile.mkdtemp(prefix="pinwash-candidate-")).resolve()
            templates = scratch / "empty-templates"
            templates.mkdir()
            for case in plan["cases"]:
                name = case["id"]
                case_problems, scans = [], []
                report = {"id": name, "expected_session": case["session_expected"], "scans": scans,
                          "state": "NOT_RUN", "problems": case_problems}
                reports.append(report)
                if commands.blocked:
                    case_problems.append(commands.blocked)
                    continue
                repo = scratch / name
                repo.mkdir()
                try:
                    require(name + "-init", git + ["init", "-b", "main", "--template", str(templates)], repo)
                    patch(repo, case["base"])
                    require(name + "-base-add", git + ["add", "-A"], repo)
                    require(name + "-base-commit", git + ["commit", "-m", "base"], repo)
                    base = require(name + "-base", git + ["rev-parse", "HEAD"], repo)
                    patch(repo, case["commit"])
                    require(name + "-session-add", git + ["add", "-A"], repo)
                    require(name + "-session-commit", git + ["commit", "-m", "session"], repo)
                    head = require(name + "-head", git + ["rev-parse", "HEAD"], repo)
                    patch(repo, case["worktree"])
                    before = fixture_snapshot(repo)
                    status = require(name + "-status", git + ["status", "--porcelain", "-z"], repo)
                    if base == head or not status or "subject-executed" in before:
                        raise RuntimeError("fixture does not contain a settled nonempty session")
                    report.update(base=base, head=head, worktree_sha256=before, state="COMPLETED")
                    range_args = [f"{base}..HEAD", f"{base}..WORKTREE", None]
                    for index, range_arg in enumerate(range_args):
                        exp = case["expected"][index]
                        argv = python + ["-m", "pinwash", "check"] + ([range_arg] if range_arg else [])
                        pair = []
                        for seed in SEEDS:
                            step = commands.run(f"{name}-scan{index + 1}-seed{seed}", argv, repo, seed=seed)
                            payload, mismatch = check_payload(step["stdout"], step["exit_code"], exp, plan,
                                                              base if index < 2 else "HEAD",
                                                              "HEAD" if index == 0 else "WORKTREE")
                            if step["state"] != "COMPLETED":
                                mismatch.append(step["state"])
                            if step["stderr"]:
                                mismatch.append("unexpected judge stderr")
                            case_problems.extend(f"scan{index + 1}/seed{seed}: {p}" for p in mismatch)
                            pair.append((step, payload))
                        same = bool(pair[0][0]["stdout"]) and pair[0][0]["stdout"] == pair[1][0]["stdout"]
                        if not same or pair[0][0]["exit_code"] != pair[1][0]["exit_code"]:
                            case_problems.append(f"scan{index + 1}: raw JSON/exit differs between seeds")
                        scan_state = aggregate_seed_state(pair)
                        scans.append({"range": RANGES[index], "state": scan_state,
                                      "exit_code": pair[0][0]["exit_code"], "payload": pair[0][1],
                                      "seeds": [{"seed": seed, "state": step["state"], "exit_code": step["exit_code"],
                                                 "payload": payload} for seed, (step, payload) in zip(SEEDS, pair)],
                                      "raw_json_equal": same, "expectation_matched": not any(
                                          p.startswith(f"scan{index + 1}") for p in case_problems)})
                    report["session_outcomes_by_seed"] = {seed: session_outcome([
                        {**scan, **scan["seeds"][i]} for scan in scans]) for i, seed in enumerate(SEEDS)}
                    report["session_outcome"] = session_outcome(scans)
                    if len(set(report["session_outcomes_by_seed"].values())) != 1:
                        report["session_outcome"] = "not-judged"
                    if report["session_outcome"] != case["session_expected"]:
                        case_problems.append("session outcome differs from preregistration")
                    # Equivalent finding identities retain fingerprints across range labels.
                    for scan in scans:
                        for finding in (scan["payload"] or {}).get("findings", []):
                            key = fingerprint_identity(finding)
                            if key in identities and identities[key] != finding["fingerprint"]:
                                case_problems.append("equivalent finding fingerprint changed across cases/ranges/severity")
                            identities[key] = finding["fingerprint"]
                    if before != fixture_snapshot(repo) or "subject-executed" in fixture_snapshot(repo):
                        case_problems.append("subject files changed or subject execution canary fired")
                    if require(name + "-final-head", git + ["rev-parse", "HEAD"], repo) != head:
                        case_problems.append("judge changed fixture HEAD")
                    if require(name + "-final-status", git + ["status", "--porcelain", "-z"], repo) != status:
                        case_problems.append("judge changed fixture Git status")
                except (OSError, ValueError, RuntimeError) as exc:
                    report["state"] = "FAILED"
                    case_problems.append(f"fixture failed: {type(exc).__name__}: {exc}")
                    commands.blocked = "fixture setup/inspection failed; remaining cases NOT_RUN"
        finally:
            if scratch is not None:
                uncertain = any(s["cleanup"] is not None and not s["cleanup"]["confirmed"] for s in commands.steps)
                # Never erase inputs potentially still used by an owned child.
                if uncertain:
                    scratch_cleanup = {"state": "RETAINED", "path": str(scratch), "reason": "owned command cleanup unconfirmed"}
                    problems.append("scratch retained because owned command cleanup was unconfirmed")
                elif scratch.parent == Path(tempfile.gettempdir()).resolve() and scratch.name.startswith("pinwash-candidate-"):
                    shutil.rmtree(scratch)
                    scratch_cleanup = {"state": "REMOVED", "path": str(scratch)}
                else:
                    scratch_cleanup = {"state": "RETAINED", "path": str(scratch), "reason": "scratch ownership/path check failed"}
                    problems.append("scratch ownership/path check failed")
        if require("final-source", git + ["rev-parse", "HEAD"]) != expected:
            problems.append("source changed")
        if require("final-source-status", git + ["status", "--porcelain", "-z"]):
            problems.append("source checkout changed")
    except (OSError, ValueError, RuntimeError) as exc:
        problems.append(f"workload incomplete: {type(exc).__name__}: {exc}")
    finally:
        seen = {r["id"] for r in reports}
        reports.extend({"id": c["id"], "expected_session": c["session_expected"], "state": "NOT_RUN",
                        "scans": [], "problems": ["workload stopped before case start"]}
                       for c in plan["cases"] if c["id"] not in seen)
        completed = sum(r["state"] == "COMPLETED" and len(r["scans"]) == 3
                        and all(s["state"] == "COMPLETED" for s in r["scans"]) for r in reports)
        matched = sum(r["state"] == "COMPLETED" and len(r["scans"]) == 3 and not r["problems"] for r in reports)
        if completed != CASE_COUNT or matched != CASE_COUNT:
            problems.append("not every preregistered case completed and matched")
        result = {"schema_version": 1, "passed": not problems, "requested_sha": expected, "actual_sha": actual,
                  "candidate_revision": plan["candidate_revision"], "candidate_pinwash_tree": plan["candidate_pinwash_tree"],
                  "spec_version": plan["spec_version"], "spec_sha256": plan["spec_sha256"],
                  "manifest_sha256": digest(raw_manifest), "cleanup_helper_sha256": digest(helper.read_bytes()),
                  "runtime": {"python": sys.version, "platform": platform.platform()}, "today": plan["today"],
                  "cases_expected": CASE_COUNT, "cases_completed": completed, "cases_matched": matched,
                  "cases": reports, "steps": commands.steps, "problems": problems,
                  "scratch_cleanup": scratch_cleanup,
                  "limitations": ["seeded candidate CLI integration, not held-out agent accuracy",
                                  "one native runtime; no OS/Python matrix or host hook execution",
                                  "full suite and top-level doctor are NOT_RUN by this workload",
                                  "historical live-fire judges and records are unchanged; no current-candidate historical rejudge",
                                  "candidate PR head evidence does not accept a future merge SHA"]}
        write_json(out / "result.json", result)
        (out / "SUMMARY.md").write_text(
            f"# Candidate session integration\n\n{'PASS' if result['passed'] else 'FAIL'} at `{actual}`.\n\n"
            f"Candidate engine `{plan['candidate_revision']}` / spec {plan['spec_version']}; "
            f"{matched}/{CASE_COUNT} preregistered cases matched. Three scans per case, seeds 1 and 17.\n\n"
            "Raw commands, exits, JSON, unknown rows, expectations and runtime: `result.json` and per-command logs.\n\n"
            "Full suite/doctor, historical rejudge, cross-platform and held-out acceptance remain separate.\n",
            encoding="utf-8", newline="\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
