"""Exact-source public CLI sessions; run only by a newly approved EC dispatch."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import platform
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
NAME = "candidate-sessions"
# Freeze only after the candidate source and reviewed literal oracles are final.
MANIFEST_SHA256 = "6bf8f7c501b3c45d4b79808fa5ee33e15085199a7231cf2c77434e18b83410a3"
HARNESS_TESTS = 12
spec = importlib.util.spec_from_file_location("validation_common", ROOT / "workloads/validation_common.py")
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)


def validate_manifest(plan):
    if (plan["schema_version"] != 2 or plan["status"] != "PREREGISTERED_NOT_RUN"
            or plan["ranges"] != common.RANGES or plan["seeds"] != common.SEEDS
            or plan["today"] != "2026-10-22" or len(plan["cases"]) != 40
            or plan["expected_counts"] != {"cases": 40, "scans": 480, "seed_pairs": 240}):
        raise ValueError("manifest is draft or contract drifted")
    common.validate_engines(plan["engines"])
    bundle = plan["engines_bundle"]
    if (bundle["path"] != "workloads/candidate_sessions/engines.bundle"
            or bundle["refs"] != {"baseline": "refs/remotes/origin/main", "candidate": "refs/heads/codex/env-evidence-candidate-20261022"}
            or not re.fullmatch(r"[0-9a-f]{64}", bundle["sha256"])):
        raise ValueError("engine bundle identity drift")
    ids = set()
    for case in plan["cases"]:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,70}", case["id"]) or case["id"] in ids:
            raise ValueError("unsafe or duplicate case id")
        ids.add(case["id"])
        for stage in ("base", "commit", "worktree"):
            if not isinstance(case[stage], dict):
                raise ValueError("fixture stage must be a literal file mapping")
            for path, text in case[stage].items():
                if not common.safe_path(path) or not (isinstance(text, str) or text is None):
                    raise ValueError("unsafe fixture path or content")
                if stage == "base" and text is None:
                    raise ValueError("base files cannot be deletions")
        if set(case["expected"]) != set(plan["engines"]):
            raise ValueError("both engine oracles required")
        for engine, expected in case["expected"].items():
            if len(expected) != 3:
                raise ValueError("all three range oracles required")
            for exp in expected:
                if set(exp) != {"exit_code", "findings", "unknown_coverage"}:
                    raise ValueError("incomplete oracle")
                payload = expected_payload(exp, plan["engines"][engine], "BASE", "HEAD")
                common.check_payload(common.canonical(payload).encode(), exp["exit_code"],
                                     plan["engines"][engine], "BASE", "HEAD")


def expected_payload(exp, engine, base, head):
    return {"pinwash_findings_version": 1, "run": {"pinwash_version": engine["engine_version"],
        "spec_version": engine["spec_version"], "base": base, "head": head},
        "findings": exp["findings"], "unknown_coverage": exp["unknown_coverage"], "config_errors": [],
        "verdict": "block" if exp["exit_code"] == 1 else "pass",
        "summary": {s: sum(f["severity"] == s for f in exp["findings"]) for s in ("critical", "high", "info", "warn")}}


def snapshot(repo):
    return {p.relative_to(repo).as_posix(): common.digest(p.read_bytes())
            for p in sorted(repo.rglob("*")) if p.is_file() and ".git" not in p.relative_to(repo).parts}


def apply_files(repo, files):
    for name, text in files.items():
        path = repo.joinpath(*name.split("/"))
        if text is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(text.encode("utf-8"))


def run_verified(out, requested):
    raw = (HERE / "cases.json").read_bytes()
    if common.digest(raw) != MANIFEST_SHA256:
        raise ValueError("preregistration is not frozen or manifest digest differs")
    plan = common.decode(raw)
    validate_manifest(plan)
    bundle = ROOT / plan["engines_bundle"]["path"]
    if common.digest(bundle.read_bytes()) != plan["engines_bundle"]["sha256"]:
        raise ValueError("offline engine bundle bytes differ")
    (out / "cases.json").write_bytes(raw)
    neutral = out / "neutral-home"
    neutral.mkdir()
    env = {k: v for k, v in os.environ.items() if k.upper() in {
        "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATH", "PATHEXT", "TEMP", "TMP"}}
    env.update(HOME=str(neutral), USERPROFILE=str(neutral), XDG_CONFIG_HOME=str(neutral),
        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM="1",
        GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0",
        GIT_AUTHOR_DATE="2026-10-22T00:00:00Z", GIT_COMMITTER_DATE="2026-10-22T00:00:00Z",
        PYTHONPATH=str(ROOT), PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1", PYTHONSAFEPATH="1", PINWASH_TODAY=plan["today"])
    commands = common.Commands(out, env)
    python = [sys.executable, "-P", "-s", "-X", "utf8", "-B"]
    git = ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "core.autocrlf=false", "-c", "core.eol=lf",
        "-c", "core.fsmonitor=false", "-c", "core.attributesFile=" + os.devnull,
        "-c", "credential.helper=", "-c", "commit.gpgsign=false", "-c", "user.name=pinwash-fixture",
        "-c", "user.email=fixture@invalid"]
    def require(name, args, cwd=ROOT, *, raw=False):
        step = commands.run(name, args, cwd)
        if step["state"] != "COMPLETED" or step["exit_code"] != 0:
            raise RuntimeError(f"{name}: {step['state']} exit {step['exit_code']}")
        return step["stdout"] if raw else step["stdout"].decode("utf-8", "strict").strip()

    problems, rows, sessions = [], [], []
    scratch, cleanup, actual = None, {"state": "NOT_CREATED"}, None
    work = Path(os.environ["EC_WORKLOAD_WORK"])
    common.reject_redirected_ancestors(work)
    if work.resolve() != work or not work.is_dir() or work == ROOT or ROOT in work.parents or work in ROOT.parents:
        raise ValueError("work must be an absolute real directory separate from source")
    try:
        actual = require("source", git + ["rev-parse", "HEAD"])
        if actual != requested or require("source-status", git + ["status", "--porcelain", "-z"]):
            raise ValueError("dispatch source identity/cleanliness differs")
        require("runtime-git", git + ["--version"])
        require("harness-tests", python + ["-m", "unittest", "discover", "-s", str(HERE / "tests"), "-v"])
        tests = (out / "harness-tests.stderr").read_text(encoding="utf-8", errors="replace")
        counts = re.findall(r"(?m)^Ran (\d+) tests? in ", tests)
        if not counts or int(counts[-1]) != HARNESS_TESTS or not re.search(r"(?m)^OK$", tests):
            raise ValueError("harness tests incomplete, skipped or unsuccessful")
        scratch = Path(tempfile.mkdtemp(prefix="pinwash-candidate-", dir=work)).resolve()
        cleanup = {"state": "CREATED", "path": str(scratch)}
        templates = scratch / "empty-templates"
        templates.mkdir()
        engine_store = scratch / "engine-store"
        require("engine-store-init", git + ["init", "-q", "--template=" + str(templates), str(engine_store)], scratch)
        for engine, ref in plan["engines_bundle"]["refs"].items():
            require("engine-fetch-" + engine, git + ["fetch", "--no-tags", "--no-write-fetch-head", str(bundle),
                ref + ":refs/heads/" + engine], engine_store)
            if require("engine-head-" + engine, git + ["rev-parse", "refs/heads/" + engine], engine_store) != plan["engines"][engine]["revision"]:
                raise ValueError("offline engine commit differs")
        engines = {}
        for engine, identity in plan["engines"].items():
            target = scratch / ("engine-" + engine)
            common.export_engine(require, git, engine_store, target, identity)
            engines[engine] = target
        for case in plan["cases"]:
            if commands.blocked:
                break
            name, repo = case["id"], scratch / case["id"]
            repo.mkdir()
            require(name + "-init", git + ["init", "-b", "main", "--template", str(templates)], repo)
            apply_files(repo, case["base"])
            require(name + "-base-add", git + ["add", "-A"], repo)
            require(name + "-base-commit", git + ["commit", "-m", "base"], repo)
            base = require(name + "-base", git + ["rev-parse", "HEAD"], repo)
            apply_files(repo, case["commit"])
            require(name + "-session-add", git + ["add", "-A"], repo)
            require(name + "-session-commit", git + ["commit", "-m", "session"], repo)
            head = require(name + "-head", git + ["rev-parse", "HEAD"], repo)
            apply_files(repo, case["worktree"])
            before, status = snapshot(repo), require(name + "-status", git + ["status", "--porcelain", "-z"], repo)
            if base == head or not status or "subject-executed" in before:
                raise ValueError("fixture lacks a settled nonempty session")
            for engine, identity in plan["engines"].items():
                selected = []
                for index, range_name in enumerate(common.RANGES):
                    argv = python + ["-m", "pinwash", "check"] + ([base + "..HEAD"] if index == 0 else [base + "..WORKTREE"] if index == 1 else [])
                    for seed in common.SEEDS:
                        step = commands.run(f"{name}-{engine}-scan{index + 1}-seed{seed}", argv, repo, seed=seed, pythonpath=engines[engine])
                        payload, errors = None, []
                        try:
                            if step["state"] != "COMPLETED":
                                raise ValueError(step["state"])
                            payload = common.check_payload(step["stdout"], step["exit_code"], identity,
                                base if index < 2 else "HEAD", "HEAD" if index == 0 else "WORKTREE")
                        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
                            errors.append(str(exc))
                        matched = payload is not None and common.matches_oracle(payload, step["exit_code"], case["expected"][engine][index])
                        if not matched:
                            errors.append("complete literal oracle mismatch")
                        if step["stderr"]:
                            errors.append("unexpected public CLI stderr")
                        row = {k: v for k, v in step.items() if k not in ("stdout", "stderr")}
                        row.update(tuple=[name, engine, range_name, seed], payload=payload, oracle_matched=matched and not step["stderr"], problems=errors)
                        rows.append(row)
                        selected.append(row)
                for seed in common.SEEDS:
                    scans = [r for r in selected if r["tuple"][3] == seed]
                    sessions.append({"case": name, "engine": engine, "seed": seed,
                        "public_session_outcome": common.session_outcome(scans),
                        "conservative_acceptance_state": common.session_outcome(scans, conservative=True)})
            if before != snapshot(repo) or "subject-executed" in snapshot(repo):
                raise ValueError("subject mutation or execution canary fired")
            if require(name + "-final-head", git + ["rev-parse", "HEAD"], repo) != head or require(name + "-final-status", git + ["status", "--porcelain", "-z"], repo) != status:
                raise ValueError("judge changed subject Git state")
        if require("final-source", git + ["rev-parse", "HEAD"]) != requested or require("final-source-status", git + ["status", "--porcelain", "-z"]):
            raise ValueError("source changed")
    except (ValueError, RuntimeError, OSError) as exc:
        problems.append(f"workload incomplete: {type(exc).__name__}: {exc}")
    finally:
        if scratch is not None:
            if any(s["cleanup"] is not None and not s["cleanup"]["confirmed"] for s in commands.steps):
                cleanup = {"state": "RETAINED", "path": str(scratch), "reason": "owned child cleanup unconfirmed"}
                problems.append("scratch retained while child cleanup uncertain")
            else:
                try:
                    common.remove_owned_tree(scratch, work)
                    cleanup = {"state": "REMOVED", "path": str(scratch)}
                except (ValueError, OSError) as exc:
                    cleanup = {"state": "FAILED", "path": str(scratch), "error": str(exc)}
                    problems.append("current dispatch scratch cleanup failed")
    wanted = common.expected_tuples(plan["cases"], plan["engines"])
    seen = {tuple(r["tuple"]) for r in rows}
    for key in sorted(wanted - seen):
        rows.append({"tuple": list(key), "state": "NOT_RUN", "exit_code": None, "payload": None,
            "oracle_matched": False, "stdout_sha256": None, "stderr_sha256": None, "problems": ["stopped before launch"]})
    statuses = common.matrix_status(rows, wanted)
    passed = not problems and statuses["execution_status"] == "COMPLETE" and statuses["determinism_status"] == statuses["semantic_status"] == "PASS" and cleanup["state"] == "REMOVED"
    result = {"schema_version": 2, "passed": passed, **statuses, "requested_sha": requested, "actual_sha": actual,
        "manifest_sha256": common.digest(raw), "engines": plan["engines"], "rows": rows, "sessions": sessions,
        "steps": commands.steps, "problems": problems, "scratch_cleanup": cleanup,
        "runtime": {"python": sys.version, "platform": platform.platform()},
        "limitations": ["Synthetic fixtures; not held-out accuracy or host invocation evidence.",
            "No historical PASS transfers to these source identities.", "Unknown coverage holds conservative acceptance only; public CLI behavior is recorded separately."]}
    common.write_json(out / "result.json", result)
    (out / "SUMMARY.md").write_text(f"# Candidate sessions\n\n{'PASS' if passed else 'FAIL'}; {statuses}.\n\nExact tuple inventory and full raw channels accompany result.json.\n", encoding="utf-8")
    return 0 if passed else 1


def main():
    requested = os.environ.get("EC_WORKLOAD_SHA", "")
    if (os.environ.get("EC_WORKLOAD_REPOSITORY") != "taipei49314/pinwash" or os.environ.get("EC_WORKLOAD_NAME") != NAME
            or not re.fullmatch(r"[0-9a-f]{40}", requested) or Path(os.environ.get("EC_WORKLOAD_SOURCE", "")).resolve() != ROOT):
        raise RuntimeError("requires an exact newly approved EC dispatch")
    out = Path(os.environ["EC_WORKLOAD_OUT"]).resolve()
    if out == ROOT or out in ROOT.parents or ROOT in out.parents:
        raise RuntimeError("output must be separate from source")
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise RuntimeError("refusing existing output evidence")
    try:
        return run_verified(out, requested)
    except Exception as exc:
        common.write_json(out / "runner-failure.json", {"passed": False, "execution_status": "NOT_RUN_OR_INCOMPLETE",
            "determinism_status": "NOT_JUDGED", "semantic_status": "NOT_JUDGED", "requested_sha": requested,
            "error": f"{type(exc).__name__}: {exc}"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
