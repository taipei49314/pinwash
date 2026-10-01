"""Re-judge the published live-fire rounds with their pinned judges on an approved EC pool job.

Offline. Inputs are all in this commit: live-fire/ (the published round
records), judges.bundle (the pinned judge commits) and expected_worktrees.json
(sha256 of every file in the original cell worktrees). The workload rebuilds
the fixture base and every cell, checks the rebuilt bytes, runs the judge that
was pinned for each record, projects its output the way that record was
projected, and compares. It never runs the subject repositories' code.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
NAME = "live-fire-rejudge"
LIVE = ROOT / "live-fire"

MANIFEST_SHA256 = "04e4abbef8a1ed76c6350f1bb75e87b9804cb84b7fd5b5c362ca27514e65f5cd"
BUNDLE_SHA256 = "de42d4df776782f5fd860d91fe1d301c4e21a9fd907a635f8cf97c93c7503ed1"
EXPECTED_WORKTREES_SHA256 = "5df532db137ef35f9c514bffdfa143ac97ea9a67378fdaabc086efe1e5bc4b03"

BASE = "2354c96be0b9a390c7785ad3591d43c56278ada1"
BASE_TREE = "d6e67f14ef7045c874e2ea3261d60fe44aa48924"
BASE_IDENT = ("fixture", "fixture@test", "1790519884 +0800")
BASE_MESSAGE = b"fixture: guarded repo for pinwash round 0\n"
# Round 1 first-launch HEAD 3a0be5f: its tree is checked; the commit is rebuilt
# under a neutral identity, so its id differs from 3a0be5f by design.
FIRST_LAUNCH = "first-launch-attack-longcat-2.5-preview-free"
FIRST_LAUNCH_TREE = "8e4b6f102bf11468cb1d33b57a69b2ef19a94205"
REBUILD_IDENT = ("live-fire rejudge", "rejudge@invalid", "1790519884 +0800")

J416 = "416b962ca08623531be180e0a4d0613001d38776"
J86B = "86bdccee9c5b63e92b1c3ef21af61374c078db15"
J9DE = "9dec33210208b2715b62085fa433ded04fffc14f"
JDF5 = "df5eb217f31f02cded1b29628cadfacb781fabcb"
J722 = "7222bfcbabeea1047680aa8f6d3fbb488a1a3e92"
# judge commit -> tree id of its pinwash/ package
JUDGES = {
    J416: "74b79679d7b890ddac8920b09c8deda3d916c30a",
    J86B: "e9ad3ef55a820e63d1c588a06d9bbc6e66b9900c",
    J9DE: "e9ad3ef55a820e63d1c588a06d9bbc6e66b9900c",
    JDF5: "884db97385ef9d9fbb20cdd3f538c3b2d277c262",
    J722: "121335cfdb61af45d6da7ff92b09a6d64d9d7de9",
}

FULL_RANGE = f"{BASE}..HEAD"
# One record type per entry: which judge, which ranges with which argument,
# which judge.json field holds the record, how it was projected, and whether
# a mismatch fails the workload. Secondary records are reported only: their
# drive-time cell state is not proven equal to the published state
# (live-fire/round0/REPORT.md process finding 1, late landing;
# live-fire/round1/REPORT.md platform finding, late writes).
# PINWASH_TODAY is pinned for replay only. The judges read it solely for
# .pinwash/allow.toml validity, and no cell has one.
RECORDS = [
    # Round 0 judged the worktree only.
    {"id": "r0-official", "round": 0, "judge": J416, "today": "2026-09-27",
     "ranges": {"worktree": []}, "field": "official_post_quiescence_rejudge",
     "projection": "r0_official", "primary": True},
    {"id": "r0-drive", "round": 0, "judge": J416, "today": "2026-09-27",
     "ranges": {"worktree": []}, "field": "drive_time",
     "projection": "r0_drive", "primary": False},
    {"id": "r1-drive", "round": 1, "judge": J416, "today": "2026-09-27",
     "ranges": {"committed": [FULL_RANGE], "worktree": []}, "field": "drive_time",
     "projection": "dict4", "primary": False},
    # The spec 7 re-judge ran the uncommitted tree that became 86bdcce
    # (identical pinwash/ to 9dec332); it passed the short base sha.
    {"id": "r1-spec7", "round": 1, "judge": J86B, "today": "2026-09-28",
     "ranges": {"committed": ["2354c96..HEAD"], "worktree": []},
     "field": "post_bump_rejudge_spec7", "projection": "spec7", "primary": True},
    {"id": "r2", "round": 2, "judge": J9DE, "today": "2026-09-28",
     "ranges": {"committed": [FULL_RANGE], "worktree": []}, "field": "drive_time",
     "projection": "dict4", "primary": True},
    {"id": "r3", "round": 3, "judge": JDF5, "today": "2026-09-28",
     "ranges": {"committed": [FULL_RANGE], "worktree": []}, "field": "drive_time",
     "projection": "dict4", "primary": True},
    {"id": "r4", "round": 4, "judge": J722, "today": "2026-09-28",
     "ranges": {"committed": [FULL_RANGE], "worktree": []}, "field": "drive_time",
     "projection": "dict4", "primary": True},
]
# Round 3 under spec 9: the set of ranges whose (rule, severity) projection or
# verdict changed against the recorded spec 8 result must equal
# live-fire/round3/rejudge_spec9.json (rejudge_spec9.py semantics).
SPEC9 = {"id": "r3-spec9", "round": 3, "judge": J722, "today": "2026-09-28",
         "ranges": {"committed": [FULL_RANGE], "worktree": []}}
# Never judged at the time; judged here for the record, not compared.
UNRECORDED = [
    {"id": "r1-first-launch", "round": 1, "cell": FIRST_LAUNCH, "judge": judge,
     "today": "2026-09-27", "ranges": {"committed": [FULL_RANGE], "worktree": []}}
    for judge in (J416, J86B)
]
SEEDS = ("1", "17")
STEP_TIMEOUT = 120
TIMEOUT_EXIT = 124
# The declaration allows 60 minutes; stop judging early enough to write the receipt.
DEADLINE_SECONDS = 50 * 60


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, sort_keys=True, ensure_ascii=False, indent=2)
        handle.write("\n")


def file_sha256(path: Path) -> str | None:
    try:
        return sha256(path.read_bytes())
    except OSError:
        return None


class Failure(Exception):
    pass


def main() -> int:
    required = ("EC_WORKLOAD_SOURCE", "EC_WORKLOAD_OUT", "EC_WORKLOAD_WORK", "EC_WORKLOAD_SHA")
    if any(not os.environ.get(key) for key in required):
        raise RuntimeError("run only through the approved EC pool workload")
    out = Path(os.environ["EC_WORKLOAD_OUT"]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    expected = os.environ["EC_WORKLOAD_SHA"]
    work = Path(os.environ["EC_WORKLOAD_WORK"]).resolve() / "rejudge"
    state: dict[str, object] = {
        "expected": expected, "source": "unknown", "steps": [], "problems": [],
        "rebuild": {}, "comparisons": {}, "unrecorded": {}, "determinism": {},
    }
    refusals = [
        (os.environ.get("EC_WORKLOAD_REPOSITORY") == "taipei49314/pinwash", "unexpected workload repository"),
        (os.environ.get("EC_WORKLOAD_NAME") == NAME, "unexpected workload name"),
        (Path(os.environ["EC_WORKLOAD_SOURCE"]).resolve() == ROOT,
         "workload source does not match this entry point"),
        (re.fullmatch(r"[0-9a-f]{40}", expected) is not None, "an exact source SHA is required"),
        (not work.exists(), "work directory is not fresh"),
    ]
    state["problems"].extend(reason for ok, reason in refusals if not ok)
    if not state["problems"]:
        try:
            rejudge(state, out, work)
        except Exception as exc:  # any abort is reported, never passed
            state["problems"].append(f"aborted: {type(exc).__name__}: {exc}")
    return finish(out, state)


def rejudge(state: dict, out: Path, work: Path) -> None:
    started = time.monotonic()
    expected = state["expected"]
    problems: list[str] = state["problems"]
    steps: list[dict[str, object]] = state["steps"]

    # Git and the judges see a neutral configuration: no system config, a
    # global config holding only core.longpaths, no excludes file, no
    # inherited repository variables.
    home = work / "home"
    (home / ".config" / "git").mkdir(parents=True)
    git_config = home / "pool.gitconfig"
    git_config.write_bytes(b"[core]\n\tlongpaths = true\n")
    base_env = {k: v for k, v in os.environ.items()
                if not k.startswith(("PYTHON", "GIT_", "PINWASH_"))}
    base_env.update(
        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(git_config),
        HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
        GIT_TERMINAL_PROMPT="0",
    )

    def git(cwd: Path, *args: str, stdin: bytes | None = None, env: dict | None = None) -> bytes:
        try:
            process = subprocess.run(["git", *args], cwd=cwd, env=env or base_env, input=stdin,
                                     capture_output=True, timeout=STEP_TIMEOUT, check=False)
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise Failure(f"git {' '.join(args[:3])} in {cwd.name}: {type(exc).__name__}") from exc
        if process.returncode:
            raise Failure(f"git {' '.join(args[:3])} failed in {cwd.name}: "
                          + process.stderr.decode("utf-8", "replace")[:300])
        return process.stdout

    def ident_env(ident: tuple[str, str, str]) -> dict:
        name, email, date = ident
        return dict(base_env, GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email, GIT_AUTHOR_DATE=date,
                    GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email, GIT_COMMITTER_DATE=date)

    def record_step(name: str, ok: bool, reason: str = "failed", **detail: object) -> None:
        steps.append({"name": name, "ok": ok, **detail, **({} if ok else {"reason": reason})})
        if not ok:
            problems.append(f"{name}: {reason}")

    # 1. Source identity and pinned inputs. Hashes are compared before any
    # input is parsed.
    source = git(ROOT, "rev-parse", "--verify", "HEAD").decode("ascii", "replace").strip()
    state["source"] = source
    status = git(ROOT, "status", "--porcelain", "-z")
    record_step("source", source == expected and not status,
                actual=source, reason="source SHA mismatch or unclean checkout")
    bundle = HERE / "judges.bundle"
    pins = {
        "live-fire/MANIFEST.json": (LIVE / "MANIFEST.json", MANIFEST_SHA256),
        "judges.bundle": (bundle, BUNDLE_SHA256),
        "expected_worktrees.json": (HERE / "expected_worktrees.json", EXPECTED_WORKTREES_SHA256),
    }
    actual_pins = {label: file_sha256(path) for label, (path, _) in pins.items()}
    record_step("pinned-inputs", all(actual_pins[label] == want for label, (_, want) in pins.items()),
                sha256=actual_pins, reason="a pinned input differs from its pinned sha256")
    if problems:
        return
    manifest = json.loads((LIVE / "MANIFEST.json").read_bytes())
    bad = [f["path"] for f in manifest["files"] if file_sha256(ROOT / f["path"]) != f["sha256"]]
    record_step("live-fire-manifest", not bad, files=len(manifest["files"]), mismatched=bad,
                reason="files listed in live-fire/MANIFEST.json differ from it")
    expected_cells = json.loads((HERE / "expected_worktrees.json").read_bytes())["cells"]
    if problems:
        return

    # 2. Judges: fetch the bundle offline, prove each commit and its pinwash/
    # tree by object id, extract pinwash/ only.
    judges_repo = work / "judges.git"
    judge_dirs: dict[str, Path] = {}
    try:
        git(work, "init", "-q", "--bare", str(judges_repo))
        git(judges_repo, "fetch", "-q", str(bundle), "refs/heads/judge/*:refs/heads/judge/*")
    except Failure as exc:
        record_step("judges-bundle", False, reason=str(exc))
        return
    for commit, tree in JUDGES.items():
        try:
            got_commit = git(judges_repo, "rev-parse", "--verify", f"{commit}^{{commit}}").decode().strip()
            got_tree = git(judges_repo, "rev-parse", "--verify", f"{commit}:pinwash").decode().strip()
            ok, reason = got_commit == commit and got_tree == tree, "judge commit or pinwash/ tree id mismatch"
            if ok:
                target = work / "judge" / commit[:12]
                archive = git(judges_repo, "-c", "core.autocrlf=false", "archive", "--format=tar", commit, "pinwash")
                with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                    tar.extractall(target, filter="data")
                ok, reason = (target / "pinwash" / "__main__.py").is_file(), "extracted judge has no pinwash/__main__.py"
                if ok:
                    judge_dirs[commit] = target
            record_step(f"judge-{commit[:7]}", ok, reason, commit=got_commit, pinwash_tree=got_tree)
        except (Failure, OSError, tarfile.TarError) as exc:
            record_step(f"judge-{commit[:7]}", False, reason=str(exc))

    # 3. Fixture base: apply base.patch, prove the tree and the exact commit id.
    base_repo = work / "base"
    try:
        git(work, "init", "-q", "-b", "main", str(base_repo))
        git(base_repo, "-c", "core.autocrlf=false", "apply", "--whitespace=nowarn",
            str(LIVE / "fixture" / "base.patch"))
        git(base_repo, "-c", "core.autocrlf=false", "add", "-A")
        tree = git(base_repo, "write-tree").decode().strip()
        commit = git(base_repo, "commit-tree", tree, stdin=BASE_MESSAGE,
                     env=ident_env(BASE_IDENT)).decode().strip()
        git(base_repo, "update-ref", "refs/heads/main", commit)
        record_step("fixture-base", tree == BASE_TREE and commit == BASE, tree=tree, commit=commit,
                    reason="rebuilt fixture base differs from 2354c96")
    except Failure as exc:
        record_step("fixture-base", False, reason=str(exc))
    if problems:
        return

    # 4. Cells. Paths named in change.patch take the patch bytes (LF build);
    # every other file keeps the CRLF checkout bytes, as the originals did on
    # the Windows host with core.autocrlf=true. The result is checked against
    # expected_worktrees.json byte for byte.
    rebuild: dict[str, dict[str, object]] = state["rebuild"]
    cell_dirs: dict[str, Path] = {}
    for rnd in range(5):
        for cell_dir in sorted((LIVE / f"round{rnd}" / "cells").iterdir()):
            key = f"round{rnd}/{cell_dir.name}"
            try:
                cell_dirs[key] = build_cell(git, ident_env, work, base_repo, rnd, cell_dir)
                actual = tree_hashes(cell_dirs[key])
                want = expected_cells.get(key) or {}
                diff = sorted(p for p in set(actual) | set(want) if actual.get(p) != want.get(p))
                rebuild[key] = {"ok": key in expected_cells and not diff, "files": len(actual),
                                "differing_paths": diff}
            except (Failure, OSError) as exc:
                rebuild[key] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            if not rebuild[key]["ok"]:
                problems.append(f"rebuild {key}: " + str(rebuild[key].get(
                    "error", "worktree differs from the original cell")))
    if set(rebuild) != set(expected_cells):
        problems.append("published cells and expected_worktrees.json list different cells")

    # 5. Judge and compare.
    raw_dir = out / "raw"
    cache: dict[tuple, dict[str, object] | None] = {}
    nondeterministic: set[tuple] = set()
    deadline_hit: dict[tuple, str] = {}

    def judge(rnd: int, cell: str, commit: str, args: list[str], today: str) -> dict[str, object] | None:
        """One judgment, run once per seed; None when the deadline has passed."""
        key = (rnd, cell, commit, tuple(args), today)
        if key in cache:
            return cache[key]
        if time.monotonic() - started > DEADLINE_SECONDS:
            deadline_hit[key] = f"round{rnd}/{cell} {commit[:7]} {' '.join(args) or 'worktree'}"
            return None
        runs = []
        for seed in SEEDS:
            env = dict(base_env, PYTHONPATH=str(judge_dirs[commit]), PYTHONSAFEPATH="1",
                       PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1",
                       PYTHONHASHSEED=seed, PINWASH_TODAY=today)
            began = time.monotonic()
            try:
                process = subprocess.run(
                    [sys.executable, "-X", "utf8", "-B", "-s", "-m", "pinwash", "check", *args],
                    cwd=cell_dirs[f"round{rnd}/{cell}"], env=env, capture_output=True,
                    timeout=STEP_TIMEOUT, check=False)
                code, stdout, stderr = process.returncode, process.stdout, process.stderr
            except subprocess.TimeoutExpired as exc:
                code, stdout, stderr = TIMEOUT_EXIT, exc.stdout or b"", exc.stderr or b""
            runs.append({"seed": seed, "exit": code, "stdout": stdout, "stderr": stderr,
                         "elapsed_seconds": round(time.monotonic() - began, 3)})
            if code == TIMEOUT_EXIT:
                break
        first = runs[0]
        label = "committed" if args else "worktree"
        stem = raw_dir / f"round{rnd}" / cell / f"{commit[:7]}-{label}"
        stem.parent.mkdir(parents=True, exist_ok=True)
        for run in runs:
            # The first seed's output is always kept; a later seed's only when it differs.
            if run is first or run["stdout"] != first["stdout"] or run["stderr"] != first["stderr"]:
                suffix = "" if run is first else f"-seed{run['seed']}"
                (stem.parent / f"{stem.name}{suffix}.stdout").write_bytes(run["stdout"])
                if run["stderr"]:
                    (stem.parent / f"{stem.name}{suffix}.stderr").write_bytes(run["stderr"])
        deterministic = len(runs) == len(SEEDS) and all(
            r["exit"] == first["exit"] and r["stdout"] == first["stdout"] for r in runs)
        if not deterministic:
            nondeterministic.add(key)
        result = {
            "exit": first["exit"], "stdout": first["stdout"], "stderr": first["stderr"],
            "stdout_sha256": sha256(first["stdout"]),
            "seeds": [{"seed": r["seed"], "exit": r["exit"], "stdout_sha256": sha256(r["stdout"]),
                       "elapsed_seconds": r["elapsed_seconds"]} for r in runs],
        }
        try:
            result["payload"] = json.loads(first["stdout"]) if first["exit"] in (0, 1) else None
        except ValueError:
            result["payload"] = None
        cache[key] = result
        return result

    def project(kind: str, result: dict[str, object]) -> object:
        payload = result["payload"]
        code = result["exit"]
        if payload is None:
            if kind == "spec7":
                # The original spec 7 script had no error branch; this
                # sentinel can only ever be a MISMATCH.
                return {"verdict": "exit2", "findings": []}
            error = result["stderr"].decode("utf-8", "replace")
            if kind == "r0_drive":
                return {"pinwash_exit": code, "pinwash_error": error[:300]}
            if kind == "r0_official":
                return {"exit": code, "error": error[:200]}
            return {"exit": code, "error": error[:300]}
        findings = payload["findings"]
        if kind == "dict4":
            return {"exit": code, "verdict": payload["verdict"],
                    "findings": [{k: f.get(k, "") for k in ("rule", "severity", "path", "locator")}
                                 for f in findings]}
        if kind == "r0_drive":
            return {"pinwash_exit": code, "verdict": payload["verdict"],
                    "findings": [{k: f.get(k, "") for k in
                                  ("rule", "severity", "path", "locator", "message", "before", "after")}
                                 for f in findings]}
        if kind == "r0_official":
            return {"exit": code, "verdict": payload["verdict"],
                    "findings": [[f["rule"], f["severity"], f["path"], f.get("locator", "")]
                                 for f in findings]}
        if kind == "spec7":
            return {"verdict": payload["verdict"],
                    "findings": [[f["rule"], f["severity"], f["message"]] for f in findings]}
        raise ValueError(kind)

    def recorded(kind: str, field: dict, label: str) -> object:
        if kind == "r0_drive":
            return {k: field[k] for k in ("pinwash_exit", "pinwash_error", "verdict", "findings") if k in field}
        if kind == "r0_official":
            return {k: field[k] for k in ("exit", "error", "verdict", "findings") if k in field}
        return field[label]

    def runnable(key: str, commit: str) -> bool:
        return bool(rebuild.get(key, {}).get("ok")) and commit in judge_dirs

    comparisons: dict[str, dict[str, object]] = state["comparisons"]
    for spec in RECORDS:
        rows = []
        for cell_dir in sorted((LIVE / f"round{spec['round']}" / "cells").iterdir()):
            cell = cell_dir.name
            if cell == FIRST_LAUNCH:
                continue
            key = f"round{spec['round']}/{cell}"
            record = json.loads((cell_dir / "judge.json").read_text(encoding="utf-8"))[spec["field"]]
            for label, args in spec["ranges"].items():
                result = (judge(spec["round"], cell, spec["judge"], args, spec["today"])
                          if runnable(key, spec["judge"]) else None)
                if result is None:
                    rows.append({"cell": cell, "range": label, "status": "NOT_RUN"})
                    continue
                want = recorded(spec["projection"], record, label)
                got = project(spec["projection"], result)
                row = {"cell": cell, "range": label,
                       "status": "MATCH" if canonical(got) == canonical(want) else "MISMATCH",
                       "exit": result["exit"], "stdout_sha256": result["stdout_sha256"],
                       "seeds": result["seeds"]}
                if row["status"] == "MISMATCH":
                    row.update(recorded=want, rejudged=got)
                rows.append(row)
        counts = {s: sum(r["status"] == s for r in rows) for s in ("MATCH", "MISMATCH", "NOT_RUN")}
        comparisons[spec["id"]] = {"judge": spec["judge"], "field": spec["field"],
                                   "projection": spec["projection"], "primary": spec["primary"],
                                   "pinwash_today": spec["today"], "counts": counts, "rows": rows}
        if spec["primary"] and (counts["MISMATCH"] or counts["NOT_RUN"]):
            problems.append(f"{spec['id']}: {counts['MISMATCH']} mismatched, {counts['NOT_RUN']} not run")

    # Round 3 under spec 9: recompute the delta rows exactly as rejudge_spec9.py did.
    delta_rows, spec9_not_run = [], []
    for cell_dir in sorted((LIVE / "round3" / "cells").iterdir()):
        cell = cell_dir.name
        record = json.loads((cell_dir / "judge.json").read_text(encoding="utf-8"))["drive_time"]
        for label, args in SPEC9["ranges"].items():
            result = (judge(3, cell, J722, args, SPEC9["today"])
                      if runnable(f"round3/{cell}", J722) else None)
            if result is None:
                spec9_not_run.append(f"{cell} {label}")
                continue
            payload = result["payload"]
            new = ({"verdict": "exit2", "findings": []} if payload is None else
                   {"verdict": payload["verdict"],
                    "findings": [[f["rule"], f["severity"]] for f in payload["findings"]]})
            old = record[label]
            old_f = [[f["rule"], f["severity"]] for f in old.get("findings", [])]
            if old.get("verdict") != new["verdict"] or old_f != new["findings"]:
                delta_rows.append({"cell": cell, "range": label,
                                   "spec8_verdict": old.get("verdict"), "spec9_verdict": new["verdict"],
                                   "spec8_findings": old_f, "spec9_findings": new["findings"]})
    published = json.loads((LIVE / "round3" / "rejudge_spec9.json").read_text(encoding="utf-8"))
    order = lambda row: (row["cell"], row["range"])  # noqa: E731
    delta_rows.sort(key=order)
    spec9_match = not spec9_not_run and canonical(delta_rows) == canonical(sorted(published, key=order))
    spec9_status = "NOT_RUN" if spec9_not_run else ("MATCH" if spec9_match else "MISMATCH")
    comparisons[SPEC9["id"]] = {"judge": J722, "field": "round3/rejudge_spec9.json",
                                "projection": "spec9_delta", "primary": True,
                                "pinwash_today": SPEC9["today"], "status": spec9_status,
                                "rejudged_rows": delta_rows, "not_run": spec9_not_run}
    if spec9_status == "NOT_RUN":
        problems.append(f"r3-spec9: {len(spec9_not_run)} ranges not run")
    elif spec9_status == "MISMATCH":
        problems.append("r3-spec9: delta rows differ from round3/rejudge_spec9.json")

    unrecorded: dict[str, object] = state["unrecorded"]
    for spec in UNRECORDED:
        key = f"round{spec['round']}/{spec['cell']}"
        for label, args in spec["ranges"].items():
            name = f"{spec['id']}-{spec['judge'][:7]}-{label}"
            result = (judge(spec["round"], spec["cell"], spec["judge"], args, spec["today"])
                      if runnable(key, spec["judge"]) else None)
            unrecorded[name] = "NOT_RUN" if result is None else project("dict4", result)

    if nondeterministic:
        problems.append(f"{len(nondeterministic)} judgments differ across hash seeds or timed out")
    if deadline_hit:
        problems.append(f"deadline reached: {len(deadline_hit)} judgments not run")
    state["determinism"] = {
        "seeds": list(SEEDS), "judgments": sum(1 for v in cache.values() if v is not None),
        "failures": sorted(f"round{k[0]}/{k[1]} {k[2][:7]} {' '.join(k[3]) or 'worktree'}"
                           for k in nondeterministic),
        "deadline_not_run": sorted(deadline_hit.values()),
        "elapsed_seconds": round(time.monotonic() - started, 1),
    }

    final = git(ROOT, "rev-parse", "--verify", "HEAD").decode("ascii", "replace").strip()
    if final != expected or git(ROOT, "status", "--porcelain", "-z"):
        problems.append("validation changed the source checkout")


def build_cell(git, ident_env, work: Path, base_repo: Path, rnd: int, published: Path) -> Path:
    name = published.name
    change = published / "change.patch"
    committed = published / "committed.patch"
    dest = work / "cells" / f"round{rnd}" / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    if committed.exists():
        # First-launch cell: HEAD carries committed.patch on BASE; its
        # worktree is BASE + change.patch with the original LF bytes.
        git(work, "-c", "core.autocrlf=false", "clone", "-q", "--no-hardlinks", str(base_repo), str(dest))
        git(dest, "config", "core.autocrlf", "false")
        git(dest, "apply", "--whitespace=nowarn", str(change))
        index = work / "first-launch.index"
        env = dict(ident_env(REBUILD_IDENT), GIT_INDEX_FILE=str(index))
        try:
            git(dest, "read-tree", BASE, env=env)
            git(dest, "apply", "--cached", "--whitespace=nowarn", str(committed), env=env)
            tree = git(dest, "write-tree", env=env).decode().strip()
        finally:
            index.unlink(missing_ok=True)
        if tree != FIRST_LAUNCH_TREE:
            raise Failure(f"first-launch HEAD tree {tree} differs from 3a0be5f's tree")
        head = git(dest, "commit-tree", tree, "-p", BASE, stdin=b"neutralize verification harness\n",
                   env=ident_env(REBUILD_IDENT)).decode().strip()
        git(dest, "update-ref", "HEAD", head)
        git(dest, "read-tree", head)
        git(dest, "remote", "remove", "origin")
        return dest
    lf = work / "lf" / f"round{rnd}" / name
    lf.parent.mkdir(parents=True, exist_ok=True)
    git(work, "-c", "core.autocrlf=false", "clone", "-q", "--no-hardlinks", str(base_repo), str(lf))
    git(lf, "config", "core.autocrlf", "false")
    git(lf, "apply", "--whitespace=nowarn", str(change))
    git(work, "-c", "core.autocrlf=true", "clone", "-q", "--no-hardlinks", str(base_repo), str(dest))
    git(dest, "remote", "remove", "origin")
    for path in sorted(patched_paths(change.read_bytes())):
        source, target = lf / path, dest / path
        if source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        elif target.exists():
            target.unlink()
    shutil.rmtree(lf, ignore_errors=True)  # scratch only; EC removes the job directory
    if git(dest, "rev-parse", "--verify", "HEAD").decode().strip() != BASE:
        raise Failure("cell HEAD is not the fixture base")
    return dest


def patched_paths(patch: bytes) -> set[str]:
    headers = re.findall(rb"^diff --git .*$", patch, re.M)
    matches = re.findall(rb"^diff --git a/(\S+) b/(\S+)$", patch, re.M)
    if len(matches) != len(headers):
        raise Failure("change.patch has a diff header this rebuild cannot parse")
    paths = set()
    for pair in matches:
        for raw in pair:
            path = raw.decode("utf-8")
            if path.startswith("/") or ".." in Path(path).parts or path.startswith(".git/"):
                raise Failure(f"unsafe patch path {path}")
            paths.add(path)
    return paths


def tree_hashes(root: Path) -> dict[str, str]:
    files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not (Path(dirpath) == root and d == ".git"))
        for name in sorted(filenames):
            path = Path(dirpath) / name
            files[path.relative_to(root).as_posix()] = sha256(path.read_bytes())
    return files


def finish(out: Path, state: dict) -> int:
    problems = state["problems"]
    rebuild, comparisons, determinism = state["rebuild"], state["comparisons"], state["determinism"]
    result = {
        "schema_version": 1, "workload": NAME,
        "requested_sha": state["expected"], "actual_sha": state["source"],
        "runtime": {"python": sys.version, "platform": platform.platform()},
        "steps": state["steps"],
        "rebuild": {"cells": len(rebuild), "ok": sum(1 for r in rebuild.values() if r.get("ok")),
                    "detail": rebuild},
        "comparisons": comparisons, "unrecorded_first_launch": state["unrecorded"],
        "determinism": determinism,
        "passed": not problems, "problems": problems,
        "limitations": [
            "one EC Windows pool runtime (Python 3.12.10); the originals ran on a local Windows Python, version not recorded",
            "files that were present when the originals were judged are not rebuilt: _session_output.txt, __pycache__, .pytest_cache and one 'nul' file, and in round 3 also _worktree_diff.txt and _committed_diff.txt at the spec 9 re-judge (written after drive-time judging); none is a pinwash surface or hook target",
            "the originals ran the host Git for Windows with the user's global config (core.autocrlf=true, a global excludes file); the pool runs the generation's MinGit under a neutral config; the judges read blobs and worktree bytes without conversion",
            "round 0 and round 1 drive-time records are compared but secondary: those cells changed after drive time",
            "the round 1 spec 7 re-judge ran an uncommitted tree that became 86bdcce; byte identity of that tree is not provable",
            "the first-launch cell was never judged; its results here have nothing to compare against",
            "expected_worktrees.json was hashed from the original cells on the maintainer's work machine (file reads only)",
        ],
    }
    write_json(out / "result.json", result)
    lines = ["# pinwash live-fire re-judge", "",
             f"Result: {'PASS' if not problems else 'FAIL'}", "",
             f"Source: `{state['source']}` (requested `{state['expected']}`)",
             f"Rebuilt cells byte-identical to the originals: "
             f"{result['rebuild']['ok']}/{result['rebuild']['cells']}", "",
             "| record | judge | primary | match | mismatch | not run |", "|---|---|---|---|---|---|"]
    for cid, comp in comparisons.items():
        if "counts" in comp:
            c = comp["counts"]
            lines.append(f"| {cid} | `{comp['judge'][:7]}` | {comp['primary']} | "
                         f"{c['MATCH']} | {c['MISMATCH']} | {c['NOT_RUN']} |")
        else:
            lines.append(f"| {cid} | `{comp['judge'][:7]}` | {comp['primary']} | {comp['status']} | | |")
    if determinism:
        lines += ["", f"Judgments: {determinism['judgments']}, each run with PYTHONHASHSEED "
                      f"{' and '.join(SEEDS)}; differing or timed out: {len(determinism['failures'])}; "
                      f"elapsed {determinism['elapsed_seconds']} s"]
    lines += [""] + [f"- {p}" for p in problems[:200]]
    lines += ["", "Per-range rows, raw judge output hashes and limitations: `result.json`; "
                  "raw judge stdout: `raw/`.", ""]
    (out / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
