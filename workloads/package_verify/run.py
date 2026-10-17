"""Proposed EC package acceptance. Run only after its declaration is approved."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND_URL = "https://files.pythonhosted.org/packages/5d/40/e1e72872c6354b306daef1703549e8e83b4d43cfea356311bf722a043752/setuptools-83.0.0-py3-none-any.whl"
BACKEND_SHA = "29b23c360f22f414dc7336bb39178cc7bcbf6021ed2733cde173f09dba19abb3"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if platform.node().upper() in {"LAPTOP-01AGNPJU", "LAPTOP-16NUA5I8"}:
        raise RuntimeError("Package verification belongs on the approved EC pool, not a work machine")
    if (os.environ.get("EC_WORKLOAD_REPOSITORY") != "taipei49314/pinwash"
            or os.environ.get("EC_WORKLOAD_NAME") != "package-verify"
            or Path(os.environ.get("EC_WORKLOAD_SOURCE", "")).resolve() != ROOT):
        raise RuntimeError("Use the approved EC package-verify dispatch")
    expected = os.environ["EC_WORKLOAD_SHA"]
    out = Path(os.environ["EC_WORKLOAD_OUT"]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(("GIT_", "PYTHON", "PIP_"))}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", PIP_NO_INDEX="1",
               PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK="1",
               PIP_NO_CACHE_DIR="1", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               PINWASH_TODAY="2026-09-30")
    env.pop("PINWASH_DOCTOR_SELFTEST", None)
    steps, artifacts, problems = [], [], []

    def run(name, args, cwd, accepted=(0,), timeout=900):
        began = time.monotonic()
        try:
            result = subprocess.run(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, check=False, timeout=timeout)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr = 2, exc.stdout or b"", exc.stderr or b""
            stderr += b"\nPACKAGE STEP TIMEOUT\n"
        except OSError as exc:
            code, stdout, stderr = 2, b"", str(exc).encode("utf-8", "replace")
        (out / f"{name}.stdout").write_bytes(stdout)
        (out / f"{name}.stderr").write_bytes(stderr)
        steps.append({"name": name, "command": args, "cwd": str(cwd), "exit_code": code,
                      "elapsed_seconds": round(time.monotonic() - began, 3),
                      "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                      "stderr_sha256": hashlib.sha256(stderr).hexdigest()})
        if code not in accepted:
            raise RuntimeError(f"{name}: exit {code}")
        return stdout

    def python(venv):
        return str(venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))

    try:
        actual = run("source-sha", ["git", "rev-parse", "HEAD"], ROOT).decode().strip()
        if actual != expected or run("source-clean", ["git", "status", "--porcelain"], ROOT):
            raise RuntimeError("Source must be exact and clean")
        with tempfile.TemporaryDirectory(prefix="pw-package-") as temporary:
            scratch = Path(temporary)
            source = scratch / "source"
            shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "*.egg-info", "dist", "build"))
            backend = scratch / "setuptools-83.0.0-py3-none-any.whl"
            with urllib.request.urlopen(BACKEND_URL, timeout=60) as response:
                content = response.read(2_000_001)
            if len(content) > 2_000_000 or hashlib.sha256(content).hexdigest() != BACKEND_SHA:
                raise RuntimeError("Build backend hash/size mismatch")
            backend.write_bytes(content)
            build_env = scratch / "builder"
            run("build-venv", [sys.executable, "-I", "-m", "venv", str(build_env)], scratch)
            build_python = python(build_env)
            run("backend-install", [build_python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", str(backend)], scratch)
            wheels, sdists, rebuilt = [scratch / name for name in ("wheels", "sdists", "rebuilt")]
            for path in (wheels, sdists, rebuilt):
                path.mkdir()
            run("build-wheel", [build_python, "-I", "-c", "from setuptools.build_meta import build_wheel; import sys; build_wheel(sys.argv[1])", str(wheels)], source)
            run("build-sdist", [build_python, "-I", "-c", "from setuptools.build_meta import build_sdist; import sys; build_sdist(sys.argv[1])", str(sdists)], source)
            wheel, = wheels.glob("*.whl")
            sdist, = sdists.glob("*.tar.gz")
            unpacked = scratch / "unpacked"
            unpacked.mkdir()
            with tarfile.open(sdist) as archive:
                for member in archive.getmembers():
                    destination = (unpacked / member.name).resolve()
                    if not destination.is_relative_to(unpacked) or not (member.isfile() or member.isdir()):
                        raise RuntimeError("Unsafe source archive member")
                    if member.isdir():
                        destination.mkdir(parents=True, exist_ok=True)
                    else:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        with archive.extractfile(member) as stream:
                            destination.write_bytes(stream.read())
            source_again, = unpacked.iterdir()
            run("rebuild-wheel", [build_python, "-I", "-c", "from setuptools.build_meta import build_wheel; import sys; build_wheel(sys.argv[1])", str(rebuilt)], source_again)
            rebuilt_wheel, = rebuilt.glob("*.whl")

            def wheel_files(path):
                with zipfile.ZipFile(path) as archive:
                    return {name: archive.read(name) for name in archive.namelist() if not name.endswith("/RECORD")}

            contents = wheel_files(wheel)
            if contents != wheel_files(rebuilt_wheel):
                raise RuntimeError("Wheel rebuilt from sdist differs in file contents")
            for name in ("SPEC.md", "THREATMODEL.md", "tests/gates/test_v0_acceptance.py", "tests/test_consumer.py"):
                if f"pinwash/_verification/{name}" not in contents:
                    raise RuntimeError(f"Missing verification resource: {name}")
            if any(name.startswith("tests/") for name in contents):
                raise RuntimeError("Wheel pollutes top-level tests namespace")
            expected_bundle = {"SPEC.md": (ROOT / "SPEC.md").read_bytes(), "THREATMODEL.md": (ROOT / "THREATMODEL.md").read_bytes()}
            expected_bundle.update({p.relative_to(ROOT).as_posix(): p.read_bytes() for p in (ROOT / "tests").rglob("*.py")})
            actual_bundle = {name.removeprefix("pinwash/_verification/"): data for name, data in contents.items() if name.startswith("pinwash/_verification/")}
            if actual_bundle != expected_bundle:
                raise RuntimeError("Bundled verification files differ from the exact source set")
            for source_py in (ROOT / "pinwash").rglob("*.py"):
                name = source_py.relative_to(ROOT).as_posix()
                if contents.get(name) != source_py.read_bytes():
                    raise RuntimeError(f"Wheel differs from dispatched code: {name}")
            for label, path in (("wheel", wheel), ("sdist", sdist), ("rebuilt-wheel", rebuilt_wheel)):
                destination = out / label / path.name
                destination.parent.mkdir()
                shutil.copyfile(path, destination)
                artifacts.append({"kind": label, "file": str(destination.relative_to(out)), "sha256": digest(destination)})

            for number, artifact in enumerate((wheel, rebuilt_wheel), 1):
                label = f"install-{number}"
                runtime = scratch / label
                run(f"{label}-venv", [sys.executable, "-I", "-m", "venv", str(runtime)], scratch)
                runtime_python = python(runtime)
                run(f"{label}-wheel", [runtime_python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", str(artifact)], scratch)
                command = str(runtime / ("Scripts/pinwash.exe" if os.name == "nt" else "bin/pinwash"))
                run(f"{label}-version", [command, "--version"], scratch)
                metadata = json.loads(run(f"{label}-metadata", [runtime_python, "-I", "-c",
                    "import importlib.metadata as m,json,pinwash; d=m.distribution('pinwash'); print(json.dumps({'version':d.version,'requires':d.requires,'module':pinwash.__file__,'entry':[e.value for e in d.entry_points if e.name=='pinwash']}))"], scratch))
                if metadata["requires"] or metadata["entry"] != ["pinwash.cli:main"] or not Path(metadata["module"]).is_relative_to(runtime):
                    raise RuntimeError("Incorrect installed metadata or import location")
                installed = Path(metadata["module"]).parent
                for source_py in (ROOT / "pinwash").rglob("*.py"):
                    if (installed / source_py.relative_to(ROOT / "pinwash")).read_bytes() != source_py.read_bytes():
                        raise RuntimeError("Installed code differs from exact source")
                installed_bundle = installed / "_verification"
                if {p.relative_to(installed_bundle).as_posix(): p.read_bytes()
                    for p in installed_bundle.rglob("*") if p.is_file()
                    and "__pycache__" not in p.parts and p.suffix != ".pyc"} != expected_bundle:
                    raise RuntimeError("Installed verification resources differ from exact source")
                fixture = scratch / f"subject-{number}"
                fixture.mkdir()
                (fixture / ".claude").mkdir()
                (fixture / ".claude" / "settings.json").write_text('{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"python hooks/judge.py"}]}]}}')
                (fixture / "hooks").mkdir()
                executed = scratch / f"subject-executed-{number}"
                sentinel = ("from pathlib import Path\nPath(" + repr(str(executed))
                            + ").write_text('executed')\nraise RuntimeError('subject must not execute')\n")
                (fixture / "hooks" / "judge.py").write_text(sentinel, encoding="utf-8")
                git = ["git", "-c", "user.name=PinWash acceptance", "-c", "user.email=pinwash@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull]
                run(f"{label}-git-init", git + ["init", "-b", "main"], fixture)
                run(f"{label}-git-add", git + ["add", "."], fixture)
                run(f"{label}-git-commit", git + ["commit", "-m", "base"], fixture)
                state = str(scratch / f"state-{number}")
                run(f"{label}-start", [command, "session", "start", "--state-dir", state], fixture)
                (fixture / ".claude" / "settings.json").write_text('{"hooks":{}}')
                (fixture / "json.py").write_text(sentinel, encoding="utf-8")
                report_text = run(f"{label}-review", [command, "session", "review", "--state-dir", state, "--stopped"], fixture, accepted=(1,))
                if b"Next:" not in report_text or b"HOOK_REMOVED" not in report_text:
                    raise RuntimeError("Human report missing explanation or next step")
                result = json.loads(run(f"{label}-json", [command, "session", "review", "--state-dir", state, "--stopped", "--json"], fixture, accepted=(1,)))
                if result["status"] != "block" or not result["execution_complete"] or len(result["runs"]) != 3:
                    raise RuntimeError("Installed session did not judge all three comparisons")
                if executed.exists():
                    raise RuntimeError("Installed consumer executed subject code")
                doctor = json.loads(run(f"{label}-doctor", [command, "doctor"], scratch, timeout=1200))
                tests = doctor["self_tests"]
                if doctor["subject_judged"] is not False or not tests["ok"] or tests["tests_run"] < 1 or tests["skipped_count"] or tests.get("nested_depth") != 0:
                    raise RuntimeError("Installed doctor did not run the full passing suite")
                if (doctor["spec_sha256"] != digest(ROOT / "SPEC.md")
                        or doctor["spec_version"] != result["judge"]["spec_version"]
                        or doctor["pinwash_version"] != metadata["version"]):
                    raise RuntimeError("Installed doctor reported a different contract or version")
    except Exception as exc:
        problems.append(str(exc))
    result = {"source_sha": expected, "host": platform.node(), "python": sys.version,
              "backend": {"url": BACKEND_URL, "sha256": BACKEND_SHA},
              "steps": steps, "artifacts": artifacts, "problems": problems,
              "status": "FAIL" if problems else "PASS", "published": False}
    (out / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    (out / "SUMMARY.md").write_text(f"# PinWash package acceptance: {result['status']}\n\nSource: `{expected}`\n\n" + "\n".join(problems) + "\n\nNo publication. This result covers only the recorded host/runtime.\n", encoding="utf-8")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
