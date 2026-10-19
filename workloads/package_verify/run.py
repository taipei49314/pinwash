"""Package acceptance. Requires its approved EC dispatch or explicit local grant."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
import tomllib
from email.parser import BytesParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND_URL = "https://files.pythonhosted.org/packages/5d/40/e1e72872c6354b306daef1703549e8e83b4d43cfea356311bf722a043752/setuptools-83.0.0-py3-none-any.whl"
BACKEND_SHA = "29b23c360f22f414dc7336bb39178cc7bcbf6021ed2733cde173f09dba19abb3"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if platform.node().upper() in {"LAPTOP-01AGNPJU", "LAPTOP-16NUA5I8"}:
        raise RuntimeError("Do not execute this harness directly on a work machine")
    execution = os.environ.get("PINWASH_PACKAGE_EXECUTION")
    local = execution == "human-authorized-local-docker"
    local_linux = execution == "human-authorized-pju-linux-package"
    linux_pool = execution == "ec-pool-linux"
    strict_linux = local_linux or linux_pool
    offline = local or strict_linux
    if offline:
        # This is provenance, not an authority mechanism. The host operator must
        # verify and consume the separately recorded human grant before Docker.
        physical_host = "LAPTOP-01AGNPJU" if local or local_linux else "LAPTOP-50KP71KA"
        inputs_root = "/inputs" if local else "/source/inputs"
        source_root = "/tmp/source" if local else "/work/source"
        output_root = "/out" if local else "/output/results"
        if (sys.platform != "linux" or os.getuid() != 1000 or not Path("/.dockerenv").is_file()
                or os.environ.get("PINWASH_PACKAGE_HOST") != physical_host
                or Path(os.environ.get("PINWASH_PACKAGE_SOURCE", "")).resolve() != ROOT
                or not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("PINWASH_PACKAGE_SHA", ""))
                or not re.fullmatch(r"[0-9a-f]{64}", os.environ.get("PINWASH_PACKAGE_DECISION_SHA256", ""))
                or os.environ.get("PINWASH_PACKAGE_OUT") != output_root
                or os.environ.get("PINWASH_PACKAGE_BACKEND") != inputs_root + "/setuptools-83.0.0-py3-none-any.whl"):
            raise RuntimeError("Explicit Docker package provenance and offline inputs required")
        if strict_linux and (str(ROOT) != source_root or os.environ.get("TMPDIR") != "/work"
                or sys.version_info[:3] != (3, 12, 15)):
            raise RuntimeError("Fixed Linux package layout and Python 3.12.15 required")
        if local_linux and any(key.startswith("EC_WORKLOAD_") for key in os.environ):
            raise RuntimeError("Local Linux package validation cannot claim an EC workload")
        if linux_pool and (os.environ.get("EC_WORKLOAD_REPOSITORY") != "taipei49314/pinwash"
                or os.environ.get("EC_WORKLOAD_NAME") != "package-linux-verify"
                or os.environ.get("EC_WORKLOAD_SHA") != os.environ.get("PINWASH_PACKAGE_SHA")
                or os.environ.get("EC_WORKLOAD_SOURCE") != source_root
                or os.environ.get("EC_WORKLOAD_OUT") != output_root):
            raise RuntimeError("Fixed admitted Linux package workload provenance required")
        expected = os.environ["PINWASH_PACKAGE_SHA"]
        out = Path(output_root)
    else:
        if (os.environ.get("PINWASH_PACKAGE_EXECUTION")
                or os.environ.get("EC_WORKLOAD_REPOSITORY") != "taipei49314/pinwash"
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
        code, step_error, timed_out = None, None, False
        if offline:
            # Persist partial output even if the outer Docker deadline kills us.
            stdout_path, stderr_path = out / f"{name}.stdout", out / f"{name}.stderr"
            with stdout_path.open("xb") as stdout_file, stderr_path.open("xb") as stderr_file:
                try:
                    result = subprocess.run(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                            stdout=stdout_file, stderr=stderr_file, check=False, timeout=timeout)
                    code = result.returncode
                except subprocess.TimeoutExpired as exc:
                    if strict_linux:
                        timed_out, step_error = True, {"type": type(exc).__name__, "message": str(exc)}
                    else:
                        code = 2
                        stderr_file.write(b"\nPACKAGE STEP TIMEOUT\n")
                except OSError as exc:
                    if strict_linux:
                        step_error = {"type": type(exc).__name__, "message": str(exc)}
                    else:
                        code = 2
                        stderr_file.write(str(exc).encode("utf-8", "replace"))
            stdout, stderr = stdout_path.read_bytes(), stderr_path.read_bytes()
        else:
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
        step = {"name": name, "command": args, "cwd": str(cwd), "exit_code": code,
                      "elapsed_seconds": round(time.monotonic() - began, 3),
                      "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                      "stderr_sha256": hashlib.sha256(stderr).hexdigest()}
        if strict_linux:
            # Keep actual nullable exit separate from wrapper failure, and never
            # insert our own timeout/exception text into a child's raw stderr.
            step.update(outcome="PASS" if type(code) is int and code in accepted and step_error is None else "FAIL",
                        error=step_error, timed_out=timed_out)
        steps.append(step)
        if strict_linux and step["outcome"] != "PASS":
            raise RuntimeError(f"{name}: {step_error or ('exit ' + str(code))}")
        if code not in accepted:
            raise RuntimeError(f"{name}: exit {code}")
        return stdout

    def python(venv):
        return str(venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))

    try:
        actual = run("source-sha", ["git", "rev-parse", "HEAD"], ROOT).decode().strip()
        if actual != expected or run("source-clean", ["git", "status", "--porcelain"], ROOT):
            raise RuntimeError("Source must be exact and clean")
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        expected_version = project["version"]
        if strict_linux and (expected_version != "0.1.1"
                or digest(ROOT / "SPEC.md") != "e31d7b466378f9358a5dbaf505cc8fb07c2c02093cc4daa24ac949666afd969b"):
            raise RuntimeError("Fixed 0.1.1 / SPEC 29 Linux package source required")
        expected_license = (ROOT / "LICENSE").read_bytes()

        def check_metadata(raw):
            metadata = BytesParser().parsebytes(raw)
            if (metadata["Name"] != "pinwash" or metadata["Version"] != expected_version
                    or metadata["Requires-Python"] != ">=3.11"
                    or metadata["License-Expression"] != "MIT"
                    or metadata.get_all("License-File") != ["LICENSE"]
                    or metadata.get_all("Requires-Dist")
                    or metadata["Description-Content-Type"] != "text/markdown"):
                raise RuntimeError("Release metadata differs from the expected project contract")
        with tempfile.TemporaryDirectory(prefix="pw-package-") as temporary:
            scratch = Path(temporary)
            source = scratch / "source"
            shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "*.egg-info", "dist", "build"))
            backend = scratch / "setuptools-83.0.0-py3-none-any.whl"
            if offline:
                backend_input = Path(os.environ["PINWASH_PACKAGE_BACKEND"])
                if backend_input.is_symlink() or not backend_input.is_file():
                    raise RuntimeError("Offline build backend must be an ordinary file")
                response = backend_input.open("rb")
            else:
                response = urllib.request.urlopen(BACKEND_URL, timeout=60)
            with response:
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
            if (source_again / "LICENSE").read_bytes() != expected_license:
                raise RuntimeError("Source distribution license differs from source")
            check_metadata((source_again / "PKG-INFO").read_bytes())
            run("rebuild-wheel", [build_python, "-I", "-c", "from setuptools.build_meta import build_wheel; import sys; build_wheel(sys.argv[1])", str(rebuilt)], source_again)
            rebuilt_wheel, = rebuilt.glob("*.whl")

            def wheel_files(path):
                with zipfile.ZipFile(path) as archive:
                    return {name: archive.read(name) for name in archive.namelist() if not name.endswith("/RECORD")}

            contents = wheel_files(wheel)
            if contents != wheel_files(rebuilt_wheel):
                raise RuntimeError("Wheel rebuilt from sdist differs in file contents")
            dist_info = f"pinwash-{expected_version}.dist-info"
            check_metadata(contents[f"{dist_info}/METADATA"])
            if contents.get(f"{dist_info}/licenses/LICENSE") != expected_license:
                raise RuntimeError("Wheel license differs from source")
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
                before_status = json.loads(run(f"{label}-status-before", [command, "session", "status", "--state-dir", state, "--json"], fixture))
                if before_status["status"] != "active" or before_status["latest_review"] is not None:
                    raise RuntimeError("New session status did not preserve an unreviewed baseline")
                active_state = Path(before_status["state_path"])
                state_bytes = active_state.read_bytes()
                (fixture / ".claude" / "settings.json").write_text('{"hooks":{}}')
                (fixture / "json.py").write_text(sentinel, encoding="utf-8")
                report_text = run(f"{label}-review", [command, "session", "review", "--state-dir", state, "--stopped"], fixture, accepted=(1,))
                if b"Next:" not in report_text or b"HOOK_REMOVED" not in report_text or b"Priority summary:" not in report_text:
                    raise RuntimeError("Human report missing explanation or next step")
                result = json.loads(run(f"{label}-json", [command, "session", "review", "--state-dir", state, "--stopped", "--json"], fixture, accepted=(1,)))
                if result["status"] != "block" or not result["execution_complete"] or len(result["runs"]) != 3:
                    raise RuntimeError("Installed session did not judge all three comparisons")
                after_status = json.loads(run(f"{label}-status-after", [command, "session", "status", "--state-dir", state, "--json"], fixture))
                if (after_status["status"] != "active" or after_status["current_changes"] != "not_reviewed"
                        or after_status["session"]["base"] != before_status["session"]["base"]
                        or after_status["latest_review"]["status"] != "block"
                        or active_state.read_bytes() != state_bytes):
                    raise RuntimeError("Status changed state or misreported historical evidence")
                status_text = run(f"{label}-status-text", [command, "session", "status", "--state-dir", state], fixture)
                if b"NOT REVIEWED" not in status_text or b"historical" not in status_text:
                    raise RuntimeError("Status text did not distinguish history from current changes")
                run(f"{label}-restore-demo-hook", git + ["restore", "--", ".claude/settings.json"], fixture)
                restored = json.loads(run(f"{label}-review-restored", [command, "session", "review", "--state-dir", state, "--stopped", "--json"], fixture))
                if restored["status"] != "pass" or restored["base"] != before_status["session"]["base"]:
                    raise RuntimeError("Restored demo did not pass against its original baseline")
                if executed.exists():
                    raise RuntimeError("Installed consumer executed subject code")
                doctor = json.loads(run(f"{label}-doctor", [command, "doctor"], scratch, timeout=1200))
                tests = doctor["self_tests"]
                if strict_linux and (tests.get("available") is not True or tests.get("ok") is not True
                        or type(tests.get("tests_run")) is not int or tests["tests_run"] != 690
                        or any(type(tests.get(key)) is not int or tests[key] != 0 for key in
                               ("errors", "failures", "skipped_count", "expected_failures", "unexpected_successes", "nested_depth"))
                        or type(doctor.get("spec_version")) is not int or doctor["spec_version"] != 29
                        or doctor.get("pinwash_version") != "0.1.1"):
                    raise RuntimeError("Linux package doctor must complete the fixed 690-test suite without exceptions")
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
              "execution_class": "HUMAN_AUTHORIZED_LOCAL_DOCKER_NOT_EC_POOL" if local else "HUMAN_AUTHORIZED_PJU_LINUX_PACKAGE_NOT_EC_POOL" if local_linux else "EC_POOL_DOCKER_LINUX" if linux_pool else "EC_POOL",
              "physical_host": os.environ["PINWASH_PACKAGE_HOST"] if offline else platform.node(),
              "decision_sha256": os.environ["PINWASH_PACKAGE_DECISION_SHA256"] if offline else None,
              "backend_mode": "offline-file" if offline else "pinned-download",
              "steps": steps, "artifacts": artifacts, "problems": problems,
              "status": "FAIL" if problems else "PASS", "published": False}
    (out / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    (out / "SUMMARY.md").write_text(f"# PinWash package acceptance: {result['status']}\n\nSource: `{expected}`\n\n" + "\n".join(problems) + "\n\nNo publication. This result covers only the recorded host/runtime.\n", encoding="utf-8")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
