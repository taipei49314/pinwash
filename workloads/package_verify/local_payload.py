"""Fixed local Docker payload. An independently approved host operator starts it.

Inputs are a read-only Git bundle, pinned backend wheel and execution manifest.
Only /out (a fresh designated output folder) and bounded /tmp are writable.
This module is never an authorization to run a workload on a work machine.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    if (sys.platform != "linux" or os.getuid() != 1000 or not Path("/.dockerenv").is_file()
            or Path("/tmp/source").exists()):
        raise RuntimeError("Fresh nonroot Linux Docker payload required")
    out = Path("/out")
    if not out.is_dir() or any(out.iterdir()):
        raise RuntimeError("Fresh empty designated output required")
    manifest = json.loads(Path("/inputs/execution.json").read_text(encoding="utf-8"))
    required = {"schema_version", "kind", "host", "source_sha", "bundle_sha256", "decision_sha256", "payload_sha256"}
    if (set(manifest) != required or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1 or manifest["kind"] != "pinwash-local-package"
            or manifest["host"] != "LAPTOP-01AGNPJU"):
        raise RuntimeError("Closed local package manifest required")
    import re
    for key, length in (("source_sha", 40), ("bundle_sha256", 64), ("decision_sha256", 64), ("payload_sha256", 64)):
        if not isinstance(manifest[key], str) or not re.fullmatch("[0-9a-f]{" + str(length) + "}", manifest[key]):
            raise RuntimeError("Invalid identity: " + key)
    for path, key in ((Path("/inputs/source.bundle"), "bundle_sha256"),
                      (Path(__file__), "payload_sha256")):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            raise RuntimeError("Invalid bounded input: " + str(path))
        if hashlib.sha256(path.read_bytes()).hexdigest() != manifest[key]:
            raise RuntimeError("Input hash differs: " + key)
    # Minimal environment: no host credentials, Git config, Python or pip hooks.
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp",
           "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
    source = Path("/tmp/source")
    steps = []
    started = time.monotonic()

    def run(name, argv, cwd="/tmp", timeout=60):
        timeout = min(timeout, 3300 - (time.monotonic() - started))
        if timeout <= 0:
            raise RuntimeError("Shared payload deadline exhausted")
        with (out / ("payload-" + name + ".stdout")).open("xb") as stdout, (out / ("payload-" + name + ".stderr")).open("xb") as stderr:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, start_new_session=True)
            timed_out = False
            try:
                code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(proc.pid, signal.SIGKILL)
                code = proc.wait(timeout=5)
            # Close remaining descendants in this command's owned process group.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        steps.append(dict(name=name, argv=argv, exit_code=code, timed_out=timed_out))
        if code != 0 or timed_out:
            raise RuntimeError(name + " failed or timed out")

    error = None
    try:
        run("python-version", [sys.executable, "--version"])
        run("git-version", ["git", "--version"])
        run("clone", ["git", "-c", "core.hooksPath=/dev/null", "clone", "--no-checkout", "/inputs/source.bundle", str(source)])
        run("checkout", ["git", "-c", "core.hooksPath=/dev/null", "checkout", "--detach", manifest["source_sha"]], source)
        run("source-before", ["git", "status", "--porcelain"], source)
        if (out / "payload-source-before.stdout").read_bytes():
            raise RuntimeError("Source is not clean before verification")
        env.update(PINWASH_PACKAGE_EXECUTION="human-authorized-local-docker", PINWASH_PACKAGE_HOST=manifest["host"],
                   PINWASH_PACKAGE_SOURCE=str(source), PINWASH_PACKAGE_SHA=manifest["source_sha"],
                   PINWASH_PACKAGE_DECISION_SHA256=manifest["decision_sha256"], PINWASH_PACKAGE_OUT="/out",
                   PINWASH_PACKAGE_BACKEND="/inputs/setuptools-83.0.0-py3-none-any.whl")
        remaining = 3300 - (time.monotonic() - started)
        if remaining <= 0:
            raise RuntimeError("Payload deadline exhausted")
        run("verify", [sys.executable, "-I", "-B", str(source / "workloads/package_verify/run.py")], source, remaining)
        run("source-after", ["git", "status", "--porcelain"], source)
        if (out / "payload-source-after.stdout").read_bytes():
            raise RuntimeError("Source changed during verification")
        run("head-after", ["git", "rev-parse", "HEAD"], source)
        if (out / "payload-head-after.stdout").read_text(encoding="ascii").strip() != manifest["source_sha"]:
            raise RuntimeError("Source HEAD changed during verification")
        result = json.loads((out / "result.json").read_text(encoding="utf-8"))
        if result["status"] != "PASS" or result["source_sha"] != manifest["source_sha"]:
            raise RuntimeError("Package acceptance did not pass at the fixed source")
    except Exception as exc:
        error = str(exc)
    summary = dict(schema_version=1, execution_class="HUMAN_AUTHORIZED_LOCAL_DOCKER_NOT_EC_POOL",
                   manifest=manifest, steps=steps, error=error, status="PASS" if error is None else "FAIL",
                   elapsed_seconds=round(time.monotonic() - started, 3), published=False)
    (out / "payload-result.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0 if error is None else 2


if __name__ == "__main__":
    raise SystemExit(main())
