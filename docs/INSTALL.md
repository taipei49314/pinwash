# Install PinWash 0.1.0

For a complete source download, isolated installation and first review, start
with the [five-minute quickstart](QUICKSTART.md). This page covers alternatives
and packaging details.

Python 3.11+ and Git are required. PinWash 0.1.0 is Alpha, licensed under MIT,
and has zero runtime dependencies. Linux is the package acceptance target;
Windows/macOS acceptance is not claimed. Keep the judge outside the project
that the agent edits and fixed throughout each session.

## Install in an isolated environment

If pipx is already available:

```text
pipx install pinwash==0.1.0
```

Otherwise use a new, separate environment (POSIX shell):

```sh
python3 -m venv /absolute/path/to/pinwash-env &&
/absolute/path/to/pinwash-env/bin/python -m pip install 'pinwash==0.1.0'
```

Use that environment's `bin/pinwash`, or activate it for the short command.
Never overwrite an installation used by an active session.

For an accepted wheel whose source and SHA-256 you have checked:

```text
pipx install /absolute/path/to/pinwash-0.1.0-py3-none-any.whl
```

For a reviewed source checkout at a fixed SHA:

```text
pipx install /absolute/path/to/trusted/pinwash-checkout
```

Source installation downloads pinned setuptools 83.0.0. Installing the wheel
requires no build backend. Installed scans use no network. Read the
[quickstart](QUICKSTART.md) for the first session and [release procedure](RELEASE.md)
for how artifact hashes and publication are verified. Historical candidate
acceptance documents cover only their recorded source, not this version.

## Build and verify

PEP 517 uses `setuptools==83.0.0`. The custom build step includes the original
tests and SPEC/THREATMODEL in `pinwash/_verification/`; it does not install a
generic top-level `tests` package. Source distributions include those inputs
so a wheel can also be built from the sdist.

Installed `doctor` copies the actual installed package and its bundled test
resources into a temporary source layout, then invokes the original full suite
in an isolated child process. It preserves nested-doctor recursion protection.
Missing resources, zero tests and skipped tests remain failures. Running doctor
is a workload, not a lightweight environment/version check.

Package acceptance is separate from core source-suite acceptance. The
`package-verify` workload builds wheel and sdist, rebuilds from sdist, installs
both wheels in fresh temporary venvs, compares installed package bytes, checks
the console command away from the checkout, exercises the session/report flow
and runs installed doctor. It records exact source, commands, outputs and hashes.
Execution uses a separately approved EC workload declaration; it does not publish.
