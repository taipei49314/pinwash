# Install PinWash 0.1.1 / SPEC 29

These commands install the published **0.1.1 / SPEC 29** Alpha release. See
[release and source versions](VERSIONS.md) for exact source and artifact hashes,
and the [release notes](RELEASE_0_1_1.md) for its changes and acceptance scope.

For a complete source download, isolated installation and first review, start
with the [five-minute quickstart](QUICKSTART.md). This page covers alternatives
and packaging details.

Python 3.11+ and Git are required. PinWash 0.1.1 is Alpha, licensed under MIT,
and has zero runtime dependencies. Linux is the package acceptance target;
Windows/macOS acceptance is not claimed. Keep the judge outside the project
that the agent edits and fixed throughout each session.

## Install in an isolated environment

If pipx is already available:

```text
pipx install pinwash==0.1.1
```

Otherwise use a new, separate environment (POSIX shell):

```sh
python3 -m venv /absolute/path/to/pinwash-env &&
/absolute/path/to/pinwash-env/bin/python -m pip install 'pinwash==0.1.1'
```

Use that environment's `bin/pinwash`, or activate it for the short command.
Never overwrite an installation used by an active session.

## Verified wheel or source checkout

You can also install the original wheel from the
[GitHub release](https://github.com/taipei49314/pinwash/releases/tag/v0.1.1).
Check its SHA-256 against the release's `SHA256SUMS` and `ACCEPTANCE.json`:
`d002160a73f5affbd4cf3446f676aa2809ef006a12feff77cab5edb4a8c62e03`.
Its accepted source is `fdb3c4d753d637e89aba5a22372d61dc2c292939`, tag `v0.1.1`.

```text
pipx install /absolute/path/to/pinwash-0.1.1-py3-none-any.whl
```

For development review of a trusted source checkout at a fixed SHA (this is
not an accepted release installation):

```text
pipx install /absolute/path/to/trusted/pinwash-checkout
```

Source installation downloads pinned setuptools 83.0.0. Installing the wheel
requires no build backend. Installed scans use no network. Read the
[quickstart](QUICKSTART.md) for the first session and [release procedure](RELEASE.md)
for how artifact hashes and publication are verified. Each acceptance record
covers only its recorded source and artifacts, not another checkout or wheel
that shares the version string. The SPEC 29 wheels from PR #56 were built for
verification only and were not uploaded to PyPI.

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
