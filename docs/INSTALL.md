# Installation candidate

Python 3.11+ and Git are required. PinWash has zero runtime dependencies. There
is no PyPI publication or GitHub release for this work, and the license remains
undecided by the human maintainer. Candidate archives retain version 0.0.0 and
must be identified by source SHA and artifact SHA-256, not version alone.

## Install in an isolated environment

Recommended when pipx is already available:

```text
pipx install /absolute/path/to/trusted/pinwash-checkout
```

The checkout must be reviewed and outside the project the agent edits. This
downloads the pinned setuptools build backend during installation. Installing
an accepted wheel instead does not require the build backend:

```text
pipx install /absolute/path/to/pinwash-0.0.0-py3-none-any.whl
```

Alternatively create a dedicated venv outside the project with your existing
Python, then use that venv's Python to install the trusted checkout or wheel:

```text
python -m venv /absolute/path/to/pinwash-env
/absolute/path/to/pinwash-env/bin/python -m pip install /absolute/path/to/trusted/pinwash-checkout
```

On Windows use `C:\path\to\pinwash-env\Scripts\python.exe` and run
`C:\path\to\pinwash-env\Scripts\pinwash.exe`. On macOS/Linux use
`/absolute/path/to/pinwash-env/bin/pinwash`. Activate the venv if you prefer the
short `pinwash` command. Never install the judge into the agent's subject repo.

See the README for `session start` and `session review`. Installation is not a
claim of package acceptance; check the exact candidate's validation record.

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

Package acceptance is separate from core source-suite acceptance. The proposed
`package-verify` workload builds wheel and sdist, rebuilds from sdist, installs
both wheels in fresh temporary venvs, compares installed package bytes, checks
the console command away from the checkout, exercises the session/report flow
and runs installed doctor. It records exact source, commands, outputs and hashes.
It requires separate EC workload approval before execution; it does not publish.
