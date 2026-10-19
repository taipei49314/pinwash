# Published releases and the first-release procedure

**Current release: [0.1.1 / SPEC 29](RELEASE_0_1_1.md)**, published on 2026-10-19
to [GitHub](https://github.com/taipei49314/pinwash/releases/tag/v0.1.1) and
[PyPI](https://pypi.org/project/pinwash/0.1.1/). Exact source, accepted hashes and
publication readback are recorded in [release and source versions](VERSIONS.md).

The first version, **0.1.0 (Alpha)** under MIT, was published on 2026-10-18:
[GitHub release](https://github.com/taipei49314/pinwash/releases/tag/v0.1.0) and
[PyPI](https://pypi.org/project/pinwash/0.1.0/). It uses SPEC 27 at
`f8669ad86ac71b0e85e29307b471e699df5eb265`. Only the accepted original wheel and
sdist were uploaded; the rebuilt wheel was an acceptance artifact.

Main subsequently incorporated SPEC 29 in PR #56 without changing the package
version. Those fixes are now included in 0.1.1. Its original and rebuilt installed
wheels each passed 690 tests in explicitly accepted local Docker Linux verification.
The upload-only workflow published the accepted original files on attempt 1 in
[run 39226974886](https://github.com/taipei49314/pinwash/actions/runs/39226974886).
The `pypi` environment was read back with exact `v0.1.0` and `v0.1.1` tag rules;
the existing publisher tuple was retained. The historical
[acceptance plan](PACKAGE_ACCEPTANCE_0_1_1.md) links the completed result.

The steps below record the completed first-release procedure, not a pending
dispatch or a reusable grant. Its build execution, trust configuration and
single upload received their own scoped approvals. This document grants no
new execution or publishing authority.

## Recorded first-release procedure

1. Fix a clean source SHA. Run the two-wheel package acceptance harness at that
   exact source in an authorized environment. Require complete suites with no
   failures, errors or skips, matching source/package bytes, version 0.1.0,
   MIT metadata and exact license bytes in both archives. Preserve raw results
   and artifact hashes. Old version 0.0.0 acceptance does not validate these files.
2. After source review and acceptance, merge the release preparation PR without
   changing its tree. Create annotated tag `v0.1.0` at the exact tested source
   commit, which is now an ancestor of main. Never move or overwrite the tag.
3. Stage a draft GitHub release at this tag with `target_commitish` set to the
   full tested SHA. Attach the original wheel and sdist and acceptance receipts.
   After checking both asset hashes, publish it as an Alpha prerelease; the
   upload job has read-only repository access and downloads public assets.
4. Configure the PyPI pending publisher for project `pinwash`, owner
   `taipei49314`, repository `pinwash`, workflow `publish-pypi.yml`, environment
   `pypi`. Restrict that GitHub environment to tag `v0.1.0`. This is a new trust
   delegation and requires the maintainer's explicit confirmation.
5. Register and read back the approved upload dispatch, then manually dispatch
   `publish-pypi.yml` at tag `v0.1.0` with the tested SHA and the two accepted
   SHA-256 hashes. It only downloads those release assets, checks exact
   bytes and uploads them. It never builds or executes PinWash, uses no long-lived
   PyPI token, grants no repository write permission, and has a 15-minute limit.
6. Read back the workflow result and PyPI JSON. Require version, filenames,
   license, Python requirement and both SHA-256 values to match. Then update the
   GitHub release notes with the verified PyPI link. An upload error or unknown outcome must
   be inspected before further action; do not automatically retry or overwrite.
   If PyPI upload fails, the GitHub prerelease remains published and must not be
   described as a completed PyPI release.

The first release used a manual-only workflow fixed to `v0.1.0`; the current
source is fixed to `v0.1.1`. Neither is a standing authorization for later
releases. The PyPI publisher remains attached
to this exact repository/workflow/environment; changing its scope is a separate
decision. No Windows/macOS package acceptance or 1.0 stability claim is made.
