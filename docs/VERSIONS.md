# Release and source versions

As of 2026-10-19, the published package and the source branch have different
spec versions. The package version alone does not identify the rules used.

| Track | Package version | Spec | Exact source | Publication |
|---|---|---|---|---|
| GitHub/PyPI release | `0.1.0` (Alpha, MIT) | 27 | `f8669ad86ac71b0e85e29307b471e699df5eb265`, annotated tag `v0.1.0` | Published 2026-10-18 |
| Source after PR #56 | Still `0.1.0` | 29 | Tested head `44e70b835fdf2895617a1b280773a03be0e150a6`; merged as `cc99b33f5b090955b8b3b1e236cae5c899e3c1f5` | SPEC 28–29 changes are unreleased |
| Next candidate | `0.1.1` (Alpha) | 29 | Based on `e04e115c8f3ec09809cf6f7cf5026dfb877fa7ac`; the reviewed candidate SHA is frozen in the external source manifest accompanying its acceptance proposal | NOT RUN / not published |

Sources: [release](https://github.com/taipei49314/pinwash/releases/tag/v0.1.0),
[PyPI 0.1.0](https://pypi.org/project/pinwash/0.1.0/),
[PR #56](https://github.com/taipei49314/pinwash/pull/56), and the source
[version constants](../pinwash/__init__.py) and [package metadata](../pyproject.toml).
The maintainer requested preparation of the 0.1.1 / SPEC 29 candidate on
2026-10-19. Its [draft notes](RELEASE_0_1_1.md) and
[new acceptance plan](PACKAGE_ACCEPTANCE_0_1_1.md) record the scope. The previous
0.1.0 / SPEC 29 verification artifacts remain historical and were not renamed.

## What users get

`pipx install pinwash==0.1.0` installs SPEC 27. It does not include PR #56's fixes
for command-free hook events and Claude Code's ignored hook skip keys.
Those changes are in source SPEC 29. Issues
[#42](https://github.com/taipei49314/pinwash/issues/42) and
[#45](https://github.com/taipei49314/pinwash/issues/45) retain unresolved parts;
the PR does not close all of their residuals.

The earlier source checkout and verification wheels called themselves `0.1.0`
while containing SPEC 29. This candidate now calls itself `0.1.1`, but no new
wheel has been built or accepted. Record the exact source SHA, spec version and artifact hash
with its results. Do not identify it as the PyPI release by its version or
filename alone. The [installation guide](INSTALL.md) separates package and
source installation choices.

The published files have these SHA-256 values, read back from GitHub and PyPI:

| File | SHA-256 |
|---|---|
| `pinwash-0.1.0-py3-none-any.whl` | `573cc01540a73b38a50ff26d7e375fc5ad70c1919a527a18cba16481d51a2d40` |
| `pinwash-0.1.0.tar.gz` | `b2f7c2795e3d8d2cb7463e81b25b6cfd299960e743a70fdbf9aef3bd561ad3a2` |

## What was accepted

- **Release source `f8669ad`:** the original and rebuilt installed wheels each
  passed 645 tests with zero failures, errors or skips, plus the package/session
  checks and exact container cleanup. The accepted original wheel and sdist
  were published; upload run
  [39124728317](https://github.com/taipei49314/pinwash/actions/runs/39124728317)
  succeeded. The [release record](https://github.com/taipei49314/pinwash/releases/tag/v0.1.0)
  includes the public acceptance receipt.
- **PR #56 head `44e70b8`:** both installed wheels each passed 690 tests with
  zero failures, errors, skips, expected failures or unexpected successes,
  plus the package/session checks and exact cleanup. See the
  [acceptance record](https://github.com/taipei49314/pinwash/pull/56#issuecomment-6252130711).
  Its `0.1.0` artifacts differ from the published files and were for verification
  only; they were not uploaded.

Both historical records are maintainer-authorized local Docker Linux acceptance,
`HUMAN_AUTHORIZED_LOCAL_DOCKER_NOT_EC_POOL`. They do not establish Windows/macOS
acceptance or EC pool qualification. Acceptance is tied to the recorded source
and artifacts; subsequent documentation edits do not create a new package
acceptance result. No tests or package builds were run for this documentation
update or the subsequent 0.1.1 candidate preparation. The historical 690-test
result does not accept a new version or new artifact.

## Historical text in the frozen SPEC

The current [SPEC](../SPEC.md) header still says engine `0.0.0`, not a Release
and not on PyPI; its §7 envelope example also uses `0.0.0`. These are historical
publication/version descriptions, not the current package metadata. The live
publication facts are recorded above. The SPEC remains authoritative for rules,
surfaces, severity, fingerprints, exit codes and determinism.

The SPEC preamble requires a spec-version bump and a fixture re-run for any
edit to that file. This documentation update leaves its bytes and version 29
unchanged. Correcting those historical descriptions inside SPEC belongs in a
separately validated spec change; this note changes no rule or acceptance gate.

## Other work remains separate

Drafts [#50](https://github.com/taipei49314/pinwash/pull/50),
[#51](https://github.com/taipei49314/pinwash/pull/51) and
[#52](https://github.com/taipei49314/pinwash/pull/52) retain an older SPEC 28–36
stack. Their numbering overlaps the merged specs 28–29; their evidence belongs
to their original SHAs. They are not part of the published package or this
source baseline. Reconnecting that stack requires resolving the overlap and
reviewing its remaining changes.

The [first-release procedure](RELEASE.md) records the completed `v0.1.0` run.
The next upload-only workflow is now prepared for the exact tag `v0.1.1`, with
new artifact acceptance and a deployment-environment tag-rule readback still
pending. This page does not authorize a retry, upload or change to publisher
scope; execution and its acceptance retain their separate recorded basis.
