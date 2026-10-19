# PinWash 0.1.1 / SPEC 29 — release notes

**Published 2026-10-19:** [GitHub release](https://github.com/taipei49314/pinwash/releases/tag/v0.1.1)
and [PyPI](https://pypi.org/project/pinwash/0.1.1/). This MIT-licensed Alpha uses
package version `0.1.1`, SPEC 29 and findings envelope 1. The exact accepted
source is `fdb3c4d753d637e89aba5a22372d61dc2c292939`, annotated tag `v0.1.1`,
merged in [PR #58](https://github.com/taipei49314/pinwash/pull/58).

## Changes relative to the published 0.1.0

The release carries the two spec changes merged in
[PR #56](https://github.com/taipei49314/pinwash/pull/56):

- **SPEC 28:** emptied hook events are compared with what existed at base.
  A command-free event left unchanged no longer blocks unrelated changes.
  Claude `prompt` and `agent` handlers with modeled shapes count for removal
  and `disableAllHooks` protection. Changed handler content remains explicitly
  unassessed; PinWash does not interpret the prompt or run its model.
- **SPEC 29:** Claude Code hook keys `disabled`, `hookEnabled`,
  `continueOnError` and `failOpen` do not deactivate commands in PinWash's
  `claude_settings` model. Those keys are ignored by the observed Claude host
  versions. Cursor's skip-key behavior remains unchanged.

These changes include both fewer false alarms and additional blocks:

| Example change | Released behavior |
|---|---|
| Unrelated diff beside an unchanged command-free hook event | No emptied-command finding |
| `disableAllHooks: true` over a modeled prompt-only Stop event | Blocking finding |
| The only live flagged Claude Stop judge is removed or disabled by the settings-root switch | Its ignored per-hook flag no longer hides its liveness; the applicable weakening finding can block |
| A modeled handler changes while another handler stays | Explicit coverage row; handler semantics are not evaluated |

This is not a promise that all hook-related false positives or escapes are
closed. Issues [#42](https://github.com/taipei49314/pinwash/issues/42) and
[#45](https://github.com/taipei49314/pinwash/issues/45) retain unresolved parts,
including the general base-liveness question and R13/R24 residuals. The older
draft #50–#52 stack is outside this release. No new detector change was made
by the version preparation itself.

## Installation and artifacts

Install with `pipx install pinwash==0.1.1`; Python 3.11+ and Git are required.
There are no runtime dependencies. The [installation guide](INSTALL.md) covers
venvs, the accepted original wheel and source provenance. Historical PR #56
verification wheels called `0.1.0` were not renamed or published.

| Artifact | SHA-256 |
|---|---|
| `pinwash-0.1.1-py3-none-any.whl` (366298 bytes) | `d002160a73f5affbd4cf3446f676aa2809ef006a12feff77cab5edb4a8c62e03` |
| `pinwash-0.1.1.tar.gz` (354684 bytes) | `e036b1e0a3a7e086bd2f95fa961e5549805e8ed382d33ed983add563c5ae62fa` |
| Wheel rebuilt from the sdist (verification only, 366298 bytes) | `f1b247eff069280495261322a9b11a64450a01c467ada5747acd0fe021fadff4` |

## Acceptance and publication

Both original and sdist-rebuilt installed wheels passed **690 tests each**, with
zero failures, errors, skips, expected failures or unexpected successes and
nested depth 0. Source/resource, metadata, archive/RECORD, CLI identity,
session/report, sentinel and exact container-cleanup checks passed. The corrected
run completed in 197.217 seconds; independent raw-evidence review found no
blockers. The maintainer explicitly approved that single PJU run and conditional
acceptance of its complete results. A preceding adapter preflight failed before
Docker/product execution and remains preserved separately.

The [public receipt](https://github.com/taipei49314/pinwash/releases/download/v0.1.1/ACCEPTANCE.json)
records `HUMAN_AUTHORIZED_LOCAL_DOCKER_NOT_EC_POOL`. This accepts local Docker
Linux package bytes. It does not qualify HOST50 or the EC pool, Windows/macOS,
fresh model live-fire, held-out accuracy or semantic judging. The
[historical acceptance plan](PACKAGE_ACCEPTANCE_0_1_1.md) retains its original
expectations; earlier records still belong to their original sources.

Under the maintainer's release instruction, upload-only
[run 39226974886](https://github.com/taipei49314/pinwash/actions/runs/39226974886)
succeeded on attempt 1 at the exact accepted source. It checked the original
wheel/sdist hashes and uploaded those bytes without rebuilding or running
PinWash. GitHub and PyPI downloads were independently rehashed and match the
two published artifacts above; PyPI metadata reports MIT, Python `>=3.11` and
no runtime dependencies. The existing `pypi` environment was read back with
exact `v0.1.0` and `v0.1.1` tag rules; its publisher tuple was retained.

The frozen tag and package README contain preparation notes written before
publication. This main-branch documentation records current availability;
it does not mutate the accepted tag or artifacts, or authorize another run.
