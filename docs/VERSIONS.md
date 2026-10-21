# Release and source versions

As of 2026-10-19, the current published package is **0.1.1 / SPEC 29**.
Record the exact source, spec version and artifact hash with a result; the
version or filename alone does not identify accepted bytes.

| Track | Package version | Spec | Exact source | Publication |
|---|---|---|---|---|
| Current GitHub/PyPI release | `0.1.1` (Alpha, MIT) | 29 | `fdb3c4d753d637e89aba5a22372d61dc2c292939`, annotated tag `v0.1.1`; merged in PR #58 | Published 2026-10-19 |
| Historical GitHub/PyPI release | `0.1.0` (Alpha, MIT) | 27 | `f8669ad86ac71b0e85e29307b471e699df5eb265`, annotated tag `v0.1.0` | Published 2026-10-18 |
| Historical PR #56 verification | `0.1.0` | 29 | Tested head `44e70b835fdf2895617a1b280773a03be0e150a6`; merged as `cc99b33f5b090955b8b3b1e236cae5c899e3c1f5` | Verification only; never uploaded |

Sources: [0.1.1 release](https://github.com/taipei49314/pinwash/releases/tag/v0.1.1),
[PyPI 0.1.1](https://pypi.org/project/pinwash/0.1.1/),
[PR #56](https://github.com/taipei49314/pinwash/pull/56),
[PR #58](https://github.com/taipei49314/pinwash/pull/58),
and the [release notes](RELEASE_0_1_1.md). The accepted source contains the
preparation documents as they stood before publication. This main-branch
documentation update records the completed release; it does not change the
tag, package bytes or acceptance identity.

## What users get

`pipx install pinwash==0.1.1` installs SPEC 29, including PR #56's fixes for
command-free hook events and Claude Code's ignored hook skip keys. The older
`pinwash==0.1.0` installs SPEC 27. Issues
[#42](https://github.com/taipei49314/pinwash/issues/42) and
[#45](https://github.com/taipei49314/pinwash/issues/45) retain unresolved parts;
the release does not close all of their residuals.

The current published files have these SHA-256 values, independently read back
from both GitHub and PyPI:

| File | Bytes | SHA-256 |
|---|---|---|
| `pinwash-0.1.1-py3-none-any.whl` | 366298 | `d002160a73f5affbd4cf3446f676aa2809ef006a12feff77cab5edb4a8c62e03` |
| `pinwash-0.1.1.tar.gz` | 354684 | `e036b1e0a3a7e086bd2f95fa961e5549805e8ed382d33ed983add563c5ae62fa` |

The [public acceptance receipt](https://github.com/taipei49314/pinwash/releases/download/v0.1.1/ACCEPTANCE.json)
also records the verification-only rebuilt wheel hash. That wheel was not
uploaded to PyPI. Historical 0.1.0 hashes and receipts remain on its
[release page](https://github.com/taipei49314/pinwash/releases/tag/v0.1.0).

## What was accepted

- **Release source `fdb3c4d`:** the original and sdist-rebuilt installed wheels
  each passed **690 tests**, with zero failures, errors, skips, expected failures
  or unexpected successes and nested depth 0. Exact source, resources, metadata,
  archives, RECORD, session/report, sentinel and cleanup checks passed. The
  explicitly approved corrected run took 197.217 seconds. Independent raw-evidence
  review found no blockers, satisfying the maintainer's conditional acceptance.
  The earlier adapter preflight failed before Docker/product execution and is
  preserved separately. Upload
  [39226974886](https://github.com/taipei49314/pinwash/actions/runs/39226974886)
  succeeded on attempt 1 at the accepted source; the public downloads match.
- **Historical release source `f8669ad`:** both installed wheels passed 645 tests
  with zero failures, errors or skips, plus package/session checks and cleanup.
  Upload [39124728317](https://github.com/taipei49314/pinwash/actions/runs/39124728317)
  succeeded; its original wheel and sdist were published.
- **Historical PR #56 head `44e70b8`:** both installed wheels passed 690 tests,
  with zero failures, errors, skips, expected failures or unexpected successes,
  plus package/session checks and cleanup. Its
  [acceptance record](https://github.com/taipei49314/pinwash/pull/56#issuecomment-6252130711)
  covers different `0.1.0` verification artifacts that were never uploaded.

These records are explicitly accepted local Docker Linux verification,
`HUMAN_AUTHORIZED_LOCAL_DOCKER_NOT_EC_POOL`. They do not establish HOST50 or EC
pool qualification, Windows/macOS acceptance, fresh live-fire, held-out accuracy
or 1.0 stability. Each record covers only its exact source and artifacts.
No product tests or builds were run for this subsequent documentation update.

## Historical text in the frozen SPEC

The released [SPEC](../SPEC.md) header still says engine `0.0.0`, not a Release
and not on PyPI; its §7 envelope example also uses `0.0.0`. Those publication
descriptions are historical. The current package facts are recorded above.
SPEC remains authoritative for rules, surfaces, severity, fingerprints, exit
codes and determinism.

The SPEC preamble requires a spec-version bump and fixture re-run for any edit
to that file. This documentation update leaves its bytes and version 29
unchanged. Correcting the historical descriptions inside SPEC belongs in a
separately validated spec change.

## Other work remains separate

### Completed engineering account — 2026-10-22

The [T-572 task account](https://github.com/taipei49314/estate-consolidation/blob/36811450e87fcc9e3f9c4db0381b5b97e4c1873f/governance/tasks/T-572.json)
is DONE for its bounded EC Linux package-lane engineering repair. It does not
mean the lane is activated or that its native product package acceptance is
complete. The old guidance delivery's PR #54 is also merged and T-562 is DONE;
see [GUIDANCE_ACCEPTANCE.md](GUIDANCE_ACCEPTANCE.md).

The release and those completed engineering accounts can leave the pending
list. Issues #42/#45, draft PRs #50–52 and outstanding live/native acceptance
retain their existing status. This documentation reconciliation runs no
product, changes no frozen SPEC or published bytes, and grants no dispatch.

Drafts [#50](https://github.com/taipei49314/pinwash/pull/50),
[#51](https://github.com/taipei49314/pinwash/pull/51) and
[#52](https://github.com/taipei49314/pinwash/pull/52) retain an older SPEC 28–36
stack. Their numbering overlaps the merged specs 28–29 and their evidence
belongs to their original SHAs. They are outside this release. Reconnecting
that stack requires resolving the overlap and reviewing the remaining changes.

The [release procedure](RELEASE.md) records completed uploads. The publisher
workflow is fixed to exact tag `v0.1.1`; its environment was read back with
exact `v0.1.0` and `v0.1.1` tag rules. This page authorizes no retry, upload or
publisher-scope change. Repair and acceptance of the Linux package EC pool
lane remain separate from the local package acceptance above.
