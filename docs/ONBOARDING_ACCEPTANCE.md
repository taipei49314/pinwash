# Onboarding delivery and acceptance

Human scope (2026-10-18 Asia/Taipei):

> 照你建議做，先把安裝套件、白話報告和兩步 session 流程做好。

This branch implements packaging, plain-text/JSON consumer reports and
`session start` / `session review`. It starts from main `1c340e7a`, independently
of draft detector changes #50–52. SPEC, frozen acceptance gates, engine finding
semantics and the approved alpha2 workload entry remain unchanged.

## Merge-review correction awaiting verification

The human requested review and merge of PR53 without publication on2026-10-18.
Read-only review found that a late inspection/read failure in single-diff review,
or a session report-save failure, could discard already collected blocking
findings and raw runs. These failures already exited2; they were not false
passes, but violated the evidence-retention contract.

The correction retains the existing report and adds the late error, preserves
blocking findings with exit2/incomplete, and removes report_path when saving
fails. Three regression tests cover late inspection, failed save and judge-read
failure while keeping an earlier comparison error. Independent static review
found no remaining blocking issue in the correction. SPEC/engine/frozen gates
and the package harness are unchanged.

The earlier621-test accepted result below remains evidence only for ee332f6a;
it does not verify this correction. Revalidation at the corrected source is
pending. NOT_RUN：工作機規則（POLICY work-machine-local），先前單次PJU授權已consumed；本輪僅讀檔審查與修正。

## Acceptance criteria

- A wheel contains the console entry, installed judge, original verification
  tests and contracts; sdist can rebuild the same wheel file contents.
- Installed doctor tests installed code using its own bundled resources, even
  if other distributions have parent-directory SPEC/tests files.
- The start/review path preserves the original baseline across commits and
  checks all three required comparisons from the repository root.
- Existing edits, missing/damaged state, changed judge, timeout and invalid
  output never silently select a new baseline or become a pass.
- An added exemption is held for human review; unknown coverage remains visible.
- Reports preserve raw engine JSON and per-range finding provenance, escape
  terminal controls, and distinguish blocking findings from execution failure.
- Ordinary LF/CRLF checkout differences do not prevent session start.
- Installation and state files are outside the subject; their same-user trust
  limits and the caller's stopped-writer precondition are explicit.

## Verification lanes

`alpha2-verify` is the existing approved source-suite/doctor/determinism lane.
Each dispatch must be recorded by EC at the exact reviewed source SHA.

`package-verify` is a separate lane in `ec-workloads.json`. The human approved
its declaration at `75c92df141fe70bd58294d239f2388c7bbc9ce38` and reviewed
corrections under the unchanged declaration on 2026-10-18 Asia/Taipei. EC task
T-556 records that decision; [EC PR #192](https://github.com/taipei49314/estate-consolidation/pull/192)
provides the required registry admission before execution. It creates only temporary environments, downloads
one hash-verified build backend, builds/installs the artifacts and runs the
installed checks; it performs no publication or host configuration change.

The first source-only run, [39054948949](https://github.com/taipei49314/estate-consolidation/actions/runs/39054948949),
used `75c92df141fe70bd58294d239f2388c7bbc9ce38` on DESKTOP-D127QSP. Its suite and
doctor each reached the existing 300-second timeout, so that attempt failed
without a final test count or doctor payload. Raw JSON equality and source
integrity checks passed on that SHA only. EC T-555 preserves the original
receipt; the timeout is not package acceptance or evidence about a later SHA.

The first installed-package attempt, [39064722278](https://github.com/taipei49314/estate-consolidation/actions/runs/39064722278),
ran source `79564e86ebc05f8bf8f49dfceeb719361f0f5a9b` on DESKTOP-D127QSP after
EC PR #192 merged. Wheel/sdist/rebuild content checks, the first installation,
and real session text/JSON fixtures succeeded. Installed doctor completed with
620 tests, 13 failures, 9 errors and 10 skips (exit 2); this was not a timeout.
The second wheel's installation/doctor was not reached. All artifacts remain
unaccepted. The immutable receipt is EC commit
`51ecae01921e79ec89eb74d05458e90312997080`.

That run exposed a new consumer EOF defect: an apparently interactive stdin can
close before the stopped-writer answer. The consumer now treats EOF as no
attestation, preserves JSON output and exits 2 before accessing session state;
a focused regression test covers this path. The second package run below covers
the correction, without accepting the package as a whole.
The unchanged suite also contains explicit POSIX/Linux-only tests, Windows
symlink privilege errors and older portability failures. The existing doctor
rejects skips, so the original full-suite, zero-skip acceptance cannot succeed
on native Windows as currently specified. No skip has been relabeled as success;
SPEC, frozen gates and the approved workload remain unchanged. A qualified Linux
lane is the human-selected route for full acceptance.

The second installed-package attempt, [39066600076](https://github.com/taipei49314/estate-consolidation/actions/runs/39066600076),
ran `21282b48f240ef06395431f331fcd1a1ab2bce1f` under the same D127 declaration.
Build/rebuild, first installation and session fixtures succeeded again. Doctor
completed 621 tests with 12 failures, 9 errors and 10 skips in 880.916 seconds
(exit 2, not timeout); the earlier consumer EOF failure is absent and the new
regression is included. Overall status remains FAIL. The second installation
was not reached. Receipt commit: `d5492098828dc8aa44636910e6204d5669e7f603`.
Both attempts remain preserved; no additional unchanged Windows rerun is planned.

The human selected Linux full acceptance, then explicitly approved one bounded
PJU local Docker run and conditional acceptance after the work-machine conflict
was explained: "核可本輪 PJU 執行及結果接受". EC T-559 recorded the decision and
the named one-time grant before execution. Both prior HOST50 metadata grants
remain consumed; the second returned INCOMPLETE because the fixed Docker path
was absent. HOST50 is not qualified by the local result.

The approved run at `ee332f6a6858badef36b428bb6655da25808c23c` passed on
2026-10-18. The original wheel and the wheel rebuilt from sdist each installed
in a separate environment and passed the full installed doctor: **621 tests,
0 failures, 0 errors, 0 skips**, nested_depth=0, subject_judged=false. Both
session fixtures completed all three comparisons, preserved text/JSON reports
and did not execute subject code. Package contents, installed resources, SPEC27
and version0.0.0 matched. Source HEAD and cleanliness were checked before and
after the run.

This is **HUMAN_AUTHORIZED_LOCAL_DOCKER_NOT_EC_POOL**, on LAPTOP-01AGNPJU,
Linux/amd64 with Python3.11.16 and Git2.55.0. The fixed existing image ran once
with network disabled and offline hash-pinned setuptools83. Product payload
took 158.402 seconds; preflight through exact-CID cleanup took about508 seconds,
within the approved60-minute total. No retry or product publication occurred.

The operator initially misclassified the cleanup response because Docker's
`error: no such object` text was lowercase. The original report is preserved.
Readback of the same raw remove exit0/exact CID and subsequent inspect
exit1/empty array/exact absence response confirmed completed cleanup; an
independent read-only review verified the hashes and result. No Docker action
was repeated and no acceptance condition was waived.

The human's prior conditional acceptance is satisfied for this exact source and
runtime. EC result evidence is under request
`c2aac623-0cda-457d-ad3c-68d9796f1926` (`result.md`, `acceptance.json`,
`raw-proof.json`, `output-manifest.json`). The original wheel SHA256 is
`d57233f12bc6e31907288b1aa90a82566c0eca5e91d96753e0d9c48705ee147d`.
The evidence update after the run changes documentation only; it does not
claim a separate execution at that later documentation commit.

Pool results and exact source/run links are recorded with the PR. Source-suite
success is not package acceptance, and one Windows result is not a cross-platform
qualification. The package version stays 0.0.0 pending a separate release decision;
source/artifact hashes identify this candidate. No PyPI upload, tag, release or
license decision is included in this change.
