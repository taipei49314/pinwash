# Onboarding delivery and acceptance

Human scope (2026-10-18 Asia/Taipei):

> 照你建議做，先把安裝套件、白話報告和兩步 session 流程做好。

This branch implements packaging, plain-text/JSON consumer reports and
`session start` / `session review`. It starts from main `1c340e7a`, independently
of draft detector changes #50–52. SPEC, frozen acceptance gates, engine finding
semantics and the approved alpha2 workload entry remain unchanged.

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
a focused regression test covers this path. This correction needs pool validation.
The unchanged suite also contains explicit POSIX/Linux-only tests, Windows
symlink privilege errors and older portability failures. The existing doctor
rejects skips, so the original full-suite, zero-skip acceptance cannot succeed
on native Windows as currently specified. No skip has been relabeled as success;
SPEC, frozen gates and the approved workload remain unchanged. A qualified Linux
lane or a separately reviewed portability scope is needed for full acceptance.

Local execution: **NOT_RUN：工作機規則（POLICY work-machine-local），本機僅編輯及唯讀審查；產品測試、建置、安裝驗收走已核可 pool 工作負載。**

Pool results and exact source/run links are recorded with the PR. Source-suite
success is not package acceptance, and one Windows result is not a cross-platform
qualification. The package version stays 0.0.0 pending a separate release decision;
source/artifact hashes identify this candidate. No PyPI upload, tag, release or
license decision is included in this change.
