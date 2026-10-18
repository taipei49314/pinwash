# Quickstart, status and priority summary: validation record

Human scope, 2026-10-18: five-minute quickstart, session status and report priority
summary; no release. This work starts after PR #53, from main
`cdefa7d11caeafd31d9bc0cc4e6d17e1445342c2`.

## Implementation

- A fixed-source POSIX quickstart with isolated installation, a removable-hook
  example, the two-step session flow, status and recovery guidance.
- A read-only `session status` command. It locates Git root metadata without
  scanning the worktree, preserves the original baseline and separates saved
  historical review results from current changes. Its JSON schema and exit
  meanings are distinct from review.
- A text-only priority summary: incomplete execution first, blocking changes,
  exemption decisions, configuration errors, coverage gaps and a next action.
  Engine JSON, thresholds, exit codes and exemption semantics are unchanged.

## Fixed-source acceptance completed

The human explicitly approved one bounded run and accepted a complete pass
with cleanup. Source `7851de825545dcfe7ed8f2245be1abf7bac9b20e` passed on
2026-10-18 under EC T-562: **HUMAN_AUTHORIZED_LOCAL_DOCKER_NOT_EC_POOL**.
This is Linux/amd64 acceptance on LAPTOP-01AGNPJU using the fixed existing image
`sha256:a640d42096d21ace335b6029f1c3334146f6c9dc7dec6077cc99f4b99927c5a5`,
Python 3.11.16, Git 2.55.0 and pinned setuptools 83.0.0. It is not EC pool
qualification or acceptance of other platforms.

Both the directly built wheel and the wheel rebuilt from the sdist were
installed separately and ran **645 tests each, zero failures, errors or skips**.
All declared harness checks passed, including source/package byte comparisons,
bundled resources, SPEC 27, version 0.0.0, clean source before/after, session
start/status/review, priority-summary text, and subject code never executing.
After the fixture removed a hook, review correctly blocked; status displayed
that result as historical and current changes as not reviewed. Restoring the
hook then passed against the same baseline without replacing it.

Regression coverage includes missing/changed/damaged state, report selection,
other sessions, links, duplicate keys, invalid timestamps, bounded reads,
malformed reports, no scan/write behavior, CLI routing and summary ordering
without mutating evidence. Real Git cases include status from a subdirectory
and a historical pass followed by a currently blocking change.

Independent read-only source review found and corrected two metadata-display
edges before this tested source: a failed final state read now discards
unconfirmed history, and an unreadable judge is shown as UNKNOWN rather than
CHANGED. Review also separated status/review exit meanings and made demo
preparation stop on failure. Independent post-run evidence review verified
raw stream/input/source/artifact hashes, both suites, fixtures, single
create/start, cleanup and deadlines; no acceptance blocker remained.

The single container exited 0 at `2026-10-18T10:55:57.81056625Z`; exact removal
and absence readback completed by `2026-10-18T10:56:01.741407Z`. Operator error
was null and cleanup complete. The full authorized interval was 196.697 seconds,
within the 60-minute bound. No automatic retry occurred.

## Evidence and artifacts

- [Human approval](https://github.com/taipei49314/estate-consolidation/blob/65f4dcc3de641445c8e2b71737a6a59c090f35b0/evidence/requests/10e92f2d-2a95-42a3-8e0a-6b94d3df2a6f/human-approval.md), decision SHA-256 `2a8abf9188665f392a9c22abd03f2bb5e2228c1f51c0710fde860a6f69ed257f`.
- [Published result and evidence](https://github.com/taipei49314/estate-consolidation/blob/745f0e6f7836768baeee6caad41653a5581c2b09/evidence/requests/2b881d9e-5cf8-4d7e-91a9-5b6fca598ec1/result.md); sibling `acceptance.json`, `raw-proof.json` and `output-manifest.json` preserve the machine evidence. Publication and remote readback were verified.
- The named one-time grant was [marked consumed](https://github.com/taipei49314/estate-consolidation/commit/41458478) after the run. It cannot be reused.

| Artifact | SHA-256 |
|---|---|
| wheel | `e288166de9656f2da67e452e2b8d600d055690213dd898d5c3801c2a896b8ef4` |
| sdist | `58d297d27b78d3ee435e15173eff144a3df08e2f2bcdcbf44594e56b9466f0a4` |
| rebuilt wheel | `ea3cf24035808d1abe9359d4fd4c4774a94c76b345e0b8707be8e9e6d80bf9be` |

The post-validation update changes only this evidence document and the
quickstart's installation pin/acceptance wording. Executable source, tests,
build configuration and harness remain byte-identical to tested `7851de82`.
The installation command now pins that tested source. No new execution is
claimed for the later documentation commit.

No newcomer timing study has been performed; “five-minute” is a walkthrough
target. The fixture commands were exercised by the installed harness; this is
not a timed end-to-end rehearsal of the documented source-install command.
No Windows/macOS acceptance, merge, release, tag or PyPI publication is claimed.
Older failures and PR #53's separate acceptance remain preserved.
