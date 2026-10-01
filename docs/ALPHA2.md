# Alpha round 2

The maintainer requested a second alpha-strengthening round on 2026-09-30.
This is an engineering milestone, not a `2.0.0` release or a 1.0 claim.
The engine remains `0.0.0`, spec 9, findings envelope 1.

## Acceptance

This round repairs fidelity to the existing contract; it does not add rule IDs,
surfaces, or a full YAML parser. `SPEC.md` and `tests/gates/**` remain unchanged.

| Check | Expected evidence |
|---|---|
| Existing UTF-8 instruction/skill becomes unreadable | `SURFACE_UNPARSEABLE` high; both sides unreadable warn; repair/deletion have no invented weakening |
| Last effective Stop-like hook is disabled or made fail-open | `HOOK_BYPASSED` critical; another effective sibling keeps the last-hook escalation from firing |
| Unsupported multiline workflow `if` | `unknown_coverage`; not a silent observation of a live job |
| Worktree and two-dot/three-dot ranges | Real Git and CLI checks cover modified, untracked and deleted surfaces, and merge-base semantics |
| Unicode/whitespace paths | Git tree/worktree loader preserves names; scanner sees the intended surface |
| Exemptions | Actual finding fingerprint is trusted only at base; expiration boundary is explicit and replayable |
| Resolved hook bodies | Real Git/CLI test sees a body weakened while the command stays unchanged |
| Doctor | Missing/empty/skipped own tests cannot pass; a full invocation reports a nonzero successful own-test count and a skipped count |
| Regression preservation | Full stdlib suite, including the unchanged frozen gates, passes without skips |
| Evidence | Exact candidate SHA, runtime, commands, exits, test counts, raw logs and hashes |

## Pool verification

`ec-workloads.json` declares `alpha2-verify`. Its entry point is
`workloads/alpha2_verify/run.py`. It uses the existing `profile-ec-integrity`
Python/Git generation, no cache, no dependency installation, no network request,
and a 20-minute limit. It executes pinwash's own tests and a same-tree scan;
it never executes a third-party subject.

EC must approve the exact canonical declaration entry, register pinwash in its
workload App and registry, and dispatch an exact candidate SHA. The workload
returns a failing exit if the suite is empty/failing/skipped, doctor did not run
the same suite, the source SHA changed, or independent process JSON differs.
`result.json`, `SUMMARY.md` and per-command stdout/stderr are collected in the
EC receipt ref. A prepared entry is not evidence that verification ran.

## Status and boundaries

The approved workload first passed on implementation commit
`8e0688c48467168a03439bcf8e2f1c98d8b76e80` in
[EC run 36689530277](https://github.com/taipei49314/estate-consolidation/actions/runs/36689530277).
The [immutable result receipt](https://github.com/taipei49314/estate-consolidation/blob/8fcd7cc95c7c38c103aae1eab1e9ea948bd1e5ee/result.json)
records 96 successful suite tests with no skips, doctor independently running
the same 96 tests with zero failures/errors/skips, equal raw JSON across seeds
1 and 17, and unchanged clean source before and after validation. All eight
command steps exited 0 without timeout. The runtime was Python 3.12.10 on the
EC Windows pool (`DESKTOP-D127QSP-workload`, generation `8b1bcfb4b5dc0588.1`).

The implementation remains a reviewable [PR #2](https://github.com/taipei49314/pinwash/pull/2).
For the current review head, inspect its `ec / alpha2-verify` check and linked
receipt; the initial result above applies only to its named commit. Documentation
updates do not turn an earlier commit's check into a current-head check.

The raw JSON check is a same-tree replay on one Windows/Python runtime. The suite
contains seeded regression cases, not an independently held-out attack corpus.
Cross-OS/Python determinism, new agent evaluation rounds, packaging, a license
decision, PyPI publishing and a tagged release remain outside this round.
The existing `THREATMODEL.md` residuals stay open. A consumer must inspect
`unknown_coverage`; exit 0 alone does not establish that the harness works.
