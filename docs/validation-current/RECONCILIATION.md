# PR #50–52 reconciliation — SPEC37

Status: semantic reconciliation found an additional public-evidence defect in the first session matrix. Its source-reviewed repair is awaiting a new exact-source pool run; the original session result and complete-suite/doctor acceptance remain **FAIL**. Historical replay is still executing at the exact source below. This document does not transfer an older PASS or authorize a product merge/release.

The maintainer asked on 2026-10-22 to take over PinWash, reconcile PR #50–52, consult the Checkwash family first, and delegated planning, implementation and testing decisions. Baseline is main `ea185125565f2ef5b5b023c02039d1b00e40b462`, package 0.1.1 / SPEC29. The published 0.1.1 remains `fdb3c4d753d637e89aba5a22372d61dc2c292939`; no tag or published artifact changes.

## Reconciliation decisions

| Draft family | Current disposition |
|---|---|
| old spec28 ignored Claude skip keys | Keep main spec29; do not reapply obsolete tests or skip behavior. |
| old spec29 direct command holders | Port the bounded direct-item rule across extraction, target resolution, selectors and liveness. |
| old spec30 prompt/agent credit | Preserve main spec28: model invocation/type continuity is not refusal capability. Handler additions/reorders stay silent; Counter subtraction detects lost/changed instances. |
| old spec31 async | Active execution remains observable; direct Stop async is not synchronous refusal. |
| old spec32 environment | Closed own-file bypasses plus explicit visibility; no invented cross-file precedence. Severity uses affected base and unaffected head commands, never prompt/agent credit or a removed base sibling. |
| old spec33 event keys | Visibility only; no host-schema validity claim. |
| old spec34/35 producer identity | Only exact-document, unambiguous, context-independent rekey/move forms; dynamic/reference bounds retained. |
| old spec36 global switch | Preserve main's newer command/handler separation. |

The new combined contract is SPEC37. The old draft numbering collided with released spec28–29, so it is not reused. Current main's committer-date hardening, consumer/session contract, package resources and frozen `tests/gates/**` remain. The earlier alpha2 runner cleanup change was initially excluded from the semantic port. The first actual timeout below now justifies a separately reviewed, bounded runner repair; it does not alter product semantics or the frozen gates. Historical batch documents/receipts retain their original source and meaning.

## Checkwash family lessons applied

- Checkwash expected-provenance (`47c741729889df37515e791e76e1bf8b964f29e6`): visibility and identity do not confer equivalence/refusal credit. Its D171 decision also distinguishes predefined counterexamples from unadjudicated labels; this work makes no generic claim that UNKNOWN must block the product.
- Checkwash-lab: completed shards/exit zero can coexist with semantic STOP. Validate the whole `(case, engine, range, seed)` matrix, source identity and exact outcomes independently.
- Checkwash-corpus (`86ffe1560d72356f6e59a032d1c84c061753c06a`): add explicit paired controls before running; prompt arms and historical operator intent are not ground truth.
- SmallestLie (`41da53a4d3483a41e50dfe595a55b17f26f106d7`): archived plans and unexecuted contracts are references, not successful execution evidence. Keep this workload bounded.

## Validation contract

1. `alpha2-verify`: complete source suite and doctor at an exact dispatch SHA, nonzero equal counts, no failures/skips, source clean before/after, raw seed comparison. Existing declaration remains unchanged.
2. `candidate-sessions`: baseline and candidate public CLI over the retained 27 cases plus paired controls; full finding fields/fingerprints/multiplicity, exact envelope metadata, all ranges and seeds, raw stdout/stderr/exit determinism. Literal source-authored oracles are frozen before any run. Derived public consumer status is separate from conservative validation acceptance.
3. `candidate-history-replay`: immutable historical fixture bytes; formal committed HEAD equals BASE, so committed ranges must be empty. First-launch observation remains outside formal claims. Operator intent is not a true label; compatibility and source changes are not precision/recall evidence.

EC task T-586 records only Windows execution/registration and necessary same-scope repairs. Original human instruction: `estate-consolidation/evidence/requests/d47edc51-f114-4888-b8e2-9ba0e52e9b25/human-instruction.md`. No work-machine product execution, old Temp recovery, subject execution, models, Linux/Docker admission or release. A failed oracle or process stays failed in its original receipt; repair needs a new source pin and separately recorded run.

Linux candidate status: **NOT_RUN**. HOST50 qualification completed under T-576 on 2026-10-20, but the PinWash package contract remains SPEC29/690 tests and has no SPEC37 admission. This work does not weaken that contract or relabel historical acceptance.

## Exact-source results

The first `alpha2-verify` [run 39738429809/1](https://github.com/taipei49314/estate-consolidation/actions/runs/39738429809) at source `c33d4a2572ba493b2ca0d5631bead2d41d39411c` failed: suite and doctor each exceeded the existing 300-second command limit. [Immutable result](https://github.com/taipei49314/estate-consolidation/blob/bf74e8ab615e94bddac8ed6251c5a83370cc8de5/result.json) retains both timeouts. `tests_run: 0` means no completed unittest summary, not no tests attempted. Twelve individual gate rows completed before the nested doctor gate. Exact source and clean checkout checks passed before/after; the two same-tree CLI outputs matched. These narrow observations are not complete-suite or doctor acceptance. The runner receipt does not prove descendant/temporary-directory closure.

The repair retains the existing 20-minute declaration and complete product test discovery. It provides a shared command deadline, bounded owned-process cleanup, a new dispatch-owned temporary root, and supplementary runner tests outside the packaged product tests. The suite sets nesting depth 1 to avoid a redundant third traversal; the separate public doctor must still run at depth 0. Product code/SPEC identities remain unchanged. Its actual outcomes follow; Linux remains NOT_RUN.

The repaired [run 39742729812/1](https://github.com/taipei49314/estate-consolidation/actions/runs/39742729812) at `7fccf657b20d0eb134c67f5ee776bb8e5af44c3d` completed on QL: 18 supplementary runner tests passed; suite and public depth-0 doctor each completed 731 tests, with 13 failures / 11 errors / 10 skips. Neither timed out. The same-tree outputs matched, source remained clean, and the new owned temporary root was removed. [Immutable result](https://github.com/taipei49314/estate-consolidation/blob/05056f09f08abb9401ca3abeb59becd4ea1243f2/result.json) remains **FAIL**, not product acceptance. Cleanup confirmation covers the runner's stated parent/pipe/timeout-subtree scope, not a native EC Job census.

Source-based adjudication found one outdated non-gate expectation in this port: removing `PreToolUse` while retaining an unresolved Stop must add the exact event-key visibility row under §5.1.1, although it adds no Stop-liveness row. The corrected test keeps the exact `HOOK_REMOVED/warn` finding and unchanged-tree empty control; no row is filtered.

The corrected source `d79d7ce2864107f2a080a22e2874d5f4b3435793` completed [run 39749321815/1](https://github.com/taipei49314/estate-consolidation/actions/runs/39749321815) on QL, generation `3e59f897a0b36308.1`, Windows 11 build 26200/Python 3.12.10. Eighteen supplementary runner tests passed. The suite and public depth-0 doctor each completed 731 tests with **12 failures, 11 errors and 10 skips**, without timeout; the corrected named event-key test explicitly logged `ok`. [Immutable receipt](https://github.com/taipei49314/estate-consolidation/tree/3eaccc1295e9b2cb4b6612b147f877b529c67c03) remains **FAIL**. Independent raw-byte review matched all 22 published files' SHA-256/length and all 18 step-channel hashes. Source stayed clean, raw same-tree outputs matched and the new owned temporary root was removed within the runner's stated parent/pipe/timeout-subtree scope.

The remaining failure families are eight session stderr CRLF cases, one fixture-byte CRLF case, an extreme negative-date discrepancy, an alternate-store diagnostic mismatch and the consequent doctor gate refusal. Ten symlink privilege errors and one readonly-object unlink error remain; ten existing platform skips are retained. These sites were unchanged by SPEC37, but ancestry is not proof of harmlessness or an earlier Windows PASS. The date discrepancy can affect the three-dot merge-base traversal's input ordering; no wrong baseline or verdict has yet been reproduced, and two-dot/worktree matrices cannot clear that risk. Alternate-store fixture reachability is also unproven. No host privileges, skips or frozen gates were changed.

## Preregistered matrix execution

EC [PR #222](https://github.com/taipei49314/estate-consolidation/pull/222) admitted only the two declaration hashes and original authority pointers. Exact-head [CI 39764785348/1](https://github.com/taipei49314/estate-consolidation/actions/runs/39764785348) passed all steps on QL: 2057 tests, two existing skips, 33m54s. Ordinary `ec_pr` verified no base drift and squash-merged `e57f4398c6db5660c0ee991769647fb3a63b63e0`. The contract, four merge receipts and matrix intent were then published and read back at EC `f1de9b5760e9274e1c0010bdce91b427e19637a1`, request `2d6fa040-55ab-4421-bdb2-2236dbf42fca`.

| Matrix | Exact harness source | Run / host | Current state |
|---|---|---|---|
| Sessions: 40 cases / 480 scans / 240 seed pairs; 12 harness tests | `9649dd1023fcd855b63e6e94e66cafe57839e93a` | [39770052764/1](https://github.com/taipei49314/estate-consolidation/actions/runs/39770052764), 8K | Execution COMPLETE; determinism PASS; semantic FAIL: 448 matches, 32 mismatches |
| History: 90 formal cases plus one observation / 1092 scans / 546 seed pairs; 24 harness tests | `35731936613db014eaa499a6c85f42e778528a98` | [39770077208/1](https://github.com/taipei49314/estate-consolidation/actions/runs/39770077208), D127 | IN_PROGRESS; receipt/semantic acceptance pending |

Each was dispatched once against that same EC source. The harness commits include the alpha2 runner/test repair but still compare baseline `ea185125565f2ef5b5b023c02039d1b00e40b462` with semantic engine `c33d4a2572ba493b2ca0d5631bead2d41d39411c`; later documentation is not a claim that a new head was executed. Literal session oracles and complete relational history oracles were frozen before these runs. History's first-launch observation never becomes a formal gold label. Public consumer states are projections of the executed scans, not independently executed session commands or native host hooks. Matrix results cannot replace complete-suite/doctor or SPEC37 Linux acceptance.

Session [immutable receipt `ce0ffafe`](https://github.com/taipei49314/estate-consolidation/tree/ce0ffafecda2f04bdee21b983b146b1c255caccf) completed with failure on 2026-10-22. Independent publication review matched all 1,935 files and 1,930 step channels. All 480 unique scans and 240 raw seed pairs completed; 12 harness tests passed. There were no timeout/wrapper errors, and the dispatch-owned scratch was recorded REMOVED, without a whole-host cleanup claim. Host wall-clock prepared_at preceded GitHub created_at by 42 seconds; those clocks are not treated as synchronized. The monotonic workload duration was 473.485 seconds.

The 32 mismatches are eight candidate env cases over two worktree ranges and two seeds. SPEC37 §5.1.1 requires canonical JSON before/after evidence, but `hook_env` printed `canonical_text`'s internal equality tokens (`s4:true`, `s20:hooks/environment.sh`), changing the derived public fingerprints. The independently authored literal oracles are correct and remain unchanged. Every other finding field, severity, exit and unknown row matched in those cases; that narrow observation does not turn this failed run into acceptance.

The repair changes only env evidence serialization. It retains missing-before empty text, exact trigger/visibility/severity logic, equality comparisons and the fingerprint formula. An iterative env-only serializer preserves the parser's existing depth, large exact integers, surrogate and nonfinite scalar behavior; blindly using recursive `json.dumps` could otherwise introduce new failures for a nonstring BASH_ENV base. Regression assertions bind quoted evidence and original literal fingerprints, with separate raw-input parser-boundary controls. A new candidate/package identity, engine bundle and both matrix pins are required, with separate pool runs after the explicitly agreed EC main write gap. Original receipts, failures and expectations remain immutable.
