# PR #50–52 reconciliation — SPEC37

Status: implementation/review; current validation NOT_RUN until the exact-source EC receipts below are recorded. This document does not transfer an older PASS.

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

The new combined contract is SPEC37. The old draft numbering collided with released spec28–29, so it is not reused. Current main's committer-date hardening, consumer/session contract, package resources and frozen `tests/gates/**` remain. The earlier alpha2 runner cleanup change is unrelated to these semantics and is not carried into this reconciliation. Historical batch documents/receipts retain their original source and meaning.

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

Pending source freeze and EC dispatch. Until receipts are linked here, all current candidate runtime claims are NOT_RUN.
