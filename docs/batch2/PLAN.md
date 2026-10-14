# Second execution batch: candidate session integration

Preregistered on 2026-10-14, before execution. Human steering: "繼續", following the accepted complete PinWash/EC plan and first-batch delivery. This is the first part of stage 5 (integration acceptance), not completion of stage 5 or publication.

## Fixed identities and authority

- Candidate product: `a5af21c166b1522a4e0d9d4074ff9bdd299a5ef5` (PR #50, draft), spec 36, engine 0.0.0.
- Candidate `pinwash/` Git tree: `8f3dd1e10dc590d0bc0d3335817d81648b36b4e4`; SPEC SHA-256: `e7728c61d1c1c12331b5d7d58315d9e4e0d60dd47cdaef3260abe6cb131f7581`.
- This batch adds fixtures, a trusted runner and its verification tests. It changes neither the candidate engine nor SPEC, frozen gates, historical records, nor existing workload entries.
- The dispatcher SHA identifies the exact commit containing the runner and manifest; it is separate from the candidate revision whose engine tree and SPEC must still match. A future product merge SHA needs its own evidence.
- EC currently offers native Windows/X64 `profile-ec-integrity` runners only. No Linux pool, runner/profile change or host operation is included.
- The PJU Docker exception from T-531 is consumed. All new execution goes through EC pool after separate human approval of the new declaration. `NOT_RUN: work-machine rule (POLICY work-machine-local), pending declaration approval.`
- First-batch Docker evidence remains technical PASS with human acceptance pending. This batch neither accepts that evidence nor merges PR #50.

## Scope and preregistered predictions

`workloads/candidate_sessions/cases.json` contains 27 literal cases. Each case spells base files, committed changes, settled worktree changes, all three expected rule/severity/path/locator multisets, all unknown rows, exits and session outcome. This is a seeded engineering regression set, not held-out accuracy evidence.

The scan sequence is the README consumer recipe: pinned `BASE..HEAD`, pinned `BASE..WORKTREE`, and plain `check` (`HEAD..WORKTREE`). Each scan runs in two independent processes with seeds 1 and 17. PASS requires all 27 cases and all 162 scans to complete, exact predictions to match, and raw JSON and exit codes to agree between seeds.

Covered interactions:

- Claude ignored flags, Cursor supported flags, direct command holders, command reorder, prompt/agent Stop and global switches.
- Async loss of refusal, live sibling severity, group async negative control, nonboolean async and event-key visibility.
- Exact true shell prefix, a changed CRLF BASH_ENV file, cross-settings PATH visibility and an outside-closed-prefix control.
- Producer pure rekey/move, same-name gutted decoy and dependency reference. Honest moves retain the `head job claims a required context` visibility row; pass does not erase unknown coverage.
- Session exemption planting, a valid exact base exemption, the zero-exit held outcome, renamed/gutted judge, and a required context/producer weakening split between commit and worktree.

The exemption fixture fingerprint is computed independently from the published §7 formula and literal removal identity before execution, never learned from candidate output. Every finding fingerprint is independently checked against the published formula, remains byte-identical between hash seeds, and remains equal across cases/range labels when rule/path/locator/before/after identities are equal. Severity is not a fingerprint input; the two async cases also check this when a live sibling changes critical to warn.

Static source review corrected the retarget locator to `Stop:python hooks/new.py` and retained the producer claimant rows before any run. Since spec 27, both combined and plain scans catch the renamed/gutted fixture, using different detector branches. No historical pass has been relabelled.

## Execution and evidence contract

- New workload: `candidate-sessions`, parameters `{}`, `profile-ec-integrity`, 20-minute outer limit, no cache. Runner command budget 1140 seconds, 60 seconds per child, with cleanup/receipt reserve.
- No dependency install, network, model, subject command, subject workflow, hook host or publication inside the workload. Git commands assemble literal disposable fixtures with empty templates, disabled hooks/signing/fsmonitor/attributes/global config and fixed author dates.
- Trusted candidate CLI uses `python -P -s -X utf8 -B -m pinwash check`, with PYTHONPATH containing only the trusted source and neutral home/config directories. Subject shadow modules and hook bodies contain an execution canary; their presence is not proof of a sandbox boundary.
- Exact source SHA and cleanliness are checked before and after. Candidate engine tree and SPEC hash must match. Every fixture has a nonempty committed and uncommitted session, recorded base/head SHAs, file hashes and status before/after scanning.
- The trusted harness tests run separately before cases, must be nonzero and have no skips/failures/errors. They test malformed output, identity drift, unexpected findings/rows, incomplete recipes, held/block semantics, unsafe paths and timeout launch suppression.
- A child timeout or start/IO failure stops later launches. Owned process-tree termination and drainage reuse the first-batch reviewed cleanup helper; uncertainty remains FAIL/NOT_RUN. EC's outer kill-on-close job remains the final bound.
- Raw stdout/stderr and commands/exits/hashes are retained per child. `cases.json`, `result.json` and `SUMMARY.md` preserve all expected cases, including NOT_RUN cases after an early stop. Expectations are never changed in response to a run without a new preregistered attempt.

## Remaining acceptance work

This runner does not run the complete suite or top-level doctor, replay historical cells with the candidate, probe Claude/Cursor, or provide an OS/Python matrix. Native Windows full-suite failures and the first-batch local Docker acceptance boundary remain visible. Linux/macOS matrix work, candidate historical replay, independent natural/attack samples, EC consumer policy, grammar/reader work and publication require their own concrete delivery and applicable execution approval. No new accuracy, release or merge claim follows from this workload.
