# Spec 29 → 37 historical comparison — preregistered, NOT_RUN

This migrates reconstruction and safety checks from exact #52 source
`69dae0b72da8b56e0654ea22f1988b0c637cbbec`. Original `live-fire/**` and
`docs/batch2`/`docs/batch3` evidence remain immutable. Published judge records
are displayed only as provenance. Previous source PASS results and consumed
cleanup authority are not reused.

The independently frozen product comparison is baseline
`ea185125565f2ef5b5b023c02039d1b00e40b462` (0.1.1/spec 29) versus candidate
`c33d4a2572ba493b2ca0d5631bead2d41d39411c` (0.1.1/spec 37). Exact commit,
package-tree and SPEC hashes are in manifest.json and run.py. The complete
harness source must receive its own new EC declaration and exact dispatch SHA.
No release is implied by keeping engine version 0.1.1.

Both product commits are shipped in the freshly generated, hash-pinned
`workloads/candidate_sessions/engines.bundle`. Its baseline ref is
`refs/remotes/origin/main`, candidate ref is
`refs/heads/codex/reconcile-candidates-20261022`. Fetches go only into the new
owned scratch engine store. Neither a shallow dispatch checkout nor the user's
source is mutated to obtain product history. Every exported Git blob is verified
against the frozen package/SPEC identities. Only narrow `validation_common.py`
safety support is imported, with its exact digest pinned; no older runner is
loaded to acquire cleanup authority.

The complete planned matrix stays 91 cells × 2 engines × 3 ranges × 2 seeds =
1,092 public CLI invocations and 546 seed pairs. Ninety formal cells have
HEAD=BASE; those ranges are not independent samples. The first-launch cell stays
observational: its original commit identifier is provenance and only its
reconstructed HEAD tree is asserted. It cannot be promoted to formal by a clean
run. Runtime, generation, parameters, executable versions, reconstructed bytes,
raw stdout, raw stderr, actual exits and every missing tuple remain in receipts.

The formal oracle is an exact **relational** comparison, authored from source,
not an assumption that historical labels are truth. Every finding field,
fingerprint and multiplicity, run metadata, summary, verdict, error list and exit
must agree after the already-validated spec-version field is removed and only
the explicitly listed event-key unknown rows are subtracted from the candidate.
The six formal cells listed in `EVENT_CELLS` permit one exact event-key row in
BASE..WORKTREE and HEAD..WORKTREE, never a finding change. All remaining formal
fields must agree on both seeds. No wildcard visibility exceptions are allowed.
The observed first-launch delta is retained but excluded from formal acceptance.

Source review for 29→37 keeps the historical matrix unchanged: the preserved
patches contain no prompt/agent handler or async/global-hook-env fixture family.
Those semantics are instead covered by the separate 40-case session workload.
Historical agent arm names (`natural`, `bait`, `attack`) are not TP/FP labels;
this comparison makes no false-positive rate or held-out effectiveness claim.

Execution, determinism and semantic status are separate. A process may complete
while its bytes disagree across seeds or its full finding oracle fails. Public
session outcomes use the current consumer's exemption-only hold rule; conservative
acceptance additionally holds unknown coverage and rejects incomplete evidence.
An exactly predicted new visibility row may change conservative PASS to HELD
without silently redefining the public CLI or turning it into semantic failure.

Acceptance requires the full exact tuple and command inventory, all 90 formal
oracles on both seeds, byte-equal raw stdout/stderr/exits within each seed pair,
clean source, unchanged rebuilt subjects/exports and confirmed owned cleanup.
Missing cases, wrong identities, duplicate tuples, malformed output and engine
errors never count as PASS. Setup/identity failures and timeouts stop further
launches; uncertainty retains scratch. A semantic mismatch stops acceptance,
preserves raw evidence and requires explicit adjudication before any newly
pinned rerun. No oracle may be learned from the run it judges.

Validation: NOT_RUN：工作機規則（POLICY work-machine-local），本機僅讀檔、編輯
與 git bundle 版本控制操作；24 harness tests 與完整矩陣須由新 EC pool 工作執行。
