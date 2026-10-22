# Spec 37 session validation — draft, NOT_RUN

This replacement workload migrates 27 fixtures from exact #51 source
`91c9796a0b8fc018362ed08ba7cb3f5478094adf` and adds eight prompt controls and
five environment-composition controls.
The historical `docs/batch2`, `docs/batch3`, and live-fire receipts stay immutable.
The old consumed cleanup grant is not included or loaded. Cleanup is restricted
to this dispatch's newly-created, validated scratch directory.

Baseline is `ea185125565f2ef5b5b023c02039d1b00e40b462`, engine 0.1.1/spec 29.
Candidate stays engine 0.1.1/spec 37 at
`c33d4a2572ba493b2ca0d5631bead2d41d39411c`. This is no release.
The exact commit/package-tree/SPEC hash and literal oracles are frozen in the
manifest, whose digest is pinned in run.py. A new EC declaration/dispatch must
pin the resulting complete harness source SHA.
These are separate identities: product commit, harness source, and fixture oracle.

The full planned inventory is 40 cases × 2 engines × 3 ranges × 2 hash seeds:
480 CLI scans and 240 seed pairs. No sample independence or accuracy claim is
derived from that multiplication. Each engine is exported from exact Git blobs
outside every subject repository and launched through its public `python -m
pinwash check` CLI, with isolated trusted imports. Actual 0.1.1/version and
29-versus-37 SPEC metadata are checked on every result; no hardcoded 0.0.0 remains.
The newly generated `engines.bundle` names exact baseline `ea185125...` at
`refs/remotes/origin/main` and candidate `c33d4a2...` at
`refs/heads/codex/reconcile-candidates-20261022`. Its bytes and ref map are pinned.
It is fetched only into this dispatch's owned scratch engine store, where both
commit/package-tree/SPEC hashes are verified before exact-blob export. A shallow
EC source checkout suffices and the dispatch source itself is never fetched into.

Each expected finding includes message, before, after, locator presence, severity,
path, rule and independent SPEC fingerprint. Counter comparison retains duplicate
occurrences. Envelope/run fields, unique ordered unknown rows, summaries, verdicts,
exits and empty config errors are validated separately. Extra JSON keys, duplicate
keys, missing tuples and duplicate tuples fail closed. Both complete raw output
channels are saved and compared across seeds; wrapper errors never become child
stderr or an invented exit code.

Execution completeness, byte determinism and semantic oracle agreement are three
separate statuses. `public_session_outcome` is independently derived from the
documented consumer precedence on the three observed CLI scans; it is not a claim
that `pinwash session` was invoked. `conservative_acceptance_state` additionally
holds unknown coverage and refuses incomplete sessions. A public pass with an
unknown row is therefore HELD for conservative acceptance.

The prompt controls pair text change with addition/reorder, and pair retained
prompt handlers with command removal, async and a closed environment bypass.
Retained prompts do not prove refusal and cannot lower the latter critical
findings. A holder typed prompt with a command field is modeled as a prompt;
the paired body-control demonstrates the deliberate baseline/candidate parsing
difference. These are detector oracles, not evidence that a host invoked a hook
or that a model effectively refused anything.
The environment composition controls keep, remove, gut or replace a nonbash
command sibling at HEAD. A retained or new resolved refusing sibling leaves a
warning; a removed, gutted or new unresolved sibling leaves a critical bypass.
Existing ordinary findings and unresolved-target rows remain in each exact oracle.

Stop without retry or oracle mutation after execution: any source/fixture drift,
setup failure, timeout or uncertain child cleanup stops launches and retains all
unrun tuples. Any new mismatch fails semantic acceptance and requires a separate
adjudication and freshly pinned run. No historical PASS transfers to current
candidate or future merge sources. A complete match may report acceptance only
for the exact frozen sources, fixtures, runtime and scope.

Validation: NOT_RUN：工作機規則（POLICY work-machine-local），本機只編輯與讀檔；
12 harness tests plus the CLI matrix require a newly recorded EC pool workload.
