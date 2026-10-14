# Candidate history replay

Offline EC pool comparison of fixed spec27 baseline and spec36 candidate on
preserved live-fire worktrees. See [PLAN](../../docs/batch3/PLAN.md) and
[PREREG](PREREG.md) for the accepted scope and exact difference oracle. This
source is preparatory evidence; no third-batch tests or scans have run.

Manifest SHA-256:
`f82ecf78fdfcca59684819a52f1f7c9112d792d1547df75c8454a759237a58cf`.
It copies saved metadata, patch and worktree hashes, with a source-reviewed
oracle authored before execution. Offline baseline.bundle SHA-256:
`5520b6357e55f4d75a06cccf1a84220a5524971365cf292c3340141271e6065f`
(773597 bytes); its refs/remotes/origin/main points to fixed baseline
`1c340e7a9b105169715d62ea80211394913475e7`.

## Scope and commands

- 90 formal cells: natural 30, attack 24, bait 18, attack-ci 12, bait-ci 6.
- One first-launch observation, excluded from formal semantic acceptance.
- Two engines, three ranges, seeds 1 and 17: 1092 separate judge processes and
  546 raw-JSON/exit seed comparisons. All formal HEADs equal BASE; these
  correlated scans are not independent quality samples.

First run the **24 new harness tests**, requiring zero failures/errors/skips.
Then reconstruct subjects under a fresh `pinwash-candidate-history-*` direct
child of EC_WORKLOAD_WORK, preserving recorded CRLF unchanged files and LF
patched files. Prove BASE commit/tree, each HEAD tree and all worktree bytes.
First-launch uses neutral commit metadata; its original SHA is not reconstructed.

Export both trusted engines from exact Git blobs into separate directories.
The recipe is `python -P -s -X utf8 -B -m pinwash check`, with an explicit
range only for BASE..HEAD and BASE..WORKTREE. Both CLIs already emit JSON;
plain check receives no range flag. PYTHONPATH points only to the selected
engine. Subject Python, hooks, workflows and tests are never executed.

## EC contract

New declaration/exact-source human approval precedes EC registration/dispatch.
Proposed host LAPTOP-8KGL8EFS, profile profile-ec-integrity, parameters `{}`,
cache false, 60-minute outer limit, one attempt. EC_WORKLOAD_PARAMETERS is
the EC job's parameters.json **path**, not JSON text. Source/work/out must
be canonical real disjoint job siblings. Entry verifies actual generation
path/id; EC prepare pins it and outer receipt provides its authoritative proof.

Stop new commands at 50 minutes; each child is capped at 60 seconds and the
remaining budget. Final source reads use the reserve, ending at 59 minutes.
Timeout refuses later judge launches. Unconfirmed owned process termination
retains scratch and fails. Cleanup uses the fixed second-batch ownership,
reparse, hardlink and Windows read-only-file helper only on this run's root;
it never calls old Temp recovery. EC's existing outer workspace management
remains unchanged.

Every planned engine/range/seed has an explicit state, including NOT_RUN.
Started commands retain argv/cwd, stdin hash, environment overrides, timing,
exit/timeout/termination and exact raw logs/hashes. Runtime records actual
Python and Git executable/version, host, parameter bytes and generation.
Final source SHA/status/file readback is real evidence, not a preflight inference.
Each subject and engine export is checked again after judging.

result.json separates execution completeness from formal semantic predictions.
Overall PASS needs both, all scans/equal pairs, unchanged inputs and confirmed
scratch removal/readback. Full two-version payloads and original judge.json
provenance are retained per cell. Unexpected formal differences stay FAIL;
the oracle is never relaxed after results. SUMMARY.md is a compact readout.

No network requests, installs, models, cache, automatic retries, previous-root
recovery or publication. Full suite/doctor, Linux qualification, product
acceptance, OS/Python matrix and independent quality measurement remain separate.

## Validation status

**NOT_RUN: work-machine rule (POLICY work-machine-local); first execution
must use the approved EC pool dispatch.** Source review is not a test PASS.
