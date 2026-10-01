# live-fire-rejudge

An EC pool workload that re-judges the published live-fire records in
[`live-fire/`](../../live-fire/) with the judge pinned for each record and
compares the result with what was recorded. It is declared in
`ec-workloads.json` and runs only through an approved EC pool dispatch; it is
not run on the maintainer's work machines.

## Inputs (all in the dispatched commit, nothing fetched)

| File | What it pins |
|---|---|
| `live-fire/**` | The records. The 196 files listed in `live-fire/MANIFEST.json` are checked against it, and the MANIFEST's own sha256 is pinned in `run.py`. `live-fire/README.md` is not listed and is not read. |
| `judges.bundle` | pinwash history up to `7222bfc`, with one ref per judge. `run.py` proves each judge by commit id and by the tree id of its `pinwash/` package, then extracts `pinwash/` only. |
| `expected_worktrees.json` | sha256 of every file in the 91 original cell worktrees. It was hashed from the original evaluation workspace on the maintainer's work machine, by file reads only. It excludes the driver's `_session_output.txt`, `_worktree_diff.txt` and `_committed_diff.txt`, Python caches, `.git/`, and one unreadable file named `nul`. |

| Judge | spec | Used for |
|---|---|---|
| `416b962` | 6 | round 0 (drive time, post-quiescence re-judge); round 1 drive time |
| `86bdcce` | 7 | round 1 spec 7 re-judge. It ran an uncommitted tree that was committed 41 s later as `86bdcce`. `pinwash/` is identical to `9dec332`. |
| `9dec332` | 7 | round 2 |
| `df5eb21` | 8 | round 3 |
| `7222bfc` | 9 | round 4; round 3 spec 9 re-judge |

## Method

1. **Fixture base.** Apply `live-fire/fixture/base.patch` to an empty
   repository and commit it with the fixture's original metadata. The
   commit must come out as exactly `2354c96`.
2. **Cells.** Clone the base for each cell and apply its `change.patch`.
   - Files the patch names keep the patch bytes. Every other file keeps a
     CRLF checkout, as the originals had on a Windows host with
     `core.autocrlf=true`.
   - Every file must match `expected_worktrees.json` byte for byte.
   - In the round 1 first-launch cell, HEAD is `committed.patch` on BASE.
     It is checked by tree id `8e4b6f1`. The commit is rebuilt under a
     neutral identity, so its id differs from `3a0be5f`.
3. **Judging.** In each cell, run `python -m pinwash check` with the ranges
   each record used:
   - round 0: worktree only;
   - round 1 spec 7 re-judge: `2354c96..HEAD` and worktree;
   - all others: the full `<BASE>..HEAD` and worktree.

   Each judge runs with:
   - the judge's `pinwash/` alone on `PYTHONPATH`, and no user site;
   - a neutral git configuration;
   - a pinned `PINWASH_TODAY`, which only matters for `.pinwash/allow.toml`
     and no cell has one;
   - `PYTHONHASHSEED` 1 and then 17, whose raw stdout must be identical.

   No judgment starts later than 50 minutes after the workload starts;
   anything left counts as not run.
4. **Comparison.** Project the output exactly as the producing script did,
   then compare canonical JSON with the published `judge.json` field:

   | Record | Projection |
   |---|---|
   | round 0 drive time | 7-key finding dicts |
   | round 0 official re-judge | `[rule, severity, path, locator]` |
   | rounds 1–4 drive time | 4-key finding dicts plus exit and verdict |
   | round 1 spec 7 re-judge | `[rule, severity, message]` and verdict |
   | round 3 spec 9 | the changed-range rows of `rejudge_spec9.py`, compared with `live-fire/round3/rejudge_spec9.json` |

**PASS** requires all of the following:
- the source, inputs and judges verify;
- all 91 cells rebuild byte-identical;
- every primary record matches (round 0 official, round 1 spec 7, rounds 2,
  3 and 4, round 3 spec 9);
- no judgment differs across hash seeds or times out, and none is left
  unrun at the deadline.

Round 0 and round 1 drive-time records are compared and reported but do not
decide the result: those cells changed after drive time (round 0: late
edits, `live-fire/round0/REPORT.md` process finding 1; round 1: late writes,
`live-fire/round1/REPORT.md` platform finding). The first-launch cell was
never judged; its output
is recorded with nothing to compare against.

## Output

- `result.json`: the source SHA, runtime, every identity and rebuild check,
  every comparison row (with both sides on a mismatch), raw output hashes and
  limitations.
- `SUMMARY.md`: a one-table summary.
- `raw/round<N>/<cell>/<judge>-<range>.stdout`: raw judge output.
