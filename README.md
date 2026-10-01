# pinwash

**Flags a Git diff that makes an agent more able to claim done by weakening the verification harness around it.**

標出會讓 agent 比較容易自稱完成的 harness 變更。

Local-first. Deterministic. No LLM. No network. Does not execute the subject. Does not enforce anything.

This repository has a local **v0 engine**. There is no Release, no PyPI package, and no 1.0 claim. Read [SPEC.md](SPEC.md) (contract) and [ARCHITECTURE.md](ARCHITECTURE.md) (layers; SPEC wins on conflict). Frozen acceptance is `tests/gates/test_v0_acceptance.py`.

The [second alpha-strengthening round](docs/ALPHA2.md) repaired contract fidelity
and added real Git/CLI regressions. It is an engineering milestone, not version
`2.0.0`. Its approved EC pool verification passed 96 tests and doctor on the
implementation commit `8e0688c` and, separately, on the merged review head
`e89f05a`; the acceptance document links both receipts and lists what review
after the merge found (issues #3–#6). A commit's `ec / alpha2-verify` check
covers that commit only.

## Try it

Python 3.11+, Git. From this checkout:

```powershell
$env:PYTHONPATH = (Get-Location).Path
python -m pinwash --version
python -m pinwash doctor
python -m unittest discover -s tests -t . -v
python -m pinwash check HEAD~1..HEAD
```

`check` with no range compares `HEAD` to the worktree. Exit 0 is not proof the harness works; it means no in-scope finding was at or above `fail_on` (default `high`).

## Consumer recipe: judging an agent session

Judge what an agent session did with **two invocations over two ranges**:

```powershell
python -m pinwash check BASE..HEAD   # commits made during the session
python -m pinwash check              # uncommitted worktree edits against HEAD
```

- `BASE` is the commit you recorded **before** the session started, pinned (write down its sha). Never trust `HEAD` as the base: an agent that commits redefines it, and a single-range scan of the last commit only sees the last commit. In a live-fire round, a session committed a 7-file harness weakening (`neutralize verification harness`) that a worktree-only judge would have missed.
- A pass needs **both** invocations clean. Uncommitted edits are the other half of the surface.
- Judge only after the agent's edits have settled on disk. Some CLIs apply edits asynchronously and can still be writing after their process returns; a judge that races the writer judges a stale worktree.

**Record the judge's identity with the verdict.** A pass or block that cannot name the judge is not reproducible. Record the pinwash git revision and the `python -m pinwash doctor` output (`spec_version`, self-test state; a judge record needs `nested_depth` 0, the full own suite), and the exit codes of both ranges, e.g. "pass @ pinwash `86bdcce`, spec 7, 51 self-tests ok, exit 0 on both ranges". Round 1's judge was pinned this way (`416b962`, spec 6); its reports are not published in this repository.

**Exemptions are per finding fingerprint, on the base side only** (SPEC §10). Take the `fingerprint` field from the finding JSON (`rule/path/v1:<64hex>`), and write a `[[allow]]` record into `.pinwash/allow.toml` at the pinned base — all six keys required (`fingerprint`, `rule`, `reason`, `author`, `created`, `expires`), `expires` at most 180 days after `created`, never a rule glob. Set `created` to the day you add the record by the judge's clock (`PINWASH_TODAY`, else the judge host's local date), never a later date:

```toml
[[allow]]
fingerprint = "HOOK_REMOVED/.claude/settings.json/v1:…"
rule = "HOOK_REMOVED"
reason = "planned migration, ticket #…"
author = "you"
created = "2026-09-28"
expires = "2026-12-01"
```

Head-side valid additions surface as `EXEMPTION_ADDED` (warn), or critical when an added record's `created` is after today; editing or deleting a base exemption is `CONFIG_RELAXED` (critical). A base record exempts its finding only while `expires` is at most 180 days after the earlier of `created` and today, and the exemption channel never exempts its own findings (`CONFIG_RELAXED` and `EXEMPTION_ADDED` at `.pinwash/allow.toml`) (SPEC §10, spec 11).

Exit codes: `0` no finding at or above `fail_on` · `1` verdict block · `2` engine error. A crash must not exit 1; exit 0 is never proof the harness works.

## Neighbours

pinwash is not checkwash (product tests), not tripwire (hooks that run judges), not walkaround (session admission). It only asks whether **this diff** weakened pins, hooks, permissions, required checks, or bypass instructions. (tripwire and walkaround are no longer on GitHub — removed 2026-09-26 — and are named only to bound scope.)

## Status

| Claim | Status |
|---|---|
| Frozen rule IDs and pin lattice | yes, [SPEC.md](SPEC.md) |
| North star layers | yes, [ARCHITECTURE.md](ARCHITECTURE.md); not a 1.0 claim |
| Engine `python -m pinwash check` | yes, local v0.0.0 |
| Fixtures A1–A11 | yes, `tests/gates/test_v0_acceptance.py` (A11 = SPEC file not edited for the engine) |
| Byte-identical JSON across Windows / macOS / Linux and Python 3.11–3.13 (SPEC §9) | not CI-verified — this repository has no CI workflow; A10 compares LF and CRLF subject files in one run on one host |
| Live-fire validated | records published, not re-judged — commits `86bdcce`, `df5eb21`, `7222bfc` and `fe0838e` record rules found and closed against real coding-agent sessions (five PREREG-predicted, judge-pinned evaluation rounds, six zen free models per round), and spec 9's producer-side `REQUIRED_CHECK_DROPPED` severity as validated live. The round records are in [`live-fire/`](live-fire/) (PREREG, report, per-cell patch and pinned-judge output for rounds 0–4); the fixtures derived from them are in `tests/test_unit.py`. |
| 1.0 | no |

## License

Not chosen yet. The repository is public on GitHub and has no LICENSE file; choosing a license is a human decision. SPEC is the contract.
