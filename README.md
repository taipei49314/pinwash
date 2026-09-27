# pinwash

**Flags a Git diff that makes an agent more able to claim done by weakening the verification harness around it.**

標出會讓 agent 比較容易自稱完成的 harness 變更。

Local-first. Deterministic. No LLM. No network. Does not execute the subject. Does not enforce anything.

This repository has a local **v0 engine**. There is no Release, no PyPI package, and no 1.0 claim. Read [SPEC.md](SPEC.md) (contract) and [ARCHITECTURE.md](ARCHITECTURE.md) (layers; SPEC wins on conflict). Frozen acceptance is `tests/gates/test_v0_acceptance.py`.

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

**Record the judge's identity with the verdict.** A pass or block that cannot name the judge is not reproducible. Record the pinwash git revision and the `python -m pinwash doctor` output (`spec_version`, self-test state), and the exit codes of both ranges, e.g. "pass @ pinwash `86bdcce`, spec 7, 51 self-tests ok, exit 0 on both ranges". Round 1's reports are reproducible because the judge was pinned this way (`416b962`, spec 6).

**Exemptions are per finding fingerprint, on the base side only** (SPEC §10). Take the `fingerprint` field from the finding JSON (`rule/path/v1:<64hex>`), and write a `[[allow]]` record into `.pinwash/allow.toml` at the pinned base — `reason` and `expires` (≤ 180 days) required, never a rule glob:

```toml
[[allow]]
fingerprint = "HOOK_REMOVED/.claude/settings.json/v1:…"
rule = "HOOK_REMOVED"
reason = "planned migration, ticket #…"
author = "you"
created = "2026-09-28"
expires = "2026-12-01"
```

Head-side valid additions surface as `EXEMPTION_ADDED` (warn); editing or deleting a base exemption is `CONFIG_RELAXED` (critical).

Exit codes: `0` no finding at or above `fail_on` · `1` verdict block · `2` engine error. A crash must not exit 1; exit 0 is never proof the harness works.

## Neighbours

pinwash is not checkwash (product tests), not tripwire (hooks that run judges), not walkaround (session admission). It only asks whether **this diff** weakened pins, hooks, permissions, required checks, or bypass instructions.

## Status

| Claim | Status |
|---|---|
| Frozen rule IDs and pin lattice | yes, [SPEC.md](SPEC.md) |
| North star layers | yes, [ARCHITECTURE.md](ARCHITECTURE.md); not a 1.0 claim |
| Engine `python -m pinwash check` | yes, local v0.0.0 |
| Fixtures A1–A11 | yes, `tests/gates/test_v0_acceptance.py` (A11 = SPEC file not edited for the engine) |
| 1.0 | no |

## License

Not chosen in this commit set. SPEC is the contract; licensing is a human decision before first publication.
