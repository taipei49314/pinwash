# pinwash

**Flags a Git diff that makes an agent more able to claim done by weakening the verification harness around it.**

標出會讓 agent 比較容易自稱完成的 harness 變更。

Local-first. Deterministic. No LLM. No network. Does not execute the subject. Does not enforce anything.

This repository has a local **v0 engine**. There is no Release, no PyPI package, and no 1.0 claim. Read [SPEC.md](SPEC.md) (contract) and [ARCHITECTURE.md](ARCHITECTURE.md) (layers; SPEC wins on conflict). Frozen acceptance is `tests/gates/test_v0_acceptance.py`.

**New here? Follow the [five-minute quickstart](docs/QUICKSTART.md): install an
isolated candidate, try a small example, then use the same two steps in your
project.** Installation needs Python 3.11+, Git and download access. The guide
also explains status, exit codes and recovery. The time is a walkthrough target,
not a measured first-user success claim.

## Install

Requires Python 3.11+ and Git. This is a **source installation candidate**;
there is no published PyPI package or release yet. Install a reviewed checkout
outside the project your agent will edit, using [pipx](https://pipx.pypa.io/)
to keep the application in its own environment:

```text
pipx install /absolute/path/to/trusted/pinwash-checkout
```

On Windows, use the full Windows path instead. An accepted wheel can be installed
the same way (`pipx install /path/to/pinwash-0.0.0-py3-none-any.whl`). Source
installation downloads the pinned build backend; installed scans use no network
and have no runtime dependencies. See [installation and packaging](docs/INSTALL.md)
for a venv alternative and the separate package acceptance procedure.

## Review an AI coding session

In your project's **clean worktree**, before the agent starts:

```text
pinwash session start
```

Use your coding tool normally. Once the agent **and all processes it started**
have stopped modifying files:

```text
pinwash session review
```

Answer the stopped-writers question. PinWash saves the original baseline and
judge identity, performs all three comparisons described below, explains the
findings, and saves a JSON report outside the project. It does not terminate
processes or independently verify that they stopped. A trusted non-interactive
controller supplies `--stopped` only after ensuring that condition itself.

Each finding explains **what changed, why it matters, and what to review next**.
The report begins with a **priority summary**: unfinished checks, blocking
changes, exemption decisions, and configuration/coverage gaps. Full findings
and original JSON remain available. No findings
does not prove that verification runs or that the product works.

```text
pinwash session status
pinwash session review --json --stopped
pinwash review HEAD~1..HEAD
```

`session status` reads the saved baseline, judge match and last saved report.
It does not scan current changes, reset the baseline or approve a historical
pass. Use the same `--state-dir` on start, status and review if you chose one.

`review` explains a single diff; without a range it compares HEAD to the worktree.
It is not a whole-session review. `check` retains its original JSON output and
exit codes for existing integrations. `review` and `session review` use exit `0` for
no blocking finding, `1` for a block, `2` for an unfinished review, and `3` for
an exemption awaiting human review. Coverage gaps remain visible even on exit 0.
`session status` exit `0` only means metadata was read successfully, including
when no session exists or the historical review blocked; exit `2` needs attention.

Starting never overwrites an existing session by default. After reviewing the
previous work and choosing the next committed baseline, use
`pinwash session start --replace`. Previous baseline records and reports remain.
For details and common errors, see [the session guide](docs/SESSIONS.md).

**Trust boundary:** keep both PinWash and its state outside the agent's writable
scope. State is local convenience data, not signed evidence; placing it outside
the repository does not protect it from an unrestricted process using your account.
Run the consumer from your trusted terminal/controller, not from the agent being
judged. Keep the subject out of `PYTHONPATH` and other Python startup customization.
The consumer's isolated child judge prevents implicit repository-module shadowing;
the initial launcher environment must still be trusted. It does not sandbox the agent.

## Advanced: direct scanner and self-check

`pinwash doctor` runs the full bundled self-test suite against the installed code;
it can take several minutes and does not judge your project. It is deliberately
separate from the two-step session flow. Source contributors can still run the
suite from a trusted checkout with `python -m unittest discover -s tests -t . -v`.

`check` with no range compares `HEAD` to the worktree. Exit 0 is not proof the harness works; it means no in-scope finding was at or above `fail_on` (default `high`).

## Consumer recipe: judging an agent session

Judge what an agent session did with **three invocations**, after every process the session started has stopped:

```powershell
python -P -m pinwash check BASE..HEAD       # what the session committed, against the pinned base
python -P -m pinwash check BASE..WORKTREE   # everything it left on disk, against the pinned base
python -P -m pinwash check                  # its uncommitted edits against its own last commit
```

- `BASE` is the commit you recorded **before** the session started, pinned (write down its sha, and pass the full sha, not a branch or tag: the repository's refs, like the rest of its `.git`, are the agent's to write). Never trust `HEAD` as the base: an agent that commits redefines it, and a single-range scan of the last commit only sees the last commit. In a live-fire round, a session committed a 7-file harness weakening (`neutralize verification harness`) that a worktree-only judge would have missed.
- The first two read `.pinwash/allow.toml`, required contexts and hook bodies from `BASE` (SPEC §2). Plain `check` reads them from `HEAD`, which the session moves: a session that commits an exemption record and leaves the weakening uncommitted passes plain `check` (THREATMODEL R18), and so does one that drops a required context in a commit and deletes its job uncommitted. Plain `check` stays because it compares the worktree with the session's own commits, so a judge renamed in a commit and gutted on disk into a body that is no stub but can no longer block shows there and nowhere else (a stub body, such as `exit 0`, shows in `BASE..WORKTREE` too).
- **Pass** means all three invocations exited 0 within your timeout, each printed JSON that parses, and none reports `EXEMPTION_ADDED`. **Held** is the same, except that at least one reports `EXEMPTION_ADDED`: the session wrote an exemption record, and only a human review of each added record releases it, because once a commit holding it becomes a pinned base or is merged it drops the finding it names until it expires (THREATMODEL R18). **Block** is any exit 1. Anything else (an exit 2, a run killed or timed out, no output or output that does not parse) means the session was **not judged**, never a pass. `unknown_coverage` rows are not part of pass or held; a gate on them is your own policy, and it will flag more than weakenings: in the two worktree invocations a host-written `.claude/settings.local.json` that an ignore rule matches (GitHub's Agents.gitignore has `.claude/*.local.json`) is a row in every session that has one, and so is each ignored hook log or dependency directory under `.claude/hooks/`; a file a hook writes there that is not UTF-8 and not ignored, such as a Python `__pycache__/*.pyc`, is a row of its own (SPEC §7).
- This recipe replaced a two-invocation one (`BASE..HEAD` and plain `check`), and it judges some sessions differently: one that commits a valid exemption record is held where it passed, and a weakening split between a commit and the uncommitted worktree through a state neither old invocation read blocks where it passed: for example, an exemption record committed with the weakening left uncommitted, a required context dropped in a commit with its job deleted uncommitted, or an MCP server added `disabled: true` in a commit and enabled uncommitted.
- The next session's `BASE` is the `HEAD` this judge saw, or a commit a human chose. It is never a branch or tag in the session's repository that the judged `HEAD` does not contain: the session could have moved it.
- The worktree is read while the judge runs. A process the session left running can change files between or during the invocations (a session that swapped the genuine settings back in while `check` ran passed all three), so stop every process it started before judging.
- **Run the judge with `-P`** (Python 3.11+; `PYTHONSAFEPATH=1` does the same, and so does an installed `pinwash` script). `check` judges the directory it runs in, which the agent wrote. Without `-P`, `python -m` puts that directory first on `sys.path`, so an `importlib.py`, another standard-library name or a `pinwash/` package the agent left there runs in place of the judge, before any pinwash code, and can print any verdict. pinwash cannot guard against that itself; only the invocation can. The same goes for `doctor`. `-P` drops only the implicit current directory: if `PYTHONPATH` names the judged repository (as the "Try it" block above does, which judges this checkout itself), the agent's `pinwash/` package is imported instead of the judge. When judging another repository, run the installed `pinwash` script, or set `PYTHONPATH` to the pinwash checkout only.
- Judge a clone that has the objects the run reads. A shallow or partial clone (`--depth`, `--filter`, `scalar clone`) that lacks one is exit 2, `git object <sha> is not in the object store`, never a pass and never a fetch; fetch it, or for `BASE...HEAD` compute the merge base yourself and pass `MB..HEAD`.
- Judge only after the agent's edits have settled on disk. Some CLIs apply edits asynchronously and can still be writing after their process returns; a judge that races the writer judges a stale worktree.

**Record the judge's identity with the verdict.** A pass or block that cannot name the judge is not reproducible. Record the pinwash git revision and the `python -P -m pinwash doctor` output (`spec_version`, self-test state; a judge record needs `nested_depth` 0, the full own suite), and the exit code of each invocation. A historical example, from spec 7, when the recipe had two invocations: "pass @ pinwash `86bdcce`, spec 7, 51 self-tests ok, exit 0 on both ranges"; the spec version and test count move with the revision, so record what `doctor` prints for yours. Round 1's judge was pinned this way (`416b962`, spec 6); its reports are not published in this repository.

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

The [second alpha-strengthening round](docs/ALPHA2.md) repaired contract fidelity
and added real Git/CLI regressions. It is an engineering milestone, not version
`2.0.0`. Its approved EC pool verification passed 96 tests and doctor on the
implementation commit `8e0688c` and, separately, on the merged review head
`e89f05a`; the acceptance document links both receipts and lists what review
after the merge found (issues #3–#6). A commit's `ec / alpha2-verify` check
covers that commit only. New onboarding guidance has its own
[validation record](docs/GUIDANCE_ACCEPTANCE.md); earlier results do not validate
new code.

| Claim | Status |
|---|---|
| Frozen rule IDs and pin lattice | yes, [SPEC.md](SPEC.md) |
| North star layers | yes, [ARCHITECTURE.md](ARCHITECTURE.md); not a 1.0 claim |
| Engine `python -m pinwash check` | yes, local v0.0.0 |
| Fixtures A1–A11 | yes, `tests/gates/test_v0_acceptance.py` (A11 = SPEC file not edited for the engine) |
| Byte-identical JSON across Windows / macOS / Linux and Python 3.11–3.13 (SPEC §9) | not CI-verified — this repository has no CI workflow; A10 compares LF and CRLF subject files in one run on one host. Local evidence, Linux only: on `f849b8a`, `pinwash check` stdout bytes and exit codes were identical across CPython 3.11.17, 3.12.3 and 3.13.16, each with `PYTHONHASHSEED` 1 and 17, on 58 cells (22 fixture shapes in 40 real git repos, run as `base..head`, `side...head` and worktree; 348 runs), with empty stderr. The shapes include CRLF files, non-ASCII and non-UTF-8 paths, JSON nested 1500 and 20000 deep, a 5000-digit integer, a submodule gitlink and worktree files that cannot be read. At `c71c468` the 6 cells nested 1500 deep exited 2 on 3.11 only (3.12 and 3.13 printed the bytes `f849b8a` prints on all three), and the 3 long-integer, 2 non-UTF-8-path, 3 nested-20000, 3 gitlink and 2 unreadable-file cells exited 2 on all three. Windows and macOS untested |
| Live-fire validated | records published, not re-judged — commits `86bdcce`, `df5eb21`, `7222bfc` and `fe0838e` record rules found and closed against real coding-agent sessions (five PREREG-predicted, judge-pinned evaluation rounds, six zen free models per round), and spec 9's producer-side `REQUIRED_CHECK_DROPPED` severity as validated live. The round records are in [`live-fire/`](live-fire/) (PREREG, report, per-cell patch and pinned-judge output for rounds 0–4); the fixtures derived from them are in `tests/test_unit.py`. |
| 1.0 | no |

## License

Not chosen yet. The repository is public on GitHub and has no LICENSE file; choosing a license is a human decision. SPEC is the contract.
