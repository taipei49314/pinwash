# First execution batch, 2026-10-14

Status: prepared before implementation and pool execution. Human instruction: "照這版做，先從第一個執行批次開始，測試與驗證都走 EC pool。"

## Frozen starting identities

- Product baseline: `1c340e7a9b105169715d62ea80211394913475e7`, spec 27, engine 0.0.0.
- EC observed baseline: `d7235204a30c50d14980484eb12c22f61f8c4317`.
- Existing `alpha2-verify` declaration entry: `2eecb85e22d3aedff69eb182dbe2ed2abc4586a1f398fd92d2558dc506ea4ce6`; unchanged, parameters `{}`, 20-minute limit.
- All execution goes through EC pool. No work-machine tests, doctor, product CLI, compilation, lint, dependency installation, probes, re-judging or measurement. `tests/gates/**` remain human-owned and read-only.

## Ordered deliveries

1. Record baseline pool run/attempt, exact source, check, receipt and raw suite/doctor evidence. Actual results replace no historical results. A failure is retained and diagnosed.
2. Correct Claude-only host-neutral skip flags (#42), then the command-holder grammar (#44), then non-command handlers and the empty-command false positive (#45). Validate disableAllHooks and Stop escalation together.
3. Book and route the bounded global environment keys (#43), then detect only host-supported closed forms. PATH changes are visibility only. Route and detect async Stop behavior separately; version-dependent unknown events are visibility only.
4. Address producer move/rekey false positives (#29) with narrow identity and execution-condition checks. Do not grant identity on job name alone.
5. Validate the cumulative reviewed candidate on pool, obtain independent source review, retain a reviewable product PR, and report exact remaining acceptance boundaries. No release or 1.0 claim.

Every SPEC ruling is AI-assisted, changes its own spec version and lands in its own commit with named fixtures and SPEC §16 entry. Future spec numbers are allocated when that commit is written, not reserved here. Later grammar/reader work, #12/#14 detection, cross-OS validation, new agent live-fire and publication are outside this batch.

## Preregistered acceptance predictions

The following are expected outputs, not measured results:

| ID | Input change / control | Expected |
|---|---|---|
| B01 | Baseline suite and doctor at starting source | Nonzero same suite, no failures/errors/skips; actual count recorded, not forced to a target |
| C42a | Claude hook gains disabled/hookEnabled/continueOnError/failOpen flags only | No bypass finding; command remains active for other detections |
| C42b | A flagged Claude Stop command is removed or disableAllHooks becomes true | Same live-judge protection as an unflagged command |
| C42c | Existing Cursor flag semantics | Unchanged |
| C44a | Claude command moves from hooks[] item to matcher-group command | Removal detected; group command cannot preserve Stop liveness |
| C44b | Group command was already present, ordinary docs edit | No new removal finding |
| C45a | Prompt/agent-only Stop unchanged, README edit only | No empty-command finding |
| C45b | disableAllHooks becomes true over a prompt/agent Stop | Switch-off detected with Stop severity |
| C45c | Last prompt/agent Stop actually removed | Removal detected |
| C43a | Changed root SHELL_PREFIX/BASH_ENV/PATH beside active hooks in either repo settings file | Bounded env visibility, including cross-file hooks |
| C43b | Effective SHELL_PREFIX becomes exact string true | Bounded bypass finding where the admitted shell form is affected |
| C43c | BASH_ENV points to a resolved repo-relative script newly terminating the shell with exit 0 | Bounded bypass finding, including an unchanged key with changed script |
| C43d | BASH_ENV script only runs true or :, PATH honest edit, safe prefix | No invented bypass; applicable visibility remains |
| C44c | Synchronous live Stop hook becomes async true | Bounded bypass; async occurrence cannot hide loss of a blocking Stop |
| C44d | Async already true at base / async false / non-Stop async | No new Stop bypass finding |
| C44e | Version-dependent/unknown event spelling changes | Visibility only; no invented universal host-version block |
| C29a | Pure same-file job rekey preserves required context, body and execution conditions | No deleted-producer false positive |
| C29b | Byte-identical workflow moved, equivalent unambiguous producer | No deleted-producer false positive in the admitted closed move form |
| C29c | Rekey/move also guts body, changes executable workflow settings, or plants same-name decoy | Cannot receive the honest-move exemption; relevant finding/row remains |

For every row, fixtures identify exact expected rule, severity, locator, unknown reason and exit/verdict before execution. Candidate fixtures may be refined before they are run; any change after a run is documented as a new preregistered attempt, never retroactively relabelled.

## Validation boundaries

Existing alpha2-verify checks the complete suite, doctor and two hash seeds on a same-tree scan, on one Windows runtime. It does not execute Claude/Cursor, provide a Python/OS matrix, measure held-out accuracy or re-judge historical agent cells with the current three-invocation recipe. Existing live-fire-rejudge replays historical judges, not the new candidate. New workload declarations require a concrete separate approval boundary before execution; this batch does not silently broaden either existing declaration.

Source review is not execution evidence. PR-head pool acceptance does not imply merge-source acceptance. Every reported PASS must name source SHA, spec identity, runtime, commands, logs, run/attempt and receipt. Incomplete, timed-out, failed and NOT_RUN results are preserved.
