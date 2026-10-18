# Two-step session consumer

The consumer automates the README's existing three-comparison recipe. It does
not change spec 27, detector behavior, the findings envelope, or `check`.

## Start

Run `pinwash session start` from the project or any subdirectory before editing.
The consumer resolves the entire repository root and records a verified full
commit SHA, the installed Python-source digest, version, spec and repository
path. An unborn repository or dirty tracked/nonignored worktree is refused;
commit or stash your own changes first. PinWash never stashes, commits or
rewrites them. Readiness compares bytes without running Git clean filters;
UTF-8 LF/CRLF-only differences are accepted for normal Windows checkouts, and
symlink text is compared to its committed target. It is not a Git status claim.
Directory and dangling symlink nodes are also checked by their link text;
this readiness check does not extend the scanner's supported surfaces.
Other custom-filter transformations may need a checkout without those filters.
Ignored content retains the scanner's documented coverage limits.

State defaults to `%LOCALAPPDATA%/pinwash` on Windows and
`${XDG_STATE_HOME:-~/.local/state}/pinwash` elsewhere. All session commands accept
`--state-dir PATH` to select a consumer-managed directory outside the project.
The controller and agent must not share write access to authoritative state or
the judge installation if tamper resistance is required. This implementation
does not create that OS boundary or authenticate the human invoking it.

An active baseline is never implicitly replaced. `start --replace` explicitly
chooses current HEAD as a new baseline; it is not a repair for a failed review
or an approval of a new exemption. Original records stay in `sessions/`.

## Review

Run `pinwash session review` after stopping all agent writers. Interactive use
asks for confirmation. Noninteractive use requires `--stopped`, an assertion
by the trusted caller, not evidence that PinWash stopped or inspected processes.
The interactive prompt goes to stderr so `--json` keeps stdout as valid JSON.

The consumer freezes the current HEAD and runs:

1. `BASE..HEAD_SHA` (committed changes).
2. `BASE..WORKTREE` (everything visible against the original baseline).
3. `HEAD_SHA..WORKTREE` (uncommitted changes against that frozen HEAD).

All invocations use the same installed code through isolated Python startup;
repository-controlled Python modules and `PYTHONPATH` cannot select the child
judge. Git environment redirection is cleared. Each inspection/comparison has
a 60-second timeout, adjustable with `--timeout` up to 3600 seconds. This bounds
the direct child invocation, not every possible OS resource or descendant.

The consumer checks HEAD and observable worktree bytes before and after review
and rejects detected changes. Equal observations do **not** rule out a writer
that changes bytes during the scan and restores them. Stopping writers remains
a caller precondition. No subject hooks, code or model calls are executed.

Missing/damaged state, missing objects, a changed judge, invalid output or
timeout never falls back to a different baseline and never becomes a pass.
Repository paths are bound to the recorded canonical root; moving a checkout
requires deliberate handling of its previous records rather than guessing.

## Status, without a new review

Run `pinwash session status` from the repository or a subdirectory at any time.
It reads Git root metadata, the active baseline, installed judge identity and
saved reports; it does not read the current worktree contents, run comparisons,
ask for stopped-writer confirmation, create state, or change the baseline.

Text output shows the original full baseline SHA and start time, whether the
installed judge still matches, and the latest saved review's time, historical
status, counts and file path. **Current changes are always NOT REVIEWED by this
command**, even if the last saved report passed. Run review after stopping
writers to judge current changes. A missing saved report is not a pass.

`--json` uses a separate `session_status_schema_version: 1` envelope. Its
`status` is `no_session`, `active`, or `unavailable`; `current_changes` is always
`not_reviewed`. `session` contains the saved ID, base, creation time and judge;
`judge_matches` is true, false, or null when undetermined. `latest_review` is
historical metadata or null. Exit 0 means status was read successfully
(including `no_session`); exit 2 means state, judge or history needs attention.
**These are not the review verdict's exit codes.**

Only reports named for the active session are candidates. Content must match
its ID, repository, baseline and saved judge, with valid timestamps and report
structure. Selection uses the recorded review timestamp, then filename for an
equal-timestamp tie, not file modification time or an embedded `report_path`.
Damaged matching reports make history unavailable rather than allowing an old
pass to appear current. Links and special files are rejected. Reads are bounded
to 64 KiB for state, 4 MiB per report, 16 MiB total report data and 5,000 directory
entries. Exceeding a bound means exit 2; preserve the records for manual review.
These checks do not authenticate local files or provide an atomic snapshot
while another process is writing reports. Status remains informational.

## Reading a report

The text output begins with a **priority summary**. An unfinished review comes
first even when a completed comparison already blocked; its findings remain
visible. Blocking results highlight the three highest-severity findings, then
the summary calls out new exemptions, configuration errors and unassessed
items. Additional findings stay in the full details below. The next step uses
the same baseline; `start --replace` is never a shortcut to make a failure pass.
The summary is presentation only: it changes no detector threshold, verdict,
exit code, raw engine payload or exemption approval.

The full text output shows findings, whether all comparisons finished, coverage gaps,
configuration errors and a saved-report path. File-controlled terminal control
characters are escaped. Long before/after snippets are truncated in text only.
The JSON report preserves all three original payloads and exit codes.

Findings are grouped by fingerprint, displaying the highest observed severity
and retaining each range/severity observation. Any `EXEMPTION_ADDED` holds an
otherwise successful review for human approval. PinWash neither approves nor
automatically writes exemptions. Review each proposed exemption against its
reason, exact scope and expiry before allowing it into a future baseline.

| Consumer exit | Meaning |
|---|---|
| 0 | All comparisons finished; no finding reached the engine threshold and no exemption was added. Coverage gaps/configuration errors may still need review. |
| 1 | At least one comparison blocked; all comparisons finished. |
| 2 | Some part did not finish or an integrity precondition failed. Already observed blocking findings are retained. |
| 3 | All comparisons finished without a block, but a new exemption needs human review. |

`status`, `execution_complete`, `unknown_coverage` and `config_errors` are distinct.
A report can have `status: block` and exit 2 because one comparison blocked and
another timed out. `unknown_coverage` does not change the core engine verdict.
No reported coverage gaps does not expand the scanner's supported surface set.

Reports are created under `reports/` with unique names. Failed write means exit 2;
the tool does not claim a saved report that it could not write. Repeating review
uses the same original baseline and creates another report. Local records can
contain configuration values; share only after reviewing their contents.

## One diff

`pinwash review [RANGE]` is a human-readable view of one diff, useful for PR or
commit review. `--json` returns a consumer envelope containing the engine result.
Unlike session review, a single diff does not cover all session changes. Existing
integrations should continue using `pinwash check [RANGE]` unchanged.
