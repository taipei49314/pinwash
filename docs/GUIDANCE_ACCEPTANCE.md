# Quickstart, status and priority summary: validation record

Human scope, 2026-10-18: five-minute quickstart, session status and report priority
summary; no release. This work starts after PR #53, from main
`cdefa7d11caeafd31d9bc0cc4e6d17e1445342c2`.

## Implementation

- A complete fixed-source POSIX quickstart with isolated installation, a small
  removable-hook example, the two-step session flow, status and recovery guidance.
- A read-only `session status` command. It locates Git root metadata without
  scanning the worktree, preserves the original baseline and separates saved
  historical review results from current changes. Its JSON schema and exit
  meanings are distinct from review.
- A text-only priority summary: incomplete execution first, blocking changes,
  exemption decisions, configuration errors, coverage gaps and a next action.
  Engine JSON, thresholds, exit codes and exemption semantics are unchanged.

## Verification prepared, not executed

Independent read-only review found and corrected two metadata-display edges:
a failed final state read now discards unconfirmed historical output, and an
unreadable judge is shown as UNKNOWN rather than CHANGED. Regression cases
cover both. Documentation review also separated status exit codes from review
exit codes and made demo preparation stop on failure. No remaining blocking
source-review finding was identified; this is not execution evidence.

New regression cases cover missing/changed/damaged state, historical result
selection, other sessions, links, duplicate keys, invalid timestamps, bounded
reads, malformed reports, no scan/write behavior, CLI routing and summary
ordering without mutating raw evidence. Real Git cases cover status from a
subdirectory and a historical pass followed by a currently blocking change.

The existing two-wheel package harness now exercises installed status before
and after review and checks the priority-summary and historical-result wording.
It still builds wheel and sdist, rebuilds from sdist, verifies installed bytes,
runs both full installed-doctor suites with zero skips, and checks that subject
code never executes.

`NOT_RUN：工作機規則（POLICY work-machine-local），本輪新增程式與套件驗證尚無新的執行授權。`

PR #53's accepted 624-test result applies only to its recorded source
`865f02bc73d7a8a38f13fae32975487e153c6cb2`, not this change. Its one-time local
execution grant is consumed. New execution requires a fixed-source plan and
fresh authorization/EC registration or an authorized pool route. Source review
and whitespace checks do not establish runtime acceptance.

No newcomer timing study has been performed; “five-minute” is a walkthrough
target. No Windows/macOS acceptance, release, tag or PyPI publication is claimed.
