# PinWash 0.1.1 / SPEC 29 — candidate notes

**Status: candidate prepared; package acceptance NOT RUN; not published.**
This is an MIT-licensed Alpha candidate based on main
`e04e115c8f3ec09809cf6f7cf5026dfb877fa7ac`. The package version becomes `0.1.1`;
SPEC stays 29 and the findings envelope stays 1. The public package remains
[0.1.0 / SPEC 27](https://pypi.org/project/pinwash/0.1.0/).

## Changes relative to the published 0.1.0

The candidate carries the two spec changes merged in
[PR #56](https://github.com/taipei49314/pinwash/pull/56):

- **SPEC 28:** emptied hook events are compared with what existed at base.
  A command-free event left unchanged no longer blocks unrelated changes.
  Claude `prompt` and `agent` handlers with modeled shapes count for removal
  and `disableAllHooks` protection. Changed handler content remains explicitly
  unassessed; PinWash does not interpret the prompt or run its model.
- **SPEC 29:** Claude Code hook keys `disabled`, `hookEnabled`,
  `continueOnError` and `failOpen` do not deactivate commands in PinWash's
  `claude_settings` model. Those keys are ignored by the observed Claude host
  versions. Cursor's skip-key behavior remains unchanged.

These changes include both fewer false alarms and additional blocks:

| Example change | Candidate behavior |
|---|---|
| Unrelated diff beside an unchanged command-free hook event | No emptied-command finding |
| `disableAllHooks: true` over a modeled prompt-only Stop event | Blocking finding |
| The only live flagged Claude Stop judge is removed or disabled by the settings-root switch | Its ignored per-hook flag no longer hides its liveness; the applicable weakening finding can block |
| A modeled handler changes while another handler stays | Explicit coverage row; handler semantics are not evaluated |

This is not a promise that all hook-related false positives or escapes are
closed. Issues [#42](https://github.com/taipei49314/pinwash/issues/42) and
[#45](https://github.com/taipei49314/pinwash/issues/45) retain unresolved parts,
including the general base-liveness question and R13/R24 residuals. The older
draft #50–#52 stack is outside this candidate. No new detector change is made
by the version preparation itself.

## Installation and artifacts

No `0.1.1` release download or accepted wheel is available from this preparation.
The [installation guide](INSTALL.md) keeps public-install commands on `0.1.0`
and explains the later local-wheel option. Do not relabel the historical
`0.1.0` verification wheels as `0.1.1`.

| Planned artifact | Current state |
|---|---|
| `pinwash-0.1.1-py3-none-any.whl` | NOT BUILT; no accepted SHA-256 |
| `pinwash-0.1.1.tar.gz` | NOT BUILT; no accepted SHA-256 |
| Wheel rebuilt from the sdist | NOT BUILT; verification artifact only |

## Acceptance and later publication

The [acceptance plan](PACKAGE_ACCEPTANCE_0_1_1.md) requires a newly fixed source
SHA, both installed wheels' full suites, exact source/resource checks, metadata
and CLI identity readback, session/report fixtures, and complete cleanup. Prior
645- and 690-test records belong to their original sources and artifacts.

Linux is the intended package acceptance target. Windows/macOS acceptance,
fresh model live-fire, held-out accuracy and semantic judge qualification are
not established by this candidate.

After new acceptance and the applicable publication authorization, publication
preparation must explicitly bind `v0.1.1`, the exact accepted source and the
original wheel/sdist hashes. The existing `publish-pypi.yml` and environment
restriction remain scoped to `v0.1.0`; this preparation changes neither. No tag,
upload dispatch or persistent publisher-scope change is performed here.
