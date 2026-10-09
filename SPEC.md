# pinwash SPEC — frozen contracts

**One sentence:** pinwash flags a Git diff that makes an agent more able to claim done by weakening the verification harness around it.

**一句話：** 標出會讓 agent 比較容易自稱完成的 harness 變更。

This file is the single source of truth for rule IDs, pin identity, surfaces, severity, exit codes, and determinism. Changing anything here requires a spec-version bump and a fixture re-run. Authority: the human maintainer owns `tests/gates/**`; on 2026-09-27 the maintainer delegated spec rulings and edits to the maintaining agent, under the discipline that every change bumps the spec version, lands as its own commit, and re-runs the fixture suite. On 2026-10-09 the maintainer extended that delegation to every ruling, including one that reverses SPEC text or turns a passing result into a block, on the condition that each ruling the maintaining agent makes is marked **AI-assisted** in its §16 row, its commit message and its issue; rulings the maintainer makes are marked as the maintainer's.

Spec version: **13** (draft spec 0 was frozen by the first commit of this file; the findings envelope is `pinwash_findings_version: 1`). A local engine exists (`pinwash` 0.0.0, stdlib only, zero runtime dependencies); it is not a Release, not on PyPI, and not a 1.0 claim. This document began as the preregistration: acceptance in §12 was frozen before implementation. Detectors must not be patched to fit a fixture; fixtures that are out of spec stay residuals.

## 0. What it is / is not

| It is | It is not |
|---|---|
| A static, local, deterministic **diff scanner** | An enforcer, hook, or required status check |
| A judge of **harness weakening** | A judge of product tests, claims, or journeys |
| Fail-closed on its own parse errors | Proof that the remaining harness works |

It **never** emits `SECURE`, `HARNESS_INTACT`, `HONEST`, `COMPLETE`, or `ENFORCED`. The strongest valid pass sentence is:

> No in-scope weakening finding at or above `fail_on` was observed on this base/head pair, under this spec version, surface set, and pinwash revision.

A pass is not enforcement. tripwire (or GitHub rulesets) may still be absent, skipped by a human `--no-verify`, or running a different pin. pinwash does not install, invoke, or trust those tools.

### Neighbours (do not reimplement)

| Product | Question pinwash does **not** answer |
|---|---|
| checkwash | Did this diff weaken **product tests / CI oracles**? |
| walkaround / action-receipt / claim-receipt-lab | Did the agent **enter** a contract or **emit** a receipt for a done-claim? |
| phaseledger | Did a **measurer** allow a phase advance? |
| charterlock | Was the journey **allowed to be the exam**? |
| tripwire | Is a hook **actually executing** a pinned judge on this host? |
| boundkit | Was the **task** claimed and authorized? |
| smallestlie | What lie does **this** verifier still accept? |

checkwash already rates many guardrail-path edits `GUARDRAIL_TOUCHED`. That event is “a constraint file changed”. pinwash events are **structured weakenings** (hook gone, pin floated, permission widened). Both may fire on one diff. Identities must not be shared.

## 1. Trust model

1. The **head** tree — including the whole working tree in hook mode — is attacker-controlled data. Agents write it.
2. pinwash **configuration and allowlists are read from the base** side only. A head-side config that disables rules does not govern the run that reviews that head. Creating a base-absent config that relaxes defaults is itself a finding (`CONFIG_RELAXED`).
3. pinwash **never executes** subject code, hooks, judges, workflows, MCP servers, or skills. It reads bytes.
4. pinwash **never uses a network** on the core path. GitHub rulesets that exist only on the API and not as a file in the trees are `UNKNOWN`, not pass and not block.
5. pinwash **never calls a model**.
6. Missing observation is never a pass: an input this spec version cannot observe surfaces as a finding (`SURFACE_UNPARSEABLE`), a `config_errors` entry, or an `unknown_coverage` row — never as a silent `verdict: pass`. A crashed engine is exit 2, never a block (exit 1).
7. Artifacts the agent wrote in the same diff (`*.log`, screenshots, “CI is green” markdown) are never evidence that a harness still runs.

## 2. Analysis unit

pinwash analyses a **diff**: a pair of git trees `base` and `head`. It never judges a single snapshot as “the harness is fine”.

Range notation matches checkwash:

- `BASE..HEAD` — tree to tree.
- `BASE...HEAD` — `merge-base(BASE, HEAD)..HEAD`. It must not silently become two-dot.

Paths are normalized to forward slashes. Comparison text is CRLF→LF before parse.

## 3. Surfaces (closed set for spec v0)

A **surface** is a named, path-bounded, parse-bounded family. Adding a surface is a spec bump. v0 surfaces:

| ID | Paths (any match) | Parse |
|---|---|---|
| `claude_settings` | `.claude/settings.json`, `.claude/settings.local.json` | JSON object |
| `claude_hooks` | `.claude/hooks/**`, plus hook `command` strings that resolve to repo-relative files per §3.3 | JSON if `.json`, else **command line** as a single string |
| `cursor_hooks` | `.cursor/hooks.json` | JSON object |
| `cursor_mcp` | `.cursor/mcp.json`, `.mcp.json` | JSON object |
| `agent_markdown` | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `QWEN.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`, `.cursor/rules/**/*.mdc`, `.cursor/rules/**/*.md` | UTF-8 text; only `SKILL_BYPASS` uses this surface |
| `skill_md` | `**/SKILL.md`, `.agents/skills/**/SKILL.md`, `.cursor/skills/**/SKILL.md` | UTF-8 text; only `SKILL_BYPASS` |
| `gha_workflow` | `.github/workflows/*.{yml,yaml}` | **Bounded line grammar** (§3.1), not YAML 1.2 |
| `gha_ruleset` | `.github/required-ruleset.json`, `.github/rulesets/*.json` | JSON object |
| `action_pin` | same workflow files as `gha_workflow` | `uses:` lines in the bounded grammar |
| `declared_pins` | `.pinwash/pins.json` (optional) | JSON array of pin records (§4) |
| `checkwash_config` | `.checkwash/config.toml`, `.greenwash/config.toml` | **Bounded TOML** (§3.2) for disable / `fail_on` only |
| `gemini_settings` | `.gemini/settings.json` | JSON object |
| `opencode_config` | `opencode.json` | JSON object |

Files outside these paths are invisible to v0. A harness that lives only in a user’s home directory, an untracked `.claude/settings.local.json`, or a SaaS UI is a residual (§11).

If a surface file existed at base and is unparseable at head under that surface’s parse, emit `SURFACE_UNPARSEABLE` (high). Do not skip the file. If it was also unparseable at base, emit `SURFACE_UNPARSEABLE` at warn (no new information). The engine emits `SURFACE_UNPARSEABLE` for no other parse-status pair; whether §3.2's sentence on a checkwash config that is not UTF-8 also reaches one absent at base is open (#22). In (unparseable, ok) no rule reads the base, and in (missing, unparseable) and (unparseable, missing) no rule reads the unparseable side: residual R19 (#22).

### 3.1 Bounded line grammar (GitHub Actions YAML)

v0 does not ship a YAML parser. On each workflow file, after CRLF→LF:

- Drop lines whose first non-space is `#`.
- Track indentation width in spaces. **Tab rule** (stated in spec 12; the engine has applied it since spec 0): a line that contains a tab (U+0009, written `<TAB>` here) before its first `#` character, or anywhere when the line has no `#`, makes the whole file unparseable under §3, and none of its pins, jobs or triggers is compared. The test runs on every line, split at LF, CRLF or a lone CR, before comment lines are dropped, and the first `#` counts wherever it stands (in a value, inside quotes, with or without a space before it). So a tab in indentation, in a value or in block-scalar content, before an inline comment (`if: false<TAB># x`), on a whitespace-only line, or before the `#` of an indented comment line fails the file; a tab after a line's first `#` does not. The rule is not narrowed to indentation: recorded values truncate only at ` #` (below), so `if: false<TAB># x` would then stop reading as `false` (#25). Its costs are residual R20.
- Record:
  - `uses:` value (strip quotes) at any indent.
  - `continue-on-error:` value `true` / `false`.
  - `if:` value as raw remainder of the line.
  - `name:` at job indent (the first `name:` under a `jobs:` key at indent 2, using a stack).
  - Job keys: a line matching `^  [A-Za-z0-9_-]+:\s*$` under `jobs:`.
  - `on:` triggers (spec 8), at column 0 only: inline scalar, inline `[a, b]` list, block list items (`- item`) at indent 2, block mapping keys (`key:`) at indent 2. Deeper lines under a trigger are trigger configuration, not triggers. A second top-level key ends the `on:` block.

Every recorded value is **truncated at the first ` #`** (space followed by `#`) — the bounded form of a YAML inline comment. A `#` without a preceding space is kept. Spec 5 added this truncation after live-fire on a real repository showed sha-pinned `uses:` lines annotated `# vX.Y.Z` classified as floating, so honest release annotation bumps fired `JUDGE_UNPINNED`. Residual: a quoted value that legitimately contains ` #` truncates at the wrong point.

**Residuals (not findings, not passes):** YAML aliases (`*anchor`), multiline `>` / `|` scalars, `uses` split across lines, `true` written as `yes`, jobs generated by reusable workflows, `workflow_call` indirection, and an `on:` block whose forms the grammar cannot resolve (flow mapping `on: {…}`, unrecognized items → recorded as unknown `on triggers unresolved`, never treated as an observed trigger removal). Those are `UNKNOWN` coverage, documented in THREATMODEL, never invented as “no `uses` change”.

**Outside the grammar, not recorded** (residual R20, booked in spec 12; no `unknown_coverage` reason is defined for them): quoted keys other than `on`, `key :` spacing, flow-style job bodies and workflows written in JSON syntax (#23); job keys not at indent 2 (the job-key form above) and job bodies not at indent 4, where the engine reads a job's `if:`, `continue-on-error:` and `name:` (#24). A weakening written in these forms is not observed, and an honest requote or reindent of a recorded key can read as a removed pin or job. A top-level key after `jobs:` does not end the jobs block, so its indent-2 children are read as jobs (#24).

### 3.2 Bounded TOML (checkwash config)

v0 reads only:

- `[detectors]` or equivalent key/value `detect_* = false` / `disable = ["RULE"]` if present as a single-line assignment.
- `fail_on = "..."` single-line.

Full TOML 1.0 is a residual. Unknown keys are ignored. A file that does not parse as UTF-8 is `SURFACE_UNPARSEABLE`.

### 3.3 Hook command target resolution

A hook `command` string (from `claude_settings` or `cursor_hooks` JSON, on a given side) resolves to target files as follows, and nothing else: strip surrounding quotes; replace `;`, `&`, and `|` with spaces; split on whitespace. A token is a target iff it fully matches `[A-Za-z0-9_./-]+\.(py|sh|bash|js|mjs|cjs|ps1)`, does not start with `/`, `-`, or `~`, and names a path present in that side's tree after path normalization. Resolved targets are `claude_hooks` surface members for the §3 parse-status check and the §5.2 body check, in addition to `.claude/hooks/**` paths.

Residuals: module-form commands (`python -m pkg.mod`), quoted paths containing spaces, tokens with variable expansion (`$HOME/...`), inline `-c` payloads, and targets absent from the tree. Targets outside the extension set (other extensions, case variants such as `.PY`, no extension, suffixes such as `.bak`) and a path quoted as a whole token (`python "hooks/judge.py"`: quotes are stripped only from the ends of the whole command) do not resolve either. All of these are residual R07 (#18). A retarget from a resolved judge into one of them is R12 (#10); shell composition around a command that still resolves is R11 (#9). None of these are invented as stubs, and no body check reads the files behind them. For the §6.1 count an unresolved command is live under the same test as any other command (§5.2), because no body is read for it; its string and skip flags are tested as for any command (spec 13, AI-assisted ruling on the tension R12 recorded, #10).

**Unknown coverage (spec 13).** Four reasons route what this resolution leaves unread to `unknown_coverage` (§1.6, §7), each reported at most once per hook surface file. A command is *active* when it carries no §5.1 skip flag (its own or an enclosing object's), is not a §5.2 stub string and does not begin with `#`.

- `hook stop liveness rests on an unresolved command`: a Stop-like hook finding in the file (§6.1) is kept below critical only because an unresolved command counts live; or the diff leaves the file's Stop liveness resting only on unresolved commands (at head a Stop-like event keeps a live command and no live command of a Stop-like event resolves, while at base one did).
- `hook command target no longer resolved`: in an event present on both sides, an active command that resolved at base is active at head with the same string and resolves to nothing there; or an active command that resolved at base is absent from the head event while a command active at head and not active in the base event (absent from it, or flagged, stubbed or commented out there) resolves to nothing at head. No row for a command dropped with no replacement, for a replacement that resolves, or for a removed event (`HOOK_REMOVED`'s case).
- `hook command names a changed file it does not resolve`: an active command, on either side, names a path whose bytes differ between base and head (added, edited or deleted; compared after CRLF→LF, §2, a lone CR kept, so rewriting a shell judge's line feeds to lone CRs is a change) and that is not one of that command's own targets on that side. Reading `\` as `/`, a command names a path when the path occurs in it with the start of the command, whitespace, or one of `" ' / = ; & | (` and backquote before it, and the end of the command, whitespace, or one of `" ' ; & | ) < >` and backquote after it. A `-m` token followed by a token that is an ASCII dotted identifier (`a.b`: one or more dot-separated runs of ASCII letters, digits and `_`, none starting with a digit) also names `a/b.py`, `a/b/__init__.py` and `a/b/__main__.py`. In a repository whose hook commands use the `"$CLAUDE_PROJECT_DIR"/...` form, which §3.3 does not resolve, this reason appears on every diff that edits a hook script those commands name, an honest edit included: until that prefix is resolved (a later detection bump) it says that the edited body was not judged, not that the edit is suspect.
- `hook command environment changed` (`claude_settings`): a root `env` key that the diff adds, changes or removes is expanded, as `$K` or `${K` with the name ending where it cannot continue, by an active hook command of the same file on either side.

None of the last three can fire on an unchanged tree, and none of the four changes a finding or the verdict. What stays silent is booked in R07 and R12: a body reached indirectly (an import, a build output not in the tree, a directory runner such as `run-parts`, an environment set outside the file, such as an `env` key in the other settings file or the host's own environment); a rewrite that changes only CRLF line endings, or only a file's executable bit, which the trees do not carry; a path the command does not spell as the repo-relative path at those boundaries (relative to a `cd` or `--directory`, `./`, `..` or `//` inside the path, a quote inside the path, globs, case variants); the module spellings `-mpkg.mod` and `-m "pkg.mod"`; and a gut behind a command that an earlier diff already respelled into an unresolved form (that earlier diff had its row).

## 4. Pin identity

A **pin** is a closed record:

```json
{
  "locator": "surface-specific string, stable across reformatting",
  "kind": "git_tag | git_sha | action_ref | digest_sha256",
  "value": "non-empty string",
  "product": "optional label, not used in identity"
}
```

`locator` examples: `gha_workflow:.github/workflows/tripwire.yml:uses:taipei49314/greenwash#0`, `declared_pins:greenwash`. In a workflow locator, `#<n>` counts, from 0, the earlier `uses:` lines in the same file that §3.1 records as pins of the same action (the value before its last `@`, with a non-empty ref after it; local `./` paths and `docker://` values are not pins), so a second step pinning one action is `#1`.

**Kind lattice** (stronger to weaker):

```
digest_sha256 > git_sha (full 40 hex) > git_tag (v-prefixed or annotated-looking) > action_ref-that-is-tag > action_ref-that-is-branch-or-floating
```

Classification of `action_ref` value `R`:

| `R` | Kind treated as |
|---|---|
| 40 lowercase hex | `git_sha` |
| matches `^v?[0-9]+\.[0-9].*` and contains no `/` | `git_tag` |
| `main`, `master`, `HEAD`, `latest`, empty, `*` | **floating** (weakest) |
| anything else (`feat/…`, unprefixed names) | **floating** |

**Unpin** (the `JUDGE_UNPINNED` event) is any of:

1. kind moved **down** the lattice;
2. value changed and the new value is floating;
3. pin **removed** while the locator’s consumer still exists (workflow still there, `uses` line gone or stubbed);
4. `digest_sha256` present at base, absent at head, other fields equal;
5. SHA shortened below 40 hex.

Pin **tightening** (tag → sha, sha + digest added) is not a finding.

Vendor directory **content** edits without a pin-record change are **not** `JUDGE_UNPINNED` in v0 (residual: silent patch of a vendored judge). tripwire’s “never patch the judge” is enforcement policy for that product; pinwash v0 only sees pin records.

`.pinwash/pins.json` is optional. If present at base, every record must keep kind/value or a documented allow fingerprint. Head-only creation of this file is not a finding.

## 5. Rule IDs (frozen)

Base severity of every finding is `warn`, except the producer-side disjuncts of `REQUIRED_CHECK_DROPPED` (spec 9), which base at `high`, and the §10 exemption-channel severities (`CONFIG_RELAXED` at `.pinwash/allow.toml` is `critical`; `EXEMPTION_ADDED` is `critical` when an added record's `created` is after today, spec 11). Escalators in §6 may raise a severity. Detectors are not configurable except disable-whole, and disable-whole on the **head** config does not apply to the current run (§1.2).

| Rule ID | Trigger |
|---|---|
| `HOOK_REMOVED` | A named hook event that existed at base on `claude_settings` or `cursor_hooks` is absent at head, **or** its command list is empty. Renaming the event (`Stop` → `stop` if the host is case-sensitive — treat Claude `Stop` / `PreToolUse` as exact). Adding hooks is not this rule. |
| `HOOK_BYPASSED` | An existing hook **remains named** but a skip was introduced: command prefixed with a no-op; JSON `disabled: true` / `"hookEnabled": false` added. Host-specific keys are an exact table in §5.1. An event left with no command, whatever its entries' `matcher` values, is `HOOK_REMOVED`; an entry emptied while a sibling command stays is R12 (#10); selector changes with the command kept (`matcher`, per-hook `if`, handler `type`) are R13, reported in `unknown_coverage` and never a finding (§5.1, #12). |
| `GATE_STUBBED` | A remaining hook `command` at head is a **stub** (§5.2) and the base command was not a stub; **or** the command resolves per §3.3 to target file(s) whose body is a stub (§5.2) while the base command resolved to a non-stub body. |
| `JUDGE_UNPINNED` | A pin identity weakened per §4. |
| `PERMISSION_WIDENED` | A permission or auto-approval set grew per §5.3. Shrinking is not a finding. |
| `SKILL_BYPASS` | An **added or edited** line in `skill_md` or `agent_markdown` matches the bypass phrase table (§5.4). Deletions of such lines are not a finding. |
| `REQUIRED_CHECK_DROPPED` | A required status context named at base in `gha_ruleset` is missing at head; **or** the workflow job that produced that `name:` was deleted / `if: false` / `if: 'false'` introduced / `continue-on-error: true` introduced on that job; **or** (spec 8) the workflow that contains the producing job included `push` or `pull_request` in its `on:` triggers at base and includes neither at head, so the context loses every enforcement-path run. An `on:` block the grammar cannot resolve is a residual (§3.1), not an observed removal. **Severity**: ruleset-side drops are `warn` (`critical` per §6.2 when the last remaining context goes); the producer-side disjuncts — deleted job, `if` disable, `continue-on-error`, trigger-loss — base at `high` (spec 9). |
| `CONFIG_RELAXED` | Base-absent or edited `checkwash_config` **disables** a detector or raises `fail_on` above the base value (or above default `high` if base file missing). Tightening stays silent. Also a base `.pinwash/allow.toml` exemption deleted, edited, or unconfirmable at head (§10, `critical`); that finding is never exempted (spec 11). |
| `EXEMPTION_ADDED` | A valid (§10) `.pinwash/allow.toml` record present at head and absent at base. Visibility only: head-side records never govern the current run (§1.2). `warn`, except an addition whose `created` is after today, which is `critical` (§10, spec 11). Never exempted (§10, spec 11). |
| `SURFACE_UNPARSEABLE` | See §3. |

No other rule IDs exist in this spec version. Internal helper names must not appear in JSON `rule` fields.

### 5.1 HOOK_BYPASSED key table

Exact keys, case-sensitive:

| Surface | Key / shape | Event |
|---|---|---|
| `claude_settings` | `hooks.<Event>` array length 0 | bypass |
| both | `"disabled": true` added | bypass |
| both | `"hookEnabled": false` added | bypass |
| both | `"continueOnError": true` / `"failOpen": true` added | bypass |

**Skip flags are judged per command (spec 10).** A flag on a matcher or group object applies to every command under it. A flag is *added* when (1) a command present at base and head lost active (unflagged) occurrences and gained flagged ones; (2) fewer commands stay active and more are flagged overall; or (3) an active base command is absent at head while a command absent at base appears already flagged (rename plus skip). Commands are compared as multisets of their strings, so reordering is not a change. Adding a new flagged command next to unchanged ones is not a bypass of an existing hook, whichever flag it carries. "Command prefixed with a no-op" in §5 is a command shape, not a key: its v0 closed form is a shell comment (`#`).

An event whose command list is emptied is `HOOK_REMOVED` (§5), whatever its entries' `matcher` values; an entry emptied while a sibling entry keeps a command is R12 (#10). This table has no matcher row (spec 13, #12 member 2, AI-assisted ruling: the row for `*` removed with the command list emptied could never fire, because `HOOK_REMOVED` covers that shape first).

Unknown JSON keys are ignored (not findings). A new unknown skip key is a residual (R06). A §5.1 flag key whose value is not the JSON boolean is read and not interpreted (R06); since spec 13 the file gets the `unknown_coverage` reason `hook skip flag value not boolean` (§7) when the diff adds or changes one, that is when an (event, command, key, value) occurrence is more frequent at head than at base, counted as a multiset as commands are: a hook object that carries such a value counts it once for each command the object holds itself or a hook item directly under it holds (on both hosts' shapes, every command the value applies to), or once with an empty command when it holds none; and also when a §5 hook finding fires in the file while either side holds one. Values compare as parsed JSON (`"true"`, `1` and `[true]` are three values). On `claude_settings`, a root `disableAllHooks` whose head value differs from its base value and is neither absent nor the JSON `false` gets the reason `hook settings root disableAllHooks`, and so does a root value that is neither absent nor `false` on either side while a §5 hook finding fires in the file (spec 13; R06). Neither is a finding, and neither decides which other settings file the host reads first.

`matcher`, per-hook `if` and handler `type` changes with the command kept are residual R13 (#12): no finding, because which tools and events a selector governs is host semantics that pinwash does not evaluate. Since spec 13 they are reported in `unknown_coverage` with the reason `hook selector changed (not evaluated)`, once per file, when a command live on both sides of an event (no skip flag, not a §5.2 stub string, not commented out) differs in its entry's `matcher` value, its per-hook `if`, its handler `type` (absent reads as `command`; in the list form a `type` that names the hook's event is that event, not a handler type), or a `matcher` key below its entry. Commands pair by string first, and each string's selectors are judged on their own, so one command's narrowing cannot hide behind a sibling's widening of the same script; a command whose string changed is the same as one whose §3.3 targets are the same on each side. Values compare as parsed JSON, object key order ignored. A `matcher` change adds no row when the head matcher matches everything (absent, `""` and `*` are one value here, INFERRED from host docs), or when both values are names joined by `|` (each of ASCII letters, digits, `_` and `-`) and the head names include every base name: read as alternation, adding a name cannot narrow a selector. A per-hook `if` that is dropped only widens when the hook runs, so only a gained or changed `if` is a row. That reading of `|` is INFERRED host semantics (under exact-string matching, `Bash` → `Bash|PowerShell` would narrow). A command whose string and targets both change in the same edit is R12, and gets no row. The `cursor_hooks` row that §5.3 carried through spec 12 (`Write|Edit|Bash` narrowed away from `Bash`) is one of these changes: a row, not `HOOK_BYPASSED` (spec 13, AI-assisted ruling, #12).

### 5.2 Stub commands

A command string is a stub if, after trim, it matches **any** of (whole string, unquoted comparison):

- `true`
- `:` 
- `exit 0`
- `exit 0;`
- `echo {}`
- `echo "{}"`
- `python -c "print('{}')"`
- `python -c "print(\"{}\")"`
- `cmd /c exit 0`
- empty string

No regex beyond this closed list in v0. `python hooks/tripwire_stop.py --help` is **not** a stub.

A hook **body** file — a target resolved per §3.3 — is a stub if every non-blank, non-comment line (after strip) is a member of the closed set for its extension. Lines split at LF after CRLF→LF (§2); a lone CR also splits lines except in a `.sh` / `.bash` body, which the shell reads with a lone CR as an ordinary character (spec 13):

- `.py`: `pass`, `import sys`, `import os`, `if __name__ == "__main__":`, `sys.exit(0)`, `os._exit(0)`, `exit(0)`, `quit()`, `raise SystemExit`, `raise SystemExit(0)`, `print('{}')`, `print("{}")`
- `.sh` / `.bash`: `exit 0`, `true`, `:`
- `.js` / `.mjs` / `.cjs`: `process.exit(0)`, `process.exit(0);`
- `.ps1`: `exit 0`

An empty body after comment removal is a stub. A body containing any other line is not a stub — a real judge has work lines. No regex beyond these closed lists in v0.

**Block-capability shape (spec 7).** A body-stub list cannot enumerate reformattings that keep the file's function shape while removing its decision logic. A §3.3 target whose **base** body mentions `block` or `deny` (case-insensitive substring) is **block-capable**; if the **head** body mentions neither, the gate can no longer refuse anything, and `GATE_STUBBED` fires (message "lost block capability") even though no closed line matches. The two shapes are independent — either can fire. A judge whose base body never mentions `block`/`deny` (e.g. refusal expressed only through exit codes) is invisible to this shape and stays residual. So do a gutted head body that keeps either word anywhere (a comment, docstring, string, identifier or unrelated word, or a dead branch that keeps the decision literal) and a `block` → `deny` swap: residual R07 (#11). The comparison is per target path, so a judge whose path changes has no base body to compare: residual R12 (#10).

For the last-Stop escalator (§6.1), a command at head is **live** unless it is a stub command string, carries a §5.1 skip flag (its own or one inherited from its matcher or group object), starts with `#` (§5.1), resolves (§3.3) only to stub bodies, or **lost block capability**. Nothing else is read: a command §3.3 does not resolve is live (§3.3 says when the run reports that), and so is a command added in the same diff (R12) (spec 13, AI-assisted ruling, #10).

### 5.3 PERMISSION_WIDENED

Closed comparisons:

| Surface | Base → head |
|---|---|
| `claude_settings` | `permissions.allow` gains `Bash(*)`, `Bash(rm *)`, `Bash(git push --force*)`, or a new `*` entry |
| `claude_settings` | `permissionMode` becomes `dontAsk` or `acceptEdits` when it was absent or stricter (`default` / `acceptEdits` → `dontAsk` is widen; reverse is not) |
| `cursor_mcp` | a server (an object under `mcpServers`, or under `servers` when `mcpServers` is not an object) is absent at base, a file absent at base included, and its `disabled` is not the JSON `true`; a base server's `disabled` goes from `true` to the JSON `false`; or a server's `"alwaysAllow"` / `"autoApprove"` array gains `"*"`, on a new server too |
| `gemini_settings` | `autoAccept` becomes `true` when it was absent or `false`; `approvalMode` becomes `yolo` or `auto_edit` when it was absent or stricter (`default` / `auto_edit` → `yolo` is widen; reverse is not); an `mcpServers` entry is added with `"trust": true` or gains it |
| `opencode_config` | a `permission.<tool>` value moves down `deny` > `ask` > `allow`, or is added as `allow` (`deny` → `ask` and `deny` / `ask` → `allow` widen; the reverse, and a value added as `deny` or `ask`, do not) |

`permissionMode` lattice, stricter to weaker: `default` > `acceptEdits` > `dontAsk`. `approvalMode` lattice, stricter to weaker: `default` > `auto_edit` > `yolo`. `permission.<tool>` lattice, stricter to weaker: `deny` > `ask` > `allow`. Unknown values: no finding, residual (R17). Object-form `permission.bash` patterns in `opencode.json` are a residual (v0 compares string values only). Deleting `"disabled": true` from a `cursor_mcp` server that stays, or changing it to anything but the JSON `false`, is no finding, and neither is a `claude_settings` permission change outside its two rows: residual R17 (#16, #26).

### 5.4 SKILL_BYPASS phrase table

UTF-8, compared on each added line after LF split, case-folded with `casefold()`, then tested for **substring** membership in this closed list:

- `--no-verify`
- `skip tripwire`
- `skip checkwash`
- `skip greenwash`
- `disable the hook`
- `disable the stop hook`
- `bypass the hook`
- `do not run the hook`
- `chmod +x` **and** `hook` on the same line (both required)
- `alwaysApprove`
- `required status check` **and** (`remove` or `delete` or `drop`) on the same line

Documentation of the phrases in `SPEC.md` / `THREATMODEL.md` / `README.md` is excluded by path. Product code comments in `src/` are not a v0 surface.

This detector will false-block honest threat-model writeups **outside** those excluded paths. That is accepted for v0; extra exclude globs are a spec bump.

## 6. Escalators

Applied in order, all deterministic. No scores.

1. If `HOOK_REMOVED` or `HOOK_BYPASSED` or `GATE_STUBBED` removes or stubs the **last remaining** Stop-like hook, severity becomes **critical**. The last one is gone when no Stop-like event in that file keeps a command that is live under §5.2; the count is per file. Stop-like events are a closed, case-sensitive set per surface (spec 13, #26 item 6, AI-assisted ruling): `Stop` on `claude_settings`; `stop` on `cursor_hooks`, the Cursor event that runs when the agent loop ends and can submit a follow-up message. `afterAgentResponse` and `afterAgentThought` only observe a turn, `subagentStop` belongs to a subagent (as Claude's `SubagentStop` does, which is not Stop-like either), and `finish` and `Stop` name no Cursor event; a hook under any of these names, or any other, never keeps this escalator off, so moving the last Stop-like judge to one of them is removing it. Which Cursor events run, and what they can return, is taken from Cursor's hook documentation, not observed on a host.
2. If `REQUIRED_CHECK_DROPPED` removes the last remaining required context in a ruleset file, severity becomes **critical**.
3. If `JUDGE_UNPINNED` moves a pin to **floating**, severity becomes **high** (critical if it was the last non-floating pin on that workflow file).
4. `SURFACE_UNPARSEABLE` at head when base parsed: **high**.
5. Otherwise leave the rule's base severity — `warn`, except the producer-side `REQUIRED_CHECK_DROPPED` disjuncts, which base at `high` (spec 9), and the §10 exemption-channel severities (`CONFIG_RELAXED` at `.pinwash/allow.toml` is `critical`; `EXEMPTION_ADDED` is `critical` when an added record's `created` is after today, spec 11).

Default `fail_on` is **high**. `warn` findings do not fail the run. `critical` and `high` do. This matches checkwash’s “visible warn can still pass” so installing pinwash on a noisy docs edit of SKILL.md does not by itself brick merge until phrases hit and escalate — `SKILL_BYPASS` stays warn unless later spec says otherwise. v0: `SKILL_BYPASS` never escalates (phrase hits are review, not merge-block). `PERMISSION_WIDENED` escalates to **high**. `CONFIG_RELAXED` escalates to **high**; at `.pinwash/allow.toml` it is **critical** (§10). `EXEMPTION_ADDED` stays `warn`, except an addition whose `created` is after today, which is **critical** (§10, spec 11). Spec 9: a required check that can no longer run on any enforcement path is a dropped check, so its producer-side shapes block at the default `fail_on` (round 3 live warn-gap specimen: `# on: push` fired warn and the verdict stayed pass).

## 7. Findings envelope

When an engine ships, stdout JSON (UTF-8, sorted keys, `ensure_ascii=False`, `\n`) :

```json
{
  "pinwash_findings_version": 1,
  "run": {
    "base": "label",
    "head": "label",
    "pinwash_version": "0.0.0",
    "spec_version": 13
  },
  "verdict": "pass | block",
  "findings": [],
  "summary": {"info": 0, "warn": 0, "high": 0, "critical": 0},
  "config_errors": [],
  "unknown_coverage": []
}
```

Each finding:

| field | meaning |
|---|---|
| `rule` | §5 ID |
| `severity` | `info` \| `warn` \| `high` \| `critical` |
| `message` | stable English, no timestamps |
| `path` | repo-relative, forward slashes |
| `before` / `after` | optional short evidence strings |
| `locator` | optional, emitted only when non-empty: where the finding sits in its file (a §4 pin locator, a hook event or `<event>:<command>`, a job key or ruleset context, an MCP server or key path); the fingerprint's “locator if any” |
| `fingerprint` | `sha256` of canonical JSON: `rule`, path, locator if any, before digest, after digest; hex 64, emitted `rule/path/v1:<64hex>` |

`unknown_coverage` lists residual hits, inputs the engine read but did not evaluate, as objects `{ "path", "reason" }`, each (path, reason) once, sorted by `path`, then `reason`. `reason` is fixed text from this closed list (spec 13):

| Reason | Surface | Where |
|---|---|---|
| `multiline uses or scalar`, `yaml alias`, `docker uses`, `on triggers unresolved`, `continue-on-error value unresolved` | `gha_workflow` | §3.1 grammar hits |
| `hook stop liveness rests on an unresolved command` | `claude_settings`, `cursor_hooks` | §3.3 (R12) |
| `hook command target no longer resolved`, `hook command names a changed file it does not resolve` | `claude_settings`, `cursor_hooks` | §3.3 (R07) |
| `hook selector changed (not evaluated)` | `claude_settings`, `cursor_hooks` | §5.1 (R13) |
| `hook skip flag value not boolean` | `claude_settings`, `cursor_hooks` | §5.1 (R06) |
| `hook settings root disableAllHooks` | `claude_settings` | §5.1 (R06) |
| `hook command environment changed` | `claude_settings` | §3.3 (R07) |

A row never adds, drops or changes a finding, and does **not** change `verdict`. A gate that requires “no unknown coverage” is a consumer policy, not this spec.

Human report may degrade glyphs; machine JSON may not.

## 8. Exit codes

| exit | meaning |
|---|---|
| 0 | no finding at or above `fail_on`; engine finished |
| 1 | verdict `block` |
| 2 | engine error, including unexpected exceptions and unreadable git trees |

A crash must not exit 1. Parse failures of **subject** surfaces are findings (`SURFACE_UNPARSEABLE`), not exit 2, unless git itself cannot be read.

## 9. Determinism

- No floats in the verdict path.
- No network.
- No clock in findings JSON.
- CRLF→LF; JSON bytes identical on Windows / macOS / Linux for the same trees and Python 3.11–3.13 (grammar of JSON/TOML bounded subset, not of subject Python).
- No random.
- Zero runtime dependencies.

## 10. Exemptions

Base-side `.pinwash/allow.toml` only, per fingerprint, never per-rule-glob:

```toml
[[allow]]
fingerprint = "HOOK_REMOVED/.claude/settings.json/v1:…"
rule = "HOOK_REMOVED"
reason = "…"
author = "…"
created = "2026-09-27"
expires = "2026-12-24"
```

All six keys are required and non-empty; `created` and `expires` must parse with Python 3.11+ `date.fromisoformat` (ISO 8601 dates in extended, basic, or week form; not ordinal). "Today" is `PINWASH_TODAY` if set, else the current local date of the host running pinwash — the only clock that may affect a verdict, overridable for replay.

A record is **valid** when `expires` is at most 180 days after `created` and not before today (the expiry day itself counts; an `expires` before `created` passes the first condition). An **exemption** is a valid record. Records that fail validity are invisible to both checks below: deleting or editing one is not a finding, and adding one emits nothing.

A base exemption is **in force**, and drops the finding whose `fingerprint` and `rule` it names, only while `expires` is also at most 180 days after the earlier of `created` and today (spec 11). A `created` date in the future therefore cannot lengthen the window: no record is in force more than 180 days before it expires. Validity alone decides the checks below, so a future-dated record is visible when it is added and when it is edited or deleted, even on days it is not yet in force. A record is also not in force while another valid base record for the same `fingerprint` and `rule` has its `created` after today (spec 11). Records added in one change whose windows follow one another would otherwise keep one fingerprint exempt for more than 180 days after that change; that needs a record whose `created` is after the day it is added, and adding one blocks (below), while such records already in a base shrink to their last one. Renewing an exemption later with a fresh record is an ordinary addition (warn).

Head-side **append-only** valid additions emit `EXEMPTION_ADDED` at warn (visibility), or at **critical** when any added record's `created` is after today (spec 11). Editing or deleting a base exemption is `CONFIG_RELAXED` at critical; an edit is any change to a base exemption record, not only its removal. A head `allow.toml` that is missing or not UTF-8 cannot confirm any base exemption, so it counts as deleting all of them. A warn addition is in force on every later run whose base holds it, merged or only committed at the `HEAD` that `check` compares the worktree against: that pre-seed is residual R18 (#17).

The exemption channel never exempts its own findings (spec 11): `CONFIG_RELAXED` and `EXEMPTION_ADDED` at `.pinwash/allow.toml` are always reported. A record naming either one is still a valid record, so adding, editing, or deleting it is visible as above, but it drops nothing. `CONFIG_RELAXED` from `checkwash_config` (§5) is a different channel and stays exemptible.

## 11. Residuals (not silent passes)

These are expected non-findings. Each needs a THREATMODEL row before an engine ships. A row marked Closed without a fixture fails the suite (`tests/test_residual_rows.py` since spec 12, which also holds this table and THREATMODEL's to the same IDs).

| ID | Residual |
|---|---|
| R01 | Human terminal `git commit --no-verify` / host CLI that never consults repo hooks |
| R02 | Harness only in `$HOME`, SaaS UI, or gitignored `settings.local.json` |
| R03 | YAML aliases, multiline `uses`, reusable workflows |
| R04 | Vendored judge **bytes** patched without pin-record change |
| R05 | GitHub ruleset live on API, file not in trees |
| R06 | Hosts beyond the spec 6 surface set (Codex host config lives in `$HOME` → R02; Qoder; Copilot agent settings beyond `copilot-instructions.md`); unknown skip keys; `opencode.jsonc`; object-form `permission.bash` patterns; skip-flag values that are not the JSON boolean (§5.1) and settings-root `disableAllHooks` (#18). Since spec 13 both have an `unknown_coverage` row (§5.1) when a diff adds or changes them (`disableAllHooks` set or changed to a value other than absent or `false`), or when a §5 hook finding fires beside them; an unchanged value with no hook finding has none, and neither has an unknown skip key |
| R07 | Stub shapes outside the §5.2 closed body lists and outside the block-capability shape (judges whose base body never mentions `block`/`deny`; guarded one-liners; trailing comments on stub lines; a gutted head body that keeps `block` or `deny` in a comment, docstring, string, identifier or unrelated word, a dead branch that keeps the decision literal, or a `block` → `deny` swap, #11); opaque command forms (`python -m pkg.mod`, inline `-c` payloads, quoted paths with spaces, variable expansion); hook command targets absent from the tree or outside the §3.3 extension set (other extensions, case variants, no extension, suffixes such as `.bak`), whole-token quoted paths, and the body behind any unresolved command (#18). Since spec 13 a diff that moves a resolved command out of §3.3's sight, or changes a file an active command names but does not resolve, reports `unknown_coverage` (§3.3); and so does a root `env` key the diff changes that an active command of the same file expands; silent still: bodies reached indirectly (imports, build outputs not in the tree, directory runners, an environment set outside the file), rewrites of CRLF line endings or of the executable bit only, paths not spelled as the repo-relative path at §3.3's boundaries (after a `cd` or `--directory`, `./`, `..` or `//` inside the path, an inner quote, globs, case variants), the module spellings `-mpkg.mod` and `-m "pkg.mod"`, and a gut behind a command an earlier diff respelled — the import-time `sys.exit(0)` attack is in scope since spec 4, the shape-preserving gut job since spec 7 |
| R08 | `SKILL_BYPASS` missed paraphrases; also false hits on non-excluded docs |
| R09 | Required check context renamed in GitHub but job `name:` unchanged, or the reverse, when no ruleset file exists |
| R10 | Pinwash itself disabled by not running pinwash |
| R11 | Shell composition around a hook command that still resolves to its judge (§3.3), or around a target-free command: status or output masking after it (`\|\| true`, `; exit 0`, `\| cat`, `> /dev/null`, a newline), or output appended on success (`&& echo ok`); no-op or short-circuit prefixes other than a leading `#` (`:`, `true \|\|`, `echo`, `exit 0;`, `false &&`); a §5.2 stub followed by a comment naming the judge; argument, verb, interpreter, input or environment-prefix changes (`--help` per §5.2, `cat`, `timeout 0`, `< /dev/null`) (#9) |
| R12 | Hook judge identity changes with no same-path body comparison: a rename or repoint to a file that cannot refuse; a wrapper launcher that takes the unchanged judge as an argument; a retarget to a command §3.3 does not resolve; a quoted no-space path gutted in place; a judge command removed while a sibling stays; a sibling added in the diff that keeps the §6.1 escalator off (#10). Ruled in spec 13 (AI-assisted): an unresolved command is live for §6.1 under §5.2's test; a Stop-like hook finding kept below critical only because an unresolved command counts live, or a diff after which the file's Stop liveness rests only on unresolved commands, reports `unknown_coverage` (§3.3), and so does a replace or retarget into an unresolved command; a sibling added in the diff stays live, and counting it as not live is this row's detection candidate. No row for a resolved sibling added in the diff, a retarget to a gutted resolved copy, or a judge removed while another command of its Stop event stays live, when the judge did not resolve or a remaining live one does (a plugin's own Cursor `stop` command, for one) |
| R13 | Hook selector changes with the command kept, on `claude_settings` and `cursor_hooks`: `matcher` narrowed, replaced, added, case-flipped or set to a pattern that never matches, also when the command text changes in the same edit; a per-hook `if`; handler `type`. Which tools and events these keys govern on a host is INFERRED (#12). Since spec 13 each such change is an `unknown_coverage` row, never a finding, when the command is live on both sides and keeps its §3.3 targets or its string (§5.1); a command that changes both in the same edit stays here and in R12 without a row. Ruled (AI-assisted, spec 13): the §5.3 `cursor_hooks` row and §5's two matcher phrases are withdrawn; detection waits for executed host evidence of matcher semantics and a design for regex spellings |
| R14 | Required-check producer skipped while its job, `name:` and triggers remain: `push` / `pull_request` configuration (`paths`, `paths-ignore`, `branches`, `branches-ignore`, `tags`, `types`); job `if:` values the engine does not read as false (it reads `false` and `${{ false }}`, quoted or not, in any letter case; §5 names `false` and `'false'`), job-scope event filters included; `needs:` on a job that is skipped or fails (#13). Recorded for a later ruling: whether §6's "a required check that can no longer run on any enforcement path is a dropped check" makes these shapes `REQUIRED_CHECK_DROPPED` |
| R15 | Required-check producer step contents: step `if:`, `continue-on-error:` and `shell:`; `run:` text (`\|\| true`, `set +e`, a check step replaced or deleted); step `with:` inputs; `defaults.run.shell`; deleted local or ref-less actions. Weakened CI test commands are checkwash's question (§0, §15) (#14) |
| R16 | Required-check linkage drift with a ruleset file: a producer's `name:` added, changed (literal, expression or case) or removed; a head job, new or existing, claiming a ruleset context; matrix-suffixed contexts; drops on a producer no longer linked at base (a rename already merged, or a base `name:` that is an expression) (#15). R09 keeps the no-ruleset case as worded |
| R17 | Permission and auto-approval changes outside the §5.3 closed comparisons: on `claude_settings`, other `permissions.allow` spellings (tool-wide, flagged, interpreter, path, MCP), `deny` / `ask` removals, other `permissions` keys, `permissions.defaultMode`, modes outside the lattice or removed, `enableAllProjectMcpServers`, `sandbox.autoAllowBashIfSandboxed`; gemini `approvalMode` and opencode `permission.<tool>` values outside their lattices (#16); `"disabled": true` deleted from a `cursor_mcp` server that stays (#26) |
| R18 | Exemption pre-seed: a valid `allow.toml` record that reached a base through an `EXEMPTION_ADDED` warn drops every later finding with its `fingerprint` and `rule` while in force; that base can be the session's own commit, which `check` reads when it compares the worktree against `HEAD`, so no merge is needed. Any fingerprint can be computed before the weakening exists; those without content or severity (hook event removed, command list or array emptied, skip flag added, `permissions.allow gained Bash(*)`, `SURFACE_UNPARSEABLE`) are the same in every repository for that path and event and cover every repeat, the critical form included; `lost block capability` keys only on the command string (#17 A12, S3, S4) |
| R19 | Parse-status pairs with an unparseable side that no rule reads (§3): (unparseable, ok), where the base is never compared, so a head that repairs the file and weakens it in the same edit passes (on `gha_workflow`, a base tab removed while pins, jobs or triggers weaken; a corrupt `gha_ruleset` links no producer), and on `claude_settings` permissions, `cursor_mcp`, `gemini_settings` and `opencode_config` the head is not compared either, so a head that blocks against an absent base passes (`checkwash_config` and the markdown surfaces compare it as against an absent base); (missing, unparseable), a new surface file pinwash cannot parse; (unparseable, missing), a corrupt base file deleted (#22, #25) |
| R20 | Workflow syntax outside the bounded grammar (§3.1): quoted keys other than `on` (a quoted `on:` key is reported as unknown `on triggers unresolved`), `key :` spacing, flow-style job bodies, JSON-syntax workflows (#23); job keys not at indent 2 or job bodies not at indent 4, and a top-level key after `jobs:` read as a phantom job (#24); honest requotes or reindents read as removals; the tab rule's costs: honest tabs (in values, comments, heredocs) that make a file unparseable, and an unparseable base, after which later weakenings in that file show only as the one both-sides warn while the tab stays, and as nothing when the same edit removes it (R19) (#25) |
| R21 | Untracked surface files hidden from worktree mode: `check` reads tracked files and the untracked files no ignore rule matches, so a surface file that an agent-writable ignore source (a worktree `.gitignore`, `.git/info/exclude`) matches is not read, and a new `.mcp.json` with `autoApprove: ["*"]` listed in `.gitignore` passes. R02 keeps the gitignored `settings.local.json` (#17) |

R07 is the important “GATE_STUBBED in the Python file” hole. Since spec 4 the engine stub-checks both the **command string** in JSON and the §3.3-resolved target **file bodies** (§5.2 closed lists; block-capability shape since spec 7). The shapes in the R07 row above stay residual; spec 12 added the head-side marker retention that defeats the block-capability shape (#11) and the targets §3.3 does not resolve (#18), while judge identity changes and shell composition around a judge that still resolves are R12 and R11. Closing more of them is a spec bump.

Rows R11–R21 and the spec 12 additions to R06 and R07 book the open red-team families (#9–#18, #22–#25, and #26 item 3 in R17) under the maintainer's 2026-10-09 direction: book first, detect later. Each row is a pointer; the issue and its executed-reproduction comment hold the members and the evidence. Spec 12 changes no verdict on these shapes and adds no `unknown_coverage` reason for them. Where a row names an input the engine cannot observe, §1.6 asks for one; spec 13 routes the hook-side inputs (R06, R07, R12, R13: §3.3, §5.1, §7), the workflow, permission, parse-status and exemption inputs follow in later bumps, and detection after the routing, one family per bump. A row's `unknown_coverage` reason closes nothing: the row stays Open.

## 12. Preregistered v0 engine acceptance

An implementation may call itself pinwash v0 only if **all** of the following hold. They cannot be edited to match the code.

| # | Criterion |
|---|---|
| A1 | `python -m pinwash check BASE..HEAD` on a fixture repo; stdlib unittest; no network |
| A2 | Fixture `last-stop-removed`: base has Claude `Stop` command, head deletes it → `HOOK_REMOVED` critical, exit 1 |
| A3 | Fixture `pin-to-main`: `uses: org/tool@v1.2.3` → `uses: org/tool@main` → `JUDGE_UNPINNED` high, exit 1 |
| A4 | Fixture `pin-to-sha`: `@v1.2.3` → `@` + 40 hex → no `JUDGE_UNPINNED` |
| A5 | Fixture `stub-stop`: command becomes `echo {}` → `GATE_STUBBED`, exit 1 if it was the last Stop |
| A6 | Fixture `skill-skip-line`: SKILL.md adds `skip tripwire` → `SKILL_BYPASS` warn, exit **0** (warn < default `fail_on`) |
| A7 | Fixture `ruleset-drop`: required context `tripwire` removed → `REQUIRED_CHECK_DROPPED` critical, exit 1 |
| A8 | Fixture `honest-docs`: README wording change only → exit 0, empty findings |
| A9 | Unreadable `.git` → exit 2, not 1 |
| A10 | Findings JSON byte-identical on two OS fixtures for A2 (CRLF subject files included) |
| A11 | This SPEC file is not modified by the engine PR that first satisfies A1–A10 |

No public 1.0 claim is licensed by meeting A1–A11.

## 13. Default CLI (when implemented)

```
pinwash check [RANGE]
pinwash check              # worktree vs HEAD
pinwash --version
pinwash doctor             # own tests / spec hash; does not judge the subject
```

`doctor` passing is not a subject pass.

## 14. Claims policy

- Do not say pinwash “secures agents” or “stops jailbreaks”.
- Do not say a repo “has an intact harness” because pinwash exited 0.
- Do not treat pinwash as tripwire, or tripwire as pinwash.
- Quote run labels, spec version, and pinwash revision with every measurement.

## 15. Non-goals for spec v0

- Enforcing hooks (tripwire).
- Parsing Python/JS hook bodies (R07).
- LLM classification of skills.
- Live GitHub / Cursor API reads.
- Replacing checkwash CI/test rules.
- Auto-fixing the diff.

## 16. Spec changelog

- **13** — Hook routing bump (taipei49314/pinwash#9, #10, #12, #18, #26 item 6; every ruling in this row is AI-assisted, under the preamble's delegation of 2026-10-09). **Recorded no-bump fix (#10, #9).** The engine commit right before this one pairs hook commands by command string as well as by list index, following §5, §5.1 and §5.2 as written (spec 12's row left it for its own ruling): the body-stub and comment-out branches pair with the base command at the same index first, then with the same string wherever it stood at base (a comment-out with the base command whose exact text the `#` prefixes, when that command lost an occurrence); the block-capability shape needs no pairing and lost its list-index guard; the string-stub branch keeps the index alone. It is monotone: every finding spec 12 emitted keeps its rule, severity, message, `before` / `after`, locator and fingerprint, and where the string pairing fires below the base list length on a command that also lost block capability the finding stays spec 12's "lost block capability", so a base exemption naming it still matches. Passes that became blocks, each where the same edit at the original index already blocked: a judge gutted behind an inserted sibling that is disabled or `failOpen`, a target-free judge commented out behind a new stub-body sibling, and the shifted twin of the spec 7 shape's honest false positive (a judge refactored to move `block` into a helper) where nothing live remains. No block became a pass. The shifted comment-out pairs only on the exact text (`# T (paused)` behind an inserted sibling stays R12). **R12 liveness (#10).** §3.3, §5.2 and §6.1 now state the engine's rule rather than the reverse: a command §3.3 does not resolve is live for §6.1 unless its string or skip flags make it not live, the whole §5.2 test is written out, and the count is per file. Rejected: counting unresolved commands as never live, which blocked honest restructurings in real repositories, where most hook commands do not resolve. Left to R12's detection bump: live only if present at base, never live if added in the diff, or live if added only when it resolves to a body that can refuse. New reason `hook stop liveness rests on an unresolved command` (§3.3): a Stop-like hook finding kept below critical only because an unresolved command counts live, or a diff after which the file's Stop liveness rests only on unresolved commands. Which reason covers each form: a replace or retarget into an unresolved command is `hook command target no longer resolved` (and also the liveness reason on a Stop-like event when no resolved live command stays); a judge removed beside a pre-existing unresolved sibling, so that the file's Stop liveness rests on unresolved commands only, and a Stop-like finding kept at warn by an unresolved command are the liveness reason. Without a row still: a resolved sibling added in the diff, a retarget to a gutted resolved copy, and a judge removed while another resolved live command of its Stop event stays (R12). **#12.** §5.1's row "matcher string `*` removed and command list emptied" is withdrawn: it never fired, because `HOOK_REMOVED` covers the shape first; its dead branch is deleted, with no output change. §5.3's `cursor_hooks` row and §5's phrases "empty matcher that never fires" and "Cursor hook `matcher` widened then command removed" are withdrawn: selector changes with the command kept (`matcher`, per-hook `if`, handler `type`, a nested `matcher`) are R13 and report `hook selector changed (not evaluated)` (§5.1), never a finding. Values compare through a canonical encoding built on an explicit stack with object keys sorted, so key order is no change and a value nested at any depth reads the same on 3.11–3.13. The name-list superset exemption reads `|` as alternation, which is INFERRED. No detection is scheduled; it reopens only with executed host evidence of matcher semantics and a design for regex spellings. **#18.** `hook command target no longer resolved` (a resolved active command left §3.3's sight in an event present on both sides) and `hook command names a changed file it does not resolve` (an active command names a changed path that is not one of its own targets on that side; compared after CRLF→LF, `\` read as `/`, plus the closed `-m` module mapping), both diff-scoped. Rejected: a standing per-file "unresolved" row, which reports on unchanged trees. The `$CLAUDE_PROJECT_DIR` prefix resolution is its own later detection bump, after an FP pass on real histories of such hooks, adversarial verification of the closed forms (with a guard for a settings `env.CLAUDE_PROJECT_DIR`), a ruling on the spec 7 exit-code refactor false positive it would multiply, and the #10 ruling above. `hook skip flag value not boolean`: an (event, command, key, value) occurrence more frequent at head than at base, counted as a multiset, or a §5 hook finding in a file where either side holds one. `hook settings root disableAllHooks`: a root value the diff sets or changes to anything but `false`, or a value other than absent or `false` on either side while a §5 hook finding fires in the file. The §5.1 `HOOK_BYPASSED` row for `disableAllHooks: true` is its own later detection bump, after rulings on cross-file precedence between the two settings files, on whether a head `true` zeroes the §6.1 live count, on its content-free fingerprint (R18), and on an unchanged base `true` (with hooks off at base, removing or gutting the disabled Stop hook already blocks critical). Booked in R07, not routed: an `env` key that points a hook command elsewhere, and a change of the executable bit only, which the trees do not carry. **#26 item 6.** The Stop-like set is closed and case-sensitive per surface (§6.1): `Stop` on `claude_settings`, `stop` on `cursor_hooks` (the engine's Cursor set also held `Stop`, `finish` and `afterAgentResponse`). Passes that become blocks: on `cursor_hooks`, the `stop` judge removed, stubbed, gutted or skipped while a hook under `afterAgentResponse`, `finish` or `Stop` stays, or moved to one of those names; this includes an honest edit, removing a `stop` hook that is no gate (a notification) while an `afterAgentResponse` hook stays, which has the attack's bytes. Blocks that become passes: removing or stubbing the last hook under `afterAgentResponse`, `finish` or `Stop`, now `warn`. Still open (R12): the judge removed from `stop` while another `stop` command stays (a plugin's) gives no finding. **§7.** `unknown_coverage` lists residual hits from the §3.1 grammar and the hook rows above; `reason` is fixed text from a closed list, each (path, reason) once, sorted by path, then reason; a row never adds, drops or changes a finding and never changes `verdict`. R06, R07, R12 and R13 say which of their members now have a row; every row stays Open. Apart from #26 item 6, no rule ID, severity, message, locator, fingerprint or verdict changed: the hook rows are new `unknown_coverage` entries only. `tests/test_hook_routing.py` pins the rows and the withdrawn matcher row, `tests/test_spec_statements.py` the Stop-like set and the closed reason list; one non-gate test (`finish` as a second Cursor Stop-like event) was rewritten. **Adversarial review of this bump (AI-assisted rulings).** A narrowing of one command could hide behind a sibling's widening of the same script, because selectors were judged over the union of a target set: commands now pair by string first, each string judged on its own. `hook command target no longer resolved` compared the replacement against every base command, flagged ones included, so enabling an unresolved sibling staged disabled in an earlier diff replaced a judge silently: the comparison is now against commands active at base. The changed-file comparison and the §5.2 body checks folded a lone CR to LF, so rewriting a shell judge's line feeds to lone CRs (one line, run by the shell as a `#!` comment, a gutted judge) read as unchanged: the changed-file row now folds CRLF only, and a `.sh` / `.bash` body splits lines at LF and CRLF only (§5.2), so that rewrite is a stub body, `GATE_STUBBED` (a pass that becomes a block; Python, JavaScript and PowerShell read a lone CR as a line break, so their bodies still fold it). The env redirect a hook command expands is routed as `hook command environment changed` (the env-redirect amendment, which this row first left booked). Honest-edit noise removed: `-` is a matcher name character (kebab-case agent names, MCP server names), a head matcher that matches everything (absent, `""` or `*`) is a widening, and a dropped per-hook `if` only widens; each is INFERRED host semantics, and none can hide a narrowing. The changed-file test is linear in command length. Disclosed rather than changed: in a repository that uses `"$CLAUDE_PROJECT_DIR"/...` commands, the changed-file row appears on every edit of a hook script until that prefix is resolved; an honest Cursor `stop` notifier removed beside an `afterAgentResponse` hook blocks (#26 item 6, above).
- **12** — Booking bump, text only (taipei49314/pinwash#9–#18, #22–#26; maintainer direction 2026-10-09: book first, detect later, one family per detection bump; the booking is split into consecutive bumps for review, and this is the first; that split and every other ruling in this row are AI-assisted, under the preamble's delegation as extended on 2026-10-09, which this version records). §11 and THREATMODEL gain one Open row per red-team family, same ID and wording in both: R11 shell composition around a hook judge that still resolves, or around a target-free command (#9); R12 hook judge identity changes with no same-path body comparison, recording for a later ruling that §3.3 says unresolved forms are not invented as live judges while §5.2's not-live list does not name them and the engine counts them live (#10); R13 hook selector changes with the command kept, recording for a later ruling that the §5.3 `cursor_hooks` row calls one such narrowing `HOOK_BYPASSED` while no §5.1 row reads it and the engine emits nothing (#12); R14 a required-check producer skipped while its job, `name:` and triggers remain, recording for a later ruling whether §6's dropped-check sentence covers these shapes (#13); R15 producer step contents (#14); R16 required-check linkage drift with a ruleset file, R09 left as worded so its default-Permanent reading keeps its meaning (#15); R17 permission and auto-approval changes outside the §5.3 closed comparisons (#16, #26 item 3); R18 exemption pre-seed, the session's own commit as base included (#17 A12, S3, S4); R19 parse-status pairs with an unparseable side that no rule reads, a base tab removed in the same edit as a weakening included (#22, #25); R20 workflow syntax outside the bounded grammar and the tab rule's costs, a row of its own because R03 holds the constructs §3.1's residual list already names as UNKNOWN coverage (#23, #24, #25); R21 untracked surface files an agent-writable ignore rule hides from worktree mode, a row of its own because R02 is default Permanent (#17). R07 gains head-side marker retention (#11) and the targets §3.3 does not resolve (#18); R06 gains non-boolean skip-flag values and settings-root `disableAllHooks` (#18). §3, §3.1, §3.3, §5 (`HOOK_BYPASSED`), §5.1, §5.2, §5.3 and §10 point their residual sentences at the rows, and §11 says what the rows are; §3 also says the engine emits `SURFACE_UNPARSEABLE` for no other status pair and leaves open whether §3.2's non-UTF-8 sentence reaches a checkwash config absent at base (#22). §3.1 states the tab rule the engine has applied since spec 0 — a tab before a line's first `#`, or anywhere on a line without one, makes the workflow unparseable — and why it is not narrowed to indentation (#25, option (i)). The old line ("spaces only; tabs → `SURFACE_UNPARSEABLE`") sat under indentation tracking without limiting tabs to it. The spec 11 ledger (ARCHITECTURE §10) read it as indentation only and tagged the engine as beyond the text; #25 reads it as ambiguous, and the codification rests on that reading, under which it changes no verdict and reverses no text. Ruled (AI-assisted): the old line is ambiguous, and the codification stands (ARCHITECTURE §10). #26, delegated items, each stating what the engine already does: the §5.3 `opencode_config` row uses the lattice the §5.3 lattice sentence, the engine and `test_opencode_ask_to_allow_fires` already use, so `deny` → `ask` is named (item 2); the §5.3 `cursor_mcp` row states the engine's comparison (a server new at head and not `disabled: true`, a created file included; `true` → `false`; `"*"` gained), and deleting `"disabled": true` is booked in R17 (item 3); §7 lists the optional `locator` field the engine emits (item 4); §4's example carries the `#<n>` suffix and says what it counts (item 5); rows 5 and 6 below cite ARCHITECTURE §9 items 3 and 2 (item 8); §2 drops the sentence on spans, which no field carries (item 9). §11's "A row marked Closed without a fixture fails the suite" had no test; `tests/test_residual_rows.py` now enforces it, holds both tables to one ID set, and requires the IDs to run from R01 in order through at least R21, so a booked row cannot be dropped without a test change. `tests/test_spec_statements.py` pins what the §5.3 `cursor_mcp` row, the §3.1 tab rule and the §4 `#<n>` sentence state. No engine behaviour, rule ID, locator, fingerprint, severity or envelope field changed: `pinwash/**` changes only `SPEC_VERSION`, and `run.spec_version` is the only change in `check` output. Not in this bump, each listed in ARCHITECTURE §10 with its route: the index pairing of the body-stub, block-capability and comment-out branches (#10's index shift, and #9's `#` comment-out at a shifted list index), an engine defect against §5, §5.1 and §5.2 rather than a residual, left for its own AI-assisted ruling because the fix turns passes into blocks; #12 member 2 (the unreachable §5.1 matcher row), the #16 `dontAsk` direction and top-level `permissionMode` key, #17 S4's session pass definition, and #26 items 1, 6 and 7 (each for its own later AI-assisted ruling); #17 S4's `BASE..WORKTREE` contract range (a later §2 / §13 bump); #14's step-level `continue-on-error:` block scalar, #15's reusable-workflow producer and #26 item 10 (engine-only, no bump). Routing the inputs these rows name that the engine cannot observe to `unknown_coverage` follows in spec 13 and later; detection after that, one family per bump.
- **11** — §10, §5 `CONFIG_RELAXED` / `EXEMPTION_ADDED` rows and preamble, §6: the exemption channel never exempts its own findings, and a record exempts only within 180 days of the earlier of `created` and today (taipei49314/pinwash#17; maintainer ruling: S1 and S2 are bugs against §10). S1: a base record naming the constant `CONFIG_RELAXED` fingerprint of `.pinwash/allow.toml` silenced every later edit or deletion of exemptions, and one naming the `EXEMPTION_ADDED` fingerprint every later addition, while they stayed valid; such records stay valid and visible but drop nothing. S2: the cap was measured from the record's self-declared `created`, so `created = "9999-01-01"`, `expires = "9999-06-30"` exempted on every date until 9999-06-30; a record is now in force only while `expires` is at most 180 days after `min(created, today)`. Because in force is per record, records dated in the future could be chained so their windows follow one another: adding a record whose `created` is after today is `EXEMPTION_ADDED` at **critical** with its own message (`head allow.toml adds a record whose created date is after today`), and a base record is not in force while another valid record for the same fingerprint and rule is dated after today, so chains already in a base shrink to their last record. §10 now states the validity rule the engine has applied since spec 0 (six required keys, ISO dates, `expires` at most 180 days after `created`, not expired), the date parser, the host-local clock, and the fail-closed reading of a missing or non-UTF-8 head `allow.toml`; validity, and so what the `EXEMPTION_ADDED` / `CONFIG_RELAXED` checks see, is unchanged. The §5 `CONFIG_RELAXED` row now names the `allow.toml` trigger §10 already defined, and §5/§6 name its `critical` severity. Date arithmetic uses day differences, so a `created` near 9999-12-31 no longer overflows into exit 2. Issue #17's A12 (plant then weaken through a warn; not a §12 criterion), S3 (content-free fingerprints) and S4 (in-session self-authorization) keep the classification #17 gave them (consistent with SPEC as written). `CONFIG_RELAXED` from `checkwash_config` stays exemptible. No rule ID, locator, fingerprint, or envelope-field change.
- **10** — §5.1 is the exact table of what the engine detects: `"disabled": true` and `"hookEnabled": false` apply to both hook surfaces (the §5 row already named `hookEnabled`; §5.1 omitted it and scoped `disabled` to `cursor_hooks`), and skip flags are judged per command instead of as one per-event aggregate. The aggregate fired `HOOK_BYPASSED` when a new, already flagged sibling was added next to unchanged commands, depending on which flag name it carried, and missed a live command renamed and flagged when the same flag name already existed elsewhere in the event (taipei49314/pinwash#5, #6). Severity, message, locator and fingerprint fields are unchanged.
- **9** — Producer-side `REQUIRED_CHECK_DROPPED` severity `warn` → `high` (§5 preamble exception, §5 row severity note, §6.5): the deleted-job, `if`-disable, `continue-on-error`, and trigger-loss disjuncts now base at `high`, so a required check that cannot run on any enforcement path blocks at the default `fail_on=high`. Found as the round 3 warn-gap (opencode zen bench, `pinwash-live/round3`): the live trigger-loss specimen (`on: push` → `# on: push`) fired warn and the verdict stayed pass while the check could never gate again. Ruleset-side drops are unchanged (`warn`; `critical` per §6.2). No grammar, surface, or rule-ID change.
- **8** — `REQUIRED_CHECK_DROPPED` gains the trigger-loss disjunct, found live in round 2 (opencode zen bench, `pinwash-live/round2`): a producing job's workflow that drops `push`/`pull_request` from `on:` (live escape: `on: push` → `on: workflow_dispatch`) leaves the required context with no enforcement-path run, so the job's survival, `if:`, and `continue-on-error` disjuncts all stay silent while the check can never fire. §3.1's bounded grammar gains closed `on:` trigger forms (inline scalar/list, block list items and mapping keys at indent 2); unresolvable `on:` blocks are residuals (`on triggers unresolved`), never treated as an observed removal.
- **7** — §5.2 block-capability shape, found live in round 1 (opencode zen bench, `pinwash-live/round1`): a §3.3 target whose base body mentions `block`/`deny` but whose head body mentions neither fires `GATE_STUBBED` ("lost block capability") and counts as not live for the last-Stop escalator. Closes the shape-preserving gut job (function frame kept, decision logic removed) that the closed-line list structurally could not see. Residual stays: judges whose base body never mentions block/deny.
- **6** — R06 first closing wave (ARCHITECTURE §9 item 2): new surfaces `gemini_settings` (`.gemini/settings.json`) and `opencode_config` (`opencode.json`) with closed §5.3 widening rows (`autoAccept`, `approvalMode`, mcp `trust`; `permission.<tool>` lattice `deny > ask > allow`), and `agent_markdown` widened to the Gemini/Qwen/Copilot/Windsurf/Cline instruction files (`GEMINI.md`, `QWEN.md`, `.github/copilot-instructions.md`, `.windsurfrules`, `.clinerules`). Grounded on real files on the maintainer host (`opencode.json` permission blocks; boundkit’s `GEMINI.md` and `.github/copilot-instructions.md`). Residuals: `opencode.jsonc`, object-form `permission.bash` patterns, Codex repo-level config (Codex keeps host config in `$HOME` → R02), all further hosts.
- **5** — Bounded GHA grammar widened (first ARCHITECTURE §9 item 3 widening): recorded values truncate at the first ` #` (space-hash), the bounded form of a YAML inline comment. Found by live-fire on taipei49314/checkwash: sha-pinned `uses:` lines annotated `# vX.Y.Z` classified as floating, so honest release annotation bumps fired `JUDGE_UNPINNED` critical. With truncation, shas classify as `git_sha`; annotation-only bumps are silent; genuine floats still fire.
- **4** — R07 narrowed by implementation: §3.3 defines the closed rule by which hook `command` strings resolve to repo-relative target files, restored to the `claude_hooks` surface; §5.2 defines closed per-extension body stub sets, and `GATE_STUBBED` fires when a base non-stub body becomes one; the §6.1 last-Stop escalator treats body-stubbed commands as not live. The import-time `sys.exit(0)` attack named in R07 is now in scope; R07 stays Open for shapes outside the closed lists.
- **3** — Honesty sync and the command-target ruling: the preamble states a local engine exists and records the 2026-09-27 delegated edit authority; the `claude_hooks` surface is narrowed to `.claude/hooks/**` (hook `command` strings are not resolved to repo-relative target files — moved into R07’s bump scope). Engine behavior is unchanged by this version.
- **2** — §1.6 rewritten: the undefined `INCOMPLETE` token is gone; the fail-closed invariant (missing observation is never a pass) now names the three channels that carry it (`SURFACE_UNPARSEABLE`, `config_errors`, `unknown_coverage`). No detector or envelope change.
- **1** — `EXEMPTION_ADDED` formalized as a §5 rule (it was named in §10 but missing from the §5 closed set). §10 now states that only records satisfying the validity rule count as exemptions for the addition check and the edit/delete check, and that an edit is any change to a base exemption record.
- **0** — initial freeze (first commit of this file).
