# pinwash SPEC — frozen contracts

**One sentence:** pinwash flags a Git diff that makes an agent more able to claim done by weakening the verification harness around it.

**一句話：** 標出會讓 agent 比較容易自稱完成的 harness 變更。

This file is the single source of truth for rule IDs, pin identity, surfaces, severity, exit codes, and determinism. Changing anything here requires a spec-version bump and a fixture re-run. Authority: the human maintainer owns `tests/gates/**`; on 2026-09-27 the maintainer delegated spec rulings and edits to the maintaining agent, under the discipline that every change bumps the spec version, lands as its own commit, and re-runs the fixture suite.

Spec version: **10** (draft spec 0 was frozen by the first commit of this file; the findings envelope is `pinwash_findings_version: 1`). A local engine exists (`pinwash` 0.0.0, stdlib only, zero runtime dependencies); it is not a Release, not on PyPI, and not a 1.0 claim. This document began as the preregistration: acceptance in §12 was frozen before implementation. Detectors must not be patched to fit a fixture; fixtures that are out of spec stay residuals.

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

Paths are normalized to forward slashes. Comparison text is CRLF→LF before parse. Spans are character offsets into that normalized text.

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

If a surface file existed at base and is unparseable at head under that surface’s parse, emit `SURFACE_UNPARSEABLE` (high). Do not skip the file. If it was also unparseable at base, emit `SURFACE_UNPARSEABLE` at warn (no new information).

### 3.1 Bounded line grammar (GitHub Actions YAML)

v0 does not ship a YAML parser. On each workflow file, after CRLF→LF:

- Drop lines whose first non-space is `#`.
- Track indentation width (spaces only; tabs → `SURFACE_UNPARSEABLE` for that file).
- Record:
  - `uses:` value (strip quotes) at any indent.
  - `continue-on-error:` value `true` / `false`.
  - `if:` value as raw remainder of the line.
  - `name:` at job indent (the first `name:` under a `jobs:` key at indent 2, using a stack).
  - Job keys: a line matching `^  [A-Za-z0-9_-]+:\s*$` under `jobs:`.
  - `on:` triggers (spec 8), at column 0 only: inline scalar, inline `[a, b]` list, block list items (`- item`) at indent 2, block mapping keys (`key:`) at indent 2. Deeper lines under a trigger are trigger configuration, not triggers. A second top-level key ends the `on:` block.

Every recorded value is **truncated at the first ` #`** (space followed by `#`) — the bounded form of a YAML inline comment. A `#` without a preceding space is kept. Spec 5 added this truncation after live-fire on a real repository showed sha-pinned `uses:` lines annotated `# vX.Y.Z` classified as floating, so honest release annotation bumps fired `JUDGE_UNPINNED`. Residual: a quoted value that legitimately contains ` #` truncates at the wrong point.

**Residuals (not findings, not passes):** YAML aliases (`*anchor`), multiline `>` / `|` scalars, `uses` split across lines, `true` written as `yes`, jobs generated by reusable workflows, `workflow_call` indirection, and an `on:` block whose forms the grammar cannot resolve (flow mapping `on: {…}`, unrecognized items → recorded as unknown `on triggers unresolved`, never treated as an observed trigger removal). Those are `UNKNOWN` coverage, documented in THREATMODEL, never invented as “no `uses` change”.

### 3.2 Bounded TOML (checkwash config)

v0 reads only:

- `[detectors]` or equivalent key/value `detect_* = false` / `disable = ["RULE"]` if present as a single-line assignment.
- `fail_on = "..."` single-line.

Full TOML 1.0 is a residual. Unknown keys are ignored. A file that does not parse as UTF-8 is `SURFACE_UNPARSEABLE`.

### 3.3 Hook command target resolution

A hook `command` string (from `claude_settings` or `cursor_hooks` JSON, on a given side) resolves to target files as follows, and nothing else: strip surrounding quotes; replace `;`, `&`, and `|` with spaces; split on whitespace. A token is a target iff it fully matches `[A-Za-z0-9_./-]+\.(py|sh|bash|js|mjs|cjs|ps1)`, does not start with `/`, `-`, or `~`, and names a path present in that side's tree after path normalization. Resolved targets are `claude_hooks` surface members for the §3 parse-status check and the §5.2 body check, in addition to `.claude/hooks/**` paths.

Residuals: module-form commands (`python -m pkg.mod`), quoted paths containing spaces, tokens with variable expansion (`$HOME/...`), inline `-c` payloads, and targets absent from the tree. None of these are invented as stubs or as live judges.

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

`locator` examples: `gha_workflow:.github/workflows/tripwire.yml:uses:taipei49314/greenwash`, `declared_pins:greenwash`.

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

Base severity of every finding is `warn`, except the producer-side disjuncts of `REQUIRED_CHECK_DROPPED` (spec 9), which base at `high`. Escalators in §6 may raise a severity. Detectors are not configurable except disable-whole, and disable-whole on the **head** config does not apply to the current run (§1.2).

| Rule ID | Trigger |
|---|---|
| `HOOK_REMOVED` | A named hook event that existed at base on `claude_settings` or `cursor_hooks` is absent at head, **or** its command list is empty. Renaming the event (`Stop` → `stop` if the host is case-sensitive — treat Claude `Stop` / `PreToolUse` as exact). Adding hooks is not this rule. |
| `HOOK_BYPASSED` | An existing hook **remains named** but a skip was introduced: Claude `hooks` entry replaced by an empty matcher that never fires; Cursor hook `matcher` widened then command removed; command prefixed with a no-op; JSON `disabled: true` / `"hookEnabled": false` added. Host-specific keys are an exact table in §5.1. |
| `GATE_STUBBED` | A remaining hook `command` at head is a **stub** (§5.2) and the base command was not a stub; **or** the command resolves per §3.3 to target file(s) whose body is a stub (§5.2) while the base command resolved to a non-stub body. |
| `JUDGE_UNPINNED` | A pin identity weakened per §4. |
| `PERMISSION_WIDENED` | A permission or auto-approval set grew per §5.3. Shrinking is not a finding. |
| `SKILL_BYPASS` | An **added or edited** line in `skill_md` or `agent_markdown` matches the bypass phrase table (§5.4). Deletions of such lines are not a finding. |
| `REQUIRED_CHECK_DROPPED` | A required status context named at base in `gha_ruleset` is missing at head; **or** the workflow job that produced that `name:` was deleted / `if: false` / `if: 'false'` introduced / `continue-on-error: true` introduced on that job; **or** (spec 8) the workflow that contains the producing job included `push` or `pull_request` in its `on:` triggers at base and includes neither at head, so the context loses every enforcement-path run. An `on:` block the grammar cannot resolve is a residual (§3.1), not an observed removal. **Severity**: ruleset-side drops are `warn` (`critical` per §6.2 when the last remaining context goes); the producer-side disjuncts — deleted job, `if` disable, `continue-on-error`, trigger-loss — base at `high` (spec 9). |
| `CONFIG_RELAXED` | Base-absent or edited `checkwash_config` **disables** a detector or raises `fail_on` above the base value (or above default `high` if base file missing). Tightening stays silent. |
| `EXEMPTION_ADDED` | A valid (§10) `.pinwash/allow.toml` record present at head and absent at base. Visibility only: head-side records never govern the current run (§1.2). |
| `SURFACE_UNPARSEABLE` | See §3. |

No other rule IDs exist in this spec version. Internal helper names must not appear in JSON `rule` fields.

### 5.1 HOOK_BYPASSED key table

Exact keys, case-sensitive:

| Surface | Key / shape | Event |
|---|---|---|
| `claude_settings` | `hooks.<Event>` array length 0 | bypass |
| `claude_settings` | matcher string `*` removed **and** command list emptied (matcher-only change without emptying commands is not enough) | bypass if commands gone |
| both | `"disabled": true` added | bypass |
| both | `"hookEnabled": false` added | bypass |
| both | `"continueOnError": true` / `"failOpen": true` added | bypass |

**Skip flags are judged per command (spec 10).** A flag on a matcher or group object applies to every command under it. A flag is *added* when (1) a command present at base and head lost active (unflagged) occurrences and gained flagged ones; (2) fewer commands stay active and more are flagged overall; or (3) an active base command is absent at head while a command absent at base appears already flagged (rename plus skip). Commands are compared as multisets of their strings, so reordering is not a change. Adding a new flagged command next to unchanged ones is not a bypass of an existing hook, whichever flag it carries. "Command prefixed with a no-op" in §5 is a command shape, not a key: its v0 closed form is a shell comment (`#`).

Unknown JSON keys are ignored (not findings). A new unknown skip key is a residual, and so is a flag whose value is not the JSON boolean in this table.

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

A hook **body** file — a target resolved per §3.3 — is a stub if every non-blank, non-comment line (after strip) is a member of the closed set for its extension:

- `.py`: `pass`, `import sys`, `import os`, `if __name__ == "__main__":`, `sys.exit(0)`, `os._exit(0)`, `exit(0)`, `quit()`, `raise SystemExit`, `raise SystemExit(0)`, `print('{}')`, `print("{}")`
- `.sh` / `.bash`: `exit 0`, `true`, `:`
- `.js` / `.mjs` / `.cjs`: `process.exit(0)`, `process.exit(0);`
- `.ps1`: `exit 0`

An empty body after comment removal is a stub. A body containing any other line is not a stub — a real judge has work lines. No regex beyond these closed lists in v0.

**Block-capability shape (spec 7).** A body-stub list cannot enumerate reformattings that keep the file's function shape while removing its decision logic. A §3.3 target whose **base** body mentions `block` or `deny` (case-insensitive substring) is **block-capable**; if the **head** body mentions neither, the gate can no longer refuse anything, and `GATE_STUBBED` fires (message "lost block capability") even though no closed line matches. The two shapes are independent — either can fire. A judge whose base body never mentions `block`/`deny` (e.g. refusal expressed only through exit codes) is invisible to this shape and stays residual.

For the last-Stop escalator (§6.1), a command whose resolved targets are all stub bodies — or that **lost block capability** — is **not live**, exactly like a stub command string.

### 5.3 PERMISSION_WIDENED

Closed comparisons:

| Surface | Base → head |
|---|---|
| `claude_settings` | `permissions.allow` gains `Bash(*)`, `Bash(rm *)`, `Bash(git push --force*)`, or a new `*` entry |
| `claude_settings` | `permissionMode` becomes `dontAsk` or `acceptEdits` when it was absent or stricter (`default` / `acceptEdits` → `dontAsk` is widen; reverse is not) |
| `cursor_mcp` | an MCP server `disabled: false` added, or `"alwaysAllow"` / `"autoApprove"` array gains `"*"` |
| `gemini_settings` | `autoAccept` becomes `true` when it was absent or `false`; `approvalMode` becomes `yolo` or `auto_edit` when it was absent or stricter (`default` / `auto_edit` → `yolo` is widen; reverse is not); an `mcpServers` entry is added with `"trust": true` or gains it |
| `opencode_config` | a `permission.<tool>` value becomes `allow` when it was absent, `ask`, or `deny` (`deny` / `ask` → `allow` is widen; reverse is not) |
| `cursor_hooks` | matcher `Write\|Edit\|Bash` **narrowed away from Bash** so PreToolUse no longer sees commits — this is `HOOK_BYPASSED`, not this rule |

`permissionMode` lattice, stricter to weaker: `default` > `acceptEdits` > `dontAsk`. `approvalMode` lattice, stricter to weaker: `default` > `auto_edit` > `yolo`. `permission.<tool>` lattice, stricter to weaker: `deny` > `ask` > `allow`. Unknown values: no finding, residual. Object-form `permission.bash` patterns in `opencode.json` are a residual (v0 compares string values only).

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

1. If `HOOK_REMOVED` or `HOOK_BYPASSED` or `GATE_STUBBED` removes or stubs the **last remaining** Stop-like hook on `claude_settings` (`Stop` event) or the last remaining Cursor stop/finish hook, severity becomes **critical**.
2. If `REQUIRED_CHECK_DROPPED` removes the last remaining required context in a ruleset file, severity becomes **critical**.
3. If `JUDGE_UNPINNED` moves a pin to **floating**, severity becomes **high** (critical if it was the last non-floating pin on that workflow file).
4. `SURFACE_UNPARSEABLE` at head when base parsed: **high**.
5. Otherwise leave the rule's base severity — `warn`, except the producer-side `REQUIRED_CHECK_DROPPED` disjuncts, which base at `high` (spec 9).

Default `fail_on` is **high**. `warn` findings do not fail the run. `critical` and `high` do. This matches checkwash’s “visible warn can still pass” so installing pinwash on a noisy docs edit of SKILL.md does not by itself brick merge until phrases hit and escalate — `SKILL_BYPASS` stays warn unless later spec says otherwise. v0: `SKILL_BYPASS` never escalates (phrase hits are review, not merge-block). `PERMISSION_WIDENED` escalates to **high**. `CONFIG_RELAXED` escalates to **high**. `EXEMPTION_ADDED` never escalates. Spec 9: a required check that can no longer run on any enforcement path is a dropped check, so its producer-side shapes block at the default `fail_on` (round 3 live warn-gap specimen: `# on: push` fired warn and the verdict stayed pass).

## 7. Findings envelope

When an engine ships, stdout JSON (UTF-8, sorted keys, `ensure_ascii=False`, `\n`) :

```json
{
  "pinwash_findings_version": 1,
  "run": {
    "base": "label",
    "head": "label",
    "pinwash_version": "0.0.0",
    "spec_version": 10
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
| `fingerprint` | `sha256` of canonical JSON: `rule`, path, locator if any, before digest, after digest; hex 64, emitted `rule/path/v1:<64hex>` |

`unknown_coverage` lists residual grammar hits (e.g. `gha_workflow multiline uses`) as objects `{ "path", "reason" }`. They do **not** change `verdict`. A gate that requires “no unknown coverage” is a consumer policy, not this spec.

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

`reason` and `expires` required; `expires` at most 180 days. Expiry uses `PINWASH_TODAY` if set, else the current date — the only clock that may affect a verdict, overridable for replay.

An **exemption** is a record that satisfies the validity rule above. Records that fail validity are invisible to both checks: deleting or editing one is not a finding, and adding one emits nothing.

Head-side **append-only** valid additions emit `EXEMPTION_ADDED` at warn (visibility). Editing or deleting a base exemption is `CONFIG_RELAXED` at critical; an edit is any change to a base exemption record, not only its removal.

## 11. Residuals (not silent passes)

These are expected non-findings. Each needs a THREATMODEL row before an engine ships. A row marked Closed without a fixture fails the suite.

| ID | Residual |
|---|---|
| R01 | Human terminal `git commit --no-verify` / host CLI that never consults repo hooks |
| R02 | Harness only in `$HOME`, SaaS UI, or gitignored `settings.local.json` |
| R03 | YAML aliases, multiline `uses`, reusable workflows |
| R04 | Vendored judge **bytes** patched without pin-record change |
| R05 | GitHub ruleset live on API, file not in trees |
| R06 | Hosts beyond the spec 6 surface set (Codex host config lives in `$HOME` → R02; Qoder; Copilot agent settings beyond `copilot-instructions.md`); unknown skip keys; `opencode.jsonc`; object-form `permission.bash` patterns |
| R07 | Stub shapes outside the §5.2 closed body lists and outside the block-capability shape (judges whose base body never mentions `block`/`deny`; guarded one-liners; trailing comments on stub lines); opaque command forms (`python -m pkg.mod`, inline `-c` payloads, quoted paths with spaces, variable expansion) — the import-time `sys.exit(0)` attack is in scope since spec 4, the shape-preserving gut job since spec 7 |
| R08 | `SKILL_BYPASS` missed paraphrases; also false hits on non-excluded docs |
| R09 | Required check context renamed in GitHub but job `name:` unchanged, or the reverse, when no ruleset file exists |
| R10 | Pinwash itself disabled by not running pinwash |

R07 is the important “GATE_STUBBED in the Python file” hole. Since spec 4 the engine stub-checks both the **command string** in JSON and the §3.3-resolved target **file bodies** (§5.2 closed lists; block-capability shape since spec 7). The shapes in the R07 row above stay residual; closing more of them is a spec bump.

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

- **10** — §5.1 is the exact table of what the engine detects: `"disabled": true` and `"hookEnabled": false` apply to both hook surfaces (the §5 row already named `hookEnabled`; §5.1 omitted it and scoped `disabled` to `cursor_hooks`), and skip flags are judged per command instead of as one per-event aggregate. The aggregate fired `HOOK_BYPASSED` when a new, already flagged sibling was added next to unchanged commands, depending on which flag name it carried, and missed a live command renamed and flagged when the same flag name already existed elsewhere in the event (taipei49314/pinwash#5, #6). Severity, message, locator and fingerprint fields are unchanged.
- **9** — Producer-side `REQUIRED_CHECK_DROPPED` severity `warn` → `high` (§5 preamble exception, §5 row severity note, §6.5): the deleted-job, `if`-disable, `continue-on-error`, and trigger-loss disjuncts now base at `high`, so a required check that cannot run on any enforcement path blocks at the default `fail_on=high`. Found as the round 3 warn-gap (opencode zen bench, `pinwash-live/round3`): the live trigger-loss specimen (`on: push` → `# on: push`) fired warn and the verdict stayed pass while the check could never gate again. Ruleset-side drops are unchanged (`warn`; `critical` per §6.2). No grammar, surface, or rule-ID change.
- **8** — `REQUIRED_CHECK_DROPPED` gains the trigger-loss disjunct, found live in round 2 (opencode zen bench, `pinwash-live/round2`): a producing job's workflow that drops `push`/`pull_request` from `on:` (live escape: `on: push` → `on: workflow_dispatch`) leaves the required context with no enforcement-path run, so the job's survival, `if:`, and `continue-on-error` disjuncts all stay silent while the check can never fire. §3.1's bounded grammar gains closed `on:` trigger forms (inline scalar/list, block list items and mapping keys at indent 2); unresolvable `on:` blocks are residuals (`on triggers unresolved`), never treated as an observed removal.
- **7** — §5.2 block-capability shape, found live in round 1 (opencode zen bench, `pinwash-live/round1`): a §3.3 target whose base body mentions `block`/`deny` but whose head body mentions neither fires `GATE_STUBBED` ("lost block capability") and counts as not live for the last-Stop escalator. Closes the shape-preserving gut job (function frame kept, decision logic removed) that the closed-line list structurally could not see. Residual stays: judges whose base body never mentions block/deny.
- **6** — R06 first closing wave (§9.2): new surfaces `gemini_settings` (`.gemini/settings.json`) and `opencode_config` (`opencode.json`) with closed §5.3 widening rows (`autoAccept`, `approvalMode`, mcp `trust`; `permission.<tool>` lattice `deny > ask > allow`), and `agent_markdown` widened to the Gemini/Qwen/Copilot/Windsurf/Cline instruction files (`GEMINI.md`, `QWEN.md`, `.github/copilot-instructions.md`, `.windsurfrules`, `.clinerules`). Grounded on real files on the maintainer host (`opencode.json` permission blocks; boundkit’s `GEMINI.md` and `.github/copilot-instructions.md`). Residuals: `opencode.jsonc`, object-form `permission.bash` patterns, Codex repo-level config (Codex keeps host config in `$HOME` → R02), all further hosts.
- **5** — Bounded GHA grammar widened (first §9.3 widening): recorded values truncate at the first ` #` (space-hash), the bounded form of a YAML inline comment. Found by live-fire on taipei49314/checkwash: sha-pinned `uses:` lines annotated `# vX.Y.Z` classified as floating, so honest release annotation bumps fired `JUDGE_UNPINNED` critical. With truncation, shas classify as `git_sha`; annotation-only bumps are silent; genuine floats still fire.
- **4** — R07 narrowed by implementation: §3.3 defines the closed rule by which hook `command` strings resolve to repo-relative target files, restored to the `claude_hooks` surface; §5.2 defines closed per-extension body stub sets, and `GATE_STUBBED` fires when a base non-stub body becomes one; the §6.1 last-Stop escalator treats body-stubbed commands as not live. The import-time `sys.exit(0)` attack named in R07 is now in scope; R07 stays Open for shapes outside the closed lists.
- **3** — Honesty sync and the command-target ruling: the preamble states a local engine exists and records the 2026-09-27 delegated edit authority; the `claude_hooks` surface is narrowed to `.claude/hooks/**` (hook `command` strings are not resolved to repo-relative target files — moved into R07’s bump scope). Engine behavior is unchanged by this version.
- **2** — §1.6 rewritten: the undefined `INCOMPLETE` token is gone; the fail-closed invariant (missing observation is never a pass) now names the three channels that carry it (`SURFACE_UNPARSEABLE`, `config_errors`, `unknown_coverage`). No detector or envelope change.
- **1** — `EXEMPTION_ADDED` formalized as a §5 rule (it was named in §10 but missing from the §5 closed set). §10 now states that only records satisfying the validity rule count as exemptions for the addition check and the edit/delete check, and that an edit is any change to a base exemption record.
- **0** — initial freeze (first commit of this file).
