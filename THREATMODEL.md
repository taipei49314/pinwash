# THREATMODEL — pinwash

Status values: **Open** (residual, no closing fixture), **Closed** (fixture exists and is named). A Closed row without a fixture is invalid.

A local v0 engine exists (not a Release, not on PyPI). Every residual row below is Open. Closing a row is a spec bump plus a named fixture.

| ID | Status | Fixture | Residual |
|---|---|---|---|
| R01 | Open | — | Human CLI `--no-verify` / host that never reads repo hooks |
| R02 | Open | — | Harness only in `$HOME`, SaaS UI, or gitignored local settings |
| R03 | Open | — | YAML aliases, multiline `uses`, reusable workflows |
| R04 | Open | — | Vendored judge bytes patched without pin-record change |
| R05 | Open | — | Live GitHub ruleset not present as a file in the trees |
| R06 | Open | — | Hosts beyond the spec 6 surface set (Codex host config lives in `$HOME` → R02; Qoder; Copilot agent settings beyond `copilot-instructions.md`); unknown skip keys; `opencode.jsonc`; object-form `permission.bash` patterns |
| R07 | Open | — | Stub shapes outside the SPEC §5.2 closed body lists and outside the block-capability shape (judges whose base body never mentions `block`/`deny`; guarded one-liners; trailing comments on stub lines); opaque hook command forms (`python -m pkg.mod`, inline `-c` payloads, quoted paths with spaces, variable expansion). SPEC §3.3-resolved hook bodies are scanned since spec 4, which brought the import-time `sys.exit(0)` attack into scope; the block-capability shape since spec 7 covers the shape-preserving gut job |
| R08 | Open | — | `SKILL_BYPASS` paraphrase misses and false hits |
| R09 | Open | — | Required-check context rename vs job `name:` when no ruleset file exists |
| R10 | Open | — | pinwash not run |

See [SPEC.md](SPEC.md) §11.
