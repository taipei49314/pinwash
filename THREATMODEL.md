# THREATMODEL — pinwash

Status values: **Open** (residual, no closing fixture), **Closed** (fixture exists and is named). A Closed row without a fixture is invalid.

Engine not shipped. Every row below is Open. Closing a row is a spec bump plus a named fixture.

| ID | Status | Fixture | Residual |
|---|---|---|---|
| R01 | Open | — | Human CLI `--no-verify` / host that never reads repo hooks |
| R02 | Open | — | Harness only in `$HOME`, SaaS UI, or gitignored local settings |
| R03 | Open | — | YAML aliases, multiline `uses`, reusable workflows |
| R04 | Open | — | Vendored judge bytes patched without pin-record change |
| R05 | Open | — | Live GitHub ruleset not present as a file in the trees |
| R06 | Open | — | Unknown skip keys; hosts outside the v0 surface table |
| R07 | Open | — | Stub inside Python/JS hook bodies; v0 only sees JSON command strings |
| R08 | Open | — | `SKILL_BYPASS` paraphrase misses and false hits |
| R09 | Open | — | Required-check context rename vs job `name:` when no ruleset file exists |
| R10 | Open | — | pinwash not run |

See [SPEC.md](SPEC.md) §11.
