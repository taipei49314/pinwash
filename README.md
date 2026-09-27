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
