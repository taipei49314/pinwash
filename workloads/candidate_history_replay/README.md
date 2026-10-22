# Candidate history replay

Read [PREREG.md](PREREG.md) and the fixed manifest before dispatch. This is the
spec29→37 replacement for PR #52, preserving the historical corpus and receipts.
Run only through a newly recorded EC pool workload named `candidate-history-replay`.

The standalone runner consumes no nonempty parameters, writes new evidence only
under `EC_WORKLOAD_OUT`, and cleans only scratch it creates beneath
`EC_WORKLOAD_WORK`. The bundled engine store supports shallow EC source fetches.
Source SHA, source-clean invariant, complete matrices, exact oracle agreement,
determinism and cleanup are independently recorded. No previous one-time recovery
action is part of this workload. Current status: **NOT_RUN**.
