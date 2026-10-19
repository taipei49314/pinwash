# Proposed package acceptance — 0.1.1 / SPEC 29

**Historical plan; completed and explicitly accepted on 2026-10-19.**
The fixed source was `fdb3c4d753d637e89aba5a22372d61dc2c292939`. Original and
sdist-rebuilt installed wheels each passed 690 tests with zero failures, errors
or skips; metadata, archive, source, session/report and exact cleanup checks
passed. This was an explicitly authorized and accepted local PJU Docker Linux
run, `HUMAN_AUTHORIZED_LOCAL_DOCKER_NOT_EC_POOL`; it did not qualify HOST50.
The corrected attempt took 197.217 seconds. The preceding adapter preflight
failed before Docker/product execution and is retained separately.
See the [completed release record](RELEASE_0_1_1.md) and
[public receipt](https://github.com/taipei49314/pinwash/releases/download/v0.1.1/ACCEPTANCE.json).
The text below preserves the proposal's expectations and authority boundaries
as they stood before its separate exact-source approvals; it is not a reusable grant.

**Preparation only. Execution NOT RUN; no dispatch or local workload grant.**
The maintainer requested a candidate and plan on 2026-10-19, then requested
release followed by repair of the PinWash Linux package pool lane using the
local work machine. The local workload conflicts with the standing work-machine
rule; a separate exact-source local proposal is being prepared for explicit
confirmation. This document does not grant that execution or accept its
results in advance.

## Fixed inputs

The accompanying external source manifest must name the complete candidate
commit SHA and root tree, plus raw Git blob SHA-256 values for SPEC, package
metadata, version constants, README, LICENSE, build inputs, the declaration and
the unchanged `workloads/package_verify/run.py`. It also pins the full tests
tree. Its source commit contains this plan; the manifest is kept outside that
source to avoid a self-referential hash. A changed candidate SHA requires a new
manifest and a review of whether the planned acceptance still applies.

- Expected package version: `0.1.1`; SPEC: `29`; findings envelope: `1`.
- Expected SPEC SHA-256:
  `e31d7b466378f9358a5dbaf505cc8fb07c2c02093cc4daa24ac949666afd969b`.
- Expected full-suite count: **690 per installed wheel**, based on the accepted
  PR #56 suite, whose complete tests tree is unchanged in this candidate. This
  is a preregistered expectation, not a result from this preparation.
- Python 3.11+ and Git on a declared Linux runtime; record exact versions and
  physical host in the receipt. Do not infer current host readiness from old
  receipts.
- Build backend: only `setuptools-83.0.0-py3-none-any.whl`, SHA-256
  `29b23c360f22f414dc7336bb39178cc7bcbf6021ed2733cde173f09dba19abb3`, from
  `https://files.pythonhosted.org/packages/5d/40/e1e72872c6354b306daef1703549e8e83b4d43cfea356311bf722a043752/setuptools-83.0.0-py3-none-any.whl`;
  maximum 2,000,000 bytes. No other dependency or index access.

## Execution admission

The normal route is a newly admitted, exact-source EC pool `package-verify`
dispatch, maximum **60 minutes**, cache disabled. A qualified Linux execution
lane and its exact physical host/runtime must be named before dispatch. Existing
Windows results do not satisfy this Linux target. Do not silently route to a
different host or start host provisioning.

The current product declaration is retained unchanged, but the old EC registry
entry covers a different declaration hash and earlier scope. Verify/admit the
current declaration, fixed source, entry hashes, profile and execution budget,
publish the EC accounting and read it back before dispatch. This preparation
does not reopen or reuse T-556, T-567 or an old dispatch.

Neither work machine is an execution venue under the pool route above. All previous
PinWash PJU grants are consumed. Any subsequently requested PJU Docker route
needs a new, explicit scoped human decision, fresh EC accounting, a fixed
reviewed operator and exact cleanup ownership; it is not a fallback authorized
by this document. Such results must retain their local provenance and need
explicit human acceptance.

## Run recipe

Use the fixed, unchanged `workloads/package_verify/run.py`, with the recorded
source checked out clean using `core.autocrlf=false`. Supply its admitted
`EC_WORKLOAD_REPOSITORY`, `EC_WORKLOAD_NAME`, `EC_WORKLOAD_SHA`,
`EC_WORKLOAD_SOURCE` and unique `EC_WORKLOAD_OUT` through the EC runner. They
must identify `taipei49314/pinwash`, `package-verify` and this exact candidate.
The entry is `python -I -B workloads/package_verify/run.py` in that checkout;
invoke it only through the admitted dispatch, never on a work machine.

1. Prove exact source/cleanliness and pinned inputs. In temporary directories
   create the builder, download and hash-check the one fixed backend, and build
   the original wheel and sdist. Safely unpack the sdist and rebuild a wheel.
2. Compare original and rebuilt wheel member bytes, excluding generated
   `RECORD`; record separate archive hashes. Require exact dispatched Python
   code and complete bundled SPEC/THREATMODEL/tests bytes. Preserve LICENSE
   bytes, MIT metadata, Python >=3.11, no runtime dependencies, and the console
   entry `pinwash.cli:main`; reject a top-level `tests` package.
3. Install each wheel offline in its own clean temporary runtime. Run console
   identity and metadata checks away from the source. Run the trusted Git
   session fixture: start/status, removed hook blocking with text/JSON and the
   priority summary, exactly three completed comparisons, historical status
   preserving the original baseline/state, restored hook passing, and no
   subject or shadow-module sentinel execution.
4. Run each installed `doctor` with its entire original suite, not a selected
   subset. Preserve its raw stdout/stderr and the complete command receipt.
5. Independently read back all outputs below, then prove source still exact and
   clean, all owned subprocesses stopped and per-run temporary resources
   cleaned. The harness's success alone is not the final acceptance decision.

## Required independent readback

The unchanged harness does not itself enforce every release-specific value.
The readback must enforce these additional gates using saved output/artifacts:

| Evidence | Required value |
|---|---|
| `result.json` | Expected source SHA; correct execution class/physical host; `status=PASS`; empty `problems`; all required steps present |
| `install-1-version.stdout`, `install-2-version.stdout` | Exactly `pinwash 0.1.1 spec 29` with the normal terminal newline |
| Both installed metadata outputs | `version=0.1.1`; correct console entry, no requirements, module under the corresponding isolated runtime |
| Both doctor outputs | Version `0.1.1`, spec `29`, exact SPEC digest above, `subject_judged=false` |
| Both doctors' `self_tests` | `available=true`, `ok=true`, `tests_run=690`, `nested_depth=0`; zero failures, errors, skips, expected failures and unexpected successes |
| Artifact inventory | Exactly the original wheel, sdist and rebuilt wheel, all with recorded SHA-256; wheel/sdist names carry `0.1.1` |
| Archive review | Wheel metadata README equals the fixed source README; sdist README/pyproject/build inputs/LICENSE/SPEC/THREATMODEL/docs/tests/package sources equal their fixed source bytes; expected generated metadata verified separately |
| Session outputs | New baseline initially unreviewed; removal blocks; restored hook passes against the original baseline; complete three-run JSON; no sentinel execution |
| End-of-run receipt | Source SHA and clean status re-read; no unhandled timeout/unknown operation; owned-process and temporary-resource cleanup complete |

Do not call archive hashes reproducible merely because member contents match.
Do not silently accept a smaller passing suite or substitute the prior 690-test
result. If any gate fails or output is absent, preserve the failed/partial
record and mark the unperformed steps NOT RUN. Do not automatically retry;
inspect the exact failure and original operation before proposing a corrected
source or another attempt.

## Evidence and decision

Preserve the complete command/exit/time/stdout/stderr manifest, raw outputs,
runtime and physical-host receipt, source manifest, all three artifacts and
their hashes, content comparisons, readback verdict and cleanup evidence.
Raw paths and records may contain host details; publish only a reviewed summary
and sanitized acceptance receipt. A complete technical pass and evidence review
support a separate acceptance decision for these exact artifacts on this
runtime. They do not establish Windows/macOS coverage, fresh live-fire quality,
held-out accuracy, semantic correctness or 1.0 stability.

No product merge, tag, PyPI upload, publisher change or old-stack execution is
part of this run. Candidate preparation is recorded as
`NOT_RUN：工作機規則（POLICY work-machine-local），本輪只準備候選與新版套件驗收方案，未執行產品、測試、建置或驗收。`
