# Proposed offline Linux package verification

Current disposition (2026-10-22): the EC pool declaration remains proposed,
but the PJU follow-up is complete for exact source
`67b6e43d5c6e33fbd4efd515e6f7ef3ccebf775e`. A separately authorized review of
preserved evidence recorded
[`ACCEPTED_LOCAL_REVIEW`](https://github.com/taipei49314/estate-consolidation/blob/bca120d601e52c4a816a33d9204f4ca9bca1dac1/evidence/requests/7410783b-7e53-4b50-9dd4-f7664ef4ab2a/local-acceptance-decision.json).
It did not repeat native execution or qualify EC pool/HOST50. The original
attempt remains `FAIL_NOT_ACCEPTED`; the later review is a separate acceptance
record. [T-572](https://github.com/taipei49314/estate-consolidation/blob/36811450e87fcc9e3f9c4db0381b5b97e4c1873f/governance/tasks/T-572.json)
is DONE for its source-engineering scope, with the route dormant and registry
unapproved. No release or rerun is pending under that task.

`package-linux-verify` is a new proposed declaration. It is not admitted by the
existing Windows `package-verify` / D127 registration and is not executed by the
generic Windows dispatcher. No published 0.1.1 artifact is rebuilt or replaced
by this source proposal; the released source remains `fdb3c4d` at tag `v0.1.1`.

The proposed controller supplies an exact Git bundle, reviewed PID1 payload and
the fixed setuptools 83.0.0 wheel, then runs this harness in pinned Linux amd64
Python 3.12.15 with `PINWASH_PACKAGE_EXECUTION=ec-pool-linux`. Source is
`/work/source`, input backend is `/source/inputs/setuptools-83.0.0-py3-none-any.whl`
and results are `/output/results`. The Linux mode refuses fallback downloads and
unknown execution modes. Host/source/declaration/decision/runtime claims need
separate controller admission and original byte receipts; environment variables
alone grant no authority and are not host attestation.

For the separately approved PJU validation route, the explicit mode is
`human-authorized-pju-linux-package`. It uses the same layout, Python 3.12.15,
strict command records and package checks, but requires physical host
`LAPTOP-01AGNPJU`, rejects all `EC_WORKLOAD_*` claims and emits
`HUMAN_AUTHORIZED_PJU_LINUX_PACKAGE_NOT_EC_POOL`. The independently pinned host
operator and PID1 payload must be approved before execution. The old
`human-authorized-local-docker` route and historical result grammar are retained.

The harness builds an original wheel and sdist, rebuilds another wheel from the
sdist, verifies package contents/metadata/resources and installs both wheels in
separate temporary environments. Each installed doctor must report exactly 690
tests, SPEC 29 at SHA256
`e31d7b466378f9358a5dbaf505cc8fb07c2c02093cc4daa24ac949666afd969b`,
version 0.1.1 and zero failures/errors/skips/expected failures/unexpected
successes/nested depth. Session/report, historical review, restored hook,
sentinel and source-clean/HEAD checks remain required. Partial raw stdout/stderr
is preserved; a command timeout is a failure.

In this new mode each inner command records its actual nullable exit separately
from `outcome`, `timed_out` and wrapper `error`. If an exception provides no
actual exit, the value is null. Timeout and spawn diagnostics are metadata;
the child's raw stderr is preserved unchanged. The historical LOCAL and legacy
formats retain their original grammar. The new PJU mode shares this strict
Linux command grammar; it does not impersonate a pool owner or workload.

The separate EC controller must prove original attempt 1, exact admitted source
and declaration, qualified runtime/storage prerequisites, original ownership,
fixed helper recipes and all writer/terminal/export/cleanup/custody gates. Full
immutable remote receipt readback and a durable local ACK precede reset release.
The whole lifecycle is bounded to 60 minutes, including reserved export,
cleanup and publication time. This source does not grant Docker/image setup,
host service/security/runner changes, network in the runtime, work-machine
execution, workload dispatch or publication.

Source review and EC synthetic fixtures do not establish Linux lane acceptance.
HOST50 qualification remains separate. All older one-time PJU product grants
are consumed; none is reused by this declaration.

The fixed `3433a5b` local attempt `fea986e7` failed on Python 3.12.15 / Git
2.39.5: the first installed doctor ran 690 tests with two failures; the second
installation was not reached. Exact container cleanup and absence were recorded.
That source/runtime result is not accepted and its one-time grant is consumed.
The date regression exposed a real difference between old and newer Git commit
parsers, also affecting the published engine's compatibility assumptions. The
candidate now refuses ambiguous commit metadata with exit 2, retaining the
native Git oracle for common date semantics and every original regression case.
This is an engine hardening change, not merely a test adjustment. Frozen
acceptance gates, SPEC 29, rule IDs and severities remain unchanged.

The subsequent PJU attempt `ab0f9444-831f-4f1f-a7c2-2cd11b335f85` ran source
`67b6e43` and preserved two installed doctors with 690 tests each and zero
failures/errors/skips/expected failures/unexpected successes/nested depth,
package checks and exact container cleanup. Its result reader stopped at a
stale expected judge fingerprint, so that attempt remains `FAIL_NOT_ACCEPTED`.

Under a new explicit human decision, read-only review
`9553247a-125e-4988-ae5b-80eb1153e472` independently derived the identity from
the fixed source and verified the complete preserved evidence. The acceptance
receipt linked above records driver, finalization and completion PASS, actual
exit 0 and a tool return before the deadline. It accepts that exact source's
local evidence as `HUMAN_AUTHORIZED_PJU_LINUX_PACKAGE_NOT_EC_POOL`; it neither
rewrites the failed attempt nor repeats native execution.

The earlier selection of PJU as the next target is therefore resolved for this
source. A future execution needs a separate current task, fixed grant and
prerequisite receipts. HOST50, four-helper named-volume custody, workload
admission, remote receipt ACK and reset release remain unaccepted. This EC
declaration remains proposed, and all previous one-time grants remain consumed.

The published 0.1.1 wheel and sdist remain the original accepted bytes from
`fdb3c4d`. Their embedded README and PyPI long description reflect that source's
prepublication wording; current main documentation records the completed
publication. This proposal does not replace those artifacts or claim a new
package acceptance for its changed source.
