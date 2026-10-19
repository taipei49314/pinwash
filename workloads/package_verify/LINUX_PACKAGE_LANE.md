# Proposed offline Linux package verification

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
This is an engine hardening change, not merely a test adjustment. It has no new
native validation yet. Frozen acceptance gates, SPEC 29, rule IDs and severities
remain unchanged. A new fixed approval package is required before any rerun.

The human selected PJU as the next validation target. A fresh fixed approval
package is required; that selection alone is not an execution grant. Its local
single-container route can validate the shared harness/PID1/package behavior.
It cannot validate HOST50, four-helper named-volume custody, workload admission,
remote receipt ACK or reset release. This declaration remains proposed.

The published 0.1.1 wheel and sdist remain the original accepted bytes from
`fdb3c4d`. Their embedded README and PyPI long description reflect that source's
prepublication wording; current main documentation records the completed
publication. This proposal does not replace those artifacts or claim a new
package acceptance for its changed source.
