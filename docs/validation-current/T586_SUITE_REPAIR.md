# T-586 complete-suite repair, 2026-10-23

The human requested continuation of T-586 session validation and complete-suite
failure repair, with all verification on the pool. The current task and handoff
are [recorded in EC](https://github.com/taipei49314/estate-consolidation/blob/main/governance/tasks/T-586.json).
This source starts from SPEC37 candidate `dec428881f978c7ac3ffa4cbac0aaea81eeec4a8`.
It does not change the frozen SPEC, gates, rule semantics, doctor acceptance,
workload declarations, session/history oracles or published 0.1.1 artifacts.

## Original result and repairs

[Run 39790047159/1](https://github.com/taipei49314/estate-consolidation/actions/runs/39790047159)
at dec4288 ran 732 tests in both the suite and public doctor, with 12 failures,
11 errors and 10 skips. Its
[receipt](https://github.com/taipei49314/estate-consolidation/tree/f0637b0318d656e8402a5fa1d586220d337de01e)
remains FAIL. Eighteen supplementary runner tests passed; this did not accept
the product suite.

- Eight invalid-range subtests expected LF stderr despite the CLI using native
  text output. The tests now require the exact complete diagnostic and exactly
  one native newline. Exit 2 and empty stdout assertions remain; no stripping or
  permissive matching is introduced. JSON output is unchanged.
- The worktree fidelity fixture now writes its specified UTF-8 bytes directly,
  so a Windows text writer cannot turn its intended LF input into CRLF. Its
  original byte assertion remains.
- The alternate-store fixture writes an absolute forward-slash path and LF
  bytes. Native Git must demonstrably read the forged bytes through that
  alternate before PinWash's original hash-mismatch assertion can pass.
- The deleted-commit fixture clears the readonly bit on only its own generated
  object immediately before deleting it. The missing-object/merge-base oracle
  is unchanged. Directory symlink fixtures explicitly declare their target type;
  file symlink fixtures remain files.
- **Product hardening:** negative timestamp magnitudes exceeding the unsigned
  64-bit range now raise the existing ambiguous-commit-date error. Native Git
  disagreed with the former saturation result on the Windows receipt; selecting
  one runtime's queue date would not be a safe portable merge-base decision.
  The original extreme raw value is retained as a refusal regression, together
  with exact overflow boundaries. Distinct commit IDs force the public
  three-dot CLI path to read the date and require exit 2. Ordinary negative
  dates and positive overflow retain their prior checks.

An independent read-only source review found no blocking issue in these five
source/test file changes. That review is not execution evidence. The fixture
changes do not modify any frozen test or skip condition.

## Remaining acceptance limits

The existing Windows runtime had ten symlink privilege errors. Correct target
types do not grant that privilege. Its ten existing skips cover POSIX shell
execution, symlinks, newline-containing paths and Linux `/proc/self/mem` EIO.
The doctor requires zero failures, errors and skips, and its frozen gate must
keep that requirement. A Windows rerun may demonstrate repair of the changed
cases while still failing full acceptance; record both facts explicitly.

Linux source-suite/doctor acceptance requires a separately admitted exact
SPEC37 pool contract. The current Linux package lane is dormant and retains its
SPEC29/690-test contract. HOST50 qualification does not admit changed product
workloads. No local Docker run, host privilege change, extra skip, narrowed
discovery, new Linux activation, product merge or release is authorized here.

The successful history receipt at e0003fa and any session result using the
earlier dec4288 engine remain limited to those bytes; neither validates this
new date-hardening source. A new fixed-source pool run and raw receipt are
required. No execution result is claimed by this source-preparation document.

NOT_RUN：工作機規則（POLICY work-machine-local），本機僅來源修改及唯讀審查，修復效果待 pool 驗證。
