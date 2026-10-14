# Second candidate, prepared before pool dispatch

This is a new exact-source attempt; it does not rewrite the fixed first candidate
`1e48df01adaaa918725dd719c6f623e05d1facf7` or either run's results.

AI-assisted source review identified these corrections after candidate 1 was
dispatched. They are not measured results until the second pool receipt arrives:

- Spec 35 refuses any `github` context token for bounded producer identity.
  Indexed, grouped and dot-whitespace access cannot evade the guard. Stable
  properties such as `github.repository` are conservatively refused as well;
  their honest rekeys/moves can retain a deleted-producer finding.
- Spec 36 reconciles current host-specific activity, switch and command-empty
  wording with specs 28–33. Prompt/agent handlers retain switch protection.
- Existing non-gate Claude flag fixtures are explicitly migrated to the new
  contract, with the old Cursor flag cases retained. Non-command handler types
  cannot preserve a command. Changed event-key sets add their exact visibility
  reason; no catch-all removal or filtering of unknown rows is introduced.
- The existing 20-minute declaration and all fixture gates remain unchanged.
  The entry retains 60 seconds for owned-tree cleanup and receipt writing.
  Expired command budgets never launch another command. Nonzero/failed
  `taskkill` or incomplete drainage marks cleanup unconfirmed and every later
  command `NOT_RUN`; the overall result remains FAIL with raw evidence.

`tests.test_producer_identity.ProducerIdentity` pins the context access and
conservative refusal cases. `tests.test_alpha2_entry_cleanup.OwnedCleanup` and
`EntryFailClosed` pin kill success/failure/timeout, incomplete pipe drainage,
expired budget, no later process launch and failure receipt retention using
mocks. They do not operate or terminate an unrelated process.

Expected acceptance remains the complete nonzero suite, zero failures/errors/
skips, top-level doctor with the same count and exact SPEC hash, clean exact
source, and identical same-tree JSON across the two seeds. A mock proving
failure receipt retention is not evidence of a live timeout recovery.

NOT_RUN: work-machine rule (POLICY work-machine-local). No tests, product CLI,
compile, lint, installation or live host probe ran locally. Candidate 2 runs
only after the prior native run is terminal, its raw results are retained,
the new source is reviewed/published, and its EC intent is published/read back.
