# Second native attempt proposal: cleanup correction and named recovery

Prepared after immutable native run38510675237/1; no second execution yet.

## Preserved first result

Source6706815e36ced670630fb2ae51219f6cd1bb5767, ECsource412f03baf6c0836950fe59ea4b9703e96cae538f, LAPTOP-8KGL8EFS-workload, generation8b1bcfb4b5dc0588.1, Python3.12.10, Git2.55.0.windows.5. Receipt commitfeae654459d5a8b1cb4ed7ad30a77e0f362ebd6e.

All27 cases matched; all162 scans completed, with81 raw seed pairs equal and empty judge stderr;12 harness tests OK. Overall FAIL remains unchanged: deleting an owned Git loose object raised WinError5. Final source checks did not execute. The original receipt's scratch_cleanup=NOT_CREATED was inaccurate after scratch creation, and the directory may have been partially deleted. That historical receipt is not edited or called PASS.

The failure is consistent with Windows Git read-only object files, but no separate attribute read-back exists in that receipt. The repair only retries deletion when the actual regular file is read-only; other errors remain failure. The [Python rmtree example](https://docs.python.org/3.11/library/shutil.html#rmtree-example) and EC's existing pool.remove_tree use a read-only-file callback. This implementation adds absolute-parent, namespace, regular-file and reparse checks; it is not a sandbox or a race-free hostile-filesystem claim.

## New bounded implementation

- Create fresh scratch within EC_WORKLOAD_WORK, so it stays inside the EC-owned job workspace. Validate the resolved direct parent and the pinwash-candidate- prefix before recursive deletion; reject symlinks/reparse throughout the absolute path's ancestors and tree, and reject nonregular entries before any removal. The fixed old path must resolve to itself, so a redirected Temp ancestor cannot select another physical directory.
- On a PermissionError deleting an ordinary owned leaf, clear only its existing read-only bit, then retry that unlink. Reject hardlinked files in preflight and require st_nlink=1 again before chmod, so an outside hardlink's attributes cannot be altered. No ACL, takeown, elevation, security setting or blanket attribute change. Otherwise preserve failure.
- Record scratch CREATED/path immediately; cleanup errors record FAILED/path/error. Complete final source SHA/status checks even after a filesystem cleanup failure when owned processes are confirmed terminal.
- After27 cases match and current scratch cleanup succeeds, recover only the previous failed scratch on LAPTOP-8KGL8EFS: C:/Users/S3452MA/AppData/Local/Temp/pinwash-candidate-hubxl1c3. recovery.json pins receipt/source/path and every recorded non-Git file hash; remaining files must match. Directory allowlist includes only empty-templates, recorded cases/file ancestors and their Git metadata. Unexpected files, empty directories or reparse points cause refusal. Read back absence before recording REMOVED; already absent is separately recorded.
- Four additional harness tests cover readonly deletion with a mocked hardlink refusal, wrong-parent refusal, pre-deletion reparse rejection at root/parent and preservation of an unexpected previous-workspace file/empty directory. Require exactly16 successful harness tests before fixtures start. No test or product program is run on a work machine.

The27 case inputs, predictions, manifest hash, candidate engine tree and SPEC remain unchanged. The declaration changes to explicitly name recovery of the old host directory and pin recovery.json; its new canonical hash must be human-approved and registered before any second run. The one original native execution authority is not silently reused. Same host, parameters{}, cache=false and20-minute limit; full suite/doctor/matrix/held-out/publication remain outside scope.

Proposed declaration SHA-256: `f519ed4b586759ba38ca15d397676d5723b32ac950e02f42a21e339b4e034e85`. Recovery plan SHA-256: `278af37c6e0033a552fc38664478c127f48d42a03cd1d9a89c4e44617e9e7178`. Both existing alpha2-verify/live-fire-rejudge declarations remain identical. Tests, cleanup execution and the second native run are **NOT_RUN** at this source-review stage; source reasoning/whitespace review does not replace EC pool execution.
