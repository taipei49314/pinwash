# Publishing 0.1.0

The first version is **0.1.0 (Alpha)** under MIT. SPEC 27 and the findings schema
are unchanged. Only the exact accepted original wheel and sdist are uploaded;
the wheel rebuilt from the sdist is an acceptance artifact, not a second upload.

This procedure does not grant execution or publishing authority. The maintainer
has requested the first tag and PyPI upload; build execution and new PyPI trust
configuration still need their explicit scoped authorization.

1. Fix a clean source SHA. Run the two-wheel package acceptance harness at that
   exact source in an authorized environment. Require complete suites with no
   failures, errors or skips, matching source/package bytes, version 0.1.0,
   MIT metadata and exact license bytes in both archives. Preserve raw results
   and artifact hashes. Old version 0.0.0 acceptance does not validate these files.
2. After source review and acceptance, merge the release preparation PR without
   changing its tree. Create annotated tag `v0.1.0` at the exact tested source
   commit, which is now an ancestor of main. Never move or overwrite the tag.
3. Stage a draft GitHub release at this tag with `target_commitish` set to the
   full tested SHA. Attach the original wheel and sdist and acceptance receipts.
   After checking both asset hashes, publish it as an Alpha prerelease; the
   upload job has read-only repository access and downloads public assets.
4. Configure the PyPI pending publisher for project `pinwash`, owner
   `taipei49314`, repository `pinwash`, workflow `publish-pypi.yml`, environment
   `pypi`. Restrict that GitHub environment to tag `v0.1.0`. This is a new trust
   delegation and requires the maintainer's explicit confirmation.
5. Register and read back the approved upload dispatch, then manually dispatch
   `publish-pypi.yml` at tag `v0.1.0` with the tested SHA and the two accepted
   SHA-256 hashes. It only downloads those release assets, checks exact
   bytes and uploads them. It never builds or executes PinWash, uses no long-lived
   PyPI token, grants no repository write permission, and has a 15-minute limit.
6. Read back the workflow result and PyPI JSON. Require version, filenames,
   license, Python requirement and both SHA-256 values to match. Then update the
   GitHub release notes with the verified PyPI link. An upload error or unknown outcome must
   be inspected before further action; do not automatically retry or overwrite.
   If PyPI upload fails, the GitHub prerelease remains published and must not be
   described as a completed PyPI release.

The workflow is manual-only and limited to this first version. It is not a
standing authorization for later releases. The PyPI publisher remains attached
to this exact repository/workflow/environment; changing its scope is a separate
decision. No Windows/macOS package acceptance or 1.0 stability claim is made.
