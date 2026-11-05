# Fortis Approvals source extraction — 2026-11-03

## Result

A local copy of `/workspace/repos/rd-graphs/fortis_approvals` was created at `/workspace/repos/fortis-approvals/fortis_approvals`.

- Original non-generated files: 196.
- Initially copied files: 196.
- Total initially copied bytes: 1,721,755.
- Symlinks in source: 0.
- Generated Python cache files excluded: 97.
- Initial source SHA-256 comparison: PASS for every copied file.
- Current-state guide SHA-256 comparison at extraction: PASS.
- Original RDG subtree: left untouched.
- At extraction, Git initialization / commit / push had not been performed; the later owner decision below records local Git initialization.
- Docker / Gateway runtime changes: none.

## Owner decision after extraction

On 2026-11-03, the owner approved `fortis-approvals` as a standalone repository and accepted the extracted tree as the canonical development source. Local Git was initialized on `main`. No commit, remote or push was created. The original `rd-graphs/fortis_approvals` subtree remains untouched as the preserved original copy. Remote visibility and publishing credentials require a separate decision.

## Included

- Python package modules and entry points.
- Unit tests.
- Static Owner Portal assets.
- Deployment Dockerfiles, Compose references and scripts.
- Current source README and deploy index.
- Existing evidence and preserved historical archive.

## Excluded

- Generated `__pycache__` directories.
- Generated `.pyc` files.
- Runtime SQLite databases and other generated state.
- Any credentials or private runtime material; no secret files were found by the filename-only scan. The scan did find historical documentation and scripts whose names contain `TOKEN` or `PRIVILEGED`; those are source/history artifacts, not token values.

## Verification method

The source and copy were independently enumerated, sorted and hashed with SHA-256. The resulting manifests were compared byte-for-byte. No symlinks were present, so the copy did not follow or flatten linked paths.

The current-state guide was copied to `docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md` and its SHA-256 matched the original.

## Follow-up changes in the extracted copy

After the original source comparison, a narrow documentation/test correction was made in the new copy only:

1. `fortis_approvals/tests/test_r7_p1_trusted_provisioning_static.py` now reads the full archived provisioning runbook for historical invariants and tests the deploy pointer separately.
2. `fortis_approvals/tests/test_universal_gateway_acceptance_matrix.py` now reads the full archived acceptance matrix and tests the deploy pointer separately.
3. The universal-matrix test was aligned to the exact archived wording `real Sonar WRITE BLOCKED`.
4. The source README links to the archived acceptance matrix and explicitly labels it historical.
5. The source README and deploy README were normalized to the owner-approved Fortis Approvals Gateway naming; exact old image and Compose identifiers remain documented for provenance.
6. A new render-only target-name Compose candidate, `fortis_approvals/deploy/compose-fortis-approvals-dryrun.yaml`, was added after extraction. It is a new planning artifact, not part of the original 196-file source snapshot and not a live deployment file.

The original `SOURCE-MANIFEST.sha256` remains immutable and describes the extracted source snapshot. It reports exactly four changed original package files: the two test corrections and the source/deploy README updates. `CURRENT-SOURCE-MANIFEST.sha256` describes those same 196 original manifest entries after the changes; the new dry-run candidate is intentionally outside both extraction manifests. Both manifests contain 196 entries.

## Offline test result

See [TEST-RESULTS-2026-11-03.md](../TEST-RESULTS-2026-11-03.md): 198 tests passed across 26 selected offline/static suites. Several additional suites remain blocked by missing pinned `cryptography` and `fido2` packages; no packages were installed into the running container.

## Important boundary

The extracted tree is a local development copy, not a deployed runtime. The deployed Fortis Approvals Gateway image is owner-reported as a separately built artifact; its exact image ID and historical image tag are recorded in the current-state guide. Changing this source does not update that image. The source tree and deployment reference must be reviewed before any future build.

The original source remains under the dirty `rd-graphs` worktree and is still untracked by Git. Do not delete or stage it as part of RDG work. The extraction does not resolve GitHub remote visibility, branch policy, remote permissions or credential isolation; those remain outside the first documentation stage.

## Follow-up classification

1. **Deferred code-maintenance item:** module docstrings in `repo_action_contract.py` and `sonar.py` retain wording from earlier candidates. They are flagged in the Fortis Container source map and must not override the current-state guide or deployed-image evidence. Correct them only during a separately reviewed source-maintenance task; this is not a blocker for the documentation-layout stage.
2. **Completed:** deployment scripts and Dockerfiles are classified in `fortis_approvals/deploy/README.md`; the image-only build script's pinned Dockerfile is distinguished from the older top-level server Dockerfile.
3. **Completed:** the owner accepted this local copy as the canonical development source and approved the standalone `fortis-approvals` repository.
4. **Completed:** local Git was initialized on `main`. No commit or remote exists; remote creation and publishing remain deferred.
