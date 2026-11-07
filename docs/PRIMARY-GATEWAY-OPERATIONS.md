# Primary Fortis Gateway — operator procedure

The initial Backup/Promote, Docker Desktop restart and Legacy retirement were
owner-confirmed on 2026-11-07 in
[dated cutover evidence](../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md).
Later image releases replaced that initial Primary; its container/image IDs are
not today's deployment pins. [Current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)
owns the latest confirmed runtime/source record. Before any operation, resolve
exact IDs, configuration and state through protected controller records and
live readback. Keep provider credentials, owner state and referenced rollback
artifacts. Normal ports remain 19203/19204; retained Legacy is not a fallback.

## Architecture and roles

- ONE Primary Gateway process handles authenticated Approvals, SonarCloud,
  GitHub/native worktree and installed extension operations. Not a generic proxy:
  only installed typed operations/grants/policies are available.
- `fortis-repo-test` remains a separate authorized machine client / local
  native-worktree worker. GitHub Actions run on GitHub, not in another Gateway.
- Only Primary receives normal Repo work. Legacy may stay stopped without losing
  the retained rollback state; it is not a replacement for GitHub/native recovery.
- Primary defaults to machine port `19204`, owner portal `19203`. No automatic
  fallback to legacy `19104` and no bypass through provider tokens/helpers.

## One-time operator adoption (Windows PowerShell 5.1)

**Historical completed adoption.** The sequence below explains the original
promotion and its contract; do not rerun it merely to update documentation or
copy its old runtime pins. Normal image releases use the next section.

1. Accept source changes through Gateway PR/CI/owner-approved merge and get the
   approved merged `main` into the clean Windows clone by the Mirror procedure.
   Check file hashes, exact source SHA and PowerShell parse before executing.
2. Ensure the *existing* accepted Gateway is healthy, protected `current.json`
   points to a Complete release, no undecided active request, no conflicting
   writer, and `fortis-gateway` is not already owned by an unrelated container.
3. In the accepted Windows clone, run:

   ```powershell
   $dir = Join-Path $HOME 'Repos\fortis-approvals\fortis_approvals\deploy'
   $manager = Join-Path $dir 'Manage-Integrations.ps1'
   $errors = $null; $tokens = $null
   foreach ($script in @($manager,(Join-Path $dir 'Primary-Gateway.ps1'),
                         (Join-Path $dir 'Provider-Credentials.ps1'))) {
       [void][Management.Automation.Language.Parser]::ParseFile($script,[ref]$tokens,[ref]$errors)
       if ($errors.Count) { throw "POWERSHELL_PARSE_FAILED: $script" }
   }
   & $manager -Action SelfTest
   & $manager -Action Backup
   & $manager -Action Promote
   ```

   `Backup` stops only the pinned candidate briefly, creates a new named-volume
   copy and compares complete native/GitHub/Sonar/Owner state receipts, stores a
   protected receipt under `%LOCALAPPDATA%\Fortis\GatewayReleases`, then starts
   the same container and checks health. It never copies credentials into Repo.
   The backup is a local Docker recovery copy, not an off-machine disaster backup.
   `Promote` requires that protected verified backup; changes only container
   name to `fortis-gateway` and restart to `unless-stopped`, then writes
   **separate** `primary.json` without altering the old release record.
4. Check Docker identity, image, read-only secret mounts and policy:

   ```powershell
   docker inspect fortis-gateway --format '{{.Id}} | {{.Name}} | {{.State.Health.Status}} | {{.HostConfig.RestartPolicy.Name}}'
   docker ps --filter 'name=^/fortis-gateway$' --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
   ```

   Expected same pinned ID/image/state/ports, `healthy`, `unless-stopped`.
   **STOP** for any discrepancy; no manual editing protected records.

## Normal releases after adoption

`Manage-Integrations.ps1 -Action Apply` retains the exact source, stages a
new image in a run-specific container (`restart=no`), performs readbacks and
writes a new protected Complete record. Following successful activation and
owner evidence, run `-Action Backup` and `-Action Promote` again. The former
Primary (now stopped) gets its historical name and `restart=no`. Do not try to
start two Gateways on the same published ports or RW state volume. Resume/Return
must continue using the original attempt record, not fabricated identifiers.

## Acceptance and retirement

1. From actual Fortis Repo client: verify Sonar Quality Gate/Issues, GitHub
   repository/branches/open PRs/Actions, live capabilities and TLS machine grant.
2. Verify Owner Portal/WebAuthn on 19203; preserve ALLOW/ASK/DENY restrictions.
3. Confirm no normal client uses Legacy 19104. Set only its restart policy to
   `no`, stop only its exact ID; do not delete image, state or credential volumes.
   Updating Legacy's old Compose service can reconfigure it: don't `compose up`
   that project during normal operation.
4. During an agreed maintenance window restart Docker Desktop and confirm
   `fortis-gateway` becomes healthy and Repo readbacks pass without manual start.
   Docker Desktop must itself start with the user session; engine-level service
   before Windows logon is a different deployment goal.
5. Record verified host output, final release pointer, retained recovery volume
   and limits for the new release. Do not overwrite the initial cutover evidence
   or present an old acceptance result as a fresh check.
   The reported owner host output and Repo readback confirm deployment; a fresh
   full ALLOW/ASK/DENY policy acceptance cycle is still outstanding.

## STOP and rollback boundaries

Mismatched source image/record, unexpected writer, insecure mount/ACL, missing
backup, owner credential mismatch, pending or uncertain effect, unhealthy
Gateway, parse failure or any Docker rename ambiguity means STOP. The controller
attempts bounded name/policy rollback only on exact IDs and reports
`PRIMARY_PROMOTION_RECOVERY_REQUIRED` if reconciliation is necessary.
Rolling back an installed image never undoes already published GitHub changes;
compare receipts and GitHub head before any state restore. Do not repoint
clients to Legacy as an automatic fallback.
