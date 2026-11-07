# Windows PowerShell 5.1, trusted owner console only. Default Preview has no mutation.
# -Issue creates a one-use invitation, valid for 300s; DO NOT paste it into chat/logs.
[CmdletBinding()]
param([switch]$Issue)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or
    $PSVersionTable.PSEdition -cne 'Desktop') { throw 'OWNER_INVITE_POWERSHELL_51_REQUIRED' }
$base = Join-Path $env:LOCALAPPDATA 'Fortis\GatewayReleases'
$pointerPath = Join-Path $base 'primary.json'
if (-not (Test-Path -LiteralPath $pointerPath -PathType Leaf)) { throw 'OWNER_INVITE_PRIMARY_POINTER_REQUIRED' }
$record = Get-Content -LiteralPath $pointerPath -Raw | ConvertFrom-Json
if ($record.schema -cne 'fortis-primary-v1' -or $record.phase -cne 'Complete') {
    throw 'OWNER_INVITE_PRIMARY_RECORD_INVALID'
}
$runtime = $record.runtime
if ($runtime.pilotName -cne 'fortis-gateway' -or
    $runtime.restartPolicy -cne 'unless-stopped' -or
    $runtime.pilotId -cnotmatch '^[a-f0-9]{64}$' -or
    $runtime.image -cnotmatch '^sha256:[a-f0-9]{64}$' -or
    $runtime.stateVolume -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$') {
    throw 'OWNER_INVITE_PRIMARY_IDENTITY_INVALID'
}
$raw = @(& docker container inspect --type container $runtime.pilotId --format '{{json .}}')
if ($LASTEXITCODE -ne 0 -or $raw.Count -ne 1) { throw 'OWNER_INVITE_DOCKER_INSPECT_FAILED' }
$c = $raw[0] | ConvertFrom-Json
if ($c.Id -cne $runtime.pilotId -or $c.Image -cne $runtime.image -or
    $c.Name -cne '/fortis-gateway' -or $c.State.Running -ne $true -or
    $c.State.Health.Status -cne 'healthy' -or
    $c.HostConfig.RestartPolicy.Name -cne 'unless-stopped') {
    throw 'OWNER_INVITE_PRIMARY_NOT_ADMITTED'
}
$state = @($c.Mounts | Where-Object { $_.Destination -ceq '/state' })
if ($state.Count -ne 1 -or $state[0].Type -cne 'volume' -or
    $state[0].Name -cne $runtime.stateVolume -or $state[0].RW -ne $true) {
    throw 'OWNER_INVITE_STATE_MOUNT_CHANGED'
}
if (-not $Issue) {
    Write-Host 'OWNER_INVITE_PREVIEW_PASS'
    Write-Host 'Owner can explicitly run the same file with -Issue in trusted Windows PowerShell 5.1.'
    return
}
# No secret values are supplied via argv. Token is printed ONLY to the trusted owner's terminal.
# The running Gateway does not need stopping; SQLite provides transactional protection.
$code = "import sys;sys.path.insert(0,'/opt/fortis');from fortis_approvals.owner_auth import OwnerWebAuthn;print(OwnerWebAuthn('/state/private/owner.sqlite',origin='http://localhost:19203').issue_invitation())"
$invite = @(& docker exec --user 10001:10001 $runtime.pilotId python -I -B -c $code)
if ($LASTEXITCODE -ne 0 -or $invite.Count -ne 1 -or $invite[0] -cnotmatch '^[A-Za-z0-9_-]{40,80}$') {
    throw 'OWNER_INVITE_ISSUE_FAILED'
}
Write-Host 'OWNER_INVITE_ISSUED_EXPIRY_300_SECONDS'
Write-Host 'Paste this invitation ONLY into http://localhost:19203 registration form:'
Write-Host $invite[0]
Write-Host 'Never paste the invitation into ChatGPT, logs, tickets or Git.'
