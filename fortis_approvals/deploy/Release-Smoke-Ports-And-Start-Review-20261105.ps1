$ErrorActionPreference = 'Stop'
$BlockerName = 'fortis-gateway-candidate-smoke-r3-20261105'
$ReviewName = 'fortis-gateway-modularized-review-20261105'
$HelperImage = 'sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84'
$ProductionImage = 'sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402'
function Read-StopContainer {
    param([string]$Name)
    $Raw = (& docker.exe inspect --type container $Name | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'SMOKE_OR_PRODUCTION_INSPECT_FAILED' }
    return (ConvertFrom-Json $Raw)[0]
}
function Read-StopProductionBaseline {
    $C = Read-StopContainer 'fortis-approvals-gateway'
    if ($C.Image -cne $ProductionImage -or $C.State.Status -cne 'running' -or
        $C.State.Health.Status -cne 'healthy') { throw 'PRODUCTION_BASELINE_MISMATCH' }
    return ([ordered]@{ id=$C.Id; image=$C.Image; startedAt=$C.State.StartedAt
        mounts=$C.Mounts; ports=$C.HostConfig.PortBindings } | ConvertTo-Json -Depth 8 -Compress)
}
function Select-StopInspect {
    param([object]$C)
    # Only public configuration fields; never pass environment or credentials.
    return [ordered]@{ Id=$C.Id; Name=$C.Name; Image=$C.Image; Mounts=$C.Mounts
        Config=@{ User=$C.Config.User; Entrypoint=$C.Config.Entrypoint; Cmd=$C.Config.Cmd }
        State=@{ Status=$C.State.Status; Health=@{ Status=$C.State.Health.Status } }
        HostConfig=@{ ReadonlyRootfs=$C.HostConfig.ReadonlyRootfs; Privileged=$C.HostConfig.Privileged
            AutoRemove=$C.HostConfig.AutoRemove; Binds=$C.HostConfig.Binds
            VolumesFrom=$C.HostConfig.VolumesFrom; Devices=$C.HostConfig.Devices
            PidMode=$C.HostConfig.PidMode; IpcMode=$C.HostConfig.IpcMode
            NetworkMode=$C.HostConfig.NetworkMode; PortBindings=$C.HostConfig.PortBindings; Tmpfs=$C.HostConfig.Tmpfs } }
}
$Tokens = $null
$ParseErrors = $null
foreach ($Name in @('Start-Modularized-Review-20261105.ps1','Test-Modularized-Review-Sonar-GET-20261105.ps1')) {
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot $Name),[ref]$Tokens,[ref]$ParseErrors)
    if ($ParseErrors.Count -ne 0) { throw ('REVIEW_SCRIPT_PARSE_FAILED:' + $Name) }
}
$Before = Read-StopProductionBaseline
$ExistingReview = @(& docker.exe ps -aq --filter "name=^/$ReviewName$")
if ($LASTEXITCODE -ne 0) { throw 'REVIEW_EXISTENCE_CHECK_FAILED' }
if ($ExistingReview.Count -ne 0) { throw 'REVIEW_ALREADY_EXISTS_NO_STOP_OR_REPLACE' }
$RawImage = (& docker.exe image inspect $HelperImage | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'PINNED_HELPER_IMAGE_MISSING' }
$Image = (ConvertFrom-Json $RawImage)[0]
if ($Image.Id -cne $HelperImage -or
    $Image.Config.Labels.'org.opencontainers.image.source-snapshot-sha256' -cne '3a0d8f99f11a2f27dd1467593e1ac37ce452a183c19c7abf685643e1727b6d14') {
    throw 'PINNED_HELPER_IMAGE_METADATA_MISMATCH'
}
$Blocker = Read-StopContainer $BlockerName
$Summary = Select-StopInspect $Blocker
$SummaryJson = $Summary | ConvertTo-Json -Depth 10 -Compress
Write-Host ('SMOKE_BLOCKER_PUBLIC_INSPECT=' + $SummaryJson)
$Contract = Get-Content (Join-Path $PSScriptRoot 'smoke_tmpfs_contract.py') -Raw
$Contract64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Contract))
$Inspect64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($SummaryJson))
$Code = "import base64,json;ns={};exec(compile(base64.b64decode('$Contract64'),'<smoke-stop-admission>','exec'),ns);print(json.dumps(ns['inspect_tmpfs'](json.loads(base64.b64decode('$Inspect64'))),sort_keys=True))"
if ($Code.Length -gt 24000) { throw 'SMOKE_INSPECT_PAYLOAD_TOO_LARGE' }
$Previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & docker.exe run --rm --pull=never --network none --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 --memory 128m --entrypoint python $HelperImage -c $Code
    $AdmissionExit = $LASTEXITCODE
} finally { $ErrorActionPreference = $Previous }
if ($AdmissionExit -ne 0) { throw 'SMOKE_STOP_NOT_ADMITTED_NO_CHANGES' }
$VolumePins = @{}
foreach ($Mount in @($Blocker.Mounts | Where-Object { $_.Type -ceq 'volume' })) {
    $Raw = (& docker.exe volume inspect $Mount.Name | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'SMOKE_VOLUME_INSPECT_FAILED_NO_STOP' }
    $Volume = (ConvertFrom-Json $Raw)[0]
    if ($Volume.Name -cne $Mount.Name -or $Volume.Driver -cne 'local' -or
        ($Volume.Options -and @($Volume.Options.PSObject.Properties).Count -ne 0) -or
        $Volume.Mountpoint -cne $Mount.Source) { throw 'SMOKE_VOLUME_DRIVER_OR_ALIAS_UNKNOWN_NO_STOP' }
    $VolumePins[$Mount.Name] = ([ordered]@{ Name=$Volume.Name; Driver=$Volume.Driver
        Mountpoint=$Volume.Mountpoint; CreatedAt=$Volume.CreatedAt } | ConvertTo-Json -Compress)
}
# Read only the three r3 SQLite databases. A nonempty temporary state is
# never stopped by this script; it needs a separate protected backup first.
$Probe = Get-Content (Join-Path $PSScriptRoot 'probe_smoke_state.py') -Raw
$Probe64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Probe))
$ProbeCode = "import base64,json;ns={};exec(compile(base64.b64decode('$Probe64'),'<r3-readonly-counts>','exec'),ns);print(json.dumps(ns['probe'](),sort_keys=True))"
$Previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $ProbeOutput = @(& docker.exe exec --user 10001:10001 $Blocker.Id python -B -c $ProbeCode 2>&1)
    $ProbeExit = $LASTEXITCODE
} finally { $ErrorActionPreference = $Previous }
$ProbeOutput | ForEach-Object { Write-Host ([string]$_) }
if ($ProbeExit -ne 0) { throw 'R3_STATE_PROBE_FAILED_NO_STOP' }
$ReportLines = @($ProbeOutput | ForEach-Object { [string]$_ } | Where-Object { $_.StartsWith('{') })
if ($ReportLines.Count -ne 1) { throw 'R3_STATE_PROBE_RECEIPT_INVALID_NO_STOP' }
$Report = $ReportLines[0] | ConvertFrom-Json
$Report64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Report | ConvertTo-Json -Depth 8 -Compress)))
$EmptyAdmissionCode = "import base64,json;ns={};exec(compile(base64.b64decode('$Contract64'),'<empty-r3-stop-admission>','exec'),ns);print(json.dumps(ns['admit_empty_stop'](json.loads(base64.b64decode('$Inspect64')),json.loads(base64.b64decode('$Report64'))),sort_keys=True))"
$Previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & docker.exe run --rm --pull=never --network none --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 --memory 128m --entrypoint python $HelperImage -c $EmptyAdmissionCode
    $EmptyAdmissionExit = $LASTEXITCODE
} finally { $ErrorActionPreference = $Previous }
if ($EmptyAdmissionExit -ne 0) { throw 'R3_STATE_NOT_PROVEN_EMPTY_NO_STOP_BACKUP_REQUIRED_IF_NONEMPTY' }
$Fresh = Read-StopContainer $Blocker.Id
if (((Select-StopInspect $Fresh) | ConvertTo-Json -Depth 10 -Compress) -cne $SummaryJson) {
    throw 'SMOKE_CONFIGURATION_CHANGED_BEFORE_STOP'
}
if ((Read-StopProductionBaseline) -cne $Before) { throw 'PRODUCTION_CHANGED_BEFORE_SMOKE_STOP' }
Write-Host "STOPPING_ONLY_VERIFIED_SMOKE_ID=$($Blocker.Id)"
$Previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & docker.exe stop --timeout 20 $Blocker.Id
    $StopExit = $LASTEXITCODE
} finally { $ErrorActionPreference = $Previous }
if ($StopExit -ne 0) { throw 'SMOKE_STOP_FAILED_INSPECT_BEFORE_RETRY' }
$Stopped = Read-StopContainer $Blocker.Id
if ($Stopped.State.Status -cne 'exited') { throw 'SMOKE_DID_NOT_STOP' }
foreach ($Mount in @($Blocker.Mounts | Where-Object { $_.Type -ceq 'volume' })) {
    $Raw = (& docker.exe volume inspect $Mount.Name | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'SMOKE_VOLUME_NOT_PRESENT_AFTER_STOP' }
    $Volume = (ConvertFrom-Json $Raw)[0]
    $Pin = [ordered]@{ Name=$Volume.Name; Driver=$Volume.Driver
        Mountpoint=$Volume.Mountpoint; CreatedAt=$Volume.CreatedAt } | ConvertTo-Json -Compress
    if ($Pin -cne $VolumePins[$Mount.Name]) { throw 'SMOKE_VOLUME_IDENTITY_MISMATCH' }
}
if ((Read-StopProductionBaseline) -cne $Before) { throw 'PRODUCTION_CHANGED_DURING_SMOKE_STOP' }
Write-Host 'VERIFIED_OLD_SMOKE_STOPPED_ALL_NAMED_VOLUMES_RETAINED_PASS'
& (Join-Path $PSScriptRoot 'Start-Modularized-Review-20261105.ps1')
if ((Read-StopProductionBaseline) -cne $Before) { throw 'PRODUCTION_CHANGED_DURING_REVIEW_START' }
Write-Host 'FORTIS_SMOKE_RELEASE_AND_REVIEW_START_PASS'
Write-Host 'OLD_SMOKE_CONTAINER_RETAINED=YES'
Write-Host 'OLD_SMOKE_VOLUMES_RETAINED=YES'
Write-Host 'ONLY_CONFIRMED_EMPTY_SMOKE_TMPFS_DISCARDED=YES'
