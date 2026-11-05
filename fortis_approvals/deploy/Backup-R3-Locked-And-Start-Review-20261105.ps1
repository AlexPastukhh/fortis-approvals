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

function Read-PrivateFrameLine {
    param([Diagnostics.Process]$Process)
    $Task = $Process.StandardOutput.ReadLineAsync()
    if (-not $Task.Wait(60000)) { throw 'R3_BACKUP_TRANSPORT_TIMEOUT' }
    $Line = $Task.Result
    if ($null -eq $Line) { throw 'R3_BACKUP_EXPORTER_CLOSED_PIPE' }
    return $Line
}
function Assert-NewBackupAcl {
    param([string]$Folder)
    $Paths = @($Folder) + @(Get-ChildItem -LiteralPath $Folder -Force -File | ForEach-Object { $_.FullName })
    foreach ($Path in $Paths) {
        $Acl = Get-Acl -LiteralPath $Path
        if ($Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $OwnerSid.Value) {
            throw 'R3_BACKUP_ACL_OWNER_MISMATCH'
        }
        foreach ($Rule in $Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($Rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $AllowedSids -cnotcontains $Rule.IdentityReference.Value) { throw 'R3_BACKUP_ACL_UNEXPECTED_ALLOW' }
        }
    }
    if (-not (Get-Acl -LiteralPath $Folder).AreAccessRulesProtected) { throw 'R3_BACKUP_ROOT_INHERITANCE_NOT_PROTECTED' }
}
$OwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$AllowedSids = @($OwnerSid.Value,'S-1-5-18','S-1-5-32-544')
$BackupName = 'R3-pre-stop-20261105-' + [Guid]::NewGuid().ToString('N')
$BackupDir = Join-Path (Join-Path $env:LOCALAPPDATA 'Fortis\Backups') $BackupName
if (Test-Path -LiteralPath $BackupDir) { throw 'R3_BACKUP_TARGET_ALREADY_EXISTS' }
$null = [IO.Directory]::CreateDirectory($BackupDir)
$Acl = [Security.AccessControl.DirectorySecurity]::new()
$Acl.SetAccessRuleProtection($true,$false)
$Acl.SetOwner($OwnerSid)
$Inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
foreach ($SidValue in $AllowedSids) {
    $Sid = [Security.Principal.SecurityIdentifier]::new($SidValue)
    $Rule = [Security.AccessControl.FileSystemAccessRule]::new($Sid,
        [Security.AccessControl.FileSystemRights]::FullControl,$Inheritance,
        [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
    $Acl.AddAccessRule($Rule)
}
Set-Acl -LiteralPath $BackupDir -AclObject $Acl
Assert-NewBackupAcl $BackupDir
Write-Host ('R3_PROTECTED_BACKUP_DIRECTORY=' + $BackupDir)
$Export = Get-Content (Join-Path $PSScriptRoot 'snapshot_smoke_locked.py') -Raw
$Export64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Export))
$ExportCode = "import base64;exec(compile(base64.b64decode('$Export64'),'<r3-locked-snapshot>','exec'))"
$Info = [Diagnostics.ProcessStartInfo]::new()
$Info.FileName = (Get-Command docker.exe).Source
$Info.Arguments = 'exec -i --user 10001:10001 ' + $Blocker.Id + ' python -B -u -c "' + $ExportCode + '"'
$Info.UseShellExecute = $false
$Info.CreateNoWindow = $true
$Info.RedirectStandardInput = $true
$Info.RedirectStandardOutput = $true
$Info.RedirectStandardError = $true
$Exporter = [Diagnostics.Process]::new()
$Exporter.StartInfo = $Info
$ProcessStarted = $false
$StopSucceeded = $false
try {
    if (-not $Exporter.Start()) { throw 'R3_BACKUP_EXPORTER_START_FAILED' }
    $ProcessStarted = $true
    $Exporter.StandardInput.AutoFlush = $true
    # Export stdout is private transport, not console output or a transcript.
    $Header = Read-PrivateFrameLine $Exporter
    if ($Header -notmatch '^FORTIS_R3_LOCKED_ZIP_V1 ([0-9]+) ([0-9a-f]{64})$') { throw 'R3_BACKUP_FRAME_HEADER_INVALID' }
    $EncodedLength = [long]$Matches[1]
    $ExpectedZipHash = $Matches[2]
    if ($EncodedLength -le 0 -or $EncodedLength -gt 24000000) { throw 'R3_BACKUP_FRAME_LENGTH_INVALID' }
    $PrivateLine = Read-PrivateFrameLine $Exporter
    if ($PrivateLine.Length -ne $EncodedLength) { throw 'R3_BACKUP_FRAME_TRUNCATED' }
    try { $PrivateBytes = [Convert]::FromBase64String($PrivateLine) }
    catch { throw 'R3_BACKUP_FRAME_ENCODING_INVALID' }
    $PrivateLine = $null
    $ArchiveFile = Join-Path $BackupDir 'snapshot.zip'
    $Stream = [IO.FileStream]::new($ArchiveFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $Stream.Write($PrivateBytes,0,$PrivateBytes.Length); $Stream.Flush($true) }
    finally { $Stream.Dispose() }
    $PrivateBytes = $null
    if ((Get-FileHash -LiteralPath $ArchiveFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedZipHash) {
        throw 'R3_BACKUP_ARCHIVE_HASH_MISMATCH'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Zip = [IO.Compression.ZipFile]::OpenRead($ArchiveFile)
    try {
        $ExpectedEntries = @('.fortis-r7-unified-v1','approvals.sqlite','owner.sqlite','sonar-receipts.sqlite','manifest.json','manifest.sha256')
        $ActualEntries = @($Zip.Entries | ForEach-Object { $_.FullName })
        if (Compare-Object ($ExpectedEntries | Sort-Object) ($ActualEntries | Sort-Object) -CaseSensitive) {
            throw 'R3_BACKUP_ARCHIVE_FILE_SET_INVALID'
        }
        if (($Zip.Entries | Measure-Object -Property Length -Sum).Sum -gt 134217728) { throw 'R3_BACKUP_ARCHIVE_UNPACKED_SIZE_INVALID' }
    } finally { $Zip.Dispose() }
    Expand-Archive -LiteralPath $ArchiveFile -DestinationPath $BackupDir
    Assert-NewBackupAcl $BackupDir
    $Verifier = Get-Content (Join-Path $PSScriptRoot 'verify_smoke_backup.py') -Raw
    $Verifier64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Verifier))
    $VerifyCode = "import base64,json;ns={};exec(compile(base64.b64decode('$Verifier64'),'<verify-protected-r3-backup>','exec'),ns);print(json.dumps(ns['verify']('/backup'),sort_keys=True))"
    $VerifyArguments = @('run','--rm','--pull=never','--network','none','--read-only','--user','0:0',
        '--cap-drop','ALL','--cap-add','DAC_OVERRIDE','--security-opt','no-new-privileges:true',
        '--pids-limit','64','--memory','128m','--mount',"type=bind,source=$BackupDir,target=/backup,readonly",
        '--entrypoint','python',$HelperImage,'-c',$VerifyCode)
    $Previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $VerifiedOutput = @(& docker.exe @VerifyArguments 2>&1); $VerifyExit = $LASTEXITCODE }
    finally { $ErrorActionPreference = $Previous }
    $VerifiedOutput | ForEach-Object { Write-Host ([string]$_) }
    if ($VerifyExit -ne 0) { throw 'R3_BACKUP_SQLITE_VERIFICATION_FAILED_NO_STOP' }
    $ReceiptLines = @($VerifiedOutput | ForEach-Object { [string]$_ } | Where-Object { $_.StartsWith('{') })
    if ($ReceiptLines.Count -ne 1) { throw 'R3_BACKUP_VERIFICATION_RECEIPT_INVALID' }
    $Verified = $ReceiptLines[0] | ConvertFrom-Json
    if ($Verified.verification -cne 'PASS' -or $Verified.allLogicalContentHashesMatch -ne $true -or
        $Verified.summary.requests -lt 1 -or $Verified.summary.events -lt 1) { throw 'R3_BACKUP_UNEXPECTED_SUMMARY_NO_STOP' }
    $Fresh = Read-StopContainer $Blocker.Id
    if (((Select-StopInspect $Fresh) | ConvertTo-Json -Depth 10 -Compress) -cne $SummaryJson) {
        throw 'R3_CONFIGURATION_CHANGED_BEFORE_STOP'
    }
    if ((Read-StopProductionBaseline) -cne $Before) { throw 'PRODUCTION_CHANGED_BEFORE_R3_STOP' }
    $Exporter.StandardInput.WriteLine('STATUS')
    $Lease = Read-PrivateFrameLine $Exporter
    if ($Lease -notmatch '^R3_LOCKS_HELD ([0-9]+)$' -or [int]$Matches[1] -lt 60 -or $Exporter.HasExited) {
        throw 'R3_SOURCE_LOCKS_NOT_HELD_OR_LEASE_TOO_SHORT_NO_STOP'
    }
    Write-Host 'R3_PROTECTED_BACKUP_VERIFIED_SOURCE_READ_LOCKS_HELD_PASS'
    Write-Host ('R3_BACKUP_ARCHIVE_SHA256=' + $ExpectedZipHash)
    Write-Host ('R3_BACKUP_MANIFEST_SHA256=' + $Verified.manifestSha256)
    Write-Host "STOPPING_ONLY_BACKED_UP_R3_ID=$($Blocker.Id)"
    $Previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & docker.exe stop --timeout 20 $Blocker.Id; $StopExit = $LASTEXITCODE }
    finally { $ErrorActionPreference = $Previous }
    if ($StopExit -ne 0) { throw 'R3_STOP_FAILED_INSPECT_BEFORE_RETRY' }
    $Stopped = Read-StopContainer $Blocker.Id
    if ($Stopped.State.Status -cne 'exited') { throw 'R3_DID_NOT_STOP' }
    $StopSucceeded = $true
    if (-not $Exporter.WaitForExit(10000)) { throw 'R3_EXPORT_TRANSPORT_NOT_CLOSED_AFTER_STOP' }
    Write-Host ('R3_EXPORTER_EXIT_AFTER_CONTAINER_STOP=' + $Exporter.ExitCode)
    if ((Get-FileHash $ArchiveFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedZipHash) {
        throw 'R3_BACKUP_ARCHIVE_CHANGED_AFTER_STOP'
    }
    Assert-NewBackupAcl $BackupDir
} catch {
    if ($ProcessStarted -and $Exporter.HasExited -and -not $StopSucceeded) {
        $Diagnostic = $Exporter.StandardError.ReadToEnd()
        if ($Diagnostic.Length -gt 0) {
            $Diagnostic = [regex]::Replace($Diagnostic,'[A-Za-z0-9+/=]{100,}','[encoded text redacted]')
            Write-Host ('R3_EXPORTER_DIAGNOSTIC=' + $Diagnostic.Substring(0,[Math]::Min(4000,$Diagnostic.Length)))
        }
    }
    throw
} finally {
    if ($ProcessStarted -and -not $Exporter.HasExited) {
        # On failure before stopping, release read locks and retain the running r3.
        try { $null = $Exporter.StandardOutput.ReadToEndAsync() } catch {}
        try { $Exporter.StandardInput.WriteLine('RELEASE'); $Exporter.StandardInput.Flush() } catch {}
        if (-not $Exporter.WaitForExit(5000)) {
            try { $Exporter.StandardInput.Close() } catch {}
        }
    }
    $Exporter.Dispose()
}
if (-not $StopSucceeded) { throw 'R3_STOP_NOT_CONFIRMED' }

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
Write-Host 'NONEMPTY_SMOKE_STATE_PRESERVED_IN_VERIFIED_WINDOWS_BACKUP=YES'
Write-Host ('R3_BACKUP_DIRECTORY=' + $BackupDir)
