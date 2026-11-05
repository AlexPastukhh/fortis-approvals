param(
    [string]$BackupDir = 'C:\Users\alexa\AppData\Local\Fortis\Backups\R7-pre-cutover-20261105-175200-c879d04aa14b4126b4f5a56932ade799'
)
$ErrorActionPreference = 'Stop'
$TargetVolume = 'fortis-r7-state-review-20261105'
$HelperImage = 'sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84'
$ImageSnapshot = '3a0d8f99f11a2f27dd1467593e1ac37ce452a183c19c7abf685643e1727b6d14'
$PinnedManifestHash = '0b783913f0465ab9fb8fc098953ae0b74070cc6f8e854845258390486f7078dd'
$ExpectedProductionImage = 'sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402'

function Read-ProductionBaseline {
    $Raw = (& docker.exe inspect --type container fortis-approvals-gateway | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'PRODUCTION_INSPECT_FAILED' }
    $Item = (ConvertFrom-Json $Raw)[0]
    if ($Item.Image -cne $ExpectedProductionImage -or
        $Item.State.Status -cne 'running' -or $Item.State.Health.Status -cne 'healthy') {
        throw 'PRODUCTION_IDENTITY_OR_HEALTH_MISMATCH'
    }
    return ([ordered]@{ id=$Item.Id; startedAt=$Item.State.StartedAt; image=$Item.Image
        mounts=$Item.Mounts; ports=$Item.HostConfig.PortBindings } | ConvertTo-Json -Depth 8 -Compress)
}
function Read-OneReceipt {
    param([object[]]$Lines)
    $JsonLines = @($Lines | ForEach-Object { [string]$_ } | Where-Object { $_.StartsWith('{') })
    if ($JsonLines.Count -ne 1) { throw 'HELPER_RECEIPT_MISSING_OR_AMBIGUOUS' }
    return ($JsonLines[0] | ConvertFrom-Json)
}
function Encode-Python {
    param([string]$File)
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { throw 'REVIEW_HELPER_MISSING' }
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content -LiteralPath $File -Raw)))
}
$DockerInfo = (& docker.exe info --format '{{.OSType}}' | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $DockerInfo -cne 'linux') { throw 'DOCKER_LINUX_ENGINE_REQUIRED' }
$ProductionBefore = Read-ProductionBaseline
$ImageRaw = (& docker.exe image inspect $HelperImage | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'PINNED_REVIEW_IMAGE_MISSING' }
$ImageInfo = (ConvertFrom-Json $ImageRaw)[0]
if ($ImageInfo.Id -cne $HelperImage -or $ImageInfo.Config.User -cne '10001:10001' -or
    $ImageInfo.Config.Labels.'org.opencontainers.image.source-snapshot-sha256' -cne $ImageSnapshot) {
    throw 'PINNED_REVIEW_IMAGE_METADATA_MISMATCH'
}
$RestoreEncoded = Encode-Python (Join-Path $PSScriptRoot 'restore_review_state.py')
$VerifyEncoded = Encode-Python (Join-Path $PSScriptRoot 'verify_review_state.py')
if (-not (Test-Path -LiteralPath $BackupDir -PathType Container)) { throw 'R7_BACKUP_DIRECTORY_MISSING' }
$ExpectedFiles = @('.fortis-r7-unified-v1','approvals.sqlite','owner.sqlite','sonar-receipts.sqlite')
$ManifestPath = Join-Path $BackupDir 'manifest.json'
$HashPath = Join-Path $BackupDir 'manifest.sha256'
$OwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$AllowedSids = @($OwnerSid,'S-1-5-18','S-1-5-32-544')
$AclPaths = @($BackupDir,$ManifestPath,$HashPath) + @($ExpectedFiles | ForEach-Object { Join-Path $BackupDir $_ })
foreach ($Path in $AclPaths) {
    $Item = Get-Item -LiteralPath $Path -Force
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'BACKUP_REPARSE_POINT_DENIED' }
    $Acl = Get-Acl -LiteralPath $Path
    if (-not $Acl.AreAccessRulesProtected -or $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $OwnerSid) {
        throw ('BACKUP_ACL_OWNER_OR_INHERITANCE_MISMATCH:' + $Item.Name)
    }
    $Rules = $Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
    foreach ($Rule in $Rules) {
        if ($Rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $AllowedSids -cnotcontains $Rule.IdentityReference.Value) {
            throw ('BACKUP_ACL_UNEXPECTED_ALLOW:' + $Item.Name + ':' + $Rule.IdentityReference.Value)
        }
    }
    Write-Host ('BACKUP_ACL_PATH_PASS=' + $Item.Name)
}
Write-Host 'BACKUP_ACL_ALL_SEVEN_PATHS_PASS'
$ActualManifestHash = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ActualManifestHash -cne $PinnedManifestHash) { throw 'R7_PINNED_MANIFEST_HASH_MISMATCH' }
$HashLine = (Get-Content -LiteralPath $HashPath -Raw).Trim()
if ($HashLine -notmatch '^([0-9a-f]{64})(?:\s+.*)?$' -or $Matches[1] -cne $PinnedManifestHash) {
    throw 'R7_BACKUP_MANIFEST_HASH_FILE_INVALID'
}
$Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$ActualFiles = @($Manifest.sha256.PSObject.Properties.Name | Sort-Object)
if (Compare-Object ($ExpectedFiles | Sort-Object) $ActualFiles) { throw 'R7_BACKUP_FILE_SET_MISMATCH' }
foreach ($Name in $ExpectedFiles) {
    $File = Join-Path $BackupDir $Name
    $Hash = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Hash -cne $Manifest.sha256.$Name) { throw ('R7_BACKUP_FILE_HASH_MISMATCH:' + $Name) }
}
if ($Manifest.ownerBindingPass -ne $true -or $Manifest.databases.'owner.sqlite'.credentialsActive -ne 1) {
    throw 'R7_BACKUP_OWNER_STATE_MISMATCH'
}
$Volumes = @(& docker.exe volume ls --format '{{.Name}}')
if ($LASTEXITCODE -ne 0) { throw 'DOCKER_VOLUME_LIST_FAILED' }
if ($Volumes -ccontains $TargetVolume) { throw 'R7_REVIEW_VOLUME_ALREADY_EXISTS_NO_OVERWRITE' }
$VolumeResult = (& docker.exe volume create $TargetVolume | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $VolumeResult -cne $TargetVolume) { throw 'R7_REVIEW_VOLUME_CREATE_FAILED' }
$PythonCommand = "import base64;exec(compile(base64.b64decode('$RestoreEncoded'),'<r7-review-restore>','exec'))"
$RunArguments = @('run','--rm','--pull=never','--network','none','--read-only',
    '--user','0:0','--cap-drop','ALL','--cap-add','CHOWN','--cap-add','DAC_OVERRIDE',
    '--security-opt','no-new-privileges:true','--pids-limit','64','--memory','128m',
    '--tmpfs','/tmp:rw,nosuid,nodev,size=16m',
    '--mount',"type=volume,source=$TargetVolume,target=/state",
    '--mount',"type=bind,source=$BackupDir,target=/backup,readonly",
    '--entrypoint','python',$HelperImage,'-c',$PythonCommand)
$Previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $Output = @(& docker.exe @RunArguments 2>&1)
    $RestoreExitCode = $LASTEXITCODE
} finally { $ErrorActionPreference = $Previous }
$Output | ForEach-Object { Write-Host ([string]$_) }
if ($RestoreExitCode -ne 0) { throw 'R7_REVIEW_RESTORE_FAILED_VOLUME_LEFT_FOR_INSPECTION' }
$Receipt = Read-OneReceipt -Lines $Output
if ($Receipt.manifestSha256 -cne $PinnedManifestHash -or $Receipt.credentialsUnchanged -ne $true -or
    $Receipt.historyBytesUnchanged -ne $true -or $Receipt.ownerOrigin -cne 'http://localhost:19203' -or
    $Receipt.rpId -cne 'localhost' -or $Receipt.credentialsActive -ne 1 -or
    $Receipt.events -ne $Manifest.databases.'approvals.sqlite'.events -or
    $Receipt.receipts -ne $Manifest.databases.'sonar-receipts.sqlite'.receipts -or
    $Receipt.ownerCopySha256 -notmatch '^[0-9a-f]{64}$') { throw 'RESTORE_RECEIPT_INVALID' }
foreach ($Name in @('.fortis-r7-unified-v1','approvals.sqlite','sonar-receipts.sqlite')) {
    if ($Receipt.sha256.$Name -cne $Manifest.sha256.$Name) { throw 'RESTORED_HISTORY_RECEIPT_HASH_MISMATCH' }
}
if ($Receipt.sha256.'owner.sqlite' -cne $Receipt.ownerCopySha256) { throw 'RESTORED_OWNER_RECEIPT_HASH_MISMATCH' }
$ReceiptEncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Receipt | ConvertTo-Json -Depth 8 -Compress)))
$VerifyCommand = "import base64,json;ns={'__name__':'review_verify'};exec(compile(base64.b64decode('$VerifyEncoded'),'<r7-review-verify>','exec'),ns);print(json.dumps(ns['verify']('/state',json.loads(base64.b64decode('$ReceiptEncoded'))),sort_keys=True));print('R7_REVIEW_UID10001_READONLY_VERIFY_PASS')"
$VerifyArguments = @('run','--rm','--pull=never','--network','none','--read-only',
    '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
    '--pids-limit','64','--memory','128m','--tmpfs','/tmp:rw,nosuid,nodev,size=16m',
    '--mount',"type=volume,source=$TargetVolume,target=/state,readonly",
    '--entrypoint','python',$HelperImage,'-c',$VerifyCommand)
$Previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $VerifyOutput = @(& docker.exe @VerifyArguments 2>&1)
    $VerifyExitCode = $LASTEXITCODE
} finally { $ErrorActionPreference = $Previous }
$VerifyOutput | ForEach-Object { Write-Host ([string]$_) }
if ($VerifyExitCode -ne 0) { throw 'R7_REVIEW_RUNTIME_UID_VERIFICATION_FAILED_VOLUME_LEFT_FOR_INSPECTION' }
$Verified = Read-OneReceipt -Lines $VerifyOutput
if ($Verified.verification -cne 'PASS' -or $Verified.uid -ne 10001 -or $Verified.gid -ne 10001 -or
    $Verified.allHashesMatchRestoreReceipt -ne $true) { throw 'READONLY_VERIFIER_RECEIPT_INVALID' }
foreach ($Name in $ExpectedFiles) {
    $Hash = (Get-FileHash -LiteralPath (Join-Path $BackupDir $Name) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Hash -cne $Manifest.sha256.$Name) { throw 'BACKUP_CHANGED_DURING_RESTORE' }
}
if ((Get-FileHash $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $PinnedManifestHash) {
    throw 'BACKUP_MANIFEST_CHANGED_DURING_RESTORE'
}
$ProductionAfter = Read-ProductionBaseline
if ($ProductionAfter -cne $ProductionBefore) { throw 'PRODUCTION_BASELINE_CHANGED_DURING_RESTORE' }
Write-Host 'FORTIS_R7_REVIEW_STATE_VOLUME_READY'
Write-Host "VOLUME=$TargetVolume"
Write-Host "HELPER_IMAGE_ID=$HelperImage"
Write-Host 'PRODUCTION_CONTAINER_BASELINE_UNCHANGED=YES'
Write-Host 'BACKUP_BYTES_UNCHANGED=YES'
Write-Host 'EXISTING_CLONE_VOLUME_CHANGED=NO'
Write-Host 'REVIEW_GATEWAY_STARTED=NO'
Write-Host 'PUBLISHED_PORTS=NONE'
