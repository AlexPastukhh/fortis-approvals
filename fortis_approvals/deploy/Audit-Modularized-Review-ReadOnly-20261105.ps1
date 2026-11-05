# Windows PowerShell 5.1. Observations only; no Docker lifecycle or database access.
param(
    [string]$BackupDir = 'C:\Users\alexa\AppData\Local\Fortis\Backups\R7-pre-cutover-20261105-175200-c879d04aa14b4126b4f5a56932ade799'
)
$ErrorActionPreference = 'Stop'
function Read-DockerJson {
    param([string[]]$DockerArguments)
    $Raw = @(& docker.exe @DockerArguments)
    if ($LASTEXITCODE -ne 0) { throw ('DOCKER_READ_FAILED:' + ($DockerArguments -join ' ')) }
    return (($Raw -join "`n") | ConvertFrom-Json)
}
$Engine = (& docker.exe info --format '{{.OSType}}' | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $Engine -cne 'linux') { throw 'DOCKER_LINUX_ENGINE_REQUIRED' }
$Names = @(& docker.exe ps -a --format '{{.Names}}')
if ($LASTEXITCODE -ne 0) { throw 'CONTAINER_INVENTORY_FAILED' }
$Wanted = @('fortis-approvals-gateway','fortis-repo-test',
    'fortis-gateway-state-clone-20261105','fortis-gateway-candidate-smoke-r2-20261105',
    'fortis-gateway-modularized-review-20261105')
$Containers = @()
foreach ($Name in $Wanted) {
    if ($Names -cnotcontains $Name) {
        $Containers += [ordered]@{ name=$Name; present=$false }
        continue
    }
    $Items = @(Read-DockerJson -DockerArguments @('inspect','--type','container',$Name))
    if ($Items.Count -ne 1) { throw 'CONTAINER_INSPECT_COUNT_INVALID' }
    $C = $Items[0]
    $Health = $null
    if ($C.State.Health) { $Health = $C.State.Health.Status }
    $Containers += [ordered]@{
        name=$Name; present=$true; id=$C.Id; imageId=$C.Image
        imageReference=$C.Config.Image; status=$C.State.Status; health=$Health
        user=$C.Config.User; readonlyRootfs=$C.HostConfig.ReadonlyRootfs
        privileged=$C.HostConfig.Privileged; ports=$C.NetworkSettings.Ports
        mounts=@($C.Mounts | Select-Object Type,Name,Source,Destination,RW)
        endpointEnvironment=@($C.Config.Env | Where-Object {
            $_ -cmatch '^FORTIS_(OWNER_ORIGIN|MACHINE_HOST)='
        })
    }
}
$ImageLines = @(& docker.exe image ls --no-trunc --format '{{json .}}')
if ($LASTEXITCODE -ne 0) { throw 'IMAGE_INVENTORY_FAILED' }
$Images = @()
foreach ($Line in $ImageLines) {
    $I = $Line | ConvertFrom-Json
    if ($I.Repository -notmatch '^fortis') { continue }
    $Detail = @(Read-DockerJson -DockerArguments @('image','inspect',$I.ID))[0]
    $Images += [ordered]@{ repository=$I.Repository; tag=$I.Tag; id=$Detail.Id
        revision=$Detail.Config.Labels.'org.opencontainers.image.revision'
        user=$Detail.Config.User }
}
$VolumeNames = @(& docker.exe volume ls --format '{{.Name}}')
if ($LASTEXITCODE -ne 0) { throw 'VOLUME_INVENTORY_FAILED' }
$Volumes = @($VolumeNames | Where-Object { $_ -cmatch '^fortis-' })
if (-not (Test-Path -LiteralPath $BackupDir -PathType Container)) { throw 'BACKUP_DIRECTORY_MISSING' }
$ManifestPath = Join-Path $BackupDir 'manifest.json'
$ManifestHash = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$HandoffHash = '0b783913f0465ab9fb8fc098953ae0b74070cc6f8e854845258390486f7078dd'
$Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$ExpectedNames = @('.fortis-r7-unified-v1','approvals.sqlite','owner.sqlite','sonar-receipts.sqlite')
$ActualNames = @($Manifest.sha256.PSObject.Properties.Name)
if (Compare-Object ($ExpectedNames | Sort-Object) ($ActualNames | Sort-Object)) { throw 'BACKUP_MANIFEST_FILE_SET_MISMATCH' }
$Files = @()
foreach ($Name in $ExpectedNames) {
    $File = Join-Path $BackupDir $Name
    $ActualHash = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant()
    $Files += [ordered]@{ name=$Name; sha256=$ActualHash
        matchesManifest=($ActualHash -ceq $Manifest.sha256.$Name) }
}
$AclEntries = @()
foreach ($Path in @($BackupDir,$ManifestPath) + @($ExpectedNames | ForEach-Object { Join-Path $BackupDir $_ })) {
    $Acl = Get-Acl -LiteralPath $Path
    $AclEntries += [ordered]@{ path=$Path; owner=$Acl.Owner
        inheritanceProtected=$Acl.AreAccessRulesProtected
        access=@($Acl.Access | Select-Object IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags,PropagationFlags) }
}
[ordered]@{
    audit='Fortis read-only host observations'; timeUtc=[DateTime]::UtcNow.ToString('o')
    containers=$Containers; images=$Images; volumes=$Volumes
    backup=[ordered]@{ path=$BackupDir; manifestSha256=$ManifestHash
        matchesHandoffHash=($ManifestHash -ceq $HandoffHash)
        ownerBindingRecorded=$Manifest.ownerBindingPass
        databaseSummaryRecorded=$Manifest.databases; files=$Files; acl=$AclEntries }
    limits=@('No fresh SQLite integrity check','No fresh credential or owner binding verification',
        'No state-clone database inspection','No image smoke execution',
        'ACL entries reported for review; no automatic ACL verdict')
} | ConvertTo-Json -Depth 12
