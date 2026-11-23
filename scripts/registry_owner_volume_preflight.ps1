# Windows PowerShell 5.1. Source-only E1.3b owner-read inventory.
# Plan: no Docker/Git. Inventory: Docker + Git read-only; NO volume create/run/exec.
[CmdletBinding()]
param(
    [ValidateSet('Plan','Inventory')][string]$Action='Plan',
    [string]$SourceRoot='',
    [string]$SourceSha='',
    [string]$OwnerSuffix='',
    [string]$RegistryImageId='',
    [string]$ImageSourceSha='',
    [string]$GatewayContainerId='',
    [string]$GatewayImageId='',
    [string]$RepoContainerId='',
    [string]$RepoImageId=''
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2

if ($Action -ceq 'Plan') {
    Write-Host 'E13B_OWNER_VOLUME_SOURCE_PLAN_ONLY'
    Write-Host 'Inventory requires exact clean Windows main, fixed image/container pins, and owner-selected suffix.'
    Write-Host 'Inventory only reads Docker and Git metadata; it cannot prove Linux groups, Windows ACL, volumes root modes or absence of in-flight writes.'
    Write-Host 'NO Docker run/exec, volume create/chown/rm, bind mounts, Preview or Provision.'
    return
}

function Assert-Input {
    param([string]$Name,[string]$Value,[string]$Pattern)
    if ($Value -cnotmatch $Pattern) { throw ('STOP: E13B_VOLUME_'+$Name+'_INVALID') }
}
function Docker-Lines {
    param([string[]]$ArgsList)
    $result=@(& docker @ArgsList)
    if ($LASTEXITCODE -ne 0) { throw 'STOP: E13B_DOCKER_READ_FAILED' }
    return ,$result
}
function Read-OneJson {
    param([string[]]$ArgsList,[string]$Marker)
    $raw=Docker-Lines -ArgsList $ArgsList
    if ($raw.Count -eq 0) { throw ('STOP: '+$Marker+'_EMPTY') }
    $objects=@(($raw -join "`n") | ConvertFrom-Json -ErrorAction Stop)
    if ($objects.Count -ne 1) { throw ('STOP: '+$Marker+'_NOT_EXACT') }
    return $objects[0]
}

Assert-Input 'SOURCE_SHA' $SourceSha '^[0-9a-f]{40}$'
Assert-Input 'IMAGE_SOURCE_SHA' $ImageSourceSha '^[0-9a-f]{40}$'
Assert-Input 'REGISTRY_IMAGE' $RegistryImageId '^sha256:[0-9a-f]{64}$'
Assert-Input 'GATEWAY_IMAGE' $GatewayImageId '^sha256:[0-9a-f]{64}$'
Assert-Input 'REPO_IMAGE' $RepoImageId '^sha256:[0-9a-f]{64}$'
Assert-Input 'GATEWAY_ID' $GatewayContainerId '^[0-9a-f]{64}$'
Assert-Input 'REPO_ID' $RepoContainerId '^[0-9a-f]{64}$'
Assert-Input 'SUFFIX' $OwnerSuffix '^[0-9a-f]{8,32}$'
if ($GatewayContainerId -ceq $RepoContainerId) { throw 'STOP: CONTAINER_ID_COLLISION' }

$expectedRoot=[IO.Path]::GetFullPath((Join-Path $HOME 'Repos\fortis-approvals'))
if (-not $SourceRoot -or ([IO.Path]::GetFullPath($SourceRoot) -cne $expectedRoot)) {
    throw 'STOP: SOURCE_ROOT_INVALID'
}
$scriptRoot=[IO.Path]::GetFullPath((Join-Path $SourceRoot 'scripts'))
if ([IO.Path]::GetFullPath($PSScriptRoot) -cne $scriptRoot) {
    throw 'STOP: SCRIPT_ORIGIN_NOT_MERGED_MAIN'
}
$head=@(& git -C $SourceRoot rev-parse HEAD)
if ($LASTEXITCODE -ne 0 -or $head.Count -ne 1 -or $head[0] -cne $SourceSha) {
    throw 'STOP: SOURCE_SHA_MISMATCH'
}
$branch=@(& git -C $SourceRoot branch --show-current)
if ($LASTEXITCODE -ne 0 -or $branch.Count -ne 1 -or $branch[0] -cne 'main') {
    throw 'STOP: SOURCE_NOT_MAIN'
}
$dirty=@(& git -C $SourceRoot status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) { throw 'STOP: SOURCE_NOT_CLEAN' }
$context=Docker-Lines -ArgsList @('context','show')
if ($context.Count -ne 1 -or $context[0] -cne 'desktop-linux') {
    throw 'STOP: WRONG_DOCKER_CONTEXT'
}
$engine=Docker-Lines -ArgsList @('info','--format','{{.OSType}}')
if ($engine.Count -ne 1 -or $engine[0] -cne 'linux') {
    throw 'STOP: NOT_LINUX_DOCKER_ENGINE'
}
$security=Docker-Lines -ArgsList @('info','--format','{{json .SecurityOptions}}')
if ($security.Count -ne 1) { throw 'STOP: ENGINE_SECURITY_NOT_EXACT' }
$img=Read-OneJson -ArgsList @('image','inspect',$RegistryImageId) -Marker 'REGISTRY_IMAGE'
if ($img.Id -cne $RegistryImageId -or $img.Os -cne 'linux' -or
    $img.Architecture -cne 'amd64' -or $img.Config.User -cne '20002:20002' -or
    $img.Config.Labels.'org.opencontainers.image.revision' -cne $ImageSourceSha) {
    throw 'STOP: REGISTRY_IMAGE_IDENTITY_CHANGED'
}

function Assert-Container {
    param([string]$Name,[string]$ExpectedId,[string]$Image,[string]$Uid)
    $c=Read-OneJson -ArgsList @('container','inspect',$Name) -Marker 'CONTAINER'
    if ($c.Id -cne $ExpectedId -or $c.Image -cne $Image -or
        $c.Config.User -cne $Uid -or $c.State.Status -cne 'running' -or
        $c.HostConfig.Privileged -ne $false -or
        $c.HostConfig.ReadonlyRootfs -ne $true) {
        throw ('STOP: CONTAINER_BASELINE_CHANGED_'+$Name)
    }
    $nn=@($c.HostConfig.SecurityOpt | Where-Object { $null -ne $_ -and $_ -match '^no-new-privileges(:true)?$' })
    if ($nn.Count -eq 0) { throw ('STOP: CONTAINER_NNP_NOT_SET_'+$Name) }
    return $c
}
$gateway=Assert-Container -Name 'fortis-gateway' -ExpectedId $GatewayContainerId -Image $GatewayImageId -Uid '10001:10001'
if ($gateway.State.Health.Status -cne 'healthy') { throw 'STOP: GATEWAY_NOT_HEALTHY' }
$repo=Assert-Container -Name 'fortis-repo-test' -ExpectedId $RepoContainerId -Image $RepoImageId -Uid '1000:1000'

$stateVolume='fortis-registry-state-e13b-'+$OwnerSuffix
$configVolume='fortis-registry-config-e13b-'+$OwnerSuffix
$socketVolume='fortis-registry-read'
$targets=@($stateVolume,$configVolume,$socketVolume)
if (@($targets | Sort-Object -Unique).Count -ne 3) { throw 'STOP: VOLUME_NAME_COLLISION' }

$volumes=Docker-Lines -ArgsList @('volume','ls','--format','{{.Name}}')
$registryNames=@($volumes | Where-Object { $_ -match '^fortis-registry-(state-e13b-|config-e13b-|read$)' })
if ($registryNames.Count -ne 0) { throw 'STOP: REGISTRY_VOLUME_NAME_ALREADY_RESERVED' }

# Docker inspect only, including stopped containers; suppress all env/credentials and
# print no raw inspect payload. Check collisions across existing mount metadata.
$ids=Docker-Lines -ArgsList @('ps','-aq','--no-trunc')
foreach ($id in $ids) {
    Assert-Input 'CONTAINER_SCAN_ID' $id '^[0-9a-f]{64}$'
    $c=Read-OneJson -ArgsList @('container','inspect',$id) -Marker 'CONTAINER_SCAN'
    if ($c.Id -cne $id) { throw 'STOP: CONTAINER_SCAN_ID_CHANGED' }
    foreach ($mount in @($c.Mounts)) {
        if ($null -eq $mount) { continue }
        # Docker bind/tmpfs mounts may omit Name; strict PowerShell 5.1
        # property access would throw before the collision check. Reject
        # incomplete named-volume data instead of silently ignoring it.
        $typeProperty=$mount.PSObject.Properties['Type']
        if ($null -eq $typeProperty -or [string]::IsNullOrWhiteSpace([string]$typeProperty.Value)) {
            throw 'STOP: MOUNT_TYPE_MISSING'
        }
        $type=[string]$typeProperty.Value
        if (@('volume','bind','tmpfs') -cnotcontains $type) {
            throw 'STOP: MOUNT_TYPE_UNSUPPORTED'
        }
        $nameProperty=$mount.PSObject.Properties['Name']
        $sourceProperty=$mount.PSObject.Properties['Source']
        $name=''
        $source=''
        if ($null -ne $nameProperty -and $null -ne $nameProperty.Value) {
            $name=[string]$nameProperty.Value
        }
        if ($null -ne $sourceProperty -and $null -ne $sourceProperty.Value) {
            $source=[string]$sourceProperty.Value
        }
        if ($type -ceq 'volume' -and [string]::IsNullOrWhiteSpace($name)) {
            throw 'STOP: VOLUME_MOUNT_NAME_MISSING'
        }
        if (($type -ceq 'volume' -or $type -ceq 'bind') -and
            [string]::IsNullOrWhiteSpace($source)) {
            throw 'STOP: MOUNT_SOURCE_MISSING'
        }
        if (($targets -ccontains $name) -or
            $name -match '^fortis-registry-(state-e13b-|config-e13b-|read$)' -or
            $source -match 'fortis-registry-(state-e13b-|config-e13b-|read($|[/\\]))') {
            throw 'STOP: EXISTING_CONTAINER_REGISTRY_MOUNT_CONFLICT'
        }
    }
}
foreach ($name in $targets) {
    $attached=Docker-Lines -ArgsList @('ps','-aq','--filter',('volume='+$name))
    if ($attached.Count -ne 0) { throw 'STOP: TARGET_VOLUME_ATTACHED' }
}
$contextAfter=Docker-Lines -ArgsList @('context','show')
if ($contextAfter.Count -ne 1 -or $contextAfter[0] -cne $context[0]) {
    throw 'STOP: DOCKER_CONTEXT_CHANGED_DURING_READ'
}
$gatewayAfter=Read-OneJson -ArgsList @('container','inspect','fortis-gateway') -Marker 'GATEWAY_POST'
$repoAfter=Read-OneJson -ArgsList @('container','inspect','fortis-repo-test') -Marker 'REPO_POST'
if ($gatewayAfter.Id -cne $GatewayContainerId -or $gatewayAfter.Image -cne $GatewayImageId -or
    $gatewayAfter.State.Status -cne 'running' -or $gatewayAfter.State.Health.Status -cne 'healthy' -or
    $repoAfter.Id -cne $RepoContainerId -or $repoAfter.Image -cne $RepoImageId -or
    $repoAfter.State.Status -cne 'running') {
    throw 'STOP: POSTREADBACK_CONTAINER_CHANGED'
}
Write-Host ('E13B_SELECTED_STATE_VOLUME='+$stateVolume)
Write-Host ('E13B_SELECTED_CONFIG_VOLUME='+$configVolume)
Write-Host ('E13B_SELECTED_SOCKET_VOLUME='+$socketVolume)
Write-Host ('E13B_CONTAINER_METADATA_SCANNED='+$ids.Count)
Write-Host ('E13B_DOCKER_SECURITY_OPTIONS='+$security[0])
Write-Host 'E13B_OWNER_VOLUME_METADATA_READONLY_PASS'
Write-Host 'E13B_USERNS_GROUPS_OWNERSHIP_WRITER_FENCE_UNKNOWN_STOP_BEFORE_CREATE'
