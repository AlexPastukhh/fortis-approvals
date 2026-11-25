# Windows PowerShell 5.1 / non-Production E1.3b only.
# Owner-only Plan or independently approved ephemeral Preview/Provision/Verify.
# StartManaged adopts the existing pilot on the normal Docker restart policy.
[CmdletBinding()]
param(
    [ValidateSet('Plan','Preview','Provision','Verify','StartManaged')][string]$Action='Plan',
    [string]$SourceRoot='',
    [string]$SourceSha='',
    [string]$RegistryImageId='',
    [string]$SpecPath='',
    [string]$ExpectedSpecSha256='',
    [string]$StateVolume='',
    [string]$ConfigVolume='',
    [string]$SocketVolume='fortis-registry-read',
    [switch]$ConfirmProvision,
    [string]$PlannerKeySha256='',
    [switch]$ConfirmManagedStart
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2

function Assert-Registry-Bootstrap-Input {
    param([string]$Name,[string]$Value,[string]$Pattern)
    if ($Value -cnotmatch $Pattern) { throw ('REGISTRY_BOOTSTRAP_'+$Name+'_INVALID') }
}

function Invoke-Registry-Bootstrap-DockerRead {
    param([string[]]$Arguments)
    $Result=@(& docker @Arguments)
    if ($LASTEXITCODE -ne 0) { throw 'REGISTRY_BOOTSTRAP_DOCKER_READ_FAILED' }
    return ,$Result
}

$ManagedStart=$Action -ceq 'StartManaged'
if ($ManagedStart -ne [bool]$ConfirmManagedStart -or (-not $ManagedStart -and $PlannerKeySha256)) {
    throw 'REGISTRY_BOOTSTRAP_MANAGED_START_CONFIRMATION_REQUIRED'
}
if ($ManagedStart) {
    Assert-Registry-Bootstrap-Input 'PLANNER_KEY_SHA256' $PlannerKeySha256 '^[0-9a-f]{64}$'
    if ($SpecPath -or $ExpectedSpecSha256) { throw 'REGISTRY_BOOTSTRAP_MANAGED_START_SPEC_NOT_SUPPORTED' }
}

if ($Action -ceq 'Plan') {
    if ($ConfirmProvision) { throw 'REGISTRY_BOOTSTRAP_PROVISION_FLAG_INVALID' }
    Write-Host 'REGISTRY_BOOTSTRAP_PLAN_SOURCE_ONLY'
    Write-Host 'Order: owner source+CI -> owner image-only build -> independent host identity/volume ownership -> Preview -> separately approved Provision -> inactive Verify -> backup+inactive restore -> socket/peer+Repo-denial -> nonce seal -> UC-GW-005.'
    Write-Host 'Registry UID:GID=20002:20002; reader UID:GID=10001:10001; socket volume=fortis-registry-read; SQLite and private config require separate pre-owned 0700 volumes.'
    Write-Host 'No Docker commands, host writes, volume creation or privileges performed by Plan.'
    return
}
if ($ConfirmProvision -and $Action -cne 'Provision') {
    throw 'REGISTRY_BOOTSTRAP_PROVISION_FLAG_INVALID'
}
if ($Action -ceq 'Provision' -and -not $ConfirmProvision) {
    throw 'REGISTRY_BOOTSTRAP_INDEPENDENT_PROVISION_GO_REQUIRED'
}

Assert-Registry-Bootstrap-Input 'SOURCE_SHA' $SourceSha '^[0-9a-f]{40}$'
Assert-Registry-Bootstrap-Input 'IMAGE_ID' $RegistryImageId '^sha256:[0-9a-f]{64}$'
Assert-Registry-Bootstrap-Input 'STATE_VOLUME' $StateVolume '^fortis-registry-state-e13b-[0-9a-f]{8,32}$'
Assert-Registry-Bootstrap-Input 'CONFIG_VOLUME' $ConfigVolume '^fortis-registry-config-e13b-[0-9a-f]{8,32}$'
if ($SocketVolume -cne 'fortis-registry-read' -or $StateVolume -ceq $ConfigVolume) {
    throw 'REGISTRY_BOOTSTRAP_VOLUME_NAME_INVALID'
}
$ExpectedRoot=[IO.Path]::GetFullPath((Join-Path $HOME 'Repos\fortis-approvals'))
if (-not $SourceRoot -or ([IO.Path]::GetFullPath($SourceRoot) -cne $ExpectedRoot)) {
    throw 'REGISTRY_BOOTSTRAP_SOURCE_ROOT_INVALID'
}
# The reviewed entrypoint itself must be inside the reviewed Windows main.
$ExpectedScriptRoot=[IO.Path]::GetFullPath((Join-Path $SourceRoot 'fortis_approvals\deploy'))
if ([IO.Path]::GetFullPath($PSScriptRoot) -cne $ExpectedScriptRoot) {
    throw 'REGISTRY_BOOTSTRAP_SCRIPT_ORIGIN_INVALID'
}
if (-not (Test-Path -LiteralPath (Join-Path $SourceRoot '.git'))) {
    throw 'REGISTRY_BOOTSTRAP_SOURCE_GIT_MISSING'
}
if (-not $ManagedStart) {
    Assert-Registry-Bootstrap-Input 'SPEC_SHA' $ExpectedSpecSha256 '^[0-9a-f]{64}$'
    if (-not $SpecPath -or -not (Test-Path -LiteralPath $SpecPath -PathType Leaf)) {
        throw 'REGISTRY_BOOTSTRAP_SPEC_UNAVAILABLE'
    }
    $SpecInfo=Get-Item -LiteralPath $SpecPath -Force
    if (($SpecInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'REGISTRY_BOOTSTRAP_SPEC_REPARSE_DENIED'
    }
    $SpecBytes=[IO.File]::ReadAllBytes($SpecInfo.FullName)
    if ($SpecBytes.Length -le 0 -or $SpecBytes.Length -gt 4096) {
        throw 'REGISTRY_BOOTSTRAP_SPEC_SIZE_DENIED'
    }
    foreach ($Byte in $SpecBytes) {
        if ($Byte -gt 127 -or $Byte -eq 0 -or $Byte -eq 10 -or $Byte -eq 13) {
            throw 'REGISTRY_BOOTSTRAP_SPEC_ASCII_SINGLE_LINE_REQUIRED'
        }
    }
    $SpecActual=(Get-FileHash -LiteralPath $SpecInfo.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($SpecActual -cne $ExpectedSpecSha256) {
        throw 'REGISTRY_BOOTSTRAP_SPEC_PIN_CHANGED'
    }
    $SpecLine=[Text.Encoding]::ASCII.GetString($SpecBytes)
}

$Branch=@(& git -C $SourceRoot branch --show-current)
if ($LASTEXITCODE -ne 0 -or $Branch.Count -ne 1 -or $Branch[0] -cne 'main') {
    throw 'REGISTRY_BOOTSTRAP_WINDOWS_SOURCE_NOT_MAIN'
}
$ActualSha=@(& git -C $SourceRoot rev-parse HEAD)
if ($LASTEXITCODE -ne 0 -or $ActualSha.Count -ne 1 -or $ActualSha[0] -cne $SourceSha) {
    throw 'REGISTRY_BOOTSTRAP_WINDOWS_SOURCE_SHA_MISMATCH'
}
$Dirty=@(& git -C $SourceRoot status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $Dirty.Count -ne 0) {
    throw 'REGISTRY_BOOTSTRAP_WINDOWS_SOURCE_DIRTY'
}

$OSType=Invoke-Registry-Bootstrap-DockerRead -Arguments @('info','--format','{{.OSType}}')
if ($OSType.Count -ne 1 -or $OSType[0] -cne 'linux') {
    throw 'REGISTRY_BOOTSTRAP_LINUX_ENGINE_REQUIRED'
}
$Image=Invoke-Registry-Bootstrap-DockerRead -Arguments @('image','inspect','--format','{{.Id}}|{{.Config.User}}|{{.Os}}|{{.Architecture}}',$RegistryImageId)
if ($Image.Count -ne 1 -or $Image[0] -cne ($RegistryImageId+'|20002:20002|linux|amd64')) {
    throw 'REGISTRY_BOOTSTRAP_IMAGE_IDENTITY_INVALID'
}
foreach ($Name in @($StateVolume,$ConfigVolume,$SocketVolume)) {
    $Volume=Invoke-Registry-Bootstrap-DockerRead -Arguments @('volume','inspect','--format','{{.Name}}|{{.Driver}}|{{.Scope}}',$Name)
    if ($Volume.Count -ne 1 -or $Volume[0] -cne ($Name+'|local|local')) {
        throw 'REGISTRY_BOOTSTRAP_VOLUME_NOT_OWNER_VERIFIED'
    }
    if ($ManagedStart) {
        $Users=Invoke-Registry-Bootstrap-DockerRead -Arguments @('ps','-aq','--no-trunc','--filter',('volume='+$Name))
        foreach ($Id in $Users) {
            Assert-Registry-Bootstrap-Input 'VOLUME_HOLDER' $Id '^[0-9a-f]{64}$'
            $Holder=Invoke-Registry-Bootstrap-DockerRead -Arguments @(
                'container','inspect','--format','{{.State.Status}}|{{.HostConfig.RestartPolicy.Name}}|{{json .Mounts}}',$Id)
            if ($Holder.Count -ne 1) { throw 'REGISTRY_BOOTSTRAP_MOUNT_READBACK_FAILED' }
            $Fields=$Holder[0] -split '\|',3
            if ($Fields.Count -ne 3) { throw 'REGISTRY_BOOTSTRAP_MOUNT_READBACK_FAILED' }
            $Dormant=($Fields[0] -cin @('created','exited') -and $Fields[1] -ceq 'no')
            if ($Dormant) { continue }
            # Existing Gateway may retain the private socket as a reader.
            $SocketMount=@(ConvertFrom-Json -InputObject $Fields[2] |
                Where-Object { $_.Type -ceq 'volume' -and $_.Name -ceq $Name })
            if ($Name -cne $SocketVolume -or $SocketMount.Count -ne 1 -or
                $SocketMount[0].RW -isnot [bool] -or $SocketMount[0].RW -ne $false) {
                throw ('REGISTRY_BOOTSTRAP_VOLUME_ALREADY_ATTACHED_'+$Name)
            }
        }
    } else {
        $Users=Invoke-Registry-Bootstrap-DockerRead -Arguments @('ps','-aq','--filter',('volume='+$Name))
        if ($Users.Count -ne 0) {
            throw ('REGISTRY_BOOTSTRAP_VOLUME_ALREADY_ATTACHED_'+$Name)
        }
    }
}

if ($ManagedStart) {
    $StartArgs=@(
        'run','-d','--pull=never','--name','fortis-registry-managed','--restart=unless-stopped',
        '--init','--network=none','--read-only','--user','20002:20002',
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','128m',
        '--mount',('type=volume,src='+$StateVolume+',dst=/run/fortis-registry-state,volume-nocopy'),
        '--mount',('type=volume,src='+$ConfigVolume+',dst=/run/fortis-registry-runtime,volume-nocopy,readonly'),
        '--mount',('type=volume,src='+$SocketVolume+',dst=/run/fortis-registry-read,volume-nocopy'),
        $RegistryImageId,'python','-m','fortis_approvals.registry.local_candidate_read_service',
        '--owner-config','/run/fortis-registry-runtime/profile.json',
        '--functional-planner-key-digest',$PlannerKeySha256,'--managed-startup'
    )
    $RegistryId=@(& docker @StartArgs)
    if ($LASTEXITCODE -ne 0 -or $RegistryId.Count -ne 1 -or $RegistryId[0] -cnotmatch '^[0-9a-f]{64}$') {
        throw 'REGISTRY_BOOTSTRAP_MANAGED_START_UNKNOWN_INSPECT_ORIGINAL'
    }
    Write-Host ('REGISTRY_BOOTSTRAP_MANAGED_CONTAINER_ID='+$RegistryId[0])
    # Docker accepted the start. Normal protected Gateway Check verifies the
    # actual Registry proof before admitting the release.
    return
}

# A fixed script, never dynamic Python generated from untrusted spec. The spec
# travels on stdin (not command-line argv), is independently SHA256-pinned,
# and is materialized only inside a private 20002-owned tmpfs of this run.
$PythonRunner=@'
import hashlib
import json
import os
import sys
raw = sys.stdin.buffer.read(4098)
if not raw or len(raw) > 4097:
    raise RuntimeError('REGISTRY_BOOTSTRAP_STDIN_BOUNDS')
raw = raw.rstrip(b'\r\n')
if not raw or hashlib.sha256(raw).hexdigest() != sys.argv[2]:
    raise RuntimeError('REGISTRY_BOOTSTRAP_STDIN_DIGEST_CHANGED')
if any(x >= 128 for x in raw):
    raise RuntimeError('REGISTRY_BOOTSTRAP_STDIN_NOT_ASCII')
path = '/run/fortis-registry-bootstrap/spec.json'
fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
with os.fdopen(fd, 'wb') as output:
    output.write(raw)
    output.flush()
    os.fsync(output.fileno())
sys.path.insert(0, '/opt/fortis')
from fortis_approvals.registry.owner_functional_v1_bootstrap import run
result = run(sys.argv[1], expected_spec_sha256=sys.argv[2])
print(json.dumps(result, sort_keys=True, separators=(',', ':')))
'@
$StateFlag='readonly'
$ConfigFlag='readonly'
if ($Action -ceq 'Provision') {
    $StateFlag=''
    $ConfigFlag=''
}
$StateMount=('type=volume,src='+$StateVolume+',dst=/run/fortis-registry-state,volume-nocopy')
$ConfigMount=('type=volume,src='+$ConfigVolume+',dst=/run/fortis-registry-runtime,volume-nocopy')
if ($StateFlag) { $StateMount+=',readonly' }
if ($ConfigFlag) { $ConfigMount+=',readonly' }
$SocketMount=('type=volume,src='+$SocketVolume+',dst=/run/fortis-registry-read,volume-nocopy,readonly')
$DockerArgs=@(
    'run','-i','--rm','--pull=never','--network=none','--read-only',
    '--user','20002:20002','--cap-drop','ALL',
    '--security-opt','no-new-privileges:true','--pids-limit','64','--memory','128m',
    '--tmpfs','/run/fortis-registry-bootstrap:rw,nosuid,nodev,noexec,size=16k,uid=20002,gid=20002,mode=0700',
    '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=8m,uid=20002,gid=20002,mode=0700',
    '--mount',$StateMount,'--mount',$ConfigMount,'--mount',$SocketMount,
    '--entrypoint','python',$RegistryImageId,'-I','-B','-c',$PythonRunner,
    $Action,$ExpectedSpecSha256
)
Write-Host ('REGISTRY_BOOTSTRAP_OWNER_ACTION='+$Action)
Write-Host ('REGISTRY_BOOTSTRAP_SOURCE_SHA='+$SourceSha)
Write-Host ('REGISTRY_BOOTSTRAP_IMAGE_ID='+$RegistryImageId)
Write-Host ('REGISTRY_BOOTSTRAP_SPEC_SHA256='+$ExpectedSpecSha256)
Write-Host 'REGISTRY_BOOTSTRAP_EXISTING_VOLUMES_REVIEWED'
# This single native invocation is the ONLY docker run; no retry or cleanup
# after a partial/unknown Provision effect. Native nonzero always STOP.
$Output=@($SpecLine | & docker @DockerArgs)
$RunExit=$LASTEXITCODE
if ($RunExit -ne 0) {
    throw ('REGISTRY_BOOTSTRAP_'+$Action+'_FAILED_EXIT_'+$RunExit+'_STOP_NO_RETRY')
}
if ($Output.Count -ne 1) { throw 'REGISTRY_BOOTSTRAP_OUTPUT_NOT_EXACT' }
try {
    $Receipt=$Output[0] | ConvertFrom-Json -ErrorAction Stop
} catch { throw 'REGISTRY_BOOTSTRAP_OUTPUT_INVALID_JSON' }
$AllowedResult=@{
    Preview='SOURCE_ONLY_REGISTRY_BOOTSTRAP_PREVIEW'
    Provision='SOURCE_ONLY_REGISTRY_BOOTSTRAP_PROVISIONED'
    Verify='SOURCE_ONLY_REGISTRY_BOOTSTRAP_VERIFIED'
}
if ($Receipt.result -cne $AllowedResult[$Action] -or
    $Receipt.specSha256 -cne $ExpectedSpecSha256 -or
    $Receipt.hostAccepted -ne $false -or $Receipt.admissionAllowed -ne $false) {
    throw 'REGISTRY_BOOTSTRAP_RESULT_INVARIANT_FAILED_STOP'
}
Write-Host $Output[0]
Write-Host ('REGISTRY_BOOTSTRAP_'+$Action.ToUpperInvariant()+'_SOURCE_ONLY_PASS')
