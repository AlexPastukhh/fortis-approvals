# Windows PowerShell 5.1 / non-Production E1.3b only.
# Owner-only Plan or independently approved ephemeral Preview/Provision/Verify.
# StartManaged adopts the existing pilot on the normal Docker restart policy.
[CmdletBinding()]
param(
    [ValidateSet('Plan','Preview','Provision','Verify','PrepareSuccessor','AccountDeliveryRepair','AccountBootstrapMigration','StartManaged')][string]$Action='Plan',
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
    [string]$SuccessorReleaseNonce='', [string]$SuccessorProfileSha256='',
    [string]$TransitionEvidenceSha256='', [string]$RepairEvidenceSha256='',
    [ValidateSet('1','2')][int]$RepairPredecessorRevision=1,
    [string]$BootstrapReviewSha256='', [string]$BootstrapEvidenceSha256='', [string]$BootstrapReviewProofRecord='',
    [switch]$ConfirmManagedStart, [switch]$CorrectivePreview, [switch]$CorrectiveWriter
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

function Test-Registry-Bootstrap-ReadOnlySocket {
    param([string]$MountJson,[string]$VolumeName)
    return (Test-Registry-Bootstrap-ReadOnlyMount $MountJson $VolumeName '/run/fortis-registry-read')
}
function Test-Registry-Bootstrap-ReadOnlyMount {
    param([string]$MountJson,[string]$VolumeName,[string]$Destination)
    # Windows PowerShell 5.1 emits the entire JSON array as one pipeline item.
    $Mounts=ConvertFrom-Json -InputObject $MountJson
    $SocketMount=@(foreach ($Mount in $Mounts) {
        if ($Mount.Type -ceq 'volume' -and $Mount.Name -ceq $VolumeName) { $Mount }
    })
    if ($SocketMount.Count -ne 1 -or $SocketMount[0].Destination -cne $Destination -or
        $SocketMount[0].RW -isnot [bool] -or $SocketMount[0].RW -ne $false) {
        return $false
    }
    return $true
}

$ManagedStart=$Action -ceq 'StartManaged'
$PrepareSuccessor=$Action -ceq 'PrepareSuccessor'
$RepairDelivery=$Action -ceq 'AccountDeliveryRepair'
$AccountBootstrap=$Action -ceq 'AccountBootstrapMigration'
$SuccessorWrite=$PrepareSuccessor -or $RepairDelivery -or $AccountBootstrap
if($AccountBootstrap -ne [bool]$BootstrapReviewSha256 -or $AccountBootstrap -ne [bool]$BootstrapEvidenceSha256 -or $AccountBootstrap -ne [bool]$BootstrapReviewProofRecord){
    throw 'REGISTRY_BOOTSTRAP_MIGRATION_PINS_REQUIRED'
}
if($AccountBootstrap){
    Assert-Registry-Bootstrap-Input 'MIGRATION_REVIEW_SHA256' $BootstrapReviewSha256 '^[0-9a-f]{64}$'
    Assert-Registry-Bootstrap-Input 'MIGRATION_EVIDENCE_SHA256' $BootstrapEvidenceSha256 '^[0-9a-f]{64}$'
    if($BootstrapReviewSha256 -ceq $BootstrapEvidenceSha256){throw 'REGISTRY_BOOTSTRAP_MIGRATION_PINS_REQUIRED'}
}
$SuccessorStart=$ManagedStart -and [bool]$SuccessorReleaseNonce
$Successor=$SuccessorWrite -or $SuccessorStart
if(($CorrectivePreview -and $CorrectiveWriter) -or
   (($CorrectivePreview -or $CorrectiveWriter) -and (-not $SuccessorStart -or
    -not $ConfirmManagedStart -or $SourceSha -cnotmatch '^[0-9a-f]{40}$'))){
    throw 'REGISTRY_BOOTSTRAP_CORRECTIVE_PREVIEW_DENIED'
}
if(-not $RepairDelivery -and $PSBoundParameters.ContainsKey('RepairPredecessorRevision')){
    throw 'REGISTRY_BOOTSTRAP_REPAIR_REVISION_ACTION_DENIED'
}
if($RepairDelivery -ne [bool]$RepairEvidenceSha256){
    throw 'REGISTRY_BOOTSTRAP_REPAIR_EVIDENCE_REQUIRED'
}
if($RepairDelivery){
    Assert-Registry-Bootstrap-Input 'REPAIR_EVIDENCE_SHA256' $RepairEvidenceSha256 '^[0-9a-f]{64}$'
}
$AccountTransition=[bool]$TransitionEvidenceSha256
if($AccountTransition){
    if(-not $PrepareSuccessor){throw 'REGISTRY_BOOTSTRAP_TRANSITION_ACTION_DENIED'}
    Assert-Registry-Bootstrap-Input 'TRANSITION_EVIDENCE_SHA256' $TransitionEvidenceSha256 '^[0-9a-f]{64}$'
}
if ($ManagedStart -ne [bool]$ConfirmManagedStart -or (-not $ManagedStart -and $PlannerKeySha256)) {
    throw 'REGISTRY_BOOTSTRAP_MANAGED_START_CONFIRMATION_REQUIRED'
}
if($Successor){
    if($PlannerKeySha256){throw 'REGISTRY_BOOTSTRAP_SUCCESSOR_PROFILE_REQUIRED'}
    Assert-Registry-Bootstrap-Input 'SUCCESSOR_NONCE' $SuccessorReleaseNonce '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    Assert-Registry-Bootstrap-Input 'SUCCESSOR_PROFILE_SHA256' $SuccessorProfileSha256 '^[0-9a-f]{64}$'
} elseif($SuccessorReleaseNonce -or $SuccessorProfileSha256){
    throw 'REGISTRY_BOOTSTRAP_SUCCESSOR_PROFILE_REQUIRED'
} elseif($ManagedStart){
    Assert-Registry-Bootstrap-Input 'PLANNER_KEY_SHA256' $PlannerKeySha256 '^[0-9a-f]{64}$'
}
if (($ManagedStart -or $SuccessorWrite) -and ($SpecPath -or $ExpectedSpecSha256)) {
    throw 'REGISTRY_BOOTSTRAP_MANAGED_START_SPEC_NOT_SUPPORTED'
}

if ($Action -ceq 'Plan') {
    if ($ConfirmProvision) { throw 'REGISTRY_BOOTSTRAP_PROVISION_FLAG_INVALID' }
    Write-Host 'REGISTRY_BOOTSTRAP_PLAN_SOURCE_ONLY'
    Write-Host 'Order: owner source+CI -> owner image-only build -> independent host identity/volume ownership -> Preview -> separately approved Provision -> inactive Verify -> backup+inactive restore -> socket/peer+Repo-denial -> nonce seal -> UC-GW-005.'
    Write-Host 'Registry UID:GID=20002:20002; reader UID:GID=10001:10001; socket volume=fortis-registry-read; SQLite and private config require separate pre-owned 0700 volumes.'
    Write-Host 'No Docker commands, host writes, volume creation or privileges performed by Plan.'
    return
}
if ($ConfirmProvision -and $Action -cne 'Provision' -and -not $SuccessorWrite) {
    throw 'REGISTRY_BOOTSTRAP_PROVISION_FLAG_INVALID'
}
if ($Action -ceq 'Provision' -and -not $ConfirmProvision) {
    throw 'REGISTRY_BOOTSTRAP_INDEPENDENT_PROVISION_GO_REQUIRED'
}
if ($SuccessorWrite -and -not $ConfirmProvision) {
    throw 'REGISTRY_BOOTSTRAP_INDEPENDENT_PROVISION_GO_REQUIRED'
}

Assert-Registry-Bootstrap-Input 'SOURCE_SHA' $SourceSha '^[0-9a-f]{40}$'
Assert-Registry-Bootstrap-Input 'IMAGE_ID' $RegistryImageId '^sha256:[0-9a-f]{64}$'
Assert-Registry-Bootstrap-Input 'STATE_VOLUME' $StateVolume '^fortis-registry-state-e13b-[0-9a-f]{8,32}$'
$ConfigPattern=if($AccountBootstrap){'^fortis-registry-config-e13b-[0-9a-f]{32}-prepared$'}else{'^fortis-registry-config-e13b-[0-9a-f]{8,32}$'}
Assert-Registry-Bootstrap-Input 'CONFIG_VOLUME' $ConfigVolume $ConfigPattern
$ExpectedSocket='fortis-registry-read'
$VolumeNames=@($StateVolume,$ConfigVolume,$SocketVolume)
if($Successor){
    $Id=$SuccessorReleaseNonce.Replace('-','')
    $ExpectedConfig='fortis-registry-config-e13b-'+$Id
    if($AccountBootstrap){$ExpectedConfig+='-prepared'}
    if($StateVolume -cne ('fortis-registry-state-e13b-'+$Id) -or
       $ConfigVolume -cne $ExpectedConfig){
        throw 'REGISTRY_BOOTSTRAP_SUCCESSOR_CLONE_VOLUME_REQUIRED'
    }
    $ExpectedSocket='fortis-registry-read-'+$Id
    if($SuccessorWrite){$VolumeNames=@($StateVolume,$ConfigVolume)}
}
if($SuccessorStart -or $AccountTransition -or $RepairDelivery -or $AccountBootstrap){
    $ValidatorVolume='fortis-registry-source-'+$Id
    $VolumeNames+=@($ValidatorVolume)
}
if($AccountBootstrap){
    $IncumbentNonce='4ec7d8b82b5144578b156559bcdeae94'
    if($Id -ceq $IncumbentNonce){throw 'REGISTRY_BOOTSTRAP_MIGRATION_CLONE_ALIAS'}
    $IncumbentState='fortis-registry-state-e13b-'+$IncumbentNonce
    $IncumbentConfig='fortis-registry-config-e13b-'+$IncumbentNonce
}
if($SuccessorStart){
    $EvidenceVolume='fortis-registry-source-evidence-'+$Id
    $InterlockVolume='fortis-r7-maintenance-interlock'
    $VolumeNames+=@($EvidenceVolume,$InterlockVolume)
}
if ($SocketVolume -cne $ExpectedSocket -or $StateVolume -ceq $ConfigVolume) {
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
if (-not $ManagedStart -and -not $SuccessorWrite) {
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
if ($RepairDelivery -or $AccountBootstrap -or $CorrectivePreview -or $CorrectiveWriter) {
    $Labels=Invoke-Registry-Bootstrap-DockerRead -Arguments @(
        'image','inspect','--format','{{json .Config.Labels}}',$RegistryImageId)
    if ($Labels.Count -ne 1) { throw 'REGISTRY_BOOTSTRAP_REPAIR_IMAGE_SOURCE_CHANGED' }
    $Metadata=$Labels[0] | ConvertFrom-Json
    if ($null -eq $Metadata -or
       -not $Metadata.PSObject.Properties['org.opencontainers.image.revision'] -or
       $Metadata.'org.opencontainers.image.revision' -cne $SourceSha) {
        throw 'REGISTRY_BOOTSTRAP_REPAIR_IMAGE_SOURCE_CHANGED'
    }
}
foreach ($Name in $VolumeNames) {
    $Volume=Invoke-Registry-Bootstrap-DockerRead -Arguments @('volume','inspect','--format','{{.Name}}|{{.Driver}}|{{.Scope}}',$Name)
    if ($Volume.Count -ne 1 -or $Volume[0] -cne ($Name+'|local|local')) {
        throw 'REGISTRY_BOOTSTRAP_VOLUME_NOT_OWNER_VERIFIED'
    }
    if ($ManagedStart) {
        $Users=Invoke-Registry-Bootstrap-DockerRead -Arguments @('ps','-aq','--no-trunc','--filter',('volume='+$Name))
        foreach ($HolderId in $Users) {
            Assert-Registry-Bootstrap-Input 'VOLUME_HOLDER' $HolderId '^[0-9a-f]{64}$'
            $Holder=Invoke-Registry-Bootstrap-DockerRead -Arguments @(
                'container','inspect','--format','{{.State.Status}}|{{.HostConfig.RestartPolicy.Name}}|{{json .Mounts}}',$HolderId)
            if ($Holder.Count -ne 1) { throw 'REGISTRY_BOOTSTRAP_MOUNT_READBACK_FAILED' }
            $Fields=$Holder[0] -split '\|',3
            if ($Fields.Count -ne 3) { throw 'REGISTRY_BOOTSTRAP_MOUNT_READBACK_FAILED' }
            $Dormant=($Fields[0] -cin @('created','exited') -and $Fields[1] -ceq 'no')
            if ($Dormant) { continue }
            if($SuccessorStart -and $Name -ceq $InterlockVolume -and
               (Test-Registry-Bootstrap-ReadOnlyMount $Fields[2] $Name '/run/r7-maintenance')){
                continue
            }
            if($CorrectivePreview -or $CorrectiveWriter){throw 'REGISTRY_BOOTSTRAP_CORRECTIVE_PREVIEW_VOLUME_ATTACHED'}
            # Existing Gateway may retain the private socket as a reader.
            if ($Name -cne $SocketVolume -or -not (Test-Registry-Bootstrap-ReadOnlySocket $Fields[2] $Name)) {
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

if($AccountBootstrap){
    # Authenticate the original pre-merge owner record before any clone
    # write; its exact bytes are independently bound in the review digest.
    . (Join-Path $SourceRoot 'fortis_approvals\deploy\Run-GitHub-Pilot-E2E.ps1') -Mode Functions
    $ProofPath=[IO.Path]::GetFullPath($BootstrapReviewProofRecord)
    $ProofRoot=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Fortis'))
    if(-not $ProofPath.StartsWith($ProofRoot+'\',[StringComparison]::OrdinalIgnoreCase)){
        throw 'REGISTRY_BOOTSTRAP_OWNER_REVIEW_PATH_INVALID'
    }
    foreach($Path in @($ProofPath,(Split-Path $ProofPath -Parent))){
        if((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){
            throw 'REGISTRY_BOOTSTRAP_OWNER_REVIEW_PATH_INVALID'
        }
    }
    $script:RecordPath=$ProofPath
    Assert-RecordAcl
    $ProofBytes=[IO.File]::ReadAllBytes($ProofPath)
    if($ProofBytes.Length -le 0 -or $ProofBytes.Length -gt 4096){
        throw 'REGISTRY_BOOTSTRAP_OWNER_REVIEW_SIZE_INVALID'
    }
    $ProofLine=[Convert]::ToBase64String($ProofBytes)
    # The source mounts are read-only even when the approved incumbent is
    # still running. This only prepares a candidate; the controller must
    # prove physical exclusion and the same prefix before cutover.
    $IncumbentWriter='fb747224e917dc88653dac29961f2d11bebca6023c9f73317c4ce6ce7597ae18'
    $IncumbentPreview='e0c1dcd7e587a5ebea7883b678578dbbedf8dedb607946fbf314cd77c83d0467'
    foreach($Name in @($IncumbentState,$IncumbentConfig)){
        $Volume=Invoke-Registry-Bootstrap-DockerRead -Arguments @('volume','inspect','--format','{{.Name}}|{{.Driver}}|{{.Scope}}',$Name)
        if($Volume.Count -ne 1 -or $Volume[0] -cne ($Name+'|local|local')){throw 'REGISTRY_BOOTSTRAP_MIGRATION_INCUMBENT_VOLUME_CHANGED'}
        $Users=Invoke-Registry-Bootstrap-DockerRead -Arguments @('ps','-aq','--no-trunc','--filter',('volume='+$Name))
        if($IncumbentWriter -cnotin $Users -or @($Users|Where-Object{$_ -cnotin @($IncumbentWriter,$IncumbentPreview)}).Count){
            throw 'REGISTRY_BOOTSTRAP_MIGRATION_INCUMBENT_HOLDER_CHANGED'
        }
    }
}
if ($ManagedStart) {
    $Name='fortis-registry-managed';$Memory='128m';$Extra=@()
    $ProofArgs=@('--functional-planner-key-digest',$PlannerKeySha256,'--managed-startup')
    if($SuccessorStart){
        $Name='fortis-registry-successor-'+$Id
        $Memory='512m'
        $Extra=@('--tmpfs','/tmp:rw,nosuid,nodev,size=256m',
            '--mount',('type=volume,src='+$EvidenceVolume+',dst=/run/fortis-registry-source-evidence,volume-nocopy,readonly'),
            '--mount',('type=volume,src='+$ValidatorVolume+',dst=/run/fortis-registry-source,volume-nocopy,readonly'),
            '--mount',('type=volume,src='+$InterlockVolume+',dst=/run/r7-maintenance,volume-nocopy,readonly'))
        $ProofArgs=@('--expected-profile-sha256',$SuccessorProfileSha256)
    }
    $Restart='--restart=unless-stopped'
    $StateAccess=''
    $Verb=@('run','-d')
    if($CorrectiveWriter){
        # Create BEFORE preview. This mounts no active writer, and a Docker
        # restart must not start it. Only the paired controller may start it.
        $Verb=@('create')
        $Restart='--restart=no'
    }
    if($CorrectivePreview){
        $Name+='-preview'
        $Restart='--restart=no'
        $StateAccess=',readonly'
        $ProofArgs+=@('--corrective-preview-sha',$SourceSha)
    }
    $StartArgs=$Verb+@(
        '--pull=never','--name',$Name,$Restart,
        '--init','--network=none','--read-only','--user','20002:20002',
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory',$Memory,
        '--mount',('type=volume,src='+$StateVolume+',dst=/run/fortis-registry-state,volume-nocopy'+$StateAccess),
        '--mount',('type=volume,src='+$ConfigVolume+',dst=/run/fortis-registry-runtime,volume-nocopy,readonly'),
        '--mount',('type=volume,src='+$SocketVolume+',dst=/run/fortis-registry-read,volume-nocopy')
    ) + $Extra + @($RegistryImageId,'python','-m','fortis_approvals.registry.local_candidate_read_service',
        '--owner-config','/run/fortis-registry-runtime/profile.json') + $ProofArgs
    $RegistryId=@(& docker @StartArgs)
    if ($LASTEXITCODE -ne 0 -or $RegistryId.Count -ne 1 -or $RegistryId[0] -cnotmatch '^[0-9a-f]{64}$') {
        throw 'REGISTRY_BOOTSTRAP_MANAGED_START_UNKNOWN_INSPECT_ORIGINAL'
    }
    if($CorrectiveWriter){
        $Created=Invoke-Registry-Bootstrap-DockerRead -Arguments @(
            'inspect','--type','container','--format','{{.State.Status}}|{{.HostConfig.RestartPolicy.Name}}|{{.State.StartedAt}}',$RegistryId[0])
        if($Created.Count -ne 1 -or $Created[0] -cne 'created|no|0001-01-01T00:00:00Z'){
            throw 'REGISTRY_BOOTSTRAP_CORRECTIVE_WRITER_NOT_PRISTINE'
        }
        Write-Host ('REGISTRY_BOOTSTRAP_CORRECTIVE_WRITER_ID='+$RegistryId[0])
        return
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
if($SuccessorWrite){$StateFlag=''}
if ($Action -ceq 'Provision') {
    $StateFlag=''
    $ConfigFlag=''
}
$StateMount=('type=volume,src='+$StateVolume+',dst=/run/fortis-registry-state,volume-nocopy')
$ConfigMount=('type=volume,src='+$ConfigVolume+',dst=/run/fortis-registry-runtime,volume-nocopy')
if ($StateFlag) { $StateMount+=',readonly' }
if ($ConfigFlag) { $ConfigMount+=',readonly' }
$SocketMount=('type=volume,src='+$SocketVolume+',dst=/run/fortis-registry-read,volume-nocopy,readonly')
$BootstrapMemory=if($AccountTransition -or $RepairDelivery -or $AccountBootstrap){'512m'}else{'128m'}
$DockerArgs=@(
    'run','-i','--rm','--pull=never','--network=none','--read-only',
    '--user','20002:20002','--cap-drop','ALL',
    '--security-opt','no-new-privileges:true','--pids-limit','64','--memory',$BootstrapMemory
)
if($SuccessorWrite){
    # Reserve the managed name so accounting and startup cannot overlap.
    $PythonRunner=@'
import base64, json, sys
sys.path.insert(0, '/opt/fortis')
from fortis_approvals.registry.owner_functional_v1_bootstrap import account_delivery_repair, prepare_successor, account_bootstrap_migration
profile, action = sys.argv[1:3]
if action == 'AccountDeliveryRepair':
    evidence, source, revision = sys.argv[3:]
    result = account_delivery_repair(profile, repair_evidence_sha256=evidence,
                                     source_sha=source, predecessor_revision=int(revision))
elif action == 'AccountBootstrapMigration':
    review, evidence, source = sys.argv[3:]
    result = account_bootstrap_migration(profile, review_sha256=review,
                                         evidence_sha256=evidence, source_sha=source,
                                         owner_review_raw=base64.b64decode(sys.stdin.buffer.read(5500).strip(),validate=True))
elif action == 'PrepareSuccessor':
    evidence, source = sys.argv[3:] if len(sys.argv) > 3 else (None, None)
    result = prepare_successor(profile, transition_evidence_sha256=evidence, source_sha=source)
else:
    raise RuntimeError('REGISTRY_BOOTSTRAP_ACTION_DENIED')
print(json.dumps(result, sort_keys=True, separators=(',', ':')))
'@
    if($AccountTransition -or $RepairDelivery -or $AccountBootstrap){
        $DockerArgs+=@('--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=256m',
            '--mount',('type=volume,src='+$ValidatorVolume+',dst=/run/fortis-registry-source,volume-nocopy,readonly'))
    }
    if($AccountBootstrap){
        $DockerArgs+=@('--mount',('type=volume,src='+$IncumbentState+',dst=/run/fortis-registry-incumbent-state,volume-nocopy,readonly'),
            '--mount',('type=volume,src='+$IncumbentConfig+',dst=/run/fortis-registry-incumbent-runtime,volume-nocopy,readonly'))
    }
    $DockerArgs+=@('--name',('fortis-registry-successor-'+$Id),
        '--mount',$StateMount,'--mount',$ConfigMount,
        '--entrypoint','python',$RegistryImageId,'-I','-B','-c',$PythonRunner,$SuccessorProfileSha256,$Action)
    if($AccountTransition){$DockerArgs+=@($TransitionEvidenceSha256,$SourceSha)}
    if($RepairDelivery){$DockerArgs+=@($RepairEvidenceSha256,$SourceSha,[string]$RepairPredecessorRevision)}
    if($AccountBootstrap){$DockerArgs+=@($BootstrapReviewSha256,$BootstrapEvidenceSha256,$SourceSha)}
    $SpecLine=if($AccountBootstrap){$ProofLine}else{''}
} else {
    $DockerArgs+=@(
        '--tmpfs','/run/fortis-registry-bootstrap:rw,nosuid,nodev,noexec,size=16k,uid=20002,gid=20002,mode=0700',
        '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=8m,uid=20002,gid=20002,mode=0700',
        '--mount',$StateMount,'--mount',$ConfigMount,'--mount',$SocketMount,
        '--entrypoint','python',$RegistryImageId,'-I','-B','-c',$PythonRunner,
        $Action,$ExpectedSpecSha256
    )
}
Write-Host ('REGISTRY_BOOTSTRAP_OWNER_ACTION='+$Action)
Write-Host ('REGISTRY_BOOTSTRAP_SOURCE_SHA='+$SourceSha)
Write-Host ('REGISTRY_BOOTSTRAP_IMAGE_ID='+$RegistryImageId)
if($SuccessorWrite){
    Write-Host ('REGISTRY_BOOTSTRAP_SUCCESSOR_PROFILE_SHA256='+$SuccessorProfileSha256)
} else {
    Write-Host ('REGISTRY_BOOTSTRAP_SPEC_SHA256='+$ExpectedSpecSha256)
}
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
if($RepairDelivery){
    $ExpectedPriorKind=if($RepairPredecessorRevision -eq 1){'TRANSITION'}else{'DELIVERY_REPAIR'}
    if($Receipt.result -cne 'SOURCE_ONLY_REGISTRY_DELIVERY_REPAIR_ACCOUNTED' -or
       $Receipt.profileSha256 -cne $SuccessorProfileSha256 -or
       $Receipt.repairEvidenceSha256 -cne $RepairEvidenceSha256 -or
       $Receipt.transitionDigest -cnotmatch '^[0-9a-f]{64}$' -or
       $Receipt.legacyPrefixDigest -cnotmatch '^[0-9a-f]{64}$' -or
       $Receipt.hostAccepted -ne $false -or $Receipt.admissionAllowed -ne $false -or
       $Receipt.predecessorReceipt.kind -cne $ExpectedPriorKind -or
       $Receipt.predecessorReceipt.sourceRevision -ne $RepairPredecessorRevision -or
       $Receipt.sourceRepairReceipt.kind -cne 'DELIVERY_REPAIR' -or
       $Receipt.sourceRepairReceipt.sourceRevision -ne ($RepairPredecessorRevision+1) -or
       $Receipt.sourceRepairReceipt.sourceCursor -cne $SourceSha -or
       $Receipt.sourceRepairReceipt.deploymentAuthorized -ne $false){
        throw 'REGISTRY_BOOTSTRAP_REPAIR_RESULT_INVARIANT_FAILED_STOP'
    }
    Write-Host $Output[0]
    Write-Host 'REGISTRY_BOOTSTRAP_DELIVERY_REPAIR_SOURCE_ONLY_PASS'
    return
}
if($AccountBootstrap){
    # This result accounts a source edge only, on an inactive clone. It
    # never authorizes pair startup, a release or a host mutation.
    if($Receipt.result -cne 'SOURCE_ONLY_REGISTRY_BOOTSTRAP_MIGRATION_ACCOUNTED' -or
       $Receipt.profileSha256 -cne $SuccessorProfileSha256 -or
       $Receipt.reviewSha256 -cne $BootstrapReviewSha256 -or
       $Receipt.evidenceSha256 -cne $BootstrapEvidenceSha256 -or
       $Receipt.hostAccepted -isnot [bool] -or $Receipt.hostAccepted -ne $false -or
       $Receipt.admissionAllowed -isnot [bool] -or $Receipt.admissionAllowed -ne $false -or
       $Receipt.prefix.predecessorReceipt.sourceRevision -ne 3 -or
       $Receipt.prefix.predecessorReceipt.sourceCursor -cne '073d6f8701595e499eac5a1fa0cbe90accb05819' -or
       $Receipt.sourceMigrationReceipt.kind -cne 'BOOTSTRAP_MIGRATION' -or
       $Receipt.sourceMigrationReceipt.sourceRevision -ne 4 -or
       $Receipt.sourceMigrationReceipt.sourceCursor -cne $SourceSha -or
       $Receipt.sourceMigrationReceipt.deploymentAuthorized -isnot [bool] -or
       $Receipt.sourceMigrationReceipt.deploymentAuthorized -ne $false -or
       $Receipt.checkpoint.sourceRevision -ne 4 -or $Receipt.checkpoint.snapshotRevision -ne 4 -or
       $Receipt.checkpoint.sourceCursor -cne $SourceSha -or
       $Receipt.checkpoint.eventDigest -cnotmatch '^[0-9a-f]{64}$'){
        throw 'REGISTRY_BOOTSTRAP_MIGRATION_RESULT_INVARIANT_FAILED_STOP'
    }
    Write-Host $Output[0]
    Write-Host 'REGISTRY_BOOTSTRAP_MIGRATION_SOURCE_ONLY_PASS'
    return
}
if($PrepareSuccessor){
    if($Receipt.result -cne 'SOURCE_ONLY_REGISTRY_SUCCESSOR_PREPARED' -or
       $Receipt.profileSha256 -cne $SuccessorProfileSha256 -or
       $Receipt.transitionDigest -cnotmatch '^[0-9a-f]{64}$' -or
       $Receipt.legacyPrefixDigest -cnotmatch '^[0-9a-f]{64}$' -or
       $Receipt.sourceTransitionPending -isnot [bool] -or
       $Receipt.sourceTransitionPending -ne (-not $AccountTransition) -or
       $Receipt.hostAccepted -ne $false -or $Receipt.admissionAllowed -ne $false){
        throw 'REGISTRY_BOOTSTRAP_RESULT_INVARIANT_FAILED_STOP'
    }
    if($AccountTransition -and ($Receipt.transitionEvidenceSha256 -cne $TransitionEvidenceSha256 -or
       $Receipt.sourceTransitionReceipt.kind -cne 'TRANSITION' -or
       $Receipt.sourceTransitionReceipt.sourceCursor -cne $SourceSha -or
       $Receipt.sourceTransitionReceipt.sourceRevision -ne 1 -or
       $Receipt.sourceTransitionReceipt.deploymentAuthorized -ne $false)){
        throw 'REGISTRY_BOOTSTRAP_RESULT_INVARIANT_FAILED_STOP'
    }
    Write-Host $Output[0]
    Write-Host 'REGISTRY_BOOTSTRAP_PREPARESUCCESSOR_SOURCE_ONLY_PASS'
    return
}
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
