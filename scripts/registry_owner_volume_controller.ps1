# Windows PowerShell 5.1, owner-only source candidate. No implicit GO.
[CmdletBinding()]
param(
    [ValidateSet('Plan','Prepare','Inspect')][string]$Action='Plan',
    [string]$SourceRoot='', [string]$SourceSha='', [string]$OwnerSuffix='',
    [string]$RegistryImageId='', [string]$ImageSourceSha='',
    [string]$GatewayContainerId='', [string]$GatewayImageId='',
    [string]$RepoContainerId='', [string]$RepoImageId='',
    [string]$OperationId='', [string]$OwnerReviewPath='',
    [string]$OwnerReviewSha256='', [string]$HostIdentityEvidencePath='',
    [string]$ExclusiveWriterFenceEvidencePath='', [string]$ImageProvenanceEvidencePath='',
    [switch]$ConfirmHostEffects
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2

function Need {
    param([bool]$Condition,[string]$Code)
    if (-not $Condition) { throw ('STOP: '+$Code) }
}
function Prop {
    param($Object,[string]$Name)
    Need ($null -ne $Object) 'OBJECT_MISSING'
    $p=$Object.PSObject.Properties[$Name]
    Need ($null -ne $p) ('PROPERTY_MISSING_'+$Name)
    return $p.Value
}
function Optional-Prop {
    param($Object,[string]$Name)
    Need ($null -ne $Object) 'OBJECT_MISSING'
    $p=$Object.PSObject.Properties[$Name]
    if ($null -ne $p) { return $p.Value }
    return $null
}
function Equal-List {
    param([object[]]$Actual,[object[]]$Expected)
    $a=@($Actual | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)
    $b=@($Expected | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)
    return ($a.Count -eq $b.Count -and ($a -join "`n") -ceq ($b -join "`n"))
}
function New-Layout {
    param([string]$Suffix)
    Need ($Suffix -cmatch '^[0-9a-f]{8,32}$') 'OWNER_SUFFIX_INVALID'
    return @(
        [pscustomobject]@{Name=('fortis-registry-state-e13b-'+$Suffix); Destination='/run/fortis-registry-state'; Uid=20002; Gid=20002; Mode=448},
        [pscustomobject]@{Name=('fortis-registry-config-e13b-'+$Suffix); Destination='/run/fortis-registry-runtime'; Uid=20002; Gid=20002; Mode=448},
        [pscustomobject]@{Name='fortis-registry-read'; Destination='/run/fortis-registry-read'; Uid=20002; Gid=10001; Mode=1480}
    )
}
function New-HelperArgs {
    param([string]$Phase,[string]$Name,[string]$Image,[object[]]$Layout,[string]$Payload,[string]$OpId)
    Need (@('Prepare','Inspect') -ccontains $Phase) 'PHASE_INVALID'
    $inspect=($Phase -ceq 'Inspect')
    $user='0:10001'
    if ($inspect) { $user='20002:20002' }
    $a=@('container','create','--name',$Name,'--pull=never','--network=none',
        '--read-only','--user',$user,'--cap-drop','ALL','--restart=no','--ipc=private','--cgroupns=private',
        '--security-opt','no-new-privileges:true','--pids-limit','64','--memory','128m',
        '--log-driver','json-file','--log-opt','max-size=1m','--log-opt','max-file=1',
        '--label',('fortis.registry.owner-operation='+$OpId),
        '--label',('fortis.registry.owner-phase='+$Phase))
    if (-not $inspect) { $a+=@('--cap-add','CHOWN','--cap-add','FOWNER') }
    foreach ($row in $Layout) {
        $m='type=volume,src='+$row.Name+',dst='+$row.Destination+',volume-nocopy'
        if ($inspect) { $m+=',readonly' }
        $a+=@('--mount',$m)
    }
    # Single fixed -c expression without shell or quotes requiring Windows argv escaping.
    $a+=@('--entrypoint','python',$Image,'-I','-B','-c',
        "exec(__import__('base64').b64decode(__import__('sys').argv[1]))",$Payload)
    return ,$a
}

function Docker-Lines {
    param([string[]]$Arguments)
    $out=@(& docker --context desktop-linux @Arguments)
    if ($LASTEXITCODE -ne 0) { throw 'STOP: DOCKER_EFFECT_OR_READ_FAILED_NO_RETRY_NO_CLEANUP' }
    return ,$out
}
function Docker-One {
    param([string[]]$Arguments)
    $out=Docker-Lines -Arguments $Arguments
    Need ($out.Count -eq 1) 'DOCKER_OUTPUT_NOT_EXACT'
    return [string]$out[0]
}
function Docker-Object {
    param([string[]]$Arguments)
    $line=Docker-One -Arguments $Arguments
    $o=$line | ConvertFrom-Json -ErrorAction Stop
    Need ($null -ne $o) 'DOCKER_JSON_EMPTY'
    return $o
}
function Sha-Bytes {
    param([byte[]]$Bytes)
    $hash=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function Read-PinnedBytes {
    param([string]$Path,[string]$Expected,[int]$Limit=16384)
    Need ($Limit -ge 1 -and $Limit -le 1048576 -and $Expected -cmatch '^[0-9a-f]{64}$') 'FILE_DIGEST_INVALID'
    Need (-not [string]::IsNullOrWhiteSpace($Path)) 'PINNED_FILE_PATH_REQUIRED'
    $item=Get-Item -LiteralPath $Path -ErrorAction Stop
    Need (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $item.Length -gt 0 -and $item.Length -le $Limit) 'FILE_NOT_BOUNDED_REGULAR'
    [byte[]]$bytes=[IO.File]::ReadAllBytes($item.FullName)
    Need ($bytes.Length -gt 0 -and $bytes.Length -le $Limit -and (Sha-Bytes $bytes) -ceq $Expected) 'FILE_DIGEST_CHANGED'
    return ,$bytes
}
function Assert-Baseline {
    foreach ($pin in @(@('fortis-gateway',$GatewayContainerId,$GatewayImageId,'10001:10001'), @('fortis-repo-test',$RepoContainerId,$RepoImageId,'1000:1000'))) {
        $c=Docker-Object @('container','inspect','--format','{{json .}}',$pin[0])
        Need ($c.Id -ceq $pin[1] -and $c.Image -ceq $pin[2] -and $c.Config.User -ceq $pin[3] -and $c.State.Status -ceq 'running' -and -not $c.HostConfig.Privileged -and $c.HostConfig.ReadonlyRootfs) 'BASELINE_CHANGED'
        Need (@($c.HostConfig.SecurityOpt | Where-Object { $_ -match '^no-new-privileges(:true)?$' }).Count -gt 0) 'BASELINE_NNP_MISSING'
        if ($pin[0] -ceq 'fortis-gateway') { Need ($c.State.Health.Status -ceq 'healthy') 'GATEWAY_NOT_HEALTHY' }
    }
}
function Assert-Volume {
    param([string]$Name)
    $v=Docker-Object @('volume','inspect','--format','{{json .}}',$Name)
    Need ($v.Name -ceq $Name -and $v.Driver -ceq 'local' -and $v.Scope -ceq 'local') 'VOLUME_IDENTITY_INVALID'
    Need ($null -eq (Optional-Prop $v 'Options') -or @($v.Options.PSObject.Properties).Count -eq 0) 'VOLUME_DRIVER_OPTIONS_UNEXPECTED'
    Need ((Prop $v.Labels 'fortis.registry.owner-operation') -ceq $OperationId) 'VOLUME_OPERATION_LABEL_MISMATCH'
    Need (-not [string]::IsNullOrWhiteSpace([string]$v.Mountpoint)) 'VOLUME_MOUNTPOINT_MISSING'
    return [string]$v.Mountpoint
}
function Assert-Attachments {
    param([object[]]$Expected)
    foreach ($row in $layout) {
        $attached=Docker-Lines @('ps','-aq','--no-trunc','--filter',('volume='+$row.Name))
        Need (Equal-List $attached $Expected) 'VOLUME_ATTACHMENT_CONFLICT'
    }
}
function Assert-Helper {
    param([string]$Id,[string]$Phase,[string]$Name,[string]$Payload,[string]$Status)
    $c=Docker-Object @('container','inspect','--format','{{json .}}',$Id)
    $ro=($Phase -ceq 'Inspect')
    $user='0:10001'; $caps=@('CHOWN','FOWNER')
    if ($ro) { $user='20002:20002'; $caps=@() }
    Need ($c.Id -ceq $Id -and $c.Name -ceq ('/'+$Name) -and $c.Image -ceq $RegistryImageId -and $c.Config.User -ceq $user -and $c.State.Status -ceq $Status) 'HELPER_IDENTITY_OR_STATUS_INVALID'
    Need ((Prop $c.Config.Labels 'fortis.registry.owner-operation') -ceq $OperationId -and (Prop $c.Config.Labels 'fortis.registry.owner-phase') -ceq $Phase) 'HELPER_OPERATION_LABEL_INVALID'
    $h=$c.HostConfig
    Need (-not $h.Privileged -and $h.ReadonlyRootfs -and -not $h.AutoRemove -and $h.NetworkMode -ceq 'none' -and -not $h.PidMode -and -not $h.UsernsMode -and -not $h.UTSMode -and $h.IpcMode -ceq 'private' -and $h.CgroupnsMode -ceq 'private' -and $h.RestartPolicy.Name -ceq 'no' -and $h.PidsLimit -eq 64 -and $h.Memory -eq 134217728) 'HELPER_CONFINEMENT_INVALID'
    Need ((Equal-List @($h.CapDrop | ForEach-Object { ([string]$_).ToUpperInvariant() -replace '^CAP_','' }) @('ALL')) -and (Equal-List @((Optional-Prop $h 'CapAdd') | ForEach-Object { if ($null -ne $_) { ([string]$_).ToUpperInvariant() -replace '^CAP_','' } }) $caps)) 'HELPER_CAPS_INVALID'
    Need (Equal-List $h.SecurityOpt @('no-new-privileges:true')) 'HELPER_SECURITY_OPT_INVALID'
    Need ($h.LogConfig.Type -ceq 'json-file' -and (Prop $h.LogConfig.Config 'max-size') -ceq '1m' -and (Prop $h.LogConfig.Config 'max-file') -ceq '1') 'HELPER_LOG_POLICY_INVALID'
    Need (@((Optional-Prop $h 'Binds') | Where-Object { $null -ne $_ }).Count -eq 0 -and @((Optional-Prop $h 'Devices') | Where-Object { $null -ne $_ }).Count -eq 0 -and @((Optional-Prop $h 'GroupAdd') | Where-Object { $null -ne $_ }).Count -eq 0 -and @((Optional-Prop $h 'DeviceRequests') | Where-Object { $null -ne $_ }).Count -eq 0 -and @((Optional-Prop $h 'VolumesFrom') | Where-Object { $null -ne $_ }).Count -eq 0) 'HELPER_EXTRA_HOST_ACCESS'
    Need ($null -eq (Optional-Prop $h 'Tmpfs') -or @($h.Tmpfs.PSObject.Properties).Count -eq 0) 'HELPER_TMPFS_UNEXPECTED'
    Need (Equal-List $c.Config.Entrypoint @('python')) 'HELPER_ENTRYPOINT_INVALID'
    $expectedCmd=@('-I','-B','-c',"exec(__import__('base64').b64decode(__import__('sys').argv[1]))",$Payload)
    Need (@($c.Config.Cmd).Count -eq $expectedCmd.Count -and ($c.Config.Cmd -join "`n") -ceq ($expectedCmd -join "`n")) 'HELPER_PAYLOAD_INVALID'
    Need (@($c.Mounts).Count -eq 3 -and @($h.Mounts).Count -eq 3) 'HELPER_MOUNT_COUNT_INVALID'
    foreach ($row in $layout) {
        $m=@($c.Mounts | Where-Object { $_.Destination -ceq $row.Destination })
        $hc=@($h.Mounts | Where-Object { $_.Target -ceq $row.Destination })
        Need ($m.Count -eq 1 -and $hc.Count -eq 1) 'HELPER_MOUNT_NOT_EXACT'
        Need ($m[0].Type -ceq 'volume' -and $m[0].Name -ceq $row.Name -and $m[0].Driver -ceq 'local' -and $m[0].RW -eq (-not $ro) -and $m[0].Source -ceq (Assert-Volume $row.Name)) 'HELPER_MOUNT_INVALID'
        $rawRo=Optional-Prop $hc[0] 'ReadOnly'
        Need ($null -eq $rawRo -or $rawRo -is [bool]) 'HELPER_MOUNT_RO_TYPE_INVALID'
        Need ($hc[0].Type -ceq 'volume' -and $hc[0].Source -ceq $row.Name -and [bool]$rawRo -eq $ro -and $hc[0].VolumeOptions.NoCopy -eq $true) 'HELPER_NOCOPY_OR_RO_INVALID'
    }
    if ($Status -ceq 'exited') { Need ($c.State.ExitCode -eq 0 -and -not $c.State.OOMKilled) 'HELPER_EXIT_NOT_PASS' }
}
function Read-RootReceipt {
    param([string[]]$Lines,[string]$ExpectedMarker)
    $lineset=@($Lines)
    Need (($ExpectedMarker -ceq 'E13B_VOLUME_ROOT_PREPARE_PASS' -and $lineset.Count -eq 4) -or ($ExpectedMarker -ceq 'E13B_VOLUME_ROOT_INSPECT_READONLY_PASS' -and $lineset.Count -eq 1)) 'HELPER_OUTPUT_BOUNDS'
    $receipt=$lineset[-1] | ConvertFrom-Json -ErrorAction Stop
    Need ($receipt.result -ceq $ExpectedMarker -and @($receipt.roots).Count -eq 3) 'HELPER_RECEIPT_INVALID'
    $seen=@()
    foreach ($row in $layout) {
        $hits=@($receipt.roots | Where-Object { $_.path -ceq $row.Destination })
        Need ($hits.Count -eq 1) 'HELPER_RECEIPT_ROOT_MISSING'
        $x=$hits[0]
        Need ($x.uid -eq $row.Uid -and $x.gid -eq $row.Gid -and $x.mode -eq $row.Mode -and $x.device -ge 0 -and $x.inode -gt 0) 'HELPER_RECEIPT_STAT_INVALID'
        $seen+=([string]$x.device+':'+[string]$x.inode)
    }
    Need (@($seen | Sort-Object -Unique).Count -eq 3) 'HELPER_RECEIPT_ALIASES'
    return $receipt
}

if ($Action -ceq 'Plan') {
    Write-Host 'E13B_VOLUME_CONTROLLER_SOURCE_PLAN_ONLY_NO_HOST_GO'
    Write-Host 'Prepare: three fresh local volumes; isolated helper 0:10001, CHOWN/FOWNER only, RW three roots; read-only rootfs, no network.'
    Write-Host 'Inspect: separate container 20002:20002, zero caps, three RO mounts; retained containers; no implicit cleanup.'
    Write-Host 'Both phases require separately owner-reviewed evidence file and explicit scoped host GO. No host access in Plan.'
    return
}

# An exact independently reviewed owner record is required; a hash alone is
# not proof of mappings, exclusive fence, upstream provenance or authority.
Need $ConfirmHostEffects.IsPresent 'SEPARATE_OWNER_HOST_GO_REQUIRED'
$layout=@(New-Layout $OwnerSuffix)
Need ($SourceSha -cmatch '^[0-9a-f]{40}$' -and $ImageSourceSha -cmatch '^[0-9a-f]{40}$' -and $OperationId -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') 'SOURCE_OR_OPERATION_PIN_INVALID'
foreach ($v in @($RegistryImageId,$GatewayImageId,$RepoImageId)) { Need ($v -cmatch '^sha256:[0-9a-f]{64}$') 'IMAGE_PIN_INVALID' }
foreach ($v in @($GatewayContainerId,$RepoContainerId)) { Need ($v -cmatch '^[0-9a-f]{64}$') 'CONTAINER_PIN_INVALID' }
Need ($GatewayContainerId -cne $RepoContainerId) 'BASELINE_ID_COLLISION'
$expectedRoot=[IO.Path]::GetFullPath((Join-Path $HOME 'Repos\fortis-approvals'))
Need ($SourceRoot -and [IO.Path]::GetFullPath($SourceRoot) -ceq $expectedRoot -and [IO.Path]::GetFullPath($PSScriptRoot) -ceq (Join-Path $expectedRoot 'scripts')) 'SOURCE_ROOT_INVALID'
$head=@(& git -C $SourceRoot rev-parse HEAD); Need ($LASTEXITCODE -eq 0 -and $head.Count -eq 1 -and $head[0] -ceq $SourceSha) 'SOURCE_SHA_CHANGED'
$branch=@(& git -C $SourceRoot branch --show-current); Need ($LASTEXITCODE -eq 0 -and $branch.Count -eq 1 -and $branch[0] -ceq 'main') 'SOURCE_BRANCH_INVALID'
$dirty=@(& git -C $SourceRoot status --porcelain=v1 --untracked-files=all); Need ($LASTEXITCODE -eq 0 -and $dirty.Count -eq 0) 'SOURCE_NOT_CLEAN'
Need (-not $env:DOCKER_HOST -and (-not $env:DOCKER_CONTEXT -or $env:DOCKER_CONTEXT -ceq 'desktop-linux')) 'DOCKER_ENV_OVERRIDE'
$context=@(& docker context show); Need ($LASTEXITCODE -eq 0 -and $context.Count -eq 1 -and $context[0] -ceq 'desktop-linux') 'DOCKER_CONTEXT_INVALID'
Need ((Docker-One @('info','--format','{{.OSType}}')) -ceq 'linux') 'DOCKER_ENGINE_INVALID'
$endpoint=Docker-One @('context','inspect','--format','{{.Endpoints.docker.Host}}','desktop-linux')
Need ($endpoint -ceq 'npipe:////./pipe/dockerDesktopLinuxEngine') 'DOCKER_DESKTOP_ENDPOINT_INVALID'
[byte[]]$reviewBytes=Read-PinnedBytes $OwnerReviewPath $OwnerReviewSha256
$review=[Text.Encoding]::UTF8.GetString($reviewBytes) | ConvertFrom-Json -ErrorAction Stop
$expected=@{schemaVersion=1; decision=$Action; operationId=$OperationId; ownerSuffix=$OwnerSuffix; sourceSha=$SourceSha; registryImageId=$RegistryImageId; imageSourceSha=$ImageSourceSha; gatewayContainerId=$GatewayContainerId; gatewayImageId=$GatewayImageId; repoContainerId=$RepoContainerId; repoImageId=$RepoImageId; context='desktop-linux'; dockerEndpoint=$endpoint}
foreach ($key in $expected.Keys) { Need ((Prop $review $key) -ceq $expected[$key]) 'OWNER_REVIEW_SCOPE_MISMATCH' }
foreach ($key in @('hostIdentityEvidenceSha256','exclusiveWriterFenceEvidenceSha256','imageProvenanceEvidenceSha256','preparePayloadSha256','inspectPayloadSha256')) { Need ((Prop $review $key) -cmatch '^[0-9a-f]{64}$') 'OWNER_REVIEW_EVIDENCE_PIN_INVALID' }
# Verify the actual referenced evidence bytes, not only digest-shaped strings.
# This is integrity binding, never a substitute for independent owner review.
$null=Read-PinnedBytes $HostIdentityEvidencePath (Prop $review 'hostIdentityEvidenceSha256') 1048576
$null=Read-PinnedBytes $ExclusiveWriterFenceEvidencePath (Prop $review 'exclusiveWriterFenceEvidenceSha256') 1048576
$null=Read-PinnedBytes $ImageProvenanceEvidencePath (Prop $review 'imageProvenanceEvidenceSha256') 1048576
$prepareBytes=Read-PinnedBytes (Join-Path $PSScriptRoot 'registry_owner_volume_prepare_roots.py') (Prop $review 'preparePayloadSha256')
$inspectBytes=Read-PinnedBytes (Join-Path $PSScriptRoot 'registry_owner_volume_inspect_roots.py') (Prop $review 'inspectPayloadSha256')
$preparePayload=[Convert]::ToBase64String($prepareBytes)
$inspectPayload=[Convert]::ToBase64String($inspectBytes)
$prepareName='fortis-registry-volume-prep-e13b-'+$OwnerSuffix
$inspectName='fortis-registry-volume-inspect-e13b-'+$OwnerSuffix
$img=Docker-Object @('image','inspect','--format','{{json .}}',$RegistryImageId)
Need ($img.Id -ceq $RegistryImageId -and $img.Os -ceq 'linux' -and $img.Architecture -ceq 'amd64' -and $img.Config.User -ceq '20002:20002' -and (Prop $img.Config.Labels 'org.opencontainers.image.revision') -ceq $ImageSourceSha) 'REGISTRY_IMAGE_PIN_INVALID'
Need ($null -eq (Optional-Prop $img.Config 'Volumes') -or @($img.Config.Volumes.PSObject.Properties).Count -eq 0) 'IMAGE_IMPLICIT_VOLUMES_UNSUPPORTED'
Assert-Baseline
$names=Docker-Lines @('ps','-a','--format','{{.Names}}')
Need ($names -cnotcontains $inspectName) 'INSPECT_HELPER_ALREADY_EXISTS'
Write-Host ('E13B_OWNER_REVIEW_SHA256='+$OwnerReviewSha256)
Write-Host ('E13B_VOLUME_OPERATION_ID='+$OperationId)

if ($Action -ceq 'Prepare') {
    Need ($names -cnotcontains $prepareName) 'PREPARE_HELPER_ALREADY_EXISTS'
    # Revalidate the full corrected inventory immediately before any write.
    & (Join-Path $PSScriptRoot 'registry_owner_volume_preflight.ps1') -Action Inventory -SourceRoot $SourceRoot -SourceSha $SourceSha -OwnerSuffix $OwnerSuffix -RegistryImageId $RegistryImageId -ImageSourceSha $ImageSourceSha -GatewayContainerId $GatewayContainerId -GatewayImageId $GatewayImageId -RepoContainerId $RepoContainerId -RepoImageId $RepoImageId
    $mountpoints=@()
    foreach ($row in $layout) {
        $existing=Docker-Lines @('volume','ls','--format','{{.Name}}')
        Need ($existing -cnotcontains $row.Name) 'VOLUME_ALREADY_EXISTS_NO_ADOPTION'
        $attached=Docker-Lines @('ps','-aq','--no-trunc','--filter',('volume='+$row.Name))
        Need ($attached.Count -eq 0) 'VOLUME_ALREADY_ATTACHED'
        Write-Host ('E13B_VOLUME_CREATE_INTENT='+$row.Name)
        $created=Docker-One @('volume','create','--driver','local','--label',('fortis.registry.owner-operation='+$OperationId),'--name',$row.Name)
        Need ($created -ceq $row.Name) 'VOLUME_CREATE_NAME_MISMATCH'
        $mountpoints+=(Assert-Volume $row.Name)
        Write-Host ('E13B_VOLUME_CREATED_LOCAL='+$row.Name)
    }
    Need (@($mountpoints | Sort-Object -Unique).Count -eq 3) 'VOLUME_MOUNTPOINT_ALIAS'
    Assert-Attachments @()
    $helperArgs=New-HelperArgs 'Prepare' $prepareName $RegistryImageId $layout $preparePayload $OperationId
    Write-Host ('E13B_PREPARE_HELPER_CREATE_INTENT='+$prepareName)
    $id=Docker-One $helperArgs
    Need ($id -cmatch '^[0-9a-f]{64}$') 'HELPER_ID_INVALID'
    Write-Host ('E13B_PREPARE_HELPER_ID='+$id)
    Assert-Helper $id 'Prepare' $prepareName $preparePayload 'created'
    Assert-Attachments @($id)
    Assert-Baseline
    $output=Docker-Lines @('container','start','--attach',$id)
    Assert-Helper $id 'Prepare' $prepareName $preparePayload 'exited'
    $receipt=Read-RootReceipt $output 'E13B_VOLUME_ROOT_PREPARE_PASS'
    Assert-Attachments @($id)
    Assert-Baseline
    Write-Host ($receipt | ConvertTo-Json -Depth 5 -Compress)
    Write-Host 'E13B_VOLUME_PREPARE_OWNER_READBACK_PASS_INSPECT_REQUIRED'
    Write-Host 'E13B_HELPERS_RETAINED_NO_CLEANUP_NO_BOOTSTRAP_GO'
    return
}

# Independently read the real roots as non-root. Docker create/start itself is
# an owner-approved host effect even though all three volume mounts are RO.
$mountpoints=@(foreach ($row in $layout) { Assert-Volume $row.Name })
Need (@($mountpoints | Sort-Object -Unique).Count -eq 3) 'VOLUME_MOUNTPOINT_ALIAS'
$prepare=Docker-Object @('container','inspect','--format','{{json .}}',$prepareName)
$prepareId=[string]$prepare.Id
Need ($prepareId -cmatch '^[0-9a-f]{64}$') 'PREPARE_HELPER_ID_INVALID'
Assert-Helper $prepareId 'Prepare' $prepareName $preparePayload 'exited'
Assert-Attachments @($prepareId)
$previous=Read-RootReceipt (Docker-Lines @('container','logs',$prepareId)) 'E13B_VOLUME_ROOT_PREPARE_PASS'
$helperArgs=New-HelperArgs 'Inspect' $inspectName $RegistryImageId $layout $inspectPayload $OperationId
Write-Host ('E13B_INSPECT_HELPER_CREATE_INTENT='+$inspectName)
$id=Docker-One $helperArgs
Need ($id -cmatch '^[0-9a-f]{64}$') 'HELPER_ID_INVALID'
Write-Host ('E13B_INSPECT_HELPER_ID='+$id)
Assert-Helper $id 'Inspect' $inspectName $inspectPayload 'created'
Assert-Attachments @($prepareId,$id)
Assert-Baseline
$output=Docker-Lines @('container','start','--attach',$id)
Assert-Helper $id 'Inspect' $inspectName $inspectPayload 'exited'
$receipt=Read-RootReceipt $output 'E13B_VOLUME_ROOT_INSPECT_READONLY_PASS'
foreach ($row in $layout) {
    $a=@($previous.roots | Where-Object { $_.path -ceq $row.Destination })[0]
    $b=@($receipt.roots | Where-Object { $_.path -ceq $row.Destination })[0]
    Need ($a.device -eq $b.device -and $a.inode -eq $b.inode) 'INDEPENDENT_ROOT_IDENTITY_CHANGED'
}
Assert-Attachments @($prepareId,$id)
Assert-Baseline
Write-Host ($receipt | ConvertTo-Json -Depth 5 -Compress)
Write-Host 'E13B_VOLUME_INSPECT_OWNER_READBACK_PASS'
Write-Host 'E13B_HELPERS_RETAINED_SEPARATE_OWNER_CLEANUP_REQUIRED_NO_BOOTSTRAP_GO'
