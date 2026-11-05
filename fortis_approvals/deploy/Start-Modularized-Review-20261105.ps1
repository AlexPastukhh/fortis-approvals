$ErrorActionPreference = 'Stop'
$ProductionName = 'fortis-approvals-gateway'
$ExpectedProductionImage = 'sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402'
$CandidateName = 'fortis-gateway-modularized-review-20261105'
$CandidateImage = 'sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84'
$Snapshot = '3a0d8f99f11a2f27dd1467593e1ac37ce452a183c19c7abf685643e1727b6d14'
$ReviewVolume = 'fortis-r7-state-review-20261105'
function Read-Container {
    param([string]$Name)
    $Raw = (& docker.exe inspect --type container $Name | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'CONTAINER_INSPECT_FAILED' }
    return (ConvertFrom-Json $Raw)[0]
}
function Read-ProductionBaseline {
    $Item = Read-Container $ProductionName
    if ($Item.Image -cne $ExpectedProductionImage -or $Item.State.Status -cne 'running' -or
        $Item.State.Health.Status -cne 'healthy') { throw 'PRODUCTION_IDENTITY_OR_HEALTH_MISMATCH' }
    return ([ordered]@{ id=$Item.Id; image=$Item.Image; startedAt=$Item.State.StartedAt
        mounts=$Item.Mounts; ports=$Item.HostConfig.PortBindings } | ConvertTo-Json -Depth 8 -Compress)
}
function Encode-Text {
    param([string]$Value)
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value))
}
function Invoke-ReviewPython {
    param([string]$Code, [string[]]$MountArguments = @())
    $Arguments = @('run','--rm','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','64','--memory','128m','--tmpfs','/tmp:rw,nosuid,nodev,size=16m') +
        $MountArguments + @('--entrypoint','python',$CandidateImage,'-c',$Code)
    $Previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $Output = @(& docker.exe @Arguments 2>&1)
        $ExitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $Previous }
    $Output | ForEach-Object { Write-Host ([string]$_) }
    if ($ExitCode -ne 0) { throw 'REVIEW_PYTHON_VERIFICATION_FAILED' }
}
function Assert-ReviewContainer {
    param([object]$Container, [string]$Status)
    $InspectEncoded = Encode-Text ($Container | ConvertTo-Json -Depth 20 -Compress)
    $Code = "import base64,json;ns={};exec(compile(base64.b64decode('$ContractEncoded'),'<review-runtime-contract>','exec'),ns);print(json.dumps(ns['validate'](json.loads(base64.b64decode('$InspectEncoded')),expected_status='$Status'),sort_keys=True))"
    Invoke-ReviewPython -Code $Code
}
$DockerInfo = (& docker.exe info --format '{{.OSType}}' | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $DockerInfo -cne 'linux') { throw 'DOCKER_LINUX_ENGINE_REQUIRED' }
$Before = Read-ProductionBaseline
$RawImage = (& docker.exe image inspect $CandidateImage | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'PINNED_REVIEW_IMAGE_MISSING' }
$ImageInfo = (ConvertFrom-Json $RawImage)[0]
if ($ImageInfo.Id -cne $CandidateImage -or $ImageInfo.Config.User -cne '10001:10001' -or
    $ImageInfo.Config.Labels.'org.opencontainers.image.source-snapshot-sha256' -cne $Snapshot) {
    throw 'REVIEW_IMAGE_METADATA_MISMATCH'
}
$ContractEncoded = Encode-Text (Get-Content (Join-Path $PSScriptRoot 'review_runtime_contract.py') -Raw)
$VerifierEncoded = Encode-Text (Get-Content (Join-Path $PSScriptRoot 'verify_review_state.py') -Raw)
$ReceiptEncoded = Encode-Text (Get-Content (Join-Path $PSScriptRoot 'review-state-receipt-20261105.json') -Raw)
$Existing = @(& docker.exe ps -aq --filter "name=^/$CandidateName$")
if ($LASTEXITCODE -ne 0) { throw 'CONTAINER_LIST_FAILED' }
if ($Existing.Count -ne 0) { throw 'REVIEW_CONTAINER_ALREADY_EXISTS_NO_OVERWRITE' }
$VolumeUsers = @(& docker.exe ps -aq --filter "volume=$ReviewVolume")
if ($LASTEXITCODE -ne 0) { throw 'REVIEW_VOLUME_USAGE_CHECK_FAILED' }
if ($VolumeUsers.Count -ne 0) { throw 'REVIEW_STATE_VOLUME_ALREADY_ATTACHED' }
$Volumes = @(& docker.exe volume ls --format '{{.Name}}')
if ($LASTEXITCODE -ne 0) { throw 'VOLUME_LIST_FAILED' }
foreach ($Name in @($ReviewVolume,'fortis-r7-identity','fortis-r7-grant','fortis-r7-sonar-token')) {
    if ($Volumes -cnotcontains $Name) { throw ('REQUIRED_VOLUME_MISSING:' + $Name) }
}
# Exact HostConfig.PortBindings are authoritative; a publish filter hit alone
# does not establish that a running container occupies the requested host port.
$AllIds = @(& docker.exe ps -aq --no-trunc)
if ($LASTEXITCODE -ne 0) { throw 'PORT_CONTAINER_INVENTORY_FAILED' }
$Inventory = @()
foreach ($Id in $AllIds) {
    $Id = ([string]$Id).Trim()
    if ($Id -notmatch '^[0-9a-f]{64}$') { throw 'PORT_INVENTORY_ID_INVALID' }
    $Item = Read-Container $Id
    $Inventory += [ordered]@{ Name=$Item.Name; State=@{ Status=$Item.State.Status }
        HostConfig=@{ PortBindings=$Item.HostConfig.PortBindings } }
}
$InventoryJson = ConvertTo-Json -InputObject $Inventory -Depth 8 -Compress
$InventoryEncoded = Encode-Text $InventoryJson
$PortCode = "import base64,json;ns={};exec(compile(base64.b64decode('$ContractEncoded'),'<review-port-contract>','exec'),ns);claims=ns['port_claims'](json.loads(base64.b64decode('$InventoryEncoded')));print(json.dumps({'reviewPortClaims':claims},sort_keys=True),flush=True);ns['require'](not any(c['blocking'] for c in claims),'REVIEW_PORT_IN_USE_BY_ACTIVE_CONTAINER');print('REVIEW_NO_ACTIVE_DOCKER_HOST_PORT_CONFLICT_PASS')"
if ($PortCode.Length -gt 24000) { throw 'PORT_INVENTORY_TOO_LARGE_FOR_SAFE_NATIVE_ARGUMENT' }
Invoke-ReviewPython -Code $PortCode
$Listeners = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
$ConflictingListeners = @($Listeners | Where-Object { $_.Port -in @(19203,19204) })
if ($ConflictingListeners.Count -ne 0) {
    $Endpoints = @($ConflictingListeners | ForEach-Object { $_.ToString() }) -join ', '
    throw ('REVIEW_PORT_ALREADY_LISTENING:' + $Endpoints)
}
$Code = "import base64,json;ns={};exec(compile(base64.b64decode('$VerifierEncoded'),'<review-state-verifier>','exec'),ns);print(json.dumps(ns['verify']('/state',json.loads(base64.b64decode('$ReceiptEncoded'))),sort_keys=True))"
Invoke-ReviewPython -Code $Code -MountArguments @('--mount',"type=volume,source=$ReviewVolume,target=/state,readonly")
Write-Host 'REVIEW_RESTORED_STATE_PRESTART_PASS'
$CreateArguments = @('create','--pull=never','--name',$CandidateName,'--restart','no','--init',
    '--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
    '--pids-limit','100','--memory','512m','--network','bridge','--tmpfs','/tmp:rw,nosuid,nodev,size=16m',
    '--env','FORTIS_OWNER_ORIGIN=http://localhost:19203',
    '--env','FORTIS_MACHINE_HOST=host.docker.internal:19204',
    '--env','FORTIS_SONAR_REGION=eu','--env','FORTIS_SONAR_ORGANIZATIONS=alexpastukhh',
    '--env','FORTIS_SONAR_PROJECT_KEY=AlexPastukhh_obs-planning-docs',
    '--publish','127.0.0.1:19203:19103','--publish','127.0.0.1:19204:19104',
    '--mount',"type=volume,source=$ReviewVolume,target=/state",
    '--mount','type=volume,source=fortis-r7-identity,target=/run/r7-identity,readonly',
    '--mount','type=volume,source=fortis-r7-grant,target=/run/r7-grant,readonly',
    '--mount','type=volume,source=fortis-r7-sonar-token,target=/run/r7-sonar-token,readonly',
    '--health-cmd','python -m fortis_approvals.r7_unified_server health',
    '--health-interval','20s','--health-timeout','5s','--health-retries','3','--health-start-period','20s',
    $CandidateImage)
$CreatedId = (& docker.exe @CreateArguments | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $CreatedId -notmatch '^[0-9a-f]{64}$') { throw 'REVIEW_CONTAINER_CREATE_FAILED' }
$Created = Read-Container $CreatedId
Assert-ReviewContainer -Container $Created -Status 'created'
Write-Host 'REVIEW_CREATED_CONTAINER_ADMISSION_PASS'
if ((Read-ProductionBaseline) -cne $Before) { throw 'PRODUCTION_BASELINE_CHANGED_BEFORE_REVIEW_START' }
& docker.exe start $CreatedId
if ($LASTEXITCODE -ne 0) { throw 'REVIEW_START_FAILED_CONTAINER_LEFT_FOR_INSPECTION' }
$Deadline = (Get-Date).AddSeconds(100)
do {
    $Candidate = Read-Container $CreatedId
    if ($Candidate.State.Status -cne 'running') { throw 'REVIEW_CONTAINER_EXITED' }
    $Health = $Candidate.State.Health.Status
    if ($Health -ceq 'healthy') { break }
    if ($Health -ceq 'unhealthy') { throw 'REVIEW_CONTAINER_UNHEALTHY' }
    Start-Sleep -Seconds 2
} while ((Get-Date) -lt $Deadline)
if ($Health -cne 'healthy') { throw 'REVIEW_HEALTHCHECK_TIMEOUT' }
Assert-ReviewContainer -Container $Candidate -Status 'running'
$Portal = Invoke-WebRequest -Uri 'http://localhost:19203/' -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 10
if ($Portal.StatusCode -ne 200) { throw 'REVIEW_OWNER_PORTAL_HTTP_FAILED' }
Write-Host 'FORTIS_REVIEW_OWNER_HTTP_HOST_PASS'
& (Join-Path $PSScriptRoot 'Test-Modularized-Review-Sonar-GET-20261105.ps1')
if ((Read-ProductionBaseline) -cne $Before) { throw 'PRODUCTION_BASELINE_CHANGED_DURING_REVIEW_START' }
Write-Host 'FORTIS_MODULARIZED_REVIEW_CANDIDATE_HEALTHY_PASS'
Write-Host 'FORTIS_REVIEW_START_AND_READ_CHECKS_PASS'
Write-Host "CONTAINER_ID=$CreatedId"
Write-Host "IMAGE_ID=$CandidateImage"
Write-Host "STATE_VOLUME=$ReviewVolume"
Write-Host 'OWNER_PORT=http://localhost:19203'
Write-Host 'MACHINE_PORT=https://host.docker.internal:19204'
Write-Host 'CREDENTIAL_VOLUMES=READ_ONLY'
Write-Host 'PRODUCTION_CONTAINER_BASELINE_UNCHANGED=YES'
Write-Host 'PRODUCTION_CUTOVER=NOT_PERFORMED'
Write-Host 'PHYSICAL_WEBAUTHN_LOGIN=PENDING_OWNER_BROWSER_TEST'
