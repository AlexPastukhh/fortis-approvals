$ErrorActionPreference = 'Stop'

$ProductionName = 'fortis-approvals-gateway'
$ExpectedProductionImage = 'sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402'
$CandidateName = 'fortis-gateway-modularized-review-20261105'
$CandidateImage = 'fortis-approvals-gateway:modularized-review-origin-20261105'
$ReviewVolume = 'fortis-r7-state-review-20261105'
$Project = 'fortis-modularized-review-20261105'
$ComposeFile = Join-Path $PSScriptRoot 'compose-modularized-review-20261105.yaml'

if (-not (Test-Path -LiteralPath $ComposeFile -PathType Leaf)) {
    throw 'REVIEW_COMPOSE_FILE_MISSING'
}
$DockerInfo = (& docker.exe info --format '{{.OSType}}' | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $DockerInfo -cne 'linux') {
    throw 'DOCKER_LINUX_ENGINE_REQUIRED'
}

$ProductionRaw = (& docker.exe inspect $ProductionName | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'PRODUCTION_INSPECT_FAILED' }
$Production = (ConvertFrom-Json $ProductionRaw)[0]
if ($Production.State.Status -ne 'running' -or
    $Production.State.Health.Status -ne 'healthy' -or
    $Production.Image -cne $ExpectedProductionImage) {
    throw 'PRODUCTION_IDENTITY_OR_HEALTH_MISMATCH'
}

$Images = @(& docker.exe image ls --format '{{.Repository}}:{{.Tag}}')
if ($LASTEXITCODE -ne 0) { throw 'DOCKER_IMAGE_LIST_FAILED' }
if ($Images -cnotcontains $CandidateImage) {
    throw 'MODULARIZED_REVIEW_IMAGE_MISSING'
}
$Volumes = @(& docker.exe volume ls --format '{{.Name}}')
if ($LASTEXITCODE -ne 0) { throw 'DOCKER_VOLUME_LIST_FAILED' }
foreach ($RequiredVolume in @(
    $ReviewVolume,
    'fortis-r7-identity',
    'fortis-r7-grant',
    'fortis-r7-sonar-token'
)) {
    if ($Volumes -cnotcontains $RequiredVolume) {
        throw "REQUIRED_VOLUME_MISSING: $RequiredVolume"
    }
}

$ExistingCandidate = @(& docker.exe ps -aq --filter "name=^/$CandidateName$")
if ($LASTEXITCODE -ne 0) { throw 'DOCKER_PS_FAILED' }
if ($ExistingCandidate.Count -ne 0) {
    throw 'REVIEW_CONTAINER_ALREADY_EXISTS_NO_OVERWRITE'
}
$ReviewVolumeUsers = @(& docker.exe ps -aq --filter "volume=$ReviewVolume")
if ($LASTEXITCODE -ne 0) { throw 'REVIEW_VOLUME_USAGE_CHECK_FAILED' }
if ($ReviewVolumeUsers.Count -ne 0) {
    throw 'REVIEW_VOLUME_ALREADY_ATTACHED_TO_CONTAINER'
}

$PortUsers = @()
foreach ($Port in @(19203, 19204)) {
    $Ids = @(& docker.exe ps -aq --filter "publish=$Port")
    if ($LASTEXITCODE -ne 0) { throw 'PORT_USAGE_CHECK_FAILED' }
    foreach ($Id in $Ids) {
        $Raw = (& docker.exe inspect $Id | Out-String)
        if ($LASTEXITCODE -ne 0) { throw 'PORT_USER_INSPECT_FAILED' }
        $Item = (ConvertFrom-Json $Raw)[0]
        $PortUsers += "$($Item.Name) [$($Item.State.Status)]"
    }
}
if ($PortUsers.Count -ne 0) {
    throw ('REVIEW_PORTS_ALREADY_IN_USE: ' + ($PortUsers -join '; '))
}

$PreviousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & docker.exe compose -p $Project -f $ComposeFile config --quiet
    $ConfigExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $PreviousPreference
}
if ($ConfigExitCode -ne 0) { throw 'REVIEW_COMPOSE_CONFIG_INVALID' }

$PreviousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & docker.exe compose -p $Project -f $ComposeFile up -d --no-build --pull never
    $StartExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $PreviousPreference
}
if ($StartExitCode -ne 0) {
    throw 'REVIEW_CONTAINER_START_FAILED_PRODUCTION_UNCHANGED'
}

$Deadline = (Get-Date).AddSeconds(100)
$Health = 'starting'
do {
    $Raw = (& docker.exe inspect $CandidateName | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'REVIEW_CONTAINER_INSPECT_FAILED' }
    $Candidate = (ConvertFrom-Json $Raw)[0]
    if ($Candidate.State.Status -ne 'running') {
        throw "REVIEW_CONTAINER_EXITED: $($Candidate.State.ExitCode)"
    }
    $Health = $Candidate.State.Health.Status
    if ($Health -eq 'healthy') { break }
    if ($Health -eq 'unhealthy') { throw 'REVIEW_HEALTHCHECK_FAILED' }
    Start-Sleep -Seconds 2
} while ((Get-Date) -lt $Deadline)
if ($Health -ne 'healthy') { throw 'REVIEW_HEALTHCHECK_TIMEOUT' }

if ($Candidate.Config.User -cne '10001:10001' -or
    -not $Candidate.HostConfig.ReadonlyRootfs -or
    $Candidate.HostConfig.Privileged) {
    throw 'REVIEW_CONTAINER_SECURITY_MISMATCH'
}
$StateMount = @($Candidate.Mounts | Where-Object {
    $_.Type -eq 'volume' -and $_.Name -eq $ReviewVolume -and
    $_.Destination -eq '/state' -and $_.RW
})
if ($StateMount.Count -ne 1) { throw 'REVIEW_STATE_VOLUME_MISMATCH' }

$CredentialVolumes = @(
    @{ Name='fortis-r7-identity'; Target='/run/r7-identity' },
    @{ Name='fortis-r7-grant'; Target='/run/r7-grant' },
    @{ Name='fortis-r7-sonar-token'; Target='/run/r7-sonar-token' }
)
foreach ($Entry in $CredentialVolumes) {
    $Mount = @($Candidate.Mounts | Where-Object {
        $_.Type -eq 'volume' -and $_.Name -eq $Entry.Name -and
        $_.Destination -eq $Entry.Target -and -not $_.RW
    })
    if ($Mount.Count -ne 1) {
        throw "REVIEW_CREDENTIAL_VOLUME_MISMATCH: $($Entry.Name)"
    }
}

$ProductionAfterRaw = (& docker.exe inspect $ProductionName | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'PRODUCTION_POST_START_INSPECT_FAILED' }
$ProductionAfter = (ConvertFrom-Json $ProductionAfterRaw)[0]
if ($ProductionAfter.State.Status -ne 'running' -or
    $ProductionAfter.State.Health.Status -ne 'healthy' -or
    $ProductionAfter.Image -cne $ExpectedProductionImage) {
    throw 'PRODUCTION_CHANGED_DURING_REVIEW_START'
}

Write-Host 'FORTIS_MODULARIZED_REVIEW_CANDIDATE_HEALTHY_PASS'
Write-Host "CONTAINER=$CandidateName"
Write-Host "IMAGE=$($Candidate.Config.Image)"
Write-Host "IMAGE_ID=$($Candidate.Image)"
Write-Host "HEALTH=$Health"
Write-Host "OWNER_PORT=http://localhost:19203"
Write-Host "MACHINE_PORT=https://host.docker.internal:19204"
Write-Host "STATE_VOLUME=$ReviewVolume"
Write-Host 'CREDENTIAL_VOLUMES=READ_ONLY'
Write-Host 'PRODUCTION=UNCHANGED_AND_HEALTHY'
Write-Host 'PRODUCTION_CUTOVER=NOT_PERFORMED'
