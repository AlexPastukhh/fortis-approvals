$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$ExpectedBranch = 'candidate/test-origin-overrides-20261105'
$ImageTag = 'fortis-approvals-gateway:modularized-review-origin-20261105'
$Dockerfile = Join-Path $RepoRoot 'fortis_approvals\deploy\Dockerfile-Gateway-Modularized-Candidate'

$Branch = (& git.exe -C $RepoRoot branch --show-current | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $Branch -cne $ExpectedBranch) {
    throw 'REVIEW_BUILD_WRONG_BRANCH'
}
$Commit = (& git.exe -C $RepoRoot rev-parse HEAD | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $Commit -notmatch '^[0-9a-f]{40}$') {
    throw 'REVIEW_BUILD_COMMIT_ID_INVALID'
}
$Dirty = @(& git.exe -C $RepoRoot status --porcelain)
if ($LASTEXITCODE -ne 0 -or $Dirty.Count -ne 0) {
    throw 'REVIEW_BUILD_WORKTREE_NOT_CLEAN'
}
if (-not (Test-Path -LiteralPath $Dockerfile -PathType Leaf)) {
    throw 'MODULARIZED_DOCKERFILE_MISSING'
}

$DockerInfo = (& docker.exe info --format '{{.OSType}}' | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $DockerInfo -cne 'linux') {
    throw 'DOCKER_LINUX_ENGINE_REQUIRED'
}
$Images = @(& docker.exe image ls --format '{{.Repository}}:{{.Tag}}')
if ($LASTEXITCODE -ne 0) { throw 'DOCKER_IMAGE_LIST_FAILED' }
if ($Images -ccontains $ImageTag) {
    throw 'REVIEW_IMAGE_TAG_ALREADY_EXISTS_NO_OVERWRITE'
}
if ($Images -cnotcontains 'python:3.11-slim') {
    throw 'PYTHON_BASE_IMAGE_NOT_PRESENT_NO_PULL'
}

$BuildArguments = @(
    'build', '--pull=false',
    '--tag', $ImageTag,
    '--label', "org.opencontainers.image.revision=$Commit",
    '--file', $Dockerfile,
    $RepoRoot
)

$PreviousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & docker.exe @BuildArguments
    $BuildExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $PreviousPreference
}
if ($BuildExitCode -ne 0) {
    throw 'MODULARIZED_REVIEW_IMAGE_BUILD_FAILED'
}

$ImageId = (& docker.exe image inspect --format '{{.Id}}' $ImageTag | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $ImageId -notmatch '^sha256:[0-9a-f]{64}$') {
    throw 'MODULARIZED_REVIEW_IMAGE_INSPECT_FAILED'
}

Write-Host 'FORTIS_MODULARIZED_REVIEW_IMAGE_BUILD_PASS'
Write-Host "SOURCE_BRANCH=$Branch"
Write-Host "SOURCE_COMMIT=$Commit"
Write-Host "IMAGE_TAG=$ImageTag"
Write-Host "IMAGE_ID=$ImageId"
Write-Host 'CONTAINERS_STARTED=NO'
Write-Host 'VOLUMES_CHANGED=NO'
Write-Host 'PRODUCTION_CHANGED=NO'
Write-Host 'DEPLOYMENT=NOT_PERFORMED'
