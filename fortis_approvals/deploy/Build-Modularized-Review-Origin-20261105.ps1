$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$ExpectedBranch = 'candidate/test-origin-overrides-20261105'
$ImageTag = 'fortis-approvals-gateway:modularized-review-origin-20261105'
$Dockerfile = Join-Path $RepoRoot 'fortis_approvals\deploy\Dockerfile-Gateway-Modularized-Candidate'

$SnapshotPath = Join-Path $RepoRoot 'review-source.json'
$SourceLabels = @()
if (Test-Path -LiteralPath $SnapshotPath -PathType Leaf) {
    # This is an owner-reviewed source snapshot, not a Windows Git worktree.
    $Snapshot = Get-Content -LiteralPath $SnapshotPath -Raw | ConvertFrom-Json
    if ($Snapshot.baseCommit -notmatch '^[0-9a-f]{40}$' -or
        $Snapshot.sourceTreeSha256 -notmatch '^[0-9a-f]{64}$') { throw 'SOURCE_SNAPSHOT_INVALID' }
    foreach ($Entry in $Snapshot.files.PSObject.Properties) {
        if ($Entry.Name -match '(^/|\\|(^|/)\.\.(/|$)|:)' -or $Entry.Value -notmatch '^[0-9a-f]{64}$') {
            throw 'SOURCE_SNAPSHOT_PATH_OR_HASH_INVALID'
        }
        $Source = Join-Path $RepoRoot $Entry.Name
        if ((Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Entry.Value) {
            throw ('SOURCE_SNAPSHOT_HASH_MISMATCH:' + $Entry.Name)
        }
    }
    $ActualPaths = @(Get-ChildItem -LiteralPath $RepoRoot -Force -Recurse -File | ForEach-Object {
        $_.FullName.Substring($RepoRoot.Length + 1).Replace('\','/')
    } | Where-Object { $_ -cne 'review-source.json' } | Sort-Object)
    $ExpectedPaths = @($Snapshot.files.PSObject.Properties.Name | Sort-Object)
    if (Compare-Object $ExpectedPaths $ActualPaths) { throw 'SOURCE_SNAPSHOT_FILE_SET_MISMATCH' }
    $ManifestHash = (Get-FileHash (Join-Path $RepoRoot 'docs/MODULARIZED-SOURCE-MANIFEST.sha256') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ManifestHash -cne $Snapshot.sourceTreeSha256) { throw 'SOURCE_TREE_HASH_MISMATCH' }
    $SnapshotHash = (Get-FileHash $SnapshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $Branch = 'uncommitted-owner-review-snapshot'
    $Commit = $Snapshot.baseCommit
    $SourceLabels = @('--label', "org.opencontainers.image.base-revision=$Commit",
        '--label', "org.opencontainers.image.source-snapshot-sha256=$SnapshotHash",
        '--label', "org.opencontainers.image.source-tree-sha256=$ManifestHash")
} else {
    $Branch = (& git.exe -C $RepoRoot branch --show-current | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $Branch -cne $ExpectedBranch) { throw 'REVIEW_BUILD_WRONG_BRANCH' }
    $Commit = (& git.exe -C $RepoRoot rev-parse HEAD | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $Commit -notmatch '^[0-9a-f]{40}$') { throw 'REVIEW_BUILD_COMMIT_ID_INVALID' }
    $Dirty = @(& git.exe -C $RepoRoot status --porcelain)
    if ($LASTEXITCODE -ne 0 -or $Dirty.Count -ne 0) { throw 'REVIEW_BUILD_WORKTREE_NOT_CLEAN' }
    $SourceLabels = @('--label', "org.opencontainers.image.revision=$Commit")
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
    '--tag', $ImageTag
) + $SourceLabels + @('--file', $Dockerfile, $RepoRoot)

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
Write-Host "SOURCE_BASE_COMMIT=$Commit"
if ($SnapshotHash) { Write-Host "SOURCE_SNAPSHOT_SHA256=$SnapshotHash" }
Write-Host "IMAGE_TAG=$ImageTag"
Write-Host "IMAGE_ID=$ImageId"
Write-Host 'CONTAINERS_STARTED=NO'
Write-Host 'VOLUMES_CHANGED=NO'
Write-Host 'PRODUCTION_CHANGED=NO'
Write-Host 'DEPLOYMENT=NOT_PERFORMED'
