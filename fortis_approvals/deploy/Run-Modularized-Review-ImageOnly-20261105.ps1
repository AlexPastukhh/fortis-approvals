$ErrorActionPreference = 'Stop'
foreach ($Name in @('Build-Modularized-Review-Origin-20261105.ps1','Test-Modularized-ImageOffline-20261105.ps1')) {
    $Tokens = $null
    $Errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot $Name), [ref]$Tokens, [ref]$Errors)
    if ($Errors.Count -ne 0) { throw ('POWERSHELL_PARSE_FAILED:' + $Name + ':' + ($Errors -join ';')) }
}
$ExpectedProduction = 'sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402'
function Read-Production {
    $Raw = (& docker.exe inspect --type container fortis-approvals-gateway | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'PRODUCTION_INSPECT_FAILED' }
    $Item = (ConvertFrom-Json $Raw)[0]
    if ($Item.Image -cne $ExpectedProduction -or $Item.State.Status -cne 'running' -or
        $Item.State.Health.Status -cne 'healthy') { throw 'PRODUCTION_BASELINE_MISMATCH' }
    return $Item
}
$Before = Read-Production
& (Join-Path $PSScriptRoot 'Test-Modularized-ImageOffline-20261105.ps1')
& (Join-Path $PSScriptRoot 'Build-Modularized-Review-Origin-20261105.ps1')
$Tag = 'fortis-approvals-gateway:modularized-review-origin-20261105'
$Raw = (& docker.exe image inspect $Tag | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'NEW_IMAGE_INSPECT_FAILED' }
$Image = (ConvertFrom-Json $Raw)[0]
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$SnapshotHash = (Get-FileHash (Join-Path $Root 'review-source.json') -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Image.Config.Labels.'org.opencontainers.image.source-snapshot-sha256' -cne $SnapshotHash) {
    throw 'NEW_IMAGE_SOURCE_LABEL_MISMATCH'
}
& (Join-Path $PSScriptRoot 'Test-Modularized-ImageOffline-20261105.ps1') -Image $Image.Id -ExpectedImageId $Image.Id
$EndpointCode = "from fortis_approvals.r7_unified_server import runtime_endpoints; assert runtime_endpoints() == ('http://localhost:19203','host.docker.internal:19204'); print('IMAGE_REVIEW_ENDPOINTS_PASS')"
& docker.exe run --rm --pull=never --network none --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 --memory 128m --env FORTIS_OWNER_ORIGIN=http://localhost:19203 --env FORTIS_MACHINE_HOST=host.docker.internal:19204 --entrypoint python $Image.Id -c $EndpointCode
if ($LASTEXITCODE -ne 0) { throw 'NEW_IMAGE_ENDPOINT_CHECK_FAILED' }
$After = Read-Production
if ($After.Id -cne $Before.Id -or $After.State.StartedAt -cne $Before.State.StartedAt) {
    throw 'PRODUCTION_ID_OR_START_TIME_CHANGED'
}
Write-Host 'FORTIS_REVIEW_IMAGE_ONLY_CHECKS_PASS'
Write-Host "NEW_IMAGE_ID=$($Image.Id)"
Write-Host "SOURCE_SNAPSHOT_SHA256=$SnapshotHash"
Write-Host 'PRODUCTION_CONTAINER_ID_AND_START_TIME_UNCHANGED=YES'
Write-Host 'STATE_OR_CREDENTIAL_VOLUMES_MOUNTED_BY_CHECKS=NO'
Write-Host 'REVIEW_GATEWAY_STARTED=NO'
Write-Host 'STATE_RESTORED=NO'
