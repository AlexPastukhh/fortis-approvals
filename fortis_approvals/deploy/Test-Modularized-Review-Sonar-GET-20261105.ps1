$ErrorActionPreference = 'Stop'

$GatewayName = 'fortis-gateway-modularized-review-20261105'
$RepoContainer = 'fortis-repo-test'
$CandidateImage = 'fortis-approvals-gateway:modularized-review-origin-20261105'

$GatewayRaw = (& docker.exe inspect $GatewayName | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'REVIEW_GATEWAY_INSPECT_FAILED' }
$Gateway = (ConvertFrom-Json $GatewayRaw)[0]
if ($Gateway.State.Status -ne 'running' -or
    $Gateway.State.Health.Status -ne 'healthy' -or
    $Gateway.Config.Image -cne $CandidateImage) {
    throw 'REVIEW_GATEWAY_NOT_HEALTHY_OR_WRONG_IMAGE'
}

$RepoRaw = (& docker.exe inspect $RepoContainer | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'REPO_CONTAINER_INSPECT_FAILED' }
$Repo = (ConvertFrom-Json $RepoRaw)[0]
if ($Repo.State.Status -ne 'running') { throw 'REPO_CONTAINER_NOT_RUNNING' }

$ClientMount = @($Repo.Mounts | Where-Object {
    $_.Type -eq 'volume' -and $_.Name -eq 'fortis-r7-client' -and
    $_.Destination -eq '/run/fortis-client' -and -not $_.RW
})
if ($ClientMount.Count -ne 1) {
    throw 'REPO_MACHINE_CREDENTIAL_MOUNT_INVALID'
}

$PythonSource = @'
import sys
sys.path.insert(0, "/workspace/repo/Worktrees/fortis-approvals/candidate-origin-overrides-20261105")

from fortis_approvals.integrations.sonarcloud.repo_client import client

client.ENDPOINT = "https://host.docker.internal:19204"
client.ALLOW_TEST_ENDPOINTS = True

result = client.call(
    "sonar.get_quality_gate",
    target="AlexPastukhh_obs-planning-docs",
)
if (result.get("service") != "sonarcloud" or
        result.get("operation") != "get_quality_gate" or
        type(result.get("data")) is not dict):
    raise SystemExit("REVIEW_SONAR_GET_RESPONSE_INVALID")

print("FORTIS_REVIEW_MACHINE_TLS_GET_PASS")
print("SERVICE=sonarcloud")
print("OPERATION=get_quality_gate")
print("UPSTREAM_MUTATION=NO")
'@

$EncodedPython = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($PythonSource)
)
$PythonCommand = "import base64;exec(compile(base64.b64decode('$EncodedPython'),'<review-sonar-get>','exec'))"

$PreviousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $Output = @(& docker.exe exec $RepoContainer python -c $PythonCommand 2>&1)
    $ExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $PreviousPreference
}
$Output | ForEach-Object { Write-Host ([string]$_) }
if ($ExitCode -ne 0) { throw 'REVIEW_SONAR_GET_FAILED' }

Write-Host 'PRODUCTION_GATEWAY_NOT_TOUCHED'
Write-Host 'SONAR_WRITE=NOT_PERFORMED'
