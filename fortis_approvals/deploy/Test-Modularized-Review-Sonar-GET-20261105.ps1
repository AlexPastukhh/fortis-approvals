$ErrorActionPreference = 'Stop'
$GatewayName = 'fortis-gateway-modularized-review-20261105'
$RepoContainer = 'fortis-repo-test'
$CandidateImage = 'sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84'
$Raw = (& docker.exe inspect --type container $GatewayName | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'REVIEW_GATEWAY_INSPECT_FAILED' }
$Gateway = (ConvertFrom-Json $Raw)[0]
if ($Gateway.Image -cne $CandidateImage -or $Gateway.State.Status -cne 'running' -or
    $Gateway.State.Health.Status -cne 'healthy') { throw 'REVIEW_GATEWAY_IDENTITY_OR_HEALTH_MISMATCH' }
if (@($Gateway.Config.Env | Where-Object { $_ -ceq 'FORTIS_MACHINE_HOST=host.docker.internal:19204' }).Count -ne 1 -or
    @($Gateway.HostConfig.PortBindings.'19104/tcp').Count -ne 1 -or
    $Gateway.HostConfig.PortBindings.'19104/tcp'[0].HostIp -cne '127.0.0.1' -or
    $Gateway.HostConfig.PortBindings.'19104/tcp'[0].HostPort -cne '19204') {
    throw 'REVIEW_MACHINE_ENDPOINT_MISMATCH'
}
$Raw = (& docker.exe inspect --type container $RepoContainer | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'REPO_INSPECT_FAILED' }
$Repo = (ConvertFrom-Json $Raw)[0]
if ($Repo.State.Status -cne 'running' -or $Repo.Config.User -cne '1000:1000') { throw 'REPO_IDENTITY_MISMATCH' }
$Mount = @($Repo.Mounts | Where-Object { $_.Type -ceq 'volume' -and $_.Name -ceq 'fortis-r7-client' -and
    $_.Destination -ceq '/run/fortis-client' -and -not $_.RW })
if ($Mount.Count -ne 1) { throw 'REPO_CLIENT_VOLUME_MISMATCH' }
$Source = Get-Content (Join-Path $PSScriptRoot 'review_repo_get.py') -Raw
$Hashes = Get-Content (Join-Path $PSScriptRoot 'review-repo-source-hashes-20261105.json') -Raw
$Source64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Source))
$Hashes64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Hashes))
$Code = "import base64,json;ns={};exec(compile(base64.b64decode('$Source64'),'<review-repo-get>','exec'),ns);ns['run'](json.loads(base64.b64decode('$Hashes64')))"
$Previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & docker.exe exec --user 1000:1000 $RepoContainer python3 -I -B -c $Code
    $ExitCode = $LASTEXITCODE
} finally { $ErrorActionPreference = $Previous }
if ($ExitCode -ne 0) { throw 'REVIEW_SONAR_GET_FAILED' }
Write-Host 'SONAR_WRITE=NOT_PERFORMED'
