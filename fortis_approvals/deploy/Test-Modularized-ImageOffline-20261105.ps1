param(
    [string]$Image = 'fortis-approvals-gateway:modularized-review-3355941',
    [string]$ExpectedImageId = 'sha256:a2fd23c3def0609ed254cd796f40fb51cc4a5a103f0486bb0052d44d76b23267'
)
$ErrorActionPreference = 'Stop'
$Raw = (& docker.exe image inspect $Image | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'SMOKE_IMAGE_NOT_FOUND' }
$Info = (ConvertFrom-Json $Raw)[0]
if ($Info.Id -cne $ExpectedImageId -or $Info.Config.User -cne '10001:10001') {
    throw 'SMOKE_IMAGE_ID_OR_USER_MISMATCH'
}
$ImageId = $Info.Id
$Common = @('run','--rm','--pull=never','--network','none','--read-only',
    '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
    '--pids-limit','64','--memory','256m','--tmpfs','/tmp:rw,nosuid,nodev,size=32m',
    '--entrypoint','python',$ImageId)
function Invoke-ImageCheck {
    param([string[]]$PythonArguments)
    $Previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & docker.exe @Common @PythonArguments
        $ExitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $Previous }
    if ($ExitCode -ne 0) { throw ('IMAGE_CHECK_FAILED: ' + ($PythonArguments[0])) }
}
Invoke-ImageCheck -PythonArguments @('-m','pip','check')
Write-Host "IMAGE_PIP_CHECK_PASS=$ImageId"
Invoke-ImageCheck -PythonArguments @('-m','fortis_approvals.r7_unified_server','preflight-imports')
$SmokeSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'image_offline_smoke.py') -Raw
$Encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($SmokeSource))
$Command = "import base64;exec(compile(base64.b64decode('$Encoded'),'<image-offline-smoke>','exec'))"
Invoke-ImageCheck -PythonArguments @('-c',$Command)
Write-Host "FORTIS_IMAGE_OFFLINE_CHECKS_PASS=$ImageId"
Write-Host 'RUNTIME_STATE_MOUNTS=NONE'
Write-Host 'CREDENTIAL_MOUNTS=NONE'
Write-Host 'PUBLISHED_PORTS=NONE'
