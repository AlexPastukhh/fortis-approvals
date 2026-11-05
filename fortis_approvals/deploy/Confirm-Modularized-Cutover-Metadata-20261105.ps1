# Windows PowerShell 5.1. Narrow metadata follow-up; no lifecycle or database reads.
param([Parameter(Mandatory=$true)][string]$ProductionLaunchFile)
$ErrorActionPreference = 'Stop'
$SelectedProductionLaunchFile = $ProductionLaunchFile
$AuditPath = Join-Path $PSScriptRoot 'Audit-Modularized-Cutover-ReadOnly-20261105.ps1'
. $AuditPath -SelfTest

$ProductionName = 'fortis-approvals-gateway'
$ReviewName = 'fortis-gateway-modularized-review-20261105'
$Production = @(Read-DockerJson -Arguments @('inspect','--type','container',$ProductionName))[0]
$Review = @(Read-DockerJson -Arguments @('inspect','--type','container',$ReviewName))[0]
if ($Production.Name -cne '/fortis-approvals-gateway' -or
    $Review.Name -cne '/fortis-gateway-modularized-review-20261105') {
    throw 'CONTAINER_IDENTITY_CHANGED'
}
$Profiles = @()
foreach ($C in @($Production,$Review)) {
    $Projected = Public-Profile $C
    $Profiles += [ordered]@{ name=$C.Name; id=$C.Id; imageId=$C.Image
        status=$C.State.Status; health=$C.State.Health.Status
        healthCommand=$Projected.healthcheck.command
        hasLegacyBindSpecifications=$Projected.hasLegacyBindSpecifications
        actualHostBindCount=$Projected.actualHostBindCount }
}
$Volumes = @()
foreach ($Name in @('fortis-r7-state','fortis-r7-state-review-20261105',
    'fortis-r7-grant','fortis-r7-identity','fortis-r7-sonar-token')) {
    $V = @(Read-DockerJson -Arguments @('volume','inspect',$Name))[0]
    $Names = @(Public-PropertyNames $V.Options)
    $Volumes += [ordered]@{ name=$V.Name; driver=$V.Driver; mountpoint=$V.Mountpoint
        optionsVerifiedEmpty=($Names.Count -eq 0); optionNames=$Names }
}
$ComposePath = $SelectedProductionLaunchFile
$ExpectedHash = '1405dbc21642e6f3a056d75cb35624943fd028adf69432d22b412d33f28f1b69'
$LabelPath = $Production.Config.Labels.'com.docker.compose.project.config_files'
$Compose = [ordered]@{ path=$ComposePath; labelMatches=($LabelPath -ceq $ComposePath)
    status='NOT_HASHED'; sha256=$null; matchesGitHistoricalFile=$false }
if ($Compose.labelMatches -and (Test-Path -LiteralPath $ComposePath -PathType Leaf)) {
    $Item = Get-Item -LiteralPath $ComposePath
    if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        $Compose.status='REPARSE_POINT_NOT_HASHED'
    } else {
        $Hash = (Get-FileHash -LiteralPath $ComposePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $Compose.status='HASHED_WITHOUT_CONTENT_OUTPUT'
        $Compose.sha256=$Hash
        $Compose.matchesGitHistoricalFile=($Hash -ceq $ExpectedHash)
    }
}
$Stable = $true
foreach ($C in @($Production,$Review)) {
    $After = @(Read-DockerJson -Arguments @('inspect','--type','container',$C.Id))[0]
    $Stable = $Stable -and (
        (ConvertTo-Json -InputObject (Public-Profile $C) -Depth 20 -Compress) -ceq
        (ConvertTo-Json -InputObject (Public-Profile $After) -Depth 20 -Compress))
}
[ordered]@{ audit='Fortis narrow metadata follow-up'; timeUtc=[DateTime]::UtcNow.ToString('o')
    profilesStable=$Stable; containers=$Profiles; volumes=$Volumes; compose=$Compose
    limits=@('This does not select a maintained future deployment source',
        'No state, credential, container lifecycle or upstream change')
} | ConvertTo-Json -Depth 10
if (-not $Stable) { throw 'CONTAINER_PROFILE_CHANGED' }
if (@($Volumes | Where-Object { -not $_.optionsVerifiedEmpty -or $_.driver -cne 'local' }).Count) {
    throw 'VOLUME_DRIVER_CONFIGURATION_REQUIRES_REVIEW'
}
if (@($Profiles | Where-Object { -not $_.healthCommand.recognized -or $_.actualHostBindCount -ne 0 }).Count) {
    throw 'COMMAND_OR_HOST_BIND_CONFIGURATION_REQUIRES_REVIEW'
}
if (-not $Compose.matchesGitHistoricalFile) { throw 'COMPOSE_BYTES_REQUIRE_REVIEW' }
Write-Output 'FORTIS_CUTOVER_METADATA_FOLLOWUP_PASS'
