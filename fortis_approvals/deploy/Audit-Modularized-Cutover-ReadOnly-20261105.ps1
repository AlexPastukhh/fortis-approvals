# Windows PowerShell 5.1. Docker metadata reads only; no database or credential access.
param([string]$ProductionLaunchFile = '', [switch]$SelfTest)
$ErrorActionPreference = 'Stop'

function Read-DockerJson {
    param([string[]]$Arguments)
    $Raw = @(& docker.exe @Arguments)
    if ($LASTEXITCODE -ne 0) { throw 'DOCKER_METADATA_READ_FAILED' }
    return (($Raw -join "`n") | ConvertFrom-Json)
}
function Public-PropertyNames {
    param($Value)
    if ($null -eq $Value) { return }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($Key in $Value.Keys) { if ($null -ne $Key) { [string]$Key } }
        return
    }
    foreach ($Property in $Value.PSObject.Properties) {
        if ($null -ne $Property -and $null -ne $Property.Name) { $Property.Name }
    }
}
function Public-Command {
    param($Value)
    if ($null -eq $Value) { return [ordered]@{ recognized=$true; argv=$null } }
    $Encoded = ConvertTo-Json -InputObject @($Value) -Compress
    $Known = @('[]',
        '["python","-m","fortis_approvals.r7_unified_server"]',
        '["CMD","python","-m","fortis_approvals.r7_unified_server","health"]',
        '["CMD-SHELL","python -m fortis_approvals.r7_unified_server health"]')
    if ($Known -ccontains $Encoded) {
        return [ordered]@{ recognized=$true; argv=@($Value) }
    }
    return [ordered]@{ recognized=$false; argumentCount=@($Value).Count }
}
function Public-Environment {
    param($Values)
    $Public = [ordered]@{}
    $Hidden = @()
    $Patterns = @{
        FORTIS_OWNER_ORIGIN='^http://localhost:[0-9]{4,5}$'
        FORTIS_MACHINE_HOST='^host\.docker\.internal:[0-9]{4,5}$'
        FORTIS_SONAR_REGION='^(eu|us)$'
        FORTIS_SONAR_ORGANIZATIONS='^[A-Za-z0-9_.:-]+(,[A-Za-z0-9_.:-]+)*$'
        FORTIS_SONAR_PROJECT_KEY='^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
    }
    foreach ($Item in @($Values)) {
        $Parts = $Item -split '=',2
        if ($Parts.Count -ne 2) { $Hidden += '<invalid-entry>'; continue }
        $Key,$Value = $Parts
        if ($Patterns.ContainsKey($Key) -and $Value -cmatch $Patterns[$Key]) {
            $Public[$Key] = $Value
        } else {
            if ($Key -cmatch '^[A-Za-z_][A-Za-z0-9_]*$') { $Hidden += $Key }
            else { $Hidden += '<nonstandard-name>' }
        }
    }
    return [ordered]@{ public=$Public; omittedValueNames=$Hidden }
}
function Public-Profile {
    param($Container)
    $C = $Container
    $Labels = [ordered]@{}
    foreach ($Key in @('com.docker.compose.project','com.docker.compose.service',
        'com.docker.compose.project.working_dir',
        'com.docker.compose.project.config_files','com.docker.compose.config-hash')) {
        if ($null -ne $C.Config.Labels.$Key) { $Labels[$Key]=$C.Config.Labels.$Key }
    }
    $Health = $null
    if ($C.State.Health) { $Health=$C.State.Health.Status }
    return [ordered]@{
        name=$C.Name; id=$C.Id; imageId=$C.Image; imageReference=$C.Config.Image
        status=$C.State.Status; health=$Health; startedAt=$C.State.StartedAt
        restartCount=$C.RestartCount; user=$C.Config.User
        command=(Public-Command $C.Config.Cmd)
        entrypoint=(Public-Command $C.Config.Entrypoint)
        workingDirectory=$C.Config.WorkingDir; stopSignal=$C.Config.StopSignal
        environment=(Public-Environment $C.Config.Env); composeLabels=$Labels
        healthcheck=[ordered]@{
            command=(Public-Command $C.Config.Healthcheck.Test)
            interval=$C.Config.Healthcheck.Interval; timeout=$C.Config.Healthcheck.Timeout
            startPeriod=$C.Config.Healthcheck.StartPeriod; retries=$C.Config.Healthcheck.Retries
        }
        mounts=@($C.Mounts | Select-Object Type,Name,Source,Destination,RW,Mode,Propagation)
        host=($C.HostConfig | Select-Object ReadonlyRootfs,Privileged,Init,AutoRemove,
            CapAdd,CapDrop,SecurityOpt,ReadonlyPaths,MaskedPaths,RestartPolicy,
            PortBindings,Tmpfs,NetworkMode,PidMode,IpcMode,UTSMode,UsernsMode,
            PidsLimit,Memory,MemorySwap,MemoryReservation,NanoCpus,CpuShares,
            CpuPeriod,CpuQuota,CpusetCpus,CpusetMems,Ulimits,ShmSize,ExtraHosts,
            Dns,DnsOptions,DnsSearch,Devices,DeviceRequests,VolumesFrom)
        hasLegacyBindSpecifications=(@($C.HostConfig.Binds | Where-Object { $null -ne $_ }).Count -gt 0)
        actualHostBindCount=@($C.Mounts | Where-Object { $_.Type -ceq 'bind' }).Count
        logDriver=$C.HostConfig.LogConfig.Type
        logOptionNames=@(Public-PropertyNames $C.HostConfig.LogConfig.Config)
        networks=@($C.NetworkSettings.Networks.PSObject.Properties | ForEach-Object {
            [ordered]@{ name=$_.Name; networkId=$_.Value.NetworkID
                ipAddress=$_.Value.IPAddress; gateway=$_.Value.Gateway
                aliases=$_.Value.Aliases }
        })
    }
}

if ($SelfTest) {
    $Cases = 0
    foreach ($Value in @($null, [pscustomobject]@{}, (ConvertFrom-Json '{}'), @{})) {
        if (@(Public-PropertyNames $Value).Count -ne 0) { throw 'EMPTY_OPTIONS_REGRESSION' }
        $Cases++
    }
    foreach ($Value in @([pscustomobject]@{ device='DO_NOT_OUTPUT_VALUE' },
        @{ device='DO_NOT_OUTPUT_VALUE' }, (ConvertFrom-Json '{"device":"DO_NOT_OUTPUT_VALUE"}'))) {
        $Names = @(Public-PropertyNames $Value)
        if ($Names.Count -ne 1 -or $Names[0] -cne 'device') { throw 'OPTION_NAMES_REGRESSION' }
        if ((ConvertTo-Json -InputObject $Names) -match 'DO_NOT_OUTPUT_VALUE') {
            throw 'OPTION_VALUE_DISCLOSED'
        }
        $Cases++
    }
    foreach ($Command in @(
        @('CMD','python','-m','fortis_approvals.r7_unified_server','health'),
        @('CMD-SHELL','python -m fortis_approvals.r7_unified_server health'))) {
        if (-not (Public-Command $Command).recognized) { throw 'KNOWN_HEALTH_COMMAND_REJECTED' }
        $Cases++
    }
    $Unknown = Public-Command @('CMD-SHELL','DO_NOT_OUTPUT_UNKNOWN_COMMAND')
    if ($Unknown.recognized -or (ConvertTo-Json $Unknown) -match 'DO_NOT_OUTPUT') {
        throw 'UNKNOWN_COMMAND_DISCLOSED'
    }
    $Cases++
    $Fake = [pscustomobject]@{
        Config=[pscustomobject]@{ Env=@(); Labels=[pscustomobject]@{} }
        State=[pscustomobject]@{}
        HostConfig=[pscustomobject]@{ Binds=@('fortis-r7-state:/state:rw') }
        NetworkSettings=[pscustomobject]@{ Networks=[pscustomobject]@{} }
        Mounts=@([pscustomobject]@{ Type='volume' })
    }
    $Projected = Public-Profile $Fake
    if (-not $Projected.hasLegacyBindSpecifications -or $Projected.actualHostBindCount -ne 0) {
        throw 'NAMED_VOLUME_BIND_SPECIFICATION_MISCLASSIFIED'
    }
    $Cases++
    $Fake.Mounts=@([pscustomobject]@{ Type='bind' })
    if ((Public-Profile $Fake).actualHostBindCount -ne 1) { throw 'HOST_BIND_MISCLASSIFIED' }
    $Cases++
    Write-Output ('FORTIS_AUDIT_PROJECTION_SELFTEST_PASS cases=' + $Cases)
    return
}

$Engine = (& docker.exe info --format '{{.OSType}}' | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $Engine -cne 'linux') { throw 'LINUX_DOCKER_ENGINE_REQUIRED' }
$Ids = @(& docker.exe ps -a -q --no-trunc)
if ($LASTEXITCODE -ne 0 -or $Ids.Count -eq 0) { throw 'CONTAINER_INVENTORY_UNAVAILABLE' }
$All = @()
foreach ($Id in $Ids) {
    $Items = @(Read-DockerJson -Arguments @('inspect','--type','container',$Id))
    if ($Items.Count -ne 1) { throw 'CONTAINER_INSPECT_COUNT_INVALID' }
    $All += $Items[0]
}
$Production = @($All | Where-Object { $_.Name -ceq '/fortis-approvals-gateway' })
$Review = @($All | Where-Object { $_.Name -ceq '/fortis-gateway-modularized-review-20261105' })
if ($Production.Count -ne 1 -or $Review.Count -ne 1) { throw 'REQUIRED_CONTAINER_MISSING' }
$Production = $Production[0]
$Review = $Review[0]
$State = @($Production.Mounts | Where-Object { $_.Destination -ceq '/state' })
if ($State.Count -ne 1) { throw 'PRODUCTION_STATE_MAPPING_UNKNOWN' }
$State = $State[0]
$StateUsers = @()
foreach ($C in $All) {
    foreach ($M in @($C.Mounts)) {
        $Alias = ($M.Name -ceq 'fortis-r7-state')
        if ($M.Source -and $State.Source) {
            $Alias = $Alias -or ($M.Source -ceq $State.Source) -or
                $M.Source.StartsWith($State.Source.TrimEnd('/') + '/', [StringComparison]::Ordinal) -or
                $State.Source.StartsWith($M.Source.TrimEnd('/') + '/', [StringComparison]::Ordinal)
        }
        if ($Alias) {
            $StateUsers += [ordered]@{ name=$C.Name; id=$C.Id; status=$C.State.Status
                rw=$M.RW; type=$M.Type; volumeName=$M.Name
                source=$M.Source; destination=$M.Destination
                unexpectedActiveWriter=($M.RW -and $C.Id -cne $Production.Id -and
                    $C.State.Status -cnotin @('exited','created','dead')) }
        }
    }
}
$VolumeNames = @(@($Production.Mounts) + @($Review.Mounts) |
    Where-Object { $_.Type -ceq 'volume' } | ForEach-Object { $_.Name } | Sort-Object -Unique)
$Volumes = @()
foreach ($Name in $VolumeNames) {
    $V = @(Read-DockerJson -Arguments @('volume','inspect',$Name))[0]
    $OptionNames = @(Public-PropertyNames $V.Options)
    $Volumes += [ordered]@{ name=$V.Name; driver=$V.Driver; scope=$V.Scope
        mountpoint=$V.Mountpoint; optionNames=$OptionNames
        optionsVerifiedEmpty=($OptionNames.Count -eq 0) }
}
$Profiles = @((Public-Profile $Production),(Public-Profile $Review))
$LaunchPaths = @()
$ComposeFiles = $Production.Config.Labels.'com.docker.compose.project.config_files'
if ($ComposeFiles) { $LaunchPaths += @($ComposeFiles -split ',') }
if ($ProductionLaunchFile) { $LaunchPaths += $ProductionLaunchFile }
$LaunchFiles = @()
foreach ($Path in @($LaunchPaths | Sort-Object -Unique)) {
    if (-not [IO.Path]::IsPathRooted($Path)) {
        $LaunchFiles += [ordered]@{ path=$Path; status='RELATIVE_PATH_NOT_RESOLVED' }
        continue
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $LaunchFiles += [ordered]@{ path=$Path; status='NOT_PRESENT_ON_WINDOWS_HOST' }
        continue
    }
    $Info = Get-Item -LiteralPath $Path
    $FileStatus = 'LABEL_PATH_METADATA_ONLY'
    $FileHash = $null
    if ($ProductionLaunchFile -and
        $Info.FullName -ieq [IO.Path]::GetFullPath($ProductionLaunchFile)) {
        if ($Info.Extension -in @('.yaml','.yml','.ps1') -and
            -not ($Info.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            $FileHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
            $FileStatus = 'OWNER_SELECTED_LAUNCH_FILE_HASHED_WITHOUT_CONTENT_OUTPUT'
        } else { $FileStatus = 'UNSUPPORTED_EXTENSION_OR_REPARSE_POINT_NO_HASH' }
    }
    $LaunchFiles += [ordered]@{ path=$Info.FullName; status=$FileStatus
        sha256=$FileHash; lastWriteTimeUtc=$Info.LastWriteTimeUtc.ToString('o'); length=$Info.Length }
}
$Stable = $true
foreach ($C in @($Production,$Review)) {
    $After = @(Read-DockerJson -Arguments @('inspect','--type','container',$C.Id))[0]
    $Stable = $Stable -and (
        (ConvertTo-Json -InputObject (Public-Profile $C) -Depth 20 -Compress) -ceq
        (ConvertTo-Json -InputObject (Public-Profile $After) -Depth 20 -Compress))
}
[ordered]@{
    audit='Fortis pre-cutover metadata inventory'; timeUtc=[DateTime]::UtcNow.ToString('o')
    stableSelectedContainerProfiles=$Stable; containers=$Profiles; volumes=$Volumes
    productionStateUsers=$StateUsers
    productionImageMatchesRecorded=($Production.Image -ceq 'sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402')
    reviewImageMatchesRecorded=($Review.Image -ceq 'sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84')
    productionLaunchFileObservations=$LaunchFiles
    launchProvenance='Compose labels and optional owner path only; maintained source not yet confirmed'
    limits=@('Unknown command values and non-allowlisted environment values are omitted',
        'Nonempty volume driver option values and log option values are omitted',
        'No database, credential file, container log or upstream API was read',
        'No backup, write lock, lifecycle operation or cutover was performed',
        'Inventory does not grant release approval or prove backup/rollback readiness')
} | ConvertTo-Json -Depth 24
if (-not $Stable) { throw 'CONTAINER_PROFILE_CHANGED_DURING_INVENTORY' }
if (@($StateUsers | Where-Object { $_.unexpectedActiveWriter }).Count -gt 0) {
    throw 'UNEXPECTED_ACTIVE_PRODUCTION_STATE_WRITER'
}
Write-Output 'FORTIS_CUTOVER_READONLY_INVENTORY_COMPLETE'
