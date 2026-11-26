# Windows PowerShell 5.1. Owner-run isolated GitHub pilot; no Production lifecycle commands.
[CmdletBinding()]
param(
    [ValidateSet('Start','Resume','Rollback','SelfTest','Functions')][string]$Mode = 'Start',
    [string]$Repository = '', [string]$Record = '', [string]$ExpectedSourceCommit = '',
    [string]$ResumePreparedSourceCommit = '',
    [switch]$ConfirmTestRepository
)
$ErrorActionPreference = 'Stop'
$SourceRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$ReviewName = 'fortis-gateway-modularized-review-20261105'
$ReviewImage = 'sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84'
$ProductionImage = 'sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402'

function Docker-Text {
    param([string[]]$Arguments)
    $Previous = $ErrorActionPreference
    try { $ErrorActionPreference = 'Continue'; $Lines = @(& docker.exe @Arguments); $Code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $Previous }
    if ($Code -ne 0) { throw 'PILOT_DOCKER_COMMAND_FAILED' }
    return ($Lines -join "`n").Trim()
}
function Docker-Json {
    param([string[]]$Arguments)
    return ((Docker-Text $Arguments) | ConvertFrom-Json)
}
function Container {
    param([string]$Identity)
    $Items = @(Docker-Json @('inspect','--type','container',$Identity))
    if ($Items.Count -ne 1) { throw 'PILOT_CONTAINER_INSPECT_INVALID' }
    return $Items[0]
}
# Fresh bounded batches of exact IDs, never cached across guards.
# 128 full IDs fit within Windows native command-line limits.
function Inspect-Containers {
    param([string[]]$Ids)
    if (-not $Ids) { return }
    $Requested=@{}
    foreach ($Id in $Ids) {
        if ($Id -cnotmatch '^[0-9a-f]{64}$' -or $Requested.ContainsKey($Id)) {
            throw 'PILOT_CONTAINER_INVENTORY_INVALID'
        }
        $Requested[$Id]=$true
    }
    $Observed=@{}
    for ($Offset=0; $Offset -lt $Ids.Count; $Offset+=128) {
        $Chunk=@($Ids[$Offset..([math]::Min($Offset+127,$Ids.Count-1))])
        $Parsed=ConvertFrom-Json -InputObject (Docker-Text (@('inspect','--type','container')+$Chunk)) -ErrorAction Stop
        $Count=0
        # PS5.1 ConvertFrom-Json can emit an array as one pipeline object.
        foreach ($Item in $Parsed) {
            if ($null -eq $Item -or $Item.Id -cnotmatch '^[0-9a-f]{64}$' -or
                $Chunk -cnotcontains $Item.Id -or $Observed.ContainsKey($Item.Id) -or
                $null -eq $Item.State -or -not $Item.State.Status -or
                $null -eq $Item.PSObject.Properties['Mounts']) {
                throw 'PILOT_CONTAINER_INVENTORY_INVALID'
            }
            $Observed[$Item.Id]=$Item
            $Count++
        }
        if ($Count -ne $Chunk.Count) { throw 'PILOT_CONTAINER_INVENTORY_INVALID' }
    }
    # Validate all chunks before yielding any results; preserve caller order.
    if ($Observed.Count -ne $Ids.Count) { throw 'PILOT_CONTAINER_INVENTORY_INVALID' }
    foreach ($Id in $Ids) { $Observed[$Id] }
}
function Private-Process {
    param([string[]]$Arguments, [string]$InputText, [string]$Executable = '',
          [switch]$DiagnosticDockerClone,
          [ValidateRange(120000,1800000)][int]$WaitTimeoutMs = 120000)
    foreach ($Argument in $Arguments) {
        if ($Argument.Contains('"') -or $Argument.EndsWith('\')) { throw 'PILOT_NATIVE_ARGUMENT_DENIED' }
    }
    if (-not $Executable) { $Executable = (Get-Command docker.exe -CommandType Application).Source }
    $Info = [Diagnostics.ProcessStartInfo]::new()
    $Info.FileName=$Executable
    $Info.Arguments=(@($Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' ')
    $Info.UseShellExecute=$false; $Info.CreateNoWindow=$true
    $Info.RedirectStandardInput=$true; $Info.RedirectStandardOutput=$true; $Info.RedirectStandardError=$true
    $Process=[Diagnostics.Process]::new(); $Process.StartInfo=$Info
    $Started=$false
    try {
        if (-not $Process.Start()) { throw 'PILOT_PRIVATE_PROCESS_START_FAILED' }
        $Started=$true
        $OutputTask=$Process.StandardOutput.ReadToEndAsync()
        $ErrorTask=$Process.StandardError.ReadToEndAsync()
        # Docker may exit early or stop reading stdin. A synchronous Write can
        # block before WaitForExit's timeout is reached. Bound that phase too.
        $StdinFailed=$false
        try {
            $WriteTask=$Process.StandardInput.WriteAsync($InputText)
            if (-not $WriteTask.Wait(30000)) {
                throw 'PILOT_PRIVATE_STDIN_TIMEOUT'
            }
        } catch {
            if ($_.Exception.Message -ceq 'PILOT_PRIVATE_STDIN_TIMEOUT') { throw }
            # Keep stderr and exit code private until the standard classifier
            # below; Docker 125 must not surface an unredacted IOException.
            $StdinFailed=$true
        }
        try { $Process.StandardInput.Close() }
        catch {
            if (-not $Process.HasExited) { throw 'PILOT_PRIVATE_STDIN_CLOSE_FAILED' }
        }
        # Default remains 120s. Only the trusted owner release controller
        # supplies a longer finite bound for large state receipt/clone helpers.
        if (-not $Process.WaitForExit($WaitTimeoutMs)) { $Process.Kill(); throw 'PILOT_PRIVATE_PROCESS_TIMEOUT' }
        if (-not $OutputTask.Wait(15000) -or -not $ErrorTask.Wait(15000)) {
            throw 'PILOT_PRIVATE_OUTPUT_PIPE_TIMEOUT'
        }
        $Output=$OutputTask.Result; $Diagnostic=$ErrorTask.Result
        if ($Process.ExitCode -ne 0) {
            # Only the credential-free state-clone call may expose a bounded,
            # redacted Docker CLI error. All other callers keep stderr private.
            if ($Process.ExitCode -eq 125 -and $DiagnosticDockerClone) {
                $Lines=@($Diagnostic -split '\r?\n' | Where-Object {
                    $_ -match '^(?:docker:\s*)?(?:Error response from daemon:|error during connect:|invalid argument|unknown flag|failed to|Unable to find image)'
                })
                $Detail='DOCKER_CLI_ERROR_UNCLASSIFIED'
                if ($Lines.Count) {
                    $Detail=$Lines[0].Trim()
                    $Detail=[regex]::Replace($Detail,'(?i)(gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|Bearer\s+\S+|https?://\S+)','[REDACTED]')
                    if($Detail.Length -gt 400){$Detail=$Detail.Substring(0,400)}
                }
                throw ('PILOT_DOCKER_CLONE_FAILED_125: ' + $Detail)
            }
            $Codes=@([regex]::Matches($Diagnostic,'(?:RuntimeError|ValueError|Denied): ([A-Z][A-Z0-9_]+)') |
                ForEach-Object { $_.Groups[1].Value })
            if ($Diagnostic -match '"error"\s*:\s*"([A-Z][A-Z0-9_]+)"') { $Codes += $Matches[1] }
            throw ('PILOT_PRIVATE_PROCESS_FAILED:' + $Process.ExitCode + ':' + ($Codes -join ','))
        }
        if ($StdinFailed) { throw 'PILOT_PRIVATE_STDIN_WRITE_FAILED' }
        return $Output.Trim()
    } finally {
        if ($Started) {
            try {
                if (-not $Process.HasExited) { $Process.Kill() }
            } catch {}
        }
        $Process.Dispose()
    }
}
function Code64 {
    param([string]$Text)
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text))
}
function Helper {
    param($Payload, [string[]]$Mounts=@(), [switch]$Root, [switch]$InsidePilot, [string]$Image='')
    $Code="import base64;ns={'__name__':'operator_helper'};exec(compile(base64.b64decode('$script:Helper64'),'<pilot-helper>','exec'),ns);ns['main']()"
    if ($InsidePilot) {
        $Arguments=@('exec','-i','--user','10001:10001',$script:R.pilotId,'python','-B','-c',$Code)
    } else {
        $Identity='10001:10001'
        if ($Root) { $Identity='0:0' }
        $Arguments=@('run','--rm','-i','--pull=never','--network','none','--read-only','--user',$Identity,
            '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64',
            '--memory','256m','--tmpfs','/tmp:rw,nosuid,nodev,size=64m')
        if ($Root) { $Arguments += @('--cap-add','CHOWN','--cap-add','DAC_OVERRIDE') }
        if (-not $Image) { $Image=$script:R.image }
        $Arguments += $Mounts + @('--entrypoint','python',$Image,'-B','-c',$Code)
    }
    return ((Private-Process $Arguments (ConvertTo-Json -InputObject $Payload -Depth 25 -Compress)) | ConvertFrom-Json)
}
function Public-Inspect {
    param($C)
    # NetworkMode alone does not reveal a later docker network connect.
    # Send only endpoint name and immutable network ID into the trusted Guard.
    $Endpoints=[ordered]@{}
    if($C.NetworkSettings -and $C.NetworkSettings.Networks){
        foreach($Endpoint in $C.NetworkSettings.Networks.PSObject.Properties){
            if($Endpoint.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty){
                throw 'PILOT_NETWORK_INSPECT_INVALID'
            }
            $Endpoints[$Endpoint.Name]=[ordered]@{NetworkID=[string]$Endpoint.Value.NetworkID}
        }
    }
    return [ordered]@{ Id=$C.Id; Name=$C.Name; Image=$C.Image; Mounts=$C.Mounts
        NetworkSettings=[ordered]@{Networks=$Endpoints}
        State=[ordered]@{ Status=$C.State.Status; Health=[ordered]@{ Status=$C.State.Health.Status } }
        Config=[ordered]@{ User=$C.Config.User; WorkingDir=$C.Config.WorkingDir; Healthcheck=$C.Config.Healthcheck
            Cmd=$C.Config.Cmd; Entrypoint=$C.Config.Entrypoint
            Env=@($C.Config.Env | Where-Object { $_.StartsWith('FORTIS_') }) }
        HostConfig=($C.HostConfig | Select-Object ReadonlyRootfs,Privileged,AutoRemove,Init,
            CapDrop,CapAdd,SecurityOpt,NetworkMode,PidsLimit,Memory,MemorySwap,ShmSize,Tmpfs,RestartPolicy,PortBindings,
            Binds,VolumesFrom,Devices,DeviceRequests,PidMode,UsernsMode,IpcMode) }
}
function Expected-Review {
    param([string]$Status)
    return [ordered]@{ id=$script:R.reviewId; name=$ReviewName; image=$ReviewImage
        stateVolume='fortis-r7-state-review-20261105'; status=$Status }
}
function Expected-Pilot {
    param([string]$Status)
    return [ordered]@{ id=$script:R.pilotId; name=$script:R.pilotName; image=$script:R.image
        stateVolume=$script:R.stateVolume; tokenVolume=$script:R.tokenVolume; status=$Status
        owner=$script:R.owner; repository=$script:R.repository; filePrBranch=$script:R.filePrBranch; ciReads=$script:R.ciReads
        nativeWorktree=$script:R.nativeWorktree; requiredWorkflows=$script:R.requiredWorkflows; bootstrapTask=$script:R.bootstrapTask }
}
function Admit-Review {
    param([string]$Status)
    $null=Helper @{ action='admit'; container=(Public-Inspect (Container $script:R.reviewId))
        expected=(Expected-Review $Status); pilot=$false }
}
function Admit-Pilot {
    param([string]$Status)
    $null=Helper @{ action='admit'; container=(Public-Inspect (Container $script:R.pilotId))
        expected=(Expected-Pilot $Status); pilot=$true }
}
function Production-Baseline {
    $C=Container 'fortis-approvals-gateway'
    if ($C.Image -cne $ProductionImage -or $C.State.Status -cne 'running' -or
        $C.State.Health.Status -cne 'healthy') { throw 'PILOT_PRODUCTION_BASELINE_CHANGED' }
    return (ConvertTo-Json -InputObject ([ordered]@{ id=$C.Id; image=$C.Image
        startedAt=$C.State.StartedAt; mounts=$C.Mounts; ports=$C.HostConfig.PortBindings }) -Depth 12 -Compress)
}
function Assert-Production {
    if ((Production-Baseline) -cne $script:R.productionBaseline) { throw 'PILOT_PRODUCTION_CHANGED' }
}
function Assert-Volume {
    param([string]$Name)
    $V=@(Docker-Json @('volume','inspect',$Name))[0]
    if ($V.Name -cne $Name -or $V.Driver -cne 'local' -or $V.Scope -cne 'local' -or
        $V.Mountpoint -cne ('/var/lib/docker/volumes/' + $Name + '/_data')) { throw 'PILOT_VOLUME_IDENTITY_INVALID' }
    if ($null -ne $V.Options -and @($V.Options.PSObject.Properties).Count -ne 0) {
        throw 'PILOT_VOLUME_DRIVER_OPTIONS_UNKNOWN'
    }
}
function Assert-OnlyWriter {
    param([string]$Volume, [string]$AllowedId='')
    $Root='/var/lib/docker/volumes/' + $Volume + '/_data'
    $Ids=@((Docker-Text @('ps','-aq','--no-trunc')) -split '\r?\n' | Where-Object { $_ })
    foreach ($C in @(Inspect-Containers $Ids)) {
        if ($C.State.Status -cin @('created','exited','dead')) { continue }
        foreach ($M in @($C.Mounts)) {
            $Alias=($M.Name -ceq $Volume -or $M.Source -ceq $Root)
            if ($M.Source) {
                $Alias=$Alias -or $M.Source.StartsWith($Root + '/',[StringComparison]::Ordinal) -or
                    $Root.StartsWith($M.Source.TrimEnd('/') + '/',[StringComparison]::Ordinal)
            }
            if ($Alias -and $M.RW -and $C.Id -cne $AllowedId) { throw 'PILOT_UNEXPECTED_STATE_WRITER' }
        }
    }
}
function Assert-ContainerInventorySelfTest {
    # No Docker or owner state: exercise the real batch parser and writer guard.
    $FixtureIds=@(1..129 | ForEach-Object { '{0:x64}' -f $_ })
    $FixtureList=$FixtureIds
    $FixtureMode='valid'
    $FixtureCalls=[Collections.Generic.List[int]]::new()
    $FixtureRows=@{}
    foreach ($FixtureId in $FixtureIds) {
        $FixtureRows[$FixtureId]=@{Id=$FixtureId;State=@{Status='exited'};Mounts=@()}
    }
    function Docker-Text {
        param([string[]]$Arguments)
        if (($Arguments -join ' ') -ceq 'ps -aq --no-trunc') { return ($FixtureList -join "`n") }
        if ($Arguments.Count -lt 4 -or ($Arguments[0..2] -join ' ') -cne 'inspect --type container') {
            throw 'INVENTORY_SELFTEST_UNEXPECTED_COMMAND'
        }
        $FixtureCalls.Add($Arguments.Count-3)
        if ($FixtureMode -ceq 'native-failure') { throw 'PILOT_DOCKER_COMMAND_FAILED' }
        $Response=@(for ($I=$Arguments.Count-1; $I -ge 3; $I--) { $FixtureRows[$Arguments[$I]] })
        switch ($FixtureMode) {
            'missing' { $Response=@($Response[0]) }
            'duplicate' { $Response=@($Response[0],$Response[0]) }
            'unexpected' { $Response=@($Response[0],$FixtureRows[$FixtureIds[2]]) }
        }
        ConvertTo-Json -InputObject $Response -Depth 8 -Compress
    }
    $Actual=@(Inspect-Containers $FixtureIds)
    if ($Actual.Count -ne 129 -or ($Actual.Id -join ',') -cne ($FixtureIds -join ',') -or
        ($FixtureCalls -join ',') -cne '128,1') { throw 'INVENTORY_SELFTEST_BATCH_FAILED' }
    $FixtureCalls.Clear()
    if (@(Inspect-Containers @()).Count -ne 0 -or $FixtureCalls.Count -ne 0) {
        throw 'INVENTORY_SELFTEST_EMPTY_FAILED'
    }
    $Pair=@($FixtureIds[0],$FixtureIds[1])
    foreach ($FixtureMode in @('missing','duplicate','unexpected','native-failure')) {
        $ExpectedError='PILOT_CONTAINER_INVENTORY_INVALID'
        if ($FixtureMode -ceq 'native-failure') { $ExpectedError='PILOT_DOCKER_COMMAND_FAILED' }
        try {
            $null=Inspect-Containers $Pair
            throw 'INVENTORY_SELFTEST_ACCEPTED_INVALID_RESPONSE'
        } catch { if ($_.Exception.Message -cne $ExpectedError) { throw } }
    }
    $FixtureMode='valid'
    try {
        $null=Inspect-Containers @($Pair[0],$Pair[0])
        throw 'INVENTORY_SELFTEST_ACCEPTED_DUPLICATE_INPUT'
    } catch { if ($_.Exception.Message -cne 'PILOT_CONTAINER_INVENTORY_INVALID') { throw } }
    $FixtureList=$Pair
    $FixtureRows[$Pair[0]].State.Status='running'
    $FixtureRows[$Pair[0]].Mounts=@(@{Name='fixture-state';Source='/var/lib/docker/volumes/fixture-state/_data';RW=$true})
    Assert-OnlyWriter 'fixture-state' $Pair[0]
    try {
        Assert-OnlyWriter 'fixture-state'
        throw 'INVENTORY_SELFTEST_ACCEPTED_WRITER'
    } catch { if ($_.Exception.Message -cne 'PILOT_UNEXPECTED_STATE_WRITER') { throw } }
    $FixtureRows[$Pair[0]].Mounts[0].Name=''
    $FixtureRows[$Pair[0]].Mounts[0].Source='/var/lib/docker/volumes'
    $FixtureRows[$Pair[0]].State.Status='paused'
    try {
        Assert-OnlyWriter 'fixture-state'
        throw 'INVENTORY_SELFTEST_ACCEPTED_ALIAS_WRITER'
    } catch { if ($_.Exception.Message -cne 'PILOT_UNEXPECTED_STATE_WRITER') { throw } }
    $FixtureRows[$Pair[0]].Mounts[0].RW=$false
    Assert-OnlyWriter 'fixture-state'
    $FixtureRows[$Pair[0]].Mounts[0].RW=$true
    $FixtureRows[$Pair[0]].State.Status='exited'
    Assert-OnlyWriter 'fixture-state'
    Write-Host 'FORTIS_CONTAINER_INVENTORY_SELFTEST_PASS'
}
function Wait-Healthy {
    param([string]$Id)
    $Deadline=[DateTime]::UtcNow.AddSeconds(100)
    do {
        $C=Container $Id
        if ($C.State.Status -cne 'running' -or $C.State.Health.Status -ceq 'unhealthy') { throw 'PILOT_GATEWAY_NOT_HEALTHY' }
        if ($C.State.Health.Status -ceq 'healthy') { return }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $Deadline)
    throw 'PILOT_HEALTH_TIMEOUT'
}
function Protect-Directory {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) { throw 'PILOT_RECORD_DIRECTORY_EXISTS' }
    $null=[IO.Directory]::CreateDirectory($Path)
    $OwnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $Acl=[Security.AccessControl.DirectorySecurity]::new()
    $Acl.SetAccessRuleProtection($true,$false); $Acl.SetOwner($OwnerSid)
    $Inheritance=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($Value in @($OwnerSid.Value,'S-1-5-18','S-1-5-32-544')) {
        $Sid=[Security.Principal.SecurityIdentifier]::new($Value)
        $Acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($Sid,
            [Security.AccessControl.FileSystemRights]::FullControl,$Inheritance,
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $Acl
}
function Assert-RecordAcl {
    $Allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    foreach ($Path in @((Split-Path $script:RecordPath -Parent),$script:RecordPath)) {
        $Acl=Get-Acl -LiteralPath $Path
        if ($Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $Allowed[0]) { throw 'PILOT_RECORD_OWNER_INVALID' }
        foreach ($Rule in $Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($Rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $Allowed -cnotcontains $Rule.IdentityReference.Value) { throw 'PILOT_RECORD_ACL_INVALID' }
        }
    }
    if (-not (Get-Acl -LiteralPath (Split-Path $script:RecordPath -Parent)).AreAccessRulesProtected) {
        throw 'PILOT_RECORD_INHERITANCE_UNPROTECTED'
    }
}
function Save-Record {
    param([string]$SerializedJson='')
    $JsonText=$SerializedJson
    if(-not $JsonText){$JsonText=ConvertTo-Json -InputObject $script:R -Depth 25}
    $Temporary=$script:RecordPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    [IO.File]::WriteAllText($Temporary,$JsonText,[Text.UTF8Encoding]::new($false))
    # Elevated Windows processes may otherwise assign Administrators as the file owner.
    $Acl=Get-Acl -LiteralPath $Temporary
    $Acl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User)
    Set-Acl -LiteralPath $Temporary -AclObject $Acl
    if (Test-Path -LiteralPath $script:RecordPath) { [IO.File]::Replace($Temporary,$script:RecordPath,[System.Management.Automation.Language.NullString]::Value) }
    else { [IO.File]::Move($Temporary,$script:RecordPath) }
    Assert-RecordAcl
}
function Assert-PreparedResume {
    # Only a failed build before credential/state/container creation can resume setup.
    if ($script:R.phase -cne 'Prepared' -or $script:R.reviewStopped -or $script:R.image -or
        $script:R.pilotId -or $script:R.sourceReceipt -or $script:R.receipt -or
        $script:R.scenario.phase -cne 'READ' -or $script:R.scenario.sourceSha) {
        throw 'PILOT_PREPARED_RESUME_HAS_SETUP_EFFECTS'
    }
    if ($script:R.sourceCommit -cne $ExpectedSourceCommit -and
        ($ResumePreparedSourceCommit -cnotmatch '^[0-9a-f]{40}$' -or
         $script:R.sourceCommit -cne $ResumePreparedSourceCommit)) {
        throw 'PILOT_PREPARED_SOURCE_CHANGE_REQUIRES_EXACT_ACK'
    }
}
function Assert-PreparedResourcesAbsent {
    $Volumes=@((Docker-Text @('volume','ls','--format','{{.Name}}')) -split '\r?\n')
    $Names=@((Docker-Text @('ps','-a','--format','{{.Names}}')) -split '\r?\n')
    if ($Volumes -ccontains $script:R.stateVolume -or $Volumes -ccontains $script:R.tokenVolume -or
        $Names -ccontains $script:R.pilotName) { throw 'PILOT_PREPARED_RESOURCES_EXIST_INSPECT_BEFORE_CONTINUING' }
}
function Check-Package {
    $Metadata=Get-Content -LiteralPath (Join-Path $SourceRoot 'review-source.json') -Raw | ConvertFrom-Json
    if ($ExpectedSourceCommit -cnotmatch '^[0-9a-f]{40}$' -or $Metadata.baseCommit -cne $ExpectedSourceCommit) {
        throw 'PILOT_APPROVED_SOURCE_COMMIT_REQUIRED'
    }
    foreach ($Property in $Metadata.files.PSObject.Properties) {
        $Path=[IO.Path]::GetFullPath((Join-Path $SourceRoot $Property.Name))
        if (-not $Path.StartsWith($SourceRoot.TrimEnd('\') + '\',[StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $Path -PathType Leaf) -or
            (Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'PILOT_PACKAGE_PATH_INVALID' }
        if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Property.Value) {
            throw 'PILOT_PACKAGE_HASH_MISMATCH'
        }
    }
    $script:Snapshot=$Metadata.sourceTreeSha256
    if ($script:Snapshot -cnotmatch '^[0-9a-f]{64}$') { throw 'PILOT_PACKAGE_SNAPSHOT_INVALID' }
    $Actual=(Get-FileHash -LiteralPath (Join-Path $SourceRoot 'docs\MODULARIZED-SOURCE-MANIFEST.sha256') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -cne $script:Snapshot) { throw 'PILOT_PACKAGE_MANIFEST_MISMATCH' }
}

function Check-RepoSource {
    $Code="import json,pathlib,subprocess;root=pathlib.Path('/workspace/repo/Repos/fortis-approvals');head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip();dirty=subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True);print(json.dumps({'head':head,'clean':not bool(dirty.strip())}))"
    $Raw=Private-Process @('exec','--user','1000:1000','fortis-repo-test','python3','-B','-c',$Code) ''
    $Info=$Raw | ConvertFrom-Json
    if ($Info.head -cne $ExpectedSourceCommit -or -not $Info.clean) { throw 'PILOT_REPO_SOURCE_NOT_APPROVED_CLEAN_MAIN' }
}
function Run-Scenario {
    Admit-Pilot 'running'; Admit-Review 'exited'; Assert-Production; Check-RepoSource
    Assert-OnlyWriter $script:R.stateVolume $script:R.pilotId
    $Deadline=[DateTime]::UtcNow.AddMinutes(15)
    $LastPrompt=''
    while ($script:R.scenario.phase -cne 'DONE') {
        $InputJson=ConvertTo-Json -InputObject $script:R.scenario -Depth 15 -Compress
        $Arguments=@('exec','-i','--user','1000:1000','--workdir','/workspace/repo/Repos/fortis-approvals',
            'fortis-repo-test','python3','-B','-m','fortis_approvals.integrations.github.repo_client.pilot_scenario')
        $Step=(Private-Process $Arguments $InputJson) | ConvertFrom-Json
        $Before=ConvertTo-Json -InputObject $script:R.scenario -Depth 15 -Compress
        $After=ConvertTo-Json -InputObject $Step.state -Depth 15 -Compress
        $script:R.scenario=$Step.state
        if ($Before -cne $After) { Save-Record }
        if ($Step.awaitOwner) {
            $Prompt=$Step.awaitOwner.decision + ':' + $Step.awaitOwner.requestId
            if ($Prompt -cne $LastPrompt) {
                Write-Host ('PILOT_OWNER_ACTION=' + $Step.awaitOwner.decision.ToUpperInvariant())
                Write-Host ('REQUEST_ID=' + $Step.awaitOwner.requestId)
                Write-Host ('BRANCH=' + $Step.awaitOwner.branch)
                Write-Host 'OWNER_PORTAL=http://localhost:19203'
                Write-Host 'Use the existing device; do not enroll another credential.'
                $LastPrompt=$Prompt
            }
            if ([DateTime]::UtcNow -gt $Deadline) { throw 'PILOT_OWNER_WAIT_TIMEOUT_RESUME_SAME_RECORD' }
            Start-Sleep -Seconds 3
        }
    }
    $Case=$script:R.scenario.approve
    $Receipt=Helper @{ action='receipt'; expected=@{ request_id=$Case.requestId
        repository=$script:R.repository; branch=$Case.branch; sha=$script:R.scenario.sourceSha } } -InsidePilot
    $Code="import json;from fortis_approvals.clients.gateway_transport import GatewayTransport;g=GatewayTransport(endpoint='https://host.docker.internal:19204',allow_test_endpoint=True);import uuid;r=g.post('/v1/reads',{'requestId':str(uuid.uuid4()),'service':'sonarcloud','operation':'get_quality_gate','target':'AlexPastukhh_obs-planning-docs','params':{},'reason':'GitHub pilot Sonar regression'});print(json.dumps({'sonarReadStatus':r['data']['status']}))"
    $Sonar=(Private-Process @('exec','--user','1000:1000','--workdir','/workspace/repo/Repos/fortis-approvals',
        'fortis-repo-test','python3','-B','-c',$Code) '') | ConvertFrom-Json
    Assert-Production
    $script:R.receipt=$Receipt; $script:R.phase='Complete'; Save-Record
    [ordered]@{ sourceCommit=$script:R.sourceCommit; image=$script:R.image
        runId=$script:R.scenario.runId; rejectRequestId=$script:R.scenario.reject.requestId
        approveRequestId=$Case.requestId; branch=$Case.branch; sha=$script:R.scenario.sourceSha
        receiptVerified=$Receipt.receiptVerified; sonarReadStatus=$Sonar.sonarReadStatus
        productionBaselineUnchanged=$true; record=$script:RecordPath } | ConvertTo-Json -Depth 6
    Write-Host 'FORTIS_GITHUB_PILOT_LIVE_E2E_PASS'
}
function Return-Review {
    if ($script:R.phase -ceq 'ReturnedReview') { Admit-Review 'running'; return }
    if (-not $script:R.reviewStopped -and -not $script:R.pilotId -and -not $script:R.image) {
        $Original=Container $script:R.reviewId
        if ($Original.Name -cne ('/' + $ReviewName) -or $Original.Image -cne $ReviewImage -or
            $Original.State.Status -cne 'running' -or $Original.State.Health.Status -cne 'healthy') {
            throw 'PILOT_PRE_SETUP_REVIEW_IDENTITY_CHANGED'
        }
        $script:R.phase='ReturnedReview'; Save-Record
        Write-Host 'PILOT_REVIEW_WAS_NEVER_STOPPED'
        return
    }
    if ($script:R.pilotId) {
        $C=Container $script:R.pilotId
        $Status=$C.State.Status
        if ($Status -cnotin @('created','exited','running')) { throw 'PILOT_ROLLBACK_CONTAINER_STATE_UNKNOWN' }
        # Admission checks configuration; an unhealthy pilot may be safely stopped.
        if ($Status -ceq 'running') {
            $Expected=Expected-Pilot 'running'
            $Expected.requireHealthy=$false
            $null=Helper @{ action='admit'; container=(Public-Inspect $C)
                expected=$Expected; pilot=$true }
            $null=Docker-Text @('stop','--timeout','20',$script:R.pilotId)
        } else { Admit-Pilot $Status }
        if ((Container $script:R.pilotId).State.Status -cnotin @('created','exited')) { throw 'PILOT_ROLLBACK_STOP_NOT_CONFIRMED' }
    }
    Assert-OnlyWriter 'fortis-r7-state-review-20261105' $script:R.reviewId
    $Original=Container $script:R.reviewId
    if ($Original.State.Status -ceq 'running') {
        if ($script:R.reviewStopped) { throw 'PILOT_REVIEW_RESTARTED_OUTSIDE_RUN_INSPECT_BEFORE_CONTINUING' }
        Admit-Review 'running'
    } else {
        Admit-Review 'exited'
        if ($script:R.sourceReceipt) {
            $Current=Helper @{ action='inspect' } -Mounts @('--mount',
                'type=volume,source=fortis-r7-state-review-20261105,target=/source,readonly')
            if ((ConvertTo-Json -InputObject $Current -Depth 10 -Compress) -cne
                (ConvertTo-Json -InputObject $script:R.sourceReceipt -Depth 10 -Compress)) {
                throw 'PILOT_ORIGINAL_REVIEW_DATA_CHANGED_NO_RESTART'
            }
        }
        $null=Docker-Text @('start',$script:R.reviewId)
        Wait-Healthy $script:R.reviewId; Admit-Review 'running'
    }
    $script:R.phase='ReturnedReview'; Save-Record
    Write-Host 'FORTIS_GITHUB_PILOT_RETURNED_TO_RETAINED_REVIEW_PASS'
}

function Build-PilotImage {
    $Tag='fortis-approvals-gateway:github-pilot-' + $script:Snapshot.Substring(0,12)
    Write-Host 'PILOT_STAGE=BUILD_AND_OFFLINE_IMAGE_SMOKE'
    $null=Docker-Text @('build','--pull=false','--file',(Join-Path $PSScriptRoot 'Dockerfile-Gateway-Modularized-Candidate'),
        '--label',('org.opencontainers.image.revision=' + $ExpectedSourceCommit),
        '--label',('org.opencontainers.image.source-snapshot-sha256=' + $script:Snapshot),
        '--tag',$Tag,$SourceRoot)
    $Image=@(Docker-Json @('image','inspect',$Tag))[0]
    if ($Image.Id -cnotmatch '^sha256:[0-9a-f]{64}$' -or $Image.Config.User -cne '10001:10001' -or
        $Image.Config.Labels.'org.opencontainers.image.source-snapshot-sha256' -cne $script:Snapshot) { throw 'PILOT_IMAGE_METADATA_INVALID' }
    $script:R.image=$Image.Id; Save-Record
    $Smoke64=Code64 (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'image_offline_smoke.py') -Raw)
    $SmokeCode="import base64;ns={'__name__':'offline_smoke'};exec(compile(base64.b64decode('$Smoke64'),'<image-smoke>','exec'),ns);ns['smoke']()"
    $Smoke=Private-Process @('run','--rm','-i','--pull=never','--network','none','--read-only','--user','10001:10001',
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','256m',
        '--tmpfs','/tmp:rw,nosuid,nodev,size=64m','--entrypoint','python',$script:R.image,'-B','-c',$SmokeCode) ''
    if ($script:R.nativeWorktree -and $Smoke -notmatch 'IMAGE_NATIVE_GIT_IMPORT_PASS') {throw 'PILOT_NATIVE_IMAGE_SMOKE_FAILED'}
    if ($Smoke -notmatch 'IMAGE_SONAR_OFFLINE_SMOKE_PASS' -or $Smoke -notmatch 'IMAGE_GITHUB_NOT_REGISTERED_PASS') {
        throw 'PILOT_OFFLINE_IMAGE_SMOKE_FAILED'
    }
}
function Create-PilotVolume {
    param([string]$Name, [string]$Role)
    $Names=@((Docker-Text @('volume','ls','--format','{{.Name}}')) -split '\r?\n')
    if ($Names -ccontains $Name) { throw 'PILOT_NEW_VOLUME_NAME_ALREADY_EXISTS' }
    $null=Docker-Text @('volume','create','--label',('io.fortis.pilot.run=' + $script:R.runId),
        '--label',('io.fortis.pilot.role=' + $Role),$Name)
    Assert-Volume $Name
    $V=@(Docker-Json @('volume','inspect',$Name))[0]
    if ($V.Labels.'io.fortis.pilot.run' -cne $script:R.runId -or $V.Labels.'io.fortis.pilot.role' -cne $Role) {
        throw 'PILOT_NEW_VOLUME_PROVENANCE_INVALID'
    }
}

function Create-PilotContainer {
    $Arguments=@('create','--pull=never','--name',$script:R.pilotName,'--restart','no','--init',
        '--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','100','--memory','512m','--memory-swap','1g','--network','bridge',
        '--tmpfs','/tmp:rw,nosuid,nodev,size=16m',
        '--env','FORTIS_OWNER_ORIGIN=http://localhost:19203','--env','FORTIS_MACHINE_HOST=host.docker.internal:19204',
        '--env','FORTIS_SONAR_REGION=eu','--env','FORTIS_SONAR_ORGANIZATIONS=alexpastukhh',
        '--env','FORTIS_SONAR_PROJECT_KEY=AlexPastukhh_obs-planning-docs',
        '--env','FORTIS_GITHUB_PILOT=1','--env',('FORTIS_GITHUB_OWNER=' + $script:R.owner),
        '--env',('FORTIS_GITHUB_REPOSITORY=' + $script:R.repository),'--env','FORTIS_GITHUB_BRANCH_PREFIX=fortis-e2e/',
        '--publish','127.0.0.1:19203:19103','--publish','127.0.0.1:19204:19104',
        '--mount',('type=volume,source=' + $script:R.stateVolume + ',target=/state'),
        '--mount',('type=volume,source=' + $script:R.tokenVolume + ',target=/run/github-token,readonly'),
        '--mount','type=volume,source=fortis-r7-identity,target=/run/r7-identity,readonly',
        '--mount','type=volume,source=fortis-r7-grant,target=/run/r7-grant,readonly',
        '--mount','type=volume,source=fortis-r7-sonar-token,target=/run/r7-sonar-token,readonly',
        '--health-cmd','python -m fortis_approvals.r7_unified_server health',
        '--health-interval','20s','--health-timeout','5s','--health-retries','3','--health-start-period','20s',
        $script:R.image)
    if ($script:R.filePrBranch) {
        $Arguments=$Arguments[0..($Arguments.Count-2)] + @('--env',('FORTIS_GITHUB_FILE_PR_BRANCH=' + $script:R.filePrBranch),$script:R.image)
    }
    if ($script:R.ciReads) {
        $Arguments=$Arguments[0..($Arguments.Count-2)] + @('--env','FORTIS_GITHUB_CI_READS=1',$script:R.image)
    }
    if ($script:R.nativeWorktree) {
        $Arguments=$Arguments[0..($Arguments.Count-2)] + @('--env','FORTIS_GITHUB_NATIVE_WORKTREE=1',
            '--env',('FORTIS_GITHUB_REQUIRED_WORKFLOWS=' + $script:R.requiredWorkflows),
            '--env',('FORTIS_GITHUB_BOOTSTRAP_TASK=' + $script:R.bootstrapTask),$script:R.image)
    }
    $script:R.pilotId=Docker-Text $Arguments
    if ($script:R.pilotId -cnotmatch '^[0-9a-f]{64}$') { throw 'PILOT_CREATED_ID_INVALID_INSPECT_BEFORE_RETRY' }
    $script:R.phase='Created'; Save-Record
    Admit-Pilot 'created'; Assert-Production
    Assert-OnlyWriter $script:R.stateVolume
    $null=Docker-Text @('start',$script:R.pilotId)
    Wait-Healthy $script:R.pilotId; Admit-Pilot 'running'
    Assert-Production
}

if ($Mode -ceq 'Functions') { return }

if ($Mode -ceq 'SelfTest') {
    # Exercise real NTFS writes/atomic replacements and ACLs in Windows PowerShell 5.1.
    $TestDirectory=Join-Path $env:TEMP ('fortis-pilot-record-selftest-' + [Guid]::NewGuid().ToString('N'))
    Protect-Directory $TestDirectory
    $script:RecordPath=Join-Path $TestDirectory 'record.json'
    $script:R=[ordered]@{ schema=1; runId='11111111111141118111111111111111'; sourceCommit=('a' * 40)
        phase='Prepared'; reviewStopped=$false; image=''; pilotId=''; sourceReceipt=$null; receipt=$null
        scenario=@{ phase='READ'; sourceSha=$null; reject=@{requestId='11111111-1111-4111-8111-111111111111'}
            approve=@{requestId='22222222-2222-4222-8222-222222222222'} } }
    try {
        Save-Record
        $OriginalIds=ConvertTo-Json $script:R.scenario -Depth 5 -Compress
        $script:R.image='sha256:test'; Save-Record
        $script:R.image=''; Save-Record
        $Saved=Get-Content -LiteralPath $script:RecordPath -Raw | ConvertFrom-Json
        if ($Saved.image -cne '' -or (ConvertTo-Json $Saved.scenario -Depth 5 -Compress) -cne $OriginalIds -or
            @(Get-ChildItem -LiteralPath $TestDirectory -Force).Count -ne 1) { throw 'PILOT_RECORD_REPLACEMENT_SELFTEST_FAILED' }
        Assert-RecordAcl
        $script:R=$Saved
        $ExpectedSourceCommit='a' * 40; Assert-PreparedResume
        $ExpectedSourceCommit='b' * 40
        function Test-PreparedCheckoutSource {
            # Execute the real check while the saved record still has the old source SHA.
            function Private-Process {
                param([string[]]$Arguments, [string]$InputText, [string]$Executable = '')
                if ($Arguments[0] -cne 'exec' -or $Arguments[3] -cne 'fortis-repo-test') {
                    throw 'SELFTEST_SOURCE_PROBE_TARGET_INVALID'
                }
                return (ConvertTo-Json $script:CheckoutFixture -Compress)
            }
            $script:CheckoutFixture=@{head=('b' * 40);clean=$true}
            Check-RepoSource
            foreach ($Fixture in @(@{head=('a' * 40);clean=$true},@{head=('b' * 40);clean=$false})) {
                $script:CheckoutFixture=$Fixture; $Blocked=$false
                try { Check-RepoSource } catch {
                    if ($_.Exception.Message -ceq 'PILOT_REPO_SOURCE_NOT_APPROVED_CLEAN_MAIN') { $Blocked=$true } else { throw }
                }
                if (-not $Blocked) { throw 'PILOT_PREPARED_CHECKOUT_SOURCE_SELFTEST_FAILED' }
            }
        }
        Test-PreparedCheckoutSource
        $Blocked=$false
        try { Assert-PreparedResume } catch {
            if ($_.Exception.Message -ceq 'PILOT_PREPARED_SOURCE_CHANGE_REQUIRES_EXACT_ACK') { $Blocked=$true } else { throw }
        }
        if (-not $Blocked) { throw 'PILOT_PREPARED_SOURCE_ACK_SELFTEST_FAILED' }
        $ResumePreparedSourceCommit='a' * 40; Assert-PreparedResume
        $script:R.image='sha256:already-saved'; $Blocked=$false
        try { Assert-PreparedResume } catch {
            if ($_.Exception.Message -ceq 'PILOT_PREPARED_RESUME_HAS_SETUP_EFFECTS') { $Blocked=$true } else { throw }
        }
        if (-not $Blocked) { throw 'PILOT_PREPARED_EFFECTS_SELFTEST_FAILED' }
        $script:R.image=''; $script:R.scenario.phase='SUBMIT_REJECT'; $Blocked=$false
        try { Assert-PreparedResume } catch {
            if ($_.Exception.Message -ceq 'PILOT_PREPARED_RESUME_HAS_SETUP_EFFECTS') { $Blocked=$true } else { throw }
        }
        if (-not $Blocked) { throw 'PILOT_PREPARED_SCENARIO_SELFTEST_FAILED' }
    } finally {
        Remove-Item -LiteralPath $TestDirectory -Recurse -Force
    }
    $Fixture='synthetic private stdin {"value":"safe"}'
    $Result=Private-Process @('-NoProfile','-Command','[Console]::Write([Console]::In.ReadToEnd())') $Fixture (Join-Path $PSHOME 'powershell.exe')
    if ($Result -cne $Fixture) { throw 'PILOT_PRIVATE_PIPE_SELFTEST_FAILED' }
    $BoundedResult=Private-Process @('-NoProfile','-Command','[Console]::Write([Console]::In.ReadToEnd())') $Fixture (Join-Path $PSHOME 'powershell.exe') -WaitTimeoutMs 900000
    if ($BoundedResult -cne $Fixture) { throw 'PILOT_PRIVATE_BOUNDED_WAIT_SELFTEST_FAILED' }
    $Denied=$false
    try { $null=Private-Process @('forbidden"argument') '' 'must-not-start' }
    catch { if ($_.Exception.Message -ceq 'PILOT_NATIVE_ARGUMENT_DENIED') { $Denied=$true } else { throw } }
    if (-not $Denied) { throw 'PILOT_NATIVE_ARGUMENT_SELFTEST_FAILED' }
    # Simulate lifecycle failures without Docker, file writes or credentials.
    $script:TestReview='a' * 64; $script:TestPilot='b' * 64
    $script:TestReviewState='exited'; $script:TestPilotState='running'
    $script:TestActions=[Collections.Generic.List[string]]::new()
    $script:TestProbe=@{ hash='changed' }
    $script:R=[ordered]@{ phase='Running'; reviewStopped=$true; reviewId=$script:TestReview
        pilotId=$script:TestPilot; pilotName='fortis-github-pilot-offline'; image='sha256:offline'
        stateVolume='offline-state'; tokenVolume='offline-token'; owner='Offline'; repository='sandbox'; sourceReceipt=$null }
    function Container {
        param([string]$Identity)
        $Status=$script:TestPilotState; $Name='/' + $script:R.pilotName; $Image=$script:R.image
        if ($Identity -ceq $script:TestReview) { $Status=$script:TestReviewState; $Name='/' + $ReviewName; $Image=$ReviewImage }
        elseif ($Identity -cne $script:TestPilot) { throw 'SELFTEST_UNKNOWN_CONTAINER' }
        return [pscustomobject]@{ Id=$Identity; Name=$Name; Image=$Image; Mounts=@()
            Config=[pscustomobject]@{ Env=@(); User='10001:10001' }; HostConfig=[pscustomobject]@{}
            State=[pscustomobject]@{ Status=$Status; Health=[pscustomobject]@{ Status='healthy' } } }
    }
    function Helper {
        param($Payload, [string[]]$Mounts=@(), [switch]$Root, [switch]$InsidePilot)
        if ($Payload.action -ceq 'inspect') { return $script:TestProbe }
        if ($Payload.action -cne 'admit') { throw 'SELFTEST_UNEXPECTED_HELPER_ACTION' }
        return @{ admission='PASS' }
    }
    function Docker-Text {
        param([string[]]$Arguments)
        if ($Arguments[0] -ceq 'stop' -and $Arguments[3] -ceq $script:TestPilot) {
            $script:TestActions.Add('stop-pilot'); $script:TestPilotState='exited'
        } elseif ($Arguments[0] -ceq 'start' -and $Arguments[1] -ceq $script:TestReview) {
            $script:TestActions.Add('start-review'); $script:TestReviewState='running'
        } else { throw 'SELFTEST_FORBIDDEN_DOCKER_OPERATION' }
        return ''
    }
    function Assert-OnlyWriter { param([string]$Volume,[string]$AllowedId='')
        if ($Volume -cne 'fortis-r7-state-review-20261105' -or $AllowedId -cne $script:TestReview) { throw 'SELFTEST_WRITER_SCOPE' } }
    function Wait-Healthy { param([string]$Id)
        if ($Id -cne $script:TestReview -or $script:TestReviewState -cne 'running') { throw 'SELFTEST_HEALTH_TARGET' } }
    function Save-Record { }
    Return-Review
    if (($script:TestActions -join ',') -cne 'stop-pilot,start-review' -or $script:R.phase -cne 'ReturnedReview') {
        throw 'PILOT_ROLLBACK_SEQUENCE_SELFTEST_FAILED'
    }
    Return-Review
    if ($script:TestActions.Count -ne 2) { throw 'PILOT_ROLLBACK_REPLAY_SELFTEST_FAILED' }
    $script:R.phase='Running'; $script:TestPilotState='paused'; $script:TestActions.Clear()
    $Blocked=$false
    try { Return-Review } catch {
        if ($_.Exception.Message -ceq 'PILOT_ROLLBACK_CONTAINER_STATE_UNKNOWN') { $Blocked=$true } else { throw }
    }
    if (-not $Blocked -or $script:TestActions.Count) { throw 'PILOT_UNKNOWN_STATE_SELFTEST_FAILED' }
    $script:TestPilotState='created'; $script:TestReviewState='exited'; $script:TestActions.Clear()
    Return-Review
    if (($script:TestActions -join ',') -cne 'start-review') { throw 'PILOT_CREATED_ROLLBACK_SELFTEST_FAILED' }
    $script:R.phase='Prepared'; $script:R.image=''; $script:R.pilotId=''; $script:R.reviewStopped=$false
    $script:TestReviewState='running'; $script:TestActions.Clear()
    Return-Review
    if ($script:TestActions.Count -ne 0) { throw 'PILOT_PRE_SETUP_ROLLBACK_SELFTEST_FAILED' }
    $script:R.phase='Running'; $script:R.image='sha256:offline'; $script:R.pilotId=$script:TestPilot
    $script:R.reviewStopped=$true; $script:R.sourceReceipt=@{ hash='expected' }
    $script:TestPilotState='running'; $script:TestReviewState='exited'; $script:TestActions.Clear(); $Blocked=$false
    try { Return-Review } catch {
        if ($_.Exception.Message -ceq 'PILOT_ORIGINAL_REVIEW_DATA_CHANGED_NO_RESTART') { $Blocked=$true } else { throw }
    }
    if (-not $Blocked -or ($script:TestActions -join ',') -cne 'stop-pilot') { throw 'PILOT_CHANGED_SOURCE_ROLLBACK_SELFTEST_FAILED' }
    Write-Host 'FORTIS_GITHUB_PILOT_WINDOWS_SELFTEST_PASS cases=19'
    return
}

Check-Package
$script:Helper64=Code64 (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'github_pilot_helpers.py') -Raw)
if ((Docker-Text @('info','--format','{{.OSType}}')) -cne 'linux') { throw 'PILOT_LINUX_DOCKER_ENGINE_REQUIRED' }
if ($Mode -cne 'Start') {
    if (-not $Record) { throw 'PILOT_EXISTING_RECORD_REQUIRED' }
    $script:RecordPath=[IO.Path]::GetFullPath($Record)
    $Base=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Fortis\GitHubPilot'))
    if (-not $script:RecordPath.StartsWith($Base + '\',[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($script:RecordPath) -cne 'record.json') { throw 'PILOT_RECORD_PATH_INVALID' }
    Assert-RecordAcl
    $script:R=Get-Content -LiteralPath $script:RecordPath -Raw | ConvertFrom-Json
    if ($script:R.runId -cnotmatch '^[0-9a-f]{32}$' -or
        $script:R.stateVolume -cne ('fortis-github-pilot-state-' + $script:R.runId) -or
        $script:R.tokenVolume -cne ('fortis-github-pilot-token-' + $script:R.runId) -or
        $script:R.pilotName -cne ('fortis-github-pilot-' + $script:R.runId)) { throw 'PILOT_RECORD_IDENTITY_INVALID' }
    Write-Host ('PILOT_RECORD=' + $script:RecordPath)
    if ($script:R.phase -ceq 'Prepared' -and $Mode -ceq 'Resume') {
        Assert-PreparedResume
        Assert-PreparedResourcesAbsent
        Check-RepoSource
        # Confirm identities before updating this local record; full admission follows the build.
        $Original=Container $script:R.reviewId
        if ($Original.Name -cne ('/' + $ReviewName) -or $Original.Image -cne $ReviewImage -or
            $Original.State.Status -cne 'running' -or $Original.State.Health.Status -cne 'healthy') {
            throw 'PILOT_PRE_SETUP_REVIEW_IDENTITY_CHANGED'
        }
        Assert-Production
        $script:R.sourceCommit=$ExpectedSourceCommit; Save-Record
        Write-Host 'PILOT_RESUMING_PREPARED_RECORD_SAME_IDS'
    } else {
        if ($script:R.sourceCommit -cne $ExpectedSourceCommit) { throw 'PILOT_RECORD_IDENTITY_INVALID' }
        if ($Mode -ceq 'Rollback') { Return-Review; return }
        if ($script:R.phase -cnotin @('Running','Complete')) { throw 'PILOT_RUN_NOT_RESUMABLE_USE_RETAINED_RECORD' }
        try { Run-Scenario }
        catch { Write-Host 'PILOT_PAUSED_RESUME_OR_ROLLBACK_SAME_RECORD'; throw }
        return
    }
}

if ($Mode -ceq 'Start') {
    if ($Record) { throw 'PILOT_START_DOES_NOT_ACCEPT_EXISTING_RECORD_USE_RESUME' }
    if (-not $ConfirmTestRepository) { throw 'PILOT_EXACT_OWNER_TEST_REPOSITORY_ACK_REQUIRED' }
    $RepoMatch=[regex]::Match($Repository,'^(?<owner>[A-Za-z0-9][A-Za-z0-9_.-]{0,99})/(?<repo>[A-Za-z0-9][A-Za-z0-9_.-]{0,99})$')
    if (-not $RepoMatch.Success) { throw 'PILOT_EXACT_OWNER_TEST_REPOSITORY_ACK_REQUIRED' }
    $SelectedOwner=$RepoMatch.Groups['owner'].Value; $SelectedRepo=$RepoMatch.Groups['repo'].Value
    $RunId=[Guid]::NewGuid().ToString('N')
    $ScenarioId=([Guid]::ParseExact($RunId,'N')).ToString('D')
    $script:RecordPath=Join-Path (Join-Path (Join-Path $env:LOCALAPPDATA 'Fortis\GitHubPilot') $RunId) 'record.json'
    Protect-Directory (Split-Path $script:RecordPath -Parent)
    $Review=Container $ReviewName
    $script:R=[ordered]@{ schema=1; runId=$RunId; sourceCommit=$ExpectedSourceCommit
        owner=$SelectedOwner; repository=$SelectedRepo; phase='Prepared'; reviewId=$Review.Id
        reviewStopped=$false; productionBaseline=(Production-Baseline); sourceReceipt=$null; receipt=$null
        image=''; pilotId=''; pilotName=('fortis-github-pilot-' + $RunId)
        stateVolume=('fortis-github-pilot-state-' + $RunId); tokenVolume=('fortis-github-pilot-token-' + $RunId)
        scenario=[ordered]@{ format='fortis-github-pilot-run-v1'; runId=$ScenarioId
            owner=$SelectedOwner; repository=$SelectedRepo; branchPrefix='fortis-e2e/'; sourceSha=$null; phase='READ'
            reject=@{ requestId=[Guid]::NewGuid().ToString('D'); branch=('fortis-e2e/' + $ScenarioId + '-reject') }
            approve=@{ requestId=[Guid]::NewGuid().ToString('D'); branch=('fortis-e2e/' + $ScenarioId + '-approve') } } }
    Save-Record
    Write-Host ('PILOT_RECORD=' + $script:RecordPath)
}
Check-RepoSource
Build-PilotImage
Admit-Review 'running'; Assert-Production
foreach ($Name in @('fortis-r7-state-review-20261105','fortis-r7-identity','fortis-r7-grant','fortis-r7-sonar-token')) { Assert-Volume $Name }
Assert-OnlyWriter 'fortis-r7-state-review-20261105' $script:R.reviewId

Write-Host 'PILOT_STAGE=OWNER_CREDENTIAL_PROVISIONING'
Write-Host ('TEST_REPOSITORY=' + $script:R.owner + '/' + $script:R.repository)
Write-Host 'Only Metadata read and Contents read/write are required on this test repository.'
$Secret=Read-Host 'Paste the separate Gateway pilot credential (hidden)' -AsSecureString
$Address=[IntPtr]::Zero
try {
    $Address=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    $Credential=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($Address)
    if ($Credential -cnotmatch '^[A-Za-z0-9_]{20,4096}$') { throw 'PILOT_CREDENTIAL_FORMAT_INVALID' }
    Create-PilotVolume $script:R.tokenVolume 'provider-token'
    $null=Helper @{ action='provision'; token=$Credential } -Root -Mounts @('--mount',
        ('type=volume,source=' + $script:R.tokenVolume + ',target=/provision'))
} finally {
    $Credential=$null
    if ($Address -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Address) }
    $Secret.Dispose(); $Secret=$null
}
Create-PilotVolume $script:R.stateVolume 'isolated-state'
$script:R.phase='CredentialReady'; Save-Record
try {
    Admit-Review 'running'; Assert-Production
    Assert-OnlyWriter 'fortis-r7-state-review-20261105' $script:R.reviewId
    Write-Host 'PILOT_STAGE=RETAIN_REVIEW_AND_CLONE_STATE'
    $null=Docker-Text @('stop','--timeout','20',$script:R.reviewId)
    $script:R.reviewStopped=$true; Save-Record
    Admit-Review 'exited'
    Assert-OnlyWriter 'fortis-r7-state-review-20261105'
    $script:R.sourceReceipt=Helper @{ action='clone' } -Root -Mounts @('--mount',
        'type=volume,source=fortis-r7-state-review-20261105,target=/source,readonly',
        '--mount',('type=volume,source=' + $script:R.stateVolume + ',target=/target'))
    $script:R.phase='StateCopied'; Save-Record
    Create-PilotContainer
    $script:R.phase='Running'; Save-Record
} catch {
    Write-Host ('PILOT_SETUP_FAILED_RECORD=' + $script:RecordPath)
    try { Return-Review }
    catch { Write-Host 'PILOT_RETURN_REQUIRES_INSPECTION_USE_SAVED_RECORD'; throw }
    throw
}
try { Run-Scenario }
catch {
    Write-Host ('PILOT_PAUSED_RECORD=' + $script:RecordPath)
    Write-Host 'Resume or return to retained review with this same entrypoint and record. No new proposal IDs.'
    throw
}
