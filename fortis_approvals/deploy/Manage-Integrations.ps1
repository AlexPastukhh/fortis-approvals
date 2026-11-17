# Windows PowerShell 5.1. Owner-only review controller; tokens never enter argv.
[CmdletBinding()]
param(
    [ValidateSet('Apply','Credential','Check','Return','Backup','Promote','SelfTest')][string]$Action='Check',
    [string]$Config='', [string]$Image='', [string]$SourceSha='', [string]$CheckedImageRecord='', [string]$CurrentRecord='',
    [string]$AttemptRecord='', [string]$CredentialName='', [switch]$Rotate,
    [string]$EmergencyRescueImage='', [string]$EmergencyRescueArchiveSha256='',
    [switch]$AcceptUnverifiedRestore,
    [ValidateSet('github','sonarcloud')][string]$Service='',
    [switch]$Build, [switch]$Pull, [switch]$EnableDynamicGitHubRepositories, [switch]$EnableOwnerShell,
    [switch]$EnablePublisherMount, [switch]$EnableActionCoreNetwork, [switch]$AllowUncertainGrowth,
    [string]$CiControlRepositories='', [string]$PreserveUncertainRequests='',
    [string]$PreserveClaimedJobs='', [string]$PreserveApprovedRequest='', [switch]$ConfirmWorkerQuiescent,
    [string]$VaultVolume='fortis-review-secrets', [string]$Probes='', [switch]$Auto
)
$ForwardParameters=@{}+ $PSBoundParameters
. (Join-Path $PSScriptRoot 'Run-GitHub-Pilot-E2E.ps1') -Mode Functions
# Windows PowerShell 5.1 only. Strict JSON DTO for Gateway release records.
# Never hand arbitrary live PowerShell objects to ConvertTo-Json -Depth 25:
# adapters and nested members can grow without an effective object budget.
# The state helper's *verified* visual-media SHA256 map keys are exactly 131
# characters. Only that one field can exceed the general 128-character limit.
function Test-Release-Json-Key {
    param([string]$Name,[string]$Scope)
    if ($Name.Length -le 128) { return $true }
    return ($Scope -ceq 'receipt-hashes' -and $Name.Length -eq 131 -and
        $Name -cmatch '^native-git/visual-media/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-[0-4]-[0-9a-f]{64}\.png\z')
}
function Get-Release-Json-ChildScope {
    param([string]$Scope,[string]$Name)
    if ($Scope -ceq 'root' -and $Name -ceq 'sourceReceipt') { return 'receipt' }
    if ($Scope -ceq 'receipt' -and $Name -ceq 'sha256') { return 'receipt-hashes' }
    return ''
}
function ConvertTo-BoundedReleaseValue {
    param($Value, [hashtable]$Budget, [int]$Depth, [string]$Scope='')

    if ($Depth -gt 20) { throw 'RELEASE_RECORD_JSON_DEPTH_EXCEEDED' }
    $Budget.nodes = [int]$Budget.nodes + 1
    if ($Budget.nodes -gt 15000 -or $Budget.watch.Elapsed.TotalSeconds -gt 15) {
        throw 'RELEASE_RECORD_JSON_WORK_BUDGET_EXCEEDED'
    }
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        if ($Value.Length -gt 262144) { throw 'RELEASE_RECORD_JSON_STRING_TOO_LONG' }
        $Budget.chars = [int]$Budget.chars + $Value.Length
        if ($Budget.chars -gt 524288) { throw 'RELEASE_RECORD_JSON_CHAR_BUDGET_EXCEEDED' }
        return [string]$Value
    }
    if ($Value -is [bool] -or $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64] -or
        $Value -is [decimal] -or $Value -is [double] -or $Value -is [single]) {
        return $Value
    }
    if ($Value -is [datetime]) {
        return $Value.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [datetimeoffset]) {
        return $Value.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }

    if ($Value -is [Collections.IDictionary]) {
        # sourceReceipt.sha256 has one entry per retained state file.
        # Visual-media rows are bounded at 5,000; native artifact bundles also
        # contribute entries. Permit a larger map only at this exact scope.
        # Global node/character/output budgets remain in force; every other
        # object stays capped at 256.
        $ObjectLimit=256
        if($Scope -ceq 'receipt-hashes'){
            $ObjectLimit=8192
            Write-Host ('FORTIS_RELEASE_RECEIPT_HASH_MAP_COUNT='+$Value.Count)
        }
        if ($Value.Count -gt $ObjectLimit) {
            Write-Host ('FORTIS_RELEASE_JSON_OBJECT_LIMIT scope='+$Scope+' count='+$Value.Count+' limit='+$ObjectLimit)
            throw 'RELEASE_RECORD_JSON_OBJECT_TOO_LARGE'
        }
        $Map = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
        foreach ($Key in $Value.Keys) {
            if ($Key -isnot [string] -or
                -not (Test-Release-Json-Key -Name $Key -Scope $Scope) -or
                $Map.ContainsKey($Key)) {
                throw 'RELEASE_RECORD_JSON_INVALID_KEY'
            }
            $Budget.chars = [int]$Budget.chars + $Key.Length
            if ($Budget.chars -gt 524288) { throw 'RELEASE_RECORD_JSON_CHAR_BUDGET_EXCEEDED' }
            $NextScope=Get-Release-Json-ChildScope -Scope $Scope -Name $Key
            $Map.Add($Key,(ConvertTo-BoundedReleaseValue -Value $Value[$Key] -Budget $Budget -Depth ($Depth+1) -Scope $NextScope))
        }
        return ,$Map
    }
    if ($Value -is [pscustomobject]) {
        $Props = @($Value.PSObject.Properties)
        # ConvertFrom-Json materializes sourceReceipt.sha256 as a PSCustomObject.
        # Keep the same narrow per-file-map exception as IDictionary above.
        $ObjectLimit=256
        if($Scope -ceq 'receipt-hashes'){
            $ObjectLimit=8192
            Write-Host ('FORTIS_RELEASE_RECEIPT_HASH_MAP_COUNT='+$Props.Count)
        }
        if ($Props.Count -gt $ObjectLimit) {
            Write-Host ('FORTIS_RELEASE_JSON_OBJECT_LIMIT scope='+$Scope+' count='+$Props.Count+' limit='+$ObjectLimit)
            throw 'RELEASE_RECORD_JSON_OBJECT_TOO_LARGE'
        }
        $Map = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
        foreach ($Prop in $Props) {
            if ($Prop.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or
                -not (Test-Release-Json-Key -Name $Prop.Name -Scope $Scope) -or
                $Map.ContainsKey($Prop.Name)) {
                throw 'RELEASE_RECORD_JSON_INVALID_PROPERTY'
            }
            $Budget.chars = [int]$Budget.chars + $Prop.Name.Length
            if ($Budget.chars -gt 524288) { throw 'RELEASE_RECORD_JSON_CHAR_BUDGET_EXCEEDED' }
            $NextScope=Get-Release-Json-ChildScope -Scope $Scope -Name $Prop.Name
            $Map.Add($Prop.Name,(ConvertTo-BoundedReleaseValue -Value $Prop.Value -Budget $Budget -Depth ($Depth+1) -Scope $NextScope))
        }
        return ,$Map
    }
    if ($Value -is [Collections.IList]) {
        if ($Value.Count -gt 8192) { throw 'RELEASE_RECORD_JSON_ARRAY_TOO_LARGE' }
        $Items = New-Object 'System.Collections.Generic.List[object]'
        foreach ($Item in $Value) {
            # An array never inherits the special receipt SHA256 map-key scope.
            $Items.Add((ConvertTo-BoundedReleaseValue -Value $Item -Budget $Budget -Depth ($Depth+1) -Scope ''))
        }
        return ,$Items.ToArray()
    }
    throw 'RELEASE_RECORD_JSON_UNSUPPORTED_TYPE'
}

# The exact, real source state receipt is decoded from JSON by State-Helper.
# Prove it is serializable in the complete live release DTO while the source
# container is still running. Never discover an unsupported PSObject member
# for the first time AFTER docker stop, where even Return's record Save could fail.
function Assert-Release-Receipt-Serializable {
    param([Collections.IDictionary]$Record,$Receipt)
    $Prior=$Record['sourceReceipt']
    try {
        $Record['sourceReceipt']=$Receipt
        $null=ConvertTo-BoundedReleaseJson $Record
    } finally {
        $Record['sourceReceipt']=$Prior
    }
}

function ConvertTo-BoundedReleaseJson {
    param($Value)

    $Budget = @{ nodes=0; chars=0; watch=[Diagnostics.Stopwatch]::StartNew() }
    $Tree = ConvertTo-BoundedReleaseValue -Value $Value -Budget $Budget -Depth 0 -Scope 'root'
    if ($Tree -isnot [Collections.IDictionary]) { throw 'RELEASE_RECORD_JSON_ROOT_INVALID' }

    # JavaScriptSerializer receives *only* a newly built, depth/size-bounded
    # tree of primitives, dictionaries and arrays; never native PSObjects.
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $Encoder = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $Encoder.MaxJsonLength = 1048576
    $Encoder.RecursionLimit = 32
    $Json = $Encoder.Serialize($Tree)
    if (-not $Json -or [Text.Encoding]::UTF8.GetByteCount($Json) -gt 1048576) {
        throw 'RELEASE_RECORD_JSON_OUTPUT_TOO_LARGE'
    }
    return $Json
}

function Assert-BoundedReleaseJsonSelfTest {
    $Uncertain = '248affc3-536f-4100-b4bc-bd166c3989be,832d7ce2-0872-473f-9ffe-683e951f1412'
    $Claimed = '2df32a24-efb1-4dac-97f6-3b66147d8944'
    $Fixture = [ordered]@{
        schema = 'fortis-extension-release-v1'
        phase = 'Prepared'
        source = @{path='C:\\source\\record.json';hash=('a'*64);runtime=([pscustomobject]@{
            pilotId=('b'*64);pilotName='fortis-gateway';preserveApprovedRequest=$Uncertain})}
        runtime = [ordered]@{
            pilotId='';pilotName='fortis-github-pilot-test';image=('sha256:'+('c'*64))
            preserveUncertainRequests=$Uncertain;preserveClaimedJobs=$Claimed
            preserveApprovedRequest=$Uncertain;workerQuiescenceOwnerAttested=$true
            ciReads=$true;requiredWorkflows='ci-checks';ciControlRepositories=''
        }
        productionBaseline = 'LEGACY_STOPPED:'
        configurationDigest = ('d'*64)
        sourceReceipt = @{ preservedUncertainIds=@($Uncertain.Split(','));preservedClaimedIds=@($Claimed)
            preservedApprovedIds=@($Uncertain.Split(','));fixture=('x'*52000) }
        activated = $false
        probesPassed = $false
        emergencyRecovery = @{ownerAcceptedUnverifiedRestore=$true;isolatedRestoreTested=$false}
    }
    $Json = ConvertTo-BoundedReleaseJson $Fixture
    $RoundTrip = ConvertFrom-Json -InputObject $Json
    if ($RoundTrip.schema -cne 'fortis-extension-release-v1' -or
        $RoundTrip.runtime.preserveUncertainRequests -cne $Uncertain -or
        $RoundTrip.runtime.preserveClaimedJobs -cne $Claimed -or
        $RoundTrip.runtime.preserveApprovedRequest -cne $Uncertain -or
        $RoundTrip.sourceReceipt.fixture.Length -ne 52000 -or
        $RoundTrip.runtime.workerQuiescenceOwnerAttested -ne $true -or
        $RoundTrip.emergencyRecovery.isolatedRestoreTested -ne $false) {
        throw 'RELEASE_RECORD_JSON_ROUNDTRIP_SELFTEST_FAILED'
    }

    # Real shape: State-Helper emits sha256 and summary JSON dictionaries.
    # Deserialize to the very PSCustomObject graph used in production, rather
    # than only a synthetic hashtable with a large string.
    $VisualKey='native-git/visual-media/248affc3-536f-4100-b4bc-bd166c3989be-0-'+('a'*64)+'.png'
    if ($VisualKey.Length -ne 131) { throw 'RELEASE_VISUAL_RECEIPT_KEY_LENGTH_SELFTEST_FAILED' }
    $ReceiptText='{"sha256":{"native-git/workflow.sqlite":"'+('f'*64)+'","'+$VisualKey+'":"'+('e'*64)+'"},"summary":{"requests":9,"requestStates":{"UNCERTAIN":3,"APPROVED":2},"native":{"jobStates":{"CLAIMED":1},"preservedClaimedIds":["'+$Claimed+'"]}}}'
    $LiveLikeReceipt=ConvertFrom-Json -InputObject $ReceiptText
    $OriginalReceipt=$Fixture.sourceReceipt
    Assert-Release-Receipt-Serializable $Fixture $LiveLikeReceipt
    if (-not [object]::ReferenceEquals($OriginalReceipt,$Fixture.sourceReceipt)) {
        throw 'RELEASE_RECEIPT_PREFLIGHT_CHANGED_RECORD'
    }
    $Fixture.sourceReceipt=$LiveLikeReceipt
    $LiveJson=ConvertTo-BoundedReleaseJson $Fixture
    $LiveRoundTrip=ConvertFrom-Json -InputObject $LiveJson
    if ($LiveRoundTrip.sourceReceipt.summary.native.jobStates.CLAIMED -ne 1 -or
        $LiveRoundTrip.sourceReceipt.sha256.'native-git/workflow.sqlite' -cne ('f'*64) -or
        $LiveRoundTrip.sourceReceipt.sha256.PSObject.Properties[$VisualKey].Value -cne ('e'*64)) {
        throw 'RELEASE_REAL_RECEIPT_SHAPE_SELFTEST_FAILED'
    }
    $Fixture.sourceReceipt=$OriginalReceipt

    # Native state receipts hash every retained file. The sha256 map can
    # legitimately exceed 256 properties (for example, retained artifact
    # bundles or visual media), while remaining bounded by the serializer's
    # aggregate node/character/output budgets.
    $LargeHashMap=[ordered]@{}
    for($Index=0;$Index -lt 300;$Index++){
        $Digest=('{0:x64}' -f $Index)
        $LargeHashMap.Add(('native-git/artifacts/'+$Digest+'.bundle'),$Digest)
    }
    $LargeReceiptText=ConvertTo-Json -InputObject @{sha256=$LargeHashMap;summary=@{requests=0}} -Compress -Depth 5
    $LargeReceipt=ConvertFrom-Json -InputObject $LargeReceiptText
    $LargeOriginalReceipt=$Fixture.sourceReceipt
    Assert-Release-Receipt-Serializable $Fixture $LargeReceipt
    $Fixture.sourceReceipt=$LargeReceipt
    $LargeJson=ConvertTo-BoundedReleaseJson $Fixture
    $LargeRoundTrip=ConvertFrom-Json -InputObject $LargeJson
    $LargeProbeDigest=('{0:x64}' -f 299)
    $LargeProbeKey='native-git/artifacts/'+$LargeProbeDigest+'.bundle'
    if(@($LargeRoundTrip.sourceReceipt.sha256.PSObject.Properties).Count -ne 300 -or
        $LargeRoundTrip.sourceReceipt.sha256.PSObject.Properties[$LargeProbeKey].Value -cne $LargeProbeDigest){
        throw 'RELEASE_LARGE_RECEIPT_HASH_MAP_SELFTEST_FAILED'
    }
    $Fixture.sourceReceipt=$LargeOriginalReceipt

    # The larger limit is ONLY for root.sourceReceipt.sha256. An unrelated
    # summary object with the same number of fields must still fail closed.
    $OversizedSummary=[ordered]@{}
    for($Index=0;$Index -lt 257;$Index++){$OversizedSummary.Add(('field'+$Index),$Index)}
    $OutOfScopeReceipt=[pscustomobject]@{
        sha256=[pscustomobject]@{'native-git/workflow.sqlite'=('f'*64)}
        summary=[pscustomobject]$OversizedSummary
    }
    $Rejected=$false
    try { Assert-Release-Receipt-Serializable $Fixture $OutOfScopeReceipt }
    catch {
        if($_.Exception.Message -cne 'RELEASE_RECORD_JSON_OBJECT_TOO_LARGE'){throw}
        $Rejected=$true
    }
    if(-not $Rejected -or -not [object]::ReferenceEquals($LargeOriginalReceipt,$Fixture.sourceReceipt)){
        throw 'RELEASE_RECEIPT_OBJECT_LIMIT_SCOPE_SELFTEST_FAILED'
    }

    # The exception is NOT a global 131-char name bypass. Reject the very
    # same path under summary, and a forged .bin path under the sha256 field.
    $BadSummary=ConvertFrom-Json -InputObject $ReceiptText
    $BadSummary.summary | Add-Member -NotePropertyName $VisualKey -NotePropertyValue ('e'*64)
    $Rejected=$false
    try { Assert-Release-Receipt-Serializable $Fixture $BadSummary }
    catch { if($_.Exception.Message -cne 'RELEASE_RECORD_JSON_INVALID_PROPERTY'){throw};$Rejected=$true }
    if (-not $Rejected -or -not [object]::ReferenceEquals($OriginalReceipt,$Fixture.sourceReceipt)) {
        throw 'RELEASE_VISUAL_KEY_SCOPE_SELFTEST_FAILED'
    }
    $BadFile=ConvertFrom-Json -InputObject $ReceiptText
    $BadFile.sha256 | Add-Member -NotePropertyName ($VisualKey.Replace('.png','.bin')) -NotePropertyValue ('e'*64)
    $Rejected=$false
    try { Assert-Release-Receipt-Serializable $Fixture $BadFile }
    catch { if($_.Exception.Message -cne 'RELEASE_RECORD_JSON_INVALID_PROPERTY'){throw};$Rejected=$true }
    if (-not $Rejected -or -not [object]::ReferenceEquals($OriginalReceipt,$Fixture.sourceReceipt)) {
        throw 'RELEASE_VISUAL_KEY_PATTERN_SELFTEST_FAILED'
    }

    # An adapted ScriptProperty must not be read, evaluated, or admitted into
    # a release record. The pre-stop proof must fail closed *and* restore the
    # Prepared in-memory object to its exact original receipt.
    $PoisonedReceipt=[pscustomobject]@{sha256=[pscustomobject]@{safe=('f'*64)}}
    $PoisonedReceipt|Add-Member -MemberType ScriptProperty -Name Unsafe -Value { throw 'UNSAFE_RECEIPT_PROPERTY_EVALUATED' }
    $Rejected=$false
    try { Assert-Release-Receipt-Serializable $Fixture $PoisonedReceipt }
    catch { if($_.Exception.Message -cne 'RELEASE_RECORD_JSON_INVALID_PROPERTY'){throw};$Rejected=$true }
    if (-not $Rejected -or -not [object]::ReferenceEquals($OriginalReceipt,$Fixture.sourceReceipt)) {
        throw 'RELEASE_RECEIPT_PREFLIGHT_FAIL_CLOSED_SELFTEST_FAILED'
    }

    $Bad = @{}
    $Bad.self = $Bad
    $Rejected = $false
    try { $null=ConvertTo-BoundedReleaseJson $Bad }
    catch { if($_.Exception.Message -cne 'RELEASE_RECORD_JSON_DEPTH_EXCEEDED'){throw};$Rejected=$true }
    if(-not $Rejected){throw 'RELEASE_RECORD_JSON_CYCLE_SELFTEST_FAILED'}
    $Rejected = $false
    try { $null=ConvertTo-BoundedReleaseJson @{huge=('x'*300000)} }
    catch { if($_.Exception.Message -cne 'RELEASE_RECORD_JSON_STRING_TOO_LONG'){throw};$Rejected=$true }
    if(-not $Rejected){throw 'RELEASE_RECORD_JSON_SIZE_SELFTEST_FAILED'}
    $Rejected = $false
    try { $null=ConvertTo-BoundedReleaseJson @{unsupported=[IO.FileInfo]::new('example')} }
    catch { if($_.Exception.Message -cne 'RELEASE_RECORD_JSON_UNSUPPORTED_TYPE'){throw};$Rejected=$true }
    if(-not $Rejected){throw 'RELEASE_RECORD_JSON_TYPE_SELFTEST_FAILED'}

    # Exercise actual atomic Windows NTFS release-record persistence without
    # contacting Docker, reading the vault or touching live release pointers.
    $TestDirectory=Join-Path $env:TEMP ('fortis-release-bounded-selftest-' + [Guid]::NewGuid().ToString('N'))
    $PreviousPath=$script:RecordPath
    try {
        Protect-Directory $TestDirectory
        $script:RecordPath=Join-Path $TestDirectory 'record.json'
        # Exercise atomic NTFS persistence with actual long visual receipt key,
        # not only the earlier synthetic large-string receipt.
        Save-Record -SerializedJson $LiveJson
        $LiveSaved=Get-Content -LiteralPath $script:RecordPath -Raw | ConvertFrom-Json
        if ($LiveSaved.sourceReceipt.sha256.PSObject.Properties[$VisualKey].Value -cne ('e'*64)) {
            throw 'RELEASE_VISUAL_RECEIPT_PERSIST_SELFTEST_FAILED'
        }
        # Persist the >256-entry per-file hash map through the same atomic
        # NTFS writer used by production release records.
        Save-Record -SerializedJson $LargeJson
        $LargeSaved=Get-Content -LiteralPath $script:RecordPath -Raw | ConvertFrom-Json
        if(@($LargeSaved.sourceReceipt.sha256.PSObject.Properties).Count -ne 300 -or
            $LargeSaved.sourceReceipt.sha256.PSObject.Properties[$LargeProbeKey].Value -cne $LargeProbeDigest){
            throw 'RELEASE_LARGE_RECEIPT_PERSIST_SELFTEST_FAILED'
        }
        Save-Record -SerializedJson $Json
        $Saved=Get-Content -LiteralPath $script:RecordPath -Raw | ConvertFrom-Json
        if ($Saved.phase -cne 'Prepared' -or
            $Saved.runtime.preserveApprovedRequest -cne $Uncertain -or
            $Saved.sourceReceipt.fixture.Length -ne 52000) {
            throw 'RELEASE_RECORD_JSON_PERSIST_SELFTEST_FAILED'
        }
        $Fixture.phase='Staged'
        Save-Record -SerializedJson (ConvertTo-BoundedReleaseJson $Fixture)
        $Updated=Get-Content -LiteralPath $script:RecordPath -Raw | ConvertFrom-Json
        if ($Updated.phase -cne 'Staged' -or
            $Updated.runtime.preserveClaimedJobs -cne $Claimed) {
            throw 'RELEASE_RECORD_JSON_REPLACE_SELFTEST_FAILED'
        }
        Assert-RecordAcl
    } finally {
        $script:RecordPath=$PreviousPath
        if (Test-Path -LiteralPath $TestDirectory -PathType Container) {
            Remove-Item -LiteralPath $TestDirectory -Recurse -Force
        }
    }
    Write-Host 'FORTIS_RELEASE_BOUNDED_JSON_SELFTEST_PASS'
}
$ErrorActionPreference='Stop'
$ReleaseBase=Join-Path $env:LOCALAPPDATA 'Fortis\GatewayReleases'
$Pointer=Join-Path $ReleaseBase 'current.json'
$AttemptPointer=Join-Path $ReleaseBase 'attempt.json'
$PrimaryPointer=Join-Path $ReleaseBase 'primary.json'
$script:Step='PREFLIGHT';$script:Image=$Image
$script:PreserveUncertainRequests=$PreserveUncertainRequests
$script:PreserveUncertainExact=[bool]$PreserveUncertainRequests
$script:GrowthEffectiveUncertainRequests=$null
$script:GrowthSourceVolume=''
$script:GrowthWitness=$null
$script:GrowthReviewedReceipt=$null
$script:PreserveClaimedJobs=$PreserveClaimedJobs
$script:PreserveClaimedExact=[bool]$PreserveClaimedJobs
$script:PreserveApprovedRequest=$PreserveApprovedRequest
$script:PreserveApprovedExact=[bool]$PreserveApprovedRequest
# Exact paths only; never accept an arbitrary endpoint or credential path from the caller.
$script:OwnerShellJson='{"port":10443,"serverCA":"/run/fortis-secrets/owner-shell/server-ca.pem","clientCert":"/run/fortis-secrets/owner-shell/client.pem","clientKey":"/run/fortis-secrets/owner-shell/client.key","secretFile":"/run/fortis-secrets/owner-shell/secret.txt"}'

function Json-Items { param([string]$Text) $Parsed=ConvertFrom-Json -InputObject $Text; foreach($Item in $Parsed){Write-Output $Item} }
function Docker-Json { param([string[]]$Arguments) Json-Items (Docker-Text $Arguments) }
function Extension-EnvLines {
    param([string]$Configuration,[string]$Nonce)
    @(( 'FORTIS_EXTENSIONS_CONFIG='+$Configuration ),( 'FORTIS_RELEASE_NONCE='+$Nonce ))
}
function Check-ExtensionEnv {
    param([string[]]$Lines,[string]$Configuration,[string]$Nonce)
    $Expected=@(Extension-EnvLines $Configuration $Nonce)
    $Actual=@($Lines|Where-Object{$_.StartsWith('FORTIS_EXTENSIONS_CONFIG=') -or $_.StartsWith('FORTIS_RELEASE_NONCE=')})
    if($Actual.Count -ne 2 -or @($Actual|Where-Object{$Expected -cnotcontains $_}).Count -or
       @($Actual|Select-Object -Unique).Count -ne 2){throw 'RELEASE_CONFIG_CHANGED'}
}
# Action Core is an explicit opt-in. These checks are read-only and owner-side;
# the process firewall rule is installed separately, never by an AI release.
function Assert-ActionCoreFirewall {
    $Path='C:\Program Files\Docker\Docker\resources\com.docker.backend.exe'
    $Backends=@(Get-CimInstance Win32_Process -Filter "Name='com.docker.backend.exe'")
    if(-not $Backends.Count -or @($Backends|Where-Object{$_.ExecutablePath -ine $Path}).Count){
        throw 'RELEASE_ACTION_CORE_BACKEND_IDENTITY_INVALID'
    }
    $Rules=@(Get-NetFirewallRule -Name 'Fortis-DockerBackend-Block-TCP8000' -PolicyStore ActiveStore -ErrorAction Stop)
    if($Rules.Count -ne 1){throw 'RELEASE_ACTION_CORE_FIREWALL_RULE_MISSING'}
    $Rule=$Rules[0]
    if([string]$Rule.Enabled -cne 'True' -or [string]$Rule.Direction -cne 'Outbound' -or
       [string]$Rule.Action -cne 'Block' -or [string]$Rule.Profile -cne 'Any'){
        throw 'RELEASE_ACTION_CORE_FIREWALL_RULE_INVALID'
    }
    $App=@(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Rule)
    $Port=@(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule)
    $Address=@(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule)
    $Service=@(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $Rule)
    $Interface=@(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $Rule)
    if($App.Count -ne 1 -or $Port.Count -ne 1 -or $Address.Count -ne 1 -or
       $Service.Count -ne 1 -or $Interface.Count -ne 1 -or
       $App[0].Program -ine $Path -or
       [string]$Port[0].Protocol -cne 'TCP' -or [string]$Port[0].RemotePort -cne '8000' -or
       [string]$Port[0].LocalPort -cne 'Any' -or
       [string]$Address[0].RemoteAddress -cne 'Any' -or
       [string]$Address[0].LocalAddress -cne 'Any' -or
       [string]$Service[0].Service -cne 'Any' -or
       [string]$Interface[0].InterfaceType -cne 'Any'){
        throw 'RELEASE_ACTION_CORE_FIREWALL_SCOPE_INVALID'
    }
    $Profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if($Profiles.Count -ne 3 -or @($Profiles|Where-Object{[string]$_.Enabled -cne 'True'}).Count){
        throw 'RELEASE_ACTION_CORE_FIREWALL_PROFILE_DISABLED'
    }
    Write-Host 'FORTIS_ACTION_CORE_FIREWALL_RULE_VERIFIED'
}
function Read-ActionCoreDockerNetwork {
    param([string]$Name,[bool]$Internal,[string]$Owner,[string]$Purpose)
    $Records=@(Docker-Json @('network','inspect',$Name))
    if($Records.Count -ne 1){throw 'RELEASE_ACTION_CORE_NETWORK_MISSING'}
    $N=$Records[0]
    if($N.Name -cne $Name -or $N.Id -cnotmatch '^[0-9a-f]{64}$' -or
       $N.Driver -cne 'bridge' -or $N.Scope -cne 'local' -or
       [bool]$N.Internal -ne $Internal -or [bool]$N.Attachable -or [bool]$N.Ingress -or
       $N.Labels.'io.fortis.owner' -cne $Owner -or
       $N.Labels.'io.fortis.purpose' -cne $Purpose){
        throw 'RELEASE_ACTION_CORE_NETWORK_IDENTITY_INVALID'
    }
    return [string]$N.Id
}
function Get-ActionCoreLocalApiAddress {
    $Containers=@(Docker-Json @('container','inspect','feedbrain-api-1'))
    if($Containers.Count -ne 1){throw 'RELEASE_ACTION_CORE_LOCAL_API_MISSING'}
    $C=$Containers[0]
    $Binding=@($C.HostConfig.PortBindings.'8000/tcp')
    $Address=[string]$C.NetworkSettings.Networks.'feedbrain_default'.IPAddress
    $Parsed=$null
    if($C.Name -cne '/feedbrain-api-1' -or $C.State.Status -cne 'running' -or
       $C.Config.Labels.'com.docker.compose.project' -cne 'feedbrain' -or
       $C.Config.Labels.'com.docker.compose.service' -cne 'api' -or
       $Binding.Count -ne 1 -or $Binding[0].HostIp -cne '127.0.0.1' -or
       [string]$Binding[0].HostPort -cne '8000' -or
       [string]$C.NetworkSettings.Networks.'feedbrain_default'.GlobalIPv6Address -ne '' -or
       -not [Net.IPAddress]::TryParse($Address,[ref]$Parsed) -or
       $Parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){
        throw 'RELEASE_ACTION_CORE_LOCAL_API_IDENTITY_INVALID'
    }
    return $Address
}
function Assert-ActionCoreWindowsLocalRead {
    try {
        $Response=Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8000/health/live' -TimeoutSec 5
        if($Response.StatusCode -ne 200){throw 'NON_200'}
    }catch{throw 'RELEASE_ACTION_CORE_WINDOWS_LOCAL_READ_FAILED'}
    Write-Host 'FORTIS_ACTION_CORE_WINDOWS_LOCAL_HTTP_OK'
}
function Read-ActionCoreBoundary {
    Assert-ActionCoreFirewall
    $Networks=[ordered]@{}
    $Networks['fortis-gateway-egress']=Read-ActionCoreDockerNetwork -Name 'fortis-gateway-egress' -Internal:$false -Owner 'fortis-approvals' -Purpose 'gateway-egress-v1'
    $Networks['fortis-actioncore-net']=Read-ActionCoreDockerNetwork -Name 'fortis-actioncore-net' -Internal:$true -Owner 'feed_and_search_and_bank_and_brain' -Purpose 'action-core-gateway-v1'
    if($Networks['fortis-gateway-egress'] -ceq $Networks['fortis-actioncore-net']){
        throw 'RELEASE_ACTION_CORE_NETWORK_ALIAS_INVALID'
    }
    $null=Get-ActionCoreLocalApiAddress
    Assert-ActionCoreWindowsLocalRead
    Write-Host 'FORTIS_ACTION_CORE_BOUNDARY_PREFLIGHT_PASS'
    return $Networks
}
function Assert-ActionCoreConfig {
    param([string]$Json)
    $Config=ConvertFrom-Json -InputObject $Json -ErrorAction Stop
    $Provider=$Config.providers.action_core
    if($Config.schemaVersion -ne 1 -or -not $Provider -or
       @($Provider.operations.PSObject.Properties.Name).Count -ne 1 -or
       @($Provider.operations.PSObject.Properties.Name)[0] -cne 'read_action' -or
       $Provider.credentials.read -cne 'action-core-read' -or
       $Provider.operations.read_action.policy -cne 'ALLOW' -or
       @($Provider.operations.read_action.targets).Count -ne 2 -or
       (@($Provider.operations.read_action.targets|Sort-Object) -join ',') -cne '3,4'){
        throw 'RELEASE_ACTION_CORE_READ_CONFIG_REQUIRED'
    }
}
function Assert-ActionCoreNoHttpFromGateway {
    param([string]$ContainerId)
    $Address=Get-ActionCoreLocalApiAddress
    $Code=@'
import socket,sys
def must_refuse(host):
    endpoints=socket.getaddrinfo(host,8000,type=socket.SOCK_STREAM)
    if not endpoints: raise RuntimeError("NO_DNS")
    for family,kind,protocol,_,endpoint in endpoints:
        with socket.socket(family,kind,protocol) as conn:
            conn.settimeout(2)
            if conn.connect_ex(endpoint)==0:
                raise RuntimeError("HTTP_8000_ROUTE_OPEN")
must_refuse("host.docker.internal")
must_refuse(sys.argv[1])
print("ACTION_CORE_HTTP8000_BOTH_DENIED")
'@
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<action-core-network-negative>','exec'))"
    $Outcome=Docker-Text @('exec','--user','10001:10001',$ContainerId,'python','-I','-B','-c',$Wrapper,$Address)
    if($Outcome.Trim() -cne 'ACTION_CORE_HTTP8000_BOTH_DENIED'){
        throw 'RELEASE_ACTION_CORE_HTTP8000_BYPASS'
    }
    Assert-ActionCoreWindowsLocalRead
    Write-Host 'FORTIS_ACTION_CORE_GATEWAY_HTTP8000_BOTH_DENIED'
}
function OwnerShell-EnvLines {
    param([bool]$Enabled)
    if($Enabled){Write-Output ('FORTIS_OWNER_SHELL_CONFIG='+$script:OwnerShellJson)}
}
function Check-OwnerShellEnv {
    param([string[]]$Lines,[bool]$Enabled)
    $Actual=@($Lines|Where-Object{$_.StartsWith('FORTIS_OWNER_SHELL_CONFIG=')})
    if($Enabled){
        if($Actual.Count -ne 1 -or $Actual[0] -cne ('FORTIS_OWNER_SHELL_CONFIG='+$script:OwnerShellJson)){
            throw 'RELEASE_OWNER_SHELL_ENV_MISMATCH'
        }
    } elseif($Actual.Count){throw 'RELEASE_OWNER_SHELL_UNEXPECTED_ENV'}
}
function Assert-PublicEnvFile {
    param([string]$Path,[string[]]$Expected)
    $Code=@'
import json,os,sys
lines=json.load(sys.stdin)
expected=dict(line.split('=',1) for line in lines)
actual={k:v for k,v in os.environ.items() if k.startswith('FORTIS_')}
assert len(expected)==len(lines) and actual==expected,'RELEASE_ENV_ROUNDTRIP_FAILED'
print('RELEASE_ENV_ROUNDTRIP_PASS')
'@
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<public-env-preflight>','exec'))"
    $Result=Private-Process @('run','--rm','-i','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','64','--memory','256m','--env-file',$Path,'--entrypoint','python',
        $script:Image,'-I','-B','-c',$Wrapper) (ConvertTo-Json -InputObject $Expected -Compress)
    if($Result -cne 'RELEASE_ENV_ROUNDTRIP_PASS'){throw 'RELEASE_ENV_ROUNDTRIP_FAILED'}
}
function Forward-NativeParameters {
    param([Collections.IDictionary]$Parameters)
    $Native=@()
    foreach($Key in $Parameters.Keys){
        $Value=$Parameters[$Key]
        if($Value -is [Management.Automation.SwitchParameter]){if($Value){$Native+=('-'+$Key)}}
        else{$Native+=@(('-'+$Key),[string]$Value)}
    }
    $Native
}
function Step { param([string]$Name) $script:Step=$Name; Write-Host ('FORTIS_INTEGRATIONS_STEP_' + $Name) }
function Assert-DirectoryAcl {
    param([string]$Path)
    if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'RELEASE_REPARSE_POINT_DENIED'}
    $Acl=Get-Acl -LiteralPath $Path
    $Allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    if (-not $Acl.AreAccessRulesProtected -or $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $Allowed[0]) {throw 'RELEASE_DIRECTORY_ACL_INVALID'}
    foreach($Rule in $Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($Rule.AccessControlType -eq 'Allow' -and $Allowed -cnotcontains $Rule.IdentityReference.Value) {throw 'RELEASE_DIRECTORY_ACL_INVALID'}
    }
}
function Read-Private {
    param([string]$Path)
    $Full=[IO.Path]::GetFullPath($Path)
    $AllowedRoot=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Fortis'))
    if (-not $Full.StartsWith($AllowedRoot+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'RELEASE_RECORD_PATH_INVALID'}
    Assert-DirectoryAcl (Split-Path $Full -Parent)
    if ((Get-Item -LiteralPath $Full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'RELEASE_REPARSE_POINT_DENIED'}
    $Saved=$script:RecordPath
    try {$script:RecordPath=$Full;Assert-RecordAcl;return (Get-Content -LiteralPath $Full -Raw | ConvertFrom-Json)}
    finally {$script:RecordPath=$Saved}
}
function Write-Private {
    param([string]$Path,$Value)
    $SavedR=$script:R;$SavedPath=$script:RecordPath
    try {$script:R=$Value;$script:RecordPath=$Path;Save-Record}
    finally {$script:R=$SavedR;$script:RecordPath=$SavedPath}
}
function Save {
    # Exact release records only: never recursively serialize the live
    # PowerShell object graph. Abort pre-STOP_SOURCE on unknown/large types.
    Write-Host 'FORTIS_INTEGRATIONS_RECORD_BOUNDED_SERIALIZE_START'
    $JsonText=ConvertTo-BoundedReleaseJson $script:R
    Write-Host 'FORTIS_INTEGRATIONS_RECORD_BOUNDED_SERIALIZE_PASS'
    Save-Record -SerializedJson $JsonText
    Write-Host 'FORTIS_INTEGRATIONS_RECORD_PERSISTED'
}
function Python-Code {
    param([string[]]$Arguments,[string]$Code,[string]$InputText='')
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<owner-integrations>','exec'))"
    Private-Process ($Arguments+@('python','-I','-B','-c',$Wrapper)) $InputText
}
function Image-CLI {
    param([string[]]$Command,[string]$InputText='', [switch]$Writable,[string]$StateVolume='')
    $Identity='10001:10001'
    if($Writable){$Identity='0:0'}
    $Arguments=@('run','--rm','-i','--pull=never','--network','none','--read-only','--user',$Identity,
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','256m',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=32m')
    if($Writable){$Arguments+=@('--cap-add','CHOWN','--cap-add','DAC_OVERRIDE')}
    $Mount='type=volume,source='+$VaultVolume+',target=/run/fortis-secrets'
    if(-not $Writable){$Mount+=',readonly'}
    if($StateVolume){Assert-Volume $StateVolume;$Arguments+=@('--mount',('type=volume,source='+$StateVolume+',target=/state,readonly'))}
    $Arguments+=@('--mount',$Mount,'--entrypoint','python',$script:Image)
    $Payload=ConvertTo-Json -InputObject @{arguments=$Command;input=$InputText} -Compress -Depth 20
    $Code=@'
import io,json,runpy,sys
sys.path.insert(0,'/opt/fortis')
p=json.load(sys.stdin);sys.argv=['integrations']+p['arguments'];sys.stdin=io.TextIOWrapper(io.BytesIO(p['input'].encode()),encoding='utf-8')
runpy.run_module('fortis_approvals.extensions.cli',run_name='__main__')
'@
    # Replace the image's entrypoint argument, rather than adding a second python.
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<owner-integrations>','exec'))"
    (Private-Process ($Arguments+@('-I','-B','-c',$Wrapper)) $Payload) | ConvertFrom-Json
}
function Image-OwnerShell-Preflight {
    # Offline, uid-10001, read-only inspection. No client credentials in argv/env/log.
    $Code=@'
import sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.owner_shell_release import verify_material
verify_material()
print('OWNER_SHELL_MATERIAL_PREFLIGHT_PASS')
'@
    $DockerArguments=@('run','--rm','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','32','--memory','128m',
        '--mount',('type=volume,source='+$VaultVolume+',target=/run/fortis-secrets,readonly'),
        '--entrypoint','python',$script:Image)
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<owner-shell-release>','exec'))"
    $Result=Private-Process ($DockerArguments+@('-I','-B','-c',$Wrapper)) ''
    if($Result -cne 'OWNER_SHELL_MATERIAL_PREFLIGHT_PASS'){
        throw 'RELEASE_OWNER_SHELL_MATERIAL_PREFLIGHT_FAILED'
    }
}
function Running-OwnerShell-Check {
    param([string]$Id)
    # Read-only HTTPS capabilities: validate both identities and bearer before activation.
    # No execute route is called. Only a fixed public result marker leaves the container.
    $Code=@'
import sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.owner_shell import OwnerShellClient
client=OwnerShellClient.from_environment()
assert client is not None,'OWNER_SHELL_DISABLED'
data=client.capabilities()
assert type(data) is dict and data=={'schemaVersion':1,'oneShot':True,'windows':True,'analyzer':False,'externalAI':False},'OWNER_SHELL_CAPABILITIES_INVALID'
print('OWNER_SHELL_STAGED_MTLS_CAPABILITIES_PASS')
'@
    $Result=Python-Code @('exec','-i','--user','10001:10001',$Id) $Code
    if($Result -cne 'OWNER_SHELL_STAGED_MTLS_CAPABILITIES_PASS'){
        throw 'RELEASE_OWNER_SHELL_STAGED_MTLS_FAILED'
    }
}
function Running-CLI {
    param([string]$Id,[string[]]$Command,[string]$InputText='', [switch]$Root)
    $Identity='10001:10001';if($Root){$Identity='0:0'}
    $Code="import runpy,sys;sys.path.insert(0,'/opt/fortis');sys.argv=['integrations']+"+("__import__('json').loads(__import__('base64').b64decode('"+(Code64 (ConvertTo-Json -InputObject $Command -Compress))+"'))")+";runpy.run_module('fortis_approvals.extensions.cli',run_name='__main__')"
    (Python-Code @('exec','-i','--user',$Identity,$Id) $Code $InputText) | ConvertFrom-Json
}
function Repo-JSON {
    param([string]$Code)
    $Prefix="import sys;sys.path.insert(0,'/workspace/repo/Repos/fortis-approvals');"
    $Encoded=Code64 ($Prefix+"`n"+$Code)
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<repo-integrations>','exec'))"
    (Private-Process @('exec','--user','1000:1000','fortis-repo-test','python3','-I','-B','-c',$Wrapper) '')|ConvertFrom-Json
}
function Assert-ApprovedScopeForwarded {
    param($Payload)
    if($Payload.action -cnotin @('inspect','clone','uncertain_growth_snapshot','uncertain_growth_review')){return}
    # Owner-pinned full list must survive PowerShell -> JSON -> Docker unchanged.
    # An empty/missing, reordered or widened list is rejected before Docker.
    $Expected=@(Approved-Ids)
    $Actual=@($Payload.preserveApprovedIds)
    if($Expected.Count){
        if(($Actual -join ',') -cne ($Expected -join ',')){
            throw 'RELEASE_APPROVED_SCOPE_NOT_FORWARDED'
        }
    } elseif($Actual.Count){
        throw 'RELEASE_APPROVED_SCOPE_UNEXPECTED'
    }
}
function State-Helper {
    param($Payload,[string[]]$Mounts=@(),[switch]$Root)
    Assert-ApprovedScopeForwarded $Payload
    if($script:PreserveApprovedRequest -and $Payload.action -cin @('inspect','clone','uncertain_growth_snapshot','uncertain_growth_review')){
        Write-Host 'FORTIS_APPROVED_SCOPE_FORWARD_VERIFIED'
    }
    if($Mounts.Count % 2 -ne 0){throw 'RELEASE_STATE_MOUNT_PAIR_INVALID'}
    for($Index=0;$Index -lt $Mounts.Count;$Index+=2){
        if($Mounts[$Index] -cne '--mount' -or
            -not $Mounts[$Index+1].StartsWith('type=volume,source=')){
            throw 'RELEASE_STATE_MOUNT_PAIR_INVALID'
        }
    }
    $Identity='10001:10001';if($Root){$Identity='0:0'}
    $Arguments=@('run','--rm','-i','--pull=never','--network','none','--read-only','--user',$Identity,
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','256m',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=32m')
    if($Root){$Arguments+=@('--cap-add','CHOWN','--cap-add','DAC_OVERRIDE')}
    $Code="import runpy;runpy.run_path('/opt/fortis/operator/state_helpers.py',run_name='__main__')"
    $Encoded=Code64 $Code;$Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<state-helper>','exec'))"
    $Native=@{};if($Payload.action -ceq 'clone'){$Native['DiagnosticDockerClone']=$true}
    (Private-Process ($Arguments+$Mounts+@('--entrypoint','python',$script:Image,'-I','-B','-c',$Wrapper)) (ConvertTo-Json -InputObject $Payload -Depth 25 -Compress) @Native) | ConvertFrom-Json
}
function Ensure-Vault {
    if($VaultVolume -cnotmatch '^fortis-review-secrets(?:-[a-z0-9-]{1,48})?$'){throw 'RELEASE_VAULT_NAME_INVALID'}
    $Names=(Docker-Text @('volume','ls','--format','{{.Name}}')) -split '\r?\n'
    if($Names -cnotcontains $VaultVolume){$null=Docker-Text @('volume','create','--label','io.fortis.credentials=review-v1',$VaultVolume)}
    Assert-Volume $VaultVolume
    $V=@(Docker-Json @('volume','inspect',$VaultVolume))[0]
    if($V.Labels.'io.fortis.credentials' -cne 'review-v1'){throw 'RELEASE_VAULT_PROVENANCE_INVALID'}
}
function Put-Credential {
    param([string]$Alias,[switch]$Rotation)
    if($Alias -cnotmatch '^[a-z][a-z0-9-]{0,47}$'){throw 'CREDENTIAL_NAME_INVALID'}
    $Info=Image-CLI @('credential-status','--name',$Alias)
    $Generation=$null
    if($Info.ready){
        if(-not $Rotation){return}
        $Generation=$Info.generation
    } elseif($Rotation){throw 'CREDENTIAL_ROTATION_TARGET_NOT_READY'}
    $Secret=Read-Host ('Gateway credential '+$Alias) -AsSecureString
    $PointerValue=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    try {
        $Plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($PointerValue)
        $InputText=ConvertTo-Json -InputObject @{name=$Alias;value=$Plain;expectedGeneration=$Generation} -Compress
        $Info=Image-CLI @('credential') $InputText -Writable
        if($Info.status -cne 'PROVISIONED'){throw 'CREDENTIAL_PROVISION_NOT_CONFIRMED'}
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PointerValue)
        $Plain=$null;$InputText=$null;$Secret.Dispose()
    }
    Write-Host ('FORTIS_CREDENTIAL_READY '+$Alias)
}
function Read-DynamicRepositoriesFlag {
    param($Record)
    if($null -eq $Record){throw 'RELEASE_DYNAMIC_RECORD_INVALID'}
    if($Record -is [Collections.IDictionary]){
        if(-not $Record.Contains('dynamicRepositories')){return $false}
        $Value=$Record['dynamicRepositories']
    } else {
        $Property=$Record.PSObject.Properties['dynamicRepositories']
        if($null -eq $Property){return $false}
        $Value=$Property.Value
    }
    if($Value -isnot [bool]){throw 'RELEASE_DYNAMIC_RECORD_INVALID'}
    return $Value
}

function Read-CiControlRepositories {
    param($Record)
    if($null -eq $Record){throw 'RELEASE_CI_CONTROL_RECORD_INVALID'}
    $Value=''
    if($Record -is [Collections.IDictionary]){
        if($Record.Contains('ciControlRepositories')){$Value=$Record['ciControlRepositories']}
    } else {
        $Prop=$Record.PSObject.Properties['ciControlRepositories']
        if($null -ne $Prop){$Value=$Prop.Value}
    }
    if($Value -isnot [string]){throw 'RELEASE_CI_CONTROL_RECORD_INVALID'}
    if($Value -and ($Value -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}(,[A-Za-z0-9][A-Za-z0-9_.-]{0,99}){0,19}$' -or
        @($Value.Split(',')|Select-Object -Unique).Count -ne @($Value.Split(',')).Count)){
        throw 'RELEASE_CI_CONTROL_RECORD_INVALID'
    }
    return $Value
}
function Parse-PreservedUncertainRequests {
    param([string]$Value)
    if(-not $Value){return}
    $Ids=@($Value.Split(','))
    if($Ids.Count -gt 20 -or @($Ids|Select-Object -Unique).Count -ne $Ids.Count){
        throw 'RELEASE_UNCERTAIN_SCOPE_INVALID'
    }
    foreach($Id in $Ids){
        if($Id -cnotmatch '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'){
            throw 'RELEASE_UNCERTAIN_SCOPE_INVALID'
        }
        Write-Output $Id
    }
}
function Read-PreservedUncertainRequests {
    param($Record)
    if($null -eq $Record){throw 'RELEASE_UNCERTAIN_RECORD_INVALID'}
    $Value=''
    if($Record -is [Collections.IDictionary]){
        if($Record.Contains('preserveUncertainRequests')){$Value=$Record['preserveUncertainRequests']}
    } else {
        $Prop=$Record.PSObject.Properties['preserveUncertainRequests']
        if($null -ne $Prop){$Value=$Prop.Value}
    }
    if($Value -isnot [string]){throw 'RELEASE_UNCERTAIN_RECORD_INVALID'}
    if($Value){$null=@(Parse-PreservedUncertainRequests $Value)}
    return $Value
}
function Read-PreservedClaimedJobs {
    param($Record)
    if($null -eq $Record){throw 'RELEASE_CLAIMED_RECORD_INVALID'}
    $Value=''
    if($Record -is [Collections.IDictionary]){
        if($Record.Contains('preserveClaimedJobs')){$Value=$Record['preserveClaimedJobs']}
    } else {
        $Prop=$Record.PSObject.Properties['preserveClaimedJobs']
        if($null -ne $Prop){$Value=$Prop.Value}
    }
    if($Value -isnot [string]){throw 'RELEASE_CLAIMED_RECORD_INVALID'}
    if($Value){$null=@(Parse-PreservedUncertainRequests $Value)}
    return $Value
}
function Read-PreservedApprovedRequest {
    param($Record)
    if($null -eq $Record){throw 'RELEASE_APPROVED_RECORD_INVALID'}
    $Value=''
    if($Record -is [Collections.IDictionary]){
        if($Record.Contains('preserveApprovedRequest')){$Value=$Record['preserveApprovedRequest']}
    } else {
        $Property=$Record.PSObject.Properties['preserveApprovedRequest']
        if($null -ne $Property){$Value=$Property.Value}
    }
    if($Value -isnot [string]){throw 'RELEASE_APPROVED_RECORD_INVALID'}
    if($Value){$null=@(Parse-PreservedUncertainRequests $Value)}
    return $Value
}
function Approved-Ids {
    if($script:PreserveApprovedRequest){
        Parse-PreservedUncertainRequests $script:PreserveApprovedRequest
    }
}
function Read-OwnerShellFlag {
    param($Record)
    if($null -eq $Record){throw 'RELEASE_OWNER_SHELL_RECORD_INVALID'}
    if($Record -is [Collections.IDictionary]){
        if(-not $Record.Contains('ownerShell')){return $false}
        $Value=$Record['ownerShell']
    } else {
        $Property=$Record.PSObject.Properties['ownerShell']
        if($null -eq $Property){return $false}
        $Value=$Property.Value
    }
    if($Value -isnot [bool]){throw 'RELEASE_OWNER_SHELL_RECORD_INVALID'}
    return $Value
}
# Publisher activation uses one fixed owner-provisioned Docker volume.
# No arbitrary host path, no env activation switch, and no automatic
# provisioning. Old protected Complete records have no field => disabled.
function Read-PublisherActivationVolume {
    param($Record)
    if($null -eq $Record){throw 'RELEASE_PUBLISHER_VOLUME_RECORD_INVALID'}
    if($Record -is [Collections.IDictionary]){
        if(-not $Record.Contains('publisherActivationVolume')){return ''}
        $Value=$Record['publisherActivationVolume']
    } else {
        $Prop=$Record.PSObject.Properties['publisherActivationVolume']
        if($null -eq $Prop){return ''}
        $Value=$Prop.Value
    }
    if($Value -isnot [string] -or $Value -cnotin @('','fortis-r7-publisher-activation')){
        throw 'RELEASE_PUBLISHER_VOLUME_RECORD_INVALID'
    }
    return [string]$Value
}
function Read-PublisherActivationDigest {
    param($Record)
    $Volume=Read-PublisherActivationVolume $Record
    if($Record -is [Collections.IDictionary]){
        if(-not $Record.Contains('publisherActivationDigest')){
            if($Volume){throw 'RELEASE_PUBLISHER_DIGEST_RECORD_MISSING'}
            return ''
        }
        $Digest=$Record['publisherActivationDigest']
    } else {
        $Prop=$Record.PSObject.Properties['publisherActivationDigest']
        if($null -eq $Prop){
            if($Volume){throw 'RELEASE_PUBLISHER_DIGEST_RECORD_MISSING'}
            return ''
        }
        $Digest=$Prop.Value
    }
    if($Digest -isnot [string] -or
        ($Volume -and $Digest -cnotmatch '^[0-9a-f]{64}$') -or
        (-not $Volume -and $Digest -cne '')){
        throw 'RELEASE_PUBLISHER_DIGEST_RECORD_INVALID'
    }
    return [string]$Digest
}
function Image-PublisherMount-Preflight {
    param([string]$ImageId)
    # Protect and attest an already owner-provisioned *local Docker volume*.
    # No creating volumes, no printing credentials, no Repo/owner shell access.
    $Name='fortis-r7-publisher-activation'
    Assert-Volume $Name
    Assert-OnlyWriter $Name
    $Code=@'
import sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.integrations.github.publisher_mount_digest import reviewed_mount_digest
print('FORTIS_PUBLISHER_MOUNT_SHA256=' + reviewed_mount_digest())
'@
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<publisher-owner-mount>','exec'))"
    $Args=@('run','--rm','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','32','--memory','128m',
        '--mount',('type=volume,source='+$Name+',target=/run/r7-publisher-activation,readonly'),
        '--entrypoint','python',$ImageId,'-I','-B','-c',$Wrapper)
    $Result=Private-Process $Args ''
    if($Result -cnotmatch '^FORTIS_PUBLISHER_MOUNT_SHA256=([0-9a-f]{64})$'){
        throw 'RELEASE_PUBLISHER_VOLUME_PREFLIGHT_FAILED'
    }
    return [string]$Matches[1]
}

function Get-SourceRecord {
    if($CurrentRecord){$Path=[IO.Path]::GetFullPath($CurrentRecord)}
    elseif(Test-Path -LiteralPath $Pointer){$Path=(Read-Private $Pointer).record}
    else {$Path=Join-Path $env:LOCALAPPDATA 'Fortis\GitHubPilot\review-update-515ad033-native-v3\record.json'}
    $Value=Read-Private $Path
    if($Value.phase -cne 'Complete'){throw 'RELEASE_COMPLETE_SOURCE_REQUIRED'}
    if($Value.schema -ceq 'fortis-extension-release-v1'){$P=$Value.runtime}
    elseif($Value.schema -eq 5 -and $Value.updaterVersion -eq 3 -and $Value.stateProfile -ceq 'native-v1'){
        $P=[ordered]@{pilotId=$Value.pilotId;pilotName=$Value.pilotName;image=$Value.image;stateVolume=$Value.stateVolume
            tokenVolume=$Value.tokenVolume;owner=$Value.owner;repository=$Value.repository;filePrBranch=$Value.filePrBranch
            ciReads=$Value.ciReads;nativeWorktree=$Value.nativeWorktree;requiredWorkflows=$Value.requiredWorkflows
            bootstrapTask=$Value.bootstrapTask;vaultVolume='';extensionsConfig='';releaseNonce='';ownerShell=$false;runId=$Value.runId}
    } else {throw 'RELEASE_SOURCE_PROFILE_UNSUPPORTED'}
    $Hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if(Test-Path -LiteralPath $PrimaryPointer){
        $Primary=Read-Private $PrimaryPointer
        if($Primary.schema -cne 'fortis-primary-v1' -or $Primary.phase -cne 'Complete'){
            throw 'PRIMARY_POINTER_SCHEMA_INVALID'
        }
        if($Primary.sourceRecord -ceq $Path){
            if($Primary.sourceHash -cne $Hash -or $Primary.runtime.pilotId -cne $P.pilotId -or
               $Primary.runtime.image -cne $P.image -or $Primary.runtime.stateVolume -cne $P.stateVolume -or
               $Primary.runtime.runId -cne $P.runId -or
               $Primary.runtime.originalPilotName -cne $P.pilotName -or
               $Primary.runtime.pilotName -cne 'fortis-gateway' -or
               $Primary.runtime.restartPolicy -cne 'unless-stopped'){
                throw 'PRIMARY_POINTER_SOURCE_MISMATCH'
            }
            $P=$Primary.runtime
        }
    }
    $Preserved=Read-PreservedUncertainRequests $P
    if(-not $script:PreserveUncertainRequests){$script:PreserveUncertainRequests=$Preserved}
    elseif($Preserved -and $Preserved -cne $script:PreserveUncertainRequests){
        # Never silently expand a previous release allowlist. An owner may
        # explicitly replace it using a newly built, SHA-pinned source image
        # and an exact match to all current UNCERTAIN IDs.
        if(-not $script:PreserveUncertainExact){
            throw 'RELEASE_UNCERTAIN_RECORD_SCOPE_CHANGED'
        }
    }
    $Claimed=Read-PreservedClaimedJobs $P
    if(-not $script:PreserveClaimedJobs){$script:PreserveClaimedJobs=$Claimed}
    elseif($Claimed -and $Claimed -cne $script:PreserveClaimedJobs){
        if(-not $script:PreserveClaimedExact){throw 'RELEASE_CLAIMED_RECORD_SCOPE_CHANGED'}
    }
    $Approved=Read-PreservedApprovedRequest $P
    if(-not $script:PreserveApprovedRequest){$script:PreserveApprovedRequest=$Approved}
    elseif($Approved -and $Approved -cne $script:PreserveApprovedRequest){
        throw 'RELEASE_APPROVED_RECORD_SCOPE_CHANGED'
    }
    return @{path=$Path;hash=$Hash;runtime=$P}
}

# SHA is of the exact UTF-8 business JSON, never of a temporary copy.
function Sha256-Utf8 {
    param([string]$Value)
    if($null -eq $Value){throw 'RELEASE_AUTO_CONFIG_INVALID'}
    $Hasher=[Security.Cryptography.SHA256]::Create()
    try {return ([BitConverter]::ToString($Hasher.ComputeHash(
        [Text.Encoding]::UTF8.GetBytes($Value))).Replace('-',''))}
    finally {$Hasher.Dispose()}
}

# Checked source SHA and protected receipt authorize reuse of the exact Check-built
# Docker image, never a tag. Recheck source/inputs/state before stopping Gateway.
function Checked-Image-Binding {
    param($Source,$Report)
    $ConfigHash='';$ProbeHash=''
    if($Auto -and $Action -cin @('Check','Apply')){
        $ConfigHash=Sha256-Utf8 $script:AutoConfigText
        $ProbeHash=Sha256-Utf8 $script:AutoProbeText
    } else {
        $ConfigHash=(Get-FileHash -LiteralPath $Config -Algorithm SHA256).Hash
        if($Probes){$ProbeHash=(Get-FileHash -LiteralPath $Probes -Algorithm SHA256).Hash}
    }
    $CurrentHash=''
    if(Test-Path -LiteralPath $Pointer){$CurrentHash=(Get-FileHash -LiteralPath $Pointer -Algorithm SHA256).Hash}
    $PrimaryHash=''
    if(Test-Path -LiteralPath $PrimaryPointer){$PrimaryHash=(Get-FileHash -LiteralPath $PrimaryPointer -Algorithm SHA256).Hash}
    $AttemptHash=''
    if(Test-Path -LiteralPath $AttemptPointer){$AttemptHash=(Get-FileHash -LiteralPath $AttemptPointer -Algorithm SHA256).Hash}
    $BackupPointer=Join-Path $ReleaseBase 'primary-backup.json'
    $BackupHash=''
    if(Test-Path -LiteralPath $BackupPointer){$BackupHash=(Get-FileHash -LiteralPath $BackupPointer -Algorithm SHA256).Hash}
    [ordered]@{
        image=$script:Image;sourceSha=$SourceSha
        sourceRecord=$Source.path;sourceHash=$Source.hash
        sourceContainerId=$Source.runtime.pilotId
        sourceImage=$Source.runtime.image
        sourceStateVolume=$Source.runtime.stateVolume
        sourceRunId=$Source.runtime.runId
        currentPointerHash=$CurrentHash;primaryPointerHash=$PrimaryHash
        attemptPointerHash=$AttemptHash;backupPointerHash=$BackupHash
        publicConfigHash=$ConfigHash;probeHash=$ProbeHash
        configurationDigest=$Report.configurationDigest
        vaultVolume=$VaultVolume
        publisherActivationVolume=$script:PublisherActivationVolume
        publisherActivationDigest=$script:PublisherActivationDigest
        emergencyRescueImage=$EmergencyRescueImage
        emergencyRescueArchiveSha256=$EmergencyRescueArchiveSha256.ToUpperInvariant()
        acceptUnverifiedRestore=[bool]$AcceptUnverifiedRestore
        enableDynamicGitHubRepositories=[bool]$EnableDynamicGitHubRepositories
        enableOwnerShell=[bool]$EnableOwnerShell
        enableActionCoreNetwork=[bool]$EnableActionCoreNetwork
        gatewayNetworks=$script:ActionCoreNetworks
        ciControlRepositories=$CiControlRepositories
        preserveUncertainRequests=$script:PreserveUncertainRequests
        allowUncertainGrowth=[bool]$AllowUncertainGrowth
        preserveClaimedJobs=$script:PreserveClaimedJobs
        preserveApprovedRequest=$script:PreserveApprovedRequest
        requireExactUncertain=$script:PreserveUncertainExact
        requireExactClaimed=$script:PreserveClaimedExact
        requireExactApproved=$script:PreserveApprovedExact
        confirmWorkerQuiescent=[bool]$ConfirmWorkerQuiescent
    }
}
function Save-Checked-Image {
    param($Source,$Report,$Receipt)
    if(-not $Build -or $Action -cne 'Check'){throw 'RELEASE_CHECKED_IMAGE_BUILD_REQUIRED'}
    $Id=[Guid]::NewGuid().ToString('N')
    $Directory=Join-Path $ReleaseBase ('image-check-'+$Id)
    Protect-Directory $Directory
    $Path=Join-Path $Directory 'record.json'
    Write-Private $Path ([ordered]@{
        schema='fortis-extension-image-check-v1';phase='Ready'
        binding=(Checked-Image-Binding $Source $Report);sourceReceipt=$Receipt
        growthWitness=$script:GrowthWitness
    })
    return $Path
}
function Assert-Checked-Image-Binding {
    param($Stored,$Expected)
    if(-not (Same-Json $Stored $Expected)){
        throw 'RELEASE_CHECKED_IMAGE_BINDING_CHANGED'
    }
}
function Verify-Checked-Image {
    param($Source,$Report)
    if(-not $CheckedImageRecord){return}
    $Record=Read-Private $CheckedImageRecord
    if($Record.schema -cne 'fortis-extension-image-check-v1' -or $Record.phase -cne 'Ready' -or
       $null -eq $Record.binding -or $null -eq $Record.sourceReceipt){
        throw 'RELEASE_CHECKED_IMAGE_RECORD_INVALID'
    }
    $Expected=Checked-Image-Binding $Source $Report
    Assert-Checked-Image-Binding $Record.binding $Expected
    $Now=Receipt $Source.runtime.stateVolume -Exact:$script:PreserveUncertainExact -ExactClaimed:$script:PreserveClaimedExact -ExactApproved:$script:PreserveApprovedExact
    if($AllowUncertainGrowth){
        # The original immutable Check receipt and prefix witness are
        # reviewed afresh; no replacement Check binding is ever written.
        if(-not (Same-Json $script:GrowthReviewedReceipt $Now)){
            throw 'RELEASE_GROWTH_SOURCE_STATE_CHANGED'
        }
    } elseif(-not (Same-Json $Record.sourceReceipt $Now)){
        throw 'RELEASE_CHECKED_IMAGE_SOURCE_STATE_CHANGED'
    }
}
function Assert-Checked-Source-Receipt {
    param($Receipt)
    if(-not $CheckedImageRecord){return}
    $Stored=Read-Private $CheckedImageRecord
    if($Stored.schema -cne 'fortis-extension-image-check-v1' -or $Stored.phase -cne 'Ready' -or
       $null -eq $Stored.sourceReceipt){
        throw 'RELEASE_CHECKED_IMAGE_SOURCE_STATE_CHANGED'
    }
    if($AllowUncertainGrowth){
        if(-not (Same-Json $script:GrowthReviewedReceipt $Receipt)){
            throw 'RELEASE_GROWTH_SOURCE_STATE_CHANGED'
        }
    } elseif(-not (Same-Json $Stored.sourceReceipt $Receipt)){
        throw 'RELEASE_CHECKED_IMAGE_SOURCE_STATE_CHANGED'
    }
}
function Emergency-Rescue-Smoke-Argument {
    # Private-Process explicitly rejects double quotes in native argv. Keep
    # Python source inside the same vetted base64 wrapper as State-Helper.
    $Code='import os,runpy;os.environ.pop("FORTIS_OWNER_SHELL_CONFIG",None);runpy.run_path("/opt/fortis/operator/image_smoke.py",run_name="__main__")'
    $Encoded=Code64 $Code
    return "import base64;exec(compile(base64.b64decode('$Encoded'),'<emergency-rescue-smoke>','exec'))"
}
function Assert-Emergency-Rescue {
    param($Source)
    # Explicit one-release risk acceptance; NEVER claim old-image retention or restore tested.
    if(-not $AcceptUnverifiedRestore -or
       $EmergencyRescueImage -cnotmatch '^sha256:[0-9a-f]{64}$' -or
       $EmergencyRescueArchiveSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
       $EmergencyRescueImage -ceq $Source.runtime.image -or
       $EmergencyRescueImage -ceq $script:Image -or
       $Source.runtime.pilotName -cne 'fortis-gateway'){
        throw 'RELEASE_EMERGENCY_RESCUE_INVALID'
    }
    # This is a fixed owner-local archive, never a caller-provided path or remote URL.
    $Directory=Join-Path $env:LOCALAPPDATA 'Fortis\GatewayRecovery'
    $Archive=Join-Path $Directory ('fortis-gateway-rescue-'+$EmergencyRescueImage.Substring(7,12)+'.tar')
    foreach($Path in @($Directory,$Archive)){
        $Item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if($Item.Attributes -band [IO.FileAttributes]::ReparsePoint){
            throw 'RELEASE_EMERGENCY_ARCHIVE_REPARSE_DENIED'
        }
    }
    if(-not (Test-Path -LiteralPath $Archive -PathType Leaf) -or
       (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash -cne
       $EmergencyRescueArchiveSha256.ToUpperInvariant()){
        throw 'RELEASE_EMERGENCY_ARCHIVE_HASH_CHANGED'
    }
    $ImageInfo=@(Docker-Json @('image','inspect',$EmergencyRescueImage))[0]
    if($null -eq $ImageInfo -or $ImageInfo.Id -cne $EmergencyRescueImage){
        throw 'RELEASE_EMERGENCY_RESCUE_IMAGE_CHANGED'
    }
    # A verified state-volume backup is required, although a restore drill
    # has explicitly been waived. Do NOT stop the Gateway to make a new one.
    $BackupPointer=Join-Path $ReleaseBase 'primary-backup.json'
    if(-not (Test-Path -LiteralPath $BackupPointer)){
        throw 'RELEASE_EMERGENCY_STATE_BACKUP_REQUIRED'
    }
    $Backup=Read-Private ((Read-Private $BackupPointer).record)
    if($Backup.schema -cne 'fortis-primary-backup-v1' -or
       $Backup.phase -cne 'Complete' -or
       $Backup.sourceRecord -cne $Source.path -or
       $Backup.sourceHash -cne $Source.hash -or
       $Backup.containerId -cne $Source.runtime.pilotId -or
       $Backup.image -cne $Source.runtime.image -or
       $Backup.stateVolume -cne $Source.runtime.stateVolume -or
       -not (Same-Json (Receipt $Backup.backupVolume) $Backup.receipt)){
        throw 'RELEASE_EMERGENCY_STATE_BACKUP_INVALID'
    }
    # Offline only, no real state, credentials, network or Owner Shell private paths.
    $Wrapper=Emergency-Rescue-Smoke-Argument
    $Smoke=Private-Process @('run','--rm','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','64','--memory','256m','--tmpfs','/tmp:rw,noexec,nosuid,size=32m',
        '--entrypoint','python',$EmergencyRescueImage,'-I','-B','-c',$Wrapper) ''
    foreach($Marker in @('IMAGE_OWNER_INCIDENT_IMPORT_PASS','IMAGE_EXTENSIONS_OFFLINE_PASS',
                         'IMAGE_NATIVE_GIT_IMPORT_PASS','IMAGE_SONAR_OFFLINE_SMOKE_PASS',
                         'IMAGE_GITHUB_NOT_REGISTERED_PASS')){
        if($Smoke -notmatch $Marker){throw 'RELEASE_EMERGENCY_RESCUE_SMOKE_FAILED'}
    }
    Write-Host 'FORTIS_EMERGENCY_UNVERIFIED_RESTORE_OWNER_ACCEPTED'
}
function Assert-Previous-Image-Retained {
    param($Source)
    $Info=$null
    try{$Info=@(Docker-Json @('image','inspect',$Source.runtime.image))[0]}
    catch{
        if(-not $AcceptUnverifiedRestore){throw 'RELEASE_PREVIOUS_IMAGE_MISSING'}
    }
    if($null -ne $Info){
        if($Info.Id -cne $Source.runtime.image){throw 'RELEASE_PREVIOUS_IMAGE_MISSING'}
        if($AcceptUnverifiedRestore){throw 'RELEASE_EMERGENCY_UNNECESSARY'}
        return
    }
    if(-not $AcceptUnverifiedRestore){throw 'RELEASE_PREVIOUS_IMAGE_MISSING'}
    Assert-Emergency-Rescue $Source
}

function Admit {
    param($C,$P,[switch]$AllowUnhealthy,[switch]$AllowPendingIngress)
    if($P.pilotId -and $C.Id -cne $P.pilotId){throw 'RELEASE_CONTAINER_ID_CHANGED'}
    if($C.Config.Labels.'io.fortis.review-update' -cne $P.runId){throw 'RELEASE_CONTAINER_PROVENANCE_INVALID'}
    $Public=Public-Inspect $C
    foreach($Pair in @(@('FORTIS_EXTENSIONS_CONFIG',$P.extensionsConfig),@('FORTIS_RELEASE_NONCE',$P.releaseNonce))){
        $Found=@($Public.Config.Env|Where-Object{$_.StartsWith($Pair[0]+'=')})
        if($Pair[1]){if($Found.Count -ne 1 -or $Found[0] -cne ($Pair[0]+'='+$Pair[1])){throw 'RELEASE_CONFIG_CHANGED'}}
        elseif($Found.Count){throw 'RELEASE_UNEXPECTED_CONFIG'}
        $Public.Config.Env=@($Public.Config.Env|Where-Object{-not $_.StartsWith($Pair[0]+'=')})
    }
    $Expected=@{id=$P.pilotId;name=$P.pilotName;image=$P.image;stateVolume=$P.stateVolume;tokenVolume=$P.tokenVolume
        owner=$P.owner;repository=$P.repository;filePrBranch=$P.filePrBranch;ciReads=$P.ciReads
        nativeWorktree=$P.nativeWorktree;requiredWorkflows=$P.requiredWorkflows;bootstrapTask=$P.bootstrapTask
        dynamicRepositories=(Read-DynamicRepositoriesFlag $P)
        ciControlRepositories=(Read-CiControlRepositories $P)
        vaultVolume=$P.vaultVolume;ownerShell=(Read-OwnerShellFlag $P);status=$C.State.Status;requireHealthy=(-not $AllowUnhealthy)
        publisherActivationVolume=(Read-PublisherActivationVolume $P)}
    if($P.gatewayNetworks){$Expected.gatewayNetworks=$P.gatewayNetworks}
    if($AllowPendingIngress){
        if(-not $P.gatewayNetworks -or $script:R.phase -cne 'Created' -or
           $script:R.activated -or $script:R.probesPassed -or
           $C.State.Status -cne 'created' -or
           $C.State.StartedAt -cne '0001-01-01T00:00:00Z'){
            throw 'RELEASE_PENDING_ACTION_CORE_NETWORK_NOT_PRISTINE'
        }
        $Expected.allowPendingActionNetwork=$true
    }
    if($P.restartPolicy -ceq 'unless-stopped'){
        # The already deployed immutable image still validates the original
        # review name and restart=no. Admit the exact primary rename/policy
        # explicitly, then normalize only those two public fields for the
        # existing image's full security, mount, image and environment audit.
        if($P.pilotName -cne 'fortis-gateway' -or
           $P.originalPilotName -cne ('fortis-github-pilot-'+$P.runId) -or
           $C.Name -cne '/fortis-gateway' -or
           $C.HostConfig.RestartPolicy.Name -cne 'unless-stopped' -or
           $C.HostConfig.RestartPolicy.MaximumRetryCount -ne 0){
            throw 'PRIMARY_RUNTIME_IDENTITY_MISMATCH'
        }
        $Public.Name='/'+$P.originalPilotName
        $Public.HostConfig.RestartPolicy=[ordered]@{Name='no';MaximumRetryCount=0}
        $Expected.name=$P.originalPilotName
    }
    $null=State-Helper @{action='admit';container=$Public;expected=$Expected;pilot=$true}
    if($Expected.publisherActivationVolume){
        $Pinned=Read-PublisherActivationDigest $P
        $Observed=Image-PublisherMount-Preflight -ImageId $P.image
        if($Observed -cne $Pinned){throw 'RELEASE_PUBLISHER_VOLUME_CONTENT_CHANGED'}
    }
}
function Admit-ReturnCandidate {
    param($C,$P)
    if($P.gatewayNetworks -and $script:R.phase -ceq 'Created' -and
       -not $script:R.activated -and -not $script:R.probesPassed -and
       $C.State.Status -ceq 'created' -and
       $C.State.StartedAt -ceq '0001-01-01T00:00:00Z'){
        $Attached=@($C.NetworkSettings.Networks.PSObject.Properties.Name)
        if($Attached.Count -eq 1 -and $Attached[0] -ceq 'fortis-gateway-egress'){
            # Only this never-started intermediate state is return-admissible;
            # no ad-hoc network connect is required to resume the old Gateway.
            Admit $C $P -AllowUnhealthy -AllowPendingIngress
            Write-Host 'FORTIS_ACTION_CORE_RETURN_UNSTARTED_PARTIAL_NETWORK'
            return
        }
    }
    try {Admit $C $P -AllowUnhealthy;return}
    catch {if($_.Exception.Message -cne 'RELEASE_CONFIG_CHANGED'){throw}}
    # Return only: exact released env-builder bug, never-started cloned state.
    if($script:R.phase -cnotin @('Created','Returned') -or $script:R.activated -or $script:R.probesPassed -or
       $C.State.Status -cne 'created' -or $C.State.StartedAt -cne '0001-01-01T00:00:00Z' -or
       $C.State.FinishedAt -cne '0001-01-01T00:00:00Z' -or -not $script:R.sourceReceipt){throw 'RELEASE_RETURN_CANDIDATE_NOT_PRISTINE'}
    $Broken=('FORTIS_EXTENSIONS_CONFIG='+$P.extensionsConfig+' FORTIS_RELEASE_NONCE='+$P.releaseNonce)
    $Actual=@($C.Config.Env|Where-Object{$_.StartsWith('FORTIS_EXTENSIONS_CONFIG=') -or $_.StartsWith('FORTIS_RELEASE_NONCE=')})
    if($Actual.Count -ne 1 -or $Actual[0] -cne $Broken){throw 'RELEASE_RETURN_CONFIG_NOT_KNOWN_BUG'}
    if(-not (Same-Json (Receipt $P.stateVolume) $script:R.sourceReceipt)){throw 'RELEASE_RETURN_CANDIDATE_STATE_CHANGED'}
    # Normalize only the proven broken public pair in an in-memory projection;
    # full image/ID/security/mount/legacy-env admission still has to pass.
    $Copy=$C|ConvertTo-Json -Depth 50 -Compress|ConvertFrom-Json
    $Copy.Config.Env=@($Copy.Config.Env|Where-Object{-not $_.StartsWith('FORTIS_EXTENSIONS_CONFIG=') -and -not $_.StartsWith('FORTIS_RELEASE_NONCE=')})
    $Copy.Config.Env+=@(Extension-EnvLines $P.extensionsConfig $P.releaseNonce)
    Admit $Copy $P -AllowUnhealthy
    Write-Host 'FORTIS_INTEGRATIONS_RETURN_NEVER_STARTED_ENV_BUG'
}
function Snapshot-Uncertain-Growth {
    param([string]$Volume)
    # Shared by standard owner -Auto and explicit manual checked Check.
    # The offline helper validates exact Core/worker/approved state before
    # sealing a witness; this never confers broader mutation privileges.
    State-Helper @{action='uncertain_growth_snapshot';github=$true;native=$true
        preserveClaimedIds=@(Parse-PreservedUncertainRequests $script:PreserveClaimedJobs)
        requireExactClaimed=([bool]$script:PreserveClaimedExact)
        preserveApprovedIds=@(Approved-Ids)
        requireExactApproved=([bool]$script:PreserveApprovedExact)} @('--mount',
        ('type=volume,source='+$Volume+',target=/source,readonly'))
}
function Review-Uncertain-Growth {
    param([string]$Volume)
    if(-not $AllowUncertainGrowth -or -not $CheckedImageRecord){
        throw 'RELEASE_GROWTH_REVIEW_UNAUTHORIZED'
    }
    $Checked=Read-Private $CheckedImageRecord
    if($Checked.schema -cne 'fortis-extension-image-check-v1' -or
       $Checked.phase -cne 'Ready' -or
       $Checked.binding.allowUncertainGrowth -isnot [bool] -or
       -not $Checked.binding.allowUncertainGrowth -or
       $null -eq $Checked.sourceReceipt -or $null -eq $Checked.growthWitness){
        throw 'RELEASE_GROWTH_WITNESS_MISSING'
    }
    $Result=State-Helper @{action='uncertain_growth_review';github=$true;native=$true
        original=$Checked.sourceReceipt;witness=$Checked.growthWitness
        preserveClaimedIds=@(Parse-PreservedUncertainRequests $script:PreserveClaimedJobs)
        requireExactClaimed=([bool]$script:PreserveClaimedExact)
        preserveApprovedIds=@(Approved-Ids)
        requireExactApproved=([bool]$script:PreserveApprovedExact)} @('--mount',
        ('type=volume,source='+$Volume+',target=/source,readonly'))
    if($null -eq $Result.receipt -or $null -eq $Result.uncertainIds -or
       $Result.addedCount -lt 0 -or $Result.addedCount -gt 20){
        throw 'RELEASE_GROWTH_REVIEW_INVALID'
    }
    $Ids=@($Result.uncertainIds)
    if($Ids.Count -gt 20 -or ($Ids -join ',') -cne ((@($Ids|Sort-Object)) -join ',')){
        throw 'RELEASE_GROWTH_IDS_INVALID'
    }
    $script:GrowthEffectiveUncertainRequests=$Ids -join ','
    $script:GrowthReviewedReceipt=$Result.receipt
    return $Result
}
function Effective-Uncertain-Ids {
    if($AllowUncertainGrowth -and $null -ne $script:GrowthEffectiveUncertainRequests){
        return @(Parse-PreservedUncertainRequests $script:GrowthEffectiveUncertainRequests)
    }
    return @(Parse-PreservedUncertainRequests $script:PreserveUncertainRequests)
}
function Receipt {
    param([string]$Volume,[switch]$Exact,[switch]$ExactClaimed,[switch]$ExactApproved)
    if($AllowUncertainGrowth -and $CheckedImageRecord -and
       $Volume -ceq $script:GrowthSourceVolume){
        $null=Review-Uncertain-Growth $Volume
    }
    $Ids=@(Effective-Uncertain-Ids)
    $Claims=@(Parse-PreservedUncertainRequests $script:PreserveClaimedJobs)
    $Approved=@(Approved-Ids)
    State-Helper @{action='inspect';github=$true;native=$true;
        preserveUncertainIds=$Ids;requireExactUncertain=([bool]$Exact);
        preserveClaimedIds=$Claims;requireExactClaimed=([bool]$ExactClaimed);
        preserveApprovedIds=$Approved;requireExactApproved=([bool]$ExactApproved)} @('--mount',
        ('type=volume,source='+$Volume+',target=/source,readonly'))
}
function Same-Json {param($A,$B) (ConvertTo-Json -InputObject $A -Compress -Depth 25) -ceq (ConvertTo-Json -InputObject $B -Compress -Depth 25)}
function Assert-SourceUnchanged {
    if((Get-FileHash -LiteralPath $script:R.source.path -Algorithm SHA256).Hash -cne $script:R.source.hash){throw 'RELEASE_SOURCE_RECORD_CHANGED'}
    Assert-OnlyWriter $script:R.source.runtime.stateVolume
    if($script:R.sourceReceipt -and -not (Same-Json (Receipt $script:R.source.runtime.stateVolume) $script:R.sourceReceipt)){throw 'RELEASE_SOURCE_STATE_CHANGED'}
}
function Return-Source {
    if($script:R.phase -ceq 'Complete' -or $script:R.activated){throw 'RELEASE_ACTIVE_RETURN_REQUIRES_REVIEW'}
    Assert-Release-Production
    $P=$script:R.runtime
    $Names=(Docker-Text @('ps','-a','--format','{{.Names}}')) -split '\r?\n'
    if($Names -ccontains $P.pilotName){
        $C=Container $P.pilotName;Admit-ReturnCandidate $C $P
        if($C.State.Status -ceq 'running'){
            $GateInput=ConvertTo-Json -InputObject @{nonce=$P.releaseNonce;configurationDigest=$script:R.configurationDigest} -Compress
            if((Image-CLI @('gate-record-status') $GateInput -StateVolume $P.stateVolume).active){throw 'RELEASE_ALREADY_ACTIVE_RETURN_REQUIRES_REVIEW'}
            $null=Docker-Text @('stop','--timeout','20',$C.Id)
        } elseif($C.State.Status -cnotin @('created','exited')){throw 'RELEASE_CANDIDATE_STATE_UNKNOWN'}
        $C=Container $C.Id;Admit-ReturnCandidate $C $P
        if($C.State.Status -cnotin @('created','exited')){throw 'RELEASE_STOP_UNCONFIRMED'}
    }
    # After stop: no concurrent effect can race the marker check. Also check when
    # the container disappeared but its retained state volume still exists.
    $Volumes=(Docker-Text @('volume','ls','--format','{{.Name}}')) -split '\r?\n'
    if($Volumes -ccontains $P.stateVolume){
        $GateInput=ConvertTo-Json -InputObject @{nonce=$P.releaseNonce;configurationDigest=$script:R.configurationDigest} -Compress
        $Gate=Image-CLI @('gate-record-status') $GateInput -StateVolume $P.stateVolume
        if($Gate.active){throw 'RELEASE_ALREADY_ACTIVE_RETURN_REQUIRES_REVIEW'}
    }
    $Old=Container $script:R.source.runtime.pilotId;Admit $Old $script:R.source.runtime
    if($Old.State.Status -ceq 'exited'){
        Assert-SourceUnchanged
        $null=Docker-Text @('start',$Old.Id);Wait-Healthy $Old.Id
    } elseif($Old.State.Status -cne 'running'){throw 'RELEASE_SOURCE_STATE_UNKNOWN'}
    Assert-Release-Production;$script:R.phase='Returned';Save
    Write-Host 'FORTIS_INTEGRATIONS_RETURNED_SOURCE'
}
function Complete-ActionCoreNetwork {
    param($C,$P)
    if(-not $P.gatewayNetworks){return $C}
    $Now=Read-ActionCoreBoundary
    if(-not (Same-Json $Now $P.gatewayNetworks)){
        throw 'RELEASE_ACTION_CORE_BOUNDARY_CHANGED'
    }
    $Attached=@($C.NetworkSettings.Networks.PSObject.Properties.Name)
    if($Attached.Count -eq 1 -and $Attached[0] -ceq 'fortis-gateway-egress'){
        # A retried owner Resume may complete an interrupted create, but may
        # never issue a second connect or attach any arbitrary Docker network.
        Admit $C $P -AllowUnhealthy -AllowPendingIngress
        Step 'ATTACH_ACTION_CORE_NETWORK'
        $null=Docker-Text @('network','connect','fortis-actioncore-net',$C.Id)
        $C=Container $C.Id
    }
    Admit $C $P -AllowUnhealthy
    return $C
}
function Resume-Target {
    $P=$script:R.runtime;$C=Container $P.pilotName
    $C=Complete-ActionCoreNetwork $C $P
    Admit $C $P -AllowUnhealthy
    if($C.State.Status -ceq 'created' -or $C.State.Status -ceq 'exited'){
        Assert-OnlyWriter $P.stateVolume;$null=Docker-Text @('start',$C.Id)
    }
    Wait-Healthy $C.Id;Admit (Container $C.Id) $P
    $script:R.runtime.pilotId=$C.Id;$script:R.phase='Staged';Save
    $Gate=Running-CLI $C.Id @('gate-status')
    if($Gate.configurationDigest -cne $script:R.configurationDigest){throw 'RELEASE_RUNNING_DIGEST_MISMATCH'}
    if(-not $Gate.active){
        Step 'VERIFY_STAGED_CATALOG'
        $Catalog=Running-CLI $C.Id @('catalog')
        if($Catalog.configurationDigest -cne $script:R.configurationDigest -or @($Catalog.operations|Where-Object{$_.policy -cne 'DENY' -and -not $_.ready}).Count){throw 'RELEASE_CATALOG_NOT_READY'}
        $RepoCatalog=Repo-JSON "import json;from fortis_approvals.extensions.client import default_client;print(json.dumps(default_client().catalog()))"
        if($RepoCatalog.configurationDigest -cne $script:R.configurationDigest){throw 'RELEASE_REPO_CATALOG_MISMATCH'}
        $null=Running-CLI $C.Id @('probe') $script:R.probes
        if($P.gatewayNetworks){
            Step 'VERIFY_ACTION_CORE_HTTP8000_DENIAL'
            Assert-ActionCoreNoHttpFromGateway $C.Id
        }
        if(Read-OwnerShellFlag $P){
            Step 'VERIFY_STAGED_OWNER_SHELL_MTLS'
            Running-OwnerShell-Check $C.Id
        }
        $script:R.probesPassed=$true;Save
        Assert-SourceUnchanged;Assert-Release-Production
        Step 'ACTIVATE'
        $Activated=Running-CLI $C.Id @('activate') '' -Root
        if($Activated.status -cne 'ACTIVATED'){throw 'RELEASE_ACTIVATION_NOT_CONFIRMED'}
    } elseif(-not $script:R.probesPassed){throw 'RELEASE_ACTIVE_WITHOUT_PROBE_RECEIPT'}
    $script:R.activated=$true;$script:R.phase='Complete';Save
    Write-Private $Pointer @{schema=1;record=$script:RecordPath}
    [ordered]@{record=$script:RecordPath;image=$P.image;configurationDigest=$script:R.configurationDigest
        active=$true;previousRetained=$true;productionUnchanged=$true;providerMutationAcceptance='PENDING_OR_NOT_APPLICABLE'}|ConvertTo-Json
    Write-Host 'FORTIS_INTEGRATIONS_ACTIVATED'
}

. (Join-Path $PSScriptRoot 'Primary-Gateway.ps1')
. (Join-Path $PSScriptRoot 'Provider-Credentials.ps1')

if($Service -and $Action -cne 'Credential'){throw 'CREDENTIAL_SERVICE_ACTION_INVALID'}
if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or $PSVersionTable.PSEdition -cne 'Desktop'){throw 'RELEASE_WINDOWS_POWERSHELL_51_REQUIRED'}
if(@(Json-Items '[{"Id":"one"},{"Id":"two"}]').Count -ne 2 -or @(Json-Items '[{"Id":"one"}]')[0].Id -cne 'one'){throw 'RELEASE_JSON_SELFTEST_FAILED'}
if($Action -eq 'SelfTest'){
    Assert-BoundedReleaseJsonSelfTest
    # Ensure the private native-argv restriction cannot break the rescue smoke.
    $RescueSmokeArgument=Emergency-Rescue-Smoke-Argument
    if(-not $RescueSmokeArgument -or $RescueSmokeArgument.Contains('"') -or
       $RescueSmokeArgument.EndsWith([string][char]92) -or
       $RescueSmokeArgument -cnotmatch '^import base64;exec\(compile\(base64\.b64decode\('){
        throw 'RELEASE_EMERGENCY_SMOKE_ARG_SELFTEST_FAILED'
    }
    if($ForwardParameters['Action'] -cne 'SelfTest' -or $ForwardParameters.ContainsKey('Mode')){throw 'RELEASE_PARAMETER_FORWARDING_SELFTEST_FAILED'}
    $Sample='{"schemaVersion":1,"providers":{}}'
    $Nonce='11111111-1111-4111-8111-111111111111'
    $Lines=@(Extension-EnvLines $Sample $Nonce)
    Check-ExtensionEnv $Lines $Sample $Nonce
    $Denied=$false
    try {Check-ExtensionEnv @('FORTIS_EXTENSIONS_CONFIG='+$Sample+' FORTIS_RELEASE_NONCE='+$Nonce) $Sample $Nonce}
    catch {if($_.Exception.Message -cne 'RELEASE_CONFIG_CHANGED'){throw};$Denied=$true}
    if(-not $Denied){throw 'RELEASE_MALFORMED_ENV_SELFTEST_FAILED'}
    $Forwarded=@(Forward-NativeParameters @{SourceSha='a value with spaces';Build=([switch]$true);Pull=([switch]$false)})
    $OldRecord='{"schema":1}' | ConvertFrom-Json
    $NewRecord='{"dynamicRepositories":true}' | ConvertFrom-Json
    $WrongRecord='{"dynamicRepositories":"false"}' | ConvertFrom-Json
    if((Read-DynamicRepositoriesFlag $OldRecord) -or
        -not (Read-DynamicRepositoriesFlag $NewRecord) -or
        (Read-DynamicRepositoriesFlag @{}) -or
        -not (Read-DynamicRepositoriesFlag @{dynamicRepositories=$true})){
        throw 'RELEASE_DYNAMIC_RECORD_COMPATIBILITY_SELFTEST_FAILED'
    }
    $Rejected=$false
    try{$null=Read-DynamicRepositoriesFlag $WrongRecord}
    catch{if($_.Exception.Message -cne 'RELEASE_DYNAMIC_RECORD_INVALID'){throw};$Rejected=$true}
    if(-not $Rejected){throw 'RELEASE_DYNAMIC_RECORD_TYPE_SELFTEST_FAILED'}
    $CiOldRecord='{"schema":1}' | ConvertFrom-Json
    $CiNewRecord='{"ciControlRepositories":"rd-graphs"}' | ConvertFrom-Json
    $CiBadRecord='{"ciControlRepositories":"rd-graphs,rd-graphs"}' | ConvertFrom-Json
    if((Read-CiControlRepositories $CiOldRecord) -cne '' -or
       (Read-CiControlRepositories $CiNewRecord) -cne 'rd-graphs'){
        throw 'RELEASE_CI_CONTROL_RECORD_COMPATIBILITY_SELFTEST_FAILED'
    }
    $CiRejected=$false
    try{$null=Read-CiControlRepositories $CiBadRecord}
    catch{if($_.Exception.Message -cne 'RELEASE_CI_CONTROL_RECORD_INVALID'){throw};$CiRejected=$true}
    if(-not $CiRejected){throw 'RELEASE_CI_CONTROL_RECORD_VALIDATION_SELFTEST_FAILED'}
    $CiForward=@(Forward-NativeParameters @{CiControlRepositories='rd-graphs'})
    if($CiForward.Count -ne 2 -or $CiForward -cnotcontains '-CiControlRepositories' -or
        $CiForward[1] -cne 'rd-graphs'){
        throw 'RELEASE_CI_CONTROL_FLAG_FORWARDING_SELFTEST_FAILED'
    }
    $OldUnknown='{"schema":1}' | ConvertFrom-Json
    $NewUnknown='{"preserveUncertainRequests":"11111111-1111-4111-8111-111111111111"}' | ConvertFrom-Json
    if((Read-PreservedUncertainRequests $OldUnknown) -cne '' -or
        (Read-PreservedUncertainRequests $NewUnknown) -cne '11111111-1111-4111-8111-111111111111'){
        throw 'RELEASE_UNCERTAIN_RECORD_SELFTEST_FAILED'
    }
    $BadScope=$false
    try {$null=@(Parse-PreservedUncertainRequests 'a,b')}
    catch {if($_.Exception.Message -cne 'RELEASE_UNCERTAIN_SCOPE_INVALID'){throw};$BadScope=$true}
    if(-not $BadScope){throw 'RELEASE_UNCERTAIN_SCOPE_SELFTEST_FAILED'}
    $OldClaim='{"schema":1}' | ConvertFrom-Json
    $NewClaim='{"preserveClaimedJobs":"11111111-1111-4111-8111-111111111111"}' | ConvertFrom-Json
    if((Read-PreservedClaimedJobs $OldClaim) -cne '' -or
        (Read-PreservedClaimedJobs $NewClaim) -cne '11111111-1111-4111-8111-111111111111'){
        throw 'RELEASE_CLAIMED_RECORD_SELFTEST_FAILED'
    }
    $ClaimForward=@(Forward-NativeParameters @{
        PreserveClaimedJobs='11111111-1111-4111-8111-111111111111';
        ConfirmWorkerQuiescent=([switch]$true)})
    if($ClaimForward.Count -ne 3 -or $ClaimForward -cnotcontains '-PreserveClaimedJobs' -or
        $ClaimForward -cnotcontains '-ConfirmWorkerQuiescent'){
        throw 'RELEASE_CLAIMED_FLAG_FORWARD_SELFTEST_FAILED'
    }
    $OldApproved='{"schema":1}' | ConvertFrom-Json
    $NewApproved='{"preserveApprovedRequest":"11111111-1111-4111-8111-111111111111"}' | ConvertFrom-Json
    if((Read-PreservedApprovedRequest $OldApproved) -cne '' -or
        (Read-PreservedApprovedRequest $NewApproved) -cne '11111111-1111-4111-8111-111111111111'){
        throw 'RELEASE_APPROVED_RECORD_SELFTEST_FAILED'
    }
    $ApprovedForward=@(Forward-NativeParameters @{
        PreserveApprovedRequest='11111111-1111-4111-8111-111111111111'})
    if($ApprovedForward.Count -ne 2 -or $ApprovedForward -cnotcontains '-PreserveApprovedRequest'){
        throw 'RELEASE_APPROVED_FLAG_FORWARD_SELFTEST_FAILED'
    }
    $SavedApproved=$script:PreserveApprovedRequest
    try {
        $script:PreserveApprovedRequest='11111111-1111-4111-8111-111111111111'
        $ApprovedScope=@(Approved-Ids)
        Assert-ApprovedScopeForwarded @{action='inspect';preserveApprovedIds=$ApprovedScope}
        Assert-ApprovedScopeForwarded @{action='clone';preserveApprovedIds=$ApprovedScope}
        $Rejected=$false
        try{Assert-ApprovedScopeForwarded @{action='inspect';preserveApprovedIds=@()}}
        catch{if($_.Exception.Message -cne 'RELEASE_APPROVED_SCOPE_NOT_FORWARDED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_APPROVED_SCOPE_FORWARD_SELFTEST_FAILED'}
        $Rejected=$false
        try{Assert-ApprovedScopeForwarded @{
            action='inspect';preserveApprovedIds=@('22222222-2222-4222-8222-222222222222')}}
        catch{if($_.Exception.Message -cne 'RELEASE_APPROVED_SCOPE_NOT_FORWARDED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_APPROVED_SCOPE_WRONG_ID_SELFTEST_FAILED'}
        $script:PreserveApprovedRequest='11111111-1111-4111-8111-111111111111,22222222-2222-4222-8222-222222222222'
        $Both=@(Approved-Ids)
        if($Both.Count -ne 2){throw 'RELEASE_APPROVED_MULTI_SCOPE_SELFTEST_FAILED'}
        Assert-ApprovedScopeForwarded @{action='inspect';preserveApprovedIds=$Both}
        $Rejected=$false
        try{Assert-ApprovedScopeForwarded @{action='clone';preserveApprovedIds=@($Both[0])}}
        catch{if($_.Exception.Message -cne 'RELEASE_APPROVED_SCOPE_NOT_FORWARDED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_APPROVED_MULTI_SCOPE_SELFTEST_FAILED'}
    } finally { $script:PreserveApprovedRequest=$SavedApproved }
    $ScriptWasUnscoped=$script:PreserveApprovedRequest
    try {
        $script:PreserveApprovedRequest=''
        $Rejected=$false
        try{Assert-ApprovedScopeForwarded @{action='inspect';preserveApprovedIds=@(
            '11111111-1111-4111-8111-111111111111')}}
        catch{if($_.Exception.Message -cne 'RELEASE_APPROVED_SCOPE_UNEXPECTED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_APPROVED_SCOPE_WIDEN_SELFTEST_FAILED'}
    } finally { $script:PreserveApprovedRequest=$ScriptWasUnscoped }
    $Disabled=@(OwnerShell-EnvLines $false)
    $Enabled=@(OwnerShell-EnvLines $true)
    if($Disabled.Count -ne 0 -or $Enabled.Count -ne 1){throw 'RELEASE_OWNER_SHELL_ENV_SELFTEST_FAILED'}
    Check-OwnerShellEnv $Disabled $false
    Check-OwnerShellEnv $Enabled $true
    $Rejected=$false
    try {Check-OwnerShellEnv @('FORTIS_OWNER_SHELL_CONFIG={}') $true}
    catch {if($_.Exception.Message -cne 'RELEASE_OWNER_SHELL_ENV_MISMATCH'){throw};$Rejected=$true}
    if(-not $Rejected){throw 'RELEASE_OWNER_SHELL_ENV_SELFTEST_FAILED'}
    $Rejected=$false
    try {Check-OwnerShellEnv @($Enabled[0],$Enabled[0]) $true}
    catch {if($_.Exception.Message -cne 'RELEASE_OWNER_SHELL_ENV_MISMATCH'){throw};$Rejected=$true}
    if(-not $Rejected){throw 'RELEASE_OWNER_SHELL_ENV_SELFTEST_FAILED'}
    $Unexpected=$false
    try {Check-OwnerShellEnv $Enabled $false}
    catch {if($_.Exception.Message -cne 'RELEASE_OWNER_SHELL_UNEXPECTED_ENV'){throw};$Unexpected=$true}
    if(-not $Unexpected){throw 'RELEASE_OWNER_SHELL_ENV_SELFTEST_FAILED'}
    $OwnerOld='{"schema":1}' | ConvertFrom-Json
    $OwnerNew='{"ownerShell":true}' | ConvertFrom-Json
    $OwnerInvalid='{"ownerShell":"true"}' | ConvertFrom-Json
    if((Read-OwnerShellFlag $OwnerOld) -or -not (Read-OwnerShellFlag $OwnerNew)){
        throw 'RELEASE_OWNER_SHELL_RECORD_SELFTEST_FAILED'
    }
    $Rejected=$false
    try{$null=Read-OwnerShellFlag $OwnerInvalid}
    catch{if($_.Exception.Message -cne 'RELEASE_OWNER_SHELL_RECORD_INVALID'){throw};$Rejected=$true}
    if(-not $Rejected){throw 'RELEASE_OWNER_SHELL_RECORD_SELFTEST_FAILED'}
    $Flag=@(Forward-NativeParameters @{EnableOwnerShell=([switch]$true)})
    if($Flag.Count -ne 1 -or $Flag[0] -cne '-EnableOwnerShell'){
        throw 'RELEASE_OWNER_SHELL_FLAG_FORWARDING_SELFTEST_FAILED'
    }
    # Owner-only publisher volume defaults off, and protected releases must
    # reject forged names/digests before any Docker/owner writes.
    $PublisherOld='{"schema":1}'|ConvertFrom-Json
    $PublisherGood='{"publisherActivationVolume":"fortis-r7-publisher-activation","publisherActivationDigest":"'+('a'*64)+'"}'|ConvertFrom-Json
    $PublisherBad='{"publisherActivationVolume":"../../owner"}'|ConvertFrom-Json
    if((Read-PublisherActivationVolume $PublisherOld) -cne '' -or
       (Read-PublisherActivationDigest $PublisherOld) -cne '' -or
       (Read-PublisherActivationVolume $PublisherGood) -cne 'fortis-r7-publisher-activation' -or
       (Read-PublisherActivationDigest $PublisherGood) -cne ('a'*64)){
        throw 'RELEASE_PUBLISHER_RECORD_SELFTEST_FAILED'
    }
    $PublisherRejected=$false
    try{$null=Read-PublisherActivationVolume $PublisherBad}
    catch{if($_.Exception.Message -cne 'RELEASE_PUBLISHER_VOLUME_RECORD_INVALID'){throw};$PublisherRejected=$true}
    if(-not $PublisherRejected){throw 'RELEASE_PUBLISHER_RECORD_SELFTEST_FAILED'}
    $PublisherRejected=$false
    try{$null=Read-PublisherActivationDigest ('{"publisherActivationVolume":"fortis-r7-publisher-activation"}'|ConvertFrom-Json)}
    catch{if($_.Exception.Message -cne 'RELEASE_PUBLISHER_DIGEST_RECORD_MISSING'){throw};$PublisherRejected=$true}
    if(-not $PublisherRejected){throw 'RELEASE_PUBLISHER_RECORD_SELFTEST_FAILED'}
    $PublisherFlag=@(Forward-NativeParameters @{EnablePublisherMount=([switch]$true)})
    if($PublisherFlag.Count -ne 1 -or $PublisherFlag[0] -cne '-EnablePublisherMount'){
        throw 'RELEASE_PUBLISHER_FLAG_FORWARDING_SELFTEST_FAILED'
    }
    $GrowthFlag=@(Forward-NativeParameters @{AllowUncertainGrowth=([switch]$true)})
    if($GrowthFlag.Count -ne 1 -or $GrowthFlag[0] -cne '-AllowUncertainGrowth'){
        throw 'RELEASE_GROWTH_FLAG_FORWARDING_SELFTEST_FAILED'
    }
    $Multi=@(Forward-NativeParameters @{EnableDynamicGitHubRepositories=([switch]$true)})
    if($Multi.Count -ne 1 -or $Multi[0] -cne '-EnableDynamicGitHubRepositories'){throw 'RELEASE_DYNAMIC_FLAG_FORWARDING_SELFTEST_FAILED'}
    $NetFlag=@(Forward-NativeParameters @{EnableActionCoreNetwork=([switch]$true)})
    if($NetFlag.Count -ne 1 -or $NetFlag[0] -cne '-EnableActionCoreNetwork'){
        throw 'RELEASE_ACTION_CORE_FLAG_FORWARDING_SELFTEST_FAILED'
    }
    $Index=[array]::IndexOf($Forwarded,'-SourceSha')
    if($Forwarded.Count -ne 3 -or $Forwarded -cnotcontains '-Build' -or $Index -lt 0 -or
       $Forwarded[$Index+1] -cne 'a value with spaces'){throw 'RELEASE_NATIVE_ARGUMENT_SELFTEST_FAILED'}
    $Binding=@{image=('sha256:'+('a'*64));sourceSha=('b'*40);confirmWorkerQuiescent=$true}
    Assert-Checked-Image-Binding $Binding $Binding
    $WrongBinding=@{image=('sha256:'+('c'*64));sourceSha=('b'*40);confirmWorkerQuiescent=$true}
    $Rejected=$false
    try{Assert-Checked-Image-Binding $Binding $WrongBinding}
    catch{if($_.Exception.Message -cne 'RELEASE_CHECKED_IMAGE_BINDING_CHANGED'){throw};$Rejected=$true}
    if(-not $Rejected){throw 'RELEASE_CHECKED_IMAGE_BINDING_SELFTEST_FAILED'}
    $WrongQuiescence=@{image=('sha256:'+('a'*64));sourceSha=('b'*40);confirmWorkerQuiescent=$false}
    $Rejected=$false
    try{Assert-Checked-Image-Binding $Binding $WrongQuiescence}
    catch{if($_.Exception.Message -cne 'RELEASE_CHECKED_IMAGE_BINDING_CHANGED'){throw};$Rejected=$true}
    if(-not $Rejected){throw 'RELEASE_CHECKED_IMAGE_QUIESCENCE_SELFTEST_FAILED'}
    Write-Host 'FORTIS_INTEGRATIONS_SELFTEST_PASS';return
}
if(-not (Test-Path -LiteralPath $ReleaseBase)){Protect-Directory $ReleaseBase}else{Assert-DirectoryAcl $ReleaseBase}
# Owner-local convenience only. All effects still pass the SAME protected
# Check / checked-image Apply / Backup / Promote controller state machine.
# Never turn a Core UNCERTAIN or CLAIMED job into a retry or completion.
$script:AutoCheckPointer=Join-Path $ReleaseBase 'auto-check.json'
$script:AutoConfigText=$null;$script:AutoProbeText=$null
if($Auto){
    if($Action -cnotin @('Check','Apply','Backup','Promote') -or
        $Config -or $Probes -or $Image -or $CheckedImageRecord -or $SourceSha -or
        $Build -or $Pull -or $CurrentRecord -or $AttemptRecord -or
        $PreserveUncertainRequests -or $PreserveClaimedJobs -or $PreserveApprovedRequest -or $AllowUncertainGrowth -or
        $EnableDynamicGitHubRepositories -or $EnableOwnerShell -or $EnableActionCoreNetwork -or
        $CiControlRepositories -or
        $ConfirmWorkerQuiescent -or $EmergencyRescueImage -or
        $EmergencyRescueArchiveSha256 -or $AcceptUnverifiedRestore -or
        $VaultVolume -cne 'fortis-review-secrets' -or $EnablePublisherMount){
        throw 'RELEASE_AUTO_MANUAL_ARGUMENTS_DENIED'
    }
    if($Action -cin @('Check','Apply')){
        # Standard owner -Auto reuses the SAME checked-image witness and
        # fail-closed append-only Core guard as manual Check/Apply. This does
        # not opt into publisher, owner-shell, new grants, or APPROVED carryover.
        $AllowUncertainGrowth=[switch]$true
        $Git=(Get-Command git.exe -CommandType Application).Source
        if((Private-Process @('-C',$SourceRoot,'status','--porcelain') '' $Git)){
            throw 'RELEASE_WINDOWS_SOURCE_DIRTY'
        }
        if((Private-Process @('-C',$SourceRoot,'branch','--show-current') '' $Git) -cne 'main'){
            throw 'RELEASE_WINDOWS_MAIN_REQUIRED'
        }
        $LocalSha=Private-Process @('-C',$SourceRoot,'rev-parse','HEAD') '' $Git
        if($LocalSha -cnotmatch '^[0-9a-f]{40}$'){throw 'RELEASE_AUTO_SOURCE_INVALID'}
        if($Action -eq 'Check'){
            $SourceSha=$LocalSha
            $Build=[switch]$true
        } else {
            if(-not (Test-Path -LiteralPath $script:AutoCheckPointer)){
                throw 'RELEASE_AUTO_CHECK_NOT_READY'
            }
            $Selection=Read-Private $script:AutoCheckPointer
            if($Selection.schema -cne 'fortis-auto-check-v1' -or
                $Selection.sourceSha -cne $LocalSha -or
                $Selection.image -cnotmatch '^sha256:[0-9a-f]{64}$' -or
                -not $Selection.record){throw 'RELEASE_AUTO_CHECK_BINDING_INVALID'}
            $CheckedImageRecord=[string]$Selection.record
            $SavedCheck=Read-Private $CheckedImageRecord
            if($SavedCheck.schema -cne 'fortis-extension-image-check-v1' -or
                $SavedCheck.phase -cne 'Ready' -or
                $SavedCheck.binding.image -cne $Selection.image -or
                $SavedCheck.binding.sourceSha -cne $LocalSha -or
                $SavedCheck.binding.allowUncertainGrowth -isnot [bool] -or
                -not $SavedCheck.binding.allowUncertainGrowth -or
                $null -eq $SavedCheck.growthWitness -or
                $null -eq $SavedCheck.sourceReceipt){
                # An old -Auto Check created before witness support cannot
                # authorize this flow. The owner must run a fresh Check.
                throw 'RELEASE_AUTO_CHECK_GROWTH_WITNESS_REQUIRED'
            }
            $SourceSha=$LocalSha;$Image=[string]$Selection.image
            $script:Image=$Image
        }
        # Check remote merge identity and read global unresolved evidence via
        # existing machine TLS/typed READ, never via GitHub token or direct API.
        $ReadCode=@'
import json
from fortis_approvals.workflow.client import default_client
c=default_client()
sha='__EXACT_HEAD_SHA__'
branches=[]
for page in range(1,21):
    branch_page=c.github.list_branches('fortis-approvals',page=page,per_page=100)['items']
    if type(branch_page) is not list or len(branch_page)>100:
        raise RuntimeError('RELEASE_BRANCH_PAGE_INVALID')
    branches.extend(branch_page)
    if len(branch_page)<100:
        break
else:
    raise RuntimeError('RELEASE_BRANCH_PAGE_LIMIT')
branch_names=[b['name'] for b in branches]
if len(branch_names)!=len(set(branch_names)):
    raise RuntimeError('RELEASE_BRANCH_DUPLICATE')
if sum(b['name']=='main' and b['sha']==sha for b in branches)!=1:
    raise RuntimeError('RELEASE_REMOTE_MAIN_MISMATCH')
caps=c.gateway.post('/v1/workspace/capabilities',{})
assert caps.get('globalRequestInventory',{}).get('crossActorDetails') is True, 'RELEASE_GLOBAL_INVENTORY_REQUIRED'
records=[];offset=0
for _ in range(20):
    d=c.list_requests(offset=offset,limit=100,unresolved_only=True)
    assert d['offset']==offset and d['unresolvedOnly'] is True and type(d['items']) is list, 'RELEASE_INVENTORY_INVALID'
    records.extend(d['items'])
    if d['nextOffset'] is None:
        assert not d['truncated'] and d['total']==len(records), 'RELEASE_INVENTORY_INCOMPLETE'
        break
    assert d['nextOffset']==offset+len(d['items']) and len(d['items'])>0, 'RELEASE_INVENTORY_OFFSET_INVALID'
    offset=d['nextOffset']
else: raise RuntimeError('RELEASE_INVENTORY_PAGE_LIMIT')
assert len(records)==len({r['requestId'] for r in records}), 'RELEASE_INVENTORY_DUPLICATE'
states={x:sorted(r['requestId'] for r in records if r['state']==x)
        for x in ('UNCERTAIN','APPROVED','PENDING','DISPATCHED')}
assert len(records)==sum(len(x) for x in states.values()), 'RELEASE_INVENTORY_STATE_UNKNOWN'
activity=[];offset=0
for _ in range(20):
    d=c.activity(offset=offset,limit=100)
    assert d['offset']==offset and type(d['items']) is list, 'RELEASE_ACTIVITY_INVALID'
    activity.extend(d['items'])
    if d['nextOffset'] is None:
        assert not d['truncated'] and d['total']==len(activity), 'RELEASE_ACTIVITY_INCOMPLETE'
        break
    assert d['nextOffset']==offset+len(d['items']) and len(d['items'])>0, 'RELEASE_ACTIVITY_OFFSET_INVALID'
    offset=d['nextOffset']
else: raise RuntimeError('RELEASE_ACTIVITY_PAGE_LIMIT')
assert all(x['jobState']=='CLAIMED' for x in activity), 'RELEASE_ACTIVITY_UNEXPECTED_JOB'
claims=sorted(x['requestId'] for x in activity)
assert len(claims)==len(set(claims)),'RELEASE_CLAIMED_DUPLICATE'
assert len(states['UNCERTAIN'])<=20 and len(states['APPROVED'])<=20 and len(claims)<=3, 'RELEASE_SCOPE_TOO_LARGE'
print(json.dumps({'schema':1,'sourceSha':sha,'uncertain':states['UNCERTAIN'],
    'approved':states['APPROVED'],'pending':states['PENDING'],
    'dispatched':states['DISPATCHED'],'claimed':claims},sort_keys=True))
'@
        $ReadCode=$ReadCode.Replace('__EXACT_HEAD_SHA__',$SourceSha)
        $Snapshot=Repo-JSON $ReadCode
        if($Snapshot.schema -ne 1 -or $Snapshot.sourceSha -cne $SourceSha -or
            $null -eq $Snapshot.uncertain -or $null -eq $Snapshot.approved -or
            $null -eq $Snapshot.pending -or $null -eq $Snapshot.dispatched -or
            $null -eq $Snapshot.claimed){throw 'RELEASE_AUTO_READBACK_INVALID'}
        if(@($Snapshot.pending).Count -or @($Snapshot.dispatched).Count -or
            @($Snapshot.approved).Count){
            # Approved needs a separate owner-reviewed exact scope, not an
            # automatic blanket carryover. Existing manual controller remains.
            throw 'RELEASE_AUTO_OWNER_REVIEW_REQUIRED'
        }
        if($Action -eq 'Apply'){
            # Bind to the ORIGINAL checked-image scope, never the freshly
            # observed list. The shared growth helper may admit only audited
            # new UNCERTAIN rows and leaves the immutable Check untouched.
            $OriginalIds=@(Parse-PreservedUncertainRequests ([string]$SavedCheck.binding.preserveUncertainRequests))
            $ObservedIds=@($Snapshot.uncertain)
            $Missing=@($OriginalIds | Where-Object { $ObservedIds -cnotcontains $_ })
            if($Missing.Count -or $ObservedIds.Count -lt $OriginalIds.Count){
                throw 'RELEASE_AUTO_UNCERTAIN_SCOPE_REDUCED'
            }
            $script:PreserveUncertainRequests=$OriginalIds -join ','
        } else {
            # Check is bound to its final offline snapshot; the Repo READ
            # inventory is advisory, not authorization to alter Core rows.
            $script:PreserveUncertainRequests=@($Snapshot.uncertain) -join ','
        }
        $script:PreserveUncertainExact=($script:PreserveUncertainRequests -ne '')
        $script:PreserveClaimedJobs=@($Snapshot.claimed) -join ','
        $script:PreserveClaimedExact=($script:PreserveClaimedJobs -ne '')
        $Source=Get-SourceRecord  # ACL checked, validates prior scopes
        # Check must not manufacture a READY release while a previous
        # attempt remains unresolved or its rollback image is missing.
        if(Test-Path -LiteralPath $AttemptPointer){
            $PriorPointer=Read-Private $AttemptPointer
            $Prior=Read-Private $PriorPointer.record
            if($Prior.phase -cnotin @('Complete','Returned')){
                throw 'RELEASE_PRIOR_ATTEMPT_REQUIRES_RESUME_OR_RETURN'
            }
        }
        Assert-Previous-Image-Retained $Source
        # Preserve the currently installed trusted vault identity; never
        # synthesize another vault or fall back to an unrelated credential.
        if($Source.runtime.vaultVolume -isnot [string] -or
            $Source.runtime.vaultVolume -cnotmatch '^fortis-review-secrets(?:-[a-z0-9-]{1,48})?$'){
            throw 'RELEASE_AUTO_VAULT_INVALID'
        }
        $VaultVolume=$Source.runtime.vaultVolume
        $script:AutoConfigText=[string]$Source.runtime.extensionsConfig
        $SourceRecord=Read-Private $Source.path
        $script:AutoProbeText=$SourceRecord.probes
        if(-not $script:AutoConfigText -or
            $script:AutoConfigText.Length -gt 262144 -or
            $script:AutoProbeText -isnot [string] -or
            -not $script:AutoProbeText){throw 'RELEASE_AUTO_CONFIG_NOT_RETAINED'}
        Write-Host ('FORTIS_RELEASE_AUTO_SCOPE_READY sha='+$SourceSha+
            ' uncertain='+@($Snapshot.uncertain).Count+
            ' claimed='+@($Snapshot.claimed).Count)
    }
    $OwnerQuiescence=Read-Host 'Independently verified no active workers? Type QUIESCENT'
    if($OwnerQuiescence -cne 'QUIESCENT'){
        throw 'RELEASE_AUTO_QUIESCENCE_NOT_ATTESTED'
    }
    $ConfirmWorkerQuiescent=[switch]$true
    if($Action -eq 'Apply'){
        $OwnerGo=Read-Host ('Apply checked Gateway image for '+$SourceSha+'? Type APPLY')
        if($OwnerGo -cne 'APPLY'){throw 'RELEASE_AUTO_OWNER_GO_REQUIRED'}
    }
    if($Action -cin @('Backup','Promote')){
        $OwnerGo=Read-Host ('Run protected '+$Action+'? Type '+$Action.ToUpperInvariant())
        if($OwnerGo -cne $Action.ToUpperInvariant()){
            throw 'RELEASE_AUTO_OWNER_GO_REQUIRED'
        }
    }
}
if($Pull -and -not $Build){throw 'RELEASE_PULL_REQUIRES_BUILD'}
$EmergencyRequested=([bool]$EmergencyRescueImage -or [bool]$EmergencyRescueArchiveSha256 -or [bool]$AcceptUnverifiedRestore)
if($EmergencyRequested -and (-not $AcceptUnverifiedRestore -or
    $EmergencyRescueImage -cnotmatch '^sha256:[0-9a-f]{64}$' -or
    $EmergencyRescueArchiveSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
    $Action -cnotin @('Check','Apply') -or $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or
    $CurrentRecord -or $AttemptRecord -or $Pull -or -not $ConfirmWorkerQuiescent -or
    ($Action -eq 'Check' -and -not $Build) -or
    ($Action -eq 'Apply' -and (-not $CheckedImageRecord -or $Build)))){
    throw 'RELEASE_EMERGENCY_EXPLICIT_CHECKED_SOURCE_REQUIRED'
}
if($CheckedImageRecord -and ($Action -cne 'Apply' -or $Build -or $Pull -or $CurrentRecord -or
    $AttemptRecord -or $Image -cnotmatch '^sha256:[0-9a-f]{64}$' -or
    $SourceSha -cnotmatch '^[0-9a-f]{40}$')){
    throw 'RELEASE_CHECKED_IMAGE_APPLY_ARGUMENTS_INVALID'
}
$ApprovedImageSource=($Build -or [bool]$CheckedImageRecord)
if($EnableActionCoreNetwork -and ($Auto -or $Action -cnotin @('Apply','Check') -or
    -not $ApprovedImageSource -or $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or
    $AttemptRecord -or $CurrentRecord)){
    throw 'RELEASE_ACTION_CORE_NETWORK_REQUIRES_APPROVED_IMAGE_BUILD'
}
if($EnableDynamicGitHubRepositories -and ($Action -cnotin @('Apply','Check') -or -not $ApprovedImageSource -or
    $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or $AttemptRecord -or $CurrentRecord)){
    throw 'RELEASE_DYNAMIC_REPOSITORIES_REQUIRES_APPROVED_IMAGE_BUILD'
}
if($EnableOwnerShell -and ($Action -cnotin @('Apply','Check') -or -not $ApprovedImageSource -or
    $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or $AttemptRecord -or $CurrentRecord)){
    throw 'RELEASE_OWNER_SHELL_REQUIRES_APPROVED_IMAGE_BUILD'
}
if($CiControlRepositories -and ($Action -cnotin @('Apply','Check') -or -not $ApprovedImageSource -or
    $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or $AttemptRecord -or $CurrentRecord)){
    throw 'RELEASE_CI_CONTROL_REQUIRES_APPROVED_IMAGE_BUILD'
}
if($AllowUncertainGrowth -and ($Action -cnotin @('Check','Apply') -or
    $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or $AttemptRecord -or $CurrentRecord -or
    -not $ConfirmWorkerQuiescent -or
    ($Action -eq 'Check' -and -not $Build) -or
    ($Action -eq 'Apply' -and (-not $CheckedImageRecord -or $Build)))) {
    throw 'RELEASE_UNCERTAIN_GROWTH_REQUIRES_OWNER_CHECKED_IMAGE'
}
if($EnablePublisherMount -and ($Auto -or $Action -cnotin @('Check','Apply') -or
    $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or $AttemptRecord -or $CurrentRecord -or
    -not $ConfirmWorkerQuiescent -or
    ($Action -eq 'Check' -and -not $Build) -or
    ($Action -eq 'Apply' -and (-not $CheckedImageRecord -or $Build)))) {
    throw 'RELEASE_PUBLISHER_REQUIRES_EXACT_OWNER_CHECKED_IMAGE'
}
if($CiControlRepositories -and ($CiControlRepositories -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}(,[A-Za-z0-9][A-Za-z0-9_.-]{0,99}){0,19}$' -or
    @($CiControlRepositories.Split(',')|Select-Object -Unique).Count -ne @($CiControlRepositories.Split(',')).Count)){
    throw 'RELEASE_CI_CONTROL_REPOSITORIES_INVALID'
}
if($PreserveUncertainRequests){
    $ScopeIds=@(Parse-PreservedUncertainRequests $PreserveUncertainRequests)
    if($Action -cnotin @('Apply','Check') -or -not $ApprovedImageSource -or
       $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or $AttemptRecord -or $CurrentRecord){
        throw 'RELEASE_UNCERTAIN_REQUIRES_APPROVED_SOURCE_BUILD'
    }
}
if($PreserveApprovedRequest){
    if(@(Parse-PreservedUncertainRequests $PreserveApprovedRequest).Count -lt 1 -or
        $Action -cnotin @('Check','Apply') -or -not $ApprovedImageSource -or
        $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or $CurrentRecord -or $AttemptRecord -or
        -not $ConfirmWorkerQuiescent){
        throw 'RELEASE_APPROVED_REQUIRES_EXACT_OWNER_BUILD_AND_QUIESCENCE'
    }
}
if($PreserveClaimedJobs){
    $ClaimIds=@(Parse-PreservedUncertainRequests $PreserveClaimedJobs)
    # Eligibility is validated by the read-only state helper: an UNCERTAIN
    # claim must be in the current reviewed uncertainty scope, while a
    # CLOSED_UNCONFIRMED claim requires an independently audited closure.
    # Do not strand already-closed claims during the next Backup/release.
    if($ClaimIds.Count -gt 3 -or
        $Action -cnotin @('Apply','Check') -or -not $ApprovedImageSource -or
        $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or $CurrentRecord -or $AttemptRecord -or
        -not $ConfirmWorkerQuiescent){throw 'RELEASE_CLAIMED_REQUIRES_OWNER_REVIEW_AND_QUIESCENCE'}
}
if($ConfirmWorkerQuiescent -and $Action -cnotin @('Check','Apply','Backup','Promote')){
    throw 'RELEASE_QUIESCENCE_ACTION_INVALID'
}
if($Build -and ($Action -cnotin @('Apply','Check') -or $AttemptRecord)){throw 'RELEASE_BUILD_ACTION_INVALID'}
if($Action -cin @('Backup','Promote') -and ($Config -or $Image -or $SourceSha -or $CurrentRecord -or $AttemptRecord -or $Pull -or $Build -or $Rotate -or $Service -or $CredentialName -or $Probes -or $EnableDynamicGitHubRepositories -or $EnableOwnerShell -or $EnableActionCoreNetwork -or $CiControlRepositories -or $PreserveUncertainRequests -or $PreserveClaimedJobs -or $PreserveApprovedRequest -or $CheckedImageRecord -or $AllowUncertainGrowth)){throw 'PRIMARY_PROMOTION_ARGUMENTS_INVALID'}
$script:ActionCoreNetworks=$null
if($EnableActionCoreNetwork){
    Step 'ACTION_CORE_NETWORK_PREFLIGHT_READ_ONLY'
    $script:ActionCoreNetworks=Read-ActionCoreBoundary
}
if($Build){
    Step 'BUILD_IMAGE'
    if($SourceSha -cnotmatch '^[0-9a-f]{40}$'){throw 'RELEASE_APPROVED_SOURCE_SHA_REQUIRED'}
    $Git=(Get-Command git.exe -CommandType Application).Source
    if((Private-Process @('-C',$SourceRoot,'status','--porcelain') '' $Git)){throw 'RELEASE_WINDOWS_SOURCE_DIRTY'}
    if((Private-Process @('-C',$SourceRoot,'branch','--show-current') '' $Git) -cne 'main'){throw 'RELEASE_WINDOWS_MAIN_REQUIRED'}
    $Before=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    if($Pull){$null=Private-Process @('-C',$SourceRoot,'pull','--ff-only') '' $Git}
    if((Private-Process @('-C',$SourceRoot,'rev-parse','HEAD') '' $Git) -cne $SourceSha){throw 'RELEASE_WINDOWS_SHA_MISMATCH'}
    if((Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash -cne $Before){
        # Continue in the exact approved revision, rather than mixing loaded old
        # functions with a newly pulled script. No confidential values are arguments.
        $ForwardParameters.Remove('Pull')
        $Next=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
        $Next+=@(Forward-NativeParameters $ForwardParameters)
        & (Join-Path $PSHOME 'powershell.exe') @Next
        if($LASTEXITCODE -ne 0){throw 'RELEASE_UPDATED_MANAGER_FAILED'}
        return
    }
    $BuildDirectory=Join-Path $env:TEMP ('fortis-integration-build-'+[Guid]::NewGuid().ToString('N'))
    Protect-Directory $BuildDirectory
    $Zip=Join-Path $BuildDirectory 'source.zip';$Context=Join-Path $BuildDirectory 'context'
    $null=Private-Process @('-C',$SourceRoot,'archive','--format=zip',('--output='+$Zip),$SourceSha) '' $Git
    Expand-Archive -LiteralPath $Zip -DestinationPath $Context
    $Tag='fortis-approvals-gateway:extensions-'+$SourceSha.Substring(0,12)
    $null=Docker-Text @('build','--label',('org.opencontainers.image.revision='+$SourceSha),'-f',
        (Join-Path $Context 'fortis_approvals\deploy\Dockerfile-Gateway-Modularized-Candidate'),'-t',$Tag,$Context)
    $script:Image=@(Docker-Json @('image','inspect',$Tag))[0].Id
}
if($CheckedImageRecord){
    # Pinned Apply cannot rely on a different Windows checkout than Check.
    $Git=(Get-Command git.exe -CommandType Application).Source
    if((Private-Process @('-C',$SourceRoot,'status','--porcelain') '' $Git)){
        throw 'RELEASE_WINDOWS_SOURCE_DIRTY'
    }
    if((Private-Process @('-C',$SourceRoot,'branch','--show-current') '' $Git) -cne 'main'){
        throw 'RELEASE_WINDOWS_MAIN_REQUIRED'
    }
    if((Private-Process @('-C',$SourceRoot,'rev-parse','HEAD') '' $Git) -cne $SourceSha){
        throw 'RELEASE_WINDOWS_SHA_MISMATCH'
    }
}
if($Action -eq 'Return' -or $AttemptRecord){
    if(-not $AttemptRecord){$AttemptRecord=(Read-Private $AttemptPointer).record}
    $script:RecordPath=[IO.Path]::GetFullPath($AttemptRecord);$script:R=Read-Private $script:RecordPath
    if($script:R.schema -cne 'fortis-extension-release-v1'){throw 'RELEASE_ATTEMPT_SCHEMA_INVALID'}
    if($script:Image -and $script:Image -cne $script:R.runtime.image){throw 'RELEASE_ATTEMPT_IDENTITY_MISMATCH'}
    $script:Image=$script:R.runtime.image;$VaultVolume=$script:R.runtime.vaultVolume
    $Stored=Read-PreservedUncertainRequests $script:R.runtime
    if($script:PreserveUncertainRequests -and $script:PreserveUncertainRequests -cne $Stored){
        throw 'RELEASE_UNCERTAIN_RECORD_SCOPE_CHANGED'
    }
    $script:PreserveUncertainRequests=$Stored
    $script:PreserveUncertainExact=$false
    $StoredApproved=Read-PreservedApprovedRequest $script:R.runtime
    if($script:PreserveApprovedRequest -and $script:PreserveApprovedRequest -cne $StoredApproved){
        throw 'RELEASE_APPROVED_RECORD_SCOPE_CHANGED'
    }
    $script:PreserveApprovedRequest=$StoredApproved
    $script:PreserveApprovedExact=$false
    $StoredClaimed=Read-PreservedClaimedJobs $script:R.runtime
    if($script:PreserveClaimedJobs -and $script:PreserveClaimedJobs -cne $StoredClaimed){
        throw 'RELEASE_CLAIMED_RECORD_SCOPE_CHANGED'
    }
    $script:PreserveClaimedJobs=$StoredClaimed
    $script:PreserveClaimedExact=$false
}
if(-not $script:Image){
    $Source=Get-SourceRecord;$script:Image=$Source.runtime.image
}
if($script:Image -cnotmatch '^sha256:[0-9a-f]{64}$'){throw 'RELEASE_IMAGE_ID_REQUIRED'}
$ImageInfo=@(Docker-Json @('image','inspect',$script:Image))[0]
if($SourceSha -and $ImageInfo.Config.Labels.'org.opencontainers.image.revision' -cne $SourceSha){throw 'RELEASE_IMAGE_REVISION_MISMATCH'}
$LockPath=Join-Path $ReleaseBase 'controller.lock'
if((Test-Path -LiteralPath $LockPath) -and ((Get-Item -LiteralPath $LockPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'RELEASE_LOCK_REPARSE_POINT_DENIED'}
try{$ControllerLock=[IO.File]::Open($LockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch{throw 'RELEASE_CONTROLLER_ALREADY_RUNNING_OR_LOCK_UNAVAILABLE'}
try {
if($Action -eq 'Credential' -and $Service){Put-ProviderCredential $Service;return}
Ensure-Vault
if($Action -eq 'Credential'){
    Put-Credential $CredentialName -Rotation:$Rotate
    return
}
if($Action -cin @('Backup','Promote')){
    $null=Get-SourceRecord
    if($script:PreserveApprovedRequest -and -not $ConfirmWorkerQuiescent){
        throw 'RELEASE_APPROVED_BACKUP_PROMOTE_REQUIRES_QUIESCENCE'
    }
    if($script:PreserveClaimedJobs -and -not $ConfirmWorkerQuiescent){
        throw 'RELEASE_CLAIMED_BACKUP_PROMOTE_REQUIRES_QUIESCENCE'
    }
}
if($Action -eq 'Backup'){Backup-Primary;return}
if($Action -eq 'Promote'){Promote-Primary;return}
if($Action -eq 'Return' -or $AttemptRecord){
    if($Action -eq 'Return'){Return-Source;return}
    if($script:PreserveClaimedJobs -and -not $ConfirmWorkerQuiescent){
        throw 'RELEASE_CLAIMED_RESUME_REQUIRES_QUIESCENCE'
    }
    if($script:R.phase -cnotin @('Created','Staged')){throw 'RELEASE_RESUME_NOT_READY_USE_RETURN'}
    Resume-Target;return
}
if(-not $Config -and -not $Auto){throw 'RELEASE_PUBLIC_CONFIG_REQUIRED'}
$SourceForOwnerShell=Get-SourceRecord
if($AllowUncertainGrowth){
    $script:GrowthSourceVolume=$SourceForOwnerShell.runtime.stateVolume
}
$script:PublisherActivationVolume=Read-PublisherActivationVolume $SourceForOwnerShell.runtime
$PreviousPublisherDigest=Read-PublisherActivationDigest $SourceForOwnerShell.runtime
if($EnablePublisherMount){$script:PublisherActivationVolume='fortis-r7-publisher-activation'}
$script:PublisherActivationDigest=''
if($script:PublisherActivationVolume){
    Step 'PUBLISHER_ACTIVATION_MATERIAL_PREFLIGHT'
    $script:PublisherActivationDigest=Image-PublisherMount-Preflight -ImageId $script:Image
    if($PreviousPublisherDigest -and $script:PublisherActivationDigest -cne $PreviousPublisherDigest){
        throw 'RELEASE_PUBLISHER_SOURCE_MATERIAL_CHANGED'
    }
}
if($SourceForOwnerShell.runtime.gatewayNetworks -and -not $EnableActionCoreNetwork){
    throw 'RELEASE_ACTION_CORE_NETWORK_DOWNGRADE_DENIED'
}
$OwnerShellEnabled=((Read-OwnerShellFlag $SourceForOwnerShell.runtime) -or [bool]$EnableOwnerShell)
if($OwnerShellEnabled){
    Step 'OWNER_SHELL_MATERIAL_PREFLIGHT'
    Image-OwnerShell-Preflight
}
if($Auto){$ConfigText=$script:AutoConfigText}
else {$ConfigText=Get-Content -LiteralPath $Config -Raw}
$PublicConfig=ConvertFrom-Json -InputObject $ConfigText -ErrorAction Stop
if($PublicConfig.providers.action_core -and -not $EnableActionCoreNetwork){
    throw 'RELEASE_ACTION_CORE_NETWORK_REQUIRED'
}
if($EnableActionCoreNetwork){Assert-ActionCoreConfig $ConfigText}
Step 'CONFIG_AND_CREDENTIAL_PREFLIGHT'
$Report=Image-CLI @('check') $ConfigText
if($Action -eq 'Apply'){
    if($CheckedImageRecord -and @($Report.missingCredentials).Count){
        throw 'RELEASE_CHECKED_IMAGE_CREDENTIAL_CHANGED'
    }
    foreach($Alias in @($Report.missingCredentials)){Put-Credential $Alias}
    $Report=Image-CLI @('check') $ConfigText
}
if($Report.status -cne 'READY'){throw 'RELEASE_CONFIG_OR_CREDENTIAL_NOT_READY'}
if($CheckedImageRecord){Verify-Checked-Image $SourceForOwnerShell $Report}
if($Action -eq 'Check'){
    $CheckReceipt=$null
    if($Build -or $script:PreserveUncertainRequests -or $script:PreserveClaimedJobs -or $script:PreserveApprovedRequest){
        $Source=Get-SourceRecord
        if(($script:PreserveClaimedJobs -or $script:PreserveApprovedRequest) -and
            -not $ConfirmWorkerQuiescent){throw 'RELEASE_PRESERVATION_REQUIRES_QUIESCENCE'}
        Step 'SOURCE_STATE_PREFLIGHT_READ_ONLY'
        if($AllowUncertainGrowth){
            $GrowthSnapshot=Snapshot-Uncertain-Growth $Source.runtime.stateVolume
            $script:PreserveUncertainRequests=@($GrowthSnapshot.uncertainIds) -join ','
            $script:PreserveUncertainExact=($script:PreserveUncertainRequests -ne '')
            $script:GrowthWitness=$GrowthSnapshot.witness
            $CheckReceipt=$GrowthSnapshot.receipt
            Write-Host ('FORTIS_UNCERTAIN_GROWTH_CHECK_BOUND count='+
                @($GrowthSnapshot.uncertainIds).Count)
        } else {
            $CheckReceipt=Receipt $Source.runtime.stateVolume -Exact:$script:PreserveUncertainExact -ExactClaimed:$script:PreserveClaimedExact -ExactApproved:$script:PreserveApprovedExact
        }
    }
    if($Build){
        if($EmergencyRequested){Assert-Previous-Image-Retained $Source}
        $Path=Save-Checked-Image $Source $Report $CheckReceipt
        $Report|Add-Member -NotePropertyName checkedImageId -NotePropertyValue $script:Image
        $Report|Add-Member -NotePropertyName checkedImageRecord -NotePropertyValue $Path
        if($Auto){
            # Only protected READY result can become the next owner-GO target.
            Write-Private $script:AutoCheckPointer ([ordered]@{
                schema='fortis-auto-check-v1';sourceSha=$SourceSha;
                image=$script:Image;record=$Path
            })
        }
    }
    $Report|ConvertTo-Json -Depth 12;return
}
if(Test-Path -LiteralPath $AttemptPointer){
    $Last=Read-Private (Read-Private $AttemptPointer).record
    if($Last.phase -cnotin @('Complete','Returned')){throw 'RELEASE_PRIOR_ATTEMPT_REQUIRES_RESUME_OR_RETURN'}
}
Step 'IMAGE_OFFLINE_SMOKE'
$Smoke=Private-Process @('run','--rm','--pull=never','--network','none','--read-only','--cap-drop','ALL',
    '--security-opt','no-new-privileges:true','--pids-limit','64','--memory','256m',
    '--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--entrypoint','python',$script:Image,'-I','-B',
    '/opt/fortis/operator/image_smoke.py') ''
foreach($Marker in @('IMAGE_NATIVE_GIT_IMPORT_PASS','IMAGE_SONAR_OFFLINE_SMOKE_PASS','IMAGE_GITHUB_NOT_REGISTERED_PASS','IMAGE_EXTENSIONS_OFFLINE_PASS','IMAGE_OWNER_INCIDENT_IMPORT_PASS')){
    if($Smoke -notmatch $Marker){throw 'RELEASE_IMAGE_SMOKE_INCOMPLETE'}
}
Step 'REPO_CLIENT_PREFLIGHT'
$Code=@'
import json,sys
sys.path.insert(0,'/workspace/repo/Repos/fortis-approvals')
from fortis_approvals.workflow.client import default_client
c=default_client(); assert c.github.list_branches('fortis-approvals',per_page=1)['items']
print(json.dumps({'nativeCapabilities':True,'githubRead':True}))
'@
$Preflight=Repo-JSON $Code
if(-not $Preflight.nativeCapabilities -or -not $Preflight.githubRead){throw 'RELEASE_REPO_CLIENT_PREFLIGHT_FAILED'}
Step 'SOURCE_ADMISSION'
$Source=Get-SourceRecord
if(($script:PreserveClaimedJobs -or $script:PreserveApprovedRequest) -and
    -not $ConfirmWorkerQuiescent){throw 'RELEASE_PRESERVATION_REQUIRES_QUIESCENCE'}
$Old=Container $Source.runtime.pilotId;Admit $Old $Source.runtime
if($Old.State.Status -cne 'running'){throw 'RELEASE_SOURCE_NOT_RUNNING'}
Step 'PREVIOUS_IMAGE_RETENTION_PREFLIGHT'
Assert-Previous-Image-Retained $Source
Assert-OnlyWriter $Source.runtime.stateVolume $Old.Id
Step 'SOURCE_STATE_PREFLIGHT';$PreStopReceipt=Receipt $Source.runtime.stateVolume -Exact:$script:PreserveUncertainExact -ExactClaimed:$script:PreserveClaimedExact -ExactApproved:$script:PreserveApprovedExact
Step 'SOURCE_STATE_PREFLIGHT_COMPLETE'
$Baseline=Release-Production-Baseline
Step 'PRODUCTION_BASELINE_CAPTURED'
$RunId=[Guid]::NewGuid().ToString('N');$Directory=Join-Path $ReleaseBase $RunId;Protect-Directory $Directory
Step 'RELEASE_DIRECTORY_PROTECTED'
Step 'PREPARE_RECORD_MODEL'
$script:RecordPath=Join-Path $Directory 'record.json'
$ConfigObject=ConvertFrom-Json -InputObject $ConfigText
$CompactConfig=ConvertTo-Json -InputObject $ConfigObject -Compress -Depth 20
$ProbeText='[]';if($Probes){$ProbeText=Get-Content -LiteralPath $Probes -Raw}
if($Auto){$ProbeText=$script:AutoProbeText}
$Nonce=[Guid]::NewGuid().ToString('D')
$Runtime=[ordered]@{pilotId='';pilotName=('fortis-github-pilot-'+$RunId);image=$script:Image
    stateVolume=('fortis-github-pilot-state-'+$RunId);tokenVolume=$Source.runtime.tokenVolume
    owner=$Source.runtime.owner;repository=$Source.runtime.repository;filePrBranch=$Source.runtime.filePrBranch
    ciReads=$true;nativeWorktree=$true;requiredWorkflows=$Source.runtime.requiredWorkflows;bootstrapTask=$Source.runtime.bootstrapTask
    dynamicRepositories=((Read-DynamicRepositoriesFlag $Source.runtime) -or [bool]$EnableDynamicGitHubRepositories)
    ciControlRepositories=$(if($CiControlRepositories){$CiControlRepositories}else{Read-CiControlRepositories $Source.runtime})
    preserveUncertainRequests=$script:PreserveUncertainRequests
    preserveClaimedJobs=$script:PreserveClaimedJobs
    preserveApprovedRequest=$script:PreserveApprovedRequest
    workerQuiescenceOwnerAttested=([bool]$ConfirmWorkerQuiescent)
    vaultVolume=$VaultVolume;extensionsConfig=$CompactConfig;releaseNonce=$Nonce
    publisherActivationVolume=$script:PublisherActivationVolume
    publisherActivationDigest=$script:PublisherActivationDigest
    ownerShell=$OwnerShellEnabled;runId=$RunId}
if($EnableActionCoreNetwork){$Runtime.gatewayNetworks=$script:ActionCoreNetworks}
$script:R=[ordered]@{schema='fortis-extension-release-v1';phase='Prepared';source=$Source;runtime=$Runtime
    productionBaseline=$Baseline;configurationDigest=$Report.configurationDigest;sourceReceipt=$null
    activated=$false;probesPassed=$false;probes=$ProbeText;failureStep='';failureMessage=''
    emergencyRecovery=[ordered]@{ownerAcceptedUnverifiedRestore=[bool]$AcceptUnverifiedRestore
        rescueImage=$EmergencyRescueImage;archiveSha256=$EmergencyRescueArchiveSha256.ToUpperInvariant()
        isolatedRestoreTested=$false}}
Step 'PREPARE_RECORD_MODEL_READY'
# A 2026-11-13 owner Apply passed the Prepared Save but failed when
# sourceReceipt first entered the bounded serializer after docker stop.
# Prove the actual pre-stop receipt against this exact runtime/source DTO;
# on denial, leave the production source running and attempt.json untouched.
Step 'SOURCE_RECEIPT_SERIALIZATION_PREFLIGHT'
Assert-Release-Receipt-Serializable $script:R $PreStopReceipt
Step 'SOURCE_RECEIPT_SERIALIZATION_PREFLIGHT_PASS'
Save
Step 'PREPARED_RECORD_SAVED'
# Keep the original attempt pointer stable through the final pinned Check
# comparison. Its SHA256 is part of the Check binding; publishing our own
# new attempt pointer first would invalidate that binding before docker stop.
try {
    Step 'PUBLIC_ENV_PREFLIGHT'
    $EnvFile=Join-Path $Directory 'public.env'
    $EnvLines=@($Old.Config.Env|Where-Object{$_.StartsWith('FORTIS_') -and
        -not $_.StartsWith('FORTIS_EXTENSIONS_CONFIG=') -and
        -not $_.StartsWith('FORTIS_RELEASE_NONCE=') -and
        -not $_.StartsWith('FORTIS_GITHUB_NATIVE_MULTI_REPO=') -and
        -not $_.StartsWith('FORTIS_GITHUB_CI_CONTROL_REPOSITORIES=') -and
        -not $_.StartsWith('FORTIS_OWNER_SHELL_CONFIG=')})
    if($Runtime.dynamicRepositories){$EnvLines+='FORTIS_GITHUB_NATIVE_MULTI_REPO=1'}
    if($Runtime.ciControlRepositories){$EnvLines+='FORTIS_GITHUB_CI_CONTROL_REPOSITORIES='+$Runtime.ciControlRepositories}
    $EnvLines+=@(Extension-EnvLines $CompactConfig $Nonce)
    $EnvLines+=@(OwnerShell-EnvLines $Runtime.ownerShell)
    Check-OwnerShellEnv $EnvLines $Runtime.ownerShell
    [IO.File]::WriteAllText($EnvFile,(($EnvLines -join "`n")+"`n"),[Text.UTF8Encoding]::new($false))
    Check-ExtensionEnv $EnvLines $CompactConfig $Nonce
    Assert-PublicEnvFile $EnvFile $EnvLines
    if($EnableActionCoreNetwork){
        Step 'ACTION_CORE_BOUNDARY_FINAL_PREFLIGHT'
        $FinalBoundary=Read-ActionCoreBoundary
        if(-not (Same-Json $FinalBoundary $script:ActionCoreNetworks)){
            throw 'RELEASE_ACTION_CORE_BOUNDARY_CHANGED'
        }
    }
    Step 'STOP_SOURCE';Assert-Release-Production;Admit (Container $Old.Id) $Source.runtime
    if($CheckedImageRecord){Verify-Checked-Image $Source $Report}
    Assert-Previous-Image-Retained $Source
    # Durable recovery pointer must exist before the first source effect,
    # but it is intentionally written AFTER the frozen Check binding audit.
    Write-Private $AttemptPointer @{schema=1;record=$script:RecordPath}
    Step 'ATTEMPT_POINTER_SAVED'
    $null=Docker-Text @('stop','--timeout','20',$Old.Id)
    if((Container $Old.Id).State.Status -cne 'exited'){throw 'RELEASE_SOURCE_STOP_UNCONFIRMED'}
    Assert-OnlyWriter $Source.runtime.stateVolume
    $script:R.sourceReceipt=Receipt $Source.runtime.stateVolume -Exact:$script:PreserveUncertainExact -ExactClaimed:$script:PreserveClaimedExact -ExactApproved:$script:PreserveApprovedExact
    if($AllowUncertainGrowth){
        # The last bounded extension is validated only AFTER the old writer
        # has exited. Seal its full exact ID scope into the candidate record
        # before cloning; the original Check record is never rewritten.
        $script:R.runtime.preserveUncertainRequests=$script:GrowthEffectiveUncertainRequests
        Write-Host ('FORTIS_UNCERTAIN_GROWTH_FROZEN count='+
            @((Effective-Uncertain-Ids)).Count)
    }
    Save
    # Close the final race: recheck the frozen source AFTER the old writer stops.
    # On mismatch, the guarded failure path returns the retained source.
    if($CheckedImageRecord){Assert-Checked-Source-Receipt $script:R.sourceReceipt}
    Step 'CLONE_STATE'
    $null=Docker-Text @('volume','create','--label',('io.fortis.release='+$RunId),$Runtime.stateVolume)
    Assert-Volume $Runtime.stateVolume;Assert-OnlyWriter $Runtime.stateVolume
    if(@(Docker-Json @('volume','inspect',$Runtime.stateVolume))[0].Labels.'io.fortis.release' -cne $RunId){throw 'RELEASE_STATE_VOLUME_PROVENANCE_INVALID'}
    $Clone=State-Helper @{action='clone';github=$true;native=$true;
        preserveUncertainIds=@(Effective-Uncertain-Ids);
        preserveClaimedIds=@(Parse-PreservedUncertainRequests $script:PreserveClaimedJobs);
        preserveApprovedIds=@(Approved-Ids);requireExactApproved=([bool]$script:PreserveApprovedExact)} @('--mount',
        ('type=volume,source='+$Source.runtime.stateVolume+',target=/source,readonly'),'--mount',
        ('type=volume,source='+$Runtime.stateVolume+',target=/target')) -Root
    if(-not (Same-Json $Clone $script:R.sourceReceipt)){throw 'RELEASE_STATE_CLONE_MISMATCH'}
    Assert-SourceUnchanged
    Step 'CREATE_STAGED'
    $Arguments=@('create','--pull=never','--name',$Runtime.pilotName,'--label',('io.fortis.review-update='+$RunId),
        '--restart','no','--init','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','100','--memory','512m','--memory-swap','1g','--network',$(if($Runtime.gatewayNetworks){'fortis-gateway-egress'}else{'bridge'}),'--tmpfs','/tmp:rw,nosuid,nodev,size=16m',
        '--env-file',$EnvFile,'--publish','127.0.0.1:19203:19103','--publish','127.0.0.1:19204:19104',
        '--mount',('type=volume,source='+$Runtime.stateVolume+',target=/state'),
        '--mount',('type=volume,source='+$Runtime.tokenVolume+',target=/run/github-token,readonly'),
        '--mount','type=volume,source=fortis-r7-identity,target=/run/r7-identity,readonly',
        '--mount','type=volume,source=fortis-r7-grant,target=/run/r7-grant,readonly',
        '--mount','type=volume,source=fortis-r7-sonar-token,target=/run/r7-sonar-token,readonly',
        '--mount',('type=volume,source='+$VaultVolume+',target=/run/fortis-secrets,readonly'),
        '--health-cmd','python -m fortis_approvals.r7_unified_server health','--health-interval','20s','--health-timeout','5s',
        '--health-retries','3','--health-start-period','20s')
    if($Runtime.publisherActivationVolume){
        $Arguments+=@('--mount',('type=volume,source='+$Runtime.publisherActivationVolume+
            ',target=/run/r7-publisher-activation,readonly'))
    }
    $Arguments+=@($script:Image)
    $script:R.runtime.pilotId=Docker-Text $Arguments
    if($script:R.runtime.pilotId -cnotmatch '^[0-9a-f]{64}$'){throw 'RELEASE_CREATED_ID_INVALID'}
    $script:R.phase='Created';Save;Resume-Target
} catch {
    $Failure='step='+$script:Step+'; '+$_.Exception.Message
    $script:R.failureStep=$script:Step;$script:R.failureMessage=$Failure
    try{Save}catch{Write-Warning 'RELEASE_FAILURE_RECORD_NOT_SAVED'}
    try{Return-Source}catch{Write-Warning ('RELEASE_RETURN_REQUIRES_REVIEW: '+$_.Exception.Message)}
    throw ('RELEASE_FAILED: '+$Failure+'; record='+$script:RecordPath)
}

} finally { $ControllerLock.Dispose() }
