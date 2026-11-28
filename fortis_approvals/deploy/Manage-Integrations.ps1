# Windows PowerShell 5.1. Owner-only review controller; tokens never enter argv.
[CmdletBinding()]
param(
    [ValidateSet('Apply','Credential','Check','Return','Backup','Promote','SelfTest','RegistrySourceDigest','BackupCleanup','ReleaseStateCleanup')][string]$Action='Check',
    [string]$Config='', [string]$Image='', [string]$SourceSha='', [string]$CheckedImageRecord='', [string]$CurrentRecord='',
    [string]$AttemptRecord='', [string]$CredentialName='', [switch]$Rotate,
    [string]$EmergencyRescueImage='', [string]$EmergencyRescueArchiveSha256='',
    [switch]$AcceptUnverifiedRestore,
    [ValidateSet('github','sonarcloud')][string]$Service='',
    [switch]$Build, [switch]$Pull, [switch]$EnableDynamicGitHubRepositories, [switch]$EnableOwnerShell,
    [switch]$EnablePublisherMount, [switch]$EnableMachinePowerShell, [switch]$EnableRegistryMount, [string]$RegistryReleaseNonce='', [string]$RegistryExpectedSourceDigest='', [switch]$EnableActionCoreNetwork, [switch]$EnableObservatoryNetwork, [switch]$AllowUncertainGrowth,
    [string]$CiControlRepositories='', [string]$CdReadRepositories='', [string]$PreserveUncertainRequests='',
    [string]$PreserveClaimedJobs='', [string]$PreserveApprovedRequest='', [switch]$ConfirmWorkerQuiescent,
    [string]$RegistryReturnContainerId='', [string]$RegistryReturnNonce='', [switch]$RegistryCrashRecovery,
    [string]$VaultVolume='fortis-review-secrets', [string]$Probes='', [switch]$Auto,
    [string]$BackupIds='', [string]$RunIds='', [switch]$Preview, [switch]$Corrective288,
    [string]$CorrectiveRegistryImage='', [string]$CorrectiveRegistryProfileSha256='',
    [switch]$Bootstrap289, [string]$BootstrapRegistryImage='', [string]$BootstrapRegistryProfileSha256='',
    [string]$BootstrapReviewSha256='', [string]$BootstrapEvidenceSha256='', [string]$BootstrapReviewProofRecord='',
    [string]$SuccessorRegistryImage='', [string]$SuccessorRegistryProfileSha256=''
)
$script:ReleaseClock=[Diagnostics.Stopwatch]::StartNew()
$script:RegistryDelivery=$null
$script:CorrectivePair=$null
$script:BootstrapPair=$null
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
# Bootstrap release-record context before SelfTest and before any protected
# private pointer READ. Under the caller's StrictMode, reading an absent
# script-scoped RecordPath (or R during Write-Private) throws even when no
# release attempt exists. Empty/null values are only initial sentinels:
# the exact protected path and model are still assigned at PREPARE_RECORD_MODEL.
$script:RecordPath=''
$script:R=$null
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
$script:RegistryReturn=$null
$script:RegistryCrash=$null
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
function Test-RecordedGatewayNetwork {
    param($Map,[string]$Name)
    if($null -eq $Map){return $false}
    if($Map -is [Collections.IDictionary]){return $Map.Contains($Name)}
    return $null -ne $Map.PSObject.Properties[$Name]
}
function Get-RecordedGatewayNetworkNames {
    param($Map)
    if($null -eq $Map){return @()}
    if($Map -is [Collections.IDictionary]){return @($Map.Keys)}
    return @($Map.PSObject.Properties.Name)
}
function Read-ObservatoryBoundary {
    # Requires owner-released Observatory on one private network; no host port.
    $Name='fortis-observatory-gw-net'
    $Id=Read-ActionCoreDockerNetwork -Name $Name -Internal:$true -Owner 'fortis-approvals' -Purpose 'observatory-gateway-v1'
    $Rows=@(Docker-Json @('container','inspect','fortis-observatory-api'))
    if($Rows.Count -ne 1){throw 'RELEASE_OBSERVATORY_CONTAINER_NOT_FOUND'}
    $C=$Rows[0]
    $Attached=@($C.NetworkSettings.Networks.PSObject.Properties.Name)
    $Published=$C.HostConfig.PortBindings
    if($C.Name -cne '/fortis-observatory-api' -or $C.State.Status -cne 'running' -or
       $C.Config.Labels.'com.docker.compose.project' -cne 'fortis-observatory-api' -or
       $C.Config.Labels.'com.docker.compose.service' -cne 'api' -or
       $C.Config.User -cne '1000:1000' -or
       -not [bool]$C.HostConfig.ReadonlyRootfs -or
       -not ($C.HostConfig.CapDrop -contains 'ALL') -or
       $C.HostConfig.CapAdd -or
       $Attached.Count -ne 1 -or $Attached[0] -cne $Name -or
       [string]$C.NetworkSettings.Networks.PSObject.Properties[$Name].Value.NetworkID -cne $Id -or
       ($Published -and @($Published.PSObject.Properties).Count -gt 0)){
        throw 'RELEASE_OBSERVATORY_DOCKER_ONLY_IDENTITY_INVALID'
    }
    Write-Host 'FORTIS_OBSERVATORY_NETWORK_DOCKER_ONLY_PASS'
    return $Id
}
function Read-GatewayNetworkBoundary {
    param([bool]$ActionCore,[bool]$Observatory)
    if(-not ($ActionCore -or $Observatory)){throw 'RELEASE_GATEWAY_NETWORK_SCOPE_REQUIRED'}
    if($ActionCore){$Networks=Read-ActionCoreBoundary}
    else {
        $Networks=[ordered]@{}
        $Networks['fortis-gateway-egress']=Read-ActionCoreDockerNetwork -Name 'fortis-gateway-egress' -Internal:$false -Owner 'fortis-approvals' -Purpose 'gateway-egress-v1'
    }
    if($Observatory){$Networks['fortis-observatory-gw-net']=Read-ObservatoryBoundary}
    if(@($Networks.Values|Select-Object -Unique).Count -ne $Networks.Count){
        throw 'RELEASE_GATEWAY_NETWORK_ID_ALIAS_INVALID'
    }
    Write-Host 'FORTIS_GATEWAY_NETWORK_BOUNDARY_PASS'
    return $Networks
}
function Read-RegistryProvider {
    param($Config)
    if($null -eq $Config){throw 'RELEASE_REGISTRY_CONFIG_INVALID'}
    $Field=$Config.PSObject.Properties['providers']
    if($null -eq $Field -or $null -eq $Field.Value -or
       $Field.Value -isnot [pscustomobject]){
        throw 'RELEASE_REGISTRY_CONFIG_INVALID'
    }
    $Property=$Field.Value.PSObject.Properties['registry']
    if($null -eq $Property){return $null}
    if($Property.Value -isnot [pscustomobject]){
        throw 'RELEASE_REGISTRY_CONFIG_INVALID'
    }
    return $Property.Value
}
function Read-ObservatoryProvider {
    param($Config)
    if($null -eq $Config){throw 'RELEASE_OBSERVATORY_CONFIG_INVALID'}
    $Field=$Config.PSObject.Properties['providers']
    if($null -eq $Field -or $null -eq $Field.Value -or
       $Field.Value -isnot [pscustomobject]){
        throw 'RELEASE_OBSERVATORY_CONFIG_INVALID'
    }
    $Property=$Field.Value.PSObject.Properties['observatory']
    if($null -eq $Property){return $null}
    if($Property.Value -isnot [pscustomobject]){
        throw 'RELEASE_OBSERVATORY_CONFIG_INVALID'
    }
    return $Property.Value
}
function Assert-ObservatoryConfig {
    param([string]$Json)
    $Cfg=ConvertFrom-Json -InputObject $Json -ErrorAction Stop
    $Provider=$Cfg.providers.observatory
    if(-not $Provider){throw 'RELEASE_OBSERVATORY_READ_ONLY_CONFIG_REQUIRED'}
    $Ops=@($Provider.operations.PSObject.Properties.Name|Sort-Object)
    $CredentialKeys=@($Provider.credentials.PSObject.Properties.Name)
    if($Cfg.schemaVersion -ne 1 -or ($Ops -join ',') -cne 'health,list_sessions' -or
       $CredentialKeys.Count -ne 1 -or $CredentialKeys[0] -cne 'api' -or
       $Provider.credentials.api -cne 'observatory-read' -or
       $Provider.operations.health.policy -cne 'ALLOW' -or
       $Provider.operations.list_sessions.policy -cne 'ALLOW' -or
       @($Provider.operations.health.targets).Count -ne 1 -or
       @($Provider.operations.list_sessions.targets).Count -ne 1 -or
       $Provider.operations.health.targets[0] -cne 'service' -or
       $Provider.operations.list_sessions.targets[0] -cne 'registry'){
        throw 'RELEASE_OBSERVATORY_READ_ONLY_CONFIG_REQUIRED'
    }
}
# Most accepted provider configs do not contain Action Core. Missing optional
# action_core must not throw PropertyNotFoundStrict in owner -Auto Check.
# The enclosing providers object remains mandatory, never a fallback.
function Read-ActionCoreProvider {
    param($Config)
    if($null -eq $Config){throw 'RELEASE_ACTION_CORE_CONFIG_INVALID'}
    $Field=$Config.PSObject.Properties['providers']
    if($null -eq $Field -or $null -eq $Field.Value -or
       $Field.Value -isnot [pscustomobject]){
        throw 'RELEASE_ACTION_CORE_CONFIG_INVALID'
    }
    $Action=$Field.Value.PSObject.Properties['action_core']
    if($null -eq $Action){return $null}
    # An explicitly present null/invalid provider is not equivalent to an
    # absent optional provider; never downgrade a malformed opt-in.
    if($Action.Value -isnot [pscustomobject]){
        throw 'RELEASE_ACTION_CORE_CONFIG_INVALID'
    }
    return $Action.Value
}
function Assert-ActionCoreConfig {
    param([string]$Json)
    $Config=ConvertFrom-Json -InputObject $Json -ErrorAction Stop
    $Provider=Read-ActionCoreProvider $Config
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
function Assert-ObservatoryPrivateTlsRead {
    param([string]$ContainerId)
    # Positive TLS/443 handshake with owner-pinned CA and DNS SAN; use the
    # expected unauthenticated 401, never an upstream bearer in command argv.
    $Code=@'
from http.client import HTTPSConnection
from fortis_approvals.integrations.observatory.transport import observatory_context
connection=HTTPSConnection("fortis-observatory-api",443,context=observatory_context(),timeout=5)
try:
    connection.request("GET","/v1/health",headers={"Host":"fortis-observatory-api","Connection":"close"})
    response=connection.getresponse()
    if response.status!=401: raise RuntimeError("OBS_TLS_UNAUTHENTICATED_NON401")
finally:
    connection.close()
print("OBSERVATORY_PRIVATE_TLS443_AUTH_GATE_PASS")
'@
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<observatory-tls443-positive>','exec'))"
    $Outcome=Docker-Text @('exec','--user','10001:10001',$ContainerId,'python','-I','-B','-c',$Wrapper)
    if($Outcome.Trim() -cne 'OBSERVATORY_PRIVATE_TLS443_AUTH_GATE_PASS'){
        throw 'RELEASE_OBSERVATORY_TLS443_READ_FAILED'
    }
    Write-Host 'FORTIS_OBSERVATORY_GATEWAY_TLS443_PASS'
}
function Assert-ObservatoryNoLegacyHttp {
    param([string]$ContainerId)
    # No credential / API read; only verifies retired HTTP socket is closed.
    $Code=@'
import socket
for host in ("fortis-observatory-api","host.docker.internal"):
    try:
        with socket.create_connection((host,18756),timeout=2):
            raise RuntimeError("OBS_HTTP18756_ROUTE_OPEN")
    except OSError:
        pass
print("OBSERVATORY_HTTP18756_BOTH_DENIED")
'@
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<observatory-http-negative>','exec'))"
    $Outcome=Docker-Text @('exec','--user','10001:10001',$ContainerId,'python','-I','-B','-c',$Wrapper)
    if($Outcome.Trim() -cne 'OBSERVATORY_HTTP18756_BOTH_DENIED'){
        throw 'RELEASE_OBSERVATORY_HTTP18756_BYPASS'
    }
    Write-Host 'FORTIS_OBSERVATORY_GATEWAY_HTTP18756_DENIED'
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
# Host-only timing evidence, never a receipt or authorization. Monotonic
# elapsed time is per invocation; UTC joins separate owner actions.
function Write-ReleaseTiming {
    param([string]$Phase)
    if($script:Action -notin @('Check','Apply','Backup','Promote','BackupCleanup','ReleaseStateCleanup','Return')){return}
    if($Phase -cnotmatch '^[A-Z][A-Z0-9_]{0,79}$'){return}
    try {
        Write-Host ('FORTIS_RELEASE_TIMING action={0} phase={1} elapsedMs={2} utc={3}' -f
            $script:Action,$Phase,$script:ReleaseClock.ElapsedMilliseconds,
            [DateTime]::UtcNow.ToString('o',[Globalization.CultureInfo]::InvariantCulture))
    } catch {} # Timing must not replace the release outcome or recovery error.
}
function Assert-ReleaseTimingSelfTest {
    $Prior=$script:Action
    try {
        $script:Action='Check'
        $HostOutput=@(Write-ReleaseTiming 'FIXTURE' 6>&1)
        if($HostOutput.Count -ne 1 -or [string]$HostOutput[0] -cnotmatch '^FORTIS_RELEASE_TIMING action=Check phase=FIXTURE elapsedMs=[0-9]+ utc=[0-9T:.Z-]+$'){
            throw 'RELEASE_TIMING_SELFTEST_FAILED'
        }
        if(@(Write-ReleaseTiming 'invalid phase' 6>&1).Count -ne 0){throw 'RELEASE_TIMING_LABEL_SELFTEST_FAILED'}
        $script:Action='SelfTest'
        if(@(Write-ReleaseTiming 'FIXTURE' 6>&1).Count -ne 0){throw 'RELEASE_TIMING_SCOPE_SELFTEST_FAILED'}
    } finally {$script:Action=$Prior}
    Write-Host 'FORTIS_RELEASE_TIMING_SELFTEST_PASS'
}
function Step {
    param([string]$Name)
    $script:Step=$Name
    Write-Host ('FORTIS_INTEGRATIONS_STEP_' + $Name)
    Write-ReleaseTiming ('STEP_'+$Name)
}
Write-ReleaseTiming 'ACTION_START'
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
    param([string]$Path,$Value,[switch]$FlushToDisk)
    $SavedR=$script:R;$SavedPath=$script:RecordPath
    try {
        $script:R=$Value;$script:RecordPath=$Path
        if($FlushToDisk){Save-Record -FlushToDisk}else{Save-Record}
    } finally {$script:R=$SavedR;$script:RecordPath=$SavedPath}
}
function Save {
    param([switch]$FlushToDisk)
    # Exact release records only: never recursively serialize the live
    # PowerShell object graph. Abort pre-STOP_SOURCE on unknown/large types.
    Write-Host 'FORTIS_INTEGRATIONS_RECORD_BOUNDED_SERIALIZE_START'
    $JsonText=ConvertTo-BoundedReleaseJson $script:R
    Write-Host 'FORTIS_INTEGRATIONS_RECORD_BOUNDED_SERIALIZE_PASS'
    Save-Record -SerializedJson $JsonText -FlushToDisk:$FlushToDisk
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
function Assert-NativeRepoRead {
    $Code=@'
import json
from fortis_approvals.workflow.client import default_client
c=default_client(); assert c.github.list_branches('fortis-approvals',per_page=1)['items']
print(json.dumps({'nativeCapabilities':True,'githubRead':True}))
'@
    $Readback=Repo-JSON $Code
    if($Readback.nativeCapabilities -ne $true -or $Readback.githubRead -ne $true){
        throw 'RELEASE_REPO_CLIENT_PREFLIGHT_FAILED'
    }
}
function Assert-PairedReleaseProbes {
    param($Source,[string]$Requested)
    $Release=Read-Private $Source.path
    if($Release.probesPassed -ne $true -or $Release.probes -isnot [string] -or
       (Get-FileHash -LiteralPath $Source.path -Algorithm SHA256).Hash -ine $Source.hash){
        throw 'RELEASE_FROZEN_PROBE_SOURCE_CHANGED'
    }
    $Result=Image-CLI @('check-frozen-probes') (ConvertTo-Json -Compress @{
        retained=$Release.probes;requested=$Requested})
    if($Result.status -cne 'FROZEN_PROBE_SET_MATCH_ONLY'){
        throw 'RELEASE_FROZEN_PROBE_SET_CHANGED'
    }
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
    $PublishInterlock=$Payload.action -ceq 'successor_interlock_publish'
    $SeedInterlock=$Payload.action -ceq 'successor_interlock_seed'
    $BeginIntent=$Payload.action -ceq 'successor_begin_intent'
    $LatestPublication=$PublishInterlock -and $Payload -is [Collections.IDictionary] -and $Payload.Contains('latest')
    if($SeedInterlock){
        if(-not $Root -or $Mounts.Count -ne 6 -or
           $Mounts[1] -cne 'type=volume,source=fortis-r7-maintenance-interlock,target=/run/r7-maintenance-source,readonly,volume-nocopy' -or
           $Mounts[3] -cne 'type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,volume-nocopy' -or
           $Mounts[5] -cne 'type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,volume-nocopy'){
            throw 'RELEASE_SUCCESSOR_SEED_MOUNT_INVALID'
        }
        foreach($Volume in @('fortis-r7-maintenance-interlock','fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor')){
            Assert-Volume $Volume
        }
        Assert-OnlyWriter 'fortis-r7-maintenance-interlock'
        Assert-ReleaseVolumeHolders @('fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor') @() 'RELEASE_SUCCESSOR_SEED_HOLDER_CHANGED'
    } elseif($BeginIntent){
        if(-not $Root -or $Mounts.Count -ne 4 -or
           $Mounts[1] -cne 'type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,readonly,volume-nocopy' -or
           $Mounts[3] -cne 'type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,volume-nocopy'){
            throw 'RELEASE_SUCCESSOR_BEGIN_INTENT_MOUNT_INVALID'
        }
        foreach($Volume in @('fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor')){
            Assert-Volume $Volume;Assert-OnlyWriter $Volume
        }
    } elseif($LatestPublication){
        if(-not $Root -or $Mounts.Count -ne 4 -or
           $Mounts[1] -cne 'type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,volume-nocopy' -or
           $Mounts[3] -cne 'type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,volume-nocopy'){
            throw 'RELEASE_SUCCESSOR_PUBLICATION_MOUNT_INVALID'
        }
        foreach($Volume in @('fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor')){
            Assert-Volume $Volume
            Assert-OnlyWriter $Volume
        }
    } elseif($PublishInterlock){
        if(-not $Root -or $Mounts.Count -ne 2 -or
           $Mounts[1] -cne 'type=volume,source=fortis-r7-maintenance-interlock,target=/run/r7-maintenance,volume-nocopy'){
            throw 'RELEASE_SUCCESSOR_PUBLICATION_MOUNT_INVALID'
        }
        Assert-Volume 'fortis-r7-maintenance-interlock'
    }
    $Identity='10001:10001';if($Root){$Identity='0:0'}
    $Arguments=@('run','--rm','-i','--pull=never','--network','none','--read-only','--user',$Identity,
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','256m',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=32m')
    if($PublishInterlock -or $SeedInterlock -or $BeginIntent){$Arguments+=@('--cap-add','DAC_OVERRIDE')}
    elseif($Root){$Arguments+=@('--cap-add','CHOWN','--cap-add','DAC_OVERRIDE')}
    $Code="import runpy;runpy.run_path('/opt/fortis/operator/state_helpers.py',run_name='__main__')"
    $Encoded=Code64 $Code;$Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<state-helper>','exec'))"
    $Native=@{}
    if($Payload.action -ceq 'clone'){
        $Native['DiagnosticDockerClone']=$true
        # inspect + byte-preserved copy/fsync + before/after hash over native
        # artifacts (1.8 GiB observed). Finite 30m only for protected clone.
        $Native['WaitTimeoutMs']=1800000
    } elseif($Payload.action -cin @('inspect','uncertain_growth_snapshot','uncertain_growth_review','successor_freeze_inspect','successor_freeze_apply_verify')){
        # SQLite integrity_check plus SHA256 of every retained artifact. The
        # general Docker/PowerShell helper limit remains 120s elsewhere.
        $Native['WaitTimeoutMs']=900000
    }
    $TimedAction=$Payload.action -cin @('inspect','clone','uncertain_growth_snapshot','uncertain_growth_review','successor_freeze_inspect','successor_freeze_apply_verify')
    if($TimedAction){Write-ReleaseTiming ('HELPER_'+$Payload.action.ToUpperInvariant()+'_BEGIN')}
    try {
        (Private-Process ($Arguments+$Mounts+@('--entrypoint','python',$script:Image,'-I','-B','-c',$Wrapper)) (ConvertTo-Json -InputObject $Payload -Depth 25 -Compress) @Native) | ConvertFrom-Json
    } finally {
        if($TimedAction){Write-ReleaseTiming ('HELPER_'+$Payload.action.ToUpperInvariant()+'_END')}
    }
}
function Read-SuccessorFreezeSeal {
    param($Payload,[string]$StateVolume,[string]$InterlockVolume)
    # The caller must already hold the controller lock and provide the
    # authenticated latest record and witnesses for the current phase.
    if($Payload.action -cnotin @('successor_freeze_inspect','successor_freeze_apply_verify') -or
       $StateVolume -ceq $InterlockVolume -or
       $InterlockVolume -cne 'fortis-r7-maintenance-interlock'){
        throw 'RELEASE_SUCCESSOR_FREEZE_BINDING_INVALID'
    }
    # v2 is a closed mode of the protected Check payload, not a caller path.
    $Latest=if($Payload -is [Collections.IDictionary]){$Payload['latestPin']}
        else{$Field=$Payload.PSObject.Properties['latestPin'];if($Field){$Field.Value}}
    if($null -ne $Latest -and ($Latest -isnot [bool] -or -not $Latest)){
        throw 'RELEASE_SUCCESSOR_FREEZE_BINDING_INVALID'
    }
    if($Latest){$InterlockVolume='fortis-r7-maintenance-interlock-v2'}
    Assert-Volume $StateVolume
    Assert-Volume $InterlockVolume
    $Mounts=@('--mount',('type=volume,source='+$StateVolume+',target=/source,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$InterlockVolume+',target=/run/r7-maintenance,readonly,volume-nocopy'))
    if($Latest){
        Assert-Volume 'fortis-r7-maintenance-anchor'
        $Mounts+=@('--mount','type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,readonly,volume-nocopy')
    }
    $Frozen=State-Helper $Payload $Mounts
    if($Payload -is [Collections.IDictionary] -and $Payload.Contains('prepare')){
        $Produced=$Frozen.payload
        if(-not $Produced -or $Produced.PSObject.Properties['prepare'] -or
           $Produced.stateDigest -cnotmatch '^[0-9a-f]{64}$' -or
           $Produced.workerAttestationDigest -cnotmatch '^[0-9a-f]{64}$'){
            throw 'RELEASE_SUCCESSOR_FREEZE_SEAL_CHANGED'
        }
        foreach($Field in $Payload.Keys){
            if($Field -cne 'prepare' -and (-not $Produced.PSObject.Properties[$Field] -or
                -not (Same-Json $Produced.$Field $Payload[$Field]))){throw 'RELEASE_SUCCESSOR_FREEZE_SEAL_CHANGED'}
        }
        $Payload=$Produced
    }
    $Binding=$Frozen.seal
    if($Binding.result -cne 'FREEZE_BINDINGS_MATCH_ONLY' -or
       $Binding.attemptId -cne $Payload.attemptId -or
       $Binding.restrictionDigest -cne $Payload.restrictionDigest -or
       ($Payload.action -ceq 'successor_freeze_inspect' -and
        $Binding.interlockDigest -cne $Payload.interlockDigest) -or
       ($Payload.action -ceq 'successor_freeze_apply_verify' -and
        -not (Same-Json $Binding $Payload.checkSeal)) -or
       $Binding.registryDigest -cne $Payload.registryDigest -or
       $Binding.stateReceiptDigest -cne $Payload.stateDigest -or
       $Binding.companionDigest -cne $Payload.companionDigest -or
       $Binding.workerAttestationDigest -cne $Payload.workerAttestationDigest -or
       $null -eq $Frozen.sourceReceipt.sha256 -or $null -eq $Frozen.sourceReceipt.summary){
        throw 'RELEASE_SUCCESSOR_FREEZE_SEAL_CHANGED'
    }
    return $Frozen
}
function Read-BootstrapSeedSource {
    param($Source,[switch]$Live,[switch]$Transition)
    if($Live -and $Transition){throw 'RELEASE_SUCCESSOR_SEED_MODE_INVALID'}
    # This one-time seed is NOT ordinary deployment admission. The enclosing
    # controller must already own the lock and authenticate the owner review,
    # complete source state/backup proof and pre-effect Return.
    $Commit='073d6f8701595e499eac5a1fa0cbe90accb05819'
    $Run='cd6d3d97350e4f5590d9c3e9ece69580'
    $Nonce='4ec7d8b8-2b51-4457-8b15-6559bcdeae94'
    $Digest='9dd0e18b2f10e5180fccd5831ff6528e973813d0fe0cf29a826bc20c750a18a3'
    $Generation='906410832e42b5f8dc835e20c75fe79bfebbcbf9d149793111a3d67992f377aa'
    if(-not $ConfirmWorkerQuiescent -or $Source.runtime.runId -cne $Run -or
       $Source.runtime.registryReleaseNonce -cne $Nonce -or
       $Source.runtime.maintenanceGeneration -cne $Generation -or
       $Source.runtime.registryDelivery.sourceDelivery.interlockDigest -cne $Digest -or
       $Source.path -cne (Join-Path $ReleaseBase ($Run+'\record.json')) -or
       $Source.hash -ine 'a8e717f425982036530aa04115d56720eb81a095e443e9c1023979d562d5fa4e' -or
       (Get-FileHash -LiteralPath $Source.path -Algorithm SHA256).Hash -cne $Source.hash -or
       (Read-Private $Pointer).record -cne $Source.path -or
       (Get-FileHash -LiteralPath $PrimaryPointer -Algorithm SHA256).Hash -ine '1a4a83906c54f878f21f7acec0c999d4ecfa09e9efa5e2c65be70679a30f2e2d'){
        throw 'RELEASE_SUCCESSOR_SEED_SOURCE_CHANGED'
    }
    $Primary=Read-Private $PrimaryPointer
    $Original=Read-Private $Source.path
    $Pair=$Original.correctivePair
    if($Primary.sourceRecord -cne $Source.path -or $Primary.sourceHash -cne $Source.hash -or
       -not (Same-Json $Primary.runtime $Source.runtime) -or
       $Source.runtime.pilotId -cne '2a6e198d6356ed225e61cad93938e1f40f4f13fe99450e782c93ddbfc6cba417' -or
       $Pair.targetRegistryId -cne 'fb747224e917dc88653dac29961f2d11bebca6023c9f73317c4ce6ce7597ae18'){
        throw 'RELEASE_SUCCESSOR_SEED_SOURCE_CHANGED'
    }
    $Old=Container $Source.runtime.pilotId
    $Status=if($Live){'running'}else{'exited'}
    $Restart=if($Live){'unless-stopped'}else{'no'}
    if($Old.Id -cne $Source.runtime.pilotId -or $Old.Image -cne $Source.runtime.image -or
       ($Transition -and ($Old.State.Status -cnotin @('running','exited') -or
        $Old.HostConfig.RestartPolicy.Name -cnotin @('no','unless-stopped'))) -or
       (-not $Transition -and ($Old.State.Status -cne $Status -or $Old.HostConfig.RestartPolicy.Name -cne $Restart))){
        throw 'RELEASE_SUCCESSOR_SEED_SOURCE_NOT_FROZEN'
    }
    $OldMount=@($Old.Mounts|Where-Object{$_.Type -ceq 'volume' -and $_.Name -ceq 'fortis-r7-maintenance-interlock' -and
        $_.Source -ceq '/var/lib/docker/volumes/fortis-r7-maintenance-interlock/_data' -and
        $_.Destination -ceq '/run/r7-maintenance' -and $_.RW -is [bool] -and -not $_.RW})
    if($OldMount.Count -ne 1){throw 'RELEASE_SUCCESSOR_SEED_SOURCE_CHANGED'}
    $OldRegistry=Container $Pair.targetRegistryId
    if($Transition){
        Assert-CorrectiveRegistryContainer $OldRegistry $Nonce $Pair.targetRegistryImage $Pair.targetRegistryProfile 'writer' $Commit -Status $OldRegistry.State.Status -BootstrapRetained
        # A stopped Registry cannot answer a peer challenge. Use the same
        # complete Docker/mount guard, and repeat the live proof on Return
        # after restoring the Registry first. No normalization of source DB.
        Admit $Old $Source.runtime -AllowUnhealthy -RegistryReturnSource -BootstrapRetained
        if($Old.State.Status -ceq 'running' -and $OldRegistry.State.Status -cne 'running'){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_SOURCE_ORDER_CHANGED'
        }
    } else {
        Assert-CorrectiveRegistryContainer $OldRegistry $Nonce $Pair.targetRegistryImage $Pair.targetRegistryProfile 'writer' $Commit -Status $Status -Accepted:$Live
    }
    Assert-CorrectiveRegistryContainer (Container $Pair.targetPreviewId) $Nonce $Pair.targetRegistryImage $Pair.targetRegistryProfile 'preview' $Commit -Status 'exited'
    Assert-CorrectiveTargetHolders $Nonce @($Old.Id,$Pair.targetRegistryId,$Pair.targetPreviewId)
    if($Live){
        if(Test-Path -LiteralPath (Join-Path $ReleaseBase 'maintenance-publication-v2.json')){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_ALREADY_SEEDED'
        }
        $Actual=Read-CorrectiveCheckpoint $Pair.targetRegistryId $Nonce $Pair.targetRegistryProfile $Pair.targetRegistryImage 3 $Commit
        if(-not (Same-Json $Actual $Pair.checkpoints.target)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_SOURCE_CHECKPOINT_CHANGED'}
        Admit-Source $Old $Source
        Assert-OnlyWriter $Source.runtime.stateVolume $Old.Id
        Assert-OnlyWriter ('fortis-registry-state-e13b-'+$Nonce.Replace('-','')) $Pair.targetRegistryId
    } elseif($Transition){
        Assert-OnlyWriter $Source.runtime.stateVolume $Old.Id
        Assert-OnlyWriter ('fortis-registry-state-e13b-'+$Nonce.Replace('-','')) $OldRegistry.Id
    } else {
        Assert-OnlyWriter $Source.runtime.stateVolume
        Assert-OnlyWriter ('fortis-registry-state-e13b-'+$Nonce.Replace('-',''))
    }
    # Read the original #288 retained publication, not a new genesis.
    $Anchor=Read-Private (Join-Path $ReleaseBase 'maintenance-publication-3ac0e38d26184b51890097107f727785.json')
    if($Anchor.schema -cne 'fortis-successor-maintenance-publication-v1' -or
       $Anchor.state -cne 'Committed' -or $Anchor.digest -cne $Digest -or
       $Anchor.record.generation -cne $Generation -or $Anchor.record.phase -cne 'NORMAL' -or $Anchor.record.sequence -ne 0){
        throw 'RELEASE_SUCCESSOR_SEED_SOURCE_CHANGED'
    }
    return $Anchor
}
function Assert-BootstrapFrozenCheck {
    param($Source,$CheckPath,$CheckHash)
    # This is the first physical freeze boundary, not a live DRAINING
    # attestation. The original owner Check must already be durably bound
    # to the pre-effect attempt; never derive it from a later stopped state.
    if($CheckHash -cnotmatch '^[0-9a-fA-F]{64}$' -or
       (Get-FileHash -LiteralPath $CheckPath -Algorithm SHA256).Hash -ine $CheckHash){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_CHECK_CHANGED'
    }
    $AttemptPath=(Read-Private $AttemptPointer).record
    if($AttemptPath -cne $script:RecordPath){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_CHECK_CHANGED'}
    $Attempt=Read-Private $AttemptPath
    $Check=Read-Private $CheckPath
    $Binding=$Check.binding
    if($Attempt.schema -cne 'fortis-extension-release-v1' -or $Attempt.phase -cne 'Prepared' -or
       $Attempt.activated -ne $false -or $Attempt.probesPassed -ne $false -or
       $Attempt.bootstrapCheckRecord -cne $CheckPath -or $Attempt.bootstrapCheckHash -ine $CheckHash -or
       $Attempt.source.path -cne $Source.path -or $Attempt.source.hash -cne $Source.hash -or
       $Check.schema -cne 'fortis-extension-image-check-v1' -or $Check.phase -cne 'Ready' -or
       $Binding.sourceRecord -cne $Source.path -or $Binding.sourceHash -cne $Source.hash -or
       $Binding.sourceContainerId -cne $Source.runtime.pilotId -or $Binding.sourceImage -cne $Source.runtime.image -or
       $Binding.sourceStateVolume -cne $Source.runtime.stateVolume -or $Binding.sourceRunId -cne $Source.runtime.runId -or
       $Binding.image -cne $Attempt.runtime.image -or $Binding.registryReleaseNonce -cne $Attempt.runtime.registryReleaseNonce -or
       $Binding.confirmWorkerQuiescent -ne $true -or $Binding.allowUncertainGrowth -ne $false -or
       $Binding.acceptUnverifiedRestore -ne $false -or $Binding.preserveApprovedRequest -or
       $null -eq $Check.sourceReceipt -or -not (Same-Json $Attempt.sourceReceipt $Check.sourceReceipt)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_CHECK_CHANGED'
    }
    foreach($Pin in @(@($Pointer,$Binding.currentPointerHash),@($PrimaryPointer,$Binding.primaryPointerHash),
        @((Join-Path $ReleaseBase 'primary-backup.json'),$Binding.backupPointerHash))){
        if((Get-FileHash -LiteralPath $Pin[0] -Algorithm SHA256).Hash -cne $Pin[1]){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_CHECK_CHANGED'
        }
    }
    Assert-OnlyWriter $Source.runtime.stateVolume
    if(-not (Same-Json (Receipt $Source.runtime.stateVolume -Exact:$Binding.requireExactUncertain -ExactClaimed:$Binding.requireExactClaimed -ExactApproved:$Binding.requireExactApproved) $Check.sourceReceipt)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_FROZEN_GATEWAY_CHANGED'
    }
    $Pair=(Read-Private $Source.path).correctivePair
    $Frozen=Read-CorrectiveCheckpoint $Pair.targetRegistryId $Source.runtime.registryReleaseNonce $Pair.targetRegistryProfile $Pair.targetRegistryImage 3 '073d6f8701595e499eac5a1fa0cbe90accb05819' -Frozen
    if(-not (Same-Json $Frozen $Pair.checkpoints.target)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_FROZEN_REGISTRY_CHANGED'
    }
    if((Get-FileHash -LiteralPath $CheckPath -Algorithm SHA256).Hash -ine $CheckHash -or
       (Get-FileHash -LiteralPath $Source.path -Algorithm SHA256).Hash -cne $Source.hash -or
       (Read-Private $AttemptPointer).record -cne $AttemptPath){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_CHECK_CHANGED'
    }
}
function Assert-BootstrapFrozenCheckSelfTest {
    $PreviousPath=$script:RecordPath
    try {
        $ReleaseBase=Join-Path ([IO.Path]::GetTempPath()) 'fortis-frozen-fixture'
        $script:RecordPath=Join-Path $ReleaseBase 'attempt.json'
        $AttemptPointer=Join-Path $ReleaseBase 'attempt-pointer.json'
        $Pointer=Join-Path $ReleaseBase 'current.json'
        $PrimaryPointer=Join-Path $ReleaseBase 'primary.json'
        $CheckPath=Join-Path $ReleaseBase 'check.json'
        $CheckHash='a'*64;$SourceHash='b'*64;$Pin='c'*64
        $Source=@{path=(Join-Path $ReleaseBase 'source.json');hash=$SourceHash;runtime=@{
            pilotId=('d'*64);image=('sha256:'+('e'*64));stateVolume='fixture';runId=('f'*32)
            registryReleaseNonce='fixture-old-nonce'}}
        $Gateway=@{sha256=@{fixture='original'};summary=@{}}
        $Registry=@{sourceRevision=3;eventDigest=('1'*64)}
        $Binding=@{sourceRecord=$Source.path;sourceHash=$SourceHash;sourceContainerId=$Source.runtime.pilotId
            sourceImage=$Source.runtime.image;sourceStateVolume=$Source.runtime.stateVolume;sourceRunId=$Source.runtime.runId
            image=('sha256:'+('2'*64));registryReleaseNonce='fixture-new-nonce';confirmWorkerQuiescent=$true
            allowUncertainGrowth=$false;acceptUnverifiedRestore=$false;preserveApprovedRequest=''
            currentPointerHash=$Pin;primaryPointerHash=$Pin;backupPointerHash=$Pin
            requireExactUncertain=$true;requireExactClaimed=$true;requireExactApproved=$true}
        $Fixture=@{gateway=$Gateway;registry=$Registry;reads=0;hashes=@{};records=@{}}
        $Fixture.records[$AttemptPointer]=@{record=$script:RecordPath}
        $Fixture.records[$script:RecordPath]=@{schema='fortis-extension-release-v1';phase='Prepared';activated=$false
            probesPassed=$false;source=$Source;runtime=@{image=$Binding.image;registryReleaseNonce=$Binding.registryReleaseNonce}
            bootstrapCheckRecord=$CheckPath;bootstrapCheckHash=$CheckHash;sourceReceipt=$Gateway}
        $Fixture.records[$CheckPath]=@{schema='fortis-extension-image-check-v1';phase='Ready';binding=$Binding;sourceReceipt=$Gateway}
        $Fixture.records[$Source.path]=@{correctivePair=@{targetRegistryId='fixture';targetRegistryProfile='profile'
            targetRegistryImage='image';checkpoints=@{target=$Registry}}}
        $Fixture.hashes[$CheckPath]=$CheckHash;$Fixture.hashes[$Source.path]=$SourceHash
        foreach($Path in @($Pointer,$PrimaryPointer,(Join-Path $ReleaseBase 'primary-backup.json'))){$Fixture.hashes[$Path]=$Pin}
        function Read-Private {param($Path) return $Fixture.records[$Path]}
        function Get-FileHash {param($LiteralPath,$Algorithm) return @{Hash=$Fixture.hashes[$LiteralPath]}}
        function Assert-OnlyWriter {param($Volume) if($Volume -cne 'fixture'){throw 'FROZEN_SELFTEST_VOLUME'}}
        function Receipt {param($Volume,[switch]$Exact,[switch]$ExactClaimed,[switch]$ExactApproved)
            if($Volume -cne 'fixture' -or -not $Exact -or -not $ExactClaimed -or -not $ExactApproved){throw 'FROZEN_SELFTEST_SCOPE'}
            return $Fixture.gateway}
        function Read-CorrectiveCheckpoint {param($Id,$Nonce,$Profile,$Image,$Revision,$Commit,[switch]$Frozen)
            if($Id -cne 'fixture' -or $Nonce -cne 'fixture-old-nonce' -or $Revision -ne 3 -or -not $Frozen){
                throw 'FROZEN_SELFTEST_REGISTRY_BINDING'}
            $Fixture.reads++;return $Fixture.registry}
        Assert-BootstrapFrozenCheck $Source $CheckPath $CheckHash
        $Fixture.gateway=@{sha256=@{fixture='changed'};summary=@{}}
        try {Assert-BootstrapFrozenCheck $Source $CheckPath $CheckHash;throw 'FROZEN_SELFTEST_GATEWAY_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_FROZEN_GATEWAY_CHANGED'){throw}}
        $Fixture.gateway=$Gateway;$Fixture.registry=@{sourceRevision=3;eventDigest=('0'*64)}
        try {Assert-BootstrapFrozenCheck $Source $CheckPath $CheckHash;throw 'FROZEN_SELFTEST_REGISTRY_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_FROZEN_REGISTRY_CHANGED'){throw}}
        $Fixture.registry=$Registry;$Fixture.hashes[$PrimaryPointer]='0'*64
        try {Assert-BootstrapFrozenCheck $Source $CheckPath $CheckHash;throw 'FROZEN_SELFTEST_POINTER_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_CHECK_CHANGED'){throw}}
        if($Fixture.reads -ne 2){throw 'FROZEN_SELFTEST_READBACK'}
    } finally {$script:RecordPath=$PreviousPath}
    Write-Host 'FORTIS_SUCCESSOR_BOOTSTRAP_FROZEN_CHECK_SELFTEST_PASS'
}
function Initialize-SuccessorBootstrapInterlock {
    param($Source,[string]$CheckPath,[string]$CheckHash)
    $Old=Read-BootstrapSeedSource $Source
    Assert-BootstrapFrozenCheck $Source $CheckPath $CheckHash
    if(-not (Same-Json (Read-BootstrapSeedSource $Source) $Old)){throw 'RELEASE_SUCCESSOR_SEED_SOURCE_CHANGED'}
    $Path=Join-Path $ReleaseBase 'maintenance-publication-v2.json'
    $Intent=[ordered]@{schema='fortis-successor-maintenance-publication-v2';state='Pending'
        sourceRecordHash=$Source.hash;record=$Old.record;digest=$Old.digest;registryDigest=$null}
    $Committed=[ordered]@{schema=$Intent.schema;state='Committed';sourceRecordHash=$Source.hash
        record=$Old.record;digest=$Old.digest;registryDigest=$null}
    $Mounts=@('--mount','type=volume,source=fortis-r7-maintenance-interlock,target=/run/r7-maintenance-source,readonly,volume-nocopy',
        '--mount','type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,volume-nocopy',
        '--mount','type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,volume-nocopy')
    $Payload=@{action='successor_interlock_seed';mode='readback';record=$Old.record;digest=$Old.digest}
    $Existing=if(Test-Path -LiteralPath $Path){Read-Private $Path}
    $Actual=State-Helper $Payload $Mounts -Root
    if($null -eq $Existing){
        if($Actual.position -cne 'EMPTY' -or $null -ne $Actual.latest){
            throw 'RELEASE_SUCCESSOR_SEED_UNOWNED_STATE'
        }
        Write-Private $Path $Intent -FlushToDisk
        $Existing=Read-Private $Path
    }
    $WasCommitted=Same-Json $Existing $Committed
    if(-not $WasCommitted -and -not (Same-Json $Existing $Intent)){
        throw 'RELEASE_SUCCESSOR_SEED_INTENT_CHANGED'
    }
    if($Actual.position -ceq 'EMPTY' -and -not $WasCommitted){
        $Payload.mode='seed'
        $Actual=State-Helper $Payload $Mounts -Root
    }
    if($Actual.position -cne 'SEEDED' -or $Actual.digest -cne $Old.digest -or
       $Actual.latest.interlockDigest -cne $Old.digest -or
       $Actual.latest.generation -cne $Old.record.generation -or
       $Actual.latest.phase -cne 'NORMAL' -or $Actual.latest.sequence -ne 0 -or
       $Actual.latest.instanceId -cne $Old.record.registryInstanceId -or
       $Actual.latest.scopeDigest -cne $Old.record.scopeDigest -or $null -ne $Actual.latest.registryDigest -or
       $Actual.latest.state -cnotin @('Pending','Committed') -or
       (-not $WasCommitted -and $Actual.latest.state -cne 'Pending') -or
       -not (Same-Json (Read-BootstrapSeedSource $Source) $Old)){
        throw 'RELEASE_SUCCESSOR_SEED_UNCONFIRMED'
    }
    if(-not $WasCommitted){
        Write-Private $Path $Committed -FlushToDisk
    }
    if(-not (Same-Json (Read-Private $Path) $Committed)){throw 'RELEASE_SUCCESSOR_SEED_UNCONFIRMED'}
    $Payload.mode='commit'
    $Final=State-Helper $Payload $Mounts -Root
    $Expected=[ordered]@{schemaVersion=1;state='Committed';instanceId=$Old.record.registryInstanceId
        scopeDigest=$Old.record.scopeDigest;sequence=0;generation=$Old.record.generation;phase='NORMAL'
        interlockDigest=$Old.digest;registryDigest=$null}
    # Compare every field; JSON member order is not authority.
    if($Final.position -cne 'SEEDED' -or $Final.digest -cne $Old.digest -or
       @($Final.latest.PSObject.Properties).Count -ne 9 -or
       @($Expected.Keys|Where-Object{$Final.latest.$_ -cne $Expected[$_]}).Count -ne 0 -or
       -not (Same-Json (Read-BootstrapSeedSource $Source) $Old)){
        throw 'RELEASE_SUCCESSOR_SEED_UNCONFIRMED'
    }
    return $Committed
}


function Read-BootstrapOwnerReviewProof {
    param([string]$Path,$Pair)
    # This is the separately retained owner review of the exact proposal
    # and predecessor, not a document produced by the post-merge Check.
    # Existing owner ACL/reparse checks authenticate the protected local
    # record; the file hash binds it to the Registry's replayed review.
    if(-not $Path){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_OWNER_REVIEW_CHANGED'}
    $Witness=$Pair.checked.registry.review
    $Proof=Read-Private $Path
    if($Proof.schema -cne 'fortis-registry-bootstrap-review-v1' -or
       $Proof.decision -cne 'APPROVE_BOOTSTRAP_MERGE' -or
       $Proof.reviewContentDigest -cnotmatch '^[0-9a-f]{64}$' -or
       $Proof.reviewContentDigest -cne $Witness.reviewContentDigest -or
       ($Proof.reviewedAt -isnot [long] -and $Proof.reviewedAt -isnot [int]) -or
       $Proof.reviewedAt -le 0 -or
       @($Proof.PSObject.Properties).Count -ne 4 -or
       (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $Witness.ownerReviewProofDigest){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_OWNER_REVIEW_CHANGED'
    }
    return $Proof
}
function New-BootstrapOwnerGo {
    param($Source,[string]$CheckPath,[string]$CheckHash,[string]$ReviewProofPath)
    # Caller owns the existing release controller lock, verifies the same
    # image Check and performs final live admission before publishing attempt.
    $Check=Read-Private $CheckPath
    $Pair=$Check.binding.bootstrapPair
    if($Check.schema -cne 'fortis-extension-image-check-v1' -or $Check.phase -cne 'Ready' -or
       $null -eq $Pair -or -not (Same-Json $Pair $script:BootstrapPair) -or
       $Check.binding.sourceHash -ine $Source.hash -or $Check.binding.sourceRecord -cne $Source.path -or
       (Get-FileHash -LiteralPath $CheckPath -Algorithm SHA256).Hash -ine $CheckHash -or
       $null -eq $Check.sourceReceipt){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_CHECK_CHANGED'
    }
    # The independent pre-merge review reference is explicitly acknowledged,
    # not manufactured by the controller from the post-merge observation.
    $Proof=Read-BootstrapOwnerReviewProof $ReviewProofPath $Pair
    $ReviewProof=$Pair.checked.registry.review.ownerReviewProofDigest
    if($ReviewProof -cnotmatch '^[0-9a-f]{64}$' -or $Pair.compatibilityDigest -cnotmatch '^[0-9a-f]{64}$'){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_OWNER_REVIEW_CHANGED'
    }
    Write-Host ('FORTIS_BOOTSTRAP_REVIEW_SHA256='+$Pair.reviewSha256)
    Write-Host ('FORTIS_BOOTSTRAP_REVIEW_PROOF_SHA256='+$ReviewProof)
    Write-Host ('FORTIS_BOOTSTRAP_EVIDENCE_SHA256='+$Pair.evidenceSha256)
    Write-Host ('FORTIS_BOOTSTRAP_COMPATIBILITY_SHA256='+$Pair.compatibilityDigest)
    $Confirm='APPLY BOOTSTRAP '+$CheckHash.ToLowerInvariant()
    if((Read-Host ('Confirm the independently reviewed merge and exact frozen-pair Check; type '+$Confirm)) -cne $Confirm){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_OWNER_GO_REQUIRED'
    }
    if((Get-FileHash -LiteralPath $CheckPath -Algorithm SHA256).Hash -ine $CheckHash -or
       (Get-FileHash -LiteralPath $Source.path -Algorithm SHA256).Hash -ine $Source.hash -or
       -not (Same-Json (Read-BootstrapOwnerReviewProof $ReviewProofPath $Pair) $Proof)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_CHECK_CHANGED'
    }
    # Stable identity/time/generation are saved in the protected attempt
    # before any stop. Recovery must never create a second owner intent.
    return [ordered]@{schemaVersion=1;attemptId=[Guid]::NewGuid().ToString('D')
        checkDigest=$CheckHash.ToLowerInvariant();compatibilityDigest=$Pair.compatibilityDigest
        sourceRecordDigest=$Source.hash.ToLowerInvariant();reviewDigest=$Pair.reviewSha256
        evidenceDigest=$Pair.evidenceSha256;reviewProofDigest=$ReviewProof
        targetGeneration=(Sha256-Utf8 ([Guid]::NewGuid().ToString('D')+[Guid]::NewGuid().ToString('D'))).ToLowerInvariant()
        recordedAt=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()}
}
function Read-BootstrapFrozenIntent {
    param($Source,[string]$CheckPath,[string]$CheckHash,[switch]$Returning,[switch]$Runtime)
    # Every effect consumes the original protected Check and durable owner
    # attempt pointer, never mutable arguments or a fresh synthetic GO.
    $Attempt=Read-Private $script:RecordPath
    $Check=Read-Private $CheckPath
    if($Attempt.PSObject.Properties['ordinaryHandover']){
        return (Read-OrdinaryFrozenIntent $Source $CheckPath $CheckHash $Attempt $Check -Returning:$Returning -Runtime:$Runtime)
    }
    $Pair=$Check.binding.bootstrapPair
    $Go=$Attempt.bootstrapOwnerGo
    $DeliveryField=$Attempt.PSObject.Properties['bootstrapDelivery']
    $RuntimeBound=$Attempt.runtime.PSObject.Properties['registryDelivery']
    if(($Runtime -or $Attempt.phase -cin @('Created','Staged','Complete')) -and -not $RuntimeBound){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'
    }
    if($RuntimeBound){
        if(-not $DeliveryField -or -not (Same-Json $RuntimeBound.Value $DeliveryField.Value) -or
           $Attempt.runtime.maintenanceGeneration -cne $Go.targetGeneration -or
           $Attempt.runtime.registryProfileDigest -cne $Attempt.bootstrapMaterials.gatewayProfileDigest){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'
        }
    }
    $AllowedPhases=if($Returning){@('Prepared','Created','Staged','Returned')}
        elseif($Runtime){@('Created','Staged','Complete')}else{@('Prepared')}
    if($Check.schema -cne 'fortis-extension-image-check-v1' -or $Check.phase -cne 'Ready' -or
       $null -eq $Check.sourceReceipt -or $null -eq $Pair -or $null -eq $Go -or $Go.schemaVersion -ne 1 -or
       $Check.binding.sourceRecord -cne $Source.path -or $Check.binding.sourceHash -ine $Source.hash -or
       (Get-FileHash -LiteralPath $Source.path -Algorithm SHA256).Hash -ine $Source.hash -or
       $Attempt.schema -cne 'fortis-extension-release-v1' -or $Attempt.phase -cnotin $AllowedPhases -or
       (-not $Runtime -and $Attempt.activated -ne $false) -or
       (-not ($Runtime -or $Returning) -and $Attempt.probesPassed -ne $false) -or
       $Attempt.bootstrapCheckRecord -cne $CheckPath -or $Attempt.bootstrapCheckHash -ine $CheckHash -or
       $Attempt.bootstrapReviewProofRecord -cne $Check.binding.bootstrapReviewProofRecord -or
       (Read-Private $AttemptPointer).record -cne $script:RecordPath -or
       (Get-FileHash -LiteralPath $CheckPath -Algorithm SHA256).Hash -ine $CheckHash -or
       $Attempt.source.hash -ine $Source.hash -or $Attempt.source.path -cne $Source.path -or
       $Go.checkDigest -cne $CheckHash.ToLowerInvariant() -or $Go.sourceRecordDigest -cne $Source.hash.ToLowerInvariant() -or
       $Go.compatibilityDigest -cne $Pair.compatibilityDigest -or $Go.reviewDigest -cne $Pair.reviewSha256 -or
       $Go.evidenceDigest -cne $Pair.evidenceSha256 -or
       $Go.reviewProofDigest -cne $Pair.checked.registry.review.ownerReviewProofDigest -or
       $Go.targetGeneration -cnotmatch '^[0-9a-f]{64}$' -or
       $Go.targetGeneration -ceq $Pair.checked.registry.binding.generation -or
       $Go.attemptId -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
       $Attempt.runtime.image -cne ('sha256:'+$Pair.checked.artifacts.gateway) -or
       $Pair.registryImage -cne ('sha256:'+$Pair.checked.artifacts.registry) -or
       $Attempt.runtime.registryReleaseNonce -cne $Pair.checked.gateway.releaseNonce -or
       (-not $RuntimeBound -and $Attempt.runtime.registryProfileDigest -cne $Pair.checked.gateway.profileDigest) -or
       -not (Same-Json $Attempt.sourceReceipt $Check.sourceReceipt)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_OWNER_GO_CHANGED'
    }
    $Proof=Read-BootstrapOwnerReviewProof $Attempt.bootstrapReviewProofRecord $Pair
    if($Proof.reviewedAt -gt $Go.recordedAt){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_OWNER_REVIEW_CHANGED'}
    return @{attempt=$Attempt;check=$Check;pair=$Pair;go=$Go}
}
function Read-OrdinaryFrozenIntent {
    param($Source,$CheckPath,$CheckHash,$Attempt,$Check,[switch]$Returning,[switch]$Runtime)
    $Ref=$Attempt.ordinaryHandover
    $ContextPath=Join-Path $ReleaseBase ('maintenance-'+$Source.runtime.runId+'.json')
    $StopPath=Join-Path (Split-Path $CheckPath -Parent) 'apply-stop.json'
    if($Ref.contextRecord -cne $ContextPath -or $Ref.stopRecord -cne $StopPath -or
       (Get-FileHash -LiteralPath $ContextPath -Algorithm SHA256).Hash -ine $Ref.contextHash -or
       (Get-FileHash -LiteralPath $StopPath -Algorithm SHA256).Hash -ine $Ref.stopHash -or
       (Get-FileHash -LiteralPath $CheckPath -Algorithm SHA256).Hash -ine $CheckHash -or
       (Get-FileHash -LiteralPath $Source.path -Algorithm SHA256).Hash -ine $Source.hash -or
       $Attempt.bootstrapCheckRecord -cne $CheckPath -or $Attempt.bootstrapCheckHash -ine $CheckHash -or
       (Read-Private $AttemptPointer).record -cne $script:RecordPath){
        throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
    }
    $Context=Read-Private $ContextPath;$Stop=Read-Private $StopPath
    $Checked=$Context.intent.compatibility;$Auth=$Context.intent.authorization;$Go=$Attempt.bootstrapOwnerGo
    $Allowed=if($Returning){@('Prepared','Created','Staged','Returned')}elseif($Runtime){@('Created','Staged','Complete')}else{@('Prepared')}
    if($Attempt.schema -cne 'fortis-extension-release-v1' -or $Attempt.phase -cnotin $Allowed -or
       (-not $Returning -and $Attempt.PSObject.Properties['ordinaryReturn']) -or
       (-not $Runtime -and $Attempt.activated -ne $false) -or $Attempt.source.hash -ine $Source.hash -or
       $Attempt.source.path -cne $Source.path -or $Check.schema -cne 'fortis-extension-image-check-v1' -or
       $Check.phase -cne 'Ready' -or $Check.binding.sourceRecord -cne $Source.path -or
       $Check.binding.sourceHash -ine $Source.hash -or $Check.binding.ordinaryIntentDigest -cne $Context.intentDigest -or
       $Context.nativeRead.githubRead -ne $true -or
       $Context.nativeRead.intentDigest -cne $Context.intentDigest -or
       -not (Same-Json $Check.binding.ordinaryNativeRead $Context.nativeRead) -or
       $Check.binding.confirmWorkerQuiescent -ne $true -or $Check.binding.allowUncertainGrowth -ne $false -or
       $Check.binding.acceptUnverifiedRestore -ne $false -or $Check.binding.preserveApprovedRequest -or
       $Check.binding.image -cne $Attempt.runtime.image -or $Check.binding.registryReleaseNonce -cne $Auth.targetNonce -or
       $Context.sourceRecordHash -ine $Source.hash -or $Context.intentDigest -cne $Context.begin.intentDigest -or
       $Context.targetNonce -cne $Attempt.runtime.registryReleaseNonce -or
       $Context.targetSourceSha -cne $Check.binding.sourceSha -or
       $Context.targetImageId -cne ('sha256:'+$Checked.artifacts.gateway) -or
       $Context.targetRegistryImage -cne ('sha256:'+$Checked.artifacts.registry) -or
       $Stop.checkedRecordDigest -cne $CheckHash.ToLowerInvariant() -or
       $Stop.sourceRecordDigest -cne $Source.hash.ToLowerInvariant() -or
       $Stop.targetImageId -cne $Attempt.runtime.image -or $Stop.next.phase -cne 'APPLY_STOP' -or
       $Go.schemaVersion -ne 1 -or $Go.intentDigest -cne $Context.intentDigest -or
       $Go.checkDigest -cne $CheckHash.ToLowerInvariant() -or $Go.attemptId -cne $Auth.attemptId -or
       $Go.targetGeneration -cne $Auth.targetGeneration -or $Go.sourceRecordDigest -cne $Auth.sourceRecordDigest -or
       -not (Same-Json $Attempt.sourceReceipt $Check.sourceReceipt)){
        throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
    }
    if($Attempt.runtime.PSObject.Properties['registryDelivery']){
        if(-not $Attempt.PSObject.Properties['bootstrapDelivery'] -or -not $Attempt.PSObject.Properties['bootstrapMaterials'] -or
           -not (Same-Json $Attempt.runtime.registryDelivery $Attempt.bootstrapDelivery) -or
           $Attempt.runtime.maintenanceGeneration -cne $Auth.targetGeneration -or
           $Attempt.runtime.registryProfileDigest -cne $Attempt.bootstrapMaterials.gatewayProfileDigest){
            throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
        }
    }elseif($Runtime -or $Attempt.phase -cin @('Created','Staged','Complete') -or
        $Attempt.runtime.registryProfileDigest -cne $Checked.gateway.profileDigest){
        throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
    }
    $Pair=@{registryImage=$Context.targetRegistryImage;registryProfileSha256=$Checked.registry.profileDigest
        checked=$Checked;compatibilityDigest=$Auth.compatibilityDigest
        finalRoots=@{Gateway=$Checked.roots.gateway;Registry=$Checked.roots.registry}
        backupRoot=$Checked.roots.backup}
    return @{attempt=$Attempt;check=$Check;pair=$Pair;go=$Go;ordinary=@{
        intent=$Context.intent;begin=$Context.begin;check=$Check.maintenanceSeal;sourceReceipt=$Check.sourceReceipt;stop=$Stop}
        context=$Context}
}

function Save-OrdinaryPreparedAttempt {
    param($Source,$Report,$Stop)
    $Path=[IO.Path]::GetFullPath($CheckedImageRecord)
    $Hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    $Check=Read-Private $Path
    $ContextPath=Join-Path $ReleaseBase ('maintenance-'+$Source.runtime.runId+'.json')
    $Context=Read-Private $ContextPath
    if($script:R.phase -cne 'Prepared' -or $script:R.activated -or $script:R.probesPassed -or
       $script:R.runtime.pilotId -or $Check.binding.ordinaryIntentDigest -cne $Context.intentDigest -or
       $Stop.checkedRecordDigest -cne $Hash.ToLowerInvariant() -or
       $Stop.sourceRecordDigest -cne $Source.hash.ToLowerInvariant()){
        throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
    }
    $Confirm='APPLY SUCCESSOR '+$Hash.ToLowerInvariant()
    if((Read-Host ('Type '+$Confirm)) -cne $Confirm){throw 'RELEASE_SUCCESSOR_ORDINARY_OWNER_GO_REQUIRED'}
    $Fresh=Verify-Checked-Image $Source $Report -PrepareSuccessorStop
    if(-not (Same-Json $Fresh $Stop)){throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'}
    $StopPath=Save-SuccessorApplyStopIntent $Stop
    $script:R['ordinaryHandover']=[ordered]@{contextRecord=$ContextPath
        contextHash=(Get-FileHash -LiteralPath $ContextPath -Algorithm SHA256).Hash
        stopRecord=$StopPath;stopHash=(Get-FileHash -LiteralPath $StopPath -Algorithm SHA256).Hash}
    $Auth=$Context.intent.authorization
    $script:R['bootstrapCheckRecord']=$Path;$script:R['bootstrapCheckHash']=$Hash
    $script:R['bootstrapOwnerGo']=[ordered]@{schemaVersion=1;intentDigest=$Context.intentDigest
        checkDigest=$Hash.ToLowerInvariant();sourceRecordDigest=$Auth.sourceRecordDigest
        attemptId=$Auth.attemptId;targetGeneration=$Auth.targetGeneration}
    $script:R.sourceReceipt=$Check.sourceReceipt
    Assert-Release-Production
    Save -FlushToDisk
    Write-Private $AttemptPointer @{schema=1;record=$script:RecordPath} -FlushToDisk
    $null=Read-BootstrapFrozenIntent $Source $Path $Hash
    $script:R=Read-Private $script:RecordPath
}

function Invoke-BootstrapFrozenPair {
    param($Source,[string]$CheckPath,[string]$CheckHash,[switch]$Readback)
    # Private bridge: no listener, no socket mount, no effect on old DB.
    # Initialize performs the full final stopped-source proof and reconciles
    # a lost seed ACK. Once publication advances, use only RO readback.
    $Intent=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
    $Pair=$Intent.pair
    $Nonce=$Intent.attempt.runtime.registryReleaseNonce
    $Id=$Nonce.Replace('-','')
    Assert-CorrectiveTargetHolders $Nonce @() -PreparedProfiles
    $State='fortis-registry-state-e13b-'+$Id
    $ConfigVolume='fortis-registry-config-e13b-'+$Id+'-prepared'
    foreach($Volume in @($State,$ConfigVolume,'fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor')){
        Assert-Volume $Volume
    }
    $RegistryInfo=@(Docker-Json @('image','inspect',$Pair.registryImage))[0]
    if($RegistryInfo.Id -cne $Pair.registryImage -or $RegistryInfo.Config.User -cne '20002:20002' -or
       $RegistryInfo.Config.Labels.'org.opencontainers.image.revision' -cne $Intent.check.binding.sourceSha -or
       @($RegistryInfo.Config.Entrypoint|Where-Object{$_}).Count){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_IMAGE_CHANGED'
    }
    $Seed=Read-BootstrapSeedSource $Source
    if($Readback -or $Intent.attempt.PSObject.Properties['bootstrapBegin']){
        $Readback=$true
        Assert-BootstrapFrozenCheck $Source $CheckPath $CheckHash
    } else {
        $Published=Initialize-SuccessorBootstrapInterlock $Source $CheckPath $CheckHash
        if($Published.digest -cne $Seed.digest){throw 'RELEASE_SUCCESSOR_SEED_UNCONFIRMED'}
    }
    Assert-CorrectiveTargetHolders $Nonce @() -PreparedProfiles
    Assert-ReleaseVolumeHolders @('fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor') @() 'RELEASE_SUCCESSOR_SEED_HOLDER_CHANGED'
    $Code=@'
import json,sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.registry.owner_functional_v1_bootstrap import bootstrap_pair_authorization,begin_bootstrap_pair,read_bootstrap_pair
p=json.load(sys.stdin)
authorization=bootstrap_pair_authorization(p['checked'],p['go'],p['sourceReceipt'],
    review_sha256=p['review'],evidence_sha256=p['evidence'],seed_digest=p['seed'])
args=dict(review_sha256=p['review'],evidence_sha256=p['evidence'],
    source_sha=p['source'],checked=p['checked'],authorization=authorization)
result=(read_bootstrap_pair(p['profile'],seed=p['seedRecord'],**args) if p['readback']
        else begin_bootstrap_pair(p['profile'],**args))
print(json.dumps(result,sort_keys=True,separators=(',',':')))
'@
    $ReadArgs=@('run','--rm','-i','--pull=never','--network','none','--read-only',
        '--name',('fortis-registry-successor-'+$Id),'--user','20002:20002',
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','32','--memory','1024m',
        '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=640m,uid=20002,gid=20002,mode=0700',
        '--mount',('type=volume,source='+$State+',target=/run/fortis-registry-state,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$ConfigVolume+',target=/run/fortis-registry-runtime,readonly,volume-nocopy'),
        $Pair.registryImage)
    $WriteArgs=@('run','--rm','-i','--pull=never','--network','none','--read-only',
        '--name',('fortis-registry-successor-'+$Id),'--user','20002:20002',
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','32','--memory','512m',
        '--mount',('type=volume,source='+$State+',target=/run/fortis-registry-state,volume-nocopy'),
        '--mount',('type=volume,source='+$ConfigVolume+',target=/run/fortis-registry-runtime,readonly,volume-nocopy'),
        '--mount','type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,readonly,volume-nocopy',
        '--mount','type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,readonly,volume-nocopy',
        $Pair.registryImage)
    $Payload=@{profile=$Pair.registryProfileSha256
        review=$Pair.reviewSha256;evidence=$Pair.evidenceSha256;source=$Intent.check.binding.sourceSha
        checked=$Pair.checked;go=$Intent.go;sourceReceipt=$Intent.check.sourceReceipt
        seed=$Seed.digest;seedRecord=$Seed.record;readback=[bool]$Readback}
    if($Readback){
        $Result=(Python-Code $ReadArgs $Code (ConvertTo-Json -Compress -Depth 25 $Payload))|ConvertFrom-Json
    } else {
        try {
            $Result=(Python-Code $WriteArgs $Code (ConvertTo-Json -Compress -Depth 25 $Payload))|ConvertFrom-Json
        } catch {
            # Never repeat a writer blindly. Prove original receipts on a
            # stable RO copy, including surviving WAL after process failure.
            Write-Warning 'RELEASE_SUCCESSOR_BOOTSTRAP_PAIR_READBACK'
            Assert-CorrectiveTargetHolders $Nonce @() -PreparedProfiles
            $Payload.readback=$true
            $Result=(Python-Code $ReadArgs $Code (ConvertTo-Json -Compress -Depth 25 $Payload))|ConvertFrom-Json
        }
    }
    $Plan=$Result.phasePlan
    if($Result.result -cne 'BOOTSTRAP_PAIR_BEGIN_ACCOUNTED_ONLY' -or $Result.hostAccepted -ne $false -or
       $Result.admissionAllowed -ne $false -or $Result.pair.attemptId -cne $Intent.go.attemptId -or
       $Result.pair.compatibilityReadbackDigest -cne $Pair.compatibilityDigest -or
       @($Result.receipts).Count -ne 2 -or @($Result.holdSnapshot.holds).Count -ne 2 -or
       $Plan.proofKind -cne 'BOOTSTRAP_PHYSICAL_FREEZE' -or $Plan.registryDigest -cne $Result.registryDigest -or
       (@($Plan.records|ForEach-Object{$_.phase}) -join ',') -cne 'DRAINING,FROZEN_BEFORE_CHECK,CHECK_SEALED,APPLY_STOP,STAGED_TARGET_FROZEN' -or
       $Plan.records[0].previousDigest -cne $Seed.digest -or $Plan.records[-1].generation -cne $Intent.go.targetGeneration -or
       $Plan.handoff.attemptId -cne $Intent.go.attemptId -or $Plan.handoff.registryDigest -cne $Result.registryDigest){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_PAIR_UNCONFIRMED'
    }
    Assert-CorrectiveTargetHolders $Nonce @() -PreparedProfiles
    $null=Read-BootstrapSeedSource $Source
    $Fresh=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
    if(-not (Same-Json $Fresh.go $Intent.go) -or -not (Same-Json $Fresh.pair $Pair) -or
       -not (Same-Json $Fresh.check $Intent.check)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_OWNER_GO_CHANGED'
    }
    $Previous=$Fresh.attempt.PSObject.Properties['bootstrapBegin']
    if($Previous){
        if(-not (Same-Json $Previous.Value $Result)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_PAIR_CHANGED'}
    } else {
        # Save original readback before publishing any phase. Lost ACK
        # before this save is recovered by the same exact writer intent.
        $Fresh.attempt|Add-Member -NotePropertyName bootstrapBegin -NotePropertyValue $Result
        $script:R=$Fresh.attempt
        Save -FlushToDisk
    }
    $Stored=Read-Private $script:RecordPath
    if(-not (Same-Json $Stored.bootstrapBegin $Result)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_PAIR_CHANGED'}
    $script:R=$Stored
    return $Result
}

function Save-BootstrapPreparedAttempt {
    param($Source,$Report,[string]$CheckPath,[string]$ReviewProofPath)
    if($script:R.phase -cne 'Prepared' -or $script:R.activated -or $script:R.probesPassed -or
       $script:R -isnot [Collections.IDictionary] -or $script:R.runtime.pilotId -or
       [IO.Path]::GetFullPath($CheckPath) -cne [IO.Path]::GetFullPath($CheckedImageRecord)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_ATTEMPT_CHANGED'
    }
    # The original Check binds the previous attempt pointer. Do not write
    # our new pointer until after the final exact read-only verification.
    $CheckPath=[IO.Path]::GetFullPath($CheckPath)
    $ReviewProofPath=[IO.Path]::GetFullPath($ReviewProofPath)
    $CheckHash=(Get-FileHash -LiteralPath $CheckPath -Algorithm SHA256).Hash
    $Check=Read-Private $CheckPath
    if($Check.binding.bootstrapReviewProofRecord -cne $ReviewProofPath){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_OWNER_REVIEW_CHANGED'
    }
    $Go=New-BootstrapOwnerGo $Source $CheckPath $CheckHash $ReviewProofPath
    $Fresh=Read-BootstrapCompatibility $Source -Recheck
    if(-not (Same-Json $Fresh $script:BootstrapPair)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_COMPATIBILITY_CHANGED'}
    $Receipt=Verify-Checked-Image $Source $Report -ReturnReceipt
    if((Get-FileHash -LiteralPath $CheckPath -Algorithm SHA256).Hash -ine $CheckHash -or
       -not (Same-Json $Receipt $Check.sourceReceipt)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_CHECK_CHANGED'
    }
    $script:R['bootstrapCheckRecord']=$CheckPath
    $script:R['bootstrapCheckHash']=$CheckHash
    $script:R['bootstrapReviewProofRecord']=$ReviewProofPath
    $script:R['bootstrapOwnerGo']=$Go
    $script:R.sourceReceipt=$Receipt
    Assert-BootstrapNoReceiver @{attempt=$script:R}
    Assert-Release-Production
    Save -FlushToDisk
    $Stored=Read-Private $script:RecordPath
    if(-not (Same-Json $Stored $script:R)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_ATTEMPT_CHANGED'}
    Write-Private $AttemptPointer @{schema=1;record=$script:RecordPath} -FlushToDisk
    $null=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
    $script:R=Read-Private $script:RecordPath
}
function Invoke-BootstrapPreparedTransition {
    # Caller already owns the existing controller lock and protected
    # Prepared attempt. This block returns a verified passive Registry;
    # the existing Gateway controller must consume the returned delivery.
    $Source=$script:R.source;$Path=$script:R.bootstrapCheckRecord;$Hash=$script:R.bootstrapCheckHash
    $Sealed=$null
    if(-not $script:R.PSObject.Properties['bootstrapMaterials']){
        Stop-BootstrapSourcePair $Source $Path $Hash
        if(-not $script:R.PSObject.Properties['ordinaryHandover']){
            $null=Invoke-BootstrapFrozenPair $Source $Path $Hash
            $null=Publish-BootstrapFrozenPhases $Source $Path $Hash
        }
        $Material=Seal-BootstrapFinalProfiles $Source $Path $Hash
        $Sealed=$Material
    } else {$Material=$script:R.bootstrapMaterials}
    $Delivery=Start-BootstrapReceiver $Source $Path $Hash -Sealed $Sealed
    $P=$script:R.runtime
    if($P.PSObject.Properties['registryDelivery']){
        if(-not (Same-Json $P.registryDelivery $Delivery)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'}
    } else {
        $P|Add-Member -NotePropertyName registryDelivery -NotePropertyValue $Delivery
        $P|Add-Member -NotePropertyName maintenanceGeneration -NotePropertyValue $Delivery.generation
        $P.registryProfileDigest=$Delivery.profileDigest
        Save -FlushToDisk
    }
    $script:RegistryDelivery=$Delivery
    return @{publication=(Read-SuccessorPublication $Source).anchor;material=$Material;delivery=$Delivery}
}

function Publish-BootstrapFrozenPhases {
    param($Source,[string]$CheckPath,[string]$CheckHash)
    # This is the physical bootstrap proof, not live DRAINING. No target
    # receiver may exist yet; STAGED_TARGET_FROZEN requires final material
    # proof separately. Re-read the exact persisted pair, not a phase hash
    # supplied by the caller or another invocation of the writer.
    $Intent=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
    Assert-Release-Production
    Assert-BootstrapNoReceiver $Intent
    $Stored=$Intent.attempt.PSObject.Properties['bootstrapBegin']
    if(-not $Stored){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_PAIR_UNCONFIRMED'}
    $Actual=Invoke-BootstrapFrozenPair $Source $CheckPath $CheckHash -Readback
    if(-not (Same-Json $Actual $Stored.Value)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_PAIR_CHANGED'}
    $Plan=$Actual.phasePlan
    $Seed=Read-BootstrapSeedSource $Source
    $Loaded=Read-SuccessorPublication $Source
    $Anchor=$Loaded.anchor
    $Records=@($Seed.record)+@($Plan.records)
    $Sequence=$Anchor.record.sequence
    if($Sequence -isnot [int] -and $Sequence -isnot [long]){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_PHASE_CHANGED'}
    if($Anchor.schema -cne 'fortis-successor-maintenance-publication-v2' -or
       $Sequence -lt 0 -or $Sequence -gt 4 -or
       -not (Same-Json $Anchor.record $Records[$Sequence]) -or
       ($Sequence -eq 0 -and $Anchor.digest -cne $Seed.digest) -or
       ($Sequence -gt 0 -and ($Anchor.registryDigest -cne $Actual.registryDigest -or
         -not (Same-Json $Anchor.previous $Records[$Sequence-1]))) -or
       ($Anchor.state -ceq 'Pending' -and ($Sequence -eq 4 -or
         -not (Same-Json $Anchor.next $Records[$Sequence+1]) -or $Anchor.nextRegistryDigest -cne $Actual.registryDigest))){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_PHASE_CHANGED'
    }
    # Publish only the missing suffix. The existing publisher reconciles
    # committed predecessor projection / Pending intent before the next
    # exact transition. No reset, replay of earlier phases or new digest.
    if($Sequence -eq 4){
        if($Anchor.state -cne 'Committed' -or
           (Publish-SuccessorInterlock $Source $Records[4] $Actual.registryDigest) -cne $Anchor.digest){
            throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
        }
    } else {
        for($Index=$Sequence+1;$Index -le 4;$Index++){
            $Digest=Publish-SuccessorInterlock $Source $Records[$Index] $Actual.registryDigest
            if($Digest -cne $Records[$Index+1].previousDigest){
                throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
            }
        }
    }
    $Final=(Read-SuccessorPublication $Source).anchor
    if($Final.state -cne 'Committed' -or $Final.digest -cne $Records[5].previousDigest -or
       $Final.registryDigest -cne $Actual.registryDigest -or -not (Same-Json $Final.record $Records[4])){
        throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
    }
    $null=Read-BootstrapSeedSource $Source
    Assert-BootstrapNoReceiver $Intent
    Assert-Release-Production
    return $Final
}

function Assert-PairedFrozenSource {
    param($Intent,$Source,[string[]]$CandidateIds=@())
    if($Intent.ContainsKey('ordinary')){
        $null=Read-OrdinarySuccessorSource $Source -Frozen -CandidateIds $CandidateIds
    }else{$null=Read-BootstrapSeedSource $Source}
}
function Invoke-BootstrapFinalMaterialHelper {
    param($Intent,$Source,$Publication,$Seed,[ValidateSet('State','Registry','Gateway')][string]$Role,
          $RegistryProfile,[switch]$VerifyOnly)
    $Pair=$Intent.pair;$Nonce=$Intent.attempt.runtime.registryReleaseNonce;$Id=$Nonce.Replace('-','')
    Assert-CorrectiveTargetHolders $Nonce @() -PreparedProfiles
    $Ordinary=$Intent.ContainsKey('ordinary')
    if($Ordinary){
        Assert-OperationalMaintenanceHolders $Source @() 'RELEASE_SUCCESSOR_SEED_HOLDER_CHANGED'
        $O=$Intent.ordinary
        $InputValue=@{checked=$Pair.checked;go=$O.intent.authorization;sourceReceipt=$Intent.check.sourceReceipt
            review=$null;evidence=$null;seed=$O.intent.normal;seedDigest=$null;begin=$O.begin
            publication=$Publication;verifyOnly=[bool]$VerifyOnly;source=$Intent.check.binding.sourceSha
            registryProfile=$RegistryProfile;ordinary=@{intent=$O.intent;check=$O.check;sourceReceipt=$O.sourceReceipt;stop=$O.stop}
            targetRoot=$(if($Role -ceq 'State'){$Pair.checked.roots.state}else{$Pair.finalRoots.$Role})}
    }else{
        if($Role -ceq 'State'){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_FINAL_MATERIAL_CHANGED'}
        Assert-ReleaseVolumeHolders @('fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor') @() 'RELEASE_SUCCESSOR_SEED_HOLDER_CHANGED'
        $InputValue=@{checked=$Pair.checked;go=$Intent.go;sourceReceipt=$Intent.check.sourceReceipt
            review=$Pair.reviewSha256;evidence=$Pair.evidenceSha256;seed=$Seed.record;seedDigest=$Seed.digest
            begin=$Intent.attempt.bootstrapBegin;publication=$Publication;verifyOnly=[bool]$VerifyOnly
            source=$Intent.check.binding.sourceSha;registryProfile=$RegistryProfile
            targetRoot=$Pair.finalRoots.$Role;ordinary=$null}
    }
    $Access=if($VerifyOnly){',readonly'}else{''}
    $Common=@('run','--rm','-i','--pull=never','--network','none','--read-only',
        '--name',('fortis-registry-seal-'+$Role.ToLowerInvariant()+'-'+$Id),
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','32',
        '--mount','type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,readonly,volume-nocopy',
        '--mount','type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,readonly,volume-nocopy')
    if($Role -ceq 'State'){
        $OldState='fortis-registry-state-e13b-'+$Source.runtime.registryReleaseNonce.Replace('-','')
        $State='fortis-registry-state-e13b-'+$Id;$Config='fortis-registry-config-e13b-'+$Id+'-prepared'
        foreach($Volume in @($OldState,$State,$Config)){Assert-Volume $Volume;Assert-OnlyWriter $Volume}
        $Arguments=$Common+@('--user','20002:20002','--memory','1024m',
            '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=640m,uid=20002,gid=20002,mode=0700',
            '--mount',('type=volume,source='+$OldState+',target=/run/fortis-registry-state,readonly,volume-nocopy'),
            '--mount',('type=volume,source='+$Config+',target=/run/fortis-registry-runtime,readonly,volume-nocopy'),
            '--mount',('type=volume,source='+$State+',target=/target,volume-nocopy'+$Access),$Pair.registryImage)
        $InputValue.profile=$Pair.registryProfileSha256
        $Code=@'
import json,sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.registry.owner_functional_v1_bootstrap import frozen_pair_backup
p=json.load(sys.stdin)
proof={**p['ordinary'],'begin':p['begin'],'publication':p['publication']}
r=frozen_pair_backup(p['profile'],pair=p['begin']['pair'],holds=p['begin']['holdSnapshot'],
    phase_record=p['publication']['record'],verify_only=p['verifyOnly'],expected_target=p['targetRoot'],ordinary=proof)
print(json.dumps(r,sort_keys=True,separators=(',',':')))
'@
    } elseif($Role -ceq 'Registry'){
        $State='fortis-registry-state-e13b-'+$Id;$Config='fortis-registry-config-e13b-'+$Id
        foreach($Volume in @($State,$Config,($Config+'-prepared'))){Assert-Volume $Volume}
        $Arguments=$Common+@('--user','20002:20002','--memory','1024m',
            '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=640m,uid=20002,gid=20002,mode=0700',
            '--mount',('type=volume,source='+$State+',target=/run/fortis-registry-state,readonly,volume-nocopy'),
            '--mount',('type=volume,source='+$Config+'-prepared,target=/run/fortis-registry-runtime,readonly,volume-nocopy'),
            '--mount',('type=volume,source='+$Config+',target=/target,volume-nocopy'+$Access),$Pair.registryImage)
        $InputValue.profile=$Pair.registryProfileSha256
        $Code=@'
import json,sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.registry.owner_functional_v1_bootstrap import seal_bootstrap_registry_material
from fortis_approvals.integrations.registry_contracts.maintenance_contract import bootstrap_pair_authorization
p=json.load(sys.stdin)
auth=(p['go'] if p['ordinary'] is not None else bootstrap_pair_authorization(p['checked'],p['go'],p['sourceReceipt'],
    review_sha256=p['review'],evidence_sha256=p['evidence'],seed_digest=p['seedDigest']))
result=seal_bootstrap_registry_material(p['profile'],review_sha256=p['review'],
    evidence_sha256=p['evidence'],source_sha=p['source'],checked=p['checked'],authorization=auth,
    seed=p['seed'],begin=p['begin'],publication=p['publication'],verify_only=p['verifyOnly'],expected_target=p['targetRoot'],ordinary=p['ordinary'])
print(json.dumps(result,sort_keys=True,separators=(',',':')))
'@
    } else {
        $Reader='fortis-r7-registry-reader-'+$Id
        foreach($Volume in @($Reader,($Reader+'-prepared'),$Source.runtime.stateVolume)){Assert-Volume $Volume}
        $Arguments=$Common+@('--user','10001:10001','--memory','512m',
            '--mount',('type=volume,source='+$Reader+'-prepared,target=/run/r7-registry-reader,readonly,volume-nocopy'),
            '--mount',('type=volume,source='+$Reader+',target=/target,volume-nocopy'+$Access),
            '--mount',('type=volume,source='+$Source.runtime.stateVolume+',target=/source,readonly,volume-nocopy'),
            $Intent.attempt.runtime.image)
        $Code=@'
import json,sys
from pathlib import Path
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.r7_unified_server import _installed_policy_source_digest
from fortis_approvals.r7_registry_reader_mount import seal_bootstrap_gateway_material
from fortis_approvals.integrations.registry_contracts.maintenance_contract import bootstrap_pair_authorization
p=json.load(sys.stdin)
if _installed_policy_source_digest()!=p['checked']['gateway']['sourceDigest']:
    raise RuntimeError('BOOTSTRAP_GATEWAY_SOURCE_CHANGED')
auth=(p['go'] if p['ordinary'] is not None else bootstrap_pair_authorization(p['checked'],p['go'],p['sourceReceipt'],
    review_sha256=p['review'],evidence_sha256=p['evidence'],seed_digest=p['seedDigest']))
result=seal_bootstrap_gateway_material(checked=p['checked'],authorization=auth,seed=p['seed'],
    begin=p['begin'],publication=p['publication'],registry_profile=p['registryProfile'],
    verify_only=p['verifyOnly'],expected_target=p['targetRoot'],incumbent_core=Path('/source/private/approvals.sqlite'),ordinary=p['ordinary'])
print(json.dumps(result,sort_keys=True,separators=(',',':')))
'@
    }
    $Actual=(Python-Code $Arguments $Code (ConvertTo-Json -Compress -Depth 25 $InputValue))|ConvertFrom-Json
    Assert-CorrectiveTargetHolders $Nonce @() -PreparedProfiles
    return $Actual
}
function Seal-BootstrapFinalProfiles {
    param($Source,[string]$CheckPath,[string]$CheckHash)
    # Exact current APPLY_STOP only. No listener or STAGED_TARGET_FROZEN
    # publication is performed here. Original Prepared materials and state
    # are retained, so every final seal has independent RO recovery.
    $Intent=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
    Assert-BootstrapNoReceiver $Intent
    $Publication=(Read-SuccessorPublication $Source).anchor
    if($Intent.ContainsKey('ordinary')){
        Assert-PairedFrozenSource $Intent $Source
        $O=$Intent.ordinary
        if($Publication.state -cne 'Committed' -or -not (Same-Json $Publication.record $O.stop.next) -or
           $Publication.registryDigest -cne $O.begin.registryDigest){throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'}
        $Seed=$null;$Written=$null
        if(-not $Intent.attempt.PSObject.Properties['bootstrapBegin']){
            try{$Written=Invoke-BootstrapFinalMaterialHelper $Intent $Source $Publication $Seed State $null}
            catch{Write-Warning 'RELEASE_SUCCESSOR_ORDINARY_STATE_READBACK'}
        }
        $State=Invoke-BootstrapFinalMaterialHelper $Intent $Source $Publication $Seed State $null -VerifyOnly
        if(($Written -and -not (Same-Json $Written $State)) -or $State.result -cne 'PAIRED_STAGED_STATE_COPY_ONLY' -or
           -not (Same-Json $State.checkpoint $O.begin.checkpoint) -or -not (Same-Json $State.holdSnapshot $O.begin.holdSnapshot) -or
           $State.final.record.phase -cne 'STAGED_TARGET_FROZEN' -or $State.final.record.previousDigest -cne $Publication.digest -or
           $State.final.handoff.registryDigest -cne $O.begin.registryDigest){
            throw 'RELEASE_SUCCESSOR_ORDINARY_STATE_CHANGED'
        }
        $Begin=$O.begin|ConvertTo-Json -Depth 25 -Compress|ConvertFrom-Json
        $Begin|Add-Member -NotePropertyName phasePlan -NotePropertyValue @{
            records=@($O.begin.draining,$Intent.check.maintenanceTransitions.frozen,$Intent.check.maintenanceTransitions.checked,$O.stop.next,$State.final.record)
            handoff=$State.final.handoff}
        $Previous=$Intent.attempt.PSObject.Properties['bootstrapBegin']
        if($Previous){
            if(-not (Same-Json $Previous.Value $Begin) -or -not (Same-Json $Intent.attempt.ordinaryStateCopy $State)){
                throw 'RELEASE_SUCCESSOR_ORDINARY_STATE_CHANGED'
            }
        }else{
            $Intent.attempt|Add-Member -NotePropertyName bootstrapBegin -NotePropertyValue $Begin
            $Intent.attempt|Add-Member -NotePropertyName ordinaryStateCopy -NotePropertyValue $State
            $script:R=$Intent.attempt;Save -FlushToDisk
        }
        $Intent=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
    }else{
        $Begin=$Intent.attempt.bootstrapBegin
        if(-not $Begin -or $Publication.state -cne 'Committed' -or
           -not (Same-Json $Publication.record $Begin.phasePlan.records[3]) -or
           $Publication.digest -cne $Begin.phasePlan.records[4].previousDigest -or
           $Publication.registryDigest -cne $Begin.registryDigest){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_PHASE_CHANGED'
        }
        $Seed=Read-BootstrapSeedSource $Source
        Assert-BootstrapFrozenCheck $Source $CheckPath $CheckHash
    }
    $Results=@{};$RegistryProfile=$null
    foreach($Role in @('Registry','Gateway')){
        $Written=$null
        if(-not $Intent.attempt.PSObject.Properties['bootstrapMaterials']){
            try {
                $Written=Invoke-BootstrapFinalMaterialHelper $Intent $Source $Publication $Seed $Role $RegistryProfile
            } catch {Write-Warning ('RELEASE_SUCCESSOR_BOOTSTRAP_MATERIAL_READBACK '+$Role)}
        }
        # Even a successful writer is not independent proof. Never use its
        # own output as admission or blindly repeat after uncertain ACK.
        $Actual=Invoke-BootstrapFinalMaterialHelper $Intent $Source $Publication $Seed $Role $RegistryProfile -VerifyOnly
        if(($Written -and -not (Same-Json $Written $Actual)) -or
           $Actual.profileDigest -cnotmatch '^[0-9a-f]{64}$' -or
           $Actual.fileHashes.'profile.json' -cne $Actual.profileDigest -or
           $Actual.generation -cne $Intent.go.targetGeneration -or
           -not (Same-Json $Actual.handoff $Begin.phasePlan.handoff)){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_FINAL_MATERIAL_CHANGED'
        }
        if($Role -ceq 'Registry'){$RegistryProfile=$Actual.profile}
        elseif($Actual.registryProfileDigest -cne $Results.Registry.profileDigest){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_FINAL_MATERIAL_CHANGED'
        }
        $Results[$Role]=$Actual
    }
    Assert-PairedFrozenSource $Intent $Source
    Assert-BootstrapNoReceiver $Intent
    if(-not (Same-Json (Read-SuccessorPublication $Source).anchor $Publication)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_PHASE_CHANGED'
    }
    $Fresh=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
    if(-not (Same-Json $Fresh.go $Intent.go) -or -not (Same-Json $Fresh.attempt.bootstrapBegin $Begin)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_OWNER_GO_CHANGED'
    }
    $Material=[ordered]@{gatewayProfileDigest=$Results.Gateway.profileDigest
        registryProfileDigest=$Results.Registry.profileDigest;generation=$Intent.go.targetGeneration
        handoff=$Begin.phasePlan.handoff;gatewayHashes=$Results.Gateway.fileHashes;registryHashes=$Results.Registry.fileHashes}
    $Previous=$Fresh.attempt.PSObject.Properties['bootstrapMaterials']
    if($Previous){
        if(-not (Same-Json $Previous.Value $Material)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_FINAL_MATERIAL_CHANGED'}
    } else {
        $Fresh.attempt|Add-Member -NotePropertyName bootstrapMaterials -NotePropertyValue $Material
        $script:R=$Fresh.attempt;Save -FlushToDisk
    }
    $script:R=Read-Private $script:RecordPath
    if(-not (Same-Json $script:R.bootstrapMaterials $Material)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_FINAL_MATERIAL_CHANGED'}
    return $Material
}

function Read-BootstrapReceiver {
    param($Intent,[string]$GatewayId='',[switch]$Accepted,[switch]$Returning)
    $Field=$Intent.attempt.PSObject.Properties['bootstrapReceiver']
    if(-not $Field){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_INTENT_MISSING'}
    $Saved=$Field.Value;$P=$Intent.attempt.runtime;$M=$Intent.attempt.bootstrapMaterials
    $Name='fortis-registry-successor-'+$P.registryReleaseNonce.Replace('-','')
    if(-not $M -or $Saved.name -cne $Name -or $Saved.image -cne $Intent.pair.registryImage -or
       $Saved.profileDigest -cne $M.registryProfileDigest -or $Saved.generation -cne $M.generation -or
       $Saved.attemptId -cne $Intent.go.attemptId -or
       ($Saved.id -and $Saved.id -cnotmatch '^[0-9a-f]{64}$')){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_CHANGED'
    }
    $Names=@((Docker-Text @('ps','-a','--format','{{.Names}}')) -split '\r?\n')
    if($Names -cnotcontains $Name){
        if($Saved.id){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_MISSING'}
        return
    }
    $C=Container $Name
    if(($Saved.id -and $Saved.id -cne $C.Id) -or
       $C.Config.Labels.'io.fortis.bootstrap-attempt' -cne $Intent.go.attemptId -or
       $C.State.Status -cnotin @('created','running','exited')){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_CHANGED'
    }
    $AlreadyAccepted=($Accepted -and $C.HostConfig.RestartPolicy.Name -ceq 'unless-stopped')
    Assert-CorrectiveRegistryContainer $C $P.registryReleaseNonce $Saved.image $Saved.profileDigest 'writer' $Intent.check.binding.sourceSha -Status $C.State.Status -LatestPin -Accepted:$AlreadyAccepted
    $Allowed=@($C.Id)
    if($GatewayId){
        if($GatewayId -cnotmatch '^[0-9a-f]{64}$' -or $GatewayId -cne $P.pilotId){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_CHANGED'
        }
        $Allowed+=@($GatewayId)
    }
    Assert-CorrectiveTargetHolders $P.registryReleaseNonce $Allowed -PreparedProfiles
    if($Intent.ContainsKey('ordinary')){
        if($Returning){
            $Original=Read-Private $Intent.attempt.source.path
            $Allowed+=@($Intent.attempt.source.runtime.pilotId,$Original.bootstrapReceiver.id)
        }
        Assert-OperationalMaintenanceHolders $Intent.attempt.source $Allowed 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_CHANGED'
    }else{Assert-ReleaseVolumeHolders @('fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor') $Allowed 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_CHANGED'}
    return $C
}
function Start-BootstrapReceiver {
    param($Source,[string]$CheckPath,[string]$CheckHash,$Sealed=$null)
    $Intent=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
    $M=$Intent.attempt.bootstrapMaterials;$B=$Intent.attempt.bootstrapBegin;$P=$Intent.attempt.runtime
    if(-not $M -or -not $B -or $M.generation -cne $Intent.go.targetGeneration -or
       -not (Same-Json $M.handoff $B.phasePlan.handoff)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_FINAL_MATERIAL_CHANGED'}
    Assert-Release-Production
    if(-not $Intent.ContainsKey('ordinary')){$null=Read-BootstrapSeedSource $Source}
    $Publication=(Read-SuccessorPublication $Source).anchor
    $Stop=$B.phasePlan.records[3];$Next=$B.phasePlan.records[4]
    if($Publication.registryDigest -cne $B.registryDigest -or
       (-not (Same-Json $Publication.record $Stop) -and -not (Same-Json $Publication.record $Next)) -or
       ($Publication.state -ceq 'Pending' -and -not (Same-Json $Publication.next $Next))){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_PHASE_CHANGED'
    }
    if(-not $Intent.attempt.PSObject.Properties['bootstrapReceiver']){
        Assert-BootstrapNoReceiver $Intent
        if($Publication.state -cne 'Committed' -or -not (Same-Json $Publication.record $Stop)){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_PHASE_CHANGED'
        }
        # In a fresh Prepared driver the independent RO seal was just
        # verified under this same controller lock, with no intervening
        # writer or holder. Re-entry must re-read both roots instead.
        if($Sealed){
            if(-not (Same-Json $Sealed $M)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_FINAL_MATERIAL_CHANGED'}
        } else {$null=Seal-BootstrapFinalProfiles $Source $CheckPath $CheckHash}
        $Intent=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
        $Saved=[pscustomobject][ordered]@{name=('fortis-registry-successor-'+$P.registryReleaseNonce.Replace('-',''))
            image=$Intent.pair.registryImage;profileDigest=$M.registryProfileDigest;generation=$M.generation
            attemptId=$Intent.go.attemptId;id=''}
        $Intent.attempt|Add-Member -NotePropertyName bootstrapReceiver -NotePropertyValue $Saved
        $script:R=$Intent.attempt;Save -FlushToDisk
        $Intent=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
    }
    $C=Read-BootstrapReceiver $Intent
    if($Intent.ContainsKey('ordinary')){
        $Ids=if($C){@($C.Id)}else{@()}
        Assert-PairedFrozenSource $Intent $Source -CandidateIds $Ids
    }
    $Saved=$Intent.attempt.bootstrapReceiver
    if(-not $C){
        if($Publication.state -cne 'Committed' -or -not (Same-Json $Publication.record $Stop)){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_MISSING'
        }
        Assert-BootstrapNoReceiver $Intent
        $Id=$P.registryReleaseNonce.Replace('-','')
        $Mounts=@(
            @(('fortis-registry-state-e13b-'+$Id),'/run/fortis-registry-state',''),
            @(('fortis-registry-config-e13b-'+$Id),'/run/fortis-registry-runtime',',readonly'),
            @(('fortis-registry-read-'+$Id),'/run/fortis-registry-read',''),
            @(('fortis-registry-source-evidence-'+$Id),'/run/fortis-registry-source-evidence',',readonly'),
            @(('fortis-registry-source-'+$Id),'/run/fortis-registry-source',',readonly'),
            @('fortis-r7-maintenance-interlock-v2','/run/r7-maintenance',',readonly'),
            @('fortis-r7-maintenance-anchor','/run/r7-maintenance-anchor',',readonly'))
        $Arguments=@('create','--pull=never','--name',$Saved.name,'--label',('io.fortis.bootstrap-attempt='+$Saved.attemptId),
            '--restart=no','--init','--network=none','--read-only','--user','20002:20002',
            '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','512m',
            '--tmpfs','/tmp:rw,nosuid,nodev,size=256m')
        foreach($Mount in $Mounts){
            Assert-Volume $Mount[0]
            $Arguments+=@('--mount',('type=volume,source='+$Mount[0]+',target='+$Mount[1]+',volume-nocopy'+$Mount[2]))
        }
        $Arguments+=@($Saved.image,'python','-m','fortis_approvals.registry.local_candidate_read_service',
            '--owner-config','/run/fortis-registry-runtime/profile.json','--expected-profile-sha256',$Saved.profileDigest)
        Step 'BOOTSTRAP_CREATE_REGISTRY_RECEIVER'
        $Ack=''
        try {$Ack=Docker-Text $Arguments}catch{Write-Warning 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_CREATE_READBACK'}
        $C=Read-BootstrapReceiver $Intent
        if(-not $C -or $C.State.Status -cne 'created' -or ($Ack -and $Ack -cne $C.Id)){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_CREATE_UNCONFIRMED'
        }
    }
    if(-not $Saved.id){
        if($C.State.Status -cne 'created' -or $Publication.state -cne 'Committed' -or
           -not (Same-Json $Publication.record $Stop)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_CHANGED'}
        $Saved.id=$C.Id
        $script:R=$Intent.attempt;Save -FlushToDisk
        $Intent=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
        $C=Read-BootstrapReceiver $Intent
    }
    # The receiver cannot start against APPLY_STOP or a Pending projection.
    if($C.State.Status -cne 'created' -and -not (Same-Json $Publication.record $Next)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_CHANGED'
    }
    $Digest=Publish-SuccessorInterlock $Source $Next $B.registryDigest
    $Published=(Read-SuccessorPublication $Source).anchor
    if($Digest -cne $M.handoff.interlockDigest -or $Published.state -cne 'Committed' -or
       $Published.digest -cne $Digest -or $Published.registryDigest -cne $B.registryDigest -or
       -not (Same-Json $Published.record $Next)){throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'}
    Step 'BOOTSTRAP_START_REGISTRY_RECEIVER'
    $C=Set-BootstrapContainerState $C Start
    Wait-CorrectiveRegistryListener $C.Id
    if($Source.runtime.runId -cnotmatch '^[0-9a-f]{32}$' -or
       $Source.runtime.stateVolume -cne ('fortis-github-pilot-state-'+$Source.runtime.runId) -or
       -not $Intent.pair.checked.gateway.companion){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'
    }
    Assert-OnlyWriter $Source.runtime.stateVolume
    $Delivery=Image-RegistrySuccessor-Preflight -ImageId $P.image -ReleaseNonce $P.registryReleaseNonce -InterlockDigest $Digest -LatestPin -IncumbentVolume $Source.runtime.stateVolume -ExpectedExisting $Intent.pair.checked.gateway.companion
    $Checkpoint=$Delivery.registryCheckpoint;$Checked=$Intent.pair.checked.registry.checkpoint
    if($Delivery.profileDigest -cne $M.gatewayProfileDigest -or
       $Delivery.generation -cne $M.generation -or $Delivery.maintenancePhase -cne 'STAGED_TARGET_FROZEN' -or
       $Delivery.sourceDelivery.policyAuthorityDigest -cne $Intent.pair.checked.registry.binding.authorityDigest -or
       $Checkpoint.registryDigest -cne $B.registryDigest -or $Checkpoint.profileDigest -cne $Checked.profileDigest -or
       $Checkpoint.sourceRevision -ne $Checked.sourceRevision -or $Checkpoint.sourceCursor -cne $Checked.sourceCursor -or
       $Checkpoint.snapshotRevision -ne $B.holdSnapshot.snapshotRevision -or $Checkpoint.eventDigest -cne $B.holdSnapshot.eventDigest -or
       -not (Same-Json $Delivery.existingCompanion $Intent.pair.checked.gateway.companion) -or
       -not (Same-Json (Read-SuccessorPublication $Source).anchor $Published)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'
    }
    $null=Read-BootstrapReceiver $Intent
    Assert-PairedFrozenSource $Intent $Source -CandidateIds @($C.Id)
    $Fresh=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
    $Previous=$Fresh.attempt.PSObject.Properties['bootstrapDelivery']
    if($Previous){
        if(-not (Same-Json $Previous.Value $Delivery)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'}
    } else {
        $Fresh.attempt|Add-Member -NotePropertyName bootstrapDelivery -NotePropertyValue $Delivery
        $script:R=$Fresh.attempt;Save -FlushToDisk
    }
    $script:R=Read-Private $script:RecordPath
    if(-not (Same-Json $script:R.bootstrapDelivery $Delivery)){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'}
    return $Delivery
}

function Assert-BootstrapNoReceiver {
    param($Intent,[switch]$Returning)
    $P=$Intent.attempt.runtime
    if(($Intent.attempt.phase -cne 'Prepared' -and -not ($Returning -and $Intent.attempt.phase -ceq 'Returned')) -or $Intent.attempt.activated -or
       $Intent.attempt.probesPassed -or $P.pilotId){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_REQUIRES_REVIEW'
    }
    # This Return is only for the pre-receiver boundary. Never guess a
    # candidate identity after a lost create/start ACK, or discard a marker.
    Assert-CorrectiveTargetHolders $P.registryReleaseNonce @() -PreparedProfiles
    if($Intent.ContainsKey('ordinary')){
        $Source=$Intent.attempt.source;$Original=Read-Private $Source.path
        Assert-ReleaseVolumeHolders @($P.stateVolume) @() 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_REQUIRES_REVIEW'
        Assert-OperationalMaintenanceHolders $Source @($Source.runtime.pilotId,$Original.bootstrapReceiver.id) 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_REQUIRES_REVIEW'
    }else{
        Assert-ReleaseVolumeHolders @($P.stateVolume,'fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor') @() 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_REQUIRES_REVIEW'
    }
    $Names=@((Docker-Text @('ps','-a','--format','{{.Names}}')) -split '\r?\n')
    if($Names -ccontains $P.pilotName -or $Names -ccontains ('fortis-registry-successor-'+$P.registryReleaseNonce.Replace('-',''))){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_REQUIRES_REVIEW'
    }
    Assert-CorrectiveGateAbsent $P
}
function Set-BootstrapContainerState {
    param($C,[ValidateSet('DisableRestart','Stop','Start','RestoreRestart')][string]$Effect)
    # Caller has just proved exact retained identity and owns the controller
    # lock. Read actual state after command failure: a lost ACK is not a
    # new intent, and a satisfied postcondition needs no second Docker call.
    $Id=$C.Id;$ImageId=$C.Image
    $State=$C.State.Status;$Restart=$C.HostConfig.RestartPolicy.Name
    if($Id -cnotmatch '^[0-9a-f]{64}$' -or $State -cnotin @('created','running','exited') -or
       ($State -ceq 'created' -and ($Effect -cne 'Start' -or $Restart -cne 'no')) -or
       $Restart -cnotin @('no','unless-stopped')){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_SOURCE_CHANGED'}
    switch -CaseSensitive ($Effect){
        'DisableRestart' {$WantedState=$State;$WantedRestart='no';$Arguments=@('update','--restart=no',$Id)}
        'Stop' {
            if($Restart -cne 'no'){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RESTART_NOT_DISABLED'}
            $WantedState='exited';$WantedRestart='no';$Arguments=@('stop','--timeout','20',$Id)}
        'Start' {
            if($Restart -cne 'no' -and $State -cne 'running'){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RESTART_NOT_DISABLED'}
            $WantedState='running';$WantedRestart=$Restart;$Arguments=@('start',$Id)}
        'RestoreRestart' {
            if($State -cne 'running'){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_SOURCE_NOT_RUNNING'}
            $WantedState='running';$WantedRestart='unless-stopped';$Arguments=@('update','--restart=unless-stopped',$Id)}
    }
    if($State -cne $WantedState -or $Restart -cne $WantedRestart){
        try {$null=Docker-Text $Arguments}
        catch {
            # No retry. Independent readback below distinguishes an applied
            # effect from an unresolved outcome; retain the attempt either way.
            Write-Warning ('RELEASE_SUCCESSOR_BOOTSTRAP_EFFECT_READBACK '+$Effect)
        }
    }
    $Actual=Container $Id
    if($Actual.Id -cne $Id -or $Actual.Image -cne $ImageId -or
       $Actual.State.Status -cne $WantedState -or $Actual.HostConfig.RestartPolicy.Name -cne $WantedRestart -or
       $Actual.HostConfig.RestartPolicy.MaximumRetryCount -ne 0){
        throw ('RELEASE_SUCCESSOR_BOOTSTRAP_EFFECT_UNCONFIRMED '+$Effect)
    }
    return $Actual
}
function Stop-BootstrapSourcePair {
    param($Source,[string]$CheckPath,[string]$CheckHash)
    $Intent=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash
    Assert-Release-Production
    Assert-BootstrapNoReceiver $Intent
    if($Intent.ContainsKey('ordinary')){
        $O=$Intent.ordinary;$Check=$Intent.check
        $Rows=Read-OrdinarySuccessorSource $Source -PublicationRecovery
        $Publication=(Read-SuccessorPublication $Source).anchor
        if($Publication.record.phase -ceq 'CHECK_SEALED' -and $Publication.state -ceq 'Committed'){
            $Verify=New-SuccessorApplyVerifyPayload $Intent.context.payload $O.check $Check.maintenanceTransitions $Publication.digest
            $Verify.prepareStop=@{sourceRecordDigest=$O.stop.sourceRecordDigest;checkedRecordDigest=$O.stop.checkedRecordDigest;targetImageId=$O.stop.targetImageId}
            $Fresh=Read-SuccessorFreezeSeal $Verify $Source.runtime.stateVolume 'fortis-r7-maintenance-interlock'
            if(-not (Same-Json $Fresh.stopIntent $O.stop) -or -not (Same-Json $Fresh.sourceReceipt $Check.sourceReceipt)){
                throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
            }
        }elseif(-not (Same-Json $Publication.record $O.stop.next) -and
            -not ($Publication.state -ceq 'Pending' -and (Same-Json $Publication.next $O.stop.next))){
            throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
        }
        $Digest=Publish-SuccessorInterlock $Source $O.stop.next $O.begin.registryDigest
        $Published=(Read-SuccessorPublication $Source).anchor
        if($Published.state -cne 'Committed' -or $Published.digest -cne $Digest -or
           -not (Same-Json $Published.record $O.stop.next)){throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'}
        $null=Set-BootstrapContainerState (Set-BootstrapContainerState $Rows.gateway DisableRestart) Stop
        $null=Set-BootstrapContainerState (Set-BootstrapContainerState $Rows.registry DisableRestart) Stop
        Assert-PairedFrozenSource $Intent $Source
        $Verify=New-SuccessorApplyVerifyPayload $Intent.context.payload $O.check $Check.maintenanceTransitions $Digest
        $Verify.stoppedIntent=$O.stop
        $Fresh=Read-SuccessorFreezeSeal $Verify $Source.runtime.stateVolume 'fortis-r7-maintenance-interlock'
        if(-not (Same-Json $Fresh.sourceReceipt $Check.sourceReceipt)){throw 'RELEASE_SUCCESSOR_ORDINARY_STATE_CHANGED'}
        Assert-Release-Production
        return
    }
    $null=Read-BootstrapSeedSource $Source -Transition
    $Original=(Read-Private $Source.path).correctivePair
    $Gateway=Container $Source.runtime.pilotId
    $Registry=Container $Original.targetRegistryId
    # Both original policies are recorded in the accepted primary/Registry
    # record. Disable restart before stopping; never mutate those records.
    # Gateway first (no new ingress), then Registry, and both are retained.
    Step 'BOOTSTRAP_DISABLE_GATEWAY_RESTART'
    $Gateway=Set-BootstrapContainerState $Gateway DisableRestart
    Step 'BOOTSTRAP_STOP_GATEWAY'
    $null=Set-BootstrapContainerState $Gateway Stop
    Step 'BOOTSTRAP_DISABLE_REGISTRY_RESTART'
    $Registry=Set-BootstrapContainerState $Registry DisableRestart
    Step 'BOOTSTRAP_STOP_REGISTRY'
    $null=Set-BootstrapContainerState $Registry Stop
    $null=Read-BootstrapSeedSource $Source
    Assert-BootstrapFrozenCheck $Source $CheckPath $CheckHash
    Assert-Release-Production
}
function Read-BootstrapGatewayCandidate {
    param($Intent)
    $P=$Intent.attempt.runtime
    $Names=@((Docker-Text @('ps','-a','--format','{{.Names}}')) -split '\r?\n')
    if($Names -cnotcontains $P.pilotName){
        if($P.pilotId){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_GATEWAY_MISSING'}
        return
    }
    if(-not $Intent.attempt.bootstrapDelivery -or -not (Same-Json $P.registryDelivery $Intent.attempt.bootstrapDelivery)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'
    }
    $C=Container $P.pilotName
    if($C.Id -cnotmatch '^[0-9a-f]{64}$' -or ($P.pilotId -and $P.pilotId -cne $C.Id) -or
       $C.State.Status -cnotin @('created','running','exited')){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_GATEWAY_CHANGED'
    }
    $Networks=Read-GatewayNetworks $P
    $Pending=$false
    if($Networks -and $C.State.Status -ceq 'created'){
        $Attached=@($C.NetworkSettings.Networks.PSObject.Properties.Name)
        $Expected=@(Get-RecordedGatewayNetworkNames $Networks)
        $Pending=($Attached -ccontains 'fortis-gateway-egress' -and
                  @($Attached|Where-Object{$Expected -cnotcontains $_}).Count -eq 0 -and
                  $Attached.Count -lt $Expected.Count)
    }
    if(-not $P.pilotId){
        if($C.State.Status -cne 'created' -or $C.State.StartedAt -cne '0001-01-01T00:00:00Z' -or
           $Intent.attempt.phase -cne 'Prepared'){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_GATEWAY_CHANGED'
        }
        # The exact runId, image, mount set and public config are verified
        # before adopting a lost create ACK. No live peer bypass on start.
        $Intent.attempt.phase='Created'
        $script:R=$Intent.attempt
        try {
            Admit $C $P -AllowUnhealthy -RegistryReturnSource -AllowPendingIngress:$Pending
        } catch {$Intent.attempt.phase='Prepared';throw}
        $P.pilotId=$C.Id;Save -FlushToDisk
    } else {
        Admit $C $P -AllowUnhealthy -RegistryReturnSource -AllowPendingIngress:$Pending
    }
    return $C
}


function Restore-OrdinarySourcePair {
    param($Intent,$Rows,[string[]]$CandidateIds)
    $Source=$Intent.attempt.source;$P=$Source.runtime;$O=$Intent.ordinary
    $Published=(Read-SuccessorPublication $Source).anchor
    $Saved=$Intent.attempt.PSObject.Properties['ordinaryReturn']
    $Returning=$Intent.attempt.phase -ceq 'Returned'
    if($Returning -and (-not $Saved -or $Rows.gateway.State.Status -cne 'running' -or
       $Rows.registry.State.Status -cne 'running' -or
       $Rows.gateway.HostConfig.RestartPolicy.Name -cne 'unless-stopped' -or
       $Rows.registry.HostConfig.RestartPolicy.Name -cne 'unless-stopped')){
        throw 'RELEASE_SUCCESSOR_ORDINARY_RETURN_CHANGED'
    }
    if(-not $Saved){
        # Reconcile only the already persisted stop/staged transition. No
        # new target start. Original source must remain the current pointer.
        if($Published.state -ceq 'Pending'){
            $Next=$Published.next
            $Stage=$Intent.attempt.PSObject.Properties['bootstrapBegin']
            if(-not (Same-Json $Next $O.stop.next) -and
               (-not $Stage -or -not (Same-Json $Next $Stage.Value.phasePlan.records[4]))){
                throw 'RELEASE_SUCCESSOR_ORDINARY_RETURN_CHANGED'
            }
        }else{$Next=$Published.record}
        if($Next.phase -cnotin @('CHECK_SEALED','APPLY_STOP','STAGED_TARGET_FROZEN')){
            throw 'RELEASE_SUCCESSOR_ORDINARY_RETURN_CHANGED'
        }
        $null=Publish-SuccessorInterlock $Source $Next $O.begin.registryDigest
        $Published=(Read-SuccessorPublication $Source).anchor
        $null=Set-BootstrapContainerState (Set-BootstrapContainerState $Rows.gateway DisableRestart) Stop
        $null=Set-BootstrapContainerState (Set-BootstrapContainerState $Rows.registry DisableRestart) Stop
        $null=Read-OrdinarySuccessorSource $Source -Frozen -CandidateIds $CandidateIds
        Assert-CorrectiveGateAbsent $Intent.attempt.runtime
        $B=$Intent.check.binding
        $Receipt=Receipt $P.stateVolume -Exact:$B.requireExactUncertain -ExactClaimed:$B.requireExactClaimed -ExactApproved:$B.requireExactApproved
        if(-not (Same-Json $Receipt $O.sourceReceipt)){throw 'RELEASE_SUCCESSOR_ORDINARY_RETURN_STATE_CHANGED'}
        $Id=$P.registryReleaseNonce.Replace('-','')
        $State='fortis-registry-state-e13b-'+$Id;$Config='fortis-registry-config-e13b-'+$Id
        foreach($V in @($State,$Config,'fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor')){Assert-Volume $V}
        $Arguments=@('run','--rm','-i','--pull=never','--network','none','--read-only',
            '--name',('fortis-registry-return-'+$Id),'--user','20002:20002',
            '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','32','--memory','1024m',
            '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=640m,uid=20002,gid=20002,mode=0700',
            '--mount',('type=volume,source='+$State+',target=/run/fortis-registry-state,readonly,volume-nocopy'),
            '--mount',('type=volume,source='+$Config+',target=/run/fortis-registry-runtime,readonly,volume-nocopy'),
            '--mount','type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,readonly,volume-nocopy',
            '--mount','type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,readonly,volume-nocopy',
            $Intent.pair.registryImage)
        $Code=@'
import json,sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.registry.owner_functional_v1_bootstrap import read_ordinary_return
p=json.load(sys.stdin)
r=read_ordinary_return(p['profile'],intent=p['intent'],begin=p['begin'],check=p['check'],
    source_receipt=p['sourceReceipt'],stop=p['stop'],publication=p['publication'])
print(json.dumps(r,sort_keys=True,separators=(',',':')))
'@
        $Payload=@{profile=$Rows.receiver.profileDigest;intent=$O.intent;begin=$O.begin
            check=$O.check;sourceReceipt=$Receipt;stop=$O.stop;publication=$Published}
        $Proof=(Python-Code $Arguments $Code (ConvertTo-Json -Compress -Depth 25 $Payload))|ConvertFrom-Json
        if($Proof.record.phase -cne 'RECOVERY_HOLD' -or $Proof.record.generation -cne $P.maintenanceGeneration -or
           $Proof.record.previousDigest -cne $Published.digest -or $Proof.registryDigest -cne $O.begin.registryDigest -or
           -not (Same-Json $Proof.checkpoint $O.begin.checkpoint) -or
           -not (Same-Json (Read-SuccessorPublication $Source).anchor $Published)){
            throw 'RELEASE_SUCCESSOR_ORDINARY_RETURN_CHANGED'
        }
        $null=Read-OrdinarySuccessorSource $Source -Frozen -CandidateIds $CandidateIds
        Assert-CorrectiveGateAbsent $Intent.attempt.runtime
        $Intent.attempt|Add-Member -NotePropertyName ordinaryReturn -NotePropertyValue $Proof
        $script:R=$Intent.attempt;Save -FlushToDisk
        $Intent=Read-BootstrapFrozenIntent $Source $Intent.attempt.bootstrapCheckRecord $Intent.attempt.bootstrapCheckHash -Returning
        if(-not (Same-Json $Intent.attempt.ordinaryReturn $Proof)){throw 'RELEASE_SUCCESSOR_ORDINARY_RETURN_CHANGED'}
    }else{$Proof=$Saved.Value}
    if($Proof.record.phase -cne 'RECOVERY_HOLD' -or $Proof.record.generation -cne $P.maintenanceGeneration -or
       $Proof.registryDigest -cne $O.begin.registryDigest -or -not (Same-Json $Proof.checkpoint $O.begin.checkpoint)){
        throw 'RELEASE_SUCCESSOR_ORDINARY_RETURN_CHANGED'
    }
    if($Saved -and $Published.record.phase -cne 'RECOVERY_HOLD'){
        $null=Read-OrdinarySuccessorSource $Source -Frozen -CandidateIds $CandidateIds
    }
    $Digest=Publish-SuccessorInterlock $Source $Proof.record $Proof.registryDigest
    $Published=(Read-SuccessorPublication $Source).anchor
    if($Published.state -cne 'Committed' -or $Published.digest -cne $Digest -or
       -not (Same-Json $Published.record $Proof.record) -or $Published.registryDigest -cne $Proof.registryDigest){
        throw 'RELEASE_SUCCESSOR_ORDINARY_RETURN_CHANGED'
    }
    $Rows=Read-OrdinarySuccessorSource $Source -PublicationRecovery -CandidateIds $CandidateIds
    if(-not $Returning -and $Rows.registry.State.Status -ceq 'exited'){
        $null=Set-BootstrapContainerState $Rows.registry Start
    }
    Wait-CorrectiveRegistryListener $Rows.registry.Id
    $Delivery=Image-RegistrySuccessor-Preflight -ImageId $P.image -ReleaseNonce $P.registryReleaseNonce -InterlockDigest $Digest -LatestPin
    Assert-SuccessorRuntimeDelivery $Delivery $P.registryDelivery $Published
    foreach($Field in @('sourceRevision','sourceCursor','snapshotRevision','eventDigest','profileDigest')){
        if($Delivery.registryCheckpoint.$Field -cne $Proof.checkpoint.$Field){throw 'RELEASE_SUCCESSOR_ORDINARY_RETURN_CHANGED'}
    }
    if(-not $Returning){
        $null=Set-BootstrapContainerState (Container $Rows.registry.Id) RestoreRestart
        if($Rows.gateway.State.Status -ceq 'exited'){
            $null=Set-BootstrapContainerState $Rows.gateway Start
        }
        Wait-Healthy $Rows.gateway.Id
        $null=Set-BootstrapContainerState (Container $Rows.gateway.Id) RestoreRestart
    }
    Admit-Source (Container $Rows.gateway.Id) $Source
    if(-not (Same-Json (Read-SuccessorPublication $Source).anchor $Published)){
        throw 'RELEASE_SUCCESSOR_ORDINARY_RETURN_CHANGED'
    }
    # Keep both holds, old generation, and every copy. No completion or NORMAL.
}

function Return-BootstrapPreparedPair {
    # Pre-activation Return restores the retained ORIGINAL, not a copied
    # database. Stop any exact new Gateway before its Registry, after
    # proving no activation marker. Retain every clone/hold/anchor. No
    # successful closure, reseed, cleanup or restart of a new generation.
    $Source=$script:R.source
    $Intent=Read-BootstrapFrozenIntent $Source $script:R.bootstrapCheckRecord $script:R.bootstrapCheckHash -Returning
    Assert-Release-Production
    $Ordinary=$Intent.ContainsKey('ordinary')
    if(-not $Ordinary){
    $null=Read-BootstrapSeedSource $Source -Transition
    $Original=(Read-Private $Source.path).correctivePair
    $Gateway=Container $Source.runtime.pilotId
    $Registry=Container $Original.targetRegistryId
    if($Registry.State.Status -ceq 'exited'){
        $Frozen=Read-CorrectiveCheckpoint $Registry.Id $Source.runtime.registryReleaseNonce $Original.targetRegistryProfile $Original.targetRegistryImage 3 '073d6f8701595e499eac5a1fa0cbe90accb05819' -Frozen
        if(-not (Same-Json $Frozen $Original.checkpoints.target)){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_FROZEN_REGISTRY_CHANGED'
        }
    }
    }
    $Candidate=Read-BootstrapGatewayCandidate $Intent
    $GatewayId=if($Candidate){$Candidate.Id}else{''}
    $Receiver=$null
    if($Intent.attempt.PSObject.Properties['bootstrapReceiver']){
        if($Ordinary){$Receiver=Read-BootstrapReceiver $Intent -GatewayId $GatewayId -Returning}
        else{$Receiver=Read-BootstrapReceiver $Intent -GatewayId $GatewayId}
    }
    if($Ordinary){
        $Ids=@($GatewayId);if($Receiver){$Ids+=@($Receiver.Id)}
        $Rows=Read-OrdinarySuccessorSource $Source -PublicationRecovery -CandidateIds $Ids
        $Gateway=$Rows.gateway;$Registry=$Rows.registry
    }
    if($Candidate -and -not $Receiver){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_MISSING'}
    if($Receiver){
        Assert-CorrectiveGateAbsent $Intent.attempt.runtime
        if(-not $Intent.attempt.bootstrapReceiver.id){
            if($Receiver.State.Status -cne 'created' -or $Candidate){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_CHANGED'}
            $Intent.attempt.bootstrapReceiver.id=$Receiver.Id
            $script:R=$Intent.attempt;Save -FlushToDisk
        }
        Assert-ReleaseVolumeHolders @($Intent.attempt.runtime.stateVolume) @($GatewayId) 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_REQUIRES_REVIEW'
        if($Candidate -and $Candidate.State.Status -ceq 'running'){
            if($Intent.attempt.phase -ceq 'Returned'){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RETURN_READBACK_CHANGED'}
            $Candidate=Set-BootstrapContainerState $Candidate Stop
        }
        Assert-CorrectiveGateAbsent $Intent.attempt.runtime
        if($Receiver.State.Status -ceq 'running'){
            if($Intent.attempt.phase -ceq 'Returned'){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RETURN_READBACK_CHANGED'}
            $Receiver=Set-BootstrapContainerState $Receiver Stop
        }
        if($Receiver.State.Status -cnotin @('created','exited')){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_CHANGED'}
    } else {Assert-BootstrapNoReceiver $Intent -Returning}
    if($Ordinary){
        Restore-OrdinarySourcePair $Intent $Rows $Ids
    }elseif($Intent.attempt.phase -ceq 'Returned'){
        # A lost final record ACK needs readback, not a second Return
        # operation. A later source failure is not part of this old attempt.
        foreach($C in @($Gateway,$Registry)){
            if($C.State.Status -cne 'running' -or $C.HostConfig.RestartPolicy.Name -cne 'unless-stopped'){
                throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RETURN_READBACK_CHANGED'
            }
        }
        Admit-Source $Gateway $Source
        Assert-Release-Production
        Write-Host 'FORTIS_SUCCESSOR_BOOTSTRAP_RETURNED_SOURCE_ONLY'
        return
    }else{
    if($Registry.State.Status -ceq 'exited'){
        $Registry=Set-BootstrapContainerState $Registry DisableRestart
        Step 'BOOTSTRAP_RETURN_REGISTRY'
        $Registry=Set-BootstrapContainerState $Registry Start
    }
    Wait-CorrectiveRegistryListener $Registry.Id
    $Actual=Read-CorrectiveCheckpoint $Registry.Id $Source.runtime.registryReleaseNonce $Original.targetRegistryProfile $Original.targetRegistryImage 3 '073d6f8701595e499eac5a1fa0cbe90accb05819'
    if(-not (Same-Json $Actual $Original.checkpoints.target)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_FROZEN_REGISTRY_CHANGED'
    }
    $null=Set-BootstrapContainerState $Registry RestoreRestart
    # A late source-state change can invalidate Check. Before any receiver
    # effect it does not justify discarding that newer ORIGINAL state.
    # Read-only live peer admission is mandatory before starting Gateway.
    Admit $Gateway $Source.runtime -AllowUnhealthy -BootstrapRetained
    if($Gateway.State.Status -ceq 'exited'){
        $Gateway=Set-BootstrapContainerState $Gateway DisableRestart
        Step 'BOOTSTRAP_RETURN_GATEWAY'
        $Gateway=Set-BootstrapContainerState $Gateway Start
    }
    Wait-Healthy $Gateway.Id
    Admit (Container $Gateway.Id) $Source.runtime -BootstrapRetained
    $null=Set-BootstrapContainerState (Container $Gateway.Id) RestoreRestart
    Admit-Source (Container $Gateway.Id) $Source
    }
    Assert-Release-Production
    if($Receiver){
        $Retained=if($Ordinary){Read-BootstrapReceiver $Intent -GatewayId $GatewayId -Returning}
            else{Read-BootstrapReceiver $Intent -GatewayId $GatewayId}
        if($Retained.Id -cne $Receiver.Id -or $Retained.State.Status -cnotin @('created','exited')){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_CHANGED'
        }
        if($Candidate -and (Container $Candidate.Id).State.Status -cnotin @('created','exited')){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_GATEWAY_CHANGED'
        }
        Assert-CorrectiveGateAbsent $Intent.attempt.runtime
    } else {Assert-BootstrapNoReceiver $Intent -Returning}
    # Never rewrite Check/owner GO/paired receipts to claim a successful
    # release. The retained operational anchor may still block a new
    # bootstrap; exact review/resolution is required, not blind re-seed.
    $script:R=Read-Private $script:RecordPath
    if($script:R.phase -cne 'Returned'){$script:R.phase='Returned';Save -FlushToDisk}
    if($Ordinary){Write-Host 'FORTIS_SUCCESSOR_ORDINARY_RETURNED_RECOVERY_HOLD'}
    else{Write-Host 'FORTIS_SUCCESSOR_BOOTSTRAP_RETURNED_SOURCE_ONLY'}
}

function Assert-OrdinaryReturnSelfTest {
    $PreviousR=$script:R;$PreviousPath=$script:RecordPath
    try {
        $script:RecordPath='fixture-return'
        $Gid='a'*64;$Rid='b'*64;$NewG='c'*64;$NewR='d'*64;$ImageId='sha256:'+('e'*64)
        $Generation='1'*64;$Pin='2'*64;$BeforeDigest='3'*64;$AfterDigest='4'*64
        $Nonce='11111111-1111-4111-8111-111111111111'
        $Checkpoint=@{sourceRevision=5;sourceCursor=('5'*40);snapshotRevision=12;eventDigest=('6'*64);profileDigest=('7'*64)}
        $Source=@{runtime=@{pilotId=$Gid;image=$ImageId;stateVolume='old-state';registryReleaseNonce=$Nonce
            maintenanceGeneration=$Generation;registryDelivery=@{latestPin=$true}}}
        $Before=@{phase='STAGED_TARGET_FROZEN';generation=('8'*64)}
        $Recovery=@{phase='RECOVERY_HOLD';generation=$Generation;previousDigest=$BeforeDigest}
        $Receipt=@{sha256=@{fixture='fixture'};summary=@{}}
        $Fixture=@{rows=@{};events=[Collections.Generic.List[string]]::new();proofs=0;phaseWrites=0;losePublish=$true;loseStart=$true;gate=$false;drift=$false}
        function Reset-ReturnFixture {
            foreach($Id in @($Gid,$Rid,$NewG,$NewR)){
                $Fixture.rows[$Id]=[pscustomobject]@{Id=$Id;Image=$ImageId
                    State=[pscustomobject]@{Status=$(if($Id -cin @($NewG,$NewR)){'running'}else{'exited'})}
                    HostConfig=[pscustomobject]@{RestartPolicy=[pscustomobject]@{Name='no';MaximumRetryCount=0}}}
            }
            $script:R=[pscustomobject]@{phase='Staged';activated=$false;source=$Source
                bootstrapCheckRecord='fixture-check';bootstrapCheckHash=('9'*64)
                bootstrapReceiver=[pscustomobject]@{id=$NewR}
                runtime=[pscustomobject]@{stateVolume='new-state';pilotId=$NewG}}
            $Fixture.events.Clear();$Fixture.proofs=0;$Fixture.phaseWrites=0;$Fixture.gate=$false;$Fixture.drift=$false
            $Fixture.anchor=@{state='Committed';record=$Before;digest=$BeforeDigest;registryDigest=$Pin}
        }
        function Read-BootstrapFrozenIntent {param($Source,$CheckPath,$CheckHash,[switch]$Returning)
            if(-not $Returning){throw 'FIXTURE_RETURN_INTENT'}
            return @{attempt=$script:R;check=@{binding=@{requireExactUncertain=$true;requireExactClaimed=$true;requireExactApproved=$true}}
                pair=@{registryImage=$ImageId};ordinary=@{intent=@{};begin=@{registryDigest=$Pin;checkpoint=$Checkpoint}
                check=@{};sourceReceipt=$Receipt;stop=@{next=@{phase='APPLY_STOP'}}}}
        }
        function Container {param($Id) return ($Fixture.rows[$Id]|ConvertTo-Json -Depth 10|ConvertFrom-Json)}
        function Read-OrdinarySuccessorSource {param($Source,[switch]$PublicationRecovery,[switch]$Frozen,[string[]]$CandidateIds)
            if($CandidateIds -cnotcontains $NewG -or $CandidateIds -cnotcontains $NewR){throw 'FIXTURE_TARGET_IDS'}
            if($Frozen -and @($Fixture.rows.Values|Where-Object{$_.State.Status -cne 'exited'}).Count){throw 'FIXTURE_RETURN_WRITER'}
            return @{gateway=(Container $Gid);registry=(Container $Rid);receiver=@{profileDigest=('a'*64)}}}
        function Read-BootstrapGatewayCandidate {return (Container $NewG)}
        function Read-BootstrapReceiver {param($Intent,$GatewayId,[switch]$Returning)
            if(-not $Returning -or $GatewayId -cne $NewG){throw 'FIXTURE_RETURN_RECEIVER'}
            return (Container $NewR)}
        function Assert-Release-Production {}
        function Assert-ReleaseVolumeHolders {}
        function Assert-Volume {}
        function Assert-CorrectiveGateAbsent {if($Fixture.gate){throw 'FIXTURE_ACTIVE_MARKER'}}
        function Receipt {param($Volume,[switch]$Exact,[switch]$ExactClaimed,[switch]$ExactApproved)
            if($Volume -cne 'old-state' -or -not ($Exact -and $ExactClaimed -and $ExactApproved)){throw 'FIXTURE_RECEIPT_MODE'}
            if($Fixture.drift){return @{sha256=@{};summary=@{}}};return $Receipt}
        function Read-SuccessorPublication {return @{anchor=$Fixture.anchor}}
        function Publish-SuccessorInterlock {param($Source,$Next,$RegistryDigest)
            if($RegistryDigest -cne $Pin){throw 'FIXTURE_RETURN_PIN'}
            if(Same-Json $Next $Before){return $BeforeDigest}
            if(-not $script:R.PSObject.Properties['ordinaryReturn'] -or -not (Same-Json $Next $Recovery)){
                throw 'FIXTURE_RECOVERY_BEFORE_PROOF'}
            if($Fixture.anchor.record.phase -ne 'RECOVERY_HOLD'){
                $Fixture.phaseWrites++;$Fixture.anchor=@{state='Committed';record=$Recovery;digest=$AfterDigest;registryDigest=$Pin}
                if($Fixture.losePublish){$Fixture.losePublish=$false;throw 'FIXTURE_RETURN_PUBLISH_ACK'}
            }
            return $AfterDigest}
        function Python-Code {param($Arguments,$Code,$InputText)
            $Fixture.proofs++
            if(@($Arguments|Where-Object{$_ -like 'type=volume,*' -and $_ -notmatch ',readonly,'}).Count -or
               @($Fixture.rows.Values|Where-Object{$_.State.Status -cne 'exited'}).Count){
                throw 'FIXTURE_RETURN_READONLY'}
            return (ConvertTo-Json -Compress -Depth 10 @{record=$Recovery;registryDigest=$Pin;checkpoint=$Checkpoint})}
        function Save {param([switch]$FlushToDisk)
            if(-not $FlushToDisk){throw 'FIXTURE_RETURN_NOT_DURABLE'}
            $Fixture.events.Add('save:'+ $script:R.phase)}
        function Read-Private {return $script:R}
        function Wait-CorrectiveRegistryListener {param($Id)
            if($Id -cne $Rid -or $Fixture.rows[$Id].State.Status -cne 'running'){throw 'FIXTURE_RETURN_LISTENER'}}
        function Image-RegistrySuccessor-Preflight {param($ImageId,$ReleaseNonce,$InterlockDigest,[switch]$LatestPin)
            if(-not $LatestPin -or $ReleaseNonce -cne $Nonce -or $InterlockDigest -cne $AfterDigest){throw 'FIXTURE_RETURN_PEER'}
            return @{registryCheckpoint=$Checkpoint}}
        function Assert-SuccessorRuntimeDelivery {param($Actual,$Retained,$Publication)
            if($Publication.record.phase -cne 'RECOVERY_HOLD'){throw 'FIXTURE_RETURN_PHASE'}}
        function Wait-Healthy {param($Id)
            if($Id -cne $Gid -or $Fixture.rows[$Id].State.Status -cne 'running'){throw 'FIXTURE_RETURN_HEALTH'}}
        function Admit-Source {param($C,$Source)
            if($C.Id -cne $Gid -or $C.State.Status -cne 'running' -or $Fixture.rows[$Rid].State.Status -cne 'running'){
                throw 'FIXTURE_RETURN_SOURCE'}}
        function Docker-Text {param($Arguments)
            $Id=$Arguments[-1];$C=$Fixture.rows[$Id]
            $Role=if($Id -ceq $Gid){'g'}elseif($Id -ceq $Rid){'r'}elseif($Id -ceq $NewG){'newg'}else{'newr'}
            $Fixture.events.Add($Role+':'+$Arguments[0])
            switch($Arguments[0]){
                'stop' {if($Role -ceq 'newr' -and $Fixture.rows[$NewG].State.Status -ne 'exited'){throw 'FIXTURE_RETURN_STOP_ORDER'}
                    $C.State.Status='exited'}
                'start' {if($Fixture.anchor.record.phase -cne 'RECOVERY_HOLD' -or $Role -cnotin @('g','r') -or
                    ($Role -ceq 'g' -and $Fixture.rows[$Rid].State.Status -ne 'running')){throw 'FIXTURE_RETURN_START_ORDER'}
                    $C.State.Status='running';if($Role -ceq 'r' -and $Fixture.loseStart){$Fixture.loseStart=$false;throw 'FIXTURE_RETURN_START_ACK'}}
                'update' {$C.HostConfig.RestartPolicy.Name=$Arguments[1].Substring(10)}
                default {throw 'FIXTURE_RETURN_EFFECT'}
            }}
        Reset-ReturnFixture
        $Fixture.gate=$true
        try {Return-BootstrapPreparedPair;throw 'FIXTURE_ACTIVE_ACCEPTED'}catch{if($_.Exception.Message -cne 'FIXTURE_ACTIVE_MARKER'){throw}}
        if($Fixture.events.Count){throw 'FIXTURE_ACTIVE_EFFECT'}
        $Fixture.gate=$false;$Fixture.drift=$true
        try {Return-BootstrapPreparedPair;throw 'FIXTURE_DRIFT_ACCEPTED'}catch{if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_ORDINARY_RETURN_STATE_CHANGED'){throw}}
        if($Fixture.proofs -or $Fixture.phaseWrites){throw 'FIXTURE_DRIFT_EFFECT'}
        $Fixture.drift=$false
        try {Return-BootstrapPreparedPair;throw 'FIXTURE_PUBLISH_ACK_ACCEPTED'}catch{if($_.Exception.Message -cne 'FIXTURE_RETURN_PUBLISH_ACK'){throw}}
        if($Fixture.proofs -ne 1 -or $Fixture.phaseWrites -ne 1 -or $Fixture.rows[$Rid].State.Status -ne 'exited'){
            throw 'FIXTURE_RETURN_PUBLISH_ORDER'}
        Return-BootstrapPreparedPair
        if($script:R.phase -cne 'Returned' -or $Fixture.proofs -ne 1 -or $Fixture.phaseWrites -ne 1 -or
            ($Fixture.events -join ',') -cne 'newg:stop,newr:stop,save:Staged,r:start,r:update,g:start,g:update,save:Returned'){
            throw ('FIXTURE_RETURN_EVENTS '+($Fixture.events -join ','))}
        $Count=$Fixture.events.Count
        Return-BootstrapPreparedPair
        if($Fixture.events.Count -ne $Count){throw 'FIXTURE_RETURN_REPLAY'}
    }finally{$script:R=$PreviousR;$script:RecordPath=$PreviousPath}
    Write-Host 'FORTIS_SUCCESSOR_ORDINARY_RETURN_SELFTEST_PASS'
}

function Assert-BootstrapGatewayLifecycleSelfTest {
    $PreviousR=$script:R;$PreviousPath=$script:RecordPath
    try {
        $script:RecordPath='fixture-attempt';$Pointer='fixture-current'
        $Gid='a'*64;$Rid='b'*64;$OldGid='c'*64;$OldRid='d'*64;$ImageId='sha256:'+('e'*64)
        $Source=@{path='fixture-source';runtime=@{pilotId=$OldGid;registryReleaseNonce='old';stateVolume='old-state'}}
        $Original=@{targetRegistryId=$OldRid;targetRegistryProfile='profile';targetRegistryImage=$ImageId
            checkpoints=@{target=@{sourceRevision=3}}}
        $Delivery=[pscustomobject]@{profileDigest=('a'*64);sourceDelivery=[pscustomobject]@{interlockDigest=('f'*64)}}
        $Digest='1'*64
        $Fixture=@{rows=@{};events=[Collections.Generic.List[string]]::new();pointer=$Source.path;gate=$false
            failProbe=$true;losePointer=$true;loseActivationSave=$false;effects=0}
        function Reset-Fixture {
            foreach($Id in @($Gid,$Rid,$OldGid,$OldRid)){
                $Status=if($Id -ceq $Gid){'created'}elseif($Id -ceq $Rid){'running'}else{'exited'}
                $Fixture.rows[$Id]=[pscustomobject]@{Id=$Id;Image=$ImageId;State=[pscustomobject]@{Status=$Status;StartedAt='0001-01-01T00:00:00Z'}
                    HostConfig=[pscustomobject]@{RestartPolicy=[pscustomobject]@{Name='no';MaximumRetryCount=0}}}
            }
            $script:R=[pscustomobject]@{phase='Prepared';activated=$false;probesPassed=$false;source=$Source
                bootstrapCheckRecord='fixture-check';bootstrapCheckHash=('2'*64);bootstrapOwnerGo=@{}
                bootstrapReceiver=[pscustomobject]@{id=$Rid};bootstrapDelivery=$Delivery
                configurationDigest=$Digest;probes='[]'
                runtime=[pscustomobject]@{pilotId='';pilotName='fixture-gateway';stateVolume='new-state';releaseNonce='new';registryDelivery=$Delivery}}
            $Fixture.pointer=$Source.path;$Fixture.gate=$false;$Fixture.events.Clear()
        }
        function Read-BootstrapFrozenIntent {param($Source,$CheckPath,$CheckHash,[switch]$Runtime,[switch]$Returning)
            return @{attempt=$script:R}}
        function Read-BootstrapSeedSource {param($Source,[switch]$Transition)
            if(-not $Transition -and ($Fixture.rows[$OldGid].State.Status -cne 'exited' -or
                $Fixture.rows[$OldRid].State.Status -cne 'exited')){throw 'FIXTURE_OLD_PAIR_NOT_FROZEN'}}
        function Read-Private {param($Path)
            if($Path -ceq $Pointer){return @{record=$Fixture.pointer}}
            if($Path -ceq $Source.path){return @{correctivePair=$Original}}
            if($Path -ceq $script:RecordPath){return $script:R}
            throw 'FIXTURE_LIFECYCLE_RECORD'}
        function Container {param($Id)
            if($Id -ceq 'fixture-gateway'){$Id=$Gid}
            if(-not $Fixture.rows.ContainsKey($Id)){throw 'FIXTURE_LIFECYCLE_ID'}
            return ($Fixture.rows[$Id]|ConvertTo-Json -Depth 10|ConvertFrom-Json)}
        function Read-BootstrapReceiver {param($Intent,$GatewayId,[switch]$Accepted)
            if($GatewayId -cne $Gid -or $Intent.attempt.runtime.pilotId -cne $Gid){throw 'FIXTURE_GATEWAY_ID_NOT_SAVED'}
            return (Container $Rid)}
        function Read-SuccessorPublication {return @{anchor=@{state='Committed';record=@{phase='STAGED_TARGET_FROZEN'}
            digest=$Delivery.sourceDelivery.interlockDigest}}}
        function Read-CorrectiveAttemptPair {}
        function Assert-Release-Production {}
        function Assert-SourceUnchanged {}
        function Assert-OnlyWriter {}
        function Assert-ReleaseVolumeHolders {}
        function Read-GatewayNetworks {}
        function Read-OwnerShellFlag {return $false}
        function Complete-ActionCoreNetwork {param($C,$P) return $C}
        function Step {}
        function Write-ReleaseTiming {}
        function Wait-Healthy {param($Id)
            if($Fixture.rows[$Id].State.Status -cne 'running'){throw 'FIXTURE_HEALTH'}}
        function Wait-CorrectiveRegistryListener {param($Id)
            if($Fixture.rows[$Id].State.Status -cne 'running'){throw 'FIXTURE_LISTENER'}}
        function Read-CorrectiveCheckpoint {param($Id,$Nonce,$Profile,$Image,$Revision,$Commit,[switch]$Frozen)
            if($Id -cne $OldRid -or $Revision -ne 3 -or $Frozen -ne ($Fixture.rows[$OldRid].State.Status -ceq 'exited')){
                throw 'FIXTURE_OLD_CHECKPOINT'}
            return $Original.checkpoints.target}
        function Admit {param($C,$P,[switch]$AllowUnhealthy,[switch]$RegistryReturnSource,[switch]$AllowPendingIngress,[switch]$BootstrapRetained)
            if($C.Id -ceq $Gid){
                if($P.pilotId -and $P.pilotId -cne $Gid){throw 'FIXTURE_GATEWAY_PIN'}
                if(-not $RegistryReturnSource -and $Fixture.rows[$Rid].State.Status -cne 'running'){throw 'FIXTURE_PEER_NOT_RUNNING'}
            } elseif($C.Id -ceq $OldGid){
                if(-not $BootstrapRetained -or $Fixture.rows[$OldRid].State.Status -cne 'running'){throw 'FIXTURE_OLD_PEER_NOT_RUNNING'}
            }else{throw 'FIXTURE_ADMIT_ID'}}
        function Admit-Source {param($C,$Source)
            if($C.Id -cne $OldGid -or $Fixture.rows[$OldGid].State.Status -cne 'running' -or
               $Fixture.rows[$OldRid].State.Status -cne 'running'){throw 'FIXTURE_RETURN_SOURCE'}}
        function Assert-CorrectiveGateAbsent {param($P)
            if($Fixture.gate){throw 'RELEASE_ALREADY_ACTIVE_RETURN_REQUIRES_REVIEW'}}
        function Image-CLI {param($Command,$InputText,$StateVolume)
            return @{active=$Fixture.gate;markerPresent=$Fixture.gate}}
        function Running-CLI {param($Id,$Command,$InputText,[switch]$Root)
            if($Id -cne $Gid -or $Fixture.rows[$Id].State.Status -cne 'running'){throw 'FIXTURE_CLI_ID'}
            switch($Command[0]){
                'gate-status' {return @{active=$Fixture.gate;configurationDigest=$Digest}}
                'catalog' {return @{configurationDigest=$Digest;operations=@()}}
                'probe-frozen' {
                    $ProbeArgs=ConvertFrom-Json -InputObject $InputText
                    if($ProbeArgs.interlockDigest -cne $Delivery.sourceDelivery.interlockDigest -or
                       $ProbeArgs.profileDigest -cne $Delivery.profileDigest -or $ProbeArgs.configurationDigest -cne $Digest -or
                       @($ProbeArgs.probes).Count){throw 'FIXTURE_FROZEN_PROBE_INPUT'}
                    if($Fixture.failProbe){throw 'FIXTURE_PROBE_FAILED'}
                    return @{status='READ_PROBES_PASS';count=0}
                }
                'activate' {
                    if(-not $Root -or -not $script:R.probesPassed -or $Fixture.gate){throw 'FIXTURE_ACTIVATION_ORDER'}
                    $Fixture.events.Add('activate');$Fixture.gate=$true;throw 'FIXTURE_ACTIVATION_ACK_LOST'}
                default {throw 'FIXTURE_CLI_COMMAND'}
            }}
        function Repo-JSON {param($Code)
            if($Code -match 'list_branches'){return @{nativeCapabilities=$true;githubRead=$true}}
            return @{configurationDigest=$Digest}
        }
        function Save {param([switch]$FlushToDisk)
            if(-not $FlushToDisk){throw 'FIXTURE_LIFECYCLE_SAVE'}
            if($script:R.activated -and -not $Fixture.gate){throw 'FIXTURE_FALSE_ACTIVATION'}
            $Fixture.events.Add('save:'+ $script:R.phase+':'+$script:R.activated)}
        function Write-Private {param($Path,$Value,[switch]$FlushToDisk)
            if($Path -cne $Pointer -or -not $FlushToDisk -or $script:R.phase -cne 'Complete' -or
               -not $script:R.activated -or $Fixture.rows[$Rid].HostConfig.RestartPolicy.Name -cne 'unless-stopped'){
                throw 'FIXTURE_POINTER_ORDER'}
            if($Fixture.losePointer){$Fixture.losePointer=$false;throw 'FIXTURE_POINTER_ACK_LOST'}
            $Fixture.pointer=$Value.record;$Fixture.events.Add('pointer')}
        function Docker-Text {param($Arguments)
            if(($Arguments -join ' ') -ceq 'ps -a --format {{.Names}}'){return 'fixture-gateway'}
            $Id=$Arguments[-1];$Row=$Fixture.rows[$Id]
            $Role=if($Id -ceq $Gid){'g'}elseif($Id -ceq $Rid){'r'}elseif($Id -ceq $OldGid){'oldg'}else{'oldr'}
            $Fixture.events.Add($Role+':'+$Arguments[0]);$Fixture.effects++
            switch($Arguments[0]){
                'start' {
                    if($Role -ceq 'g' -and ($script:R.runtime.pilotId -cne $Gid -or
                        $Fixture.rows[$Rid].State.Status -cne 'running')){throw 'FIXTURE_START_BEFORE_RECORD'}
                    if($Role -ceq 'oldg' -and $Fixture.rows[$OldRid].State.Status -cne 'running'){throw 'FIXTURE_RETURN_ORDER'}
                    $Row.State.Status='running';if($Role -ceq 'g'){throw 'FIXTURE_START_ACK_LOST'}}
                'stop' {
                    if($Fixture.gate){throw 'FIXTURE_STOP_AFTER_ACTIVATION'}
                    if($Role -ceq 'r' -and $Fixture.rows[$Gid].State.Status -ceq 'running'){throw 'FIXTURE_STOP_ORDER'}
                    $Row.State.Status='exited'}
                'update' {
                    if($Role -ceq 'r' -and -not $script:R.activated){throw 'FIXTURE_RESTART_BEFORE_MARKER'}
                    $Row.HostConfig.RestartPolicy.Name=$Arguments[1].Substring(10)}
                default {throw 'FIXTURE_LIFECYCLE_EFFECT'}
            }}
        Reset-Fixture
        $null=Read-BootstrapGatewayCandidate @{attempt=$script:R}
        if($script:R.phase -cne 'Created' -or $script:R.runtime.pilotId -cne $Gid){throw 'FIXTURE_GATEWAY_CREATE_ACK'}
        try {Resume-Target;throw 'FIXTURE_PROBE_ACCEPTED'}catch{if($_.Exception.Message -cne 'FIXTURE_PROBE_FAILED'){throw}}
        Return-BootstrapPreparedPair
        if($script:R.phase -cne 'Returned' -or ($Fixture.events -join ',') -cne
            'save:Created:False,g:start,save:Staged:False,g:stop,r:stop,oldr:start,oldr:update,oldg:start,oldg:update,save:Returned:False'){
            throw ('FIXTURE_GATEWAY_RETURN_ORDER '+($Fixture.events -join ','))
        }
        $Effects=$Fixture.effects;Return-BootstrapPreparedPair
        if($Fixture.effects -ne $Effects){throw 'FIXTURE_RETURN_REPLAY'}
        Reset-Fixture;$Fixture.failProbe=$false
        $null=Read-BootstrapGatewayCandidate @{attempt=$script:R}
        try {Resume-Target;throw 'FIXTURE_POINTER_LOSS_ACCEPTED'}catch{if($_.Exception.Message -cne 'FIXTURE_POINTER_ACK_LOST'){throw}}
        if($script:R.phase -cne 'Complete' -or -not $script:R.activated -or $Fixture.pointer -cne $Source.path){
            throw 'FIXTURE_ACTIVATION_NOT_DURABLE'}
        $Effects=$Fixture.effects
        Resume-Target;Resume-Target
        if($Fixture.pointer -cne $script:RecordPath -or $Fixture.effects -ne $Effects -or
           @($Fixture.events|Where-Object{$_ -ceq 'activate'}).Count -ne 1){
            throw 'FIXTURE_POINTER_RECOVERY_EFFECT'}
        # A lost activation record can leave the actual marker present in
        # Staged; Return must fail before any stop, not trust activated=false.
        $script:R.phase='Staged';$script:R.activated=$false
        $Fixture.rows[$Rid].HostConfig.RestartPolicy.Name='no'
        try {Return-BootstrapPreparedPair;throw 'FIXTURE_ACTIVE_RETURN_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_ALREADY_ACTIVE_RETURN_REQUIRES_REVIEW'){throw}}
        if($Fixture.effects -ne $Effects){throw 'FIXTURE_ACTIVE_RETURN_EFFECT'}
    } finally {$script:R=$PreviousR;$script:RecordPath=$PreviousPath}
    Write-Host 'FORTIS_SUCCESSOR_BOOTSTRAP_GATEWAY_LIFECYCLE_SELFTEST_PASS'
}


function Assert-BootstrapReceiverSelfTest {
    $PreviousR=$script:R
    try {
        $Nonce='11111111-1111-4111-8111-111111111111';$Id=$Nonce.Replace('-','')
        $RegistryImage='sha256:'+('a'*64);$GatewayImage='sha256:'+('b'*64)
        $Profile='c'*64;$Generation='d'*64;$Digest='e'*64;$Hold='f'*64;$Cursor='1'*40
        $AttemptId='22222222-2222-4222-8222-222222222222';$ContainerId='3'*64
        $Stop=[pscustomobject]@{phase='APPLY_STOP'}
        $Next=[pscustomobject]@{phase='STAGED_TARGET_FROZEN';generation=$Generation}
        $Handoff=[pscustomobject]@{interlockDigest=$Digest}
        $Companion=[pscustomobject]@{companionDigest=('4'*64);schemaDigest=('5'*64);authorityWitnessDigest=('6'*64)}
        $Checkpoint=[pscustomobject]@{sourceRevision=4;sourceCursor=$Cursor;profileDigest=('5'*64)}
        $Pair=[pscustomobject]@{registryImage=$RegistryImage;checked=[pscustomobject]@{
            registry=[pscustomobject]@{checkpoint=$Checkpoint;binding=[pscustomobject]@{authorityDigest=('6'*64)}}
            gateway=[pscustomobject]@{companion=$Companion}}}
        $Begin=[pscustomobject]@{registryDigest=$Hold;phasePlan=[pscustomobject]@{records=@('a','b','c',$Stop,$Next);handoff=$Handoff}
            holdSnapshot=[pscustomobject]@{snapshotRevision=6;eventDigest=('7'*64)}}
        $Material=[pscustomobject]@{registryProfileDigest=$Profile;gatewayProfileDigest=('8'*64);generation=$Generation;handoff=$Handoff}
        $Source=@{runtime=@{runId='cd6d3d97350e4f5590d9c3e9ece69580';stateVolume='fortis-github-pilot-state-cd6d3d97350e4f5590d9c3e9ece69580'}}
        $Attempt=[pscustomobject]@{phase='Prepared';activated=$false;probesPassed=$false;bootstrapMaterials=$Material;bootstrapBegin=$Begin
            runtime=[pscustomobject]@{registryReleaseNonce=$Nonce;image=$GatewayImage;pilotId='';pilotName='fixture-gateway';stateVolume='new-state'}}
        $Intent=@{attempt=$Attempt;pair=$Pair;go=@{attemptId=$AttemptId;targetGeneration=$Generation};check=@{binding=@{sourceSha=$Cursor}}}
        $Delivery=[pscustomobject]@{profileDigest=$Material.gatewayProfileDigest;generation=$Generation;maintenancePhase='STAGED_TARGET_FROZEN'
            sourceDelivery=[pscustomobject]@{policyAuthorityDigest=$Pair.checked.registry.binding.authorityDigest}
            registryCheckpoint=[pscustomobject]@{registryDigest=$Hold;profileDigest=$Checkpoint.profileDigest;sourceRevision=4
                sourceCursor=$Cursor;snapshotRevision=6;eventDigest=$Begin.holdSnapshot.eventDigest};existingCompanion=$Companion;companionDigest=$Companion.companionDigest}
        $Fixture=@{container=$null;publication=[pscustomobject]@{state='Committed';record=$Stop;registryDigest=$Hold;digest=('9'*64)}
            saves=0;creates=0;starts=0;publishes=0;seal=0;losePublish=$true;wrongProof=$true}
        function Read-BootstrapFrozenIntent {return $Intent}
        function Read-BootstrapSeedSource {}
        function Assert-Release-Production {}
        function Assert-CorrectiveGateAbsent {}
        function Assert-ReleaseVolumeHolders {}
        function Assert-CorrectiveTargetHolders {}
        function Assert-Volume {}
        function Assert-OnlyWriter {}
        function Step {}
        function Read-Private {return $Attempt}
        function Save {param([switch]$FlushToDisk)
            if(-not $FlushToDisk){throw 'FIXTURE_RECEIVER_NOT_DURABLE'}
            $Fixture.saves++}
        function Seal-BootstrapFinalProfiles {$Fixture.seal++;return $Material}
        function Read-SuccessorPublication {return @{anchor=$Fixture.publication}}
        function Container {param($Name)
            if($Name -cnotin @($ContainerId,('fortis-registry-successor-'+$Id)) -or -not $Fixture.container){throw 'FIXTURE_RECEIVER_ID'}
            return ($Fixture.container|ConvertTo-Json -Depth 15|ConvertFrom-Json)}
        function Docker-Text {param($Arguments)
            if(($Arguments -join ' ') -ceq 'ps -a --format {{.Names}}'){
                if($Fixture.container){return $Fixture.container.Name.Substring(1)}
                return ''
            }
            if($Arguments[0] -ceq 'create'){
                if($Fixture.saves -ne 1 -or $Attempt.bootstrapReceiver.id -or $Fixture.container){throw 'FIXTURE_RECEIVER_CREATE_ORDER'}
                $Fixture.creates++
                $Mounts=@(foreach($Arg in $Arguments|Where-Object{$_ -like 'type=volume,*'}){
                    $Parts=@{};foreach($Entry in ($Arg -split ',')){if($Entry -match '='){$K,$V=$Entry -split '=',2;$Parts[$K]=$V}}
                    [ordered]@{Type='volume';Name=$Parts.source;Source=('/var/lib/docker/volumes/'+$Parts.source+'/_data')
                        Destination=$Parts.target;RW=($Arg -cnotmatch ',readonly$')}
                })
                if($Mounts.Count -ne 7 -or $Arguments -cnotcontains '--restart=no' -or
                   $Arguments -cnotcontains ('io.fortis.bootstrap-attempt='+$AttemptId)){throw 'FIXTURE_RECEIVER_ARGUMENTS'}
                $Cmd=@($Arguments[($Arguments.IndexOf($RegistryImage)+1)..($Arguments.Count-1)])
                $Fixture.container=[pscustomobject]@{Id=$ContainerId;Name=('/fortis-registry-successor-'+$Id);Image=$RegistryImage
                    Path='python';Args=@($Cmd[1..($Cmd.Count-1)]);Mounts=$Mounts
                    State=[pscustomobject]@{Status='created';StartedAt='0001-01-01T00:00:00Z'}
                    Config=[pscustomobject]@{User='20002:20002';Cmd=$Cmd;Entrypoint=@();Labels=[pscustomobject]@{
                        'org.opencontainers.image.revision'=$Cursor;'io.fortis.bootstrap-attempt'=$AttemptId}}
                    HostConfig=[pscustomobject]@{NetworkMode='none';RestartPolicy=[pscustomobject]@{Name='no';MaximumRetryCount=0}
                        Init=$true;ReadonlyRootfs=$true;Privileged=$false;CapAdd=@();CapDrop=@('ALL')
                        SecurityOpt=@('no-new-privileges:true');PidsLimit=64;Memory=536870912}}
                throw 'FIXTURE_CREATE_ACK_LOST'
            }
            if($Arguments[0] -ceq 'start'){
                if($Attempt.bootstrapReceiver.id -cne $ContainerId -or $Fixture.publication.state -cne 'Committed' -or
                   $Fixture.publication.record.phase -cne 'STAGED_TARGET_FROZEN'){throw 'FIXTURE_RECEIVER_START_ORDER'}
                $Fixture.starts++;$Fixture.container.State.Status='running';throw 'FIXTURE_START_ACK_LOST'
            }
            throw 'FIXTURE_RECEIVER_UNEXPECTED_EFFECT'
        }
        function Publish-SuccessorInterlock {param($Source,$Next,$RegistryDigest)
            if($Attempt.bootstrapReceiver.id -cne $ContainerId -or $Fixture.saves -lt 2 -or $RegistryDigest -cne $Hold){
                throw 'FIXTURE_RECEIVER_PUBLISH_ORDER'}
            if($Fixture.losePublish){
                $Fixture.losePublish=$false;$Fixture.publication.state='Pending'
                $Fixture.publication|Add-Member -NotePropertyName next -NotePropertyValue $Next
                throw 'FIXTURE_PUBLISH_ACK_LOST'
            }
            if($Fixture.publication.record.phase -ceq 'APPLY_STOP'){$Fixture.publishes++}
            $Fixture.publication=[pscustomobject]@{state='Committed';record=$Next;registryDigest=$Hold;digest=$Digest}
            return $Digest
        }
        function Wait-CorrectiveRegistryListener {param($Id)
            if($Id -cne $ContainerId -or $Fixture.container.State.Status -cne 'running'){throw 'FIXTURE_RECEIVER_NOT_STARTED'}}
        function Image-RegistrySuccessor-Preflight {
            param($ImageId,$ReleaseNonce,$InterlockDigest,[switch]$LatestPin,$IncumbentVolume,$ExpectedExisting)
            if(-not $LatestPin -or $InterlockDigest -cne $Digest -or $IncumbentVolume -cne $Source.runtime.stateVolume -or -not (Same-Json $ExpectedExisting $Companion)){throw 'FIXTURE_RECEIVER_PREFLIGHT_PIN'}
            $Result=$Delivery|ConvertTo-Json -Depth 10|ConvertFrom-Json
            Assert-RegistrySuccessorCompanionPreflight $Result $IncumbentVolume $ExpectedExisting
            if($Fixture.wrongProof){$Result.registryCheckpoint.eventDigest='0'*64}
            return $Result
        }
        try {$null=Start-BootstrapReceiver $Source fixture ('a'*64);throw 'FIXTURE_PENDING_PUBLISH_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'FIXTURE_PUBLISH_ACK_LOST'){throw}}
        if($Fixture.creates -ne 1 -or $Fixture.starts -ne 0 -or $Fixture.saves -ne 2){throw 'FIXTURE_RECEIVER_PRESTART'}
        try {$null=Start-BootstrapReceiver $Source fixture ('a'*64);throw 'FIXTURE_WRONG_CHECKPOINT_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'){throw}}
        if($Fixture.starts -ne 1 -or $Fixture.saves -ne 2){throw 'FIXTURE_RECEIVER_UNVERIFIED_SAVE'}
        $Fixture.wrongProof=$false
        $Wrong=$Companion|ConvertTo-Json|ConvertFrom-Json
        $Wrong.authorityWitnessDigest='0'*64
        try {Assert-RegistrySuccessorCompanionPreflight $Delivery $Source.runtime.stateVolume $Wrong;throw 'FIXTURE_WRONG_COMPANION_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_REGISTRY_SUCCESSOR_PREFLIGHT_UNCONFIRMED'){throw}}
        try {Assert-RegistrySuccessorCompanionPreflight $Delivery $Source.runtime.stateVolume;throw 'FIXTURE_UNPINNED_COMPANION_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_REGISTRY_SUCCESSOR_PREFLIGHT_UNCONFIRMED'){throw}}
        $Actual=Start-BootstrapReceiver $Source fixture ('a'*64)
        $Again=Start-BootstrapReceiver $Source fixture ('a'*64)
        if($Fixture.creates -ne 1 -or $Fixture.starts -ne 1 -or $Fixture.publishes -ne 1 -or $Fixture.saves -ne 3 -or
           $Fixture.seal -ne 1 -or -not (Same-Json $Actual $Again)){throw 'FIXTURE_RECEIVER_DUPLICATE_EFFECT'}
        $Fixture.container.Mounts[-1].RW=$true
        try {$null=Read-BootstrapReceiver $Intent;throw 'FIXTURE_WRITABLE_ANCHOR_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_CORRECTIVE_REGISTRY_MOUNT_CHANGED'){throw}}
    } finally {$script:R=$PreviousR}
    Write-Host 'FORTIS_SUCCESSOR_BOOTSTRAP_RECEIVER_SELFTEST_PASS'
}

function Assert-BootstrapFinalMaterialSelfTest {
    $PreviousR=$script:R;$PreviousPath=$script:RecordPath
    try {
        $script:RecordPath='fixture-attempt'
        $G='a'*64;$R='b'*64;$Generation='c'*64
        $Handoff=[pscustomobject]@{role='staged_target';registryDigest=('d'*64)}
        $Stop=[pscustomobject]@{phase='APPLY_STOP'}
        $Plan=[pscustomobject]@{records=@('a','b','c',$Stop,[pscustomobject]@{previousDigest=('e'*64)});handoff=$Handoff}
        $Begin=[pscustomobject]@{phasePlan=$Plan;registryDigest=$Handoff.registryDigest}
        $Attempt=[pscustomobject]@{bootstrapBegin=$Begin}
        $Intent=@{attempt=$Attempt;go=@{targetGeneration=$Generation}}
        $Publication=[pscustomobject]@{state='Committed';record=$Stop;digest=('e'*64);registryDigest=$Handoff.registryDigest}
        $Registry=[pscustomobject]@{profileDigest=$R;profile=@{schemaVersion=3};generation=$Generation
            handoff=$Handoff;fileHashes=[pscustomobject]@{'profile.json'=$R}}
        $Gateway=[pscustomobject]@{profileDigest=$G;registryProfileDigest=$R;generation=$Generation
            handoff=$Handoff;fileHashes=[pscustomobject]@{'profile.json'=$G}}
        $Fixture=@{events=[Collections.Generic.List[string]]::new();saves=0;bad=$true;lose=$true}
        function Read-BootstrapFrozenIntent {return $Intent}
        function Assert-BootstrapNoReceiver {}
        function Read-SuccessorPublication {return @{anchor=$Publication}}
        function Read-BootstrapSeedSource {return @{digest=('f'*64)}}
        function Assert-BootstrapFrozenCheck {}
        function Read-Private {return $Attempt}
        function Save {param([switch]$FlushToDisk)
            if(-not $FlushToDisk -or (-not $script:R.PSObject.Properties['bootstrapMaterials'] -and -not $script:R.PSObject.Properties['ordinaryStateCopy'])){throw 'FIXTURE_MATERIAL_SAVE'}
            $Fixture.saves++}
        function Invoke-BootstrapFinalMaterialHelper {
            param($Intent,$Source,$Publication,$Seed,$Role,$RegistryProfile,[switch]$VerifyOnly)
            $Fixture.events.Add($Role+':'+$(if($VerifyOnly){'RO'}else{'RW'}))
            if($Role -ceq 'State'){
                if(-not $VerifyOnly){
                    if($Fixture.stateWrites){throw 'FIXTURE_DUPLICATE_STATE_COPY'}
                    $Fixture.stateWrites++;throw 'FIXTURE_STATE_COPY_ACK_LOST'
                }
                if($Fixture.stateWrites -ne 1){throw 'FIXTURE_STATE_COPY_NOT_APPLIED'}
                return $State
            }
            if($Role -ceq 'Registry'){
                if(-not $VerifyOnly -and $Fixture.lose){$Fixture.lose=$false;throw 'FIXTURE_MATERIAL_ACK_LOST'}
                return $Registry
            }
            if(-not (Same-Json $RegistryProfile $Registry.profile)){throw 'FIXTURE_REGISTRY_PROFILE_PIN'}
            if($Fixture.bad){return [pscustomobject]@{profileDigest=$G;registryProfileDigest=('0'*64)
                generation=$Generation;handoff=$Handoff;fileHashes=$Gateway.fileHashes}}
            return $Gateway
        }
        try {$null=Seal-BootstrapFinalProfiles @{} fixture ('1'*64);throw 'FIXTURE_CROSS_PROFILE_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_FINAL_MATERIAL_CHANGED'){throw}}
        if($Fixture.saves -ne 0 -or ($Fixture.events -join ',') -cne 'Registry:RW,Registry:RO,Gateway:RW,Gateway:RO'){
            throw 'FIXTURE_MATERIAL_EARLY_SAVE'}
        $Fixture.events.Clear();$Fixture.bad=$false
        $Actual=Seal-BootstrapFinalProfiles @{} fixture ('1'*64)
        $Again=Seal-BootstrapFinalProfiles @{} fixture ('1'*64)
        if($Fixture.saves -ne 1 -or -not (Same-Json $Actual $Again) -or
           ($Fixture.events -join ',') -cne 'Registry:RW,Registry:RO,Gateway:RW,Gateway:RO,Registry:RO,Gateway:RO'){
            throw 'FIXTURE_MATERIAL_REENTRY'}
        $Publication.state='Pending'
        try {$null=Seal-BootstrapFinalProfiles @{} fixture ('1'*64);throw 'FIXTURE_MATERIAL_PENDING_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_PHASE_CHANGED'){throw}}
        if($Fixture.events.Count -ne 6){throw 'FIXTURE_MATERIAL_EFFECT_BEFORE_PHASE'}
        # Ordinary copy receipts must be durable before either final seal.
        $Fixture.events.Clear();$Fixture.saves=0;$Fixture.stateWrites=0
        $Publication.state='Committed'
        $Attempt=[pscustomobject]@{phase='Prepared'}
        $OrdinaryBegin=[pscustomobject]@{draining='a';registryDigest=$Handoff.registryDigest;checkpoint=@{sourceRevision=4};holdSnapshot=@{holds=@('pair')}}
        $State=[pscustomobject]@{result='PAIRED_STAGED_STATE_COPY_ONLY';checkpoint=$OrdinaryBegin.checkpoint
            holdSnapshot=$OrdinaryBegin.holdSnapshot;final=@{record=@{phase='STAGED_TARGET_FROZEN';previousDigest=$Publication.digest};handoff=$Handoff}}
        $Intent=@{attempt=$Attempt;go=@{targetGeneration=$Generation};ordinary=@{begin=$OrdinaryBegin;stop=@{next=$Stop}}
            check=@{maintenanceTransitions=@{frozen='b';checked='c'}}}
        function Assert-PairedFrozenSource {}
        $Actual=Seal-BootstrapFinalProfiles @{} fixture ('1'*64)
        $Again=Seal-BootstrapFinalProfiles @{} fixture ('1'*64)
        if($Fixture.saves -ne 2 -or $Fixture.stateWrites -ne 1 -or -not (Same-Json $Actual $Again) -or
           ($Fixture.events -join ',') -cne 'State:RW,State:RO,Registry:RW,Registry:RO,Gateway:RW,Gateway:RO,State:RO,Registry:RO,Gateway:RO'){
            throw 'FIXTURE_ORDINARY_MATERIAL_REENTRY'
        }

    } finally {$script:R=$PreviousR;$script:RecordPath=$PreviousPath}
    Write-Host 'FORTIS_SUCCESSOR_BOOTSTRAP_FINAL_MATERIAL_SELFTEST_PASS'
}

function Assert-BootstrapPreparedAttemptSelfTest {
    $PreviousR=$script:R;$PreviousPath=$script:RecordPath;$PreviousPair=$script:BootstrapPair
    try {
        $CheckPath=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) 'fortis-bootstrap-check.json'))
        $ReviewPath=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) 'fortis-bootstrap-review.json'))
        $CheckedImageRecord=$CheckPath;$AttemptPointer='fixture-pointer'
        $script:RecordPath='fixture-attempt'
        $Source=@{path='fixture-source';hash=('a'*64)}
        $Receipt=[ordered]@{sha256=[ordered]@{fixture='b'*64};summary=[ordered]@{}}
        $Check=[ordered]@{binding=[ordered]@{bootstrapReviewProofRecord=$ReviewPath};sourceReceipt=$Receipt}
        $script:BootstrapPair=[ordered]@{compatibilityDigest=('c'*64)}
        $Go=[ordered]@{attemptId='11111111-1111-4111-8111-111111111111'}
        $script:R=[ordered]@{phase='Prepared';activated=$false;probesPassed=$false;source=$Source
            runtime=[ordered]@{pilotId=''};sourceReceipt=$null}
        $Fixture=@{records=@{};events=[Collections.Generic.List[string]]::new();changed=$true;sourceDrift=$false}
        function Get-FileHash {param($LiteralPath,$Algorithm)
            if($LiteralPath -cne $CheckPath){throw 'FIXTURE_CHECK_PATH'}
            return @{Hash=('d'*64)}}
        function Read-Private {param($Path)
            if($Path -ceq $CheckPath){return $Check}
            return ($Fixture.records[$Path]|ConvertTo-Json -Depth 25|ConvertFrom-Json)}
        function New-BootstrapOwnerGo {param($Source,$CheckPath,$CheckHash,$ReviewProofPath)
            if($ReviewProofPath -cne $ReviewPath -or $CheckHash -cne ('d'*64)){throw 'FIXTURE_GO_PIN'}
            $Fixture.events.Add('GO');return $Go}
        function Read-BootstrapCompatibility {param($Source,[switch]$Recheck)
            if(-not $Recheck){throw 'FIXTURE_RECHECK_REQUIRED'}
            $Fixture.events.Add('RECHECK')
            if($Fixture.changed){return @{compatibilityDigest=('0'*64)}}
            return $script:BootstrapPair}
        function Verify-Checked-Image {param($Source,$Report,[switch]$ReturnReceipt)
            if(-not $ReturnReceipt){throw 'FIXTURE_RECEIPT_REQUIRED'}
            $Fixture.events.Add('VERIFY')
            if($Fixture.sourceDrift){return @{changed=$true}}
            return $Receipt}
        function Assert-BootstrapNoReceiver {}
        function Assert-Release-Production {}
        function Save {param([switch]$FlushToDisk)
            if(-not $FlushToDisk -or -not (Same-Json $script:R.sourceReceipt $Receipt) -or
               -not (Same-Json $script:R.bootstrapOwnerGo $Go)){throw 'FIXTURE_ATTEMPT_NOT_DURABLE'}
            $Fixture.events.Add('SAVE');$Fixture.records[$script:RecordPath]=$script:R}
        function Write-Private {param($Path,$Value,[switch]$FlushToDisk)
            if(-not $FlushToDisk -or -not $Fixture.records[$script:RecordPath] -or $Path -cne $AttemptPointer){
                throw 'FIXTURE_POINTER_ORDER'}
            $Fixture.events.Add('POINTER');$Fixture.records[$Path]=$Value}
        function Read-BootstrapFrozenIntent {param($Source,$CheckPath,$CheckHash)
            if($Fixture.records[$AttemptPointer].record -cne $script:RecordPath){throw 'FIXTURE_POINTER_MISSING'}
            $Fixture.events.Add('READBACK')}
        try {Save-BootstrapPreparedAttempt $Source @{} $CheckPath $ReviewPath;throw 'FIXTURE_CHANGED_COMPATIBILITY_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_COMPATIBILITY_CHANGED'){throw}}
        if($Fixture.records.Count){throw 'FIXTURE_ATTEMPT_BEFORE_CHECK'}
        $Fixture.events.Clear();$Fixture.changed=$false;$Fixture.sourceDrift=$true
        try {Save-BootstrapPreparedAttempt $Source @{} $CheckPath $ReviewPath;throw 'FIXTURE_CHANGED_SOURCE_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_CHECK_CHANGED'){throw}}
        if($Fixture.records.Count){throw 'FIXTURE_ATTEMPT_BEFORE_CHECK'}
        $Fixture.events.Clear();$Fixture.sourceDrift=$false
        Save-BootstrapPreparedAttempt $Source @{} $CheckPath $ReviewPath
        if(($Fixture.events -join ',') -cne 'GO,RECHECK,VERIFY,SAVE,POINTER,READBACK' -or
           $script:R -is [Collections.IDictionary] -or -not $script:R.PSObject.Properties['bootstrapOwnerGo']){
            throw 'FIXTURE_PREPARED_ORDER'
        }
        function Stop-BootstrapSourcePair {$Fixture.events.Add('STOP')}
        function Invoke-BootstrapFrozenPair {$Fixture.events.Add('BEGIN')}
        function Publish-BootstrapFrozenPhases {$Fixture.events.Add('PUBLISH');return 'APPLY_STOP'}
        function Seal-BootstrapFinalProfiles {$Fixture.events.Add('SEAL');return 'SEALED'}
        function Start-BootstrapReceiver {
            $Fixture.events.Add('RECEIVER')
            $script:R.runtime=[pscustomobject]@{registryProfileDigest='preliminary'}
            return [pscustomobject]@{profileDigest='final';generation='new'}
        }
        function Read-SuccessorPublication {return @{anchor='STAGED_TARGET_FROZEN'}}
        $Prepared=Invoke-BootstrapPreparedTransition
        if($Prepared.publication -cne 'STAGED_TARGET_FROZEN' -or $Prepared.material -cne 'SEALED' -or $Prepared.delivery.profileDigest -cne 'final' -or
           $script:R.runtime.registryProfileDigest -cne 'final' -or
           ($Fixture.events -join ',') -cne 'GO,RECHECK,VERIFY,SAVE,POINTER,READBACK,STOP,BEGIN,PUBLISH,SEAL,RECEIVER,SAVE'){
            throw 'FIXTURE_PREPARED_TRANSITION_ORDER'
        }
        # Exercise the actual ordinary Prepared writer and persisted JSON
        # type, then the same transition. No second paired begin/migration.
        $Fixture.events.Clear();$Fixture.records.Clear()
        $ReleaseBase=Split-Path $CheckPath -Parent
        $Source.runtime=@{runId='ordinary-fixture'}
        $ContextPath=Join-Path $ReleaseBase ('maintenance-'+$Source.runtime.runId+'.json')
        $StopPath=Join-Path $ReleaseBase 'apply-stop.json'
        $Auth=@{sourceRecordDigest=$Source.hash;attemptId=$Go.attemptId;targetGeneration=('e'*64)}
        $Context=@{intentDigest=('f'*64);intent=@{authorization=$Auth}}
        $Check.binding.ordinaryIntentDigest=$Context.intentDigest
        $Stop=@{checkedRecordDigest=('d'*64);sourceRecordDigest=$Source.hash}
        $Fixture.records[$ContextPath]=$Context
        $script:R=[ordered]@{phase='Prepared';activated=$false;probesPassed=$false;source=$Source
            runtime=[ordered]@{pilotId=''};sourceReceipt=$null}
        function Get-FileHash {param($LiteralPath,$Algorithm)
            if($LiteralPath -cnotin @($CheckPath,$ContextPath,$StopPath)){throw 'FIXTURE_CHECK_PATH'}
            return @{Hash=('d'*64)}}
        function Read-Host {param($Prompt)
            if($Prompt -cne ('Type APPLY SUCCESSOR '+('d'*64))){throw 'FIXTURE_ORDINARY_GO_PIN'}
            $Fixture.events.Add('GO');return ('APPLY SUCCESSOR '+('d'*64))}
        function Verify-Checked-Image {param($Source,$Report,[switch]$PrepareSuccessorStop)
            if(-not $PrepareSuccessorStop){throw 'FIXTURE_STOP_REQUIRED'}
            $Fixture.events.Add('VERIFY');return $Stop}
        function Save-SuccessorApplyStopIntent {param($Intent)
            if(-not (Same-Json $Stop $Intent)){throw 'FIXTURE_STOP_DRIFT'}
            $Fixture.events.Add('STOP_INTENT');$Fixture.records[$StopPath]=$Intent;return $StopPath}
        function Save {param([switch]$FlushToDisk)
            if(-not $FlushToDisk -or -not (Same-Json $script:R.sourceReceipt $Receipt) -or
               $script:R.bootstrapOwnerGo.intentDigest -cne $Context.intentDigest){throw 'FIXTURE_ATTEMPT_NOT_DURABLE'}
            $Fixture.events.Add('SAVE')
            $Fixture.records[$script:RecordPath]=$script:R|ConvertTo-Json -Depth 30|ConvertFrom-Json}
        Save-OrdinaryPreparedAttempt $Source @{} $Stop
        if(-not $script:R.PSObject.Properties['ordinaryHandover']){throw 'FIXTURE_ORDINARY_RECORD_NOT_RELOADED'}
        $Prepared=Invoke-BootstrapPreparedTransition
        if($Prepared.delivery.profileDigest -cne 'final' -or
           ($Fixture.events -join ',') -cne 'GO,VERIFY,STOP_INTENT,SAVE,POINTER,READBACK,STOP,SEAL,RECEIVER,SAVE'){
            throw 'FIXTURE_ORDINARY_PREPARED_TRANSITION_ORDER'
        }

    } finally {$script:R=$PreviousR;$script:RecordPath=$PreviousPath;$script:BootstrapPair=$PreviousPair}
    Write-Host 'FORTIS_SUCCESSOR_BOOTSTRAP_PREPARED_ATTEMPT_SELFTEST_PASS'
}

function Assert-BootstrapPhasePublicationSelfTest {
    $Source=@{hash=('a'*64)}
    $Records=@([pscustomobject]@{phase='NORMAL';sequence=0;previousDigest=$null})
    $Digests=@(0..5|ForEach-Object{('{0:x64}' -f ($_+1))})
    $Names=@('DRAINING','FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP','STAGED_TARGET_FROZEN')
    for($I=1;$I -le 5;$I++){
        $Records+=@([pscustomobject]@{phase=$Names[$I-1];sequence=$I;previousDigest=$Digests[$I-1]})
    }
    $Result=[pscustomobject]@{registryDigest=('b'*64);phasePlan=[pscustomobject]@{records=@($Records[1..5])}}
    $Attempt=[pscustomobject]@{bootstrapBegin=$Result}
    $Fixture=@{anchor=[pscustomobject]@{schema='fortis-successor-maintenance-publication-v2';state='Committed'
        record=$Records[0];digest=$Digests[0];registryDigest=$null};writes=0;readbacks=0;reconciles=0;failAt=2;changed=$false}
    function Read-BootstrapFrozenIntent {return @{attempt=$Attempt}}
    function Assert-Release-Production {}
    function Assert-BootstrapNoReceiver {}
    function Invoke-BootstrapFrozenPair {param($Source,$CheckPath,$CheckHash,[switch]$Readback)
        if(-not $Readback){throw 'FIXTURE_PHASE_WRITER_REPLAY'}
        $Fixture.readbacks++
        if($Fixture.changed){return @{registryDigest=('0'*64)}}
        return $Result}
    function Read-BootstrapSeedSource {return @{record=$Records[0];digest=$Digests[0]}}
    function Read-SuccessorPublication {return @{anchor=$Fixture.anchor}}
    function Publish-SuccessorInterlock {param($Source,$Next,$RegistryDigest)
        if($RegistryDigest -cne $Result.registryDigest -or $Next.sequence -gt 4){throw 'FIXTURE_PHASE_PIN'}
        if($Fixture.anchor.state -ceq 'Committed' -and (Same-Json $Fixture.anchor.record $Next)){
            $Fixture.reconciles++;return $Fixture.anchor.digest}
        if($Next.previousDigest -cne $Fixture.anchor.digest){throw 'FIXTURE_PHASE_ORDER'}
        $Previous=$Fixture.anchor.record
        if($Next.sequence -eq $Fixture.failAt){
            $Fixture.anchor.state='Pending'
            $Fixture.anchor|Add-Member -NotePropertyName next -NotePropertyValue $Next -Force
            $Fixture.anchor|Add-Member -NotePropertyName nextRegistryDigest -NotePropertyValue $RegistryDigest -Force
            $Fixture.failAt=0
            throw 'FIXTURE_PHASE_ACK_LOST'
        }
        if($Fixture.anchor.state -ceq 'Pending' -and -not (Same-Json $Fixture.anchor.next $Next)){throw 'FIXTURE_PHASE_PENDING_CHANGED'}
        $Fixture.anchor=[pscustomobject]@{schema='fortis-successor-maintenance-publication-v2';state='Committed'
            record=$Next;digest=$Digests[$Next.sequence];registryDigest=$RegistryDigest;previous=$Previous}
        $Fixture.writes++
        return $Fixture.anchor.digest
    }
    try {$null=Publish-BootstrapFrozenPhases $Source fixture ('c'*64);throw 'FIXTURE_PHASE_ACK_ACCEPTED'}
    catch {if($_.Exception.Message -cne 'FIXTURE_PHASE_ACK_LOST'){throw}}
    if($Fixture.writes -ne 1 -or $Fixture.anchor.state -cne 'Pending'){throw 'FIXTURE_PHASE_PENDING_LOST'}
    $Fixture.anchor.nextRegistryDigest='0'*64
    try {$null=Publish-BootstrapFrozenPhases $Source fixture ('c'*64);throw 'FIXTURE_PHASE_CHANGED_ACCEPTED'}
    catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_PHASE_CHANGED'){throw}}
    $Fixture.anchor.nextRegistryDigest=$Result.registryDigest
    $Actual=Publish-BootstrapFrozenPhases $Source fixture ('c'*64)
    $Again=Publish-BootstrapFrozenPhases $Source fixture ('c'*64)
    if($Fixture.writes -ne 4 -or $Fixture.reconciles -ne 1 -or
       $Actual.record.phase -cne 'APPLY_STOP' -or -not (Same-Json $Actual $Again)){throw 'FIXTURE_PHASE_SUFFIX'}
    $Fixture.changed=$true
    try {$null=Publish-BootstrapFrozenPhases $Source fixture ('c'*64);throw 'FIXTURE_PHASE_READBACK_ACCEPTED'}
    catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_PAIR_CHANGED'){throw}}
    if($Fixture.writes -ne 4){throw 'FIXTURE_PHASE_EARLY_EFFECT'}
    Write-Host 'FORTIS_SUCCESSOR_BOOTSTRAP_PHASE_PUBLICATION_SELFTEST_PASS'
}

function Assert-BootstrapPhysicalPairSelfTest {
    $PreviousR=$script:R;$PreviousPath=$script:RecordPath
    try {
        $script:RecordPath='fixture-attempt'
        $Gid='a'*64;$Rid='b'*64;$ImageId='sha256:'+('c'*64)
        $Source=@{path='fixture-source';runtime=@{pilotId=$Gid;registryReleaseNonce='fixture-old';stateVolume='old-state'}}
        $Original=@{targetRegistryId=$Rid;targetRegistryProfile='profile';targetRegistryImage=$ImageId
            checkpoints=@{target=@{sourceRevision=3}}}
        $script:R=[pscustomobject]@{phase='Prepared';source=$Source;bootstrapCheckRecord='fixture-check';bootstrapCheckHash=('d'*64)
            runtime=@{pilotId='';registryReleaseNonce='11111111-1111-4111-8111-111111111111';pilotName='fixture-candidate';stateVolume='new-state'}
            activated=$false;probesPassed=$false}
        $Fixture=@{rows=@{};effects=[Collections.Generic.List[string]]::new();saves=0;freeze=0;target=$false
            failAt='';failBefore=$false;readback=$true;sourceDrift=$false}
        foreach($Id in @($Gid,$Rid)){
            $Fixture.rows[$Id]=[pscustomobject]@{Id=$Id;Image=$ImageId;State=[pscustomobject]@{Status='running'}
                HostConfig=[pscustomobject]@{RestartPolicy=[pscustomobject]@{Name='unless-stopped';MaximumRetryCount=0}}}
        }
        function Container {param($Id)
            if(-not $Fixture.rows.ContainsKey($Id)){throw 'BOOTSTRAP_PHYSICAL_SELFTEST_ID'}
            # Docker inspect returns an independent snapshot, not an alias.
            return ($Fixture.rows[$Id]|ConvertTo-Json -Depth 10|ConvertFrom-Json)}
        function Read-BootstrapFrozenIntent {param($Source,$CheckPath,$CheckHash)
            if($CheckPath -cne 'fixture-check' -or $CheckHash -cne ('d'*64)){throw 'BOOTSTRAP_PHYSICAL_SELFTEST_PIN'}
            return @{attempt=$script:R}}
        function Assert-Release-Production {}
        function Assert-CorrectiveTargetHolders {param($Nonce,$Allowed)
            if($Fixture.target){throw 'FIXTURE_TARGET_PRESENT'}}
        function Assert-ReleaseVolumeHolders {param($Volumes,$Allowed,$ErrorCode)
            if($Fixture.target){throw $ErrorCode}}
        function Assert-CorrectiveGateAbsent {param($P) if($Fixture.target){throw 'FIXTURE_GATE_PRESENT'}}
        function Read-BootstrapGatewayCandidate {}
        function Read-BootstrapSeedSource {param($Source,[switch]$Transition)
            if(-not $Transition){
                foreach($Row in $Fixture.rows.Values){
                    if($Row.State.Status -cne 'exited' -or $Row.HostConfig.RestartPolicy.Name -cne 'no'){
                        throw 'BOOTSTRAP_PHYSICAL_SELFTEST_NOT_FROZEN'
                    }
                }
            }}
        function Assert-BootstrapFrozenCheck {param($Source,$CheckPath,$CheckHash)
            if($Fixture.sourceDrift){throw 'FIXTURE_SOURCE_DRIFT'}
            $Fixture.freeze++}
        function Read-Private {param($Path)
            if($Path -ceq 'fixture-source'){return @{correctivePair=$Original}}
            if($Path -ceq 'fixture-attempt'){return $script:R}
            throw 'BOOTSTRAP_PHYSICAL_SELFTEST_PATH'}
        function Step {param($Name)}
        function Docker-Text {param($Arguments)
            if(($Arguments -join ' ') -ceq 'ps -a --format {{.Names}}'){return ''}
            $Id=$Arguments[-1];$Row=$Fixture.rows[$Id]
            $Role=if($Id -ceq $Gid){'g'}else{'r'}
            $Effect=$Role+':'+$Arguments[0]+$(if($Arguments[0] -ceq 'update'){':'+$Arguments[1]}else{''})
            $Fixture.effects.Add($Effect)
            if($Effect -ceq $Fixture.failAt -and $Fixture.failBefore){throw 'FIXTURE_BEFORE_EFFECT'}
            if($Arguments[0] -ceq 'update'){$Row.HostConfig.RestartPolicy.Name=$Arguments[1].Substring(10)}
            elseif($Arguments[0] -ceq 'stop'){
                if($Row.HostConfig.RestartPolicy.Name -cne 'no'){throw 'FIXTURE_RESTART_ENABLED'}
                if($Role -ceq 'r' -and $Fixture.rows[$Gid].State.Status -cne 'exited'){throw 'FIXTURE_STOP_ORDER'}
                $Row.State.Status='exited'
            } elseif($Arguments[0] -ceq 'start'){
                if($Role -ceq 'g' -and $Fixture.rows[$Rid].State.Status -cne 'running'){throw 'FIXTURE_START_ORDER'}
                $Row.State.Status='running'
            } else {throw 'FIXTURE_UNEXPECTED_EFFECT'}
            if($Effect -ceq $Fixture.failAt){throw 'FIXTURE_ACK_LOST'}
        }
        function Read-CorrectiveCheckpoint {param($Id,$Nonce,$Profile,$Image,$Revision,$Commit,[switch]$Frozen)
            if($Id -cne $Rid -or $Revision -ne 3 -or $Frozen -ne ($Fixture.rows[$Rid].State.Status -ceq 'exited')){
                throw 'FIXTURE_REGISTRY_READBACK_ORDER'
            }
            return $Original.checkpoints.target}
        function Wait-CorrectiveRegistryListener {param($Id)
            if($Id -cne $Rid -or $Fixture.rows[$Rid].State.Status -cne 'running'){throw 'FIXTURE_REGISTRY_NOT_RUNNING'}}
        function Admit {param($C,$P,[switch]$AllowUnhealthy,[switch]$BootstrapRetained)
            if(-not $BootstrapRetained -or $Fixture.rows[$Rid].State.Status -cne 'running'){throw 'FIXTURE_PEER_UNAVAILABLE'}}
        function Wait-Healthy {param($Id)
            if($Id -cne $Gid -or $Fixture.rows[$Gid].State.Status -cne 'running'){throw 'FIXTURE_GATEWAY_NOT_RUNNING'}}
        function Admit-Source {param($C,$Source)
            foreach($Row in $Fixture.rows.Values){
                if($Row.State.Status -cne 'running' -or $Row.HostConfig.RestartPolicy.Name -cne 'unless-stopped'){
                    throw 'FIXTURE_RETURN_INCOMPLETE'
                }
            }}
        function Save {param([switch]$FlushToDisk)
            if(-not $FlushToDisk -or $script:R.phase -cne 'Returned'){throw 'FIXTURE_RETURN_NOT_DURABLE'}
            $Fixture.saves++}
        # Failure before Registry stop leaves a partial pair. Return must
        # start only Gateway and restore both original restart policies.
        $Fixture.failAt='r:stop';$Fixture.failBefore=$true
        try {Stop-BootstrapSourcePair $Source fixture-check ('d'*64);throw 'FIXTURE_FAILED_STOP_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_EFFECT_UNCONFIRMED Stop'){throw}}
        if($Fixture.freeze -ne 0){throw 'FIXTURE_FROZEN_CHECK_BEFORE_STOP'}
        $Fixture.failAt='g:start';$Fixture.failBefore=$false
        Return-BootstrapPreparedPair
        if($script:R.phase -cne 'Returned' -or $Fixture.saves -ne 1 -or
           ($Fixture.effects -join ',') -cne 'g:update:--restart=no,g:stop,r:update:--restart=no,r:stop,r:update:--restart=unless-stopped,g:start,g:update:--restart=unless-stopped'){
            throw 'FIXTURE_PARTIAL_RETURN_ORDER'
        }
        $script:R.phase='Prepared';$Fixture.effects.Clear();$Fixture.failAt='g:stop'
        Stop-BootstrapSourcePair $Source fixture-check ('d'*64)
        Stop-BootstrapSourcePair $Source fixture-check ('d'*64)
        if($Fixture.freeze -ne 2 -or $Fixture.effects.Count -ne 4){throw 'FIXTURE_DUPLICATE_STOP'}
        $Fixture.target=$true
        try {Return-BootstrapPreparedPair;throw 'FIXTURE_TARGET_RETURN_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'FIXTURE_TARGET_PRESENT'){throw}}
        if($Fixture.effects.Count -ne 4 -or $Fixture.saves -ne 1){throw 'FIXTURE_EFFECT_WITH_TARGET'}
        $Fixture.target=$false;$Fixture.failAt='r:start'
        Return-BootstrapPreparedPair
        if(($Fixture.effects -join ',') -cne 'g:update:--restart=no,g:stop,r:update:--restart=no,r:stop,r:start,r:update:--restart=unless-stopped,g:start,g:update:--restart=unless-stopped' -or
           $Fixture.saves -ne 2){throw 'FIXTURE_FULL_RETURN_ORDER'}
        # A changed frozen receipt must deny seed, not strand the original
        # source when no target receiver exists.
        $script:R.phase='Prepared';$Fixture.effects.Clear();$Fixture.failAt='';$Fixture.sourceDrift=$true
        try {Stop-BootstrapSourcePair $Source fixture-check ('d'*64);throw 'FIXTURE_DRIFT_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'FIXTURE_SOURCE_DRIFT'){throw}}
        Return-BootstrapPreparedPair
        if($Fixture.saves -ne 3){throw 'FIXTURE_DRIFT_RETURN'}
        $Effects=$Fixture.effects.Count
        Return-BootstrapPreparedPair
        if($Fixture.saves -ne 3 -or $Fixture.effects.Count -ne $Effects){throw 'FIXTURE_DUPLICATE_RETURN'}
        # The exact stopped Gateway from a recovered Check is not started
        # for Apply. Lost publication ACK must be recovered before any stop.
        $script:R.phase='Prepared';$Fixture.effects.Clear();$Fixture.sourceDrift=$false
        $Fixture.rows[$Gid].State.Status='exited';$Fixture.rows[$Gid].HostConfig.RestartPolicy.Name='no'
        $Fixture.rows[$Rid].State.Status='running';$Fixture.rows[$Rid].HostConfig.RestartPolicy.Name='no'
        $Fixture.failAt='r:stop';$Fixture.failBefore=$false
        $Checked=@{phase='CHECK_SEALED'};$Next=@{phase='APPLY_STOP'}
        $Stop=@{next=$Next;sourceRecordDigest=('a'*64);checkedRecordDigest=('d'*64);targetImageId=$ImageId}
        $Receipt=@{sha256=@{fixture=('e'*64)}}
        $OrdinaryIntent=@{attempt=$script:R;ordinary=@{stop=$Stop;check=@{};begin=@{registryDigest=('f'*64)}}
            check=@{sourceReceipt=$Receipt;maintenanceTransitions=@{}};context=@{payload=@{}}}
        $Fixture.anchor=@{state='Committed';record=$Checked;digest=('1'*64)}
        $Fixture.loseStopPublish=$true;$Fixture.stopPublishes=0
        function Read-BootstrapFrozenIntent {return $OrdinaryIntent}
        function Assert-BootstrapNoReceiver {if($Fixture.target){throw 'FIXTURE_TARGET_PRESENT'}}
        function Read-OrdinarySuccessorSource {param($Source,[switch]$PublicationRecovery)
            @{gateway=(Container $Gid);registry=(Container $Rid)}}
        function Read-SuccessorPublication {return @{anchor=$Fixture.anchor}}
        function Publish-SuccessorInterlock {param($Source,$Next,$RegistryDigest)
            if($RegistryDigest -cne ('f'*64)){throw 'FIXTURE_WRONG_REGISTRY'}
            if($Fixture.anchor.record.phase -ceq 'CHECK_SEALED'){
                $Fixture.stopPublishes++;$Fixture.anchor.record=$Next;$Fixture.anchor.digest='2'*64
                if($Fixture.loseStopPublish){$Fixture.loseStopPublish=$false;throw 'FIXTURE_STOP_PUBLICATION_ACK_LOST'}
            }
            return $Fixture.anchor.digest}
        function New-SuccessorApplyVerifyPayload {return @{}}
        function Read-SuccessorFreezeSeal {param($Payload,$Volume,$Mount)
            if($Fixture.anchor.record.phase -ceq 'APPLY_STOP' -and (-not $Payload.stoppedIntent -or
                $Fixture.rows[$Rid].State.Status -cne 'exited')){throw 'FIXTURE_STOP_PROOF_EARLY'}
            return @{sourceReceipt=$Receipt;stopIntent=$Stop}}
        function Assert-PairedFrozenSource {param($Intent,$Source)
            foreach($Row in $Fixture.rows.Values){
                if($Row.State.Status -cne 'exited' -or $Row.HostConfig.RestartPolicy.Name -cne 'no'){throw 'FIXTURE_NOT_FROZEN'}
            }}
        try {Stop-BootstrapSourcePair $Source fixture-check ('d'*64);throw 'FIXTURE_STOP_PUBLICATION_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'FIXTURE_STOP_PUBLICATION_ACK_LOST'){throw}}
        if($Fixture.effects.Count){throw 'FIXTURE_STOP_BEFORE_PUBLICATION'}
        Stop-BootstrapSourcePair $Source fixture-check ('d'*64)
        Stop-BootstrapSourcePair $Source fixture-check ('d'*64)
        if($Fixture.stopPublishes -ne 1 -or ($Fixture.effects -join ',') -cne 'r:stop'){
            throw 'FIXTURE_ORDINARY_STOP_REENTRY'
        }

    } finally {$script:R=$PreviousR;$script:RecordPath=$PreviousPath}
    Write-Host 'FORTIS_SUCCESSOR_BOOTSTRAP_PHYSICAL_PAIR_SELFTEST_PASS'
}

function Assert-BootstrapFrozenPairSelfTest {
    # Exercise the actual internal controller bridge without a host effect.
    $PreviousPath=$script:RecordPath;$PreviousR=$script:R;$PreviousPair=$script:BootstrapPair
    try {
        $script:RecordPath='fixture-attempt'
        $AttemptPointer='fixture-pointer'
        $CheckPath='fixture-check';$CheckHash='a'*64
        $Source=@{path='fixture-source';hash=('b'*64)}
        $Nonce='11111111-1111-4111-8111-111111111111'
        $Pair=[pscustomobject]@{registryImage=('sha256:'+('c'*64));registryProfileSha256=('d'*64)
            reviewSha256=('e'*64);evidenceSha256=('f'*64);compatibilityDigest=('1'*64)
            checked=[pscustomobject]@{artifacts=[pscustomobject]@{gateway=('2'*64);registry=('c'*64)}
                gateway=[pscustomobject]@{releaseNonce=$Nonce;profileDigest=('3'*64)}
                registry=[pscustomobject]@{binding=[pscustomobject]@{generation=('4'*64)}
                    review=[pscustomobject]@{ownerReviewProofDigest=('5'*64);reviewContentDigest=('0'*64)}}}}
        $script:BootstrapPair=$Pair
        $Check=[pscustomobject]@{schema='fortis-extension-image-check-v1';phase='Ready'
            binding=[pscustomobject]@{sourceRecord=$Source.path;sourceHash=$Source.hash;sourceSha=('6'*40);bootstrapPair=$Pair
                bootstrapReviewProofRecord='fixture-review'}
            sourceReceipt=[pscustomobject]@{sha256=[pscustomobject]@{fixture=('7'*64)};summary=[pscustomobject]@{}}}
        $Fixture=@{records=@{};answer='WRONG';seeds=0;calls=0;effects=0;saves=0;result=$null;loseAck=$true}
        $Fixture.records[$CheckPath]=$Check
        $Fixture.records['fixture-review']=[pscustomobject]@{schema='fortis-registry-bootstrap-review-v1'
            decision='APPROVE_BOOTSTRAP_MERGE';reviewContentDigest=('0'*64);reviewedAt=100}
        $Fixture.records[$AttemptPointer]=[pscustomobject]@{record=$script:RecordPath}
        function Read-Private {param($Path) return $Fixture.records[$Path]}
        function Get-FileHash {param($LiteralPath,$Algorithm)
            if($LiteralPath -ceq $CheckPath){return @{Hash=$CheckHash}}
            if($LiteralPath -ceq $Source.path){return @{Hash=$Source.hash}}
            if($LiteralPath -ceq 'fixture-review'){return @{Hash=('5'*64)}}
            throw 'BOOTSTRAP_BRIDGE_SELFTEST_PATH'}
        function Read-Host {param($Prompt) return $Fixture.answer}
        function Save {param([switch]$FlushToDisk)
            if(-not $FlushToDisk -or $script:RecordPath -cne 'fixture-attempt'){throw 'BOOTSTRAP_BRIDGE_SELFTEST_FLUSH'}
            $Fixture.records[$script:RecordPath]=$script:R;$Fixture.saves++}
        function Assert-CorrectiveTargetHolders {param($Nonce,$Allowed)
            if($Nonce -cne '11111111-1111-4111-8111-111111111111' -or @($Allowed).Count){throw 'BOOTSTRAP_BRIDGE_SELFTEST_HOLDER'}}
        function Assert-Volume {param($Volume) if(-not $Volume){throw 'BOOTSTRAP_BRIDGE_SELFTEST_VOLUME'}}
        function Assert-ReleaseVolumeHolders {param($Volumes,$Allowed,$ErrorCode)
            if(@($Volumes).Count -ne 2 -or @($Allowed).Count){throw 'BOOTSTRAP_BRIDGE_SELFTEST_HOLDER'}}
        function Read-BootstrapSeedSource {param($Source) return @{digest=('8'*64);record=@{phase='NORMAL'}}}
        function Assert-BootstrapFrozenCheck {}
        function Initialize-SuccessorBootstrapInterlock {param($Source,$CheckPath,$CheckHash)
            $Fixture.seeds++;return @{digest=('8'*64)}}
        function Docker-Json {param($Arguments)
            if(($Arguments -join ' ') -cne ('image inspect '+$Pair.registryImage)){throw 'BOOTSTRAP_BRIDGE_SELFTEST_IMAGE'}
            return [pscustomobject]@{Id=$Pair.registryImage;Config=[pscustomobject]@{
                User='20002:20002';Entrypoint=@();Labels=[pscustomobject]@{'org.opencontainers.image.revision'=('6'*40)}}}}
        function Python-Code {param($Arguments,$Code,$InputText)
            $Fixture.calls++
            $P=ConvertFrom-Json $InputText
            if($Arguments -cnotcontains '20002:20002' -or $Arguments -cnotcontains $Pair.registryImage -or
               @($Arguments|Where-Object{$_ -match 'target=/run/fortis-registry-read'}).Count -or
               $P.profile -cne $Pair.registryProfileSha256 -or $P.review -cne $Pair.reviewSha256 -or
               $P.evidence -cne $Pair.evidenceSha256 -or $P.seed -cne ('8'*64) -or
               -not (Same-Json $P.go $Fixture.records[$script:RecordPath].bootstrapOwnerGo) -or
               -not (Same-Json $P.sourceReceipt $Check.sourceReceipt)){
                throw 'BOOTSTRAP_BRIDGE_SELFTEST_BINDING'
            }
            $StateArg=@($Arguments|Where-Object{$_ -match 'target=/run/fortis-registry-state'})
            if($StateArg.Count -ne 1 -or ([bool]($StateArg[0] -match ',readonly,') -ne $P.readback)){
                throw 'BOOTSTRAP_BRIDGE_SELFTEST_READBACK_MODE'
            }
            if($null -eq $Fixture.result){
                if($P.readback){throw 'BOOTSTRAP_BRIDGE_SELFTEST_READBACK_BEFORE_EFFECT'}
                $Fixture.effects++
                $Records=@(foreach($Phase in @('DRAINING','FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP','STAGED_TARGET_FROZEN')){
                    [ordered]@{phase=$Phase;previousDigest=('8'*64);generation=$P.go.targetGeneration}})
                $Fixture.result=[ordered]@{result='BOOTSTRAP_PAIR_BEGIN_ACCOUNTED_ONLY';hostAccepted=$false;admissionAllowed=$false
                    pair=[ordered]@{attemptId=$P.go.attemptId;compatibilityReadbackDigest=$P.go.compatibilityDigest}
                    receipts=@('r','g');holdSnapshot=[ordered]@{holds=@('r','g')};registryDigest=('9'*64)
                    phasePlan=[ordered]@{proofKind='BOOTSTRAP_PHYSICAL_FREEZE';records=$Records;registryDigest=('9'*64)
                        handoff=[ordered]@{attemptId=$P.go.attemptId;registryDigest=('9'*64)}}}
            }
            if($Fixture.loseAck){$Fixture.loseAck=$false;throw 'BOOTSTRAP_BRIDGE_SELFTEST_ACK_LOST'}
            return (ConvertTo-Json -Compress -Depth 20 $Fixture.result)
        }
        try {$null=New-BootstrapOwnerGo $Source $CheckPath $CheckHash 'fixture-review';throw 'BOOTSTRAP_BRIDGE_SELFTEST_GO_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_OWNER_GO_REQUIRED'){throw}}
        $Fixture.answer='APPLY BOOTSTRAP '+$CheckHash
        $Fixture.records['fixture-review'].reviewContentDigest='9'*64
        try {$null=New-BootstrapOwnerGo $Source $CheckPath $CheckHash 'fixture-review';throw 'BOOTSTRAP_BRIDGE_SELFTEST_REVIEW_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_OWNER_REVIEW_CHANGED'){throw}}
        $Fixture.records['fixture-review'].reviewContentDigest='0'*64
        $Go=New-BootstrapOwnerGo $Source $CheckPath $CheckHash 'fixture-review'
        $Attempt=[pscustomobject]@{schema='fortis-extension-release-v1';phase='Prepared';activated=$false;probesPassed=$false
            bootstrapCheckRecord=$CheckPath;bootstrapCheckHash=$CheckHash;bootstrapOwnerGo=$Go;bootstrapReviewProofRecord='fixture-review';source=$Source
            runtime=[pscustomobject]@{image=('sha256:'+('2'*64));registryReleaseNonce=$Nonce;registryProfileDigest=('3'*64)}
            sourceReceipt=$Check.sourceReceipt}
        $Fixture.records[$script:RecordPath]=$Attempt
        $Go.reviewProofDigest='0'*64
        try {$null=Invoke-BootstrapFrozenPair $Source $CheckPath $CheckHash;throw 'BOOTSTRAP_BRIDGE_SELFTEST_WRONG_GO_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_OWNER_GO_CHANGED'){throw}}
        if($Fixture.seeds -ne 0 -or $Fixture.calls -ne 0){throw 'BOOTSTRAP_BRIDGE_SELFTEST_EARLY_EFFECT'}
        $Go.reviewProofDigest='5'*64
        # First call loses the writer ACK, but reads back original receipts
        # through a RO helper in the same intent. Re-entry is also RO.
        $Actual=Invoke-BootstrapFrozenPair $Source $CheckPath $CheckHash
        $Again=Invoke-BootstrapFrozenPair $Source $CheckPath $CheckHash
        if($Fixture.effects -ne 1 -or $Fixture.calls -ne 3 -or $Fixture.saves -ne 1 -or
           -not (Same-Json $Actual $Again) -or -not (Same-Json $Actual $Fixture.records[$script:RecordPath].bootstrapBegin)){
            throw 'BOOTSTRAP_BRIDGE_SELFTEST_RECOVERY'
        }
        $Attempt.phase='Created'
        try {$null=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash -Runtime;throw 'FIXTURE_RUNTIME_UNBOUND_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'){throw}}
        $Delivery=[pscustomobject]@{profileDigest=('7'*64);generation=$Go.targetGeneration}
        $Attempt|Add-Member -NotePropertyName bootstrapMaterials -NotePropertyValue @{gatewayProfileDigest=$Delivery.profileDigest}
        $Attempt|Add-Member -NotePropertyName bootstrapDelivery -NotePropertyValue $Delivery
        $Attempt.runtime|Add-Member -NotePropertyName registryDelivery -NotePropertyValue $Delivery
        $Attempt.runtime|Add-Member -NotePropertyName maintenanceGeneration -NotePropertyValue $Go.targetGeneration
        $Attempt.runtime.registryProfileDigest=$Delivery.profileDigest
        $null=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash -Runtime
        $Attempt.runtime.registryProfileDigest='0'*64
        try {$null=Read-BootstrapFrozenIntent $Source $CheckPath $CheckHash -Runtime;throw 'FIXTURE_WRONG_RUNTIME_PROFILE_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'){throw}}
    } finally {$script:RecordPath=$PreviousPath;$script:R=$PreviousR;$script:BootstrapPair=$PreviousPair}
    Write-Host 'FORTIS_SUCCESSOR_BOOTSTRAP_FROZEN_PAIR_SELFTEST_PASS'
}

function Assert-SuccessorBootstrapSeedSelfTest {
    $ReleaseBase=Join-Path ([IO.Path]::GetTempPath()) 'fortis-seed-fixture'
    $Source=@{hash=('a'*64);runtime=@{runId=('b'*32)}}
    $Old=[pscustomobject]@{digest=('c'*64);record=[pscustomobject]@{
        phase='NORMAL';sequence=0;generation=('d'*64);registryInstanceId='fixture';scopeDigest=('e'*64)}}
    $Fixture=@{record=$null;position='EMPTY';projection=$null;saves=0;seeds=0;commits=0;reads=0;proofs=0;proofAllowed=$false}
    function Read-BootstrapSeedSource {param($Source) $Fixture.reads++;return $Old}
    function Assert-BootstrapFrozenCheck {
        param($Source,$CheckPath,$CheckHash)
        if(-not $Fixture.proofAllowed){throw 'SEED_SELFTEST_FROZEN_CHECK_CHANGED'}
        if($CheckPath -cne 'fixture' -or $CheckHash -cne ('a'*64)){throw 'SEED_SELFTEST_CHECK_PIN'}
        $Fixture.proofs++
    }
    function Test-Path {param($LiteralPath) return ($null -ne $Fixture.record)}
    function Read-Private {param($Path) return $Fixture.record}
    function Write-Private {
        param($Path,$Value,[switch]$FlushToDisk)
        if(-not $FlushToDisk){throw 'SEED_SELFTEST_FLUSH_REQUIRED'}
        $Fixture.record=$Value;$Fixture.saves++
    }
    function State-Helper {
        param($Payload,$Mounts,[switch]$Root)
        if(-not $Root -or $Mounts.Count -ne 6 -or $Payload.digest -cne $Old.digest -or
           -not (Same-Json $Payload.record $Old.record)){throw 'SEED_SELFTEST_BINDING'}
        if($Payload.mode -ceq 'seed'){
            if($Fixture.record.state -cne 'Pending'){throw 'SEED_SELFTEST_INTENT_REQUIRED'}
            $Fixture.seeds++;$Fixture.position='SEEDED'
            $Fixture.projection=[pscustomobject]@{schemaVersion=1;state='Pending';instanceId=$Old.record.registryInstanceId
                scopeDigest=$Old.record.scopeDigest;sequence=0;generation=$Old.record.generation
                phase='NORMAL';interlockDigest=$Old.digest;registryDigest=$null}
            throw 'SEED_SELFTEST_SEED_ACK_LOST'
        }
        if($Payload.mode -ceq 'commit'){
            if($Fixture.record.state -cne 'Committed'){throw 'SEED_SELFTEST_HOST_COMMIT_REQUIRED'}
            if($Fixture.projection.state -ceq 'Pending'){
                $Fixture.projection.state='Committed';$Fixture.commits++;throw 'SEED_SELFTEST_COMMIT_ACK_LOST'
            }
        }
        return [pscustomobject]@{position=$Fixture.position;digest=$Old.digest;latest=$Fixture.projection}
    }
    try {$null=Initialize-SuccessorBootstrapInterlock $Source fixture ('a'*64);throw 'SEED_SELFTEST_FROZEN_CHECK_ACCEPTED'}
    catch {if($_.Exception.Message -cne 'SEED_SELFTEST_FROZEN_CHECK_CHANGED'){throw}}
    if($Fixture.saves -ne 0 -or $Fixture.seeds -ne 0){throw 'SEED_SELFTEST_EFFECT_BEFORE_CHECK'}
    $Fixture.proofAllowed=$true
    try {$null=Initialize-SuccessorBootstrapInterlock $Source fixture ('a'*64);throw 'SEED_SELFTEST_SEED_UNCONFIRMED'}
    catch {if($_.Exception.Message -cne 'SEED_SELFTEST_SEED_ACK_LOST'){throw}}
    if($Fixture.record.state -cne 'Pending'){throw 'SEED_SELFTEST_PENDING_LOST'}
    try {$null=Initialize-SuccessorBootstrapInterlock $Source fixture ('a'*64);throw 'SEED_SELFTEST_COMMIT_UNCONFIRMED'}
    catch {if($_.Exception.Message -cne 'SEED_SELFTEST_COMMIT_ACK_LOST'){throw}}
    $Final=Initialize-SuccessorBootstrapInterlock $Source fixture ('a'*64)
    if($Final.state -cne 'Committed' -or $Fixture.saves -ne 2 -or $Fixture.seeds -ne 1 -or
       $Fixture.commits -ne 1 -or $Fixture.reads -lt 3){throw 'SEED_SELFTEST_READBACK'}
    $Fixture.record=$null
    try {$null=Initialize-SuccessorBootstrapInterlock $Source fixture ('a'*64);throw 'SEED_SELFTEST_UNOWNED_ACCEPTED'}
    catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_SEED_UNOWNED_STATE'){throw}}
    Write-Host 'FORTIS_SUCCESSOR_BOOTSTRAP_SEED_SELFTEST_PASS'
}

function Test-SuccessorLatestDelivery {
    param($Delivery)
    if($null -eq $Delivery){return $false}
    if($Delivery -is [Collections.IDictionary]){
        if(-not $Delivery.Contains('latestPin')){return $false}
        $Value=$Delivery['latestPin']
    } else {
        $Field=$Delivery.PSObject.Properties['latestPin']
        if(-not $Field){return $false}
        $Value=$Field.Value
    }
    if($Value -isnot [bool] -or -not $Value){throw 'RELEASE_SUCCESSOR_LATEST_PIN_INVALID'}
    return $true
}
function Read-SuccessorPublication {
    param($Source)
    if($Source.runtime.runId -cnotmatch '^[0-9a-f]{32}$' -or
       $Source.runtime.maintenanceGeneration -cnotmatch '^[0-9a-f]{64}$'){
        throw 'RELEASE_SUCCESSOR_PUBLICATION_SCOPE_INVALID'
    }
    # v2 uses a single host anchor across generations. Per-release
    # historical files must never be fallback authority for v2 receivers.
    $Delivery=if($Source.runtime -is [Collections.IDictionary]){$Source.runtime['registryDelivery']}
        else{$Field=$Source.runtime.PSObject.Properties['registryDelivery'];if($Field){$Field.Value}}
    $Latest=Test-SuccessorLatestDelivery $Delivery
    $Operational=Join-Path $ReleaseBase 'maintenance-publication-v2.json'
    if($Source.runtime.runId -ceq 'cd6d3d97350e4f5590d9c3e9ece69580'){$Latest=$true}
    $Path=if($Latest){$Operational}else{Join-Path $ReleaseBase ('maintenance-publication-'+$Source.runtime.runId+'.json')}
    $Anchor=Read-Private $Path
    $ExpectedSchema=if($Latest){'fortis-successor-maintenance-publication-v2'}else{'fortis-successor-maintenance-publication-v1'}
    if($Anchor.schema -cne $ExpectedSchema -or
       $Anchor.sourceRecordHash -cne $Source.hash -or
       $Anchor.state -cnotin @('Committed','Pending') -or
       $Anchor.digest -cnotmatch '^[0-9a-f]{64}$'){
        throw 'RELEASE_SUCCESSOR_PUBLICATION_SCOPE_INVALID'
    }
    if($Anchor.schema -ceq 'fortis-successor-maintenance-publication-v1'){
        if($Anchor.record.generation -cne $Source.runtime.maintenanceGeneration){throw 'RELEASE_SUCCESSOR_PUBLICATION_SCOPE_INVALID'}
    } else {
        if($Anchor.state -ceq 'Pending' -and -not $Anchor.PSObject.Properties['next']){
            throw 'RELEASE_SUCCESSOR_SEED_PENDING'
        }
        # The owner record remains bound to the exact source release until
        # protected promotion explicitly binds the target. No generation reset.
        $Attempt=$Anchor.record.attempt
        if($Anchor.record.generation -cne $Source.runtime.maintenanceGeneration -and
           ($null -eq $Attempt -or $Attempt.sourceGeneration -cne $Source.runtime.maintenanceGeneration -or
            $Anchor.record.generation -cne $Attempt.targetGeneration)){
            throw 'RELEASE_SUCCESSOR_PUBLICATION_SCOPE_INVALID'
        }
        if(($Anchor.record.phase -ceq 'NORMAL' -and $null -ne $Anchor.registryDigest) -or
           ($Anchor.record.phase -cne 'NORMAL' -and $Anchor.registryDigest -cnotmatch '^[0-9a-f]{64}$')){
            throw 'RELEASE_SUCCESSOR_PUBLICATION_SCOPE_INVALID'
        }
    }
    return @{path=$Path;anchor=$Anchor}
}
function Read-SuccessorRuntimePublication {
    param($Runtime)
    if(-not (Test-SuccessorLatestDelivery $Runtime.registryDelivery) -or
       $Runtime.runId -cnotmatch '^[0-9a-f]{32}$'){throw 'RELEASE_SUCCESSOR_PUBLICATION_SCOPE_INVALID'}
    $Path=Join-Path $ReleaseBase ($Runtime.runId+'\record.json')
    $Release=Read-Private $Path
    if($Release.schema -cne 'fortis-extension-release-v1' -or
       $Release.phase -cnotin @('Created','Staged','Complete') -or
       -not (Same-Json $Release.runtime.registryDelivery $Runtime.registryDelivery)){
        throw 'RELEASE_SUCCESSOR_PUBLICATION_SCOPE_INVALID'
    }
    foreach($Field in @('runId','pilotId','image','stateVolume','registryReleaseNonce',
                        'registryProfileDigest','maintenanceGeneration')){
        if($Release.runtime.$Field -cne $Runtime.$Field){throw 'RELEASE_SUCCESSOR_PUBLICATION_SCOPE_INVALID'}
    }
    $Hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    $Anchor=Read-Private (Join-Path $ReleaseBase 'maintenance-publication-v2.json')
    # During handover the original protected source owns the same anchor.
    # After rebinding it must name the exact current release. No other
    # release, older anchor, or mounted projection can substitute.
    if($Anchor.sourceRecordHash -ceq $Hash){
        $Owner=@{path=$Path;hash=$Hash;runtime=$Runtime}
    } elseif($Anchor.sourceRecordHash -ceq $Release.source.hash -and
             (Get-FileHash -LiteralPath $Release.source.path -Algorithm SHA256).Hash -ceq $Release.source.hash){
        $Owner=$Release.source
    } else {throw 'RELEASE_SUCCESSOR_PUBLICATION_SCOPE_INVALID'}
    $Current=(Read-SuccessorPublication $Owner).anchor
    if(-not (Same-Json $Current $Anchor) -or $Current.schema -cne 'fortis-successor-maintenance-publication-v2' -or
       $Current.state -cne 'Committed' -or $Current.record.generation -cne $Runtime.maintenanceGeneration -or
       $Current.record.phase -cnotin @('NORMAL','DRAINING','FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP',
            'STAGED_TARGET_FROZEN','BACKUP_FROZEN','PROMOTE_FROZEN','COMPLETION_PENDING','RECOVERY_HOLD')){
        throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
    }
    return $Current
}
function Assert-SuccessorRuntimeDelivery {
    param($Actual,$Retained,$Publication)
    if(-not (Test-SuccessorLatestDelivery $Actual) -or -not (Test-SuccessorLatestDelivery $Retained) -or
       $Actual.profileDigest -cne $Retained.profileDigest -or $Actual.companionDigest -cne $Retained.companionDigest -or
       $Actual.generation -cne $Retained.generation -or $Actual.generation -cne $Publication.record.generation -or
       $Actual.maintenancePhase -cne $Publication.record.phase -or
       $Actual.sourceDelivery.interlockDigest -cne $Publication.digest -or
       $Actual.registryCheckpoint.profileDigest -cne $Retained.registryCheckpoint.profileDigest -or
       ($Publication.record.phase -cne 'NORMAL' -and $Actual.registryCheckpoint.registryDigest -cne $Publication.registryDigest)){
        throw 'RELEASE_REGISTRY_SUCCESSOR_DELIVERY_CHANGED'
    }
    foreach($Field in @('device','inode','policyAuthorityDigest')){
        if($Actual.sourceDelivery.$Field -cne $Retained.sourceDelivery.$Field){
            throw 'RELEASE_REGISTRY_SUCCESSOR_DELIVERY_CHANGED'
        }
    }
}
function Assert-SuccessorRuntimePublicationSelfTest {
    $ReleaseBase=Join-Path ([IO.Path]::GetTempPath()) 'fortis-latest-anchor-fixture'
    $Old=@{path=(Join-Path $ReleaseBase 'old.json');hash=('a'*64);runtime=@{
        runId='cd6d3d97350e4f5590d9c3e9ece69580';maintenanceGeneration=('b'*64)}}
    $Runtime=@{runId=('c'*32);pilotId=('d'*64);image=('sha256:'+('e'*64));stateVolume='fixture'
        registryReleaseNonce='fixture';registryProfileDigest=('f'*64);maintenanceGeneration=('1'*64)
        registryDelivery=@{latestPin=$true}}
    $Path=Join-Path $ReleaseBase ($Runtime.runId+'\record.json')
    $Latest=Join-Path $ReleaseBase 'maintenance-publication-v2.json'
    $Release=@{schema='fortis-extension-release-v1';phase='Complete';runtime=$Runtime;source=$Old}
    $Anchor=@{schema='fortis-successor-maintenance-publication-v2';state='Committed';sourceRecordHash=$Old.hash
        digest=('2'*64);registryDigest=('3'*64);record=@{generation=$Runtime.maintenanceGeneration
            phase='BACKUP_FROZEN';attempt=@{sourceGeneration=$Old.runtime.maintenanceGeneration
                targetGeneration=$Runtime.maintenanceGeneration}}}
    $Fixture=@{records=@{};hashes=@{};legacyReads=0;latestPath=$Latest;releasePath=$Path}
    $Fixture.records[$Latest]=$Anchor;$Fixture.records[$Path]=$Release
    $Fixture.hashes[$Path]='4'*64;$Fixture.hashes[$Old.path]=$Old.hash
    function Read-Private {
        param($Path)
        if($Path -cne $Fixture.latestPath -and $Path -cne $Fixture.releasePath){
            $Fixture.legacyReads++;throw 'LATEST_SELFTEST_HISTORICAL_FALLBACK'
        }
        if(-not $Fixture.records.ContainsKey($Path)){throw 'LATEST_SELFTEST_ANCHOR_MISSING'}
        return $Fixture.records[$Path]
    }
    function Get-FileHash {param($LiteralPath,$Algorithm) return @{Hash=$Fixture.hashes[$LiteralPath]}}
    if(-not (Same-Json (Read-SuccessorRuntimePublication $Runtime) $Anchor)){throw 'LATEST_SELFTEST_SOURCE_ANCHOR'}
    $Anchor.sourceRecordHash=$Fixture.hashes[$Path]
    if(-not (Same-Json (Read-SuccessorRuntimePublication $Runtime) $Anchor)){throw 'LATEST_SELFTEST_REBOUND_ANCHOR'}
    $Anchor.sourceRecordHash='0'*64
    try {$null=Read-SuccessorRuntimePublication $Runtime;throw 'LATEST_SELFTEST_WRONG_OWNER_ACCEPTED'}
    catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_PUBLICATION_SCOPE_INVALID'){throw}}
    $Fixture.records.Remove($Latest)
    try {$null=Read-SuccessorRuntimePublication $Runtime;throw 'LATEST_SELFTEST_MISSING_ANCHOR_ACCEPTED'}
    catch {if($_.Exception.Message -cne 'LATEST_SELFTEST_ANCHOR_MISSING'){throw}}
    if($Fixture.legacyReads){throw 'LATEST_SELFTEST_HISTORICAL_FALLBACK'}
    Write-Host 'FORTIS_SUCCESSOR_RUNTIME_PUBLICATION_SELFTEST_PASS'
}
function Assert-SuccessorRuntimeDeliverySelfTest {
    $Retained=[pscustomobject]@{latestPin=$true;profileDigest=('a'*64);companionDigest=('b'*64);generation=('c'*64)
        sourceDelivery=[pscustomobject]@{device=1;inode=2;policyAuthorityDigest=('d'*64);interlockDigest=('e'*64)}
        registryCheckpoint=[pscustomobject]@{profileDigest=('f'*64);registryDigest=('1'*64)}}
    $Actual=$Retained|ConvertTo-Json -Depth 10|ConvertFrom-Json
    $Actual|Add-Member -NotePropertyName maintenancePhase -NotePropertyValue 'BACKUP_FROZEN'
    $Actual.sourceDelivery.interlockDigest='2'*64
    $Publication=[pscustomobject]@{record=[pscustomobject]@{generation=$Retained.generation;phase='BACKUP_FROZEN'}
        digest=('2'*64);registryDigest=$Retained.registryCheckpoint.registryDigest}
    Assert-SuccessorRuntimeDelivery $Actual $Retained $Publication
    $Actual.sourceDelivery.interlockDigest=$Retained.sourceDelivery.interlockDigest
    try {Assert-SuccessorRuntimeDelivery $Actual $Retained $Publication;throw 'LATEST_RUNTIME_SELFTEST_STALE_ACCEPTED'}
    catch {if($_.Exception.Message -cne 'RELEASE_REGISTRY_SUCCESSOR_DELIVERY_CHANGED'){throw}}
    $Actual.sourceDelivery.interlockDigest=$Publication.digest
    $Actual.registryCheckpoint.registryDigest='0'*64
    try {Assert-SuccessorRuntimeDelivery $Actual $Retained $Publication;throw 'LATEST_RUNTIME_SELFTEST_HOLD_ACCEPTED'}
    catch {if($_.Exception.Message -cne 'RELEASE_REGISTRY_SUCCESSOR_DELIVERY_CHANGED'){throw}}
    $Publication.record.phase='NORMAL';$Publication.registryDigest=$null;$Actual.maintenancePhase='NORMAL'
    Assert-SuccessorRuntimeDelivery $Actual $Retained $Publication
    $Actual.sourceDelivery.inode=3
    try {Assert-SuccessorRuntimeDelivery $Actual $Retained $Publication;throw 'LATEST_RUNTIME_SELFTEST_MOUNT_ACCEPTED'}
    catch {if($_.Exception.Message -cne 'RELEASE_REGISTRY_SUCCESSOR_DELIVERY_CHANGED'){throw}}
    Write-Host 'FORTIS_SUCCESSOR_RUNTIME_DELIVERY_SELFTEST_PASS'
}
function Publish-SuccessorLatestInterlock {
    param($Source,$Next,$Loaded,$RegistryDigest)
    # The caller owns the existing exclusive controller lock and has
    # independently verified the exact phase/hold evidence. The second
    # volume is only a projection, never the authoritative host record.
    $Anchor=$Loaded.anchor
    if(($Next.phase -ceq 'NORMAL' -and $null -ne $RegistryDigest) -or
       ($Next.phase -cne 'NORMAL' -and $RegistryDigest -cnotmatch '^[0-9a-f]{64}$')){
        throw 'RELEASE_SUCCESSOR_LATEST_PIN_INVALID'
    }
    $AlreadyCommitted=($Anchor.state -ceq 'Committed' -and (Same-Json $Anchor.record $Next))
    if($AlreadyCommitted){
        if($Anchor.registryDigest -cne $RegistryDigest -or $null -eq $Anchor.previous){
            throw 'RELEASE_SUCCESSOR_PUBLICATION_INTENT_CHANGED'
        }
        $Previous=$Anchor.previous;$PriorRegistryDigest=$Anchor.previousRegistryDigest
    } else {
        $Previous=$Anchor.record;$PriorRegistryDigest=$Anchor.registryDigest
        if($Next.previousDigest -cne $Anchor.digest){throw 'RELEASE_SUCCESSOR_PUBLICATION_INTENT_CHANGED'}
        if($Anchor.state -ceq 'Pending'){
            if(-not (Same-Json $Anchor.next $Next) -or $Anchor.nextRegistryDigest -cne $RegistryDigest){
                throw 'RELEASE_SUCCESSOR_PUBLICATION_INTENT_CHANGED'
            }
        } else {
            # Finish the previously committed publication before replacing its
            # durable intent. A crash between host commit and projection commit
            # leaves the previous exact transition available for readback.
            if($Anchor.record.sequence -gt 0){
                if((Publish-SuccessorLatestInterlock $Source $Anchor.record $Loaded $Anchor.registryDigest) -cne $Anchor.digest){
                    throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
                }
            }
            Write-Private $Loaded.path ([ordered]@{schema=$Anchor.schema;state='Pending';sourceRecordHash=$Source.hash
                record=$Previous;digest=$Anchor.digest;registryDigest=$PriorRegistryDigest;next=$Next
                nextRegistryDigest=$RegistryDigest}) -FlushToDisk
        }
    }
    $Mounts=@('--mount','type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,volume-nocopy',
        '--mount','type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,volume-nocopy')
    $Payload=@{action='successor_interlock_publish';mode='readback';previous=$Previous;next=$Next
        latest=@{previousRegistryDigest=$PriorRegistryDigest;nextRegistryDigest=$RegistryDigest}}
    $Actual=State-Helper $Payload $Mounts -Root
    if($Actual.position -ceq 'PREVIOUS' -and -not $AlreadyCommitted -and
       $Actual.digest -ceq $Anchor.digest -and $Actual.phase -ceq $Previous.phase){
        $Payload.mode='publish';$Actual=State-Helper $Payload $Mounts -Root
    }
    if($Actual.position -cne 'NEXT' -or $Actual.phase -cne $Next.phase -or
       $Actual.digest -cnotmatch '^[0-9a-f]{64}$' -or
       ($AlreadyCommitted -and $Actual.digest -cne $Anchor.digest) -or
       $Actual.latest.state -cnotin @('Pending','Committed') -or
       (-not $AlreadyCommitted -and $Actual.latest.state -cne 'Pending') -or
       $Actual.latest.interlockDigest -cne $Actual.digest -or $Actual.latest.generation -cne $Next.generation -or
       $Actual.latest.registryDigest -cne $RegistryDigest -or $Actual.latest.phase -cne $Next.phase -or
       $Actual.latest.sequence -ne $Next.sequence -or $Actual.latest.instanceId -cne $Next.registryInstanceId -or
       $Actual.latest.scopeDigest -cne $Next.scopeDigest){
        throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
    }
    if(-not $AlreadyCommitted){
        $Committed=[ordered]@{schema=$Anchor.schema;state='Committed';sourceRecordHash=$Source.hash
            record=$Next;digest=$Actual.digest;registryDigest=$RegistryDigest;previous=$Previous
            previousRegistryDigest=$PriorRegistryDigest}
        Write-Private $Loaded.path $Committed -FlushToDisk
        if(-not (Same-Json (Read-Private $Loaded.path) $Committed)){throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'}
    }
    # The helper fsyncs both directories on a Committed readback. Do not
    # launch an extra container for an already durable projection.
    if($AlreadyCommitted -and $Actual.latest.state -ceq 'Committed'){return $Actual.digest}
    # A failed ACK after either durable write is recovered by the same exact
    # readback, not a second phase or reissuing the stop/activation effect.
    $Payload.mode='commit'
    $Final=State-Helper $Payload $Mounts -Root
    if($Final.position -cne 'NEXT' -or $Final.digest -cne $Actual.digest -or $Final.phase -cne $Next.phase -or
       $Final.latest.state -cne 'Committed' -or $Final.latest.interlockDigest -cne $Final.digest -or
       $Final.latest.registryDigest -cne $RegistryDigest -or $Final.latest.generation -cne $Next.generation -or
       $Final.latest.sequence -ne $Next.sequence -or $Final.latest.instanceId -cne $Next.registryInstanceId -or
       $Final.latest.scopeDigest -cne $Next.scopeDigest -or $Final.latest.phase -cne $Next.phase){
        throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
    }
    return $Final.digest
}

function Assert-SuccessorLatestPublicationSelfTest {
    $Generation='a'*64;$OldDigest='b'*64;$NewDigest='c'*64;$RegistryDigest='d'*64;$FrozenDigest='f'*64
    $Source=@{hash=('e'*64);runtime=@{maintenanceGeneration=$Generation}}
    $Old=[ordered]@{phase='NORMAL';generation=$Generation;sequence=0;registryInstanceId='fixture';scopeDigest=('f'*64)}
    $Next=[ordered]@{phase='DRAINING';generation=$Generation;sequence=1;previousDigest=$OldDigest
        registryInstanceId=$Old.registryInstanceId;scopeDigest=$Old.scopeDigest}
    $Frozen=[ordered]@{phase='FROZEN_BEFORE_CHECK';generation=$Generation;sequence=2;previousDigest=$NewDigest
        registryInstanceId=$Old.registryInstanceId;scopeDigest=$Old.scopeDigest}
    $Fixture=@{writes=0;commits=0;saves=0;old=$Old;drain=$Next;frozen=$Frozen;current=$Old;projection='Committed';losePublish=$true;loseCommit=$true;anchor=[ordered]@{
        schema='fortis-successor-maintenance-publication-v2';state='Committed';record=$Old;digest=$OldDigest;registryDigest=$null}}
    function Read-SuccessorPublication {return @{path='fixture';anchor=$Fixture.anchor}}
    function Read-Private {param($Path) if($Path -cne 'fixture'){throw 'LATEST_SELFTEST_PATH'};return $Fixture.anchor}
    function Write-Private {
        param($Path,$Value,[switch]$FlushToDisk)
        if($Path -cne 'fixture' -or -not $FlushToDisk){throw 'LATEST_SELFTEST_SAVE'}
        if($Value.state -ceq 'Pending' -and $Value.record.phase -ceq 'DRAINING' -and $Fixture.projection -cne 'Committed'){
            throw 'LATEST_SELFTEST_PREDECESSOR_NOT_RECONCILED'
        }
        $Fixture.saves++;$Fixture.anchor=$Value
    }
    function State-Helper {
        param($Payload,$Mounts,[switch]$Root)
        if(-not $Root -or $Mounts.Count -ne 4 -or $Payload.latest.nextRegistryDigest -cne $RegistryDigest){throw 'LATEST_SELFTEST_BINDING'}
        $IsDrain=Same-Json $Payload.next $Fixture.drain
        if($IsDrain){
            if(-not (Same-Json $Payload.previous $Fixture.old)){throw 'LATEST_SELFTEST_BINDING'}
            $Pin=$NewDigest
        } else {
            if(-not (Same-Json $Payload.previous $Fixture.drain) -or -not (Same-Json $Payload.next $Fixture.frozen)){throw 'LATEST_SELFTEST_BINDING'}
            $Pin=$FrozenDigest
        }
        if($Payload.mode -ceq 'publish'){
            if($Fixture.anchor.state -cne 'Pending' -or $Fixture.projection -cne 'Committed' -or
               -not (Same-Json $Fixture.current $Payload.previous)){throw 'LATEST_SELFTEST_INTENT_REQUIRED'}
            $Fixture.writes++;$Fixture.current=$Payload.next;$Fixture.projection='Pending'
            if($Fixture.losePublish){$Fixture.losePublish=$false;throw 'LATEST_SELFTEST_PUBLISH_ACK_LOST'}
        }
        if($Payload.mode -ceq 'commit'){
            if($Fixture.anchor.state -cne 'Committed' -or -not (Same-Json $Fixture.anchor.record $Payload.next) -or
               -not (Same-Json $Fixture.current $Payload.next)){throw 'LATEST_SELFTEST_HOST_COMMIT_REQUIRED'}
            if($Fixture.projection -ceq 'Pending'){
                # Interrupt before projection commit. The next phase must
                # finish this exact committed predecessor first.
                if($Fixture.loseCommit){$Fixture.loseCommit=$false;throw 'LATEST_SELFTEST_COMMIT_ACK_LOST'}
                $Fixture.commits++;$Fixture.projection='Committed'
            }
        }
        if(Same-Json $Fixture.current $Payload.previous){
            return @{position='PREVIOUS';phase=$Payload.previous.phase;digest=$Payload.next.previousDigest}
        }
        if(-not (Same-Json $Fixture.current $Payload.next)){throw 'LATEST_SELFTEST_POSITION'}
        return @{position='NEXT';phase=$Payload.next.phase;digest=$Pin;latest=@{state=$Fixture.projection;interlockDigest=$Pin;
            registryDigest=$RegistryDigest;generation=$Generation;sequence=$Payload.next.sequence
            phase=$Payload.next.phase;instanceId=$Payload.next.registryInstanceId;scopeDigest=$Payload.next.scopeDigest}}
    }
    try {$null=Publish-SuccessorInterlock $Source $Next $RegistryDigest;throw 'LATEST_SELFTEST_PUBLISH_UNCONFIRMED'}
    catch {if($_.Exception.Message -cne 'LATEST_SELFTEST_PUBLISH_ACK_LOST'){throw}}
    if($Fixture.anchor.state -cne 'Pending' -or $Fixture.projection -cne 'Pending'){throw 'LATEST_SELFTEST_PENDING_LOST'}
    try {$null=Publish-SuccessorInterlock $Source $Next $RegistryDigest;throw 'LATEST_SELFTEST_COMMIT_UNCONFIRMED'}
    catch {if($_.Exception.Message -cne 'LATEST_SELFTEST_COMMIT_ACK_LOST'){throw}}
    if($Fixture.anchor.state -cne 'Committed' -or $Fixture.projection -cne 'Pending'){throw 'LATEST_SELFTEST_PENDING_LOST'}
    if((Publish-SuccessorInterlock $Source $Frozen $RegistryDigest) -cne $FrozenDigest -or
       (Publish-SuccessorInterlock $Source $Frozen $RegistryDigest) -cne $FrozenDigest -or
        $Fixture.anchor.state -cne 'Committed' -or $Fixture.projection -cne 'Committed' -or
        $Fixture.writes -ne 2 -or $Fixture.commits -ne 2 -or $Fixture.saves -ne 4){throw 'LATEST_SELFTEST_READBACK_FAILED'}
    try {$null=Publish-SuccessorInterlock $Source $Frozen ('0'*64);throw 'LATEST_SELFTEST_CHANGED_PIN_ACCEPTED'}
    catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_PUBLICATION_INTENT_CHANGED'){throw}}
    Write-Host 'FORTIS_SUCCESSOR_LATEST_PUBLICATION_SELFTEST_PASS'
}

function Publish-SuccessorInterlock {
    param($Source,$Next,$RegistryDigest=$null)
    # The existing owner controller lock and phase admission cover this call.
    $Loaded=Read-SuccessorPublication $Source
    $Anchor=$Loaded.anchor
    if($Anchor.schema -ceq 'fortis-successor-maintenance-publication-v2'){
        return (Publish-SuccessorLatestInterlock $Source $Next $Loaded $RegistryDigest)
    }
    $AlreadyCommitted=($Anchor.state -ceq 'Committed' -and (Same-Json $Anchor.record $Next))
    if($AlreadyCommitted){
        $Previous=$Anchor.previous
    } else {
        $Previous=$Anchor.record
        if($Next.previousDigest -cne $Anchor.digest -or
           $Next.generation -cne $Source.runtime.maintenanceGeneration -or
           $Next.phase -cnotin @('DRAINING','FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP')){
            throw 'RELEASE_SUCCESSOR_PUBLICATION_INTENT_CHANGED'
        }
        if($Anchor.state -ceq 'Pending'){
            if(-not (Same-Json $Anchor.next $Next)){throw 'RELEASE_SUCCESSOR_PUBLICATION_INTENT_CHANGED'}
        } else {
            Write-Private $Loaded.path ([ordered]@{schema=$Anchor.schema;state='Pending'
                sourceRecordHash=$Source.hash;record=$Previous;digest=$Anchor.digest;next=$Next}) -FlushToDisk
        }
    }
    $Mounts=@('--mount','type=volume,source=fortis-r7-maintenance-interlock,target=/run/r7-maintenance,volume-nocopy')
    $Payload=@{action='successor_interlock_publish';mode='readback';previous=$Previous;next=$Next}
    $Actual=State-Helper $Payload $Mounts -Root
    if($Actual.position -ceq 'PREVIOUS' -and -not $AlreadyCommitted -and
       $Actual.digest -ceq $Anchor.digest -and $Actual.phase -ceq $Previous.phase){
        $Payload.mode='publish'
        $Actual=State-Helper $Payload $Mounts -Root
    }
    if($Actual.position -cne 'NEXT' -or $Actual.phase -cne $Next.phase -or
       $Actual.digest -cnotmatch '^[0-9a-f]{64}$' -or
       ($AlreadyCommitted -and $Actual.digest -cne $Anchor.digest)){
        throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
    }
    if(-not $AlreadyCommitted){
        Write-Private $Loaded.path ([ordered]@{schema=$Anchor.schema;state='Committed'
            sourceRecordHash=$Source.hash;record=$Next;digest=$Actual.digest;previous=$Previous}) -FlushToDisk
    }
    return $Actual.digest
}
function Assert-SuccessorPublicationSelfTest {
    $Generation='a'*64;$OldDigest='b'*64;$NewDigest='c'*64
    $Source=@{hash=('d'*64);runtime=@{maintenanceGeneration=$Generation}}
    $Old=[ordered]@{phase='NORMAL';generation=$Generation}
    $Next=[ordered]@{phase='DRAINING';generation=$Generation;previousDigest=$OldDigest}
    $Fixture=@{writes=0;position='PREVIOUS';saves=0;anchor=[ordered]@{
        schema='fortis-successor-maintenance-publication-v1';state='Committed';record=$Old;digest=$OldDigest}}
    function Read-SuccessorPublication {return @{path='fixture';anchor=$Fixture.anchor}}
    function Write-Private {
        param($Path,$Value,[switch]$FlushToDisk)
        if($Path -cne 'fixture' -or -not $FlushToDisk){throw 'RELEASE_PUBLICATION_SELFTEST_SAVE_INVALID'}
        $Fixture.saves++;$Fixture.anchor=$Value
    }
    function State-Helper {
        param($Payload,$Mounts,[switch]$Root)
        if(-not $Root -or -not (Same-Json $Payload.previous $Old) -or -not (Same-Json $Payload.next $Next)){
            throw 'RELEASE_PUBLICATION_SELFTEST_BINDING_INVALID'
        }
        if($Payload.mode -ceq 'publish'){
            if($Fixture.anchor.state -cne 'Pending'){throw 'RELEASE_PUBLICATION_SELFTEST_INTENT_REQUIRED'}
            $Fixture.writes++;$Fixture.position='NEXT'
            throw 'RELEASE_PUBLICATION_SELFTEST_ACK_LOST'
        }
        if($Fixture.position -ceq 'PREVIOUS'){return @{position='PREVIOUS';phase='NORMAL';digest=$OldDigest}}
        return @{position='NEXT';phase='DRAINING';digest=$NewDigest}
    }
    try {
        $null=Publish-SuccessorInterlock $Source $Next
        throw 'RELEASE_PUBLICATION_SELFTEST_UNCONFIRMED_ACCEPTED'
    } catch {if($_.Exception.Message -cne 'RELEASE_PUBLICATION_SELFTEST_ACK_LOST'){throw}}
    if($Fixture.anchor.state -cne 'Pending'){throw 'RELEASE_PUBLICATION_SELFTEST_PENDING_LOST'}
    if((Publish-SuccessorInterlock $Source $Next) -cne $NewDigest -or
       (Publish-SuccessorInterlock $Source $Next) -cne $NewDigest -or
       $Fixture.anchor.state -cne 'Committed' -or $Fixture.writes -ne 1 -or $Fixture.saves -ne 2){
        throw 'RELEASE_PUBLICATION_SELFTEST_READBACK_FAILED'
    }
    Write-Host 'FORTIS_SUCCESSOR_PUBLICATION_SELFTEST_PASS'
}
function Read-SuccessorMaintenanceContext {
    param($Source)
    if($Bootstrap289){
        # The static #289 source cannot acknowledge operational DRAINING.
        # The one protected bootstrap uses physical exclusion before seed;
        # ordinary latest-pin and historical/static paths stay distinct.
        if($Action -cnotin @('Check','Apply')){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_EXACT_CHECK_REQUIRED'}
        $null=Read-BootstrapSeedSource $Source -Live
        return
    }
    if($Corrective288){
        # Explicit one-time initial delivery continuation, not a generic
        # successor maintenance waiver. Original NORMAL anchor is checked
        # before admitting any candidate; exact Check/Apply and owner GO
        # are required by the existing release attempt.
        $null=Read-Corrective288Anchor $Source
        return
    }
    $Generation=$Source.runtime.PSObject.Properties['maintenanceGeneration']
    if($null -eq $Generation){return}
    # A protected source opts in at provisioning. The receipt is updated only
    # by the owner controller under its lock, independently of source volume.
    if($Generation.Value -cnotmatch '^[0-9a-f]{64}$' -or
       $Source.runtime.runId -cnotmatch '^[0-9a-f]{32}$' -or
       $Action -cnotin @('Check','Apply') -or $AllowUncertainGrowth -or
       $script:RegistryReturn -or $EmergencyRequested -or $script:PreserveApprovedRequest -or
       $RegistryReturnContainerId -or
       ($Action -ceq 'Check' -and -not $script:RegistryPrebuiltCheck) -or
       ($Action -ceq 'Apply' -and -not $CheckedImageRecord)){
        throw 'RELEASE_SUCCESSOR_MAINTENANCE_CHECK_REQUIRED'
    }
    $Path=Join-Path $ReleaseBase ('maintenance-'+$Source.runtime.runId+'.json')
    $Protected=Read-Private $Path
    $Payload=$Protected.payload
    if($Protected.schema -cnotin @('fortis-successor-maintenance-check-v1','fortis-successor-maintenance-check-v2') -or
       $Protected.sourceRecordHash -cne $Source.hash -or $Protected.targetSourceSha -cne $SourceSha -or
       $Protected.targetImageId -cne $script:Image -or
       ($null -ne $Payload -and ($Payload.generation -cne $Generation.Value -or
        $Payload.targetSourceSha -cne $SourceSha))){
        throw 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'
    }
    $CurrentPublication=(Read-SuccessorPublication $Source).anchor
    $Latest=$Protected.schema -ceq 'fortis-successor-maintenance-check-v2'
    if($Latest -ne ($CurrentPublication.schema -ceq 'fortis-successor-maintenance-publication-v2')){
        throw 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'
    }
    if($Latest){
        # A durable ordinary intent can exist before any begin receipt.
        # Recovery must read that exact intent instead of repeating a
        # NORMAL-only compatibility probe against a possibly committed pair.
        if($Action -ceq 'Check' -and $Protected.PSObject.Properties['intentDigest'] -and -not $Protected.begin){
            if($Protected.intentDigest -cnotmatch '^[0-9a-f]{64}$' -or $Protected.draining -or $Payload -or
               $Protected.registryDigest -or $CurrentPublication.state -cne 'Committed' -or
               -not (Same-Json $CurrentPublication.record $Protected.intent.normal) -or
               $Protected.intent.authorization.sourceRecordDigest -cne $Source.hash.ToLowerInvariant() -or
               $Protected.targetNonce -cne $RegistryReleaseNonce -or
               $Protected.targetRegistryImage -cne $SuccessorRegistryImage -or
               $Protected.intent.compatibility.registry.profileDigest -cne $SuccessorRegistryProfileSha256){
                throw 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'
            }
            return $Protected
        }
        if($Protected.registryDigest -cnotmatch '^[0-9a-f]{64}$' -or
           ($null -ne $Payload -and ($Payload.latestPin -isnot [bool] -or -not $Payload.latestPin -or
            $Payload.registryDigest -cne $Protected.registryDigest)) -or
           ($CurrentPublication.record.phase -cne 'NORMAL' -and
            $CurrentPublication.registryDigest -cne $Protected.registryDigest)){
            throw 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'
        }
    } elseif($null -ne $Payload -and $Payload.PSObject.Properties['latestPin']){
        throw 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'
    }
    if($null -ne $Payload){
        $ExpectedUncertain=@(Parse-PreservedUncertainRequests $script:PreserveUncertainRequests|Sort-Object)
        $ExpectedClaimed=@(Parse-PreservedUncertainRequests $script:PreserveClaimedJobs|Sort-Object)
        if(($ExpectedUncertain -join ',') -cne (@($Payload.preserveUncertainIds) -join ',') -or
           ($ExpectedClaimed -join ',') -cne (@($Payload.preserveClaimedIds) -join ',')){
            throw 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'
        }
    }
    $Drain=$Protected.draining
    if($Drain.phase -cne 'DRAINING' -or $Drain.generation -cne $Generation.Value -or
       $Drain.attempt.source.sourceSha -cne $SourceSha -or
       ($null -ne $Payload -and ($Payload.action -cne 'successor_freeze_inspect' -or
        $Payload.attemptId -cne $Drain.attempt.attemptId -or
        $Payload.restrictionDigest -cne $Drain.attempt.restrictionDigest -or
        -not (Same-Json $Payload.subject $Drain.attempt.subject)))){
        throw 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'
    }
    $ExpectedPath=Successor-CheckRecordPath $Drain.attempt.attemptId
    if($Action -ceq 'Check'){return $Protected}
    if($null -eq $Payload -or
       [IO.Path]::GetFullPath($ExpectedPath) -cne [IO.Path]::GetFullPath($CheckedImageRecord)){
        throw 'RELEASE_SUCCESSOR_CHECK_RECORD_CHANGED'
    }
    $Stored=Read-Private $ExpectedPath
    $Transitions=$Stored.maintenanceTransitions
    if($Stored.schema -cne 'fortis-extension-image-check-v1' -or $Stored.phase -cne 'Ready' -or
       $null -eq $Stored.maintenanceSeal -or $null -eq $Transitions -or
       -not (Same-Json $Transitions.draining $Drain)){
        throw 'RELEASE_SUCCESSOR_CHECK_RECORD_CHANGED'
    }
    $Publication=(Read-SuccessorPublication $Source).anchor
    if($Publication.state -cne 'Committed' -or $Publication.record.phase -cne 'CHECK_SEALED' -or
       -not (Same-Json $Publication.record $Transitions.checked)){
        throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
    }
    return (New-SuccessorApplyVerifyPayload $Payload $Stored.maintenanceSeal $Transitions $Publication.digest)
}
function New-SuccessorApplyVerifyPayload {
    param($Payload,$Seal,$Transitions,[string]$Digest)
    $Verify=@{}
    foreach($Field in $Payload.PSObject.Properties){
        if($Field.Name -cne 'drain'){$Verify[$Field.Name]=$Field.Value}
    }
    $Verify.action='successor_freeze_apply_verify'
    $Verify.interlockDigest=$Digest
    $Verify.checkSeal=$Seal
    $Verify.draining=$Transitions.draining
    $Verify.frozen=$Transitions.frozen
    return $Verify
}
function Start-SuccessorMaintenanceCheck {
    param($Source,$Context)
    $Before=(Read-SuccessorPublication $Source).anchor
    if($Before.record.phase -ceq 'DRAINING' -and -not (Same-Json $Before.record $Context.draining)){
        throw 'RELEASE_SUCCESSOR_CHECK_PHASE_CHANGED'
    }
    if($Before.record.phase -cin @('FROZEN_BEFORE_CHECK','CHECK_SEALED') -or
       ($Before.record.phase -ceq 'DRAINING' -and $Before.state -ceq 'Pending')){
        if($null -eq $Context.payload){throw 'RELEASE_SUCCESSOR_CHECK_PHASE_CHANGED'}
        return @{resume=$true;payload=$Context.payload}
    }
    if($Before.record.phase -cnotin @('NORMAL','DRAINING')){throw 'RELEASE_SUCCESSOR_CHECK_PHASE_CHANGED'}
    # Re-entering a pending or completed DRAINING intent takes the same
    # exact publisher readback path before the inspector is called.
    $RegistryDigest=$null
    if($Before.schema -ceq 'fortis-successor-maintenance-publication-v2'){
        $RegistryDigest=$Context.registryDigest
        if($RegistryDigest -cnotmatch '^[0-9a-f]{64}$' -or
           ($null -ne $Context.payload -and $Context.payload.registryDigest -cne $RegistryDigest)){
            throw 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'
        }
    }
    $Digest=Publish-SuccessorInterlock $Source $Context.draining $RegistryDigest
    if($null -ne $Context.payload -and $Context.payload.interlockDigest -cne $Digest){
        throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
    }
    return @{resume=$false;digest=$Digest;payload=$Context.payload}
}
function Complete-SuccessorMaintenanceCheck {
    param($Source,$Context,$Stored)
    $Payload=$Context.payload
    $Seal=$Stored.maintenanceSeal
    $Transitions=$Stored.maintenanceTransitions
    if($null -eq $Stored.sourceReceipt -or $null -eq $Seal -or $null -eq $Transitions -or
       $Seal.result -cne 'FREEZE_BINDINGS_MATCH_ONLY' -or
       $Seal.interlockDigest -cne $Payload.interlockDigest -or
       $Seal.attemptId -cne $Payload.attemptId -or
       $Seal.restrictionDigest -cne $Payload.restrictionDigest -or
       $Seal.registryDigest -cne $Payload.registryDigest -or
       $Seal.stateReceiptDigest -cne $Payload.stateDigest -or
       $Seal.companionDigest -cne $Payload.companionDigest -or
       $Seal.workerAttestationDigest -cne $Payload.workerAttestationDigest -or
       -not (Same-Json $Transitions.draining $Context.draining)){
        throw 'RELEASE_SUCCESSOR_CHECK_RECORD_CHANGED'
    }
    $Current=(Read-SuccessorPublication $Source).anchor
    $RegistryDigest=$null
    if($Current.schema -ceq 'fortis-successor-maintenance-publication-v2'){
        $RegistryDigest=$Context.registryDigest
        if($RegistryDigest -cnotmatch '^[0-9a-f]{64}$' -or $Payload.registryDigest -cne $RegistryDigest -or
           $Current.registryDigest -cne $RegistryDigest -or $Payload.latestPin -isnot [bool] -or -not $Payload.latestPin){
            throw 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'
        }
    }
    if($Current.record.phase -ceq 'DRAINING'){
        if($Current.digest -cne $Payload.interlockDigest -or
           -not (Same-Json $Current.record $Transitions.draining)){
            throw 'RELEASE_SUCCESSOR_CHECK_PHASE_CHANGED'
        }
        $null=Publish-SuccessorInterlock $Source $Transitions.frozen $RegistryDigest
        $Current=(Read-SuccessorPublication $Source).anchor
    }
    if(($Current.record.phase -ceq 'FROZEN_BEFORE_CHECK' -and
        (Same-Json $Current.record $Transitions.frozen)) -or
       ($Current.record.phase -ceq 'CHECK_SEALED' -and
        (Same-Json $Current.record $Transitions.checked))){
        $Digest=Publish-SuccessorInterlock $Source $Transitions.checked $RegistryDigest
    } else {throw 'RELEASE_SUCCESSOR_CHECK_PHASE_CHANGED'}

    # The same read-only verifier used by Apply compares the actual mounted
    # CHECK_SEALED and state against what this Check stored.
    $Verify=New-SuccessorApplyVerifyPayload $Payload $Seal $Transitions $Digest
    $Final=Read-SuccessorFreezeSeal $Verify $Source.runtime.stateVolume 'fortis-r7-maintenance-interlock'
    if(-not (Same-Json $Final.sourceReceipt $Stored.sourceReceipt)){
        throw 'RELEASE_SUCCESSOR_CHECK_RECORD_CHANGED'
    }
    return $Digest
}
function Assert-SuccessorCheckSealSelfTest {
    $Draining=[ordered]@{phase='DRAINING'}
    $Frozen=[ordered]@{phase='FROZEN_BEFORE_CHECK'}
    $Checked=[ordered]@{phase='CHECK_SEALED'}
    $Stages=[ordered]@{draining=$Draining;frozen=$Frozen;checked=$Checked}
    $Payload=[pscustomobject]@{action='successor_freeze_inspect';interlockDigest='drain';drain='fixture'
        attemptId='attempt';restrictionDigest='restriction';registryDigest='registry';stateDigest='state'
        companionDigest='companion';workerAttestationDigest='worker'}
    $Seal=[pscustomobject]@{result='FREEZE_BINDINGS_MATCH_ONLY';interlockDigest='drain';attemptId='attempt'
        restrictionDigest='restriction';registryDigest='registry';stateReceiptDigest='state'
        companionDigest='companion';workerAttestationDigest='worker'}
    $Source=@{runtime=@{stateVolume='fixture'}}
    $Context=@{payload=$Payload;draining=$Draining}
    $Stored=@{sourceReceipt=@{sha256='fixture'};maintenanceSeal=$Seal;maintenanceTransitions=$Stages}
    $Fixture=@{stage=$Draining;writes=0;reads=0}
    function Read-SuccessorPublication {return @{anchor=@{schema='fortis-successor-maintenance-publication-v1';record=$Fixture.stage;digest='drain'}}}
    function Publish-SuccessorInterlock {
        param($Source,$Next)
        if(Same-Json $Fixture.stage $Next){return 'checked'}
        if($Fixture.stage.phase -ceq 'DRAINING' -and (Same-Json $Next $Frozen)){
            $Fixture.stage=$Next;$Fixture.writes++
            throw 'RELEASE_CHECK_SEAL_SELFTEST_ACK_LOST'
        }
        if($Fixture.stage.phase -ceq 'FROZEN_BEFORE_CHECK' -and (Same-Json $Next $Checked)){
            $Fixture.stage=$Next;$Fixture.writes++
            return 'checked'
        }
        throw 'RELEASE_CHECK_SEAL_SELFTEST_TRANSITION_INVALID'
    }
    function Read-SuccessorFreezeSeal {
        param($Verify,$Volume,$InterlockVolume)
        if($Fixture.stage.phase -cne 'CHECK_SEALED' -or $Verify.action -cne 'successor_freeze_apply_verify' -or
           $Verify.interlockDigest -cne 'checked' -or $Verify.ContainsKey('drain') -or
           -not (Same-Json $Verify.draining $Draining) -or -not (Same-Json $Verify.frozen $Frozen) -or
           -not (Same-Json $Verify.checkSeal $Seal)){
            throw 'RELEASE_CHECK_SEAL_SELFTEST_READBACK_INVALID'
        }
        $Fixture.reads++
        return @{sourceReceipt=$Stored.sourceReceipt}
    }
    try {
        $null=Complete-SuccessorMaintenanceCheck $Source $Context $Stored
        throw 'RELEASE_CHECK_SEAL_SELFTEST_MISSING_FAILURE'
    } catch {if($_.Exception.Message -cne 'RELEASE_CHECK_SEAL_SELFTEST_ACK_LOST'){throw}}
    if((Complete-SuccessorMaintenanceCheck $Source $Context $Stored) -cne 'checked' -or
       (Complete-SuccessorMaintenanceCheck $Source $Context $Stored) -cne 'checked' -or
       $Fixture.writes -ne 2 -or $Fixture.reads -ne 2){
        throw 'RELEASE_CHECK_SEAL_SELFTEST_RESUME_FAILED'
    }
    Write-Host 'FORTIS_SUCCESSOR_CHECK_SEAL_SELFTEST_PASS'
}
function Assert-SuccessorCheckStartSelfTest {
    $Draining=[ordered]@{phase='DRAINING';generation=('a'*64);previousDigest=('b'*64)}
    $Fixture=@{phase='NORMAL';calls=0;digest=('c'*64)}
    $Context=@{draining=$Draining;payload=$null}
    function Read-SuccessorPublication {
        return @{anchor=@{schema='fortis-successor-maintenance-publication-v1';state='Committed';record=$(if($Fixture.phase -ceq 'DRAINING'){$Draining}else{@{phase=$Fixture.phase}})}}
    }
    function Publish-SuccessorInterlock {
        param($Source,$Next)
        if(-not (Same-Json $Next $Draining)){throw 'RELEASE_SUCCESSOR_CHECK_SELFTEST_CHANGED_INTENT'}
        $Fixture.calls++;$Fixture.phase='DRAINING'
        return $Fixture.digest
    }
    $Start=Start-SuccessorMaintenanceCheck $null $Context
    if($Start.digest -cne $Fixture.digest -or $null -ne $Start.payload){
        throw 'RELEASE_SUCCESSOR_CHECK_SELFTEST_DRAINING_RESULT'
    }
    $Context.payload=@{interlockDigest=$Fixture.digest}
    $Ready=Start-SuccessorMaintenanceCheck $null $Context
    if(-not (Same-Json $Ready.payload $Context.payload) -or $Fixture.calls -ne 2){
        throw 'RELEASE_SUCCESSOR_CHECK_SELFTEST_READBACK'
    }
    $Context.payload=@{interlockDigest=('d'*64)}
    try {
        $null=Start-SuccessorMaintenanceCheck $null $Context
        throw 'RELEASE_SUCCESSOR_CHECK_SELFTEST_WRONG_WITNESS_ACCEPTED'
    } catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'){throw}}
    Write-Host 'FORTIS_SUCCESSOR_CHECK_START_SELFTEST_PASS'
}
function Assert-SuccessorLatestCheckSelfTest {
    $Pin='a'*64;$Digest='b'*64
    $Draining=[ordered]@{phase='DRAINING'}
    $Frozen=[ordered]@{phase='FROZEN_BEFORE_CHECK'}
    $Checked=[ordered]@{phase='CHECK_SEALED'}
    $Stages=[ordered]@{draining=$Draining;frozen=$Frozen;checked=$Checked}
    $Source=@{runtime=@{stateVolume='fixture'}}
    $Context=@{registryDigest=$Pin;draining=$Draining;payload=$null}
    $Fixture=@{stage=@{phase='NORMAL'};writes=0;reads=0}
    function Read-SuccessorPublication {
        return @{anchor=@{schema='fortis-successor-maintenance-publication-v2';state='Committed'
            record=$Fixture.stage;digest=$Digest;registryDigest=$(if($Fixture.stage.phase -cne 'NORMAL'){$Pin})}}
    }
    function Publish-SuccessorInterlock {
        param($Source,$Next,$RegistryDigest)
        if($RegistryDigest -cne $Pin){throw 'LATEST_CHECK_SELFTEST_REGISTRY_PIN'}
        $Fixture.stage=$Next;$Fixture.writes++;return $Digest
    }
    function Read-SuccessorFreezeSeal {
        param($Verify,$Volume,$InterlockVolume)
        if($Fixture.stage.phase -cne 'CHECK_SEALED' -or $Verify.latestPin -ne $true -or
           $Verify.registryDigest -cne $Pin -or $Verify.interlockDigest -cne $Digest){
            throw 'LATEST_CHECK_SELFTEST_READBACK'
        }
        $Fixture.reads++;return @{sourceReceipt=$Stored.sourceReceipt}
    }
    $Start=Start-SuccessorMaintenanceCheck $Source $Context
    if($Start.digest -cne $Digest -or $null -ne $Start.payload -or $Fixture.writes -ne 1){
        throw 'LATEST_CHECK_SELFTEST_DRAIN'
    }
    $Payload=[pscustomobject]@{action='successor_freeze_inspect';latestPin=$true;interlockDigest=$Digest;drain='fixture'
        attemptId='attempt';restrictionDigest='restriction';registryDigest=$Pin;stateDigest='state'
        companionDigest='companion';workerAttestationDigest='worker'}
    $Seal=[pscustomobject]@{result='FREEZE_BINDINGS_MATCH_ONLY';interlockDigest=$Digest;attemptId='attempt'
        restrictionDigest='restriction';registryDigest=$Pin;stateReceiptDigest='state'
        companionDigest='companion';workerAttestationDigest='worker'}
    $Context.payload=$Payload
    $Stored=@{sourceReceipt=@{sha256='fixture'};maintenanceSeal=$Seal;maintenanceTransitions=$Stages}
    $Context.registryDigest='0'*64
    try {$null=Complete-SuccessorMaintenanceCheck $Source $Context $Stored;throw 'LATEST_CHECK_SELFTEST_CHANGED_PIN_ACCEPTED'}
    catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'){throw}}
    $Context.registryDigest=$Pin
    if((Complete-SuccessorMaintenanceCheck $Source $Context $Stored) -cne $Digest -or
       $Fixture.writes -ne 3 -or $Fixture.reads -ne 1){
        throw 'LATEST_CHECK_SELFTEST_COMPLETE'
    }
    Write-Host 'FORTIS_SUCCESSOR_LATEST_CHECK_SELFTEST_PASS'
}
function Successor-CheckRecordPath {
    param([string]$AttemptId)
    if($AttemptId -cnotmatch '^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$'){
        throw 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'
    }
    return (Join-Path (Join-Path $ReleaseBase ('image-check-'+$AttemptId.Replace('-',''))) 'record.json')
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
# P4: old complete release records legitimately have no CD READ scope.
# A present field must be exact, bounded and free of case-insensitive duplicates.
# The source-only flag cannot be inherited from an untrusted Docker environment.
function Read-CdReadRepositories {
    param($Record)
    if($null -eq $Record){throw 'RELEASE_CD_READ_RECORD_INVALID'}
    $Value=''
    if($Record -is [Collections.IDictionary]){
        if($Record.Contains('cdReadRepositories')){$Value=$Record['cdReadRepositories']}
    } else {
        $Prop=$Record.PSObject.Properties['cdReadRepositories']
        if($null -ne $Prop){$Value=$Prop.Value}
    }
    if($Value -isnot [string]){throw 'RELEASE_CD_READ_RECORD_INVALID'}
    if($Value -and ($Value -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}(,[A-Za-z0-9][A-Za-z0-9_.-]{0,99}){0,9}$' -or
        @($Value.Split(',')|Select-Object -Unique).Count -ne @($Value.Split(',')).Count)){
        throw 'RELEASE_CD_READ_RECORD_INVALID'
    }
    return $Value
}
# Optional Action Core network identity on protected primary records.
# Legacy records (bridge-only) legitimately lack gatewayNetworks. StrictMode
# must never interpret that missing field as a property exception; however a
# present but malformed field MUST NOT become an implicit bridge downgrade.
function Read-GatewayNetworks {
    param($Record)
    if($null -eq $Record){throw 'RELEASE_ACTION_CORE_NETWORK_RECORD_INVALID'}
    if($Record -is [Collections.IDictionary]){
        if(-not $Record.Contains('gatewayNetworks')){return $null}
        $Value=$Record['gatewayNetworks']
    } else {
        $Property=$Record.PSObject.Properties['gatewayNetworks']
        if($null -eq $Property){return $null}
        $Value=$Property.Value
    }
    if($Value -is [Collections.IDictionary]){
        $Names=@($Value.Keys)
    } elseif($Value -is [pscustomobject]){
        $Properties=@($Value.PSObject.Properties)
        if(@($Properties|Where-Object{
            $_.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty
        }).Count){throw 'RELEASE_ACTION_CORE_NETWORK_RECORD_INVALID'}
        $Names=@($Properties|ForEach-Object{$_.Name})
    } else {
        throw 'RELEASE_ACTION_CORE_NETWORK_RECORD_INVALID'
    }
    # Retain historical Action Core shape, admit exactly Observatory-only or
    # Observatory+Action Core, and reject extra/renamed/duplicate interfaces.
    if($Names.Count -lt 2 -or $Names.Count -gt 3 -or
       $Names -cnotcontains 'fortis-gateway-egress' -or
       ($Names -cnotcontains 'fortis-actioncore-net' -and
        $Names -cnotcontains 'fortis-observatory-gw-net') -or
       @($Names|Where-Object{$_ -cnotin @(
           'fortis-gateway-egress','fortis-actioncore-net','fortis-observatory-gw-net')}).Count){
        throw 'RELEASE_ACTION_CORE_NETWORK_RECORD_INVALID'
    }
    $Networks=[ordered]@{}
    foreach($Name in @('fortis-gateway-egress','fortis-actioncore-net',
                        'fortis-observatory-gw-net')){
        if($Names -cnotcontains $Name){continue}
        $Id=$(if($Value -is [Collections.IDictionary]){$Value[$Name]}
              else{$Value.PSObject.Properties[$Name].Value})
        if($Id -isnot [string] -or $Id -cnotmatch '^[0-9a-f]{64}$' -or
           @($Networks.Values) -ccontains $Id){
            throw 'RELEASE_ACTION_CORE_NETWORK_RECORD_INVALID'
        }
        $Networks[$Name]=$Id
    }
    return $Networks
}
# Runs under Windows PowerShell 5.1 StrictMode Latest from the existing
# owner/CI SelfTest. Only fabricated JSON and local hashtables: no Docker,
# live state or network access, and no private release record is created.
function Assert-OptionalActionCoreSelfTest {
    $Legacy=ConvertFrom-Json -InputObject '{"schemaVersion":1}'
    $LegacyMap=[ordered]@{schemaVersion=1}
    if($null -ne (Read-GatewayNetworks $Legacy) -or
       $null -ne (Read-GatewayNetworks $LegacyMap)){
        throw 'RELEASE_ACTION_CORE_LEGACY_RECORD_SELFTEST_FAILED'
    }
    $Egress='a'*64
    $Action='b'*64
    $Good=[ordered]@{
        'fortis-gateway-egress'=$Egress
        'fortis-actioncore-net'=$Action
    }
    $FromMap=Read-GatewayNetworks ([ordered]@{gatewayNetworks=$Good})
    $FromJson=Read-GatewayNetworks (ConvertFrom-Json -InputObject (
        '{"gatewayNetworks":{"fortis-gateway-egress":"'+$Egress+
        '","fortis-actioncore-net":"'+$Action+'"}}'))
    if(-not (Same-Json $Good $FromMap) -or
       -not (Same-Json $Good $FromJson)){
        throw 'RELEASE_ACTION_CORE_VALID_RECORD_SELFTEST_FAILED'
    }
    $Observatory='c'*64
    $ObsOnly=[ordered]@{
        'fortis-gateway-egress'=$Egress
        'fortis-observatory-gw-net'=$Observatory
    }
    $Both=[ordered]@{
        'fortis-gateway-egress'=$Egress
        'fortis-actioncore-net'=$Action
        'fortis-observatory-gw-net'=$Observatory
    }
    foreach($Networks in @($ObsOnly,$Both)){
        $FromRecord=Read-GatewayNetworks ([ordered]@{gatewayNetworks=$Networks})
        if(-not (Same-Json $Networks $FromRecord)){
            throw 'RELEASE_OBSERVATORY_VALID_RECORD_SELFTEST_FAILED'
        }
    }
    $Malformed=@(
        ([ordered]@{gatewayNetworks=$null})
        ([ordered]@{gatewayNetworks='bridge'})
        ([ordered]@{gatewayNetworks=[ordered]@{'fortis-gateway-egress'=$Egress}})
        ([ordered]@{gatewayNetworks=[ordered]@{
            'fortis-gateway-egress'=$Egress;'fortis-actioncore-net'=$Egress}})
        ([ordered]@{gatewayNetworks=[ordered]@{
            'fortis-gateway-egress'=$Egress;'fortis-actioncore-net'=$Action
            'unexpected-net'=('c'*64)}})
        (ConvertFrom-Json -InputObject (
            '{"gatewayNetworks":{"Fortis-gateway-egress":"'+$Egress+
            '","fortis-actioncore-net":"'+$Action+'"}}'))
    )
    foreach($Bad in $Malformed){
        $Rejected=$false
        try{$null=Read-GatewayNetworks $Bad}
        catch{
            if($_.Exception.Message -cne 'RELEASE_ACTION_CORE_NETWORK_RECORD_INVALID'){throw}
            $Rejected=$true
        }
        if(-not $Rejected){throw 'RELEASE_ACTION_CORE_MALFORMED_RECORD_SELFTEST_FAILED'}
    }
    $NoAction=ConvertFrom-Json -InputObject '{"schemaVersion":1,"providers":{"github":{}}}'
    if($null -ne (Read-ActionCoreProvider $NoAction)){
        throw 'RELEASE_ACTION_CORE_ABSENT_PROVIDER_SELFTEST_FAILED'
    }
    $HasAction=ConvertFrom-Json -InputObject '{"schemaVersion":1,"providers":{"action_core":{"operations":{}}}}'
    if($null -eq (Read-ActionCoreProvider $HasAction)){
        throw 'RELEASE_ACTION_CORE_VALID_PROVIDER_SELFTEST_FAILED'
    }
    $MalformedProviders=@(
        $Legacy
        (ConvertFrom-Json -InputObject '{"schemaVersion":1,"providers":null}')
        (ConvertFrom-Json -InputObject '{"schemaVersion":1,"providers":{"action_core":null}}')
        (ConvertFrom-Json -InputObject '{"schemaVersion":1,"providers":{"action_core":false}}')
    )
    foreach($Bad in $MalformedProviders){
        $Rejected=$false
        try{$null=Read-ActionCoreProvider $Bad}
        catch{
            if($_.Exception.Message -cne 'RELEASE_ACTION_CORE_CONFIG_INVALID'){throw}
            $Rejected=$true
        }
        if(-not $Rejected){throw 'RELEASE_ACTION_CORE_MALFORMED_PROVIDER_SELFTEST_FAILED'}
    }
    Write-Host 'FORTIS_ACTION_CORE_OPTIONAL_FIELDS_SELFTEST_PASS'
}
function Parse-PreservedUncertainRequests {
    param([string]$Value)
    if(-not $Value){return}
    $Ids=@($Value.Split(','))
    if($Ids.Count -gt 20 -or @($Ids|Select-Object -Unique).Count -ne $Ids.Count){
        throw 'RELEASE_UNCERTAIN_SCOPE_INVALID'
    }
    foreach($Id in $Ids){
        if($Id -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'){
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

# Owner-provisioned immutable machine PowerShell identity: fixed Docker volume
# only, absent in all legacy Complete release records. No secret in Repo/argv.
function Read-MachinePowerShellVolume {
    param($Record)
    if($null -eq $Record){throw 'RELEASE_MACHINE_POWERSHELL_RECORD_INVALID'}
    if($Record -is [Collections.IDictionary]){
        if(-not $Record.Contains('machinePowerShellVolume')){return ''}
        $Value=$Record['machinePowerShellVolume']
    } else {
        $Prop=$Record.PSObject.Properties['machinePowerShellVolume']
        if($null -eq $Prop){return ''}
        $Value=$Prop.Value
    }
    if($Value -isnot [string] -or
       $Value -cnotin @('','fortis-r7-machine-powershell')){
        throw 'RELEASE_MACHINE_POWERSHELL_RECORD_INVALID'
    }
    return [string]$Value
}
function Read-MachinePowerShellDigest {
    param($Record)
    $Volume=Read-MachinePowerShellVolume $Record
    if($Record -is [Collections.IDictionary]){
        if(-not $Record.Contains('machinePowerShellDigest')){
            if($Volume){throw 'RELEASE_MACHINE_POWERSHELL_DIGEST_MISSING'}
            return ''
        }
        $Value=$Record['machinePowerShellDigest']
    } else {
        $Prop=$Record.PSObject.Properties['machinePowerShellDigest']
        if($null -eq $Prop){
            if($Volume){throw 'RELEASE_MACHINE_POWERSHELL_DIGEST_MISSING'}
            return ''
        }
        $Value=$Prop.Value
    }
    if($Value -isnot [string] -or
       ($Volume -and $Value -cnotmatch '^[0-9a-f]{64}$') -or
       (-not $Volume -and $Value -cne '')){
        throw 'RELEASE_MACHINE_POWERSHELL_DIGEST_INVALID'
    }
    return [string]$Value
}
function Image-MachinePowerShell-Preflight {
    param([string]$ImageId)
    # Verify all six files in the owner-provisioned Docker volume offline,
    # as the exact service UID; never copy/print key, bearer, CA or cert.
    $Name='fortis-r7-machine-powershell'
    Assert-Volume $Name
    Assert-OnlyWriter $Name
    $Code=@'
import sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.powershell_owner_mount import reviewed_machine_mount_digest
from fortis_approvals.r7_unified_candidate import ACTOR
print('FORTIS_MACHINE_POWERSHELL_MOUNT_SHA256=' + reviewed_machine_mount_digest(expected_actor=ACTOR))
'@
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<machine-powershell-mount>','exec'))"
    $Args=@('run','--rm','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','32','--memory','128m',
        '--mount',('type=volume,source='+$Name+',target=/run/fortis-machine-powershell,readonly'),
        '--entrypoint','python',$ImageId,'-I','-B','-c',$Wrapper)
    $Result=Private-Process $Args ''
    if($Result -cnotmatch '^FORTIS_MACHINE_POWERSHELL_MOUNT_SHA256=([0-9a-f]{64})$'){
        throw 'RELEASE_MACHINE_POWERSHELL_PREFLIGHT_FAILED'
    }
    return [string]$Matches[1]
}

# E1.3b Registry is an explicit owner Check/Apply exception, NOT -Auto.
# The reader activation volume is immutable per nonce so a new source image
# never requires rewriting the still-live Gateway's previous profile. Both
# mount destinations remain fixed, read-only and separately provisioned.
function Read-RegistryMountBinding {
    param($Record)
    if($null -eq $Record){throw 'RELEASE_REGISTRY_RECORD_INVALID'}
    $Values=@{}
    foreach($Name in @('registryReaderVolume','registrySocketVolume',
                        'registryReleaseNonce','registryProfileDigest')){
        if($Record -is [Collections.IDictionary]){
            if($Record.Contains($Name)){$Value=$Record[$Name]}
            else {$Value=''}
        } else {
            $Prop=$Record.PSObject.Properties[$Name]
            if($null -eq $Prop){$Value=''}
            else {$Value=$Prop.Value}
        }
        if($Value -isnot [string]){throw 'RELEASE_REGISTRY_RECORD_INVALID'}
        $Values[$Name]=[string]$Value
    }
    $Volume=$Values['registryReaderVolume'];$Socket=$Values['registrySocketVolume']
    $Nonce=$Values['registryReleaseNonce'];$Digest=$Values['registryProfileDigest']
    if(-not $Volume -and -not $Socket -and -not $Nonce -and -not $Digest){
        return [ordered]@{readerVolume='';socketVolume='';releaseNonce='';profileDigest=''}
    }
    if($Nonce -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
       $Volume -cne ('fortis-r7-registry-reader-'+$Nonce.Replace('-','')) -or
       ($Socket -cne 'fortis-registry-read' -and
        $Socket -cne ('fortis-registry-read-'+$Nonce.Replace('-',''))) -or
       $Digest -cnotmatch '^[0-9a-f]{64}$'){
        throw 'RELEASE_REGISTRY_RECORD_INVALID'
    }
    return [ordered]@{readerVolume=$Volume;socketVolume=$Socket
        releaseNonce=$Nonce;profileDigest=$Digest}
}

# The input RegistryReleaseNonce is a script parameter. Never use that
# same script-scoped name for derived state: initialization would erase the
# caller's nonce before history validation. Keep the derived binding separate.
function Initialize-RegistryReleaseBinding {
    param([bool]$Enabled,[string]$RequestedNonce)
    $script:RegistryBoundReleaseNonce='';$script:RegistryReaderVolume=''
    $script:RegistrySocketVolume='';$script:RegistryProfileDigest=''
    $script:RegistryGatewaySourceDigest=''
    if($Enabled){
        if($RequestedNonce -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'){
            throw 'RELEASE_REGISTRY_BINDING_NONCE_INVALID'
        }
        $script:RegistryBoundReleaseNonce=$RequestedNonce
        $script:RegistryReaderVolume=('fortis-r7-registry-reader-'+$RequestedNonce.Replace('-',''))
        $script:RegistrySocketVolume='fortis-registry-read'
    }
}

# Offline validation of protected owner record identity; the only exception
# is the original exact Check record for this Apply, never a release record.
function Assert-Registry-HistoryRecord {
    param($Record,[string]$Nonce,[bool]$AllowOriginalCheck=$false)
    if($null -eq $Record -or
       $Nonce -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'){
        throw 'RELEASE_REGISTRY_HISTORY_RECORD_INVALID'
    }
    # ConvertFrom-Json returns PSObjects and owner SelfTest uses StrictMode
    # Latest; absent optional legacy nonce must not throw a property exception.
    $SchemaField=$Record.PSObject.Properties['schema']
    if($null -eq $SchemaField){throw 'RELEASE_REGISTRY_HISTORY_RECORD_INVALID'}
    $Schema=$SchemaField.Value
    $Seen=''
    if($Schema -ceq 'fortis-extension-image-check-v1'){
        $PhaseField=$Record.PSObject.Properties['phase']
        $BindingField=$Record.PSObject.Properties['binding']
        if($null -eq $PhaseField -or $PhaseField.Value -cne 'Ready' -or
           $null -eq $BindingField -or $null -eq $BindingField.Value){
            throw 'RELEASE_REGISTRY_HISTORY_RECORD_INVALID'
        }
        $NonceField=$BindingField.Value.PSObject.Properties['registryReleaseNonce']
        if($null -ne $NonceField){$Seen=$NonceField.Value}
    } elseif($Schema -ceq 'fortis-extension-release-v1'){
        $RuntimeField=$Record.PSObject.Properties['runtime']
        if($null -eq $RuntimeField -or $null -eq $RuntimeField.Value){
            throw 'RELEASE_REGISTRY_HISTORY_RECORD_INVALID'
        }
        $NonceField=$RuntimeField.Value.PSObject.Properties['registryReleaseNonce']
        if($null -ne $NonceField){$Seen=$NonceField.Value}
    } else {
        throw 'RELEASE_REGISTRY_HISTORY_RECORD_INVALID'
    }
    if($null -eq $Seen){$Seen=''}
    if($Seen -isnot [string] -or ($Seen -cne '' -and
       $Seen -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')){
        throw 'RELEASE_REGISTRY_HISTORY_RECORD_INVALID'
    }
    if($Seen -ceq $Nonce -and -not ($AllowOriginalCheck -and
       $Schema -ceq 'fortis-extension-image-check-v1')){
        throw 'RELEASE_REGISTRY_NONCE_REUSE_DENIED'
    }
}
# Do not silently recycle a nonce from any retained owner release/check.
# In Apply, the one original protected Check record may mention the nonce;
# every OTHER historical owner record is a conflict. Missing/invalid private
# record ACLs STOP instead of being interpreted as an empty history.
function Assert-Registry-Nonce-Fresh {
    param([string]$Nonce,[string]$AllowedCheckRecord='')
    Assert-DirectoryAcl $ReleaseBase
    $Rows=@(Get-ChildItem -LiteralPath $ReleaseBase -Directory -Force)
    if($Rows.Count -gt 4096){throw 'RELEASE_REGISTRY_HISTORY_TOO_LARGE'}
    foreach($Entry in $Rows){
        # Owner records cannot be silently hidden by directory links, missing
        # record files, or an unrecognized protected record structure.
        if($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint){
            throw 'RELEASE_REGISTRY_HISTORY_REPARSE_DENIED'
        }
        if($Entry.Name -cnotmatch '^(?:[0-9a-f]{32}|image-check-[0-9a-f]{32})$'){continue}
        $RecordPath=Join-Path $Entry.FullName 'record.json'
        $SameOriginalCheck=($AllowedCheckRecord -and
            [IO.Path]::GetFullPath($RecordPath) -ceq [IO.Path]::GetFullPath($AllowedCheckRecord))
        if(-not (Test-Path -LiteralPath $RecordPath -PathType Leaf)){
            # An interrupted exact successor Check may have created its
            # private attempt directory but not yet stored the receipt.
            if($Action -ceq 'Check' -and $SuccessorContext -and $SameOriginalCheck -and
               -not (Test-Path -LiteralPath $RecordPath)){
                Assert-DirectoryAcl $Entry.FullName
                continue
            }
            throw 'RELEASE_REGISTRY_HISTORY_RECORD_MISSING'
        }
        $Record=Read-Private $RecordPath
        Assert-Registry-HistoryRecord -Record $Record -Nonce $Nonce -AllowOriginalCheck ([bool]$SameOriginalCheck)
    }
}
function Image-Registry-Source-Digest {
    param([string]$ImageId)
    if($ImageId -cnotmatch '^sha256:[0-9a-f]{64}$'){
        throw 'RELEASE_REGISTRY_SOURCE_IMAGE_INVALID'
    }
    $Code=@'
import sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.r7_unified_server import _installed_policy_source_digest
print('FORTIS_REGISTRY_GATEWAY_SOURCE_SHA256=' + _installed_policy_source_digest())
'@
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<registry-source-digest>','exec'))"
    $Args=@('run','--rm','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL',
        '--security-opt','no-new-privileges:true','--pids-limit','32','--memory','128m',
        '--entrypoint','python',$ImageId,'-I','-B','-c',$Wrapper)
    $Result=Private-Process $Args ''
    if($Result -cnotmatch '^FORTIS_REGISTRY_GATEWAY_SOURCE_SHA256=([0-9a-f]{64})$'){
        throw 'RELEASE_REGISTRY_SOURCE_DIGEST_READBACK_FAILED'
    }
    return [string]$Matches[1]
}
function Image-RegistryMount-Preflight {
    param([string]$ImageId,[string]$ReleaseNonce,[string]$ReaderVolume)
    # Never provision source, identity, nonce, or volume here; a protected
    # operator independently seals the exact source/boot/process pins first.
    if($ImageId -cnotmatch '^sha256:[0-9a-f]{64}$' -or
       $ReleaseNonce -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
       $ReaderVolume -cne ('fortis-r7-registry-reader-'+$ReleaseNonce.Replace('-',''))){
        throw 'RELEASE_REGISTRY_PREFLIGHT_ARGUMENTS_INVALID'
    }
    Assert-Volume $ReaderVolume
    Assert-Volume 'fortis-registry-read'
    Assert-OnlyWriter $ReaderVolume
    $Code=@'
import inspect,sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.r7_unified_server import _installed_policy_source_digest
from fortis_approvals.r7_registry_reader_mount import reviewed_registry_reader_mount_digest
nonce=sys.stdin.buffer.read(128).decode('ascii')
options={'legacy_only':True} if 'legacy_only' in inspect.signature(reviewed_registry_reader_mount_digest).parameters else {}
print('FORTIS_REGISTRY_READER_MOUNT_SHA256=' + reviewed_registry_reader_mount_digest(
    expected_release_nonce=nonce, expected_source_digest=_installed_policy_source_digest(), **options))
'@
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<registry-owner-preflight>','exec'))"
    $Args=@('run','--rm','-i','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL',
        '--security-opt','no-new-privileges:true',
        '--pids-limit','32','--memory','128m',
        '--mount',('type=volume,source='+$ReaderVolume+',target=/run/r7-registry-reader,readonly'),
        '--mount','type=volume,source=fortis-registry-read,target=/run/fortis-registry-read,readonly',
        '--entrypoint','python',$ImageId,'-I','-B','-c',$Wrapper)
    $Result=Private-Process $Args $ReleaseNonce
    if($Result -cnotmatch '^FORTIS_REGISTRY_READER_MOUNT_SHA256=([0-9a-f]{64})$'){
        throw 'RELEASE_REGISTRY_PREFLIGHT_FAILED'
    }
    return [string]$Matches[1]
}

function Read-Corrective288Anchor {
    param($Source)
    $Run='6ec445e6191543e7873275166922010b'
    $Nonce='3ac0e38d-2618-4b51-8900-97107f727785'
    $SourceHash='ea25b6d0769059e225c584a7a5518d6cedd0e8f3f138b1cb29f7194c09cc195c'
    $PriorHash='f7cdb097e257e471bd19292286d2b876cef9d0eb3059b28f539986fec7cd290b'
    $Digest='9dd0e18b2f10e5180fccd5831ff6528e973813d0fe0cf29a826bc20c750a18a3'
    $Generation='906410832e42b5f8dc835e20c75fe79bfebbcbf9d149793111a3d67992f377aa'
    if($Source.hash -ine $SourceHash -or $Source.runtime.runId -cne $Run -or
       $Source.path -cne (Join-Path $ReleaseBase ($Run+'\record.json')) -or
       $Source.runtime.registryReleaseNonce -cne $Nonce -or
       $Source.runtime.maintenanceGeneration -cne $Generation -or
       $Source.runtime.registryDelivery.sourceDelivery.interlockDigest -cne $Digest -or
       (Read-Private $Pointer).record -cne $Source.path -or
       (Test-Path -LiteralPath (Join-Path $ReleaseBase ('maintenance-'+$Run+'.json')))){
        throw 'RELEASE_CORRECTIVE_288_SOURCE_CHANGED'
    }
    Assert-Registry288RecoveredProfile $Source.runtime '86722403363418162f179ccdbb14fa7368a5eede4e5c7ba6806cbb4402e92b17'
    $Prior=Read-Private $Source.path
    if($Prior.source.hash -ine $PriorHash -or
       (Get-FileHash -LiteralPath $Prior.source.path -Algorithm SHA256).Hash -ine $PriorHash){
        throw 'RELEASE_CORRECTIVE_288_SOURCE_CHANGED'
    }
    # Reuse the exact original genesis publication; do NOT create a new
    # NORMAL record or write to the live shared interlock.
    $Anchor=Read-Private (Join-Path $ReleaseBase ('maintenance-publication-'+$Nonce.Replace('-','')+'.json'))
    if($Anchor.schema -cne 'fortis-successor-maintenance-publication-v1' -or
       $Anchor.state -cne 'Committed' -or $Anchor.sourceRecordHash -ine $PriorHash -or
       $Anchor.digest -cne $Digest -or $Anchor.record.schemaVersion -ne 1 -or
       $Anchor.record.phase -cne 'NORMAL' -or $Anchor.record.generation -cne $Generation -or $Anchor.record.sequence -ne 0 -or
       $Anchor.record.registryInstanceId -cne '08ef25a7-defb-4c7a-ac83-26ba8f994fc0' -or
       $Anchor.record.scopeDigest -cne 'ec59ce507d1e0bb29cf94a9c8d1571367aca0549ddf60305031f7d6b409aefce' -or
       $null -ne $Anchor.record.attempt -or $null -ne $Anchor.record.previousDigest -or
       $null -ne $Anchor.record.proofDigest){
        throw 'RELEASE_CORRECTIVE_288_ANCHOR_CHANGED'
    }
    return $Anchor
}
function Read-RegistrySuccessorAnchor {
    param($Source)
    if($Corrective288){return (Read-Corrective288Anchor $Source)}
    # The existing controller journal owns the committed phase. Target
    # material is keyed by the owner-sealed release nonce, outside /state.
    $Id=$script:RegistryBoundReleaseNonce.Replace('-','')
    $Path=Join-Path $ReleaseBase ('maintenance-publication-'+$Id+'.json')
    if(-not (Test-Path -LiteralPath $Path)){return}
    $Anchor=Read-Private $Path
    if($Anchor.schema -cne 'fortis-successor-maintenance-publication-v1' -or
       $Anchor.state -cne 'Committed' -or $Anchor.sourceRecordHash -cne $Source.hash -or
       $Anchor.digest -cnotmatch '^[0-9a-f]{64}$' -or $Anchor.record.phase -cne 'NORMAL' -or
       $Anchor.record.generation -cnotmatch '^[0-9a-f]{64}$'){
        throw 'RELEASE_REGISTRY_SUCCESSOR_ANCHOR_CHANGED'
    }
    return $Anchor
}
function Assert-RegistrySuccessorCompanionPreflight {
    param($Result,[string]$IncumbentVolume,$ExpectedExisting=$null)
    $Legacy=$Result.PSObject.Properties['legacyCompanion']
    $Existing=$Result.PSObject.Properties['existingCompanion']
    if(-not $IncumbentVolume){
        if($Legacy -or $Existing -or $ExpectedExisting){throw 'RELEASE_REGISTRY_SUCCESSOR_PREFLIGHT_UNCONFIRMED'}
        return
    }
    if([bool]$Legacy -eq [bool]$Existing){throw 'RELEASE_REGISTRY_SUCCESSOR_PREFLIGHT_UNCONFIRMED'}
    if($Legacy){
        if($ExpectedExisting -or $Legacy.Value.schemaDigest -cnotmatch '^[0-9a-f]{64}$' -or
           $Legacy.Value.coreRowsDigest -cnotmatch '^[0-9a-f]{64}$'){
            throw 'RELEASE_REGISTRY_SUCCESSOR_PREFLIGHT_UNCONFIRMED'
        }
    } else {
        # Legacy #288 exception stays narrow. A latest-pin handover instead
        # consumes the independently sealed incumbent companion witness
        # from the exact protected Check; not a new historical volume list.
        if(($ExpectedExisting -and
            ($IncumbentVolume -cnotmatch '^fortis-github-pilot-state-[0-9a-f]{32}$' -or
             -not (Same-Json $Existing.Value $ExpectedExisting))) -or
           (-not $ExpectedExisting -and $IncumbentVolume -cne 'fortis-github-pilot-state-6ec445e6191543e7873275166922010b') -or
           $Existing.Value.schemaDigest -cnotmatch '^[0-9a-f]{64}$' -or
           $Existing.Value.companionDigest -cne $Result.companionDigest -or
           $Existing.Value.authorityWitnessDigest -cnotmatch '^[0-9a-f]{64}$'){
            throw 'RELEASE_REGISTRY_SUCCESSOR_PREFLIGHT_UNCONFIRMED'
        }
    }
}
function Image-RegistrySuccessor-Preflight {
    param([string]$ImageId,[string]$ReleaseNonce,[string]$InterlockDigest,[string]$IncumbentVolume='', [switch]$LatestPin, [switch]$RunningSource,$ExpectedExisting=$null)
    if(([bool]$ExpectedExisting -ne [bool]($LatestPin -and $IncumbentVolume)) -or ($RunningSource -and (-not $LatestPin -or $IncumbentVolume)) -or $ImageId -cnotmatch '^sha256:[0-9a-f]{64}$' -or
       $ReleaseNonce -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
       $InterlockDigest -cnotmatch '^[0-9a-f]{64}$' -or
       ($IncumbentVolume -and $IncumbentVolume -cnotmatch '^fortis-github-pilot-state-[0-9a-f]{32}$')){
        throw 'RELEASE_REGISTRY_SUCCESSOR_PREFLIGHT_ARGUMENTS_INVALID'
    }
    $Id=$ReleaseNonce.Replace('-','')
    $Reader='fortis-r7-registry-reader-'+$Id
    $Socket='fortis-registry-read-'+$Id
    $Evidence='fortis-registry-source-evidence-'+$Id
    $Interlock=if($LatestPin){'fortis-r7-maintenance-interlock-v2'}else{'fortis-r7-maintenance-interlock'}
    foreach($Volume in @($Reader,$Socket,$Evidence,$Interlock)){Assert-Volume $Volume}
    if($LatestPin){Assert-Volume 'fortis-r7-maintenance-anchor'}
    Assert-OnlyWriter $Reader
    if($IncumbentVolume){Assert-OnlyWriter $Evidence}
    $Code=@'
import json,sys
from pathlib import Path
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.r7_unified_server import _installed_policy_source_digest
from fortis_approvals.r7_registry_reader_mount import reviewed_successor_delivery, _check_owner_readonly_mount
p=json.load(sys.stdin)
core=None
if p['inspectIncumbent']:
    root=Path('/source')
    _check_owner_readonly_mount(root)
    core=root/'private'/'approvals.sqlite'
# The historical immutable image does not know the new optional kwarg.
extra={'running_source':True} if p.get('runningSource') else {}
result=reviewed_successor_delivery(expected_release_nonce=p['nonce'],
    expected_source_digest=_installed_policy_source_digest(),
    expected_interlock_digest=p['interlockDigest'], incumbent_core=core,
    scratch_root=Path('/run/fortis-copy-check') if core is not None else None,**extra)
print(json.dumps(result,separators=(',',':'),sort_keys=True))
'@
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<registry-successor-preflight>','exec'))"
    $Memory=if($IncumbentVolume){'1536m'}else{'256m'}
    $Args=@('run','--rm','-i','--pull=never','--network','none','--read-only','--user','10001:10001',
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','32','--memory',$Memory,
        '--mount',('type=volume,source='+$Reader+',target=/run/r7-registry-reader,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$Socket+',target=/run/fortis-registry-read,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$Evidence+',target=/run/fortis-registry-source-evidence,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$Interlock+',target=/run/r7-maintenance,readonly,volume-nocopy'))
    if($LatestPin){
        $Args+=@('--mount','type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,readonly,volume-nocopy')
    }
    if($IncumbentVolume){
        Assert-Volume $IncumbentVolume
        $Args+=@('--mount',('type=volume,source='+$IncumbentVolume+',target=/source,readonly,volume-nocopy'),
            '--tmpfs','/run/fortis-copy-check:rw,noexec,nosuid,nodev,size=1g,uid=10001,gid=10001,mode=0700')
    }
    $Args+=@('--entrypoint','python',$ImageId,'-I','-B','-c',$Wrapper)
    $Payload=ConvertTo-Json -Compress -InputObject @{nonce=$ReleaseNonce
        interlockDigest=$InterlockDigest;inspectIncumbent=[bool]$IncumbentVolume;runningSource=[bool]$RunningSource}
    $WaitMs=if($IncumbentVolume){300000}else{120000}
    $Result=(Private-Process $Args $Payload -WaitTimeoutMs $WaitMs)|ConvertFrom-Json
    if($Result.profileDigest -cnotmatch '^[0-9a-f]{64}$' -or
       $Result.companionDigest -cnotmatch '^[0-9a-f]{64}$' -or
       $Result.generation -cnotmatch '^[0-9a-f]{64}$' -or
       $Result.sourceDelivery.interlockDigest -cne $InterlockDigest -or
       ([bool]$LatestPin -ne (Test-SuccessorLatestDelivery $Result))){
        throw 'RELEASE_REGISTRY_SUCCESSOR_PREFLIGHT_UNCONFIRMED'
    }
    Assert-RegistrySuccessorCompanionPreflight $Result $IncumbentVolume $ExpectedExisting
    return $Result
}
function Read-PairedGatewayMaterial {
    param($Source,[switch]$Ordinary)
    $OldReader=$Source.runtime.registryReaderVolume
    $Reader=$script:RegistryReaderVolume+'-prepared'
    foreach($V in @($OldReader,$Reader,$script:RegistryReaderVolume,$Source.runtime.stateVolume)){Assert-Volume $V}
    Assert-OnlyWriter $OldReader;Assert-OnlyWriter $Reader
    $OldSourceDigest=Image-Registry-Source-Digest -ImageId $Source.runtime.image
    $GatewayCode=@'
import json,sys
from pathlib import Path
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.r7_unified_server import _installed_policy_source_digest
from fortis_approvals.r7_registry_reader_mount import reviewed_bootstrap_gateway,inspect_bootstrap_empty_profile_target
p=json.load(sys.stdin)
actual=_installed_policy_source_digest()
if actual!=p['sourceDigest']:raise RuntimeError('BOOTSTRAP_GATEWAY_SOURCE_CHANGED')
result=reviewed_bootstrap_gateway(expected_release_nonce=p['nonce'],expected_source_digest=actual,
    incumbent_nonce=p['oldNonce'],incumbent_source_digest=p['oldSourceDigest'],
    incumbent_profile_digest=p['oldProfileDigest'],incumbent_core=Path('/source/private/approvals.sqlite'),ordinary=p['ordinary'])
print(json.dumps({'material':result,'finalRoot':inspect_bootstrap_empty_profile_target()},sort_keys=True,separators=(',',':')))
'@
    $GatewayArgs=@('run','--rm','-i','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','32','--memory','512m',
        '--mount',('type=volume,source='+$OldReader+',target=/run/r7-registry-incumbent-reader,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$Reader+',target=/run/r7-registry-reader,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$script:RegistryReaderVolume+',target=/target,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$Source.runtime.stateVolume+',target=/source,readonly,volume-nocopy'),
        $script:Image)
    $GatewayInput=ConvertTo-Json -Compress @{nonce=$script:RegistryBoundReleaseNonce;sourceDigest=$script:RegistryGatewaySourceDigest
        oldNonce=$Source.runtime.registryReleaseNonce;oldSourceDigest=$OldSourceDigest;oldProfileDigest=$Source.runtime.registryProfileDigest;ordinary=[bool]$Ordinary}
    $GatewayRead=(Python-Code $GatewayArgs $GatewayCode $GatewayInput)|ConvertFrom-Json
    return $GatewayRead
}

function Read-BootstrapCompatibility {
    param($Source,[switch]$Recheck)
    $Anchor=Read-BootstrapSeedSource $Source -Live
    $Id=$script:RegistryBoundReleaseNonce.Replace('-','')
    Assert-CorrectiveTargetHolders $script:RegistryBoundReleaseNonce @() -PreparedProfiles
    $RegistryInfo=@(Docker-Json @('image','inspect',$BootstrapRegistryImage))[0]
    $GatewayInfo=@(Docker-Json @('image','inspect',$script:Image))[0]
    if($GatewayInfo.Id -cne $script:Image -or @($GatewayInfo.Config.Entrypoint | Where-Object {$_}).Count -or
       @($RegistryInfo.Config.Entrypoint | Where-Object {$_}).Count){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_IMAGE_CHANGED'
    }
    if($RegistryInfo.Id -cne $BootstrapRegistryImage -or $RegistryInfo.Config.User -cne '20002:20002' -or
       $RegistryInfo.Os -cne 'linux' -or $RegistryInfo.Architecture -cne 'amd64' -or
       $RegistryInfo.Config.Labels.'org.opencontainers.image.revision' -cne $SourceSha){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_IMAGE_CHANGED'
    }
    $OldReader=$Source.runtime.registryReaderVolume
    $Reader=$script:RegistryReaderVolume+'-prepared'
    $State='fortis-registry-state-e13b-'+$Id
    $RegistryConfig='fortis-registry-config-e13b-'+$Id+'-prepared'
    $BackupVolume='fortis-registry-backup-68f27953baaa4f18a4695d4762d3480b'
    foreach($Volume in @($OldReader,$Reader,$Source.runtime.stateVolume,$State,$RegistryConfig,$BackupVolume,$script:RegistryReaderVolume,
        ('fortis-registry-config-e13b-'+$Id),('fortis-registry-read-'+$Id),('fortis-registry-source-evidence-'+$Id),
        ('fortis-registry-source-'+$Id),('fortis-registry-bootstrap-backup-'+$Id),'fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor')){
        Assert-Volume $Volume
    }
    foreach($Volume in @($OldReader,$Reader,$State,$RegistryConfig,$BackupVolume)){Assert-OnlyWriter $Volume}
    Assert-ReleaseVolumeHolders @('fortis-registry-bootstrap-backup-'+$Id) @() 'RELEASE_SUCCESSOR_BOOTSTRAP_BACKUP_HOLDER_CHANGED'
    $GatewayRead=Read-PairedGatewayMaterial $Source
    $Gateway=$GatewayRead.material
    $RegistryCode=@'
import json,sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.registry.owner_functional_v1_bootstrap import (
    inspect_bootstrap_pair,bootstrap_compatibility_digest,verify_bootstrap_backup)
from fortis_approvals.r7_registry_reader_mount import inspect_bootstrap_empty_profile_target
from pathlib import Path
p=json.load(sys.stdin)
registry=inspect_bootstrap_pair(p['profile'],review_sha256=p['review'],evidence_sha256=p['evidence'],source_sha=p['source'])
if registry['review']['registryBackupDigest']!=p['backup']:
    raise RuntimeError('SOURCE_BOOTSTRAP_BACKUP_CHANGED')
if not p['recheck']:verify_bootstrap_backup(p['backup'])
checked={'gateway':p['gateway'],'registry':registry,'artifacts':p['artifacts']}
print(json.dumps({'checked':checked,'compatibilityDigest':bootstrap_compatibility_digest(checked),
                  'finalRoot':inspect_bootstrap_empty_profile_target(),'backupRoot':inspect_bootstrap_empty_profile_target(Path('/reserve'))},
                 sort_keys=True,separators=(',',':')))
'@
    $RegistryArgs=@('run','--rm','-i','--pull=never','--network','none','--read-only',
        '--user','20002:20002','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','32','--memory','512m',
        '--mount',('type=volume,source='+$State+',target=/run/fortis-registry-state,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$RegistryConfig+',target=/run/fortis-registry-runtime,readonly,volume-nocopy'),
        '--mount',('type=volume,source=fortis-registry-config-e13b-'+$Id+',target=/target,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$BackupVolume+',target=/run/fortis-registry-backup,readonly,volume-nocopy'),
        '--mount',('type=volume,source=fortis-registry-bootstrap-backup-'+$Id+',target=/reserve,readonly,volume-nocopy'),
        $BootstrapRegistryImage)
    $Artifacts=@{gateway=$script:Image.Substring(7);registry=$BootstrapRegistryImage.Substring(7)}
    $Backup='384ce6e58fd8103a187c411e6ae87d1d7063d1d9822a7463b401c0785effe57a'
    $RegistryInput=ConvertTo-Json -Compress -Depth 20 @{profile=$BootstrapRegistryProfileSha256;review=$BootstrapReviewSha256
        evidence=$BootstrapEvidenceSha256;source=$SourceSha;gateway=$Gateway;artifacts=$Artifacts;backup=$Backup;recheck=[bool]$Recheck}
    $Result=(Python-Code $RegistryArgs $RegistryCode $RegistryInput)|ConvertFrom-Json
    $Review=$Result.checked.registry.review
    $BackupPath=(Read-Private (Join-Path $ReleaseBase 'primary-backup.json')).record
    $BackupRecord=Read-Private $BackupPath
    if($Review.primaryRecordDigest -cne '1a4a83906c54f878f21f7acec0c999d4ecfa09e9efa5e2c65be70679a30f2e2d' -or
       $Review.gatewayBackupDigest -cne '615875561e72018e90e2ce3719b8dcda30656edd8efb9f305eb39fb86b2ec25d' -or
       (Get-FileHash -LiteralPath $BackupPath -Algorithm SHA256).Hash -ine $Review.gatewayBackupDigest -or
       $BackupRecord.schema -cne 'fortis-primary-backup-v1' -or $BackupRecord.phase -cne 'Complete' -or
       $BackupRecord.sourceRecord -cne $Source.path -or $BackupRecord.sourceHash -ine $Source.hash -or
       (-not $Recheck -and -not (Same-Json (Receipt $BackupRecord.backupVolume) $BackupRecord.receipt)) -or
       $Review.registryBackupDigest -cne $Backup -or
       $Result.compatibilityDigest -cnotmatch '^[0-9a-f]{64}$' -or
       $Result.checked.gateway.profileDigest -cne $Gateway.profileDigest -or
       $Result.checked.registry.profileDigest -cne $BootstrapRegistryProfileSha256 -or
       $Result.checked.registry.checkpoint.sourceCursor -cne $SourceSha -or
       $Result.checked.registry.checkpoint.sourceRevision -ne 4 -or
       $Result.checked.registry.checkpoint.snapshotRevision -ne 4 -or
       $Result.checked.registry.binding.interlockDigest -cne $Anchor.digest -or
       $Result.checked.registry.binding.generation -cne $Anchor.record.generation){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_COMPATIBILITY_CHANGED'
    }
    Assert-CorrectiveTargetHolders $script:RegistryBoundReleaseNonce @() -PreparedProfiles
    if(-not (Same-Json (Read-BootstrapSeedSource $Source -Live) $Anchor)){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_COMPATIBILITY_CHANGED'
    }
    $Pair=[ordered]@{registryImage=$BootstrapRegistryImage;registryProfileSha256=$BootstrapRegistryProfileSha256
        reviewSha256=$BootstrapReviewSha256;evidenceSha256=$BootstrapEvidenceSha256
        checked=$Result.checked;compatibilityDigest=$Result.compatibilityDigest
        finalRoots=[ordered]@{Gateway=$GatewayRead.finalRoot;Registry=$Result.finalRoot}
        backupRoot=$Result.backupRoot}
    $null=Read-BootstrapOwnerReviewProof $BootstrapReviewProofRecord $Pair
    return $Pair
}
function Read-OrdinarySuccessorSource {
    param($Source,[switch]$PublicationRecovery,[switch]$Frozen,[string[]]$CandidateIds=@())
    $P=$Source.runtime
    $Release=Read-Private $Source.path
    $Primary=Read-Private $PrimaryPointer
    if(-not (Test-SuccessorLatestDelivery $P.registryDelivery) -or
       -not $ConfirmWorkerQuiescent -or $Release.schema -cne 'fortis-extension-release-v1' -or
       $Release.phase -cne 'Complete' -or $Release.activated -ne $true -or $Release.probesPassed -ne $true -or
       (Read-Private $Pointer).record -cne $Source.path -or $Primary.sourceRecord -cne $Source.path -or
       $Primary.sourceHash -ine $Source.hash -or -not (Same-Json $Primary.runtime $P) -or
       (Get-FileHash -LiteralPath $Source.path -Algorithm SHA256).Hash -ine $Source.hash -or
       -not (Same-Json $Release.runtime.registryDelivery $P.registryDelivery)){
        throw 'RELEASE_SUCCESSOR_ORDINARY_SOURCE_CHANGED'
    }
    # The first installed latest-pin release carries this exact paired
    # receiver record; later ordinary handovers retain the same binding.
    $Receiver=$Release.bootstrapReceiver
    $G=Container $P.pilotId;$R=Container $Receiver.id
    if(($Frozen -and ($G.State.Status -cne 'exited' -or $R.State.Status -cne 'exited' -or
        $G.HostConfig.RestartPolicy.Name -cne 'no' -or $R.HostConfig.RestartPolicy.Name -cne 'no')) -or
       ($PublicationRecovery -and ($G.State.Status -cnotin @('running','exited') -or
        $R.State.Status -cnotin @('running','exited'))) -or
       (-not ($PublicationRecovery -or $Frozen) -and ($G.State.Status -cne 'running' -or $G.State.Health.Status -cne 'healthy')) -or
       $R.Id -cne $Receiver.id -or $Receiver.profileDigest -cne $Release.bootstrapMaterials.registryProfileDigest -or
       $Receiver.generation -cne $P.maintenanceGeneration){
        throw 'RELEASE_SUCCESSOR_ORDINARY_SOURCE_CHANGED'
    }
    $Commit=@(Docker-Json @('image','inspect',$P.image))[0].Config.Labels.'org.opencontainers.image.revision'
    if($Commit -cnotmatch '^[0-9a-f]{40}$'){throw 'RELEASE_SUCCESSOR_ORDINARY_SOURCE_CHANGED'}
    if($PublicationRecovery -or $Frozen){
        # Exact already-accepted source, even if a pending phase prevented
        # its restart. This is structural readback for the publisher only.
        if($R.Config.Labels.'org.opencontainers.image.revision' -cne $Commit){throw 'RELEASE_SUCCESSOR_ORDINARY_SOURCE_CHANGED'}
        if($R.HostConfig.RestartPolicy.Name -ceq 'no'){
            Assert-CorrectiveRegistryContainer $R $P.registryReleaseNonce $Receiver.image $Receiver.profileDigest 'writer' $Commit -Status $R.State.Status -LatestPin
        }else{
            Assert-CorrectiveRegistryContainer $R $P.registryReleaseNonce $Receiver.image $Receiver.profileDigest 'source' $Commit -Status $R.State.Status -LatestPin
        }
    }else{
        Assert-CorrectiveRegistryContainer $R $P.registryReleaseNonce $Receiver.image $Receiver.profileDigest 'writer' $Commit -Status running -LatestPin -Accepted
    }
    Assert-CorrectiveTargetHolders $P.registryReleaseNonce @($G.Id,$R.Id)
    Assert-OperationalMaintenanceHolders $Source (@($G.Id,$R.Id)+$CandidateIds) 'RELEASE_SUCCESSOR_ORDINARY_SOURCE_CHANGED'
    # Structural admission here also works during a lost begin ACK, when
    # NORMAL with an actual hold must not pass full startup admission.
    if($G.HostConfig.RestartPolicy.Name -ceq 'no' -and ($PublicationRecovery -or $Frozen)){
        Admit $G $P -RegistryReturnSource -AllowUnhealthy -RetainedMaintenance
    }else{Admit $G $P -RegistryReturnSource -AllowUnhealthy:($PublicationRecovery -or $Frozen)}
    if($Frozen){
        Assert-OnlyWriter $P.stateVolume
        Assert-OnlyWriter ('fortis-registry-state-e13b-'+$P.registryReleaseNonce.Replace('-',''))
    }else{
        Assert-OnlyWriter $P.stateVolume $G.Id
        Assert-OnlyWriter ('fortis-registry-state-e13b-'+$P.registryReleaseNonce.Replace('-','')) $R.Id
    }
    return @{gateway=$G;registry=$R;receiver=$Receiver}
}

function Read-OrdinarySuccessorCompatibility {
    param($Source,$Publication)
    $SourcePair=Read-OrdinarySuccessorSource $Source
    if($Publication.schema -cne 'fortis-successor-maintenance-publication-v2' -or
       $Publication.state -cne 'Committed' -or $Publication.record.phase -cne 'NORMAL' -or
       -not (Same-Json (Read-SuccessorPublication $Source).anchor $Publication)){
        throw 'RELEASE_SUCCESSOR_ORDINARY_SOURCE_CHANGED'
    }
    $P=$Source.runtime;$Id=$script:RegistryBoundReleaseNonce.Replace('-','');$OldId=$P.registryReleaseNonce.Replace('-','')
    Assert-CorrectiveTargetHolders $script:RegistryBoundReleaseNonce @() -PreparedProfiles
    $Target=@(Docker-Json @('image','inspect',$SuccessorRegistryImage))[0]
    $GatewayInfo=@(Docker-Json @('image','inspect',$script:Image))[0]
    if($GatewayInfo.Id -cne $script:Image -or @($GatewayInfo.Config.Entrypoint|Where-Object{$_}).Count -or
       $Target.Id -cne $SuccessorRegistryImage -or $Target.Config.User -cne '20002:20002' -or
       $Target.Os -cne 'linux' -or $Target.Architecture -cne 'amd64' -or
       @($Target.Config.Entrypoint|Where-Object{$_}).Count -or
       $Target.Config.Labels.'org.opencontainers.image.revision' -cne $SourceSha){
        throw 'RELEASE_SUCCESSOR_ORDINARY_IMAGE_CHANGED'
    }
    $GatewayRead=Read-PairedGatewayMaterial $Source -Ordinary
    $RegistryCode=@'
import json,sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.registry.owner_functional_v1_bootstrap import inspect_ordinary_pair
from fortis_approvals.r7_registry_reader_mount import inspect_bootstrap_empty_profile_target
from pathlib import Path
from fortis_approvals.integrations.registry_contracts import maintenance_contract as mc, semantic_contract as sc
p=json.load(sys.stdin)
r=inspect_ordinary_pair(p['profile'],incumbent_profile_sha256=p['oldProfile'],source_sha=p['source'],normal=p['normal'])
roots={'gateway':p['gatewayRoot'],'registry':inspect_bootstrap_empty_profile_target(),
       'state':inspect_bootstrap_empty_profile_target(Path('/state-target')),
       'backup':inspect_bootstrap_empty_profile_target(Path('/reserve'))}
checked={'gateway':p['gateway'],'registry':r,'artifacts':p['artifacts'],'roots':roots}
auth={**p['authorization'],'compatibilityDigest':sc.digest(checked),'normalDigest':sc.digest(p['normal'])}
intent={'schemaVersion':1,'normal':p['normal'],'authorization':auth,'compatibility':checked}
pair=mc.ordinary_pair_intent(intent)
print(json.dumps({'intent':intent,'intentDigest':sc.digest(intent),'pairDigest':sc.digest(pair),'registryDigest':sc.digest(r['holdSnapshot'])},sort_keys=True,separators=(',',':')))
'@
    $Mounts=@(
        ('type=volume,source=fortis-registry-state-e13b-'+$OldId+',target=/run/fortis-registry-state,readonly,volume-nocopy'),
        ('type=volume,source=fortis-registry-config-e13b-'+$OldId+',target=/run/fortis-registry-incumbent-runtime,readonly,volume-nocopy'),
        ('type=volume,source=fortis-registry-config-e13b-'+$Id+'-prepared,target=/run/fortis-registry-runtime,readonly,volume-nocopy'),
        ('type=volume,source=fortis-registry-config-e13b-'+$Id+',target=/target,readonly,volume-nocopy'),
        ('type=volume,source=fortis-registry-state-e13b-'+$Id+',target=/state-target,readonly,volume-nocopy'),
        ('type=volume,source=fortis-registry-bootstrap-backup-'+$Id+',target=/reserve,readonly,volume-nocopy'),
        'type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,readonly,volume-nocopy',
        'type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,readonly,volume-nocopy')
    foreach($V in @(('fortis-registry-state-e13b-'+$OldId),('fortis-registry-config-e13b-'+$OldId),
        ('fortis-registry-config-e13b-'+$Id+'-prepared'),('fortis-registry-config-e13b-'+$Id),
        ('fortis-registry-state-e13b-'+$Id),('fortis-registry-bootstrap-backup-'+$Id),'fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor')){Assert-Volume $V}
    Assert-OnlyWriter ('fortis-registry-config-e13b-'+$Id+'-prepared')
    Assert-ReleaseVolumeHolders @('fortis-registry-bootstrap-backup-'+$Id) @() 'RELEASE_SUCCESSOR_ORDINARY_RESERVE_CHANGED'
    $Args=@('run','--rm','-i','--pull=never','--network','none','--read-only','--user','20002:20002',
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','32','--memory','1024m',
        '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=640m,uid=20002,gid=20002,mode=0700')
    foreach($Mount in $Mounts){$Args+=@('--mount',$Mount)}
    $Args+=@($SuccessorRegistryImage)
    $Auth=@{attemptId=[Guid]::NewGuid().ToString('D');sourceRecordDigest=$Source.hash.ToLowerInvariant()
        targetNonce=$script:RegistryBoundReleaseNonce;recordedAt=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        targetGeneration=(Sha256-Utf8 ([Guid]::NewGuid().ToString('D')+[Guid]::NewGuid().ToString('D'))).ToLowerInvariant()}
    $InputText=ConvertTo-Json -Compress -Depth 25 @{profile=$SuccessorRegistryProfileSha256;oldProfile=$SourcePair.receiver.profileDigest
        source=$SourceSha;gateway=$GatewayRead.material;gatewayRoot=$GatewayRead.finalRoot;normal=$Publication.record;authorization=$Auth
        artifacts=@{gateway=$script:Image.Substring(7);registry=$SuccessorRegistryImage.Substring(7)}}
    $Result=(Python-Code $Args $RegistryCode $InputText)|ConvertFrom-Json
    $Checked=$Result.intent.compatibility
    $Live=Image-RegistrySuccessor-Preflight -ImageId $P.image -ReleaseNonce $P.registryReleaseNonce -InterlockDigest $Publication.digest -LatestPin
    Assert-SuccessorRuntimeDelivery $Live $P.registryDelivery $Publication
    foreach($Field in @('sourceRevision','sourceCursor','snapshotRevision','eventDigest','profileDigest')){
        if($Live.registryCheckpoint.$Field -cne $Checked.registry.checkpoint.$Field){throw 'RELEASE_SUCCESSOR_ORDINARY_CHECKPOINT_CHANGED'}
    }
    if($Result.intentDigest -cnotmatch '^[0-9a-f]{64}$' -or $Result.pairDigest -cnotmatch '^[0-9a-f]{64}$' -or
       $Checked.registry.profileDigest -cne $SuccessorRegistryProfileSha256 -or
       $Checked.gateway.incumbentProfileDigest -cne $P.registryProfileDigest -or
       $Checked.registry.incumbentProfileDigest -cne $SourcePair.receiver.profileDigest -or
       $Result.intent.authorization.sourceRecordDigest -cne $Source.hash.ToLowerInvariant() -or
       $Result.intent.authorization.normalDigest -cne $Publication.digest -or
       $Checked.registry.binding.authorityDigest -cne $Live.sourceDelivery.policyAuthorityDigest -or
       $Result.registryDigest -cne $Live.registryCheckpoint.registryDigest -or
       -not (Same-Json (Read-SuccessorPublication $Source).anchor $Publication)){
        throw 'RELEASE_SUCCESSOR_ORDINARY_COMPATIBILITY_CHANGED'
    }
    return $Result
}

function Invoke-SuccessorControllerPeer {
    param($Source,[string]$IntentDigest,[switch]$Readback,[switch]$Drain)
    $P=$Source.runtime;$Id=$P.registryReleaseNonce.Replace('-','')
    $Code=@'
import json,sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.r7_unified_server import _installed_policy_source_digest
from fortis_approvals.r7_registry_reader_mount import _load_sealed_registry_reader,MOUNT,_check_live_peer
p=json.load(sys.stdin)
reader,_,digest=_load_sealed_registry_reader(MOUNT,p['nonce'],_installed_policy_source_digest())
if digest!=p['profile']:raise RuntimeError('MAINTENANCE_CONTROLLER_PROFILE_CHANGED')
_check_live_peer(reader)
if p['drain']:
    from fortis_approvals.integrations.registry_contracts import semantic_contract as sc
    gate=reader._successor_config._maintenance_gate(reader,sc.loads_strict(reader._successor_config._raw))
    result=gate.drain_status()
else:
    result=reader._semantic_transport.controller_paired_begin(p['intentDigest'],readback=p['readback'])
print(json.dumps(result,sort_keys=True,separators=(',',':')))
'@
    $Args=@('run','--rm','-i','--pull=never','--network','none','--read-only','--user','10001:10001',
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','32','--memory','256m',
        '--mount',('type=volume,source='+$P.registryReaderVolume+',target=/run/r7-registry-reader,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$P.registrySocketVolume+',target=/run/fortis-registry-read,readonly,volume-nocopy'),
        '--mount','type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,readonly,volume-nocopy',
        '--mount','type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,readonly,volume-nocopy',
        $P.image)
    return ((Python-Code $Args $Code (ConvertTo-Json -Compress @{nonce=$P.registryReleaseNonce;profile=$P.registryProfileDigest
        intentDigest=$IntentDigest;readback=[bool]$Readback;drain=[bool]$Drain}))|ConvertFrom-Json)
}

function Read-OrdinaryNativePreflight {
    param($Source,$Candidate)
    $Before=Read-OrdinarySuccessorSource $Source
    Assert-NativeRepoRead
    $After=Read-OrdinarySuccessorSource $Source
    if($Before.gateway.Id -cne $After.gateway.Id -or $Before.registry.Id -cne $After.registry.Id -or
       -not (Same-Json (Read-SuccessorPublication $Source).anchor.record $Candidate.intent.normal)){
        throw 'RELEASE_SUCCESSOR_ORDINARY_SOURCE_CHANGED'
    }
    return @{sourceRecordDigest=$Source.hash.ToLowerInvariant();intentDigest=$Candidate.intentDigest
        gatewayId=$After.gateway.Id;registryId=$After.registry.Id;githubRead=$true}
}
function Prepare-SuccessorMaintenanceContext {
    param($Source,$Candidate,[switch]$PreflightOnly,$Report=$null)
    if($PreflightOnly){
        # Check remains non-mutating until ordinary staged Apply and Return
        # can consume the holds. Never publish a partial maintenance window.
        if(-not $Candidate){throw 'RELEASE_SUCCESSOR_ORDINARY_COMPATIBILITY_REQUIRED'}
        return @{status='SUCCESSOR_PAIR_PREFLIGHT_ONLY';intentDigest=$Candidate.intentDigest
            pairDigest=$Candidate.pairDigest;checkpoint=$Candidate.intent.compatibility.registry.checkpoint}
    }
    $Path=Join-Path $ReleaseBase ('maintenance-'+$Source.runtime.runId+'.json')
    $Existing=Test-Path -LiteralPath $Path
    if($Existing){
        $Context=Read-Private $Path
    }else{
        if(-not $Candidate){throw 'RELEASE_SUCCESSOR_ORDINARY_COMPATIBILITY_REQUIRED'}
        $Native=Read-OrdinaryNativePreflight $Source $Candidate
        $Confirm='BEGIN SUCCESSOR '+$Candidate.intentDigest
        if((Read-Host ('Confirm exact independently checked successor pair and quiescent worker; type '+$Confirm)) -cne $Confirm){
            throw 'RELEASE_SUCCESSOR_ORDINARY_OWNER_GO_REQUIRED'
        }
        $Context=[pscustomobject][ordered]@{schema='fortis-successor-maintenance-check-v2'
            sourceRecordHash=$Source.hash;targetSourceSha=$SourceSha;targetImageId=$script:Image
            targetRegistryImage=$SuccessorRegistryImage;targetNonce=$script:RegistryBoundReleaseNonce
            intent=$Candidate.intent;intentDigest=$Candidate.intentDigest;pairDigest=$Candidate.pairDigest
            begin=$null;registryDigest=$null;draining=$null;payload=$null;replacement=$null
            nativeRead=$Native;preflightBinding=$(if($Report){Checked-Image-Binding $Source $Report $null}else{$null})}
        Write-Private $Path $Context -FlushToDisk
        $Context=Read-Private $Path
    }
    if($Context.schema -cne 'fortis-successor-maintenance-check-v2' -or
       $Context.sourceRecordHash -ine $Source.hash -or $Context.targetSourceSha -cne $SourceSha -or
       $Context.targetImageId -cne $script:Image -or $Context.targetRegistryImage -cne $SuccessorRegistryImage -or
       $Context.targetNonce -cne $script:RegistryBoundReleaseNonce -or
       $Context.intent.authorization.sourceRecordDigest -cne $Source.hash.ToLowerInvariant() -or
       $Context.intent.authorization.targetNonce -cne $script:RegistryBoundReleaseNonce -or
       $Context.intent.compatibility.artifacts.gateway -cne $script:Image.Substring(7) -or
       $Context.intent.compatibility.artifacts.registry -cne $SuccessorRegistryImage.Substring(7) -or
       $Context.intent.compatibility.registry.items.gateway.source.sourceSha -cne $SourceSha -or
       $Context.intent.compatibility.registry.profileDigest -cne $SuccessorRegistryProfileSha256 -or
       $Context.intentDigest -cnotmatch '^[0-9a-f]{64}$' -or $Context.pairDigest -cnotmatch '^[0-9a-f]{64}$'){
        throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
    }
    $Rows=Read-OrdinarySuccessorSource $Source -PublicationRecovery:$Existing
    if($Context.nativeRead.githubRead -ne $true -or
       $Context.nativeRead.intentDigest -cne $Context.intentDigest -or
       $Context.nativeRead.sourceRecordDigest -cne $Source.hash.ToLowerInvariant() -or
       $Context.nativeRead.gatewayId -cne $Rows.gateway.Id -or $Context.nativeRead.registryId -cne $Rows.registry.Id -or
       ($Report -and -not (Same-Json $Context.preflightBinding (Checked-Image-Binding $Source $Report $null)))){
        throw 'RELEASE_SUCCESSOR_ORDINARY_PREFLIGHT_CHANGED'
    }
    $Publication=(Read-SuccessorPublication $Source).anchor
    if(-not $Context.begin){
        if($Publication.state -cne 'Committed' -or -not (Same-Json $Publication.record $Context.intent.normal)){
            throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
        }
        if($Rows.gateway.State.Status -ceq 'exited'){
            # The original begin may have committed before its ACK and the
            # Gateway may no longer be able to start against the new hold.
            # Do not project, revoke, replace or invoke a new begin here.
            if(-not $Existing -or $Rows.registry.State.Status -cne 'running'){
                throw 'RELEASE_SUCCESSOR_ORDINARY_BEGIN_RECOVERY_REQUIRED'
            }
            Assert-OnlyWriter $Source.runtime.stateVolume
            $Actual=Invoke-SuccessorControllerPeer $Source $Context.intentDigest -Readback
            if($Actual.result -cne 'PROTECTED_PAIR_BEGIN_READBACK_ONLY'){
                throw 'RELEASE_SUCCESSOR_ORDINARY_BEGIN_RECOVERY_REQUIRED'
            }
        }else{
            $null=Read-OrdinarySuccessorSource $Source
            $Mounts=@('--mount','type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,readonly,volume-nocopy',
                '--mount','type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,volume-nocopy')
            $ProjectionInput=@{action='successor_begin_intent';intent=$Context.intent}
            if($Context.replacement){
                $ProjectionInput.mode='replace';$ProjectionInput.absence=$Context.replacement
            }
            $Projection=State-Helper $ProjectionInput $Mounts -Root
            if($Projection.intentDigest -cne $Context.intentDigest -or $Projection.pairDigest -cne $Context.pairDigest -or
               $Projection.revoked -isnot [bool]){
                throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
            }
            $Actual=Invoke-SuccessorControllerPeer $Source $Context.intentDigest -Readback
            if($Actual.result -ceq 'PROTECTED_PAIR_BEGIN_NOT_APPLIED'){
                if($Actual.intentDigest -cne $Context.intentDigest -or $Actual.revoked -isnot [bool] -or
                   $Actual.expired -isnot [bool] -or $Actual.revoked -ne $Projection.revoked){
                    throw 'RELEASE_SUCCESSOR_ORDINARY_PREDECESSOR_CHANGED'
                }
                if($Actual.expired -or $Actual.revoked){
                    # Revoke under the same reservation as begin, BEFORE the
                    # decisive absence readback. A late old effect, if already
                    # committed, must be recovered, not replaced.
                    $Revoked=State-Helper @{action='successor_begin_intent';mode='revoke';intent=$Context.intent} $Mounts -Root
                    if($Revoked.revoked -ne $true -or $Revoked.intentDigest -cne $Context.intentDigest -or
                       $Revoked.pairDigest -cne $Context.pairDigest){throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'}
                    $Actual=Invoke-SuccessorControllerPeer $Source $Context.intentDigest -Readback
                    if($Actual.result -ceq 'PROTECTED_PAIR_BEGIN_NOT_APPLIED'){
                        if($Actual.revoked -ne $true -or $Actual.intentDigest -cne $Context.intentDigest -or
                           $null -ne $Actual.receipts){throw 'RELEASE_SUCCESSOR_ORDINARY_BEGIN_UNCONFIRMED'}
                        if($Report -and (-not $Candidate -or $Candidate.intentDigest -ceq $Context.intentDigest)){
                            $Candidate=Read-OrdinarySuccessorCompatibility $Source $Publication
                        }
                        if(-not $Candidate -or $Candidate.intentDigest -ceq $Context.intentDigest -or
                           -not (Same-Json $Candidate.intent.normal $Context.intent.normal) -or
                           $Candidate.intent.authorization.attemptId -ceq $Context.intent.authorization.attemptId -or
                           $Candidate.intent.authorization.recordedAt -le $Context.intent.authorization.recordedAt -or
                           $Candidate.intent.authorization.sourceRecordDigest -cne $Source.hash.ToLowerInvariant() -or
                           $Candidate.intent.authorization.targetNonce -cne $script:RegistryBoundReleaseNonce -or
                           -not (Same-Json $Candidate.intent.compatibility.artifacts $Context.intent.compatibility.artifacts) -or
                           $Candidate.intent.compatibility.registry.profileDigest -cne $SuccessorRegistryProfileSha256 -or
                           $Candidate.intent.compatibility.registry.items.gateway.source.sourceSha -cne $SourceSha -or
                           -not (Same-Json $Candidate.intent.compatibility.registry.checkpoint $Actual.checkpoint) -or
                           -not (Same-Json $Candidate.intent.compatibility.registry.holdSnapshot $Actual.holdSnapshot)){
                            throw 'RELEASE_SUCCESSOR_ORDINARY_FRESH_CHECK_REQUIRED'
                        }
                        $Native=Read-OrdinaryNativePreflight $Source $Candidate
                        $Confirm='BEGIN SUCCESSOR '+$Candidate.intentDigest
                        if((Read-Host ('Confirm replacement of proven unused intent; type '+$Confirm)) -cne $Confirm){
                            throw 'RELEASE_SUCCESSOR_ORDINARY_OWNER_GO_REQUIRED'
                        }
                        # Retain exact old context and the decisive readback
                        # outside both runtime volumes before changing authority.
                        $Archive=Join-Path $ReleaseBase ('maintenance-unused-'+$Context.intent.authorization.attemptId+'.json')
                        $Retained=[ordered]@{context=$Context;absence=$Actual}
                        if(-not (Test-Path -LiteralPath $Archive)){Write-Private $Archive $Retained -FlushToDisk}
                        if(-not (Same-Json (Read-Private $Archive) $Retained)){throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'}
                        $Context.intent=$Candidate.intent;$Context.intentDigest=$Candidate.intentDigest
                        $Context.pairDigest=$Candidate.pairDigest;$Context.replacement=$Actual
                        $Context.nativeRead=$Native
                        Write-Private $Path $Context -FlushToDisk
                        if(-not (Same-Json (Read-Private $Path) $Context)){throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'}
                        # Re-enter the exact durable replacement; do not
                        # manufacture a second replacement from this candidate.
                        return (Prepare-SuccessorMaintenanceContext $Source $null -Report $Report)
                    }
                }
            }
            if($Actual.result -ceq 'PROTECTED_PAIR_BEGIN_NOT_APPLIED'){
                if($Actual.intentDigest -cne $Context.intentDigest -or $Actual.exactPredecessor -ne $true -or
                   $Actual.revoked -or $Actual.expired){
                    throw 'RELEASE_SUCCESSOR_ORDINARY_PREDECESSOR_CHANGED'
                }
                # A new begin is allowed only with the exact healthy running source.
                $null=Read-OrdinarySuccessorSource $Source
                $Written=$null
                try{$Written=Invoke-SuccessorControllerPeer $Source $Context.intentDigest}
                catch{Write-Warning 'RELEASE_SUCCESSOR_ORDINARY_BEGIN_READBACK'}
                $Actual=Invoke-SuccessorControllerPeer $Source $Context.intentDigest -Readback
                if($Written -and -not (Same-Json $Written $Actual)){throw 'RELEASE_SUCCESSOR_ORDINARY_BEGIN_CHANGED'}
            }
        }
        if($Actual.result -cne 'PROTECTED_PAIR_BEGIN_READBACK_ONLY' -or $Actual.intentDigest -cne $Context.intentDigest -or
           $Actual.registryDigest -cnotmatch '^[0-9a-f]{64}$' -or $Actual.draining.phase -cne 'DRAINING' -or
           $Actual.draining.previousDigest -cne $Publication.digest -or
           $Actual.draining.attempt.attemptId -cne $Context.intent.authorization.attemptId){
            throw 'RELEASE_SUCCESSOR_ORDINARY_BEGIN_UNCONFIRMED'
        }
        $Context.begin=$Actual;$Context.registryDigest=$Actual.registryDigest;$Context.draining=$Actual.draining
        Write-Private $Path $Context -FlushToDisk
        $Context=Read-Private $Path
        if(-not (Same-Json $Context.begin $Actual)){throw 'RELEASE_SUCCESSOR_ORDINARY_BEGIN_UNCONFIRMED'}
    }
    if($Context.begin.result -cne 'PROTECTED_PAIR_BEGIN_READBACK_ONLY' -or
       $Context.begin.intentDigest -cne $Context.intentDigest -or $Context.registryDigest -cne $Context.begin.registryDigest -or
       -not (Same-Json $Context.draining $Context.begin.draining)){
        throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
    }
    $script:OrdinaryFreshFreeze=$null
    $Started=Start-SuccessorMaintenanceCheck $Source $Context
    if(-not $Started.resume -and -not $Context.payload){
        $Frozen=Read-OrdinarySuccessorFreeze $Source $Context $Started.digest
        if($Frozen){
            $Context.payload=$Frozen.payload
            $script:OrdinaryFreshFreeze=$Frozen
            Write-Private $Path $Context -FlushToDisk
            if(-not (Same-Json (Read-Private $Path) $Context)){throw 'RELEASE_SUCCESSOR_FREEZE_SEAL_CHANGED'}
        }
    }
    if($Report){return (Complete-OrdinarySuccessorCheck $Source $Report $Context $script:OrdinaryFreshFreeze)}
    return $Context
}

function Complete-OrdinarySuccessorCheck {
    param($Source,$Report,$Context,$Fresh=$null)
    if(-not $Context.payload){return @{status='MAINTENANCE_DRAINING';attemptId=$Context.draining.attempt.attemptId}}
    $Payload=$Context.payload
    $Path=Successor-CheckRecordPath $Payload.attemptId
    $Publication=(Read-SuccessorPublication $Source).anchor
    if(Test-Path -LiteralPath $Path){
        $Stored=Read-Private $Path
    }else{
        if($Publication.record.phase -cne 'DRAINING' -or $Publication.state -cne 'Committed'){
            throw 'RELEASE_SUCCESSOR_CHECK_RECORD_CHANGED'
        }
        # The producer's result may be consumed under the same controller
        # lock. Re-entry independently re-inspects rather than trust cache.
        if(-not $Fresh){$Fresh=Read-SuccessorFreezeSeal $Payload $Source.runtime.stateVolume 'fortis-r7-maintenance-interlock'}
        if(-not (Same-Json $Fresh.transitions.draining $Context.draining) -or
           $Fresh.seal.stateReceiptDigest -cne $Payload.stateDigest -or
           $Fresh.seal.registryDigest -cne $Context.registryDigest -or
           $Fresh.seal.interlockDigest -cne $Publication.digest){
            throw 'RELEASE_SUCCESSOR_FREEZE_SEAL_CHANGED'
        }
        $Path=Save-Checked-Image $Source $Report $Fresh.sourceReceipt $Payload $Fresh.seal $Fresh.transitions
        $Stored=Read-Private $Path
    }
    if($Stored.schema -cne 'fortis-extension-image-check-v1' -or $Stored.phase -cne 'Ready'){
        throw 'RELEASE_SUCCESSOR_CHECK_RECORD_CHANGED'
    }
    Assert-Checked-Image-Binding $Stored.binding (Checked-Image-Binding $Source $Report $Payload)
    $Digest=Complete-SuccessorMaintenanceCheck $Source $Context $Stored
    return @{status='CHECK_SEALED';checkedImageRecord=$Path;interlockDigest=$Digest;attemptId=$Payload.attemptId}
}

function Read-OrdinarySuccessorFreeze {
    param($Source,$Context,[string]$Digest)
    if(-not $ConfirmWorkerQuiescent -or $Digest -cnotmatch '^[0-9a-f]{64}$' -or
       $Context.registryDigest -cnotmatch '^[0-9a-f]{64}$'){
        throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
    }
    $Publication=(Read-SuccessorPublication $Source).anchor
    if($Publication.state -cne 'Committed' -or $Publication.digest -cne $Digest -or
       $Publication.registryDigest -cne $Context.registryDigest -or
       -not (Same-Json $Publication.record $Context.draining)){
        throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
    }
    $Rows=Read-OrdinarySuccessorSource $Source -PublicationRecovery
    if($Rows.gateway.State.Status -ceq 'exited'){
        # A stopped source is not a new startup admission. Drain is measured
        # through the exact Registry peer and the shared inode reservation;
        # never restart the Gateway while the source generation is held.
        # Prevent an automatic source restart before the exclusive state
        # inspection. A later Return restores the recorded restart policy.
        $Gateway=Set-BootstrapContainerState $Rows.gateway DisableRestart
        if($Gateway.State.Status -cne 'exited'){throw 'RELEASE_SUCCESSOR_ORDINARY_SOURCE_CHANGED'}
        Assert-OnlyWriter $Source.runtime.stateVolume
        if($Rows.registry.State.Status -ceq 'exited'){
            if(-not (Same-Json (Read-SuccessorPublication $Source).anchor $Publication)){
                throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
            }
            $Registry=Set-BootstrapContainerState $Rows.registry DisableRestart
            $Registry=Set-BootstrapContainerState $Registry Start
            Wait-CorrectiveRegistryListener $Registry.Id
            $Rows=Read-OrdinarySuccessorSource $Source -PublicationRecovery
            if($Rows.gateway.State.Status -cne 'exited' -or $Rows.registry.Id -cne $Registry.Id){
                throw 'RELEASE_SUCCESSOR_ORDINARY_SOURCE_CHANGED'
            }
        }
    }else{
        $Rows=Read-OrdinarySuccessorSource $Source
    }
    if($Rows.registry.State.Status -cne 'running'){throw 'RELEASE_SUCCESSOR_DRAIN_UNCONFIRMED'}
    $Drain=Invoke-SuccessorControllerPeer $Source $Context.intentDigest -Drain
    if($Drain.status -ceq 'UNKNOWN'){throw 'RELEASE_SUCCESSOR_DRAIN_UNCONFIRMED'}
    if($Drain.status -cne 'DRAINING' -or $Drain.attemptId -cne $Context.draining.attempt.attemptId -or
       $Drain.generation -cne $Context.draining.generation -or
       $Drain.interlockDigest -cne $Digest -or $Drain.registryDigest -cne $Context.registryDigest -or
       $Drain.ready -isnot [bool]){throw 'RELEASE_SUCCESSOR_DRAIN_UNCONFIRMED'}
    $After=Read-OrdinarySuccessorSource $Source -PublicationRecovery
    if($After.gateway.Id -cne $Rows.gateway.Id -or $After.registry.Id -cne $Rows.registry.Id -or
       $After.registry.State.Status -cne 'running' -or
       -not (Same-Json (Read-SuccessorPublication $Source).anchor $Publication)){
        throw 'RELEASE_SUCCESSOR_DRAIN_UNCONFIRMED'
    }
    if($Rows.gateway.State.Status -ceq 'exited'){
        if($After.gateway.State.Status -cne 'exited' -or
           $After.gateway.HostConfig.RestartPolicy.Name -cne 'no'){
            throw 'RELEASE_SUCCESSOR_ORDINARY_SOURCE_CHANGED'
        }
        Assert-OnlyWriter $Source.runtime.stateVolume
    }else{
        $null=Read-OrdinarySuccessorSource $Source
    }
    if(-not $Drain.ready){return}
    if($Drain.reservations -ne 0){throw 'RELEASE_SUCCESSOR_DRAIN_UNCONFIRMED'}
    $Companion=$Context.intent.compatibility.gateway.companion
    $Payload=@{action='successor_freeze_inspect';latestPin=$true
        instanceId=$Context.draining.registryInstanceId;scopeDigest=$Context.draining.scopeDigest
        generation=$Context.draining.generation;interlockDigest=$Digest;registryDigest=$Context.registryDigest
        attemptId=$Context.draining.attempt.attemptId;restrictionDigest=$Context.draining.attempt.restrictionDigest
        subject=$Context.draining.attempt.subject;targetSourceSha=$Context.targetSourceSha
        coreSchemaDigest=$Companion.schemaDigest;companionDigest=$Companion.companionDigest
        preserveUncertainIds=@(Parse-PreservedUncertainRequests $script:PreserveUncertainRequests|Sort-Object)
        preserveClaimedIds=@(Parse-PreservedUncertainRequests $script:PreserveClaimedJobs|Sort-Object)
        drain=$Drain;prepare=@{intentDigest=$Context.intentDigest;sourceRecordDigest=$Source.hash.ToLowerInvariant()
            ownerConfirmed=$true;begin=$Context.begin}}
    return (Read-SuccessorFreezeSeal $Payload $Source.runtime.stateVolume 'fortis-r7-maintenance-interlock')
}


function Assert-OrdinaryCheckResumeSelfTest {
    $PreviousImage=$script:Image;$PreviousCheck=$script:RegistryPrebuiltCheck
    $PreviousReturn=$script:RegistryReturn;$PreviousApproved=$script:PreserveApprovedRequest
    try {
        $Bootstrap289=$false;$Corrective288=$false;$Action='Check';$AllowUncertainGrowth=$false
        $EmergencyRequested=$false;$RegistryReturnContainerId='';$CheckedImageRecord=''
        $script:RegistryReturn=$null;$script:PreserveApprovedRequest='';$script:RegistryPrebuiltCheck=$true
        $script:Image='sha256:'+('a'*64);$SourceSha='b'*40;$ReleaseBase=[IO.Path]::GetTempPath()
        $RegistryReleaseNonce='11111111-1111-4111-8111-111111111111'
        $SuccessorRegistryImage='sha256:'+('c'*64);$SuccessorRegistryProfileSha256='d'*64
        $Source=@{hash=('e'*64);runtime=[pscustomobject]@{runId=('f'*32);maintenanceGeneration=('1'*64)}}
        $Normal=@{phase='NORMAL';generation=('1'*64)}
        $Drain=@{phase='DRAINING';generation=('1'*64);attempt=@{attemptId=$RegistryReleaseNonce;source=@{sourceSha=$SourceSha}}}
        $Context=[pscustomobject]@{schema='fortis-successor-maintenance-check-v2'
            sourceRecordHash=$Source.hash;targetSourceSha=$SourceSha;targetImageId=$script:Image
            targetNonce=$RegistryReleaseNonce;targetRegistryImage=$SuccessorRegistryImage
            intentDigest=('2'*64);intent=@{normal=$Normal;authorization=@{sourceRecordDigest=$Source.hash}
                compatibility=@{registry=@{profileDigest=$SuccessorRegistryProfileSha256}}}
            payload=$null;begin=$null;draining=$null;registryDigest=$null}
        $Fixture=@{anchor=@{schema='fortis-successor-maintenance-publication-v2';state='Committed';record=$Normal;registryDigest=$null}}
        function Read-Private {return $Context}
        function Read-SuccessorPublication {return @{anchor=$Fixture.anchor}}
        function Successor-CheckRecordPath {param($Id) if($Id -cne $RegistryReleaseNonce){throw 'FIXTURE_CHECK_ATTEMPT'};return 'fixture'}
        if(-not (Same-Json (Read-SuccessorMaintenanceContext $Source) $Context)){throw 'FIXTURE_PREBEGIN_CONTEXT_LOST'}
        $Context.targetNonce='wrong'
        try {$null=Read-SuccessorMaintenanceContext $Source;throw 'FIXTURE_WRONG_NONCE_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'){throw}}
        $Context.targetNonce=$RegistryReleaseNonce;$Context.begin=@{intentDigest=$Context.intentDigest}
        $Context.draining=$Drain;$Context.registryDigest='3'*64
        $Fixture.anchor.record=$Drain;$Fixture.anchor.registryDigest=$Context.registryDigest
        if(-not (Same-Json (Read-SuccessorMaintenanceContext $Source) $Context)){throw 'FIXTURE_DRAIN_CONTEXT_LOST'}
    }finally{
        $script:Image=$PreviousImage;$script:RegistryPrebuiltCheck=$PreviousCheck
        $script:RegistryReturn=$PreviousReturn;$script:PreserveApprovedRequest=$PreviousApproved
    }
    Write-Host 'FORTIS_SUCCESSOR_ORDINARY_CHECK_RESUME_SELFTEST_PASS'
}

function Assert-OrdinaryBeginSelfTest {
    $PreviousImage=$script:Image;$PreviousNonce=$script:RegistryBoundReleaseNonce
    $PreviousUncertain=$script:PreserveUncertainRequests;$PreviousClaimed=$script:PreserveClaimedJobs
    try {
        $script:Image='sha256:'+('a'*64)
        $script:RegistryBoundReleaseNonce='11111111-1111-4111-8111-111111111111'
        $script:PreserveUncertainRequests='';$script:PreserveClaimedJobs=''
        $ConfirmWorkerQuiescent=$true
        $SuccessorRegistryImage='sha256:'+('b'*64);$SuccessorRegistryProfileSha256='c'*64
        $SourceSha='d'*40;$ReleaseBase=[IO.Path]::GetTempPath()
        $Source=@{hash=('e'*64);runtime=@{runId=('f'*32);stateVolume='fixture'}}
        $Path=Join-Path $ReleaseBase ('maintenance-'+$Source.runtime.runId+'.json')
        $Normal=@{phase='NORMAL';sequence=4}
        $FirstId='22222222-2222-4222-8222-222222222222';$NextId='33333333-3333-4333-8333-333333333333'
        $Drain=@{phase='DRAINING';sequence=5;previousDigest=('1'*64);generation=('6'*64)
            registryInstanceId='fixture-instance';scopeDigest=('7'*64)
            attempt=@{attemptId=$NextId;restrictionDigest=('8'*64);subject=@{targetId='gateway'}}}
        $OriginalCandidate=@{intentDigest=('2'*64);pairDigest=('3'*64);intent=@{normal=$Normal
            authorization=@{sourceRecordDigest=$Source.hash;attemptId=$FirstId;recordedAt=100;targetNonce=$script:RegistryBoundReleaseNonce}
            compatibility=@{artifacts=@{gateway=('a'*64);registry=('b'*64)}
                gateway=@{companion=@{schemaDigest=('9'*64);companionDigest=('a'*64)}}
                registry=@{profileDigest=$SuccessorRegistryProfileSha256;checkpoint=@{sourceRevision=5};holdSnapshot=@{holds=@()}
                    items=@{gateway=@{source=@{sourceSha=$SourceSha}}}}}}}
        $New=($OriginalCandidate|ConvertTo-Json -Depth 25 -Compress|ConvertFrom-Json)
        $New.intentDigest='b'*64;$New.pairDigest='c'*64
        $New.intent.authorization.attemptId=$NextId;$New.intent.authorization.recordedAt=401
        $Archive=Join-Path $ReleaseBase ('maintenance-unused-'+$FirstId+'.json')
        $Fixture=@{files=@{};go=0;writes=0;projection=0;revoked=$false;projected=$null
            replace=0;loseReplace=$true;publish=0;freeze=0;ready=$false;anchor=@{
                schema='fortis-successor-maintenance-publication-v2';state='Committed';record=$Normal;digest=('1'*64);registryDigest=$null}}
        function Test-Path {param($LiteralPath) return $Fixture.files.ContainsKey($LiteralPath)}
        function Read-Private {param($Path) return ($Fixture.files[$Path]|ConvertFrom-Json)}
        function Write-Private {param($Path,$Value,[switch]$FlushToDisk)
            if(-not $FlushToDisk){throw 'FIXTURE_CONTEXT_NOT_DURABLE'}
            $Fixture.files[$Path]=ConvertTo-Json -InputObject $Value -Depth 25 -Compress}
        function Read-Host {param($Prompt)
            $Fixture.go++
            if($Fixture.go -eq 1){return ('BEGIN SUCCESSOR '+$OriginalCandidate.intentDigest)}
            return ('BEGIN SUCCESSOR '+$New.intentDigest)}
        $Fixture.rows=@{gateway=@{Id='gateway';State=@{Status='running'};HostConfig=@{RestartPolicy=@{Name='unless-stopped'}}}
            registry=@{Id='registry';State=@{Status='running'};HostConfig=@{RestartPolicy=@{Name='unless-stopped'}}}}
        $CheckPath=Join-Path $ReleaseBase 'ordinary-check-fixture.json'
        $Transitions=@{draining=$Drain;frozen=@{phase='FROZEN_BEFORE_CHECK';sequence=6}
            checked=@{phase='CHECK_SEALED';sequence=7}}
        $Fixture.contextPath=$Path;$Fixture.loseFreezePublish=$true;$Fixture.checkWrites=0
        function Successor-CheckRecordPath {param($AttemptId) if($AttemptId -cne $NextId){throw 'FIXTURE_WRONG_CHECK'};return $CheckPath}
        function Checked-Image-Binding {param($Source,$Report,$Maintenance)
            $B=[ordered]@{sourceHash=$Source.hash;configurationDigest=$Report.configurationDigest}
            if($Maintenance){$B.ordinaryIntentDigest=(Read-Private $Fixture.contextPath).intentDigest}
            return $B}
        function Assert-Checked-Image-Binding {param($Stored,$Expected)
            if(-not (Same-Json $Stored $Expected)){throw 'FIXTURE_CHECK_BINDING_CHANGED'}}
        function Save-Checked-Image {param($Source,$Report,$Receipt,$Maintenance,$Seal,$Stages)
            if($Fixture.anchor.record.phase -cne 'DRAINING' -or $Fixture.checkWrites){throw 'FIXTURE_CHECK_SAVE_ORDER'}
            $Fixture.checkWrites++
            Write-Private $CheckPath @{schema='fortis-extension-image-check-v1';phase='Ready'
                binding=(Checked-Image-Binding $Source $Report $Maintenance);sourceReceipt=$Receipt
                maintenanceSeal=$Seal;maintenanceTransitions=$Stages} -FlushToDisk
            return $CheckPath}
        $Report=@{configurationDigest=('9'*64)}
        $Fixture.loseReadback=$true;$Fixture.loseDrainPublish=$true;$Fixture.recoveryStarts=0;$Fixture.nativeReads=0
        function Assert-NativeRepoRead {
            if($Fixture.rows.gateway.State.Status -cne 'running'){throw 'FIXTURE_NATIVE_SOURCE_OFFLINE'}
            $Fixture.nativeReads++
        }
        function Read-OrdinarySuccessorSource {param($Source,[switch]$PublicationRecovery)
            if(-not $PublicationRecovery -and ($Fixture.rows.gateway.State.Status -cne 'running' -or
                $Fixture.rows.registry.State.Status -cne 'running')){throw 'FIXTURE_LIVE_SOURCE_REQUIRED'}
            return ($Fixture.rows|ConvertTo-Json -Depth 10 -Compress|ConvertFrom-Json)
        }
        function Assert-OnlyWriter {param($Volume) if($Volume -cne 'fixture'){throw 'FIXTURE_WRITER_SCOPE'}}
        function Set-BootstrapContainerState {param($C,$Effect)
            $Row=if($C.Id -ceq 'gateway'){$Fixture.rows.gateway}else{$Fixture.rows.registry}
            if($Effect -ceq 'DisableRestart'){$Row.HostConfig.RestartPolicy.Name='no'}
            elseif($Effect -ceq 'Start' -and $C.Id -ceq 'registry' -and $Row.HostConfig.RestartPolicy.Name -ceq 'no' -and
                $Fixture.rows.gateway.State.Status -ceq 'exited' -and $Fixture.anchor.record.phase -ceq 'DRAINING'){
                $Fixture.recoveryStarts++;$Row.State.Status='running'
            }else{throw 'FIXTURE_UNEXPECTED_RECOVERY_EFFECT'}
            return ($Row|ConvertTo-Json -Depth 10 -Compress|ConvertFrom-Json)
        }
        function Wait-CorrectiveRegistryListener {param($Id) if($Id -cne 'registry'){throw 'FIXTURE_WRONG_LISTENER'}}
        function Assert-Volume {}
        function Parse-PreservedUncertainRequests {}
        function Read-SuccessorPublication {return @{anchor=$Fixture.anchor}}
        function State-Helper {param($Payload,$Mounts,[switch]$Root)
            if($Payload.action -ceq 'successor_freeze_apply_verify'){
                if($Fixture.anchor.record.phase -cne 'CHECK_SEALED' -or
                   $Payload.interlockDigest -cne $Fixture.anchor.digest -or -not $Fixture.checkWrites){
                    throw 'FIXTURE_CHECK_VERIFY_ORDER'}
                return @{sourceReceipt=(Read-Private $CheckPath).sourceReceipt;transitions=$Transitions;seal=$Payload.checkSeal}
            }
            if($Payload.action -ceq 'successor_freeze_inspect'){
                if($Root -or $Mounts.Count -ne 6 -or $Fixture.publish -ne 1 -or
                   $Payload.prepare.ownerConfirmed -ne $true -or $Payload.prepare.intentDigest -cne $New.intentDigest -or
                   -not $Payload.drain.ready -or -not (Read-Private $Path).begin){
                    throw 'FIXTURE_FREEZE_BEFORE_DRAIN'
                }
                $Fixture.freeze++
                $Out=@{}+ $Payload;$Out.Remove('prepare')
                $Out.stateDigest='d'*64;$Out.workerAttestationDigest='e'*64
                $Produced=$Out|ConvertTo-Json -Depth 25 -Compress|ConvertFrom-Json
                return @{payload=$Produced;seal=@{result='FREEZE_BINDINGS_MATCH_ONLY'
                    attemptId=$Payload.attemptId;restrictionDigest=$Payload.restrictionDigest
                    interlockDigest=$Payload.interlockDigest;registryDigest=$Payload.registryDigest
                    stateReceiptDigest=$Out.stateDigest;companionDigest=$Payload.companionDigest
                    workerAttestationDigest=$Out.workerAttestationDigest}
                    sourceReceipt=@{sha256=@{};summary=@{}};transitions=$Transitions}
            }
            if(-not $Root -or -not $Fixture.files.ContainsKey($Path) -or $Payload.action -cne 'successor_begin_intent'){throw 'FIXTURE_INTENT_ORDER'}
            $Fixture.projection++
            $Selected=if($Payload.intent.authorization.attemptId -ceq $FirstId){$OriginalCandidate}else{$New}
            if($Payload['mode'] -ceq 'revoke'){
                if($Fixture.projected -cne $OriginalCandidate.intentDigest){throw 'FIXTURE_REVOKE_SCOPE'}
                $Fixture.revoked=$true
            }elseif($Payload['mode'] -ceq 'replace'){
                if(-not $Fixture.revoked -and $Fixture.projected -cne $New.intentDigest){throw 'FIXTURE_REPLACE_BEFORE_REVOKE'}
                if(-not $Fixture.files.ContainsKey($Archive) -or $Payload.absence.revoked -ne $true -or
                   (Read-Private $Path).intentDigest -cne $New.intentDigest){throw 'FIXTURE_REPLACE_BEFORE_ARCHIVE'}
                if($Fixture.projected -cne $New.intentDigest){
                    $Fixture.replace++;$Fixture.revoked=$false;$Fixture.projected=$New.intentDigest
                    if($Fixture.loseReplace){$Fixture.loseReplace=$false;throw 'FIXTURE_REPLACE_ACK_LOST'}
                }
            }else{$Fixture.projected=$Selected.intentDigest}
            return @{intentDigest=$Selected.intentDigest;pairDigest=$Selected.pairDigest;revoked=$Fixture.revoked}}
        function Invoke-SuccessorControllerPeer {param($Source,$IntentDigest,[switch]$Readback,[switch]$Drain)
            if($IntentDigest -cne $Fixture.projected){throw 'FIXTURE_BEGIN_INTENT'}
            if($Drain){
                return @{status='DRAINING';attemptId=$NextId;generation=('6'*64);interlockDigest=('5'*64)
                    registryDigest=('4'*64);reservations=$(if($Fixture.ready){0}else{1});ready=$Fixture.ready}
            }
            if($IntentDigest -ceq $OriginalCandidate.intentDigest){
                if(-not $Readback){throw 'FIXTURE_EXPIRED_EFFECT'}
                return @{result='PROTECTED_PAIR_BEGIN_NOT_APPLIED';intentDigest=$IntentDigest;exactPredecessor=$true
                    revoked=$Fixture.revoked;expired=$true;receipts=$null
                    checkpoint=$OriginalCandidate.intent.compatibility.registry.checkpoint;holdSnapshot=$OriginalCandidate.intent.compatibility.registry.holdSnapshot}
            }
            if(-not $Readback){$Fixture.writes++;throw 'FIXTURE_BEGIN_ACK_LOST'}
            if($Fixture.writes -eq 0){return @{result='PROTECTED_PAIR_BEGIN_NOT_APPLIED';intentDigest=$IntentDigest;exactPredecessor=$true;revoked=$false;expired=$false}}
            if($Fixture.loseReadback){
                $Fixture.loseReadback=$false;$Fixture.rows.gateway.State.Status='exited'
                throw 'FIXTURE_BEGIN_READBACK_LOST'
            }
            return @{result='PROTECTED_PAIR_BEGIN_READBACK_ONLY';intentDigest=$IntentDigest;registryDigest=('4'*64);draining=$DrainRecord}}
        # Avoid shadowing the phase record with the peer's -Drain switch.
        $DrainRecord=$Drain
        function Publish-SuccessorInterlock {param($Source,$Next,$RegistryDigest)
            $Saved=Read-Private $Fixture.contextPath
            if(-not $Saved.begin -or $RegistryDigest -cne ('4'*64)){throw 'FIXTURE_PUBLISH_BEFORE_READBACK'}
            if($Next.phase -cin @('FROZEN_BEFORE_CHECK','CHECK_SEALED')){
                if(-not $Fixture.checkWrites){throw 'FIXTURE_PHASE_BEFORE_CHECK'}
                if($Next.phase -ceq 'FROZEN_BEFORE_CHECK'){
                    $Fixture.anchor.record=$Next;$Fixture.anchor.digest='6'*64
                    if($Fixture.loseFreezePublish){$Fixture.loseFreezePublish=$false;throw 'FIXTURE_FROZEN_ACK_LOST'}
                }else{
                    $Fixture.anchor.record=$Next;$Fixture.anchor.digest='7'*64
                }
                return $Fixture.anchor.digest
            }
            if(-not (Same-Json $Next $DrainRecord)){throw 'FIXTURE_WRONG_DRAIN'}
            if($Fixture.anchor.record.phase -ceq 'NORMAL'){
                if($Fixture.loseDrainPublish){
                    $Fixture.loseDrainPublish=$false;$Fixture.anchor.state='Pending'
                    $Fixture.anchor.next=$Next;$Fixture.rows.registry.State.Status='exited'
                    throw 'FIXTURE_DRAIN_ACK_LOST'
                }
                $Fixture.publish++;$Fixture.anchor.record=$Next;$Fixture.anchor.state='Committed'
                $Fixture.anchor.digest='5'*64;$Fixture.anchor.registryDigest=$RegistryDigest
            }
            return ('5'*64)}
        $Preview=Prepare-SuccessorMaintenanceContext $Source $OriginalCandidate -PreflightOnly
        if($Preview.status -cne 'SUCCESSOR_PAIR_PREFLIGHT_ONLY' -or $Fixture.files.Count -or $Fixture.go){throw 'FIXTURE_PREFLIGHT_EFFECT'}
        function Read-OrdinarySuccessorCompatibility {throw 'RELEASE_SUCCESSOR_ORDINARY_FRESH_CHECK_REQUIRED'}
        try {$null=Prepare-SuccessorMaintenanceContext $Source $OriginalCandidate -Report $Report;throw 'FIXTURE_EXPIRED_ACCEPTED'}
        catch {if($_.Exception.Message -cne 'RELEASE_SUCCESSOR_ORDINARY_FRESH_CHECK_REQUIRED'){throw}}
        if(-not $Fixture.revoked -or $Fixture.writes -or $Fixture.publish){throw 'FIXTURE_EXPIRED_MUTATION'}
        try {$null=Prepare-SuccessorMaintenanceContext $Source $New;throw 'FIXTURE_MISSING_ACK'}
        catch {if($_.Exception.Message -cne 'FIXTURE_REPLACE_ACK_LOST'){throw}}
        if($Fixture.replace -ne 1 -or -not $Fixture.files.ContainsKey($Archive) -or $Fixture.writes){throw 'FIXTURE_REPLACE_ACK'}
        try {$null=Prepare-SuccessorMaintenanceContext $Source $null;throw 'FIXTURE_EXPECTED_LOST_BEGIN_READBACK'}
        catch {if($_.Exception.Message -cne 'FIXTURE_BEGIN_READBACK_LOST'){throw}}
        $Projected=$Fixture.projection
        try {$null=Prepare-SuccessorMaintenanceContext $Source $null;throw 'FIXTURE_EXPECTED_LOST_DRAIN_ACK'}
        catch {if($_.Exception.Message -cne 'FIXTURE_DRAIN_ACK_LOST'){throw}}
        if($Fixture.projection -ne $Projected -or $Fixture.writes -ne 1 -or -not (Read-Private $Path).begin){
            throw 'FIXTURE_STOPPED_GATEWAY_REPLAY'
        }
        $First=Prepare-SuccessorMaintenanceContext $Source $null
        if($First.payload -or $Fixture.publish -ne 1 -or $Fixture.freeze -or $Fixture.recoveryStarts -ne 1 -or
           $Fixture.rows.gateway.State.Status -cne 'exited' -or $Fixture.rows.gateway.HostConfig.RestartPolicy.Name -cne 'no'){
            throw 'FIXTURE_BUSY_DRAIN'
        }
        $Fixture.ready=$true
        try {$null=Prepare-SuccessorMaintenanceContext $Source $null -Report $Report;throw 'FIXTURE_EXPECTED_LOST_FROZEN_ACK'}
        catch {if($_.Exception.Message -cne 'FIXTURE_FROZEN_ACK_LOST'){throw}}
        $Sealed=Prepare-SuccessorMaintenanceContext $Source $null -Report $Report
        $Again=Prepare-SuccessorMaintenanceContext $Source $null -Report $Report
        if($Sealed.status -cne 'CHECK_SEALED' -or $Fixture.checkWrites -ne 1 -or
           $Fixture.anchor.record.phase -cne 'CHECK_SEALED' -or -not (Same-Json $Sealed $Again) -or $Fixture.go -ne 2 -or $Fixture.writes -ne 1 -or
           $Fixture.replace -ne 1 -or $Fixture.publish -ne 1 -or $Fixture.freeze -ne 1 -or
           $Fixture.nativeReads -ne 2){throw 'FIXTURE_ORDINARY_BEGIN_REPLAY'}
    } finally {
        $script:Image=$PreviousImage;$script:RegistryBoundReleaseNonce=$PreviousNonce
        $script:PreserveUncertainRequests=$PreviousUncertain;$script:PreserveClaimedJobs=$PreviousClaimed
    }
    Write-Host 'FORTIS_SUCCESSOR_ORDINARY_BEGIN_SELFTEST_PASS'
}


function Read-RegistrySuccessorDelivery {
    param($Source)
    $Anchor=Read-RegistrySuccessorAnchor $Source
    if($null -eq $Anchor){return}
    $Inputs=@{ImageId=$script:Image;ReleaseNonce=$script:RegistryBoundReleaseNonce
        InterlockDigest=$Anchor.digest;IncumbentVolume=$Source.runtime.stateVolume}
    $Result=Image-RegistrySuccessor-Preflight @Inputs
    if($Result.PSObject.Properties['existingCompanion']){
        if($Source.hash -ine 'ea25b6d0769059e225c584a7a5518d6cedd0e8f3f138b1cb29f7194c09cc195c'){
            throw 'RELEASE_REGISTRY_288_REBIND_EVIDENCE_CHANGED'
        }
        Assert-Registry288RecoveredProfile $Source.runtime '86722403363418162f179ccdbb14fa7368a5eede4e5c7ba6806cbb4402e92b17'
    }
    if($Corrective288 -and -not $Result.PSObject.Properties['existingCompanion']){
        throw 'RELEASE_CORRECTIVE_288_COMPANION_REQUIRED'
    }
    $ReadBack=Read-RegistrySuccessorAnchor $Source
    if($null -eq $ReadBack -or -not (Same-Json $Anchor $ReadBack) -or
       $Result.generation -cne $Anchor.record.generation){
        throw 'RELEASE_REGISTRY_SUCCESSOR_ANCHOR_CHANGED'
    }
    return $Result
}

function Assert-CorrectiveRegistryContainer {
    param($C,[string]$Nonce,[string]$Image,[string]$Profile,[string]$Role,[string]$Commit,
          [ValidateSet('','created','running','exited')][string]$Status='',
          [switch]$Accepted,[switch]$BootstrapRetained,[switch]$LatestPin)
    $Id=$Nonce.Replace('-','')
    $Name='/fortis-registry-successor-'+$Id
    $Restart='no';$ExpectedStatus='created';$StateWrite=$true
    $Cmd=@('python','-m','fortis_approvals.registry.local_candidate_read_service',
        '--owner-config','/run/fortis-registry-runtime/profile.json','--expected-profile-sha256',$Profile)
    if($Role -ceq 'source'){$Restart='unless-stopped';$ExpectedStatus='running'}
    elseif($Role -ceq 'preview'){
        $Name+='-preview';$StateWrite=$false;$ExpectedStatus='running'
        $Cmd+=@('--corrective-preview-sha',$Commit)
    } elseif($Role -cne 'writer'){throw 'RELEASE_CORRECTIVE_REGISTRY_ROLE_INVALID'}
    if($Status){$ExpectedStatus=$Status}
    if($BootstrapRetained){
        if($Accepted -or $Role -cne 'writer' -or
           $Nonce -cne '4ec7d8b8-2b51-4457-8b15-6559bcdeae94' -or
           $C.Id -cne 'fb747224e917dc88653dac29961f2d11bebca6023c9f73317c4ce6ce7597ae18' -or
           $Commit -cne '073d6f8701595e499eac5a1fa0cbe90accb05819' -or
           $ExpectedStatus -cnotin @('running','exited') -or
           $C.HostConfig.RestartPolicy.Name -cnotin @('no','unless-stopped')){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_SOURCE_CHANGED'
        }
        $Restart=$C.HostConfig.RestartPolicy.Name
    }
    if($Accepted){
        if($Role -cne 'writer' -or $ExpectedStatus -cne 'running'){throw 'RELEASE_CORRECTIVE_REGISTRY_ROLE_INVALID'}
        $Restart='unless-stopped'
    }
    if($C.Id -cnotmatch '^[0-9a-f]{64}$' -or $C.Name -cne $Name -or $C.Image -cne $Image -or
       $Image -cnotmatch '^sha256:[0-9a-f]{64}$' -or $Profile -cnotmatch '^[0-9a-f]{64}$' -or
       $C.State.Status -cne $ExpectedStatus -or
       ($Role -ceq 'writer' -and $ExpectedStatus -ceq 'created' -and $C.State.StartedAt -cne '0001-01-01T00:00:00Z') -or
       $C.Config.User -cne '20002:20002' -or $C.HostConfig.NetworkMode -cne 'none' -or
       $C.HostConfig.RestartPolicy.Name -cne $Restart -or $C.HostConfig.RestartPolicy.MaximumRetryCount -ne 0 -or
       $C.HostConfig.Init -ne $true -or $C.HostConfig.ReadonlyRootfs -ne $true -or
       $C.HostConfig.Privileged -ne $false -or @($C.HostConfig.CapAdd|Where-Object{$_}).Count -ne 0 -or
       (@($C.HostConfig.CapDrop) -join ',') -cne 'ALL' -or
       (@($C.HostConfig.SecurityOpt) -join ',') -cne 'no-new-privileges:true' -or
       $C.HostConfig.PidsLimit -ne 64 -or $C.HostConfig.Memory -ne 536870912 -or
       $C.Path -cne 'python' -or @($C.Config.Entrypoint|Where-Object{$_}).Count -ne 0 -or
       -not (Same-Json @($C.Config.Cmd) $Cmd) -or
       -not (Same-Json @($C.Args) @($Cmd[1..($Cmd.Count-1)])) -or @($C.Mounts).Count -ne $(if($LatestPin){7}else{6})){
        throw 'RELEASE_CORRECTIVE_REGISTRY_CONTAINER_CHANGED'
    }
    if($Role -cne 'source' -and $C.Config.Labels.'org.opencontainers.image.revision' -cne $Commit){
        throw 'RELEASE_CORRECTIVE_REGISTRY_IMAGE_SOURCE_CHANGED'
    }
    $Mounts=@(
        @(('fortis-registry-state-e13b-'+$Id),'/run/fortis-registry-state',$StateWrite),
        @(('fortis-registry-config-e13b-'+$Id),'/run/fortis-registry-runtime',$false),
        @(('fortis-registry-read-'+$Id),'/run/fortis-registry-read',$true),
        @(('fortis-registry-source-evidence-'+$Id),'/run/fortis-registry-source-evidence',$false),
        @(('fortis-registry-source-'+$Id),'/run/fortis-registry-source',$false),
        @($(if($LatestPin){'fortis-r7-maintenance-interlock-v2'}else{'fortis-r7-maintenance-interlock'}),'/run/r7-maintenance',$false))
    if($LatestPin){$Mounts+=,@('fortis-r7-maintenance-anchor','/run/r7-maintenance-anchor',$false)}
    foreach($Mount in $Mounts){
        Assert-Volume $Mount[0]
        $Found=@($C.Mounts|Where-Object{$_.Type -ceq 'volume' -and $_.Name -ceq $Mount[0] -and
            $_.Source -ceq ('/var/lib/docker/volumes/'+$Mount[0]+'/_data') -and
            $_.Destination -ceq $Mount[1] -and $_.RW -is [bool] -and $_.RW -eq $Mount[2]})
        if($Found.Count -ne 1){throw 'RELEASE_CORRECTIVE_REGISTRY_MOUNT_CHANGED'}
    }
}
function Assert-CorrectiveTargetHolders {
    param([string]$Nonce,[string[]]$Allowed,[switch]$PreparedProfiles)
    $Id=$Nonce.Replace('-','')
    $Volumes=@(('fortis-registry-state-e13b-'+$Id),('fortis-registry-config-e13b-'+$Id),
        ('fortis-registry-read-'+$Id),('fortis-registry-source-evidence-'+$Id),
        ('fortis-registry-source-'+$Id),('fortis-r7-registry-reader-'+$Id))
    if($PreparedProfiles){
        $Volumes+=@(('fortis-registry-config-e13b-'+$Id+'-prepared'),('fortis-r7-registry-reader-'+$Id+'-prepared'))
    }
    Assert-ReleaseVolumeHolders $Volumes $Allowed 'RELEASE_CORRECTIVE_REGISTRY_TARGET_HOLDER_CHANGED'
}
function Assert-OperationalMaintenanceHolders {
    param($Source,[string[]]$Allowed,[string]$ErrorCode)
    # The global operational volumes survive releases. Only exact recorded
    # ancestors may retain their original RO mounts while stopped, never a
    # running or auto-restarting old generation or an unrecorded alias.
    $Retained=@{};$Seen=@{};$Cursor=$Source
    while($Cursor -and (Test-SuccessorLatestDelivery $Cursor.runtime.registryDelivery)){
        if($Seen.ContainsKey($Cursor.path) -or $Seen.Count -ge 128 -or
           (Get-FileHash -LiteralPath $Cursor.path -Algorithm SHA256).Hash -ine $Cursor.hash){
            throw $ErrorCode
        }
        $Seen[$Cursor.path]=$true
        $Record=Read-Private $Cursor.path
        $Receiver=$Record.bootstrapReceiver
        if($Record.schema -cne 'fortis-extension-release-v1' -or $Record.phase -cne 'Complete' -or
           $Record.activated -ne $true -or $Record.runtime.pilotId -cne $Cursor.runtime.pilotId -or
           $Record.runtime.image -cne $Cursor.runtime.image -or
           -not (Same-Json $Record.runtime.registryDelivery $Cursor.runtime.registryDelivery) -or
           $Receiver.id -cnotmatch '^[0-9a-f]{64}$' -or $Receiver.image -cnotmatch '^sha256:[0-9a-f]{64}$'){
            throw $ErrorCode
        }
        $Retained[$Record.runtime.pilotId]=$Record.runtime.image
        $Retained[$Receiver.id]=$Receiver.image
        $Cursor=$Record.source
    }
    Assert-ReleaseVolumeHolders @('fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor') $Allowed $ErrorCode -RetainedReadOnly $Retained
}
function Assert-ReleaseVolumeHolders {
    param([string[]]$Volumes,[string[]]$Allowed,[string]$ErrorCode,$RetainedReadOnly=$null)
    $Ids=@((Docker-Text @('ps','-aq','--no-trunc')) -split '\r?\n'|Where-Object{$_})
    foreach($C in @(Inspect-Containers $Ids)){
        if($Allowed -ccontains $C.Id){continue}
        foreach($M in $C.Mounts){
            $NameField=$M.PSObject.Properties['Name']
            $MountName=if($NameField){[string]$NameField.Value}else{''}
            $SourceField=$M.PSObject.Properties['Source']
            if(-not $SourceField){throw $ErrorCode}
            $MountSource=[string]$SourceField.Value
            foreach($V in $Volumes){
                $Root='/var/lib/docker/volumes/'+$V+'/_data'
                if($MountName -ceq $V -or ($MountSource -and ($MountSource -ceq $Root -or
                   $MountSource.StartsWith($Root+'/',[StringComparison]::Ordinal) -or
                   $Root.StartsWith($MountSource.TrimEnd('/')+'/',[StringComparison]::Ordinal)))){
                    $Destination=if($V -ceq 'fortis-r7-maintenance-interlock-v2'){'/run/r7-maintenance'}
                        elseif($V -ceq 'fortis-r7-maintenance-anchor'){'/run/r7-maintenance-anchor'}else{''}
                    if($Destination -and $RetainedReadOnly -and $RetainedReadOnly.ContainsKey($C.Id) -and
                       $C.Image -ceq $RetainedReadOnly[$C.Id] -and $C.State.Status -ceq 'exited' -and
                       $C.HostConfig.RestartPolicy.Name -ceq 'no' -and $C.HostConfig.RestartPolicy.MaximumRetryCount -eq 0 -and
                       $M.Type -ceq 'volume' -and $MountName -ceq $V -and $MountSource -ceq $Root -and
                       $M.Destination -ceq $Destination -and $M.RW -is [bool] -and -not $M.RW){continue}
                    throw $ErrorCode
                }
            }
        }
    }
}
function Read-CorrectiveSourceSnapshot {
    param([string]$Id,[string]$OldProfile)
    $SourceCode=@'
import hashlib,json,sys
sys.path.insert(0,'/opt/fortis')
from pathlib import Path
from fortis_approvals.registry.local_candidate_read_service import _load_owner_config,_check_successor_profile,_readonly_owner_runtime
from fortis_approvals.registry.owner_functional_v1_bootstrap import STATE_PATH
from fortis_approvals.registry.release_event_journal import ReleaseEventJournal
from fortis_approvals.registry.protected_transition import staged_domain
p=json.load(sys.stdin)
path='/run/fortis-registry-runtime/profile.json'
root=_readonly_owner_runtime(path)
cfg=_load_owner_config(path,allow_semantic=True)
_check_successor_profile(cfg,p['profile'])
if cfg['registryStatePath']!=str(STATE_PATH):raise RuntimeError('SOURCE_CORRECTIVE_PATH_CHANGED')
pins=cfg['semantic']
j=ReleaseEventJournal(STATE_PATH,instance_id=cfg['instanceId'],scope=cfg['scope'],
    expected_legacy=pins['legacyWitness'],transition_digest=pins['transitionDigest'])
v=staged_domain(j,root,pins).snapshot()
if v['operations']:raise RuntimeError('SOURCE_CORRECTIVE_STATE_CHANGED')
view={k:v[k] for k in ('sourceOperations','sourceRevision','snapshotRevision','sourceCursor','operations',
    'sourceTransitionPending','catalogSha256','profileDigest','eventDigest')}
view['states']={k:{f:s[f] for f in ('activeAttempt','installed','ownerReported')} for k,s in v['states'].items()}
print(json.dumps({'view':view,'instance_id':j.instance_id,'scope':j.scope,
    'legacy_witness':j.expected_legacy,'transition_digest':j.transition_digest},sort_keys=True,separators=(',',':')))
'@
    $Raw=Python-Code @('exec','-i','--user','20002:20002',$Id) $SourceCode (ConvertTo-Json -Compress @{profile=$OldProfile})
    if($Raw.Length -gt 262144){throw 'RELEASE_CORRECTIVE_REGISTRY_SOURCE_EVIDENCE_TOO_LARGE'}
    return $Raw
}
function Read-CorrectiveRegistryPair {
    param($Source)
    $Anchor=Read-Corrective288Anchor $Source
    $OldNonce=$Source.runtime.registryReleaseNonce
    $Nonce=$script:RegistryBoundReleaseNonce
    if($Nonce -ceq $OldNonce -or $Nonce -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'){
        throw 'RELEASE_CORRECTIVE_REGISTRY_NONCE_CHANGED'
    }
    $Old=Container 'abc934c2becc4066e739e4fac3cd276975dcd137a6b0acdae89b81d249df454d'
    $OldProfile='a24fe5d8cf12971b381361d5a9fa56af6dafed679df0e076251d6f5c45d69201'
    Assert-CorrectiveRegistryContainer $Old $OldNonce 'sha256:34f62160f05bd0b1986b6127ec8bb6d9e3ff3124d3550d70c3f98fdabfe27cc3' $OldProfile 'source' ''
    $Name='fortis-registry-successor-'+$Nonce.Replace('-','')
    $PreviewContainer=Container ($Name+'-preview')
    $Writer=Container $Name
    $Profile=$CorrectiveRegistryProfileSha256
    $RegistryImage=$CorrectiveRegistryImage
    Assert-CorrectiveRegistryContainer $Writer $Nonce $RegistryImage $Profile 'writer' $SourceSha
    Assert-CorrectiveRegistryContainer $PreviewContainer $Nonce $RegistryImage $Profile 'preview' $SourceSha
    if($Writer.Id -ceq $PreviewContainer.Id -or $Writer.Id -ceq $Old.Id -or
       -not (Same-Json @($Writer.Config.Env) @($PreviewContainer.Config.Env))){
        throw 'RELEASE_CORRECTIVE_REGISTRY_CONTAINER_CHANGED'
    }
    Assert-CorrectiveTargetHolders $Nonce @($PreviewContainer.Id,$Writer.Id)
    $OldId=$OldNonce.Replace('-','')
    Assert-OnlyWriter ('fortis-registry-state-e13b-'+$OldId) $Old.Id
    Assert-OnlyWriter ('fortis-registry-read-'+$OldId) $Old.Id
    Assert-OnlyWriter ('fortis-registry-config-e13b-'+$OldId)
    Assert-OnlyWriter ('fortis-registry-source-'+$OldId)
    Assert-OnlyWriter ('fortis-registry-source-evidence-'+$OldId) $Source.runtime.pilotId
    Assert-OnlyWriter 'fortis-r7-maintenance-interlock'
    # Old image replays its own database. Send bounded ASCII evidence
    # directly to the new preview's common checkpoint validator.
    $Raw=Read-CorrectiveSourceSnapshot $Old.Id $OldProfile
    $TargetCode=@'
import json,sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.registry.local_candidate_read_service import _load_owner_config,_check_successor_profile,_readonly_owner_runtime
from fortis_approvals.registry.owner_functional_v1_bootstrap import STATE_PATH
from fortis_approvals.registry.release_event_journal import ReleaseEventJournal
from fortis_approvals.registry.protected_transition import staged_domain,corrective_checkpoint,corrective_checkpoint_view,verify_corrective_pair
p=json.load(sys.stdin)
path='/run/fortis-registry-runtime/profile.json'
root=_readonly_owner_runtime(path)
cfg=_load_owner_config(path,allow_semantic=True)
_check_successor_profile(cfg,p['profile'])
if cfg['registryStatePath']!=str(STATE_PATH):raise RuntimeError('SOURCE_CORRECTIVE_PATH_CHANGED')
pins=cfg['semantic']
j=ReleaseEventJournal(STATE_PATH,instance_id=cfg['instanceId'],scope=cfg['scope'],
    expected_legacy=pins['legacyWitness'],transition_digest=pins['transitionDigest'],immutable_snapshot=True)
source=corrective_checkpoint_view(**json.loads(p['source']),expected_revision=2,
    expected_source_sha='5ab74dbd5f4f743b325bafd2444486180c3cdf7f')
target=corrective_checkpoint(staged_domain(j,root,pins),expected_revision=3,expected_source_sha=p['commit'])
print(json.dumps(verify_corrective_pair(source,target,expected_source_sha=p['commit']),sort_keys=True,separators=(',',':')))
'@
    $Payload=ConvertTo-Json -Compress @{profile=$Profile;commit=$SourceSha;source=$Raw}
    $Pair=(Python-Code @('exec','-i','--user','20002:20002',$PreviewContainer.Id) $TargetCode $Payload)|ConvertFrom-Json
    if($Pair.source.eventDigest -cne 'b3e80ca0f3bd1ae7f7fbcc15bed3942826af931dc025f9ec86f11534b368f634' -or
       $Pair.target.sourceCursor -cne $SourceSha -or $Pair.source.instanceId -cne $Anchor.record.registryInstanceId -or
       $Pair.source.scopeDigest -cne $Anchor.record.scopeDigest){
        throw 'RELEASE_CORRECTIVE_REGISTRY_PAIR_CHANGED'
    }
    Admit-Source (Container $Source.runtime.pilotId) $Source
    Assert-CorrectiveTargetHolders $Nonce @($PreviewContainer.Id,$Writer.Id)
    Assert-CorrectiveRegistryContainer (Container $Old.Id) $OldNonce $Old.Image $OldProfile 'source' ''
    Assert-CorrectiveRegistryContainer (Container $Writer.Id) $Nonce $Writer.Image $Profile 'writer' $SourceSha
    Assert-CorrectiveRegistryContainer (Container $PreviewContainer.Id) $Nonce $Writer.Image $Profile 'preview' $SourceSha
    return [ordered]@{sourceRegistryId=$Old.Id;sourceRegistryImage=$Old.Image;sourceRegistryProfile=$OldProfile
        targetRegistryId=$Writer.Id;targetPreviewId=$PreviewContainer.Id;targetRegistryImage=$Writer.Image
        targetRegistryProfile=$Profile;anchorDigest=$Anchor.digest;checkpoints=$Pair}
}



# Read the exact stopped database, including committed WAL, or the new live
# writer. No original file is modified by the frozen scratch replay.
function Read-CorrectiveCheckpoint {
    param([string]$Id,[string]$Nonce,[string]$Profile,[string]$Image,
          [int]$Revision,[string]$Commit,[switch]$Frozen)
    $Code=@'
import json,sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.registry.local_candidate_read_service import _load_owner_config,_check_successor_profile,_readonly_owner_runtime
from fortis_approvals.registry.owner_functional_v1_bootstrap import STATE_PATH
from fortis_approvals.registry.release_event_journal import ReleaseEventJournal
from fortis_approvals.registry.protected_transition import staged_domain,corrective_checkpoint,frozen_corrective_checkpoint
p=json.load(sys.stdin)
path='/run/fortis-registry-runtime/profile.json'
root=_readonly_owner_runtime(path)
cfg=_load_owner_config(path,allow_semantic=True)
_check_successor_profile(cfg,p['profile'])
if cfg['registryStatePath']!=str(STATE_PATH):raise RuntimeError('SOURCE_CORRECTIVE_PATH_CHANGED')
pins=cfg['semantic']
j=ReleaseEventJournal(STATE_PATH,instance_id=cfg['instanceId'],scope=cfg['scope'],
    expected_legacy=pins['legacyWitness'],transition_digest=pins['transitionDigest'])
kw={'expected_revision':p['revision'],'expected_source_sha':p['commit']}
result=(frozen_corrective_checkpoint(j,root,pins,**kw) if p['frozen']
        else corrective_checkpoint(staged_domain(j,root,pins),**kw))
print(json.dumps(result,sort_keys=True,separators=(',',':')))
'@
    $Payload=ConvertTo-Json -Compress @{profile=$Profile;revision=$Revision;commit=$Commit;frozen=[bool]$Frozen}
    if($Frozen){
        $Suffix=$Nonce.Replace('-','')
        $State='fortis-registry-state-e13b-'+$Suffix
        $ConfigVolume='fortis-registry-config-e13b-'+$Suffix
        Assert-Volume $State;Assert-Volume $ConfigVolume
        Assert-OnlyWriter $State;Assert-OnlyWriter $ConfigVolume
        if((Container $Id).State.Status -cnotin @('created','exited')){
            throw 'RELEASE_CORRECTIVE_REGISTRY_NOT_FROZEN'
        }
        $Args=@('run','--rm','-i','--pull=never','--network','none','--read-only',
            '--user','20002:20002','--cap-drop','ALL','--security-opt','no-new-privileges:true',
            '--pids-limit','32','--memory','1024m','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=640m,uid=20002,gid=20002,mode=0700',
            '--mount',('type=volume,source='+$State+',target=/run/fortis-registry-state,readonly,volume-nocopy'),
            '--mount',('type=volume,source='+$ConfigVolume+',target=/run/fortis-registry-runtime,readonly,volume-nocopy'),$Image)
    } else {
        $Args=@('exec','-i','--user','20002:20002',$Id)
    }
    $Result=(Python-Code $Args $Code $Payload)|ConvertFrom-Json
    if($Frozen){Assert-OnlyWriter $State;Assert-OnlyWriter $ConfigVolume}
    return $Result
}

function Read-CorrectiveAttemptPair {
    # The existing protected attempt/Check records own the exact pair.
    $PairField=if($script:R -is [Collections.IDictionary]){$script:R['correctivePair']}
        else{$P=$script:R.PSObject.Properties['correctivePair'];if($P){$P.Value}}
    if(-not $PairField){return}
    $Source=$script:R.source
    $Anchor=Read-Corrective288Anchor $Source
    if((Read-Private $AttemptPointer).record -cne $script:RecordPath -or
       (Get-FileHash -LiteralPath $script:R.correctiveCheckRecord -Algorithm SHA256).Hash -ine $script:R.correctiveCheckHash){
        throw 'RELEASE_CORRECTIVE_ATTEMPT_CHANGED'
    }
    $Checked=Read-Private $script:R.correctiveCheckRecord
    if($Checked.schema -cne 'fortis-extension-image-check-v1' -or $Checked.phase -cne 'Ready' -or
       -not (Same-Json $Checked.binding.correctivePair $PairField) -or
       $Checked.binding.sourceHash -ine $Source.hash -or $Checked.binding.image -cne $script:R.runtime.image -or
       $Checked.binding.registryReleaseNonce -cne $script:R.runtime.registryReleaseNonce -or
       $Checked.binding.sourceSha -cne $PairField.checkpoints.target.sourceCursor -or
       $Checked.binding.registryProfileDigest -cne $script:R.runtime.registryProfileDigest -or
       $Checked.binding.configurationDigest -cne $script:R.configurationDigest -or
       -not (Same-Json $Checked.binding.registryDelivery $script:R.runtime.registryDelivery) -or
       -not (Same-Json $Checked.sourceReceipt $script:R.sourceReceipt) -or
       $PairField.anchorDigest -cne $Anchor.digest){
        throw 'RELEASE_CORRECTIVE_ATTEMPT_CHANGED'
    }
    foreach($Pin in @(@($Pointer,$Checked.binding.currentPointerHash),
        @($PrimaryPointer,$Checked.binding.primaryPointerHash),
        @((Join-Path $ReleaseBase 'primary-backup.json'),$Checked.binding.backupPointerHash))){
        if((Get-FileHash -LiteralPath $Pin[0] -Algorithm SHA256).Hash -ine $Pin[1]){
            throw 'RELEASE_CORRECTIVE_ATTEMPT_CHANGED'
        }
    }
    return $PairField
}

function Assert-CorrectiveStoppedSource {
    param($Pair)
    $S=$script:R.source.runtime
    if((Container $S.pilotId).State.Status -cne 'exited'){
        throw 'RELEASE_CORRECTIVE_SOURCE_GATEWAY_RUNNING'
    }
    Assert-SourceUnchanged
    Assert-CorrectiveTargetHolders $S.registryReleaseNonce @($Pair.sourceRegistryId,$S.pilotId)
    $Old=Container $Pair.sourceRegistryId
    Assert-CorrectiveRegistryContainer $Old $S.registryReleaseNonce $Pair.sourceRegistryImage $Pair.sourceRegistryProfile 'source' '' -Status 'exited'
    $Frozen=Read-CorrectiveCheckpoint $Old.Id $S.registryReleaseNonce $Pair.sourceRegistryProfile $Pair.targetRegistryImage 2 $Pair.checkpoints.source.sourceCursor -Frozen
    if(-not (Same-Json $Frozen $Pair.checkpoints.source)){
        throw 'RELEASE_CORRECTIVE_FROZEN_SOURCE_CHANGED'
    }
}

function Assert-CorrectiveTargetCheckpoint {
    param($Pair,[switch]$Frozen)
    $P=$script:R.runtime
    $Commit=$Pair.checkpoints.target.sourceCursor
    $Status=if($Frozen){'created'}else{'running'}
    $Writer=Container $Pair.targetRegistryId
    Assert-CorrectiveRegistryContainer $Writer $P.registryReleaseNonce $Pair.targetRegistryImage $Pair.targetRegistryProfile 'writer' $Commit -Status $Status
    $Preview=Container $Pair.targetPreviewId
    Assert-CorrectiveRegistryContainer $Preview $P.registryReleaseNonce $Pair.targetRegistryImage $Pair.targetRegistryProfile 'preview' $Commit -Status 'exited'
    $Allowed=@($Writer.Id,$Preview.Id)
    if($P.pilotId){$Allowed+=$P.pilotId}
    Assert-CorrectiveTargetHolders $P.registryReleaseNonce $Allowed
    $Suffix=$P.registryReleaseNonce.Replace('-','')
    $AllowedWriter=if($Frozen){''}else{$Writer.Id}
    Assert-OnlyWriter ('fortis-registry-state-e13b-'+$Suffix) $AllowedWriter
    Assert-OnlyWriter ('fortis-registry-read-'+$Suffix) $AllowedWriter
    $Actual=Read-CorrectiveCheckpoint $Writer.Id $P.registryReleaseNonce $Pair.targetRegistryProfile $Pair.targetRegistryImage 3 $Commit -Frozen:$Frozen
    if(-not (Same-Json $Actual $Pair.checkpoints.target)){
        throw 'RELEASE_CORRECTIVE_TARGET_CHECKPOINT_CHANGED'
    }
}

function Wait-CorrectiveRegistryListener {
    param([string]$Id)
    # Docker start ACK is not listener readiness. This bounded transport-only
    # wait is followed by the full authenticated peer and journal admission.
    $Code=@'
import socket,stat,time
from pathlib import Path
path=Path('/run/fortis-registry-read/reader.sock')
deadline=time.monotonic()+15
while time.monotonic()<deadline:
    try:
        row=path.lstat()
        if not (stat.S_ISSOCK(row.st_mode) and row.st_nlink==1 and
                row.st_uid==20002 and row.st_gid==10001 and stat.S_IMODE(row.st_mode)==0o660):
            raise RuntimeError('SOURCE_CORRECTIVE_LISTENER_IDENTITY')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
            peer.settimeout(1)
            peer.connect(str(path))
        after=path.lstat()
        if (row.st_dev,row.st_ino)!=(after.st_dev,after.st_ino):
            raise RuntimeError('SOURCE_CORRECTIVE_LISTENER_CHANGED')
        print('CORRECTIVE_LISTENER_AVAILABLE')
        break
    except (FileNotFoundError,ConnectionRefusedError,TimeoutError):
        time.sleep(0.25)
else:
    raise RuntimeError('SOURCE_CORRECTIVE_LISTENER_TIMEOUT')
'@
    $Observed=Python-Code @('exec','-i','--user','20002:20002',$Id) $Code '{}'
    if($Observed -cne 'CORRECTIVE_LISTENER_AVAILABLE' -or (Container $Id).State.Status -cne 'running'){
        throw 'RELEASE_CORRECTIVE_LISTENER_UNCONFIRMED'
    }
}

function Switch-CorrectiveRegistryPair {
    $Pair=Read-CorrectiveAttemptPair
    if(-not $Pair){throw 'RELEASE_CORRECTIVE_ATTEMPT_CHANGED'}
    $S=$script:R.source.runtime
    $P=$script:R.runtime
    if((Container $S.pilotId).State.Status -cne 'exited'){throw 'RELEASE_CORRECTIVE_SOURCE_GATEWAY_RUNNING'}
    Assert-SourceUnchanged
    Assert-CorrectiveTargetHolders $S.registryReleaseNonce @($Pair.sourceRegistryId,$S.pilotId)
    Assert-CorrectiveRegistryContainer (Container $Pair.sourceRegistryId) $S.registryReleaseNonce $Pair.sourceRegistryImage $Pair.sourceRegistryProfile 'source' ''
    Assert-CorrectiveRegistryContainer (Container $Pair.targetRegistryId) $P.registryReleaseNonce $Pair.targetRegistryImage $Pair.targetRegistryProfile 'writer' $Pair.checkpoints.target.sourceCursor
    Assert-CorrectiveRegistryContainer (Container $Pair.targetPreviewId) $P.registryReleaseNonce $Pair.targetRegistryImage $Pair.targetRegistryProfile 'preview' $Pair.checkpoints.target.sourceCursor
    Assert-CorrectiveTargetHolders $P.registryReleaseNonce @($Pair.targetRegistryId,$Pair.targetPreviewId)
    Step 'CORRECTIVE_STOP_SOURCE_REGISTRY'
    $null=Docker-Text @('stop','--timeout','20',$Pair.sourceRegistryId)
    Assert-CorrectiveStoppedSource $Pair
    Step 'CORRECTIVE_STOP_READONLY_PREVIEW'
    $null=Docker-Text @('stop','--timeout','20',$Pair.targetPreviewId)
    Assert-CorrectiveTargetCheckpoint $Pair -Frozen
    Step 'CORRECTIVE_START_TARGET_REGISTRY'
    $null=Docker-Text @('start',$Pair.targetRegistryId)
    Wait-CorrectiveRegistryListener $Pair.targetRegistryId
    Assert-CorrectiveTargetCheckpoint $Pair
    # Managed schema-5 authenticates the new live process by its independent
    # key and kernel liveness, not the Preview's PID or socket inode.
    $Delivery=Image-RegistrySuccessor-Preflight -ImageId $P.image -ReleaseNonce $P.registryReleaseNonce -InterlockDigest $Pair.anchorDigest -IncumbentVolume $S.stateVolume
    if(-not (Same-Json $Delivery $P.registryDelivery)){throw 'RELEASE_CORRECTIVE_TARGET_PEER_CHANGED'}
    Assert-CorrectiveStoppedSource $Pair
}

function Complete-CorrectiveRegistryPair {
    param($Pair)
    $P=$script:R.runtime;$S=$script:R.source.runtime
    if((Container $S.pilotId).State.Status -cne 'exited' -or
       (Container $Pair.sourceRegistryId).State.Status -cne 'exited' -or
       (Container $Pair.targetPreviewId).State.Status -cne 'exited'){
        throw 'RELEASE_CORRECTIVE_SOURCE_NOT_RETAINED'
    }
    $Writer=Container $Pair.targetRegistryId
    $Accepted=$Writer.HostConfig.RestartPolicy.Name -ceq 'unless-stopped'
    Assert-CorrectiveRegistryContainer $Writer $P.registryReleaseNonce $Pair.targetRegistryImage $Pair.targetRegistryProfile 'writer' $Pair.checkpoints.target.sourceCursor -Status 'running' -Accepted:$Accepted
    Assert-CorrectiveTargetHolders $P.registryReleaseNonce @($Writer.Id,$Pair.targetPreviewId,$P.pilotId)
    Assert-OnlyWriter ('fortis-registry-state-e13b-'+$P.registryReleaseNonce.Replace('-','')) $Writer.Id
    $GateInput=ConvertTo-Json -Compress @{nonce=$P.releaseNonce;configurationDigest=$script:R.configurationDigest}
    $Gate=Image-CLI @('gate-record-status') $GateInput -StateVolume $P.stateVolume
    if($Gate.active -ne $true -or $Gate.markerPresent -ne $true){
        throw 'RELEASE_CORRECTIVE_ACTIVATION_UNCONFIRMED'
    }
    # No rollback after the durable activation marker, even if the command
    # ACK or final record is lost. Read back an already-applied policy update.
    if(-not $Accepted){
        Step 'CORRECTIVE_ACCEPT_TARGET_REGISTRY'
        $null=Docker-Text @('update','--restart=unless-stopped',$Writer.Id)
    }
    Assert-CorrectiveRegistryContainer (Container $Writer.Id) $P.registryReleaseNonce $Pair.targetRegistryImage $Pair.targetRegistryProfile 'writer' $Pair.checkpoints.target.sourceCursor -Status 'running' -Accepted
    Admit (Container $P.pilotId) $P
}

function Assert-CorrectiveGateAbsent {
    param($P)
    $Volumes=(Docker-Text @('volume','ls','--format','{{.Name}}')) -split '\r?\n'
    if($Volumes -ccontains $P.stateVolume){
        $InputText=ConvertTo-Json -Compress @{nonce=$P.releaseNonce;configurationDigest=$script:R.configurationDigest}
        $Gate=Image-CLI @('gate-record-status') $InputText -StateVolume $P.stateVolume
        # Invalid or unreadable marker is not evidence of non-activation.
        if($Gate.active -ne $false -or $Gate.markerPresent -ne $false){
            throw 'RELEASE_ALREADY_ACTIVE_RETURN_REQUIRES_REVIEW'
        }
    }
}

function Return-CorrectivePair {
    param($Pair)
    $S=$script:R.source.runtime;$P=$script:R.runtime
    Assert-Release-Production
    Assert-CorrectiveGateAbsent $P
    $OldGateway=Container $S.pilotId
    $OldRegistry=Container $Pair.sourceRegistryId
    if($OldGateway.State.Status -cnotin @('running','exited') -or
       $OldRegistry.State.Status -cnotin @('running','exited')){
        throw 'RELEASE_CORRECTIVE_SOURCE_STATE_UNKNOWN'
    }
    if($OldRegistry.State.Status -ceq 'exited'){
        Assert-CorrectiveStoppedSource $Pair
    } else {
        Assert-CorrectiveRegistryContainer $OldRegistry $S.registryReleaseNonce $Pair.sourceRegistryImage $Pair.sourceRegistryProfile 'source' ''
        Admit $OldGateway $S -AllowUnhealthy
        if($OldGateway.State.Status -ceq 'exited'){Assert-SourceUnchanged}
    }
    $Writer=Container $Pair.targetRegistryId;$Preview=Container $Pair.targetPreviewId
    if($Writer.State.Status -cnotin @('created','exited','running') -or $Preview.State.Status -cnotin @('running','exited') -or
       ($Writer.State.Status -ceq 'running' -and ($OldRegistry.State.Status -cne 'exited' -or $Preview.State.Status -cne 'exited'))){
        throw 'RELEASE_CORRECTIVE_REGISTRY_STATE_UNKNOWN'
    }
    $Commit=$Pair.checkpoints.target.sourceCursor
    Assert-CorrectiveRegistryContainer $Writer $P.registryReleaseNonce $Pair.targetRegistryImage $Pair.targetRegistryProfile 'writer' $Commit -Status $Writer.State.Status
    Assert-CorrectiveRegistryContainer $Preview $P.registryReleaseNonce $Pair.targetRegistryImage $Pair.targetRegistryProfile 'preview' $Commit -Status $Preview.State.Status
    $Names=(Docker-Text @('ps','-a','--format','{{.Names}}')) -split '\r?\n'
    $Candidate=$null
    if($Names -ccontains $P.pilotName){
        $Candidate=Container $P.pilotName
        if(-not $P.pilotId -or $Candidate.Id -cne $P.pilotId){throw 'RELEASE_CORRECTIVE_CANDIDATE_ID_UNKNOWN'}
        Admit-ReturnCandidate $Candidate $P
        if($Candidate.State.Status -cnotin @('created','exited','running')){throw 'RELEASE_CANDIDATE_STATE_UNKNOWN'}
    } elseif($P.pilotId){throw 'RELEASE_CORRECTIVE_CANDIDATE_ID_UNKNOWN'}
    $Allowed=@($Writer.Id,$Preview.Id)
    if($Candidate){$Allowed+=$Candidate.Id}
    Assert-CorrectiveTargetHolders $P.registryReleaseNonce $Allowed
    # Recheck the marker before and after the final candidate stop.
    Assert-CorrectiveGateAbsent $P
    if($Candidate -and $Candidate.State.Status -ceq 'running'){
        $null=Docker-Text @('stop','--timeout','20',$Candidate.Id)
        if((Container $Candidate.Id).State.Status -cne 'exited'){throw 'RELEASE_STOP_UNCONFIRMED'}
    }
    Assert-CorrectiveGateAbsent $P
    if($Writer.State.Status -ceq 'running'){$null=Docker-Text @('stop','--timeout','20',$Writer.Id)}
    if($Preview.State.Status -ceq 'running'){$null=Docker-Text @('stop','--timeout','20',$Preview.Id)}
    if((Container $Writer.Id).State.Status -cnotin @('created','exited') -or (Container $Preview.Id).State.Status -cne 'exited'){
        throw 'RELEASE_CORRECTIVE_TARGET_STOP_UNCONFIRMED'
    }
    Assert-OnlyWriter ('fortis-registry-state-e13b-'+$P.registryReleaseNonce.Replace('-',''))
    if($OldRegistry.State.Status -ceq 'exited'){
        Assert-CorrectiveStoppedSource $Pair
        Step 'CORRECTIVE_RETURN_SOURCE_REGISTRY'
        $null=Docker-Text @('start',$OldRegistry.Id)
        Wait-CorrectiveRegistryListener $OldRegistry.Id
    }
    Assert-CorrectiveRegistryContainer (Container $OldRegistry.Id) $S.registryReleaseNonce $Pair.sourceRegistryImage $Pair.sourceRegistryProfile 'source' ''
    $ReadBack=(Read-CorrectiveSourceSnapshot $OldRegistry.Id $Pair.sourceRegistryProfile)|ConvertFrom-Json
    if($ReadBack.view.sourceRevision -ne 2 -or $ReadBack.view.sourceCursor -cne $Pair.checkpoints.source.sourceCursor -or
       $ReadBack.view.eventDigest -cne $Pair.checkpoints.source.eventDigest){
        throw 'RELEASE_CORRECTIVE_RETURN_JOURNAL_CHANGED'
    }
    Admit $OldGateway $S -AllowUnhealthy
    if($OldGateway.State.Status -ceq 'exited'){
        Assert-SourceUnchanged
        Step 'CORRECTIVE_RETURN_SOURCE_GATEWAY'
        $null=Docker-Text @('start',$OldGateway.Id)
    }
    Wait-Healthy $OldGateway.Id
    Admit (Container $OldGateway.Id) $S
    Assert-Release-Production
    $script:R.phase='Returned';Save -FlushToDisk
    Write-Host 'FORTIS_INTEGRATIONS_RETURNED_SOURCE'
}

function Initialize-StagedRegistryCollector {
    param($Runtime)
    if(-not $Runtime.registryReaderVolume){return}
    Assert-Volume $Runtime.stateVolume
    Assert-OnlyWriter $Runtime.stateVolume
    Assert-Volume $Runtime.registryReaderVolume
    Assert-OnlyWriter $Runtime.registryReaderVolume
    $Code=@'
import json,sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.r7_unified_server import _installed_policy_source_digest
from fortis_approvals.r7_registry_reader_mount import load_owner_registry_reader,reviewed_registry_reader_mount_digest
from fortis_approvals.integrations.github.gateway.functional_review_runtime import prepare_staged_functional_state
p=json.load(sys.stdin);source=_installed_policy_source_digest()
delivery=p.get('delivery',{})
dynamic=delivery.get('latestPin') is True
def check_frozen():
    from fortis_approvals.r7_registry_reader_mount import reviewed_successor_delivery
    actual=reviewed_successor_delivery(expected_release_nonce=p['nonce'],expected_source_digest=source,
        expected_interlock_digest=delivery['sourceDelivery']['interlockDigest'])
    if actual['maintenancePhase']!='STAGED_TARGET_FROZEN' or any(
            delivery.get(k)!=v for k,v in actual.items()):
        raise RuntimeError('REGISTRY_STAGED_SUCCESSOR_WITNESS_CHANGED')
    return actual['profileDigest']
digest=check_frozen() if dynamic else reviewed_registry_reader_mount_digest(expected_release_nonce=p['nonce'],expected_source_digest=source)
if digest!=p['profileDigest']:raise RuntimeError('REGISTRY_STAGED_SEAL_CHANGED')
reader=load_owner_registry_reader(expected_release_nonce=p['nonce'],expected_source_digest=source)
if 'delivery' in p:
    from fortis_approvals.extensions.composite_preservation import prepare_staged_companion
    delivery=p['delivery']
    if 'existingCompanion' in delivery:
        if 'legacyCompanion' in delivery or reader._successor_config.inspect_existing_companion(
                reader,'/state/private/approvals.sqlite') != delivery['existingCompanion']:
            raise RuntimeError('REGISTRY_STAGED_SUCCESSOR_WITNESS_CHANGED')
    else:
        prepare_staged_companion('/state/private/approvals.sqlite',
            legacy=delivery['legacyCompanion'], expected_digest=delivery['companionDigest'],
            verify_history=reader._policy_history.verify_incumbent_storage)
result=prepare_staged_functional_state(reader,'/state/private')
if 'delivery' in p and 'existingCompanion' in p['delivery'] and result['result']!='P5_FUNCTIONAL_LOCAL_COLLECTOR_RETAINED':
    raise RuntimeError('REGISTRY_STAGED_SUCCESSOR_COLLECTOR_CHANGED')
if dynamic and check_frozen()!=digest:raise RuntimeError('REGISTRY_STAGED_SEAL_CHANGED')
print(json.dumps(result,sort_keys=True,separators=(',',':')))
'@
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<registry-staged-collector>','exec'))"
    $Args=@('run','--rm','-i','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','64','--memory','256m',
        '--mount',('type=volume,source='+$Runtime.stateVolume+',target=/state,volume-nocopy'),
        '--mount',('type=volume,source='+$Runtime.registryReaderVolume+',target=/run/r7-registry-reader,readonly'),
        '--mount',('type=volume,source='+$Runtime.registrySocketVolume+',target=/run/fortis-registry-read,readonly'))
    $InputData=@{nonce=$Runtime.registryReleaseNonce;profileDigest=$Runtime.registryProfileDigest}
    if($script:RegistryDelivery){$InputData.delivery=$script:RegistryDelivery}
    $Latest=Test-SuccessorLatestDelivery $script:RegistryDelivery
    if($Latest){
        $Publication=(Read-SuccessorPublication $script:R.source).anchor
        Assert-SuccessorRuntimeDelivery $script:RegistryDelivery $Runtime.registryDelivery $Publication
        if($Publication.state -cne 'Committed' -or $Publication.record.phase -cne 'STAGED_TARGET_FROZEN'){
            throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
        }
        $Evidence='fortis-registry-source-evidence-'+$Runtime.registryReleaseNonce.Replace('-','')
        foreach($Volume in @($Evidence,'fortis-r7-maintenance-interlock-v2','fortis-r7-maintenance-anchor')){
            Assert-Volume $Volume;Assert-OnlyWriter $Volume
        }
        $Args+=@('--mount',('type=volume,source='+$Evidence+',target=/run/fortis-registry-source-evidence,readonly,volume-nocopy'),
            '--mount','type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,readonly,volume-nocopy',
            '--mount','type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,readonly,volume-nocopy')
    }
    $Args+=@('--entrypoint','python',$Runtime.image,'-I','-B','-c',$Wrapper)
    $Payload=ConvertTo-Json -Compress -Depth 10 -InputObject $InputData
    $Result=(Private-Process $Args $Payload)|ConvertFrom-Json
    if($Latest -and -not (Same-Json (Read-SuccessorPublication $script:R.source).anchor $Publication)){
        throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
    }
    if($Result.result -cnotin @('P5_FUNCTIONAL_STATE_NOT_SELECTED',
        'P5_FUNCTIONAL_LOCAL_COLLECTOR_GENESIS','P5_FUNCTIONAL_LOCAL_COLLECTOR_RETAINED')){
        throw 'RELEASE_REGISTRY_COLLECTOR_STAGED_PREPARE_FAILED'
    }
    Write-Host ('FORTIS_REGISTRY_STAGED_COLLECTOR='+$Result.result)
}

function Get-SourceRecord {
    param([switch]$RetirementCheckOnly)
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
    Assert-ReleaseStateSourceAvailable $P
    if($RetirementCheckOnly){return}
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
            $OriginalGeneration=$P.PSObject.Properties['maintenanceGeneration']
            $PrimaryGeneration=$Primary.runtime.PSObject.Properties['maintenanceGeneration']
            if([bool]$OriginalGeneration -ne [bool]$PrimaryGeneration -or
               ($OriginalGeneration -and $OriginalGeneration.Value -cne $PrimaryGeneration.Value)){
                throw 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'
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
    if($RegistryReturnContainerId){
        # The old record carries a historical APPROVED scope. This exact
        # handover requires an independently verified empty current set.
        $script:PreserveApprovedExact=$true
    } elseif(-not $script:PreserveApprovedRequest){$script:PreserveApprovedRequest=$Approved}
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
    param($Source,$Report,$Maintenance)
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
    $Binding=[ordered]@{
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
        machinePowerShellVolume=$script:MachinePowerShellVolume
        machinePowerShellDigest=$script:MachinePowerShellDigest
        enableMachinePowerShell=[bool]$EnableMachinePowerShell
        registryReaderVolume=$script:RegistryReaderVolume
        registrySocketVolume=$script:RegistrySocketVolume
        registryReleaseNonce=$script:RegistryBoundReleaseNonce
        registryProfileDigest=$script:RegistryProfileDigest
        registryGatewaySourceDigest=$script:RegistryGatewaySourceDigest
        enableRegistryMount=[bool]$EnableRegistryMount
        emergencyRescueImage=$EmergencyRescueImage
        emergencyRescueArchiveSha256=$EmergencyRescueArchiveSha256.ToUpperInvariant()
        acceptUnverifiedRestore=[bool]$AcceptUnverifiedRestore
        enableDynamicGitHubRepositories=[bool]$EnableDynamicGitHubRepositories
        enableOwnerShell=[bool]$EnableOwnerShell
        enableActionCoreNetwork=[bool]$EnableActionCoreNetwork
        enableObservatoryNetwork=[bool]$EnableObservatoryNetwork
        gatewayNetworks=$script:ActionCoreNetworks
        ciControlRepositories=$CiControlRepositories
        cdReadRepositories=$CdReadRepositories
        preserveUncertainRequests=$script:PreserveUncertainRequests
        allowUncertainGrowth=[bool]$AllowUncertainGrowth
        preserveClaimedJobs=$script:PreserveClaimedJobs
        preserveApprovedRequest=$script:PreserveApprovedRequest
        requireExactUncertain=$script:PreserveUncertainExact
        requireExactClaimed=$script:PreserveClaimedExact
        requireExactApproved=$script:PreserveApprovedExact
        confirmWorkerQuiescent=[bool]$ConfirmWorkerQuiescent
    }
    if($script:RegistryDelivery){$Binding['registryDelivery']=$script:RegistryDelivery}
    if($script:CorrectivePair){$Binding['correctivePair']=$script:CorrectivePair}
    if($script:BootstrapPair){
        $Binding['bootstrapPair']=$script:BootstrapPair
        $Binding['bootstrapReviewProofRecord']=[IO.Path]::GetFullPath($BootstrapReviewProofRecord)
    }
    if($script:RegistryReturn){$Binding['registryReturn']=$script:RegistryReturn}
    if($script:RegistryCrash){$Binding['registryCrash']=$script:RegistryCrash}
    if($Maintenance){
        $ContextPath=Join-Path $ReleaseBase ('maintenance-'+$Source.runtime.runId+'.json')
        if(Test-Path -LiteralPath $ContextPath){
            $Context=Read-Private $ContextPath
            if($Context.PSObject.Properties['intentDigest']){
                if($Context.draining.attempt.attemptId -cne $Maintenance.attemptId -or
                   $Context.sourceRecordHash -ine $Source.hash -or $Context.targetImageId -cne $script:Image){
                    throw 'RELEASE_SUCCESSOR_CHECK_RECORD_CHANGED'
                }
                $Binding['ordinaryIntentDigest']=$Context.intentDigest
                if($Context.nativeRead.githubRead -ne $true -or
                   $Context.nativeRead.intentDigest -cne $Context.intentDigest -or
                   $Context.nativeRead.sourceRecordDigest -cne $Source.hash.ToLowerInvariant()){
                    throw 'RELEASE_SUCCESSOR_ORDINARY_PREFLIGHT_CHANGED'
                }
                $Binding['ordinaryNativeRead']=$Context.nativeRead

            }
        }
        $Binding['maintenance']=[ordered]@{attemptId=$Maintenance.attemptId;subject=$Maintenance.subject
            restrictionDigest=$Maintenance.restrictionDigest;generation=$Maintenance.generation}
    }
    return $Binding
}
function Save-Checked-Image {
    param($Source,$Report,$Receipt,$Maintenance,$Seal,$Transitions)
    if((-not $Build -and -not $script:RegistryPrebuiltCheck) -or $Action -cne 'Check'){throw 'RELEASE_CHECKED_IMAGE_BUILD_REQUIRED'}
    if($Maintenance -and ($null -eq $Seal -or $null -eq $Receipt -or $null -eq $Transitions)){
        throw 'RELEASE_SUCCESSOR_FREEZE_SEAL_CHANGED'
    }
    if($Maintenance){
        $Path=Successor-CheckRecordPath $Maintenance.attemptId
        $Directory=Split-Path $Path -Parent
    } else {
        $Id=[Guid]::NewGuid().ToString('N')
        $Directory=Join-Path $ReleaseBase ('image-check-'+$Id)
        $Path=Join-Path $Directory 'record.json'
    }
    $Record=[ordered]@{schema='fortis-extension-image-check-v1';phase='Ready'
        binding=(Checked-Image-Binding $Source $Report $Maintenance);sourceReceipt=$Receipt
        growthWitness=$script:GrowthWitness}
    if($Maintenance){
        $Record['maintenanceSeal']=$Seal
        $Record['maintenanceTransitions']=$Transitions
        if(Test-Path -LiteralPath $Path -PathType Leaf){
            if(-not (Same-Json (Read-Private $Path) $Record)){throw 'RELEASE_SUCCESSOR_CHECK_RECORD_CHANGED'}
            return $Path
        }
    }
    if($Maintenance -and (Test-Path -LiteralPath $Directory -PathType Container)){
        Assert-DirectoryAcl $Directory
    } else {Protect-Directory $Directory}
    if($Maintenance -or $script:CorrectivePair -or $script:BootstrapPair){Write-Private $Path $Record -FlushToDisk}else{Write-Private $Path $Record}
    return $Path
}
function Assert-Checked-Image-Binding {
    param($Stored,$Expected)
    if(-not (Same-Json $Stored $Expected)){
        throw 'RELEASE_CHECKED_IMAGE_BINDING_CHANGED'
    }
}
# Report only fixed component labels. Protected receipt values and file names
# outside this allowlist stay private.
function Get-Checked-Source-Changes {
    param($Before,$After)
    $BeforeHashes=$Before.PSObject.Properties['sha256']
    $AfterHashes=$After.PSObject.Properties['sha256']
    if($null -eq $BeforeHashes -or $null -eq $BeforeHashes.Value -or
       $null -eq $AfterHashes -or $null -eq $AfterHashes.Value){return 'OTHER'}
    $StateFiles=[ordered]@{
        CORE='approvals.sqlite'
        OWNER='owner.sqlite'
        WORKFLOW='native-git/workflow.sqlite'
        GITHUB_RECEIPTS='github-receipts.sqlite'
        SONAR_RECEIPTS='sonar-receipts.sqlite'
        REGISTRY_CAPTURE='registry-functional-v1/capture.sqlite'
        REGISTRY_COLLECTOR='registry-functional-v1/collector.sqlite'
    }
    $Changed=@(foreach($Label in $StateFiles.Keys){
        $Path=$StateFiles[$Label]
        $Old=$BeforeHashes.Value.PSObject.Properties[$Path]
        $New=$AfterHashes.Value.PSObject.Properties[$Path]
        $OldHash=if($null -ne $Old){[string]$Old.Value}else{''}
        $NewHash=if($null -ne $New){[string]$New.Value}else{''}
        if($OldHash -cne $NewHash){$Label}
    })
    if($Changed.Count -eq 0){return 'OTHER'}
    return ($Changed -join ',')
}
function Verify-Checked-Image {
    param($Source,$Report,[switch]$BindingOnly,[switch]$ReturnReceipt,[switch]$PrepareSuccessorStop)
    if(($BindingOnly -and $ReturnReceipt) -or
       ($PrepareSuccessorStop -and ($BindingOnly -or $ReturnReceipt -or -not $CheckedImageRecord))){
        throw 'RELEASE_CHECKED_IMAGE_VERIFICATION_MODE_INVALID'
    }
    if(-not $CheckedImageRecord){return}
    $CheckDigest=''
    if($PrepareSuccessorStop){$CheckDigest=(Get-FileHash -LiteralPath $CheckedImageRecord -Algorithm SHA256).Hash.ToLowerInvariant()}
    $Record=Read-Private $CheckedImageRecord
    if($Record.schema -cne 'fortis-extension-image-check-v1' -or $Record.phase -cne 'Ready' -or
       $null -eq $Record.binding -or $null -eq $Record.sourceReceipt){
        throw 'RELEASE_CHECKED_IMAGE_RECORD_INVALID'
    }
    $Maintenance=Read-SuccessorMaintenanceContext $Source
    $Expected=Checked-Image-Binding $Source $Report $Maintenance
    Assert-Checked-Image-Binding $Record.binding $Expected
    if($BindingOnly){return}
    if($PrepareSuccessorStop){
        if(-not $Maintenance){throw 'RELEASE_SUCCESSOR_MAINTENANCE_CHECK_REQUIRED'}
        if($Maintenance.ContainsKey('latestPin') -and $Maintenance.latestPin -eq $true){
            $Publication=(Read-SuccessorPublication $Source).anchor
            if((Publish-SuccessorInterlock $Source $Publication.record $Maintenance.registryDigest) -cne $Maintenance.interlockDigest){
                throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
            }
        }
        $Maintenance['prepareStop']=@{sourceRecordDigest=$Source.hash.ToLowerInvariant()
            checkedRecordDigest=$CheckDigest;targetImageId=$script:Image}
    }
    $Now=if($Maintenance){
        if(-not (Same-Json $Record.maintenanceSeal $Maintenance.checkSeal)){
            throw 'RELEASE_SUCCESSOR_FREEZE_SEAL_CHANGED'
        }
        $Frozen=Read-SuccessorFreezeSeal $Maintenance $Source.runtime.stateVolume 'fortis-r7-maintenance-interlock'
        if(-not (Same-Json $Record.maintenanceTransitions $Frozen.transitions)){
            throw 'RELEASE_SUCCESSOR_FREEZE_SEAL_CHANGED'
        }
        $Frozen.sourceReceipt
    } else {
        Receipt $Source.runtime.stateVolume -Exact:$script:PreserveUncertainExact -ExactClaimed:$script:PreserveClaimedExact -ExactApproved:$script:PreserveApprovedExact
    }
    if($AllowUncertainGrowth){
        # The original immutable Check receipt and prefix witness are
        # reviewed afresh; no replacement Check binding is ever written.
        if(-not (Same-Json $script:GrowthReviewedReceipt $Now)){
            throw 'RELEASE_GROWTH_SOURCE_STATE_CHANGED'
        }
    } elseif(-not (Same-Json $Record.sourceReceipt $Now)){
        Write-Host ('FORTIS_CHECKED_SOURCE_CHANGED components='+(Get-Checked-Source-Changes $Record.sourceReceipt $Now))
        throw 'RELEASE_CHECKED_IMAGE_SOURCE_STATE_CHANGED'
    }
    if($PrepareSuccessorStop){
        $Intent=$Frozen.stopIntent
        if($Intent.schemaVersion -ne 1 -or
           $Intent.next.phase -cne 'APPLY_STOP' -or
           $Intent.next.previousDigest -cne $Maintenance.interlockDigest -or
           $Intent.attemptId -cne $Maintenance.attemptId -or
           $Intent.restrictionDigest -cne $Maintenance.restrictionDigest -or
           $Intent.checkedPhaseDigest -cne $Maintenance.interlockDigest -or
           $Intent.checkedRecordDigest -cne $CheckDigest -or
           $Intent.sourceRecordDigest -cne $Maintenance.prepareStop.sourceRecordDigest -or
           $Intent.sourceReceiptDigest -cne $Maintenance.stateDigest -or
           $Intent.targetImageId -cne $script:Image -or
           (Get-FileHash -LiteralPath $Source.path -Algorithm SHA256).Hash -cne $Source.hash -or
           (Get-FileHash -LiteralPath $CheckedImageRecord -Algorithm SHA256).Hash.ToLowerInvariant() -cne $CheckDigest){
            throw 'RELEASE_SUCCESSOR_APPLY_STOP_BINDING_CHANGED'
        }
        return $Intent
    }
    if($ReturnReceipt){return $Now}
}
function Save-SuccessorApplyStopIntent {
    param($Intent)
    $Directory=Split-Path (Successor-CheckRecordPath $Intent.attemptId) -Parent
    $Path=Join-Path $Directory 'apply-stop.json'
    Assert-DirectoryAcl $Directory
    if(-not (Test-Path -LiteralPath $Path)){Write-Private $Path $Intent -FlushToDisk}
    if(-not (Same-Json (Read-Private $Path) $Intent)){
        throw 'RELEASE_SUCCESSOR_APPLY_STOP_BINDING_CHANGED'
    }
    return $Path
}
# Offline fixture: exercise the real verifier with a changing in-memory
# binding and receipt. No Docker, protected records or owner state.
function Assert-CheckedImagePreflightSelfTest {
    $CheckedImageRecord='fixture'
    $AllowUncertainGrowth=$false
    $Good=[pscustomobject]@{sha256=[pscustomobject]@{'approvals.sqlite'='good'}}
    $Bad=[pscustomobject]@{sha256=[pscustomobject]@{'approvals.sqlite'='bad'}}
    $Binding=[pscustomobject]@{image='fixture';sourceHash='original'}
    $Fixture=@{calls=0;receipt=$Good;binding=$Binding;review=$Good}
    $Source=@{runtime=@{stateVolume='fixture'}}
    function Read-Private {
        param($Path)
        return [pscustomobject]@{schema='fortis-extension-image-check-v1';phase='Ready';binding=$Binding;sourceReceipt=$Good}
    }
    function Checked-Image-Binding { param($Source,$Report) return $Fixture.binding }
    function Receipt {
        param($Volume,[switch]$Exact,[switch]$ExactClaimed,[switch]$ExactApproved)
        $Fixture.calls++
        if($AllowUncertainGrowth){$script:GrowthReviewedReceipt=$Fixture.review}
        return $Fixture.receipt
    }
    $PriorGrowth=$script:GrowthReviewedReceipt
    try {
        $Early=@(Verify-Checked-Image $Source $null -BindingOnly)
        if($Early.Count -ne 0 -or $Fixture.calls -ne 0){throw 'RELEASE_PREFLIGHT_BINDING_ONLY_SELFTEST_FAILED'}
        $Verified=Verify-Checked-Image $Source $null -ReturnReceipt
        if($Fixture.calls -ne 1 -or -not (Same-Json $Verified $Good)){throw 'RELEASE_PREFLIGHT_RECEIPT_SELFTEST_FAILED'}
        $Final=@(Verify-Checked-Image $Source $null)
        if($Final.Count -ne 0 -or $Fixture.calls -ne 2){throw 'RELEASE_PREFLIGHT_FINAL_FRESH_SELFTEST_FAILED'}
        $Fixture.binding=[pscustomobject]@{image='fixture';sourceHash='changed'}
        try {
            $null=Verify-Checked-Image $Source $null -ReturnReceipt
            throw 'RELEASE_PREFLIGHT_ACCEPTED_CHANGED_BINDING'
        } catch {if($_.Exception.Message -cne 'RELEASE_CHECKED_IMAGE_BINDING_CHANGED'){throw}}
        if($Fixture.calls -ne 2){throw 'RELEASE_PREFLIGHT_BINDING_ORDER_SELFTEST_FAILED'}
        $Fixture.binding=$Binding
        $Fixture.receipt=$Bad
        try {
            $null=Verify-Checked-Image $Source $null -ReturnReceipt
            throw 'RELEASE_PREFLIGHT_ACCEPTED_CHANGED_RECEIPT'
        } catch {if($_.Exception.Message -cne 'RELEASE_CHECKED_IMAGE_SOURCE_STATE_CHANGED'){throw}}
        $AllowUncertainGrowth=$true
        try {
            $null=Verify-Checked-Image $Source $null -ReturnReceipt
            throw 'RELEASE_PREFLIGHT_ACCEPTED_GROWTH_MISMATCH'
        } catch {if($_.Exception.Message -cne 'RELEASE_GROWTH_SOURCE_STATE_CHANGED'){throw}}
        $Fixture.review=$Bad
        $Verified=Verify-Checked-Image $Source $null -ReturnReceipt
        if($Fixture.calls -ne 5 -or -not (Same-Json $Verified $Bad)){throw 'RELEASE_PREFLIGHT_GROWTH_RECEIPT_SELFTEST_FAILED'}
    } finally {$script:GrowthReviewedReceipt=$PriorGrowth}
    Write-Host 'FORTIS_CHECKED_IMAGE_PREFLIGHT_SELFTEST_PASS'
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
        Write-Host ('FORTIS_CHECKED_SOURCE_CHANGED components='+(Get-Checked-Source-Changes $Stored.sourceReceipt $Receipt))
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


# Exact historical startup rebind, not a general exception for changed pins.
# The same packaged #288 image and live Registry peer must already have passed
# normal Admit checks. Original release, backup and primary records stay pinned.
function Assert-Registry288RecoveredProfile {
    param($P,[string]$Observed)
    $Run='6ec445e6191543e7873275166922010b'
    $Old='da63d73a34751d614ee4e96cd9cfb43bc99a9a1c79c0083cc1eb6e621dba2e40'
    $New='86722403363418162f179ccdbb14fa7368a5eede4e5c7ba6806cbb4402e92b17'
    if($P.runId -cne $Run -or $P.registryProfileDigest -cne $Old -or $Observed -cne $New){
        throw 'RELEASE_REGISTRY_PROFILE_OR_PEER_CHANGED'
    }
    $SourcePath=Join-Path $ReleaseBase ($Run+'\record.json')
    $RecoveryPath=Join-Path $ReleaseBase 'startup-rebind-c0a789e16d3f41a4a4b9e230288c0f01\record.json'
    $RehearsalPath=Join-Path $ReleaseBase 'startup-recovery-c0a789e16d3f41a4a4b9e230288c0f01\record.json'
    $Pins=[ordered]@{}
    $Pins[$SourcePath]='ea25b6d0769059e225c584a7a5518d6cedd0e8f3f138b1cb29f7194c09cc195c'
    $Pins[$RecoveryPath]='3a8e8d4432e5ad2051fb26f77c879cb3343c73ce098ae0bd675d61095e1a8cdd'
    $Pins[$RehearsalPath]='49310a7ab4cdb3db86134249806a3f22ad8633f3d1810b48c46726606febcb97'
    $Records=@{}
    foreach($Path in $Pins.Keys){
        if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $Pins[$Path]){
            throw 'RELEASE_REGISTRY_288_REBIND_EVIDENCE_CHANGED'
        }
        $Records[$Path]=Read-Private $Path
        if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $Pins[$Path]){
            throw 'RELEASE_REGISTRY_288_REBIND_EVIDENCE_CHANGED'
        }
    }
    $Source=$Records[$SourcePath];$Recovery=$Records[$RecoveryPath];$Rehearsal=$Records[$RehearsalPath]
    if($Source.schema -cne 'fortis-extension-release-v1' -or $Source.phase -cne 'Complete' -or
       $Source.activated -ne $true -or $Recovery.schema -cne 'fortis-288-startup-rebind-v1' -or
       $Recovery.phase -cne 'Recovered' -or $Recovery.ownerAction -cne 'RECOVER GATEWAY 288' -or
       $Recovery.releaseRecord -cne $SourcePath -or $Recovery.releaseHash -cne $Pins[$SourcePath] -or
       $Recovery.rehearsalRecord -cne $RehearsalPath -or $Recovery.rehearsalHash -cne $Pins[$RehearsalPath] -or
       $Recovery.oldProfileDigest -cne $Old -or $Recovery.newProfileDigest -cne $New -or
       $Recovery.configurationDigest -cne $Source.configurationDigest -or
       $Rehearsal.phase -cne 'Rehearsed' -or $Rehearsal.proof.result -cne 'RECOVERY_REHEARSAL_PACKAGED_REOPEN_PASS'){
        throw 'RELEASE_REGISTRY_288_REBIND_EVIDENCE_CHANGED'
    }
    foreach($Field in @('runId','pilotId','image','stateVolume','registryReaderVolume','registrySocketVolume',
                        'releaseNonce','registryReleaseNonce','registryProfileDigest','maintenanceGeneration')){
        if($P.$Field -cne $Source.runtime.$Field){throw 'RELEASE_REGISTRY_288_REBIND_RUNTIME_CHANGED'}
    }
    if(-not (Same-Json $P.registryDelivery $Source.runtime.registryDelivery) -or
       $Recovery.gatewayId -cne $P.pilotId -or $Recovery.image -cne $P.image -or
       $Recovery.stateVolume -cne $P.stateVolume -or $Recovery.readerVolume -cne $P.registryReaderVolume -or
       $Recovery.releaseNonce -cne $P.releaseNonce){
        throw 'RELEASE_REGISTRY_288_REBIND_RUNTIME_CHANGED'
    }
}


function Assert-Registry288RecoveredProfileSelfTest {
    $ReleaseBase=Join-Path ([IO.Path]::GetTempPath()) 'fortis-rebind-fixture'
    $Run='6ec445e6191543e7873275166922010b'
    $SourcePath=Join-Path $ReleaseBase ($Run+'\record.json')
    $RecoveryPath=Join-Path $ReleaseBase 'startup-rebind-c0a789e16d3f41a4a4b9e230288c0f01\record.json'
    $RehearsalPath=Join-Path $ReleaseBase 'startup-recovery-c0a789e16d3f41a4a4b9e230288c0f01\record.json'
    $Old='da63d73a34751d614ee4e96cd9cfb43bc99a9a1c79c0083cc1eb6e621dba2e40'
    $New='86722403363418162f179ccdbb14fa7368a5eede4e5c7ba6806cbb4402e92b17'
    $Hashes=@{}
    $Hashes[$SourcePath]='ea25b6d0769059e225c584a7a5518d6cedd0e8f3f138b1cb29f7194c09cc195c'
    $Hashes[$RecoveryPath]='3a8e8d4432e5ad2051fb26f77c879cb3343c73ce098ae0bd675d61095e1a8cdd'
    $Hashes[$RehearsalPath]='49310a7ab4cdb3db86134249806a3f22ad8633f3d1810b48c46726606febcb97'
    $Runtime=[pscustomobject]@{runId=$Run;pilotId=('a'*64);image=('sha256:'+('b'*64));stateVolume='fixture-state'
        registryReaderVolume='fixture-reader';registrySocketVolume='fixture-socket';releaseNonce='fixture-nonce'
        registryReleaseNonce='fixture-nonce';registryProfileDigest=$Old;maintenanceGeneration=('c'*64)
        registryDelivery=[ordered]@{profileDigest=$Old;generation=('c'*64)}}
    $Values=@{}
    $Values[$SourcePath]=[pscustomobject]@{schema='fortis-extension-release-v1';phase='Complete';activated=$true
        configurationDigest=('d'*64);runtime=$Runtime}
    $Values[$RecoveryPath]=[pscustomobject]@{schema='fortis-288-startup-rebind-v1';phase='Recovered';ownerAction='RECOVER GATEWAY 288'
        releaseRecord=$SourcePath;releaseHash=$Hashes[$SourcePath];rehearsalRecord=$RehearsalPath;rehearsalHash=$Hashes[$RehearsalPath]
        oldProfileDigest=$Old;newProfileDigest=$New;configurationDigest=('d'*64);gatewayId=$Runtime.pilotId
        image=$Runtime.image;stateVolume=$Runtime.stateVolume;readerVolume=$Runtime.registryReaderVolume;releaseNonce=$Runtime.releaseNonce}
    $Values[$RehearsalPath]=[pscustomobject]@{phase='Rehearsed';proof=@{result='RECOVERY_REHEARSAL_PACKAGED_REOPEN_PASS'}}
    function Read-Private {param($Path) $Values[$Path]}
    function Get-FileHash {param($LiteralPath,$Algorithm) [pscustomobject]@{Hash=$Hashes[$LiteralPath]}}
    Assert-Registry288RecoveredProfile $Runtime $New
    $Existing=[pscustomobject]@{companionDigest=('a'*64);existingCompanion=[pscustomobject]@{
        schemaDigest=('b'*64);companionDigest=('a'*64);authorityWitnessDigest=('c'*64)}}
    $Legacy=[pscustomobject]@{legacyCompanion=[pscustomobject]@{
        schemaDigest=('a'*64);coreRowsDigest=('b'*64)}}
    Assert-RegistrySuccessorCompanionPreflight $Existing ('fortis-github-pilot-state-'+$Run)
    Assert-RegistrySuccessorCompanionPreflight $Legacy 'legacy-fixture'
    $Rejected=$false
    try {Assert-RegistrySuccessorCompanionPreflight $Existing 'other-state'}
    catch {if($_.Exception.Message -cne 'RELEASE_REGISTRY_SUCCESSOR_PREFLIGHT_UNCONFIRMED'){throw};$Rejected=$true}
    if(-not $Rejected){throw 'RELEASE_REGISTRY_288_REBIND_SELFTEST_FAILED'}
    $Other=$Runtime|ConvertTo-Json -Depth 10|ConvertFrom-Json
    $Other.pilotId='f'*64
    $Cases=@(
        @{runtime=$Runtime;digest=('0'*64);code='RELEASE_REGISTRY_PROFILE_OR_PEER_CHANGED'},
        @{runtime=$Other;digest=$New;code='RELEASE_REGISTRY_288_REBIND_RUNTIME_CHANGED'}
    )
    foreach($Case in $Cases){
        $Rejected=$false
        try {Assert-Registry288RecoveredProfile $Case.runtime $Case.digest}
        catch {if($_.Exception.Message -cne $Case.code){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_REGISTRY_288_REBIND_SELFTEST_FAILED'}
    }
    $Hashes[$RecoveryPath]='0'*64
    $Rejected=$false
    try {Assert-Registry288RecoveredProfile $Runtime $New}
    catch {if($_.Exception.Message -cne 'RELEASE_REGISTRY_288_REBIND_EVIDENCE_CHANGED'){throw};$Rejected=$true}
    if(-not $Rejected){throw 'RELEASE_REGISTRY_288_REBIND_SELFTEST_FAILED'}
    Write-Host 'FORTIS_REGISTRY_288_REBIND_SELFTEST_PASS'
}

function Admit {
    param($C,$P,[switch]$AllowUnhealthy,[switch]$AllowPendingIngress,
          [string]$MountPreflightImageId='', [string]$VerifiedPromoteRescueImage='',
          [switch]$RegistryReturnSource,[switch]$BootstrapRetained,[switch]$RetainedMaintenance)
    if($RetainedMaintenance -and (-not $RegistryReturnSource -or -not $AllowUnhealthy -or
       -not (Test-SuccessorLatestDelivery $P.registryDelivery) -or
       $P.pilotId -cne $C.Id -or $P.restartPolicy -cne 'unless-stopped' -or
       $C.State.Status -cnotin @('running','exited') -or $C.HostConfig.RestartPolicy.Name -cne 'no')){
        throw 'RELEASE_SUCCESSOR_ORDINARY_SOURCE_CHANGED'
    }
    if($BootstrapRetained -and ($P.runId -cne 'cd6d3d97350e4f5590d9c3e9ece69580' -or
       $P.pilotId -cne '2a6e198d6356ed225e61cad93938e1f40f4f13fe99450e782c93ddbfc6cba417' -or
       $P.restartPolicy -cne 'unless-stopped' -or $C.State.Status -cnotin @('running','exited') -or
       $C.HostConfig.RestartPolicy.Name -cnotin @('no','unless-stopped'))){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_SOURCE_CHANGED'
    }
    # The original Docker image identity remains mandatory for State-Helper
    # admission. In one owner-accepted UC-GW-013 recovery only the two OFFLINE
    # volume-content digest checks may run under the verified rescue snapshot.
    # The caller has already revalidated old-image absence, archive SHA, exact
    # backup receipt and rescue offline smoke via Assert-Previous-Image-Retained.
    $MountImage=$P.image
    if($VerifiedPromoteRescueImage -and
       ($Action -cne 'Promote' -or $AcceptUnverifiedRestore -or
        $VerifiedPromoteRescueImage -cnotmatch '^sha256:[0-9a-f]{64}$' -or
        $MountPreflightImageId -cne $VerifiedPromoteRescueImage)){
        throw 'RELEASE_EMERGENCY_PROMOTE_MOUNT_DENIED'
    }
    if($MountPreflightImageId){
        # Promote may reuse only the rescue artifact independently verified
        # against the immutable Complete release and original prior primary.
        $VerifiedPromoteMount=($Action -ceq 'Promote' -and
            $VerifiedPromoteRescueImage -ceq $MountPreflightImageId)
        if($MountPreflightImageId -cne $P.image -and
           (((-not $AcceptUnverifiedRestore -or
              $MountPreflightImageId -cne $EmergencyRescueImage) -and
              -not $VerifiedPromoteMount) -or
            $P.image -ceq $script:Image -or
            $C.Image -cne $P.image)){
            throw 'RELEASE_EMERGENCY_SOURCE_MOUNT_IMAGE_DENIED'
        }
        $MountImage=$MountPreflightImageId
    }
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
        cdReadRepositories=(Read-CdReadRepositories $P)
        vaultVolume=$P.vaultVolume;ownerShell=(Read-OwnerShellFlag $P);status=$C.State.Status;requireHealthy=(-not $AllowUnhealthy)
        publisherActivationVolume=(Read-PublisherActivationVolume $P)
        machinePowerShellVolume=(Read-MachinePowerShellVolume $P)}
    $RegistryProtected=Read-RegistryMountBinding $P
    if($RegistryProtected.readerVolume -and
       $P.releaseNonce -cne $RegistryProtected.releaseNonce){
        throw 'RELEASE_REGISTRY_RUNTIME_NONCE_MISMATCH'
    }
    $Expected.registryReaderVolume=$RegistryProtected.readerVolume
    $Expected.registrySocketVolume=$RegistryProtected.socketVolume
    $Expected.registryReleaseNonce=$RegistryProtected.releaseNonce
    $Delivery=$null
    if($RegistryProtected.readerVolume -and $RegistryProtected.socketVolume -cne 'fortis-registry-read'){
        $Delivery=$P.registryDelivery
        if($null -eq $Delivery -or $Delivery.profileDigest -cne $RegistryProtected.profileDigest -or
           $Delivery.generation -cne $P.maintenanceGeneration){
            throw 'RELEASE_REGISTRY_SUCCESSOR_DELIVERY_CHANGED'
        }
        $Expected.registrySuccessorDelivery=$true
        if(Test-SuccessorLatestDelivery $Delivery){$Expected.registryLatestPin=$true}
    }
    $Networks=Read-GatewayNetworks $P
    if($null -ne $Networks){$Expected.gatewayNetworks=$Networks}
    if($AllowPendingIngress){
        if($null -eq $Networks -or
           ($script:R.phase -cne 'Created' -and -not ($script:R.phase -ceq 'Returned' -and $script:R.PSObject.Properties['bootstrapOwnerGo'])) -or
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
           ($C.HostConfig.RestartPolicy.Name -cne 'unless-stopped' -and
            -not (($BootstrapRetained -or $RetainedMaintenance) -and $C.HostConfig.RestartPolicy.Name -ceq 'no')) -or
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
        $Observed=Image-PublisherMount-Preflight -ImageId $MountImage
        if($Observed -cne $Pinned){throw 'RELEASE_PUBLISHER_VOLUME_CONTENT_CHANGED'}
    }
    if($Expected.machinePowerShellVolume){
        $Pinned=Read-MachinePowerShellDigest $P
        $Observed=Image-MachinePowerShell-Preflight -ImageId $MountImage
        if($Observed -cne $Pinned){throw 'RELEASE_MACHINE_POWERSHELL_CONTENT_CHANGED'}
    }
    if($RegistryProtected.readerVolume -and -not $RegistryReturnSource){
        # At each existing source/candidate/rollback admission boundary,
        # recheck the exact read-only profile bytes and kernel live peer.
        if($Delivery){
            if(Test-SuccessorLatestDelivery $Delivery){
                $Publication=Read-SuccessorRuntimePublication $P
                $RunningSource=$Publication.record.phase -cin @('DRAINING','FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP')
                if($RunningSource -and $C.State.Status -cne 'running'){throw 'RELEASE_SUCCESSOR_RUNNING_SOURCE_REQUIRED'}
                $Actual=Image-RegistrySuccessor-Preflight -ImageId $MountImage -ReleaseNonce $RegistryProtected.releaseNonce -InterlockDigest $Publication.digest -LatestPin -RunningSource:$RunningSource
                Assert-SuccessorRuntimeDelivery $Actual $Delivery $Publication
                if(-not (Same-Json (Read-SuccessorRuntimePublication $P) $Publication)){
                    throw 'RELEASE_SUCCESSOR_PUBLICATION_UNCONFIRMED'
                }
            } else {
                $Actual=Image-RegistrySuccessor-Preflight -ImageId $MountImage -ReleaseNonce $RegistryProtected.releaseNonce -InterlockDigest $Delivery.sourceDelivery.interlockDigest
                if(-not (Same-Json $Actual.sourceDelivery $Delivery.sourceDelivery) -or
                   $Actual.companionDigest -cne $Delivery.companionDigest -or $Actual.generation -cne $Delivery.generation){
                    throw 'RELEASE_REGISTRY_SUCCESSOR_DELIVERY_CHANGED'
                }
            }
            $Observed=$Actual.profileDigest
        } else {
            $Observed=Image-RegistryMount-Preflight -ImageId $MountImage `
                -ReleaseNonce $RegistryProtected.releaseNonce `
                -ReaderVolume $RegistryProtected.readerVolume
        }
        if($Observed -cne $RegistryProtected.profileDigest){
            if(-not $Delivery -or (Test-SuccessorLatestDelivery $Delivery)){throw 'RELEASE_REGISTRY_PROFILE_OR_PEER_CHANGED'}
            Assert-Registry288RecoveredProfile $P $Observed
        }
    }
}
function Admit-Source {
    param($C,$Source)
    # Mandatory before EACH source admission, including the final pre-stop
    # admission. Ordinary releases require the original image to exist.
    # Emergency releases first verify an exact owner-sealed rescue image/TAR,
    # archived state receipt and offline smoke, with explicit risk acceptance.
    Assert-Previous-Image-Retained $Source
    $MountImage=$Source.runtime.image
    if($AcceptUnverifiedRestore){$MountImage=$EmergencyRescueImage}
    if($script:RegistryReturn){
        $ExpectedStatus=if($script:RegistryCrash){'exited'}else{'running'}
        if($C.State.Status -cne $ExpectedStatus){throw 'RELEASE_REGISTRY_RETURN_SOURCE_STATUS_CHANGED'}
        Assert-RegistryReturnInputs $Source $script:RegistryReturn $C
    }
    Admit $C $Source.runtime -MountPreflightImageId $MountImage -RegistryReturnSource:([bool]$script:RegistryReturn)
}
function Admit-ReturnCandidate {
    param($C,$P)
    if((Read-GatewayNetworks $P) -and $script:R.phase -ceq 'Created' -and
       -not $script:R.activated -and -not $script:R.probesPassed -and
       $C.State.Status -ceq 'created' -and
       $C.State.StartedAt -ceq '0001-01-01T00:00:00Z'){
        $Attached=@($C.NetworkSettings.Networks.PSObject.Properties.Name)
        $Expected=@(Get-RecordedGatewayNetworkNames $NetworkMap)
        if($Attached -ccontains 'fortis-gateway-egress' -and
           @($Attached|Where-Object{$Expected -cnotcontains $_}).Count -eq 0 -and
           $Attached.Count -lt $Expected.Count){
            # Never-started exact subset only; no network effect on Return.
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
    $Bootstrap=if($script:R -is [Collections.IDictionary]){$script:R['bootstrapOwnerGo']}
        else{$F=$script:R.PSObject.Properties['bootstrapOwnerGo'];if($F){$F.Value}}
    if($Bootstrap){Return-BootstrapPreparedPair;return}
    $Pair=Read-CorrectiveAttemptPair
    if($Pair){Return-CorrectivePair $Pair;return}
    Assert-Release-Production
    $P=$script:R.runtime
    $ReturnField=$script:R.PSObject.Properties['registryReturn']
    $Reserve=if($script:R -is [Collections.IDictionary]){
        $script:R['registryReturn']
    } elseif($null -ne $ReturnField){$ReturnField.Value}
    if($Reserve){
        Restore-RegistrySource (Container $script:R.source.runtime.pilotId) $Reserve
        Assert-Release-Production
        $script:R.phase='Returned'
        Save
        return
    }
    # Fail BEFORE stopping a possibly healthy candidate if the original
    # Gateway image/profile/peer/boot/socket or protected state is stale.
    # Recheck after candidate stop as well; no automatic reseal or Apply.
    $Original=Container $script:R.source.runtime.pilotId
    Admit $Original $script:R.source.runtime
    if($Original.State.Status -cnotin @('exited','running')){
        throw 'RELEASE_SOURCE_STATE_UNKNOWN'
    }
    if($Original.State.Status -ceq 'exited'){Assert-SourceUnchanged}
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
    $Networks=Read-GatewayNetworks $P
    if($null -eq $Networks){return $C}
    $UseAction=Test-RecordedGatewayNetwork $Networks 'fortis-actioncore-net'
    $UseObservatory=Test-RecordedGatewayNetwork $Networks 'fortis-observatory-gw-net'
    $Now=Read-GatewayNetworkBoundary -ActionCore:$UseAction -Observatory:$UseObservatory
    if(-not (Same-Json $Now $Networks)){
        throw 'RELEASE_GATEWAY_BOUNDARY_CHANGED'
    }
    foreach($Name in @('fortis-actioncore-net','fortis-observatory-gw-net')){
        if(-not (Test-RecordedGatewayNetwork $Networks $Name)){continue}
        $Attached=@($C.NetworkSettings.Networks.PSObject.Properties.Name)
        if($Attached -ccontains $Name){continue}
        # Owner controller only: a never-started exact-subset candidate may
        # attach the next pinned network. Reject extra/mismatched endpoints.
        Admit $C $P -AllowUnhealthy -AllowPendingIngress
        $Fresh=Read-GatewayNetworkBoundary -ActionCore:$UseAction -Observatory:$UseObservatory
        if(-not (Same-Json $Fresh $Networks)){
            throw 'RELEASE_GATEWAY_BOUNDARY_CHANGED'
        }
        if($Name -ceq 'fortis-actioncore-net'){
            Step 'ATTACH_ACTION_CORE_NETWORK'
            $null=Docker-Text @('network','connect','fortis-actioncore-net',$C.Id)
        }else{
            Step 'ATTACH_OBSERVATORY_NETWORK'
            $null=Docker-Text @('network','connect','fortis-observatory-gw-net',$C.Id)
        }
        $C=Container $C.Id
    }
    Admit $C $P -AllowUnhealthy
    return $C
}
function Resume-Target {
    $P=$script:R.runtime;$C=Container $P.pilotName
    $Bootstrap=$script:R.PSObject.Properties['bootstrapOwnerGo']
    if($Bootstrap){
        $Intent=Read-BootstrapFrozenIntent $script:R.source $script:R.bootstrapCheckRecord $script:R.bootstrapCheckHash -Runtime
        $Current=(Read-Private $Pointer).record
        if($Current -cne $script:R.source.path -and
           ($script:R.phase -cne 'Complete' -or $Current -cne $script:RecordPath)){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_SOURCE_CHANGED'
        }
        $C=Read-BootstrapGatewayCandidate $Intent
        $P=$script:R.runtime
        $Receiver=Read-BootstrapReceiver $Intent -GatewayId $C.Id -Accepted:$script:R.activated
        if($Current -ceq $script:R.source.path -and $Receiver){
            Assert-PairedFrozenSource $Intent $script:R.source -CandidateIds @($C.Id,$Receiver.Id)
        }
        $Published=(Read-SuccessorPublication $script:R.source).anchor
        if(-not $Receiver -or $Receiver.State.Status -ne 'running' -or
           $Published.state -cne 'Committed' -or $Published.record.phase -cne 'STAGED_TARGET_FROZEN' -or
           $Published.digest -cne $P.registryDelivery.sourceDelivery.interlockDigest){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'
        }
        $GateInput=ConvertTo-Json -Compress @{nonce=$P.releaseNonce;configurationDigest=$script:R.configurationDigest}
        $GateRecord=Image-CLI @('gate-record-status') $GateInput -StateVolume $P.stateVolume
        if(($GateRecord.markerPresent -ne $false -and $GateRecord.active -ne $true) -or
           ($GateRecord.active -and -not $script:R.probesPassed) -or
           ($script:R.activated -and -not $GateRecord.active)){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_ACTIVATION_CHANGED'
        }
        if($script:R.phase -ceq 'Complete'){
            if(-not $script:R.activated -or -not $script:R.probesPassed -or
               $Receiver.HostConfig.RestartPolicy.Name -cne 'unless-stopped'){
                throw 'RELEASE_SUCCESSOR_BOOTSTRAP_ACTIVATION_CHANGED'
            }
            Admit $C $P
            Assert-Release-Production
            if($Current -ceq $script:R.source.path){Write-Private $Pointer @{schema=1;record=$script:RecordPath} -FlushToDisk}
            Write-Host 'FORTIS_SUCCESSOR_BOOTSTRAP_CURRENT_POINTER_COMPLETED'
            return
        }
    }
    $Corrective=Read-CorrectiveAttemptPair
    if($Corrective){
        if(-not $ConfirmWorkerQuiescent){throw 'RELEASE_CORRECTIVE_QUIESCENCE_REQUIRED'}
        if($script:R.phase -ceq 'Complete'){
            if(-not $script:R.activated -or -not $script:R.probesPassed -or
               (Container $Corrective.targetRegistryId).HostConfig.RestartPolicy.Name -cne 'unless-stopped'){
                throw 'RELEASE_CORRECTIVE_COMPLETION_CHANGED'
            }
            Complete-CorrectiveRegistryPair $Corrective
            Write-Private $Pointer @{schema=1;record=$script:RecordPath} -FlushToDisk
            Write-Host 'FORTIS_CORRECTIVE_CURRENT_POINTER_COMPLETED'
            return
        }
        if((Container $script:R.source.runtime.pilotId).State.Status -cne 'exited' -or
           (Container $Corrective.sourceRegistryId).State.Status -cne 'exited' -or
           (Container $Corrective.targetPreviewId).State.Status -cne 'exited'){
            throw 'RELEASE_CORRECTIVE_SOURCE_NOT_RETAINED'
        }
        $InputText=ConvertTo-Json -Compress @{nonce=$P.releaseNonce;configurationDigest=$script:R.configurationDigest}
        $GateRecord=Image-CLI @('gate-record-status') $InputText -StateVolume $P.stateVolume
        if($GateRecord.markerPresent -ne $false -and $GateRecord.active -ne $true){
            throw 'RELEASE_CORRECTIVE_ACTIVATION_UNCONFIRMED'
        }
        if(-not $GateRecord.active){Assert-CorrectiveTargetCheckpoint $Corrective}
        elseif(-not $script:R.probesPassed){throw 'RELEASE_ACTIVE_WITHOUT_PROBE_RECEIPT'}
    }
    $C=Complete-ActionCoreNetwork $C $P
    Admit $C $P -AllowUnhealthy
    if($C.State.Status -ceq 'created' -or $C.State.Status -ceq 'exited'){
        Assert-OnlyWriter $P.stateVolume
        if($Bootstrap){$C=Set-BootstrapContainerState $C Start}
        else{$null=Docker-Text @('start',$C.Id)}
    }
    Wait-Healthy $C.Id;Admit (Container $C.Id) $P
    $script:R.runtime.pilotId=$C.Id;$script:R.phase='Staged';Save -FlushToDisk:([bool]($Corrective -or $Bootstrap))
    $Gate=Running-CLI $C.Id @('gate-status')
    if($Gate.configurationDigest -cne $script:R.configurationDigest){throw 'RELEASE_RUNNING_DIGEST_MISMATCH'}
    if($Bootstrap -and $Gate.active -ne $GateRecord.active){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_ACTIVATION_CHANGED'}
    if(-not $Gate.active){
        Step 'VERIFY_STAGED_CATALOG'
        $Catalog=Running-CLI $C.Id @('catalog')
        if($Catalog.configurationDigest -cne $script:R.configurationDigest -or @($Catalog.operations|Where-Object{$_.policy -cne 'DENY' -and -not $_.ready}).Count){throw 'RELEASE_CATALOG_NOT_READY'}
        $RepoCatalog=Repo-JSON "import json;from fortis_approvals.extensions.client import default_client;print(json.dumps(default_client().catalog()))"
        if($RepoCatalog.configurationDigest -cne $script:R.configurationDigest){throw 'RELEASE_REPO_CATALOG_MISMATCH'}
        if($Bootstrap){
            Assert-NativeRepoRead
            $ProbeInput=ConvertTo-Json -Compress -Depth 20 @{
                configurationDigest=$script:R.configurationDigest
                interlockDigest=$P.registryDelivery.sourceDelivery.interlockDigest
                profileDigest=$P.registryDelivery.profileDigest
                probes=@(ConvertFrom-Json -InputObject $script:R.probes)}
            $Probe=Running-CLI $C.Id @('probe-frozen') $ProbeInput
            if($Probe.status -cne 'READ_PROBES_PASS' -or
                $Probe.count -ne @(ConvertFrom-Json -InputObject $script:R.probes).Count){
                throw 'RELEASE_SUCCESSOR_FROZEN_PROBE_UNCONFIRMED'
            }
        }else{$null=Running-CLI $C.Id @('probe') $script:R.probes}
        if(Read-GatewayNetworks $P){
            $ValidatedNetworks=Read-GatewayNetworks $P
            if(Test-RecordedGatewayNetwork $ValidatedNetworks 'fortis-actioncore-net'){
                Step 'VERIFY_ACTION_CORE_HTTP8000_DENIAL'
                Assert-ActionCoreNoHttpFromGateway $C.Id
            }
            if(Test-RecordedGatewayNetwork $ValidatedNetworks 'fortis-observatory-gw-net'){
                Step 'VERIFY_OBSERVATORY_TLS443_AUTH_GATE'
                Assert-ObservatoryPrivateTlsRead $C.Id
                Step 'VERIFY_OBSERVATORY_HTTP18756_DENIAL'
                Assert-ObservatoryNoLegacyHttp $C.Id
            }
        }
        if(Read-OwnerShellFlag $P){
            Step 'VERIFY_STAGED_OWNER_SHELL_MTLS'
            Running-OwnerShell-Check $C.Id
        }
        $script:R.probesPassed=$true;Save -FlushToDisk:([bool]($Corrective -or $Bootstrap))
        Assert-Release-Production
        if($Corrective){
            $null=Read-CorrectiveAttemptPair
            Assert-CorrectiveStoppedSource $Corrective
            Assert-CorrectiveTargetCheckpoint $Corrective
            Assert-CorrectiveGateAbsent $P
        }else{Assert-SourceUnchanged}
        if($Bootstrap){
            $Intent=Read-BootstrapFrozenIntent $script:R.source $script:R.bootstrapCheckRecord $script:R.bootstrapCheckHash -Runtime
            $RegistryCandidate=Read-BootstrapReceiver $Intent -GatewayId $C.Id
            if(-not $RegistryCandidate){throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_MISSING'}
            Assert-PairedFrozenSource $Intent $script:R.source -CandidateIds @($C.Id,$RegistryCandidate.Id)
            Admit (Container $C.Id) $P
            Assert-CorrectiveGateAbsent $P
        }
        Step 'ACTIVATE'
        if($Bootstrap){
            try {$null=Running-CLI $C.Id @('activate') '' -Root}
            catch {Write-Warning 'RELEASE_SUCCESSOR_BOOTSTRAP_ACTIVATION_READBACK'}
            $ActualGate=Image-CLI @('gate-record-status') $GateInput -StateVolume $P.stateVolume
            if($ActualGate.active -ne $true -or $ActualGate.markerPresent -ne $true){
                throw 'RELEASE_ACTIVATION_NOT_CONFIRMED'
            }
        } else {
            $Activated=Running-CLI $C.Id @('activate') '' -Root
            if($Activated.status -cne 'ACTIVATED'){throw 'RELEASE_ACTIVATION_NOT_CONFIRMED'}
        }
    } elseif(-not $script:R.probesPassed){throw 'RELEASE_ACTIVE_WITHOUT_PROBE_RECEIPT'}
    if($Corrective){
        # Persist the irreversible boundary before enabling auto-restart or
        # publishing current.json. Resume reads the actual marker after loss.
        $script:R.activated=$true;Save -FlushToDisk
        Complete-CorrectiveRegistryPair $Corrective
    }
    if($Bootstrap){
        # The marker is irreversible, even while the Registry holds block
        # business effects. Keep the receiver until protected completion.
        $script:R.activated=$true;Save -FlushToDisk
        $Intent=Read-BootstrapFrozenIntent $script:R.source $script:R.bootstrapCheckRecord $script:R.bootstrapCheckHash -Runtime
        $Receiver=Read-BootstrapReceiver $Intent -GatewayId $C.Id -Accepted
        $null=Set-BootstrapContainerState $Receiver RestoreRestart
        $null=Read-BootstrapReceiver $Intent -GatewayId $C.Id -Accepted
    }
    $script:R.activated=$true;$script:R.phase='Complete';Save -FlushToDisk:([bool]($Corrective -or $Bootstrap))
    Write-Private $Pointer @{schema=1;record=$script:RecordPath} -FlushToDisk:([bool]($Corrective -or $Bootstrap))
    [ordered]@{record=$script:RecordPath;image=$P.image;configurationDigest=$script:R.configurationDigest
        active=$true;previousRetained=$true;productionUnchanged=$true;providerMutationAcceptance='PENDING_OR_NOT_APPLICABLE'}|ConvertTo-Json
    Write-Host 'FORTIS_INTEGRATIONS_ACTIVATED'
    Write-ReleaseTiming 'APPLY_ACTIVATED'
}

# Exact owner-controlled return for this pilot handover. Loaded by
# Manage-Integrations.ps1; all Docker effects use its existing release lock.
function Read-RegistryReturnSourceDigest {
    param($Source)
    $Retained=Read-Private $Source.path
    if((Get-FileHash -LiteralPath $Source.path -Algorithm SHA256).Hash -cne $Source.hash -or
       $Retained.schema -cne 'fortis-extension-release-v1' -or $Retained.phase -cne 'Complete' -or
       $Retained.activated -ne $true -or $Retained.configurationDigest -cnotmatch '^[0-9a-f]{64}$'){
        throw 'RELEASE_REGISTRY_RETURN_SOURCE_CONFIG_CHANGED'
    }
    return $Retained.configurationDigest
}

function Assert-RegistryCrashSource {
    param($Source)
    $CrashCheck=Join-Path $ReleaseBase 'image-check-95f58a78f41f40cc93e0dc4650d1a641\record.json'
    $CheckHash=(Get-FileHash -LiteralPath $CrashCheck -Algorithm SHA256).Hash
    $Historical=Read-Private $CrashCheck
    $Binding=$Historical.binding
    if($Historical.schema -cne 'fortis-extension-image-check-v1' -or $Historical.phase -cne 'Ready' -or
       $Binding.sourceSha -cne '5e380a2deee59ec8bc0ade1e8dd2a156f9e44181' -or
       $Binding.registryReleaseNonce -cne 'c79f5138-9fb6-46b8-8785-3b36ff5d0017' -or
       $Binding.registryProfileDigest -cne 'c21071537439e35522d0db67c34200ecc2cfba2e900f06e7eb114a9cef2fd287' -or
       $Binding.sourceHash -cne $Source.hash -or $Binding.sourceRecord -cne $Source.path -or
       $Binding.sourceContainerId -cne $Source.runtime.pilotId -or
       $Binding.sourceStateVolume -cne $Source.runtime.stateVolume -or
       $Binding.sourceRunId -cne 'f280e82c893f4195927e5db70a3ed53d' -or
       (Container $Source.runtime.pilotId).State.Status -cne 'exited'){
        throw 'RELEASE_REGISTRY_CRASH_SOURCE_EVIDENCE_CHANGED'
    }
    foreach($Pair in @(@($Pointer,$Binding.currentPointerHash),@($AttemptPointer,$Binding.attemptPointerHash),
                       @($PrimaryPointer,$Binding.primaryPointerHash))){
        $Actual=if(Test-Path -LiteralPath $Pair[0]){(Get-FileHash -LiteralPath $Pair[0] -Algorithm SHA256).Hash}else{''}
        if($Actual -cne $Pair[1]){throw 'RELEASE_REGISTRY_CRASH_SOURCE_POINTER_CHANGED'}
    }
    Assert-OnlyWriter $Source.runtime.stateVolume
    if(-not $Historical.sourceReceipt -or (Get-FileHash -LiteralPath $CrashCheck -Algorithm SHA256).Hash -cne $CheckHash){
        throw 'RELEASE_REGISTRY_CRASH_CHECK_RECORD_CHANGED'
    }
    $script:RegistryCrash=[ordered]@{
        checkRecord=$CrashCheck
        checkHash=$CheckHash
        incumbentId='03992c685e9abd2e3a65cf2071e57fa9f0bbdf83ad31f129a22b8f0ce8e0a8f1'
        incumbentImage='sha256:2039987ce7c7b15d6fd6dea8111c79bf27098cdf5e9754ddea1a8034d3f20d50'
        boots=[ordered]@{previous='fe773048-0d12-45a3-b463-cfbf0d6493ca';current='a19a9a29-5e3d-4e1d-b275-09a02dcd506b'}
    }
}

function Assert-RegistryCrashReceipt {
    param($Receipt)
    $Retained=Read-Private $script:RegistryCrash.checkRecord
    if((Get-FileHash -LiteralPath $script:RegistryCrash.checkRecord -Algorithm SHA256).Hash -cne $script:RegistryCrash.checkHash -or
       -not (Same-Json $Retained.sourceReceipt $Receipt)){
        throw 'RELEASE_REGISTRY_CRASH_SOURCE_RECEIPT_CHANGED'
    }
}

function Assert-RegistryCrashIncumbent {
    param($Source)
    $Incumbent=Container $script:RegistryCrash.incumbentId
    $Primary=Read-Private $PrimaryPointer
    $State=@($Incumbent.Mounts | Where-Object { $_.Destination -ceq '/state' })
    $Ports=@((Docker-Text @('ps','--no-trunc','--format','{{.ID}}|{{.Ports}}')) -split '\r?\n' |
        Where-Object { $_ -match ':1920[34]->' })
    if($Incumbent.Name -cne '/fortis-gateway' -or $Incumbent.Image -cne $script:RegistryCrash.incumbentImage -or
       $Incumbent.State.Status -cne 'running' -or $Incumbent.State.Health.Status -cne 'healthy' -or
       $Primary.schema -cne 'fortis-primary-v1' -or $Primary.phase -cne 'Complete' -or
       $Primary.runtime.pilotId -cne $Incumbent.Id -or $Primary.runtime.image -cne $Incumbent.Image -or
       $Primary.runtime.stateVolume -ceq $Source.runtime.stateVolume -or
       $State.Count -ne 1 -or $State[0].Type -cne 'volume' -or -not $State[0].RW -or
       $State[0].Name -cne $Primary.runtime.stateVolume -or
       $Ports.Count -ne 1 -or -not $Ports[0].StartsWith($Incumbent.Id+'|')){
        throw 'RELEASE_REGISTRY_CRASH_INCUMBENT_CHANGED'
    }
    Assert-OnlyWriter $Primary.runtime.stateVolume $Incumbent.Id
}

function Assert-RegistryCrashIncumbentQuiescent {
    $Code=@'
import json
from fortis_approvals.workflow.client import default_client
result = default_client().list_requests(unresolved_only=True)
counts = result['stateCounts']
print(json.dumps({'clear': all(counts.get(s, 0) == 0 for s in ('PENDING', 'APPROVED', 'DISPATCHED'))}))
'@
    $Result=Repo-JSON $Code
    if($Result.clear -ne $true){throw 'RELEASE_REGISTRY_CRASH_INCUMBENT_WORK_EXISTS'}
}

function Assert-RegistryCrashPortsFree {
    if((Docker-Text @('ps','--format','{{.Ports}}')) -match '(?m):1920[34]->'){
        throw 'RELEASE_REGISTRY_CRASH_GATEWAY_PORTS_IN_USE'
    }
}

function Assert-RegistryCrashGate {
    param($Source,[string]$Digest)
    $Code=@'
import json, sys
sys.path.insert(0, '/opt/fortis')
from fortis_approvals.core import Denied
from fortis_approvals.extensions.staging import ReleaseGate
p = json.load(sys.stdin)
if not ReleaseGate(p['nonce'], p['digest']).ready():
    raise Denied('RELEASE_REGISTRY_CRASH_GATE_MISMATCH')
print('REGISTRY_CRASH_GATE_VERIFIED')
'@
    $Payload=ConvertTo-Json -InputObject @{nonce=$Source.runtime.releaseNonce;digest=$Digest} -Compress
    $Result=Python-Code @('run','--rm','-i','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','32','--memory','128m',
        '--mount',('type=volume,source='+$Source.runtime.stateVolume+',target=/state,readonly,volume-nocopy'),
        $script:Image) $Code $Payload
    if($Result -cne 'REGISTRY_CRASH_GATE_VERIFIED'){throw 'RELEASE_REGISTRY_CRASH_GATE_UNKNOWN'}
}

function Assert-RegistryReturnConfiguration {
    param($Source,$CandidateReport)
    $SourceDigest=Read-RegistryReturnSourceDigest $Source
    # Compare both inputs under the candidate image. The digest also includes
    # framework/provider code, so the retained source image has its own digest.
    $SourceAsCandidate=Image-CLI @('check') ([string]$Source.runtime.extensionsConfig)
    if($SourceAsCandidate.status -cne 'READY' -or
       $SourceAsCandidate.configurationDigest -cne $CandidateReport.configurationDigest){
        throw 'RELEASE_REGISTRY_RETURN_CONFIG_CHANGED'
    }
    if($script:RegistryCrash){
        Assert-RegistryCrashGate $Source $SourceDigest
        return
    }
    $SourceGate=Running-CLI $Source.runtime.pilotId @('gate-status')
    if($SourceGate.active -ne $true -or $SourceGate.configurationDigest -cne $SourceDigest){
        throw 'RELEASE_REGISTRY_RETURN_SOURCE_CONFIG_CHANGED'
    }
}

function Test-Registry259ReturnSource {
    param($Runtime)
    $Run='756d0f76a6954840a08d904d695ce592'
    return ($Runtime.runId -ceq $Run -and $Runtime.pilotName -ceq 'fortis-gateway' -and
        $Runtime.originalPilotName -ceq ('fortis-github-pilot-'+$Run) -and
        $Runtime.restartPolicy -ceq 'unless-stopped' -and
        $Runtime.pilotId -ceq '30595e061ef9e650bd66aaed8c72c5bef3cb714ffa40f1f775c2abeb77d2853e' -and
        $Runtime.image -ceq 'sha256:ecf412817a0595e66aea867c0f6744a7313b0b33a81f14bfcf590e735f9cf72e' -and
        $Runtime.registryProfileDigest -ceq '8104901c4a42b0616cabc8e7ccdb6a0d4580e918dfad1177ceaaece306be21ea' -and
        $Runtime.registryReleaseNonce -ceq '92836269-9f83-47c4-aa0c-c352249f5fa8')
}

function Test-Registry262ReturnSource {
    param($Runtime)
    $Run='1f4936ac84944c8ba3cd51560ed4a54a'
    return ($Runtime.runId -ceq $Run -and $Runtime.pilotName -ceq 'fortis-gateway' -and
        $Runtime.originalPilotName -ceq ('fortis-github-pilot-'+$Run) -and
        $Runtime.restartPolicy -ceq 'unless-stopped' -and
        $Runtime.pilotId -ceq '5563a69819e226f972d2e28c5a92a5c32bfc2b9955e36ef0adb164df99342176' -and
        $Runtime.image -ceq 'sha256:07450e0f5c362290d3fecce5f5d7cdb7abc5295dbb828f22f6e4321168068966' -and
        $Runtime.registryProfileDigest -ceq '68ac5805ee3a21112cbe1b1dd16da72aa3d3a2b7d49b31d0997dfb41fda6f9e5' -and
        $Runtime.registryReleaseNonce -ceq '370079a2-d23e-4c55-a97f-cd8cdf305600')
}

function Test-Registry265ReturnSource {
    param($Runtime)
    $Run='9ce33150477f47d3aff5dffbfe8e458d'
    return ($Runtime.runId -ceq $Run -and $Runtime.pilotName -ceq 'fortis-gateway' -and
        $Runtime.originalPilotName -ceq ('fortis-github-pilot-'+$Run) -and
        $Runtime.restartPolicy -ceq 'unless-stopped' -and
        $Runtime.pilotId -ceq 'ed698f9c497684aa7b58a73581e4b954b8505a17ca8dda6de76061afe245cbf6' -and
        $Runtime.image -ceq 'sha256:6334d9d1c75b3dff7d42c9dfef3cf730227e2ad9bf3399caa817dd00b5ad2af6' -and
        $Runtime.registryProfileDigest -ceq '4564c5c12759dd19e3035e0ea321ad98692ac38bd2b006d10a5175c16ad581b2' -and
        $Runtime.registryReleaseNonce -ceq '2471add6-079b-42ae-9e1d-a22adf821a0d')
}

function Test-Registry268ReturnSource {
    param($Runtime)
    $Run='2538f9e8c8e1489db82a61ced74622ad'
    return ($Runtime.runId -ceq $Run -and $Runtime.pilotName -ceq 'fortis-gateway' -and
        $Runtime.originalPilotName -ceq ('fortis-github-pilot-'+$Run) -and
        $Runtime.restartPolicy -ceq 'unless-stopped' -and
        $Runtime.pilotId -ceq '8ccb36158974c75492462da1e6b964b9207c3e639c0ff3ffe4c54a2549040a43' -and
        $Runtime.image -cmatch '^sha256:[0-9a-f]{64}$' -and
        $Runtime.registryProfileDigest -ceq 'fda46dc0af4c2404e8975172140e054610cec6fd96095485abe8df4fdfd255fe' -and
        $Runtime.registryReleaseNonce -ceq '83058e73-53ca-4b24-a11c-0a8e6efd221d')
}

function Get-Registry268RecoveredProfile {
    param($Source)
    $Evidence=Join-Path $ReleaseBase 'registry-peer-recovery-2936bced44a5415ca484b7b34803b5d1'
    $ExpectedRecord=Join-Path $ReleaseBase '2538f9e8c8e1489db82a61ced74622ad\record.json'
    $ArchivedProfilePath=Join-Path $Evidence 'profile-before.json'
    $Recovery=Read-Private (Join-Path $Evidence 'rebind-plan.json')
    $OriginalProfile=Read-Private $ArchivedProfilePath
    $ExpectedDigest='8be5946224de13f95dd5debeb1fc6686e4073aa13f5cc33dc33b95b60386ca58'
    if($Source.path -cne $ExpectedRecord -or
       $Recovery.releaseRecord -cne $ExpectedRecord -or
       $Recovery.gatewayId -cne $Source.runtime.pilotId -or
       $Recovery.registryId -cne '132d269cf561aa504b05223c27ec340c6b2331727c69e2dd79a84e0e3af05b2e' -or
       $Recovery.oldProfileSha256 -cne $Source.runtime.registryProfileDigest -or
       $Recovery.newProfileSha256 -cne $ExpectedDigest -or
       $OriginalProfile.releaseNonce -cne $Source.runtime.registryReleaseNonce -or
       $OriginalProfile.gatewaySourceDigest -cnotmatch '^[0-9a-f]{64}$' -or
       (Get-FileHash -LiteralPath $ArchivedProfilePath -Algorithm SHA256).Hash -ine $Source.runtime.registryProfileDigest -or
       (Read-RegistryReturnSourceDigest $Source) -cne 'cdfa7f8cd474adaafc2f4e88ee38f85d9e3f8510edcb7e3a46ae2ca74640ffd5'){
        throw 'RELEASE_REGISTRY_268_REBIND_EVIDENCE_CHANGED'
    }
    return @{profileDigest=$ExpectedDigest;sourceDigest=[string]$OriginalProfile.gatewaySourceDigest}
}

function Get-Registry262RecoveredProfileDigest {
    param($Source)
    $Evidence=Join-Path $ReleaseBase 'registry-peer-recovery-ae933096716b4d1d9d3410142089334a'
    $ExpectedRecord=Join-Path $ReleaseBase '1f4936ac84944c8ba3cd51560ed4a54a\record.json'
    $ArchivedProfilePath=Join-Path $Evidence 'profile-before.json'
    $Recovery=Read-Private (Join-Path $Evidence 'rebind-plan.json')
    $OriginalProfile=Read-Private $ArchivedProfilePath
    $ExpectedDigest='01293e503310fc4d5910858098f287766a6a8ea9ab5ab337c464ffbb346fa336'
    if($Source.path -cne $ExpectedRecord -or
       $Recovery.releaseRecord -cne $ExpectedRecord -or
       $Recovery.gatewayId -cne $Source.runtime.pilotId -or
       $Recovery.registryId -cne 'df9a6a2f534ad9bb9cd03f26c9ab0d4a0046a244929a3135ea2501d8e1cf48a3' -or
       $Recovery.bootId -cne '00e8aa14-57a0-472f-84f7-8806d0c377c2' -or
       $Recovery.oldProfileSha256 -cne $Source.runtime.registryProfileDigest -or
       $Recovery.newProfileSha256 -cne $ExpectedDigest -or
       $OriginalProfile.releaseNonce -cne $Source.runtime.registryReleaseNonce -or
       (Get-FileHash -LiteralPath $ArchivedProfilePath -Algorithm SHA256).Hash -ine $Source.runtime.registryProfileDigest){
        throw 'RELEASE_REGISTRY_262_REBIND_EVIDENCE_CHANGED'
    }
    return $ExpectedDigest
}

function Registry-ReturnRuntime {
    param($Source, [string]$Id, [string]$Nonce, [string]$ProfileDigest)
    $Original=$Source.runtime
    $Legacy=($Original.runId -ceq 'f280e82c893f4195927e5db70a3ed53d' -and
        $Original.pilotName -ceq ('fortis-github-pilot-'+$Original.runId) -and
        $Original.image -ceq 'sha256:22de6d321559c70d3e7c788dc1e77a77cde7dea078cdd7c67cbe59aa93930963' -and
        $Original.registryProfileDigest -ceq 'c11871b078930e70878f8d0b8199b90ead38626b403ee858606ba71c19cb6fa3' -and
        $Original.registryReleaseNonce -ceq 'e43f890f-fe66-4139-b397-4bb20be82e80')
    $Promoted=(Test-Registry259ReturnSource $Original) -or (Test-Registry262ReturnSource $Original) -or
        (Test-Registry265ReturnSource $Original) -or (Test-Registry268ReturnSource $Original)
    if($Source.hash -cnotmatch '^[0-9a-fA-F]{64}$' -or
       (-not $Legacy -and -not $Promoted) -or ($Promoted -and $script:RegistryCrash) -or
       $Original.stateVolume -cne ('fortis-github-pilot-state-'+$Original.runId) -or
       $Original.pilotId -cnotmatch '^[0-9a-f]{64}$' -or
       $Id -cnotmatch '^[0-9a-f]{64}$' -or $Id -ceq $Original.pilotId -or
       $Nonce -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
       $Nonce -ceq $Original.releaseNonce -or $ProfileDigest -cnotmatch '^[0-9a-f]{64}$'){
        throw 'RELEASE_REGISTRY_RETURN_SCOPE_DENIED'
    }
    $Runtime=ConvertTo-Json -InputObject $Original -Depth 25 -Compress | ConvertFrom-Json
    if($Promoted){
        $Runtime.PSObject.Properties.Remove('originalPilotName')
        $Runtime.PSObject.Properties.Remove('restartPolicy')
    }
    $Runtime.runId=$Nonce.Replace('-','')
    $Runtime.pilotId=$Id
    $Runtime.pilotName='fortis-github-pilot-'+$Runtime.runId
    $Runtime.releaseNonce=$Nonce
    $Runtime.registryReleaseNonce=$Nonce
    $Runtime.registryReaderVolume='fortis-r7-registry-reader-'+$Runtime.runId
    $Runtime.registryProfileDigest=$ProfileDigest
    $Runtime.preserveApprovedRequest=''
    return $Runtime
}

function Get-RegistryReturnSeal {
    param($Source,[string]$Nonce)
    $Original=$Source.runtime
    $Retained=Read-RegistryMountBinding $Original
    $Replacement='fortis-r7-registry-reader-'+$Nonce.Replace('-','')
    foreach($Volume in @($Retained.readerVolume,$Replacement,$Retained.socketVolume)){
        Assert-Volume $Volume
    }
    Assert-OnlyWriter $Retained.readerVolume
    Assert-OnlyWriter $Replacement
    $Code=@'
import json, sys
sys.path.insert(0, '/opt/fortis')
from fortis_approvals.r7_registry_reader_mount import reviewed_registry_return_profile

print(reviewed_registry_return_profile(**json.load(sys.stdin)))
'@
    $Inputs=@{
        source_nonce=$Retained.releaseNonce
        source_profile_digest=$Retained.profileDigest
        return_nonce=$Nonce
        source_digest=$(if(Test-Registry259ReturnSource $Original){
            'fe607625bd79e2ad45fbb7065e2fef2da45d077af6ce8c085325aac988e4ab57'
        } else {
            'ece8ada947e53301fa3cc6d9bd6b645bbc02c6b122de851e7780a07bd3b66b61'
        })
    }
    if(Test-Registry262ReturnSource $Original){
        # The protected source record still pins the original pre-crash profile.
        # Verify the retained owner recovery evidence before reading the resealed volume.
        $Inputs['source_profile_digest']=Get-Registry262RecoveredProfileDigest $Source
        $Inputs['source_digest']='c71eebc342f3e4cd45f1cdd502d0c0854088af66c0a0a5fa988fc76ff6182bb4'
    } elseif(Test-Registry265ReturnSource $Original){
        $Inputs['source_digest']='e5d23744bcdb5028d8872aaaae6dc267873a7ddf6406a5e2e40032a80a1c268e'
    } elseif(Test-Registry268ReturnSource $Original){
        $RecoveredProfile=Get-Registry268RecoveredProfile $Source
        $Inputs['source_profile_digest']=$RecoveredProfile.profileDigest
        $Inputs['source_digest']=$RecoveredProfile.sourceDigest
    }
    if($script:RegistryCrash){
        if((Get-FileHash -LiteralPath $script:RegistryCrash.checkRecord -Algorithm SHA256).Hash -cne $script:RegistryCrash.checkHash){
            throw 'RELEASE_REGISTRY_CRASH_CHECK_RECORD_CHANGED'
        }
        $Inputs['crash_boot_ids']=$script:RegistryCrash.boots
    }
    $Payload=ConvertTo-Json -InputObject $Inputs -Compress
    $Digest=Python-Code @('run','--rm','-i','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','32','--memory','128m',
        '--mount',('type=volume,source='+$Retained.readerVolume+',target=/run/r7-registry-reader-retained,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$Replacement+',target=/run/r7-registry-reader,readonly,volume-nocopy'),
        '--mount',('type=volume,source='+$Retained.socketVolume+',target=/run/fortis-registry-read,readonly,volume-nocopy'),
        $script:Image) $Code $Payload
    if($Digest -cnotmatch '^[0-9a-f]{64}$'){throw 'RELEASE_REGISTRY_RETURN_PROFILE_INVALID'}
    return $Digest
}

function Assert-RegistryReturnInputs {
    param($Source,$Reserve,$Original,[switch]$AllowUsed)
    $Expected=Registry-ReturnRuntime $Source $Reserve.pilotId $Reserve.releaseNonce $Reserve.registryProfileDigest
    if(-not (Same-Json $Expected $Reserve) -or
       $Original.Id -cne $Source.runtime.pilotId -or
       (Get-FileHash -LiteralPath $Source.path -Algorithm SHA256).Hash -cne $Source.hash){
        throw 'RELEASE_REGISTRY_RETURN_SOURCE_CHANGED'
    }
    $Fallback=Container $Reserve.pilotId
    if(((-not $AllowUsed) -and ($Fallback.State.Status -cne 'created' -or
                               $Fallback.State.StartedAt -cne '0001-01-01T00:00:00Z')) -or
       $Fallback.State.Status -cnotin @('created','exited','running')){
        throw 'RELEASE_REGISTRY_RETURN_CONTAINER_NOT_READY'
    }
    # Full existing admission checks host bindings, image, command, credentials
    # and the live replacement seal. Match every environment value except nonce.
    Admit $Fallback $Reserve -AllowUnhealthy
    $OldEnv=@($Original.Config.Env | Where-Object { -not $_.StartsWith('FORTIS_RELEASE_NONCE=') } | Sort-Object -CaseSensitive)
    $NewEnv=@($Fallback.Config.Env | Where-Object { -not $_.StartsWith('FORTIS_RELEASE_NONCE=') } | Sort-Object -CaseSensitive)
    if(-not (Same-Json $OldEnv $NewEnv) -or
       (Get-RegistryReturnSeal $Source $Reserve.releaseNonce) -cne $Reserve.registryProfileDigest){
        throw 'RELEASE_REGISTRY_RETURN_BINDING_CHANGED'
    }
    $Writer=''
    if($Original.State.Status -ceq 'running'){$Writer=$Original.Id}
    elseif($Fallback.State.Status -ceq 'running'){$Writer=$Fallback.Id}
    Assert-OnlyWriter $Source.runtime.stateVolume $Writer
}

function Assert-RegistryReturnSelfTest {
    $Run='f280e82c893f4195927e5db70a3ed53d'
    $Original=[pscustomobject]@{
        runId=$Run;pilotName=('fortis-github-pilot-'+$Run);pilotId=('a'*64)
        image='sha256:22de6d321559c70d3e7c788dc1e77a77cde7dea078cdd7c67cbe59aa93930963'
        stateVolume=('fortis-github-pilot-state-'+$Run)
        registryReleaseNonce='e43f890f-fe66-4139-b397-4bb20be82e80'
        releaseNonce='e43f890f-fe66-4139-b397-4bb20be82e80'
        registryProfileDigest='c11871b078930e70878f8d0b8199b90ead38626b403ee858606ba71c19cb6fa3'
        registryReaderVolume='fortis-r7-registry-reader-e43f890ffe664139b3974bb20be82e80'
        preserveApprovedRequest='retained';tokenVolume='original-token';extensionsConfig='{}'
    }
    $Source=@{runtime=$Original;hash=('c'*64)}
    $Nonce='44444444-4444-4444-8444-444444444444'
    $Reserve=Registry-ReturnRuntime $Source ('b'*64) $Nonce ('d'*64)
    if($Reserve.stateVolume -cne $Original.stateVolume -or
       $Reserve.tokenVolume -cne $Original.tokenVolume -or $Reserve.image -cne $Original.image -or
       $Reserve.pilotName -cne 'fortis-github-pilot-44444444444444448444444444444444' -or
       $Reserve.registryReaderVolume -cne 'fortis-r7-registry-reader-44444444444444448444444444444444' -or
       $Reserve.preserveApprovedRequest -or $Original.preserveApprovedRequest -cne 'retained'){
        throw 'RELEASE_REGISTRY_RETURN_RUNTIME_SELFTEST_FAILED'
    }
    $PromotedRun='756d0f76a6954840a08d904d695ce592'
    $Promoted=[pscustomobject]@{
        runId=$PromotedRun;pilotName='fortis-gateway'
        originalPilotName=('fortis-github-pilot-'+$PromotedRun);restartPolicy='unless-stopped'
        pilotId='30595e061ef9e650bd66aaed8c72c5bef3cb714ffa40f1f775c2abeb77d2853e'
        image='sha256:ecf412817a0595e66aea867c0f6744a7313b0b33a81f14bfcf590e735f9cf72e'
        stateVolume=('fortis-github-pilot-state-'+$PromotedRun)
        registryProfileDigest='8104901c4a42b0616cabc8e7ccdb6a0d4580e918dfad1177ceaaece306be21ea'
        registryReleaseNonce='92836269-9f83-47c4-aa0c-c352249f5fa8'
        releaseNonce='92836269-9f83-47c4-aa0c-c352249f5fa8'
        registryReaderVolume='fortis-r7-registry-reader-928362699f8347c4aa0cc352249f5fa8'
        preserveApprovedRequest=''
    }
    $PromotedSource=@{runtime=$Promoted;hash=('c'*64)}
    $WarmReserve=Registry-ReturnRuntime $PromotedSource ('b'*64) $Nonce ('d'*64)
    if($WarmReserve.pilotName -cne $Reserve.pilotName -or
       $WarmReserve.stateVolume -cne $Promoted.stateVolume -or $WarmReserve.image -cne $Promoted.image -or
       $WarmReserve.PSObject.Properties['originalPilotName'] -or
       $WarmReserve.PSObject.Properties['restartPolicy'] -or $Promoted.restartPolicy -cne 'unless-stopped'){
        throw 'RELEASE_REGISTRY_PROMOTED_RETURN_RUNTIME_SELFTEST_FAILED'
    }
    $Recovered=$Promoted | ConvertTo-Json -Compress | ConvertFrom-Json
    $Recovered.runId='1f4936ac84944c8ba3cd51560ed4a54a'
    $Recovered.originalPilotName='fortis-github-pilot-'+$Recovered.runId
    $Recovered.stateVolume='fortis-github-pilot-state-'+$Recovered.runId
    $Recovered.pilotId='5563a69819e226f972d2e28c5a92a5c32bfc2b9955e36ef0adb164df99342176'
    $Recovered.image='sha256:07450e0f5c362290d3fecce5f5d7cdb7abc5295dbb828f22f6e4321168068966'
    $Recovered.registryProfileDigest='68ac5805ee3a21112cbe1b1dd16da72aa3d3a2b7d49b31d0997dfb41fda6f9e5'
    $Recovered.registryReleaseNonce='370079a2-d23e-4c55-a97f-cd8cdf305600'
    $Recovered.releaseNonce=$Recovered.registryReleaseNonce
    $Recovered.registryReaderVolume='fortis-r7-registry-reader-'+$Recovered.registryReleaseNonce.Replace('-','')
    $RecoveredReserve=Registry-ReturnRuntime @{runtime=$Recovered;hash=('c'*64)} ('b'*64) $Nonce ('d'*64)
    if($RecoveredReserve.image -cne $Recovered.image -or $RecoveredReserve.stateVolume -cne $Recovered.stateVolume -or
       $RecoveredReserve.PSObject.Properties['restartPolicy'] -or
       $Recovered.registryProfileDigest -cne '68ac5805ee3a21112cbe1b1dd16da72aa3d3a2b7d49b31d0997dfb41fda6f9e5'){
        throw 'RELEASE_REGISTRY_262_RETURN_RUNTIME_SELFTEST_FAILED'
    }
    $Current=$Recovered | ConvertTo-Json -Compress | ConvertFrom-Json
    $Current.runId='9ce33150477f47d3aff5dffbfe8e458d'
    $Current.originalPilotName='fortis-github-pilot-'+$Current.runId
    $Current.stateVolume='fortis-github-pilot-state-'+$Current.runId
    $Current.pilotId='ed698f9c497684aa7b58a73581e4b954b8505a17ca8dda6de76061afe245cbf6'
    $Current.image='sha256:6334d9d1c75b3dff7d42c9dfef3cf730227e2ad9bf3399caa817dd00b5ad2af6'
    $Current.registryProfileDigest='4564c5c12759dd19e3035e0ea321ad98692ac38bd2b006d10a5175c16ad581b2'
    $Current.registryReleaseNonce='2471add6-079b-42ae-9e1d-a22adf821a0d'
    $Current.releaseNonce=$Current.registryReleaseNonce
    $Current.registryReaderVolume='fortis-r7-registry-reader-'+$Current.registryReleaseNonce.Replace('-','')
    $CurrentReserve=Registry-ReturnRuntime @{runtime=$Current;hash=('c'*64)} ('b'*64) $Nonce ('d'*64)
    if($CurrentReserve.image -cne $Current.image -or $CurrentReserve.stateVolume -cne $Current.stateVolume -or
       $CurrentReserve.registryReleaseNonce -cne $Nonce -or $CurrentReserve.PSObject.Properties['restartPolicy']){
        throw 'RELEASE_REGISTRY_265_RETURN_RUNTIME_SELFTEST_FAILED'
    }
    $Active=$Current | ConvertTo-Json -Compress | ConvertFrom-Json
    $Active.runId='2538f9e8c8e1489db82a61ced74622ad'
    $Active.originalPilotName='fortis-github-pilot-'+$Active.runId
    $Active.stateVolume='fortis-github-pilot-state-'+$Active.runId
    $Active.pilotId='8ccb36158974c75492462da1e6b964b9207c3e639c0ff3ffe4c54a2549040a43'
    $Active.registryProfileDigest='fda46dc0af4c2404e8975172140e054610cec6fd96095485abe8df4fdfd255fe'
    $Active.registryReleaseNonce='83058e73-53ca-4b24-a11c-0a8e6efd221d'
    $Active.releaseNonce=$Active.registryReleaseNonce
    $Active.registryReaderVolume='fortis-r7-registry-reader-'+$Active.registryReleaseNonce.Replace('-','')
    $ActiveSource=@{runtime=$Active;hash=('c'*64)}
    $ActiveReserve=Registry-ReturnRuntime $ActiveSource ('b'*64) $Nonce ('d'*64)
    if($ActiveReserve.image -cne $Active.image -or $ActiveReserve.stateVolume -cne $Active.stateVolume -or
       $ActiveReserve.registryReleaseNonce -cne $Nonce -or $ActiveReserve.PSObject.Properties['restartPolicy']){
        throw 'RELEASE_REGISTRY_268_RETURN_RUNTIME_SELFTEST_FAILED'
    }
    $Active.registryProfileDigest='8be5946224de13f95dd5debeb1fc6686e4073aa13f5cc33dc33b95b60386ca58'
    try {
        $null=Registry-ReturnRuntime $ActiveSource ('b'*64) $Nonce ('d'*64)
        throw 'RELEASE_REGISTRY_268_RETURN_ORIGINAL_PIN_SELFTEST_FAILED'
    } catch {
        if($_.Exception.Message -cne 'RELEASE_REGISTRY_RETURN_SCOPE_DENIED'){throw}
    }
    $Promoted.pilotId='a'*64
    try {
        $null=Registry-ReturnRuntime $PromotedSource ('b'*64) $Nonce ('d'*64)
        throw 'RELEASE_REGISTRY_PROMOTED_RETURN_IDENTITY_SELFTEST_FAILED'
    } catch {
        if($_.Exception.Message -cne 'RELEASE_REGISTRY_RETURN_SCOPE_DENIED'){throw}
    }
    foreach($Wrong in @($Original.releaseNonce,'invalid')){
        try {
            $null=Registry-ReturnRuntime $Source ('b'*64) $Wrong ('d'*64)
            throw 'RELEASE_REGISTRY_RETURN_NONCE_SELFTEST_FAILED'
        } catch {
            if($_.Exception.Message -cne 'RELEASE_REGISTRY_RETURN_SCOPE_DENIED'){throw}
        }
    }
    & {
        function Container { param($Id) [pscustomobject]@{Id=$Id;State=@{Status='running'}} }
        function Read-Private { param($File) @{record=$script:RecordPath} }
        function Assert-RegistryReturnInputs {}
        function Admit {}
        function Assert-RegistryCandidateInactive { throw 'TEST_ACTIVATED_CANDIDATE' }
        function Docker-Text { throw 'TEST_UNEXPECTED_DOCKER_EFFECT' }
        $OriginalContainer=[pscustomobject]@{Id=('a'*64);State=@{Status='exited'}}
        $Saved=$script:R
        try {
            $script:R=@{phase='Staged';source=@{path=$script:RecordPath;runtime=$Original};
                sourceReceipt=@{test=$true};runtime=@{stateVolume='synthetic'}}
            try {
                Restore-RegistrySource $OriginalContainer $Reserve
                throw 'RELEASE_REGISTRY_ACTIVE_CANDIDATE_SELFTEST_FAILED'
            } catch {
                if($_.Exception.Message -cne 'TEST_ACTIVATED_CANDIDATE'){throw}
            }
        } finally {$script:R=$Saved}
    }
    & {
        function Read-Private {
            param($File)
            @{schema='fortis-extension-release-v1';phase='Complete';activated=$true;configurationDigest=('c'*64)}
        }
        function Get-FileHash { param($LiteralPath,$Algorithm) @{Hash=('c'*64)} }
        function Image-CLI {
            param($Arguments,$InputText)
            if($Arguments.Count -ne 1 -or $Arguments[0] -cne 'check' -or $InputText -cne '{}'){
                throw 'TEST_REGISTRY_RETURN_CONFIGURATION_INPUT_CHANGED'
            }
            @{status='READY';configurationDigest=('a'*64)}
        }
        function Running-CLI { param($Id,$Arguments) @{active=$true;configurationDigest=$LiveDigest} }
        $Source.path='synthetic'
        $LiveDigest='c'*64
        Assert-RegistryReturnConfiguration $Source @{configurationDigest=('a'*64)}
        try {
            Assert-RegistryReturnConfiguration $Source @{configurationDigest=('b'*64)}
            throw 'RELEASE_REGISTRY_RETURN_CONFIG_SELFTEST_FAILED'
        } catch {
            if($_.Exception.Message -cne 'RELEASE_REGISTRY_RETURN_CONFIG_CHANGED'){throw}
        }
        $LiveDigest='a'*64
        try {
            Assert-RegistryReturnConfiguration $Source @{configurationDigest=('a'*64)}
            throw 'RELEASE_REGISTRY_RETURN_SOURCE_DIGEST_SELFTEST_FAILED'
        } catch {
            if($_.Exception.Message -cne 'RELEASE_REGISTRY_RETURN_SOURCE_CONFIG_CHANGED'){throw}
        }
    }
    & {
        function Read-RegistryReturnSourceDigest { return ('c'*64) }
        function Image-CLI { param($Arguments,$InputText) @{status='READY';configurationDigest=('a'*64)} }
        function Running-CLI { throw 'TEST_COLD_SOURCE_MUST_NOT_BE_EXECUTED' }
        function Assert-RegistryCrashGate {
            param($Source,$Digest)
            if($Digest -cne ('c'*64)){throw 'TEST_COLD_SOURCE_DIGEST_CHANGED'}
        }
        $Previous=$script:RegistryCrash
        try {
            $script:RegistryCrash=@{boots=@{previous='old';current='new'}}
            Assert-RegistryReturnConfiguration $Source @{configurationDigest=('a'*64)}
        } finally {$script:RegistryCrash=$Previous}
    }
    Write-Host 'FORTIS_REGISTRY_RETURN_BINDING_SELFTEST_PASS'
}

function Assert-RegistryCandidateInactive {
    param($Runtime)
    $Names=@((Docker-Text @('volume','ls','--format','{{.Name}}')) -split '\r?\n')
    if($Runtime.stateVolume -cne ('fortis-github-pilot-state-'+$Runtime.runId) -or
       $Runtime.runId -cnotmatch '^[0-9a-f]{32}$'){
        throw 'RELEASE_REGISTRY_CANDIDATE_VOLUME_INVALID'
    }
    if($Names -cnotcontains $Runtime.stateVolume){return}
    Assert-Volume $Runtime.stateVolume
    $Volume=@(Docker-Json @('volume','inspect',$Runtime.stateVolume))[0]
    if($Volume.Labels.'io.fortis.release' -cne $Runtime.runId){
        throw 'RELEASE_REGISTRY_CANDIDATE_VOLUME_INVALID'
    }
    $Code=@'
import sys
from pathlib import Path
sys.path.insert(0, '/opt/fortis')
from fortis_approvals.extensions.staging import MARKER
from fortis_approvals.core import Denied

try:
    Path(MARKER).lstat()
except FileNotFoundError:
    print('REGISTRY_CANDIDATE_MARKER_ABSENT')
else:
    raise Denied('RELEASE_REGISTRY_CANDIDATE_ACTIVATION_MARKER_PRESENT')
'@
    $Result=Python-Code @('run','--rm','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','32','--memory','128m',
        '--mount',('type=volume,source='+$Runtime.stateVolume+',target=/state,readonly,volume-nocopy'),
        $script:Image) $Code
    if($Result -cne 'REGISTRY_CANDIDATE_MARKER_ABSENT'){throw 'RELEASE_REGISTRY_CANDIDATE_GATE_UNKNOWN'}
}

function Restore-RegistrySource {
    param($Original,$Reserve)
    $Source=$script:R.source
    $Target=$script:R.runtime
    $UsingReserve=($script:R.phase -ceq 'ReturningRegistrySource')
    if($script:R.phase -cnotin @('Prepared','Created','Staged','ReturningRegistrySource') -or
       $Original.State.Status -cnotin @('running','exited') -or -not $script:R.sourceReceipt){
        throw 'RELEASE_REGISTRY_RETURN_ATTEMPT_INVALID'
    }
    if((Read-Private $AttemptPointer).record -cne $script:RecordPath){
        throw 'RELEASE_REGISTRY_RETURN_ATTEMPT_POINTER_CHANGED'
    }
    $PointerPath=(Read-Private $Pointer).record
    $RecordPath=Join-Path (Join-Path $ReleaseBase $Reserve.runId) 'record.json'
    if($PointerPath -cne $Source.path -and (-not $UsingReserve -or $PointerPath -cne $RecordPath)){
        throw 'RELEASE_REGISTRY_RETURN_POINTER_CHANGED'
    }
    if($script:RegistryCrash -and (Container $script:RegistryCrash.incumbentId).State.Status -cne 'exited'){
        throw 'RELEASE_REGISTRY_CRASH_INCUMBENT_STILL_PRESENT'
    }
    Assert-RegistryReturnInputs $Source $Reserve $Original -AllowUsed:$UsingReserve
    Admit $Original $Source.runtime -RegistryReturnSource
    Assert-RegistryCandidateInactive $Target
    $Names=@((Docker-Text @('ps','-a','--format','{{.Names}}')) -split '\r?\n')
    if($Names -ccontains $Target.pilotName){
        $Candidate=Container $Target.pilotName
        Admit-ReturnCandidate $Candidate $Target
        if($Candidate.State.Status -ceq 'running'){
            $null=Docker-Text @('stop','--timeout','20',$Candidate.Id)
        } elseif($Candidate.State.Status -cnotin @('exited','created')){
            throw 'RELEASE_CANDIDATE_STATE_UNKNOWN'
        }
        if((Container $Candidate.Id).State.Status -cnotin @('exited','created')){
            throw 'RELEASE_STOP_UNCONFIRMED'
        }
    }
    Assert-RegistryCandidateInactive $Target
    $SourceDigest=Read-RegistryReturnSourceDigest $Source
    if($Original.State.Status -ceq 'running'){
        if($UsingReserve -or (Container $Original.Id).State.Status -cne 'running'){
            throw 'RELEASE_REGISTRY_RETURN_SOURCE_CHANGED'
        }
        return
    }

    $Fallback=Container $Reserve.pilotId
    if($Fallback.State.Status -cne 'running'){Assert-SourceUnchanged}
    if(-not $UsingReserve){
        $script:R.phase='ReturningRegistrySource'
        Save
    }
    Assert-Release-Production
    $Retained=Container $Original.Id
    if($Retained.State.Status -cne 'exited'){throw 'RELEASE_REGISTRY_RETURN_SOURCE_NOT_FROZEN'}
    Assert-RegistryReturnInputs $Source $Reserve $Retained -AllowUsed
    if($Fallback.State.Status -cne 'running'){
        Assert-OnlyWriter $Reserve.stateVolume
        $null=Docker-Text @('start',$Reserve.pilotId)
    }
    Wait-Healthy $Reserve.pilotId
    Admit (Container $Reserve.pilotId) $Reserve
    Assert-OnlyWriter $Reserve.stateVolume $Reserve.pilotId
    $Gate=Running-CLI $Reserve.pilotId @('gate-status')
    if($Gate.configurationDigest -cne $SourceDigest){
        throw 'RELEASE_REGISTRY_RETURN_CONFIG_CHANGED'
    }
    Assert-RegistryCandidateInactive $Target
    Assert-Release-Production
    if(-not $Gate.active){
        $Catalog=Running-CLI $Reserve.pilotId @('catalog')
        $RepoCatalog=Repo-JSON "from fortis_approvals.extensions.client import default_client;import json;print(json.dumps(default_client().catalog()))"
        if($Catalog.configurationDigest -cne $Gate.configurationDigest -or
           $RepoCatalog.configurationDigest -cne $Gate.configurationDigest){
            throw 'RELEASE_REGISTRY_RETURN_CATALOG_CHANGED'
        }
        $null=Running-CLI $Reserve.pilotId @('probe') $script:R.probes
        if(Read-OwnerShellFlag $Reserve){Running-OwnerShell-Check $Reserve.pilotId}
        Assert-RegistryCandidateInactive $Target
        $Result=Running-CLI $Reserve.pilotId @('activate') '' -Root
        if($Result.status -cne 'ACTIVATED' -or $Result.configurationDigest -cne $Gate.configurationDigest){
            throw 'RELEASE_REGISTRY_RETURN_ACTIVATION_UNKNOWN'
        }
    }
    Assert-Release-Production
    $FallbackRecord=[ordered]@{schema='fortis-extension-release-v1';phase='Complete';
        runtime=$Reserve;activated=$true;probesPassed=$true;configurationDigest=$Gate.configurationDigest
        registryReturnAttempt=$script:RecordPath;retainedSourceRecord=$Source.path}
    if(Test-Path -LiteralPath $RecordPath){
        if(-not (Same-Json (Read-Private $RecordPath) $FallbackRecord)){
            throw 'RELEASE_REGISTRY_RETURN_RECORD_CHANGED'
        }
    } else {
        Protect-Directory (Split-Path -Parent $RecordPath)
        Write-Private $RecordPath $FallbackRecord
    }
    Write-Private $Pointer @{schema=1;record=$RecordPath}
    Write-Host 'FORTIS_INTEGRATIONS_RETURNED_REGISTRY_RESERVE'
}

. (Join-Path $PSScriptRoot 'Primary-Gateway.ps1')
. (Join-Path $PSScriptRoot 'Provider-Credentials.ps1')

if($Service -and $Action -cne 'Credential'){throw 'CREDENTIAL_SERVICE_ACTION_INVALID'}
if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or $PSVersionTable.PSEdition -cne 'Desktop'){throw 'RELEASE_WINDOWS_POWERSHELL_51_REQUIRED'}
if(@(Json-Items '[{"Id":"one"},{"Id":"two"}]').Count -ne 2 -or @(Json-Items '[{"Id":"one"}]')[0].Id -cne 'one'){throw 'RELEASE_JSON_SELFTEST_FAILED'}
function Assert-CorrectiveRegistryPairSelfTest {
    $NonceVariable=Get-Variable -Name RegistryBoundReleaseNonce -Scope Script -ErrorAction SilentlyContinue
    $PreviousNonce=if($NonceVariable){$NonceVariable.Value}else{''}
    $RVariable=Get-Variable -Name R -Scope Script -ErrorAction SilentlyContinue
    $PathVariable=Get-Variable -Name RecordPath -Scope Script -ErrorAction SilentlyContinue
    $PreviousR=if($RVariable){$RVariable.Value}
    $PreviousPath=if($PathVariable){$PathVariable.Value}
    try { & {
        $ReleaseBase=Join-Path ([IO.Path]::GetTempPath()) 'fortis-corrective-pair-fixture'
        $Pointer=Join-Path $ReleaseBase 'current.json'
        $Run='6ec445e6191543e7873275166922010b'
        $OldNonce='3ac0e38d-2618-4b51-8900-97107f727785'
        $Nonce='11111111-1111-4111-8111-111111111111'
        $SourceSha='e'*40
        $CorrectiveRegistryImage='sha256:'+('c'*64)
        $CorrectiveRegistryProfileSha256='d'*64
        $script:RegistryBoundReleaseNonce=$Nonce
        $OldProfile='a24fe5d8cf12971b381361d5a9fa56af6dafed679df0e076251d6f5c45d69201'
        $OldImage='sha256:34f62160f05bd0b1986b6127ec8bb6d9e3ff3124d3550d70c3f98fdabfe27cc3'
        $OldId='abc934c2becc4066e739e4fac3cd276975dcd137a6b0acdae89b81d249df454d'
        $Digest='9dd0e18b2f10e5180fccd5831ff6528e973813d0fe0cf29a826bc20c750a18a3'
        $Generation='906410832e42b5f8dc835e20c75fe79bfebbcbf9d149793111a3d67992f377aa'
        $SourceHash='ea25b6d0769059e225c584a7a5518d6cedd0e8f3f138b1cb29f7194c09cc195c'
        $PriorHash='f7cdb097e257e471bd19292286d2b876cef9d0eb3059b28f539986fec7cd290b'
        $SourcePath=Join-Path $ReleaseBase ($Run+'\record.json')
        $PriorPath=Join-Path $ReleaseBase 'prior\record.json'
        $Publication=Join-Path $ReleaseBase ('maintenance-publication-'+$OldNonce.Replace('-','')+'.json')
        $Source=@{path=$SourcePath;hash=$SourceHash;runtime=[pscustomobject]@{
            runId=$Run;registryReleaseNonce=$OldNonce;maintenanceGeneration=$Generation;pilotId=('a'*64)
            registryDelivery=[pscustomobject]@{sourceDelivery=[pscustomobject]@{interlockDigest=$Digest}}}}
        $Records=@{}
        $Records[$Pointer]=[pscustomobject]@{record=$SourcePath}
        $Records[$SourcePath]=[pscustomobject]@{source=[pscustomobject]@{path=$PriorPath;hash=$PriorHash}}
        $Anchor=[pscustomobject]@{schema='fortis-successor-maintenance-publication-v1';state='Committed'
            sourceRecordHash=$PriorHash;digest=$Digest;record=[pscustomobject]@{
                schemaVersion=1;phase='NORMAL';sequence=0;generation=$Generation;attempt=$null;previousDigest=$null;proofDigest=$null
                registryInstanceId='08ef25a7-defb-4c7a-ac83-26ba8f994fc0'
                scopeDigest='ec59ce507d1e0bb29cf94a9c8d1571367aca0549ddf60305031f7d6b409aefce'}}
        $Records[$Publication]=$Anchor
        $Fixture=@{holders=$null;wrongEvent=$false;admissions=0}
        function Read-Private {param($Path) $Records[$Path]}
        function Get-FileHash {param($LiteralPath,$Algorithm) [pscustomobject]@{Hash=$PriorHash}}
        function Test-Path {param($LiteralPath) $false}
        function Assert-Registry288RecoveredProfile {}
        function Assert-Volume {}
        function Assert-OnlyWriter {}
        function Admit-Source {$Fixture.admissions++}
        function New-FixtureRegistry {
            param($Id,$N,$Image,$Profile,$Role)
            $Suffix=$N.Replace('-','')
            $Name='/fortis-registry-successor-'+$Suffix
            $Status='created';$Restart='no';$Writable=$true
            $Cmd=@('python','-m','fortis_approvals.registry.local_candidate_read_service',
                '--owner-config','/run/fortis-registry-runtime/profile.json','--expected-profile-sha256',$Profile)
            if($Role -ceq 'source'){$Status='running';$Restart='unless-stopped'}
            if($Role -ceq 'preview'){$Status='running';$Name+='-preview';$Writable=$false;$Cmd+=@('--corrective-preview-sha',$SourceSha)}
            $Rows=@(
                @(('fortis-registry-state-e13b-'+$Suffix),'/run/fortis-registry-state',$Writable),
                @(('fortis-registry-config-e13b-'+$Suffix),'/run/fortis-registry-runtime',$false),
                @(('fortis-registry-read-'+$Suffix),'/run/fortis-registry-read',$true),
                @(('fortis-registry-source-evidence-'+$Suffix),'/run/fortis-registry-source-evidence',$false),
                @(('fortis-registry-source-'+$Suffix),'/run/fortis-registry-source',$false),
                @('fortis-r7-maintenance-interlock','/run/r7-maintenance',$false))
            [pscustomobject]@{Id=$Id;Name=$Name;Image=$Image;Path='python';Args=@($Cmd[1..($Cmd.Count-1)])
                State=[pscustomobject]@{Status=$Status;StartedAt='0001-01-01T00:00:00Z'}
                Config=[pscustomobject]@{User='20002:20002';Cmd=$Cmd;Entrypoint=$null;Env=@('TEST=fixture')
                    Labels=[pscustomobject]@{'org.opencontainers.image.revision'=$SourceSha}}
                HostConfig=[pscustomobject]@{NetworkMode='none';RestartPolicy=[pscustomobject]@{Name=$Restart;MaximumRetryCount=0}
                    Init=$true;ReadonlyRootfs=$true;Privileged=$false;CapAdd=$null;CapDrop=@('ALL')
                    SecurityOpt=@('no-new-privileges:true');PidsLimit=64;Memory=536870912}
                Mounts=@(foreach($Row in $Rows){[pscustomobject]@{Type='volume';Name=$Row[0]
                    Source=('/var/lib/docker/volumes/'+$Row[0]+'/_data');Destination=$Row[1];RW=$Row[2]}})}
        }
        $Old=New-FixtureRegistry $OldId $OldNonce $OldImage $OldProfile 'source'
        $Writer=New-FixtureRegistry ('b'*64) $Nonce ('sha256:'+('c'*64)) ('d'*64) 'writer'
        $Preview=New-FixtureRegistry ('f'*64) $Nonce $Writer.Image ('d'*64) 'preview'
        $Gateway=[pscustomobject]@{Id=$Source.runtime.pilotId;Name='/gateway-fixture';Mounts=@()
            State=[pscustomobject]@{Status='running'}}
        $Fixture.holders=@($Old,$Writer,$Preview,$Gateway)
        function Container {param($Identity)
            $Match=@($Fixture.holders|Where-Object{$_.Id -ceq $Identity -or $_.Name -ceq ('/'+$Identity)})
            if($Match.Count -ne 1){throw 'FIXTURE_CONTAINER_UNKNOWN'}
            $Match[0]
        }
        function Docker-Text {($Fixture.holders.Id -join "`n")}
        function Inspect-Containers {param($Ids) $Fixture.holders}
        function Python-Code {
            param($Arguments,$Code,$InputText)
            if($Arguments[-1] -ceq $Old.Id){return '{"fixture":true}'}
            if($Arguments[-1] -cne $Preview.Id){throw 'FIXTURE_WRONG_EXEC'}
            $Event=if($Fixture.wrongEvent){'0'*64}else{'b3e80ca0f3bd1ae7f7fbcc15bed3942826af931dc025f9ec86f11534b368f634'}
            return (ConvertTo-Json -Compress -Depth 6 @{
                source=[ordered]@{eventDigest=$Event;instanceId=$Anchor.record.registryInstanceId;scopeDigest=$Anchor.record.scopeDigest
                    sourceRevision=2;sourceCursor='5ab74dbd5f4f743b325bafd2444486180c3cdf7f'}
                target=[ordered]@{sourceRevision=3;sourceCursor=$SourceSha}})
        }
        $Pair=Read-CorrectiveRegistryPair $Source
        if($Pair.targetRegistryId -cne $Writer.Id -or $Pair.targetPreviewId -cne $Preview.Id -or
           $Pair.sourceRegistryId -cne $OldId -or $Fixture.admissions -ne 1){
            throw 'RELEASE_CORRECTIVE_PAIR_SELFTEST_FAILED'
        }
        $CorrectiveRegistryProfileSha256='0'*64
        $Rejected=$false
        try{$null=Read-CorrectiveRegistryPair $Source}
        catch{if($_.Exception.Message -cne 'RELEASE_CORRECTIVE_REGISTRY_CONTAINER_CHANGED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_CORRECTIVE_PAIR_SELFTEST_FAILED'}
        $CorrectiveRegistryProfileSha256='d'*64
        $Fixture.wrongEvent=$true
        $Rejected=$false
        try{$null=Read-CorrectiveRegistryPair $Source}
        catch{if($_.Exception.Message -cne 'RELEASE_CORRECTIVE_REGISTRY_PAIR_CHANGED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_CORRECTIVE_PAIR_SELFTEST_FAILED'}
        $Fixture.wrongEvent=$false
        $Preview.Mounts[0].RW=$true
        $Rejected=$false
        try{$null=Read-CorrectiveRegistryPair $Source}
        catch{if($_.Exception.Message -cne 'RELEASE_CORRECTIVE_REGISTRY_MOUNT_CHANGED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_CORRECTIVE_PAIR_SELFTEST_FAILED'}
        $Preview.Mounts[0].RW=$false
        $Writer.State.Status='running'
        $Rejected=$false
        try{$null=Read-CorrectiveRegistryPair $Source}
        catch{if($_.Exception.Message -cne 'RELEASE_CORRECTIVE_REGISTRY_CONTAINER_CHANGED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_CORRECTIVE_PAIR_SELFTEST_FAILED'}
        $Writer.State.Status='created'
        $Anchor.record.sequence=1
        $Rejected=$false
        try{$null=Read-CorrectiveRegistryPair $Source}
        catch{if($_.Exception.Message -cne 'RELEASE_CORRECTIVE_288_ANCHOR_CHANGED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_CORRECTIVE_PAIR_SELFTEST_FAILED'}
        $Anchor.record.sequence=0
        $Fixture.holders+=@([pscustomobject]@{Id=('9'*64);Name='/extra';Mounts=@(
            [pscustomobject]@{Type='bind';Source=($Preview.Mounts[2].Source+'/alias');RW=$false})})
        $Rejected=$false
        try{$null=Read-CorrectiveRegistryPair $Source}
        catch{if($_.Exception.Message -cne 'RELEASE_CORRECTIVE_REGISTRY_TARGET_HOLDER_CHANGED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_CORRECTIVE_PAIR_SELFTEST_FAILED'}
        Write-Host 'FORTIS_CORRECTIVE_REGISTRY_PAIR_SELFTEST_PASS'

        # Same Check binding, actual switch/Return/completion functions.
        # Only Docker, packaged readback and protected filesystem are mocked.
        $Fixture.holders=@($Old,$Writer,$Preview,$Gateway)
        $Fixture.events=[Collections.Generic.List[string]]::new()
        $Fixture.markerPresent=$false;$Fixture.active=$false;$Fixture.failFrozen=$false;$Fixture.loseAck=$false
        $Fixture.badHash=$false
        $AttemptPointer=Join-Path $ReleaseBase 'attempt.json'
        $PrimaryPointer=Join-Path $ReleaseBase 'primary.json'
        $CheckPath=Join-Path $ReleaseBase 'check\record.json'
        $script:RecordPath=Join-Path $ReleaseBase 'attempt\record.json'
        $Source.runtime|Add-Member -NotePropertyName stateVolume -NotePropertyValue 'source-state'
        $Target=[pscustomobject]@{Id=('7'*64);Name='/target-gateway';Mounts=@()
            State=[pscustomobject]@{Status='running'}}
        $Delivery=[pscustomobject]@{sourceDelivery=[pscustomobject]@{interlockDigest=$Digest}}
        $Runtime=[ordered]@{pilotId='';pilotName='target-gateway';image=('sha256:'+('8'*64));stateVolume='target-state'
            registryReleaseNonce=$Nonce;registryProfileDigest=('6'*64);releaseNonce=$Nonce;registryDelivery=$Delivery}
        $Receipt=[pscustomobject]@{witness='fixture'}
        $Records[$AttemptPointer]=[pscustomobject]@{record=$script:RecordPath}
        $Records[$CheckPath]=[pscustomobject]@{schema='fortis-extension-image-check-v1';phase='Ready'
            binding=[pscustomobject]@{correctivePair=$Pair;sourceHash=$SourceHash;image=$Runtime.image
                registryReleaseNonce=$Nonce;registryProfileDigest=$Runtime.registryProfileDigest;sourceSha=$SourceSha
                currentPointerHash=$PriorHash;primaryPointerHash=$PriorHash;backupPointerHash=$PriorHash
                configurationDigest=('5'*64);registryDelivery=$Delivery}
            sourceReceipt=$Receipt}
        $script:R=[ordered]@{phase='Prepared';activated=$false;source=$Source;runtime=$Runtime
            configurationDigest=('5'*64);correctivePair=$Pair;correctiveCheckRecord=$CheckPath
            correctiveCheckHash=$PriorHash;sourceReceipt=$Receipt;probesPassed=$false;probes='[]'}
        function Get-FileHash {param($LiteralPath,$Algorithm)
            [pscustomobject]@{Hash=$(if($Fixture.badHash -and $LiteralPath -ceq $CheckPath){'0'*64}else{$PriorHash})}}
        function Assert-Release-Production {}
        function Assert-SourceUnchanged {if($Gateway.State.Status -cne 'exited'){throw 'FIXTURE_SOURCE_GATEWAY_RUNNING'}}
        function Admit {param($C,$P,[switch]$AllowUnhealthy)
            if($C.Id -ceq $Gateway.Id -and $Old.State.Status -cne 'running'){throw 'FIXTURE_OLD_PEER_DOWN'}
            if($C.Id -ceq $Target.Id -and $Writer.State.Status -cne 'running'){throw 'FIXTURE_TARGET_PEER_DOWN'}}
        function Admit-ReturnCandidate {param($C,$P) Admit $C $P}
        function Step {param($Name)}
        function Wait-Healthy {param($Id) if((Container $Id).State.Status -cne 'running'){throw 'FIXTURE_NOT_RUNNING'}}
        function Save {param([switch]$FlushToDisk) if(-not $FlushToDisk){throw 'FIXTURE_DURABLE_SAVE_REQUIRED'}}
        function Image-CLI {param($Command,$InputText,$StateVolume)
            [pscustomobject]@{active=$Fixture.active;markerPresent=$Fixture.markerPresent}}
        function Image-RegistrySuccessor-Preflight {param($ImageId,$ReleaseNonce,$InterlockDigest,$IncumbentVolume) $Delivery}
        function Python-Code {
            param($Arguments,$Code,$InputText)
            $InputObject=ConvertFrom-Json $InputText
            if($Code -match 'CORRECTIVE_LISTENER_AVAILABLE'){
                if((Container $Arguments[-1]).State.Status -cne 'running'){throw 'FIXTURE_LISTENER_NOT_RUNNING'}
                return 'CORRECTIVE_LISTENER_AVAILABLE'
            }
            if($Code -match 'frozen_corrective_checkpoint'){
                if($InputObject.revision -eq 2 -and $Fixture.failFrozen){
                    return (ConvertTo-Json -Compress @{eventDigest='bad'})
                }
                $Checkpoint=if($InputObject.revision -eq 2){$Pair.checkpoints.source}else{$Pair.checkpoints.target}
                return (ConvertTo-Json -Compress -Depth 10 $Checkpoint)
            }
            if($Arguments[-1] -ceq $Old.Id){
                return (ConvertTo-Json -Compress -Depth 10 @{view=$Pair.checkpoints.source})
            }
            throw 'FIXTURE_WRONG_EXEC'
        }
        function Docker-Text {
            param($Arguments)
            if(($Arguments -join ' ') -ceq 'ps -aq --no-trunc'){return ($Fixture.holders.Id -join "`n")}
            if(($Arguments -join ' ') -ceq 'ps -a --format {{.Names}}'){
                return (($Fixture.holders|ForEach-Object{$_.Name.TrimStart('/')}) -join "`n")}
            if(($Arguments -join ' ') -ceq 'volume ls --format {{.Name}}'){return 'target-state'}
            $C=Container $Arguments[-1]
            switch($Arguments[0]){
                'stop' {$C.State.Status='exited'}
                'start' {
                    if(($C.Id -ceq $Writer.Id -and ($Old.State.Status -ne 'exited' -or $Preview.State.Status -ne 'exited' -or $Gateway.State.Status -ne 'exited')) -or
                       ($C.Id -ceq $Old.Id -and $Writer.State.Status -eq 'running') -or
                       ($C.Id -ceq $Gateway.Id -and $Old.State.Status -ne 'running')){
                        throw 'FIXTURE_WRITER_OVERLAP'
                    }
                    $C.State.Status='running'
                }
                'update' {
                    if(-not $Fixture.active -or $C.Id -cne $Writer.Id){throw 'FIXTURE_PREACTIVATION_RESTART'}
                    $C.HostConfig.RestartPolicy.Name='unless-stopped'
                }
                default {throw 'FIXTURE_UNEXPECTED_DOCKER'}
            }
            $Fixture.events.Add($Arguments[0]+':'+$C.Id)
            if($Fixture.loseAck -and $Arguments[0] -ceq 'start' -and $C.Id -ceq $Writer.Id){
                throw 'FIXTURE_START_ACK_LOST'
            }
            return $C.Id
        }
        function Assert-Effects {param([string[]]$Expected)
            if(($Fixture.events -join ',') -cne ($Expected -join ',')){throw 'RELEASE_CORRECTIVE_SWITCH_SELFTEST_EFFECT_ORDER'}}
        $Gateway.State.Status='exited'
        Switch-CorrectiveRegistryPair
        Assert-Effects @(('stop:'+$Old.Id),('stop:'+$Preview.Id),('start:'+$Writer.Id))
        $Fixture.holders+=@($Target);$Runtime.pilotId=$Target.Id
        $Fixture.events.Clear()
        Return-Source
        Assert-Effects @(('stop:'+$Target.Id),('stop:'+$Writer.Id),('start:'+$Old.Id),('start:'+$Gateway.Id))
        if($script:R.phase -cne 'Returned'){throw 'RELEASE_CORRECTIVE_SWITCH_SELFTEST_RETURN_NOT_SAVED'}

        # Frozen-source mismatch: no new writer, then separately reviewed
        # exact Return from the partial stop once the readback is valid.
        $Fixture.holders=@($Old,$Writer,$Preview,$Gateway)
        $Runtime.pilotId='';$script:R.phase='Prepared'
        $Gateway.State.Status='exited';$Writer.State.Status='created';$Preview.State.Status='running'
        $Fixture.events.Clear();$Fixture.failFrozen=$true
        $Rejected=$false
        try{Switch-CorrectiveRegistryPair}
        catch{if($_.Exception.Message -cne 'RELEASE_CORRECTIVE_FROZEN_SOURCE_CHANGED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_CORRECTIVE_SWITCH_SELFTEST_FAILED'}
        Assert-Effects @(('stop:'+$Old.Id))
        $Fixture.failFrozen=$false;$Fixture.events.Clear()
        Return-Source
        Assert-Effects @(('stop:'+$Preview.Id),('start:'+$Old.Id),('start:'+$Gateway.Id))

        # Lost start ACK: do not replay start; actual observed running
        # writer is stopped by Return before restoring old pair.
        $script:R.phase='Prepared';$Gateway.State.Status='exited';$Writer.State.Status='created';$Preview.State.Status='running'
        $Fixture.events.Clear();$Fixture.loseAck=$true
        $Rejected=$false
        try{Switch-CorrectiveRegistryPair}
        catch{if($_.Exception.Message -cne 'FIXTURE_START_ACK_LOST'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_CORRECTIVE_SWITCH_SELFTEST_FAILED'}
        Assert-Effects @(('stop:'+$Old.Id),('stop:'+$Preview.Id),('start:'+$Writer.Id))
        $Fixture.loseAck=$false;$Fixture.events.Clear()
        Return-Source
        Assert-Effects @(('stop:'+$Writer.Id),('start:'+$Old.Id),('start:'+$Gateway.Id))

        # Actual activation (including lost ACK) and malformed marker must
        # both deny stale Return before any Docker effect.
        $script:R.phase='Staged';$Gateway.State.Status='exited';$Old.State.Status='exited'
        $Writer.State.Status='running';$Preview.State.Status='exited';$Target.State.Status='running'
        $Fixture.holders+=@($Target);$Runtime.pilotId=$Target.Id
        $Fixture.events.Clear();$Fixture.markerPresent=$true
        foreach($Active in @($false,$true)){
            $Fixture.active=$Active
            $Rejected=$false
            try{Return-Source}
            catch{if($_.Exception.Message -cne 'RELEASE_ALREADY_ACTIVE_RETURN_REQUIRES_REVIEW'){throw};$Rejected=$true}
            if(-not $Rejected){throw 'RELEASE_CORRECTIVE_SWITCH_SELFTEST_FAILED'}
            Assert-Effects @()
        }
        $Fixture.badHash=$true
        $Rejected=$false
        try{Return-Source}
        catch{if($_.Exception.Message -cne 'RELEASE_CORRECTIVE_ATTEMPT_CHANGED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_CORRECTIVE_SWITCH_SELFTEST_FAILED'}
        $Fixture.badHash=$false
        Complete-CorrectiveRegistryPair $Pair
        Complete-CorrectiveRegistryPair $Pair
        Assert-Effects @(('update:'+$Writer.Id))
        Write-Host 'FORTIS_CORRECTIVE_SWITCH_RETURN_SELFTEST_PASS'

        $ConfirmWorkerQuiescent=$true
        $Fixture.activateCalls=0;$Fixture.probeCalls=0;$Fixture.loseActivation=$true;$Fixture.failPointer=$false
        $Fixture.active=$false;$Fixture.markerPresent=$false
        $Writer.HostConfig.RestartPolicy.Name='no'
        $script:R.phase='Created';$script:R.activated=$false;$script:R.probesPassed=$false
        $Fixture.events.Clear()
        function Complete-ActionCoreNetwork {param($C,$P) $C}
        function Running-CLI {
            param($Id,$Arguments,$InputText,[switch]$Root)
            if($Id -cne $Target.Id){throw 'FIXTURE_WRONG_GATEWAY'}
            switch($Arguments[0]){
                'gate-status' {return [pscustomobject]@{active=$Fixture.active;configurationDigest=$script:R.configurationDigest}}
                'catalog' {return [pscustomobject]@{configurationDigest=$script:R.configurationDigest;operations=@()}}
                'probe' {$Fixture.probeCalls++;return @{}}
                'activate' {
                    if(-not $Root -or $Fixture.active -or -not $script:R.probesPassed){throw 'FIXTURE_BAD_ACTIVATION'}
                    $Fixture.activateCalls++;$Fixture.active=$true;$Fixture.markerPresent=$true
                    if($Fixture.loseActivation){throw 'FIXTURE_ACTIVATION_ACK_LOST'}
                    return @{status='ACTIVATED'}
                }
                default {throw 'FIXTURE_WRONG_CLI'}
            }
        }
        function Repo-JSON {param($Code) [pscustomobject]@{configurationDigest=$script:R.configurationDigest}}
        function Read-GatewayNetworks {param($P) return}
        function Read-OwnerShellFlag {param($P) $false}
        function Write-ReleaseTiming {param($Name)}
        function Write-Private {
            param($Path,$Value,[switch]$FlushToDisk)
            if($Path -cne $Pointer -or -not $FlushToDisk -or -not $Fixture.active -or
               $script:R.phase -cne 'Complete' -or -not $script:R.activated -or
               $Writer.HostConfig.RestartPolicy.Name -cne 'unless-stopped'){
                throw 'FIXTURE_PREMATURE_POINTER'
            }
            if($Fixture.failPointer){throw 'FIXTURE_POINTER_ACK_LOST'}
            $Records[$Pointer]=$Value
        }
        $Rejected=$false
        try{$null=Resume-Target}
        catch{if($_.Exception.Message -cne 'FIXTURE_ACTIVATION_ACK_LOST'){throw};$Rejected=$true}
        if(-not $Rejected -or $script:R.activated -or -not $script:R.probesPassed){
            throw 'RELEASE_CORRECTIVE_SWITCH_SELFTEST_FAILED'
        }
        $Rejected=$false
        try{Return-Source}
        catch{if($_.Exception.Message -cne 'RELEASE_ALREADY_ACTIVE_RETURN_REQUIRES_REVIEW'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_CORRECTIVE_SWITCH_SELFTEST_FAILED'}
        Assert-Effects @()
        $Fixture.loseActivation=$false;$Fixture.failPointer=$true
        $Rejected=$false
        try{$null=Resume-Target}
        catch{if($_.Exception.Message -cne 'FIXTURE_POINTER_ACK_LOST'){throw};$Rejected=$true}
        if(-not $Rejected -or $script:R.phase -cne 'Complete' -or
           (Read-Private $Pointer).record -cne $SourcePath){throw 'RELEASE_CORRECTIVE_SWITCH_SELFTEST_FAILED'}
        $Fixture.failPointer=$false
        Resume-Target
        if((Read-Private $Pointer).record -cne $script:RecordPath -or
           $Fixture.activateCalls -ne 1 -or $Fixture.probeCalls -ne 1){
            throw 'RELEASE_CORRECTIVE_SWITCH_SELFTEST_FAILED'
        }
        Assert-Effects @('update:'+$Writer.Id)
        Write-Host 'FORTIS_CORRECTIVE_ACTIVATION_RESUME_SELFTEST_PASS'
    }} finally {
        if($NonceVariable){$script:RegistryBoundReleaseNonce=$PreviousNonce}
        else{Remove-Variable -Name RegistryBoundReleaseNonce -Scope Script -ErrorAction SilentlyContinue}
        if($RVariable){$script:R=$PreviousR}else{Remove-Variable -Name R -Scope Script -ErrorAction SilentlyContinue}
        if($PathVariable){$script:RecordPath=$PreviousPath}else{Remove-Variable -Name RecordPath -Scope Script -ErrorAction SilentlyContinue}
    }
}

if($Action -ne 'BackupCleanup' -and $ForwardParameters.ContainsKey('BackupIds')){throw 'BACKUP_CLEANUP_ARGUMENT_ACTION_INVALID'}
if($Action -ne 'ReleaseStateCleanup' -and $ForwardParameters.ContainsKey('RunIds')){throw 'RELEASE_STATE_CLEANUP_ARGUMENT_ACTION_INVALID'}
if($Action -cnotin @('BackupCleanup','ReleaseStateCleanup') -and $ForwardParameters.ContainsKey('Preview')){throw 'BACKUP_CLEANUP_ARGUMENT_ACTION_INVALID'}
if($Action -eq 'SelfTest'){
    # CI and owner SelfTest must exercise the same strict variable semantics.
    # This is a fixture-only path; no Docker/Primary release is attempted.
    Set-StrictMode -Version Latest
    # Exercise the same named bounded-wait argument that the heavy Docker
    # receipt and clone helpers use, without accessing Docker or Core state.
    $WaitFixture='fortis-bounded-wait-selftest'
    $WaitEcho=Private-Process @('-NoProfile','-Command','[Console]::Write([Console]::In.ReadToEnd())') $WaitFixture (Join-Path $PSHOME 'powershell.exe') -WaitTimeoutMs 900000
    if($WaitEcho -cne $WaitFixture){throw 'RELEASE_STATE_HELPER_WAIT_SELFTEST_FAILED'}
    Write-Host 'FORTIS_RELEASE_STATE_HELPER_WAIT_SELFTEST_PASS'
    Assert-BoundedReleaseJsonSelfTest
    Assert-OptionalActionCoreSelfTest
    Assert-Emergency-Promote-BindingSelfTest
    Assert-RegistryReturnSelfTest
    Assert-Registry288RecoveredProfileSelfTest
    Assert-CorrectiveRegistryPairSelfTest
    Assert-PrimaryReturnedRegistrySourceSelfTest
    Assert-BackupCleanupSelectionSelfTest
    Assert-ContainerInventorySelfTest
    Assert-CheckedImagePreflightSelfTest
    Assert-SuccessorPublicationSelfTest
    Assert-SuccessorLatestPublicationSelfTest
    Assert-SuccessorRuntimeDeliverySelfTest
    Assert-SuccessorRuntimePublicationSelfTest
    Assert-SuccessorBootstrapSeedSelfTest
    Assert-BootstrapFrozenCheckSelfTest
    Assert-BootstrapFrozenPairSelfTest
    Assert-BootstrapPhysicalPairSelfTest
    Assert-BootstrapPhasePublicationSelfTest
    Assert-BootstrapPreparedAttemptSelfTest
    Assert-BootstrapFinalMaterialSelfTest
    Assert-BootstrapReceiverSelfTest
    Assert-BootstrapGatewayLifecycleSelfTest
    Assert-BootstrapPostLifecycleSelfTest
    Assert-BootstrapPostLifecycleSelfTest -Ordinary
    Assert-OrdinaryBeginSelfTest
    Assert-OrdinaryReturnSelfTest
    Assert-OrdinaryCheckResumeSelfTest
    Assert-SuccessorCheckStartSelfTest
    Assert-SuccessorCheckSealSelfTest
    Assert-SuccessorLatestCheckSelfTest
    Assert-ReleaseTimingSelfTest
    Assert-ReleaseStateCleanupSelectionSelfTest
    Assert-FormerPrimaryRetirementSelfTest
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
    $CdOldRecord='{"schema":1}' | ConvertFrom-Json
    $CdNewRecord='{"cdReadRepositories":"fortis-approvals,rd-graphs"}' | ConvertFrom-Json
    $CdBadRecord='{"cdReadRepositories":"rd-graphs,rd-graphs"}' | ConvertFrom-Json
    if((Read-CdReadRepositories $CdOldRecord) -cne '' -or
       (Read-CdReadRepositories $CdNewRecord) -cne 'fortis-approvals,rd-graphs'){
        throw 'RELEASE_CD_READ_RECORD_COMPATIBILITY_SELFTEST_FAILED'
    }
    $CdRejected=$false
    try{$null=Read-CdReadRepositories $CdBadRecord}
    catch{if($_.Exception.Message -cne 'RELEASE_CD_READ_RECORD_INVALID'){throw};$CdRejected=$true}
    if(-not $CdRejected){throw 'RELEASE_CD_READ_RECORD_VALIDATION_SELFTEST_FAILED'}
    $CdForward=@(Forward-NativeParameters @{CdReadRepositories='fortis-approvals'})
    if($CdForward.Count -ne 2 -or $CdForward -cnotcontains '-CdReadRepositories' -or
       $CdForward[1] -cne 'fortis-approvals'){
        throw 'RELEASE_CD_READ_FLAG_FORWARDING_SELFTEST_FAILED'
    }
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
    # No host effect: validate exact Registry nonce-derived reader volume,
    # pair, digest and flag forwarding inside the existing SelfTest action.
    $RegistryOld='{"schema":1}'|ConvertFrom-Json
    $RegistryNonce='11111111-1111-4111-8111-111111111111'
    $RegistryVolume='fortis-r7-registry-reader-'+$RegistryNonce.Replace('-','')
    $RegistryGood=('{"registryReaderVolume":"'+$RegistryVolume+'","registrySocketVolume":"fortis-registry-read","registryReleaseNonce":"'+$RegistryNonce+'","registryProfileDigest":"'+('a'*64)+'"}')|ConvertFrom-Json
    $RegistryOldValues=Read-RegistryMountBinding $RegistryOld
    $RegistryGoodValues=Read-RegistryMountBinding $RegistryGood
    if($RegistryOldValues.readerVolume -cne '' -or
       $RegistryGoodValues.readerVolume -cne $RegistryVolume -or
       $RegistryGoodValues.socketVolume -cne 'fortis-registry-read' -or
       $RegistryGoodValues.releaseNonce -cne $RegistryNonce -or
       $RegistryGoodValues.profileDigest -cne ('a'*64)){
        throw 'RELEASE_REGISTRY_RECORD_SELFTEST_FAILED'
    }
    foreach($Bad in @(
        '{"registryReaderVolume":"fortis-r7-registry-reader"}',
        ('{"registryReaderVolume":"'+$RegistryVolume+'","registrySocketVolume":"fortis-registry-read","registryReleaseNonce":"22222222-2222-4222-8222-222222222222","registryProfileDigest":"'+('a'*64)+'"}'),
        ('{"registryReaderVolume":"'+$RegistryVolume+'","registrySocketVolume":"fortis-registry-read","registryReleaseNonce":"'+$RegistryNonce+'","registryProfileDigest":"NOT_HASH"}'),
        '{"registryReaderVolume":"/tmp/owner","registrySocketVolume":"fortis-registry-read"}'
    )){
        $Rejected=$false
        try{$null=Read-RegistryMountBinding (ConvertFrom-Json -InputObject $Bad)}
        catch{if($_.Exception.Message -cne 'RELEASE_REGISTRY_RECORD_INVALID'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'RELEASE_REGISTRY_RECORD_SELFTEST_FAILED'}
    }
    $RegistryForwarded=@(Forward-NativeParameters @{EnableRegistryMount=([switch]$true);RegistryReleaseNonce=$RegistryNonce;RegistryExpectedSourceDigest=('a'*64)})
    if($RegistryForwarded -cnotcontains '-EnableRegistryMount' -or
       $RegistryForwarded -cnotcontains '-RegistryReleaseNonce' -or
       $RegistryForwarded -cnotcontains '-RegistryExpectedSourceDigest' -or
       $RegistryForwarded -cnotcontains ('a'*64) -or
       $RegistryForwarded -cnotcontains $RegistryNonce){
        throw 'RELEASE_REGISTRY_FLAG_FORWARDING_SELFTEST_FAILED'
    }
    # Pure PowerShell 5.1 negative cases: exercise the real history validator,
    # not a Python grep of controller source; no Docker or owner record effects.
    $SavedRegistryInput=$RegistryReleaseNonce
    try {
        $RegistryReleaseNonce=$RegistryNonce
        Initialize-RegistryReleaseBinding -Enabled $true -RequestedNonce $RegistryReleaseNonce
        if($RegistryReleaseNonce -cne $RegistryNonce -or
           $script:RegistryBoundReleaseNonce -cne $RegistryNonce -or
           $script:RegistryReaderVolume -cne $RegistryVolume -or
           $script:RegistrySocketVolume -cne 'fortis-registry-read'){
            throw 'RELEASE_REGISTRY_NONCE_SCOPE_SELFTEST_FAILED'
        }
        Assert-Registry-HistoryRecord -Record ('{"schema":"fortis-extension-release-v1","runtime":{}}'|ConvertFrom-Json) -Nonce $RegistryReleaseNonce
        Initialize-RegistryReleaseBinding -Enabled $false -RequestedNonce $RegistryReleaseNonce
        if($RegistryReleaseNonce -cne $RegistryNonce -or $script:RegistryBoundReleaseNonce -cne '' -or
           $script:RegistryReaderVolume -cne '' -or $script:RegistrySocketVolume -cne ''){
            throw 'RELEASE_REGISTRY_NONCE_SCOPE_SELFTEST_FAILED'
        }
    } finally {$RegistryReleaseNonce=$SavedRegistryInput}
    Write-Host 'FORTIS_REGISTRY_NONCE_SCOPE_SELFTEST_PASS'
    $HistoryCheck=('{"schema":"fortis-extension-image-check-v1","phase":"Ready","binding":{"registryReleaseNonce":"'+$RegistryNonce+'"}}')|ConvertFrom-Json
    $HistoryRelease=('{"schema":"fortis-extension-release-v1","runtime":{"registryReleaseNonce":"'+$RegistryNonce+'"}}')|ConvertFrom-Json
    Assert-Registry-HistoryRecord -Record $HistoryCheck -Nonce $RegistryNonce -AllowOriginalCheck $true
    Assert-Registry-HistoryRecord -Record ('{"schema":"fortis-extension-release-v1","runtime":{}}'|ConvertFrom-Json) -Nonce $RegistryNonce
    foreach($Case in @(
        @{record=$HistoryCheck;allow=$false;code='RELEASE_REGISTRY_NONCE_REUSE_DENIED'},
        @{record=$HistoryRelease;allow=$true;code='RELEASE_REGISTRY_NONCE_REUSE_DENIED'},
        @{record=('{"schema":"fortis-extension-image-check-v1","phase":"Ready"}'|ConvertFrom-Json);allow=$true;code='RELEASE_REGISTRY_HISTORY_RECORD_INVALID'},
        @{record=('{"schema":"fortis-extension-image-check-v1","phase":"Ready","binding":{"registryReleaseNonce":"not-a-nonce"}}'|ConvertFrom-Json);allow=$true;code='RELEASE_REGISTRY_HISTORY_RECORD_INVALID'},
        @{record=('{"schema":"fortis-unknown","runtime":{}}'|ConvertFrom-Json);allow=$false;code='RELEASE_REGISTRY_HISTORY_RECORD_INVALID'}
    )){
        $HistoryRejected=$false
        try{Assert-Registry-HistoryRecord -Record $Case.record -Nonce $RegistryNonce -AllowOriginalCheck ([bool]$Case.allow)}
        catch{if($_.Exception.Message -cne $Case.code){throw};$HistoryRejected=$true}
        if(-not $HistoryRejected){throw 'RELEASE_REGISTRY_NONCE_HISTORY_SELFTEST_FAILED'}
    }
    $MachineOld='{"schema":1}'|ConvertFrom-Json
    $MachineGood=('{"machinePowerShellVolume":"fortis-r7-machine-powershell","machinePowerShellDigest":"'+('a'*64)+'"}')|ConvertFrom-Json
    $MachineBad='{"machinePowerShellVolume":"../../owner"}'|ConvertFrom-Json
    if((Read-MachinePowerShellVolume $MachineOld) -cne '' -or
       (Read-MachinePowerShellDigest $MachineOld) -cne '' -or
       (Read-MachinePowerShellVolume $MachineGood) -cne 'fortis-r7-machine-powershell' -or
       (Read-MachinePowerShellDigest $MachineGood) -cne ('a'*64)){
        throw 'RELEASE_MACHINE_POWERSHELL_RECORD_SELFTEST_FAILED'
    }
    $MachineRejected=$false
    try{$null=Read-MachinePowerShellVolume $MachineBad}
    catch{if($_.Exception.Message -cne 'RELEASE_MACHINE_POWERSHELL_RECORD_INVALID'){throw};$MachineRejected=$true}
    if(-not $MachineRejected){throw 'RELEASE_MACHINE_POWERSHELL_RECORD_SELFTEST_FAILED'}
    $MachineRejected=$false
    try{$null=Read-MachinePowerShellDigest ('{"machinePowerShellVolume":"fortis-r7-machine-powershell"}'|ConvertFrom-Json)}
    catch{if($_.Exception.Message -cne 'RELEASE_MACHINE_POWERSHELL_DIGEST_MISSING'){throw};$MachineRejected=$true}
    if(-not $MachineRejected){throw 'RELEASE_MACHINE_POWERSHELL_RECORD_SELFTEST_FAILED'}
    $MachineFlag=@(Forward-NativeParameters @{EnableMachinePowerShell=([switch]$true)})
    if($MachineFlag.Count -ne 1 -or $MachineFlag[0] -cne '-EnableMachinePowerShell'){
        throw 'RELEASE_MACHINE_POWERSHELL_FLAG_FORWARDING_FAILED'
    }
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
    $ObservatoryFlag=@(Forward-NativeParameters @{EnableObservatoryNetwork=([switch]$true)})
    if($ObservatoryFlag.Count -ne 1 -or $ObservatoryFlag[0] -cne '-EnableObservatoryNetwork'){throw 'RELEASE_OBSERVATORY_FLAG_FORWARDING_SELFTEST_FAILED'}
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
    $ReceiptBefore='{"sha256":{"approvals.sqlite":"before","owner.sqlite":"same","private-path":"before"}}'|ConvertFrom-Json
    $ReceiptAfter='{"sha256":{"approvals.sqlite":"after","owner.sqlite":"same","native-git/workflow.sqlite":"new","private-path":"after"}}'|ConvertFrom-Json
    $UnknownChange='{"sha256":{"approvals.sqlite":"before","owner.sqlite":"same","private-path":"after"}}'|ConvertFrom-Json
    if((Get-Checked-Source-Changes $ReceiptBefore $ReceiptAfter) -cne 'CORE,WORKFLOW' -or
       (Get-Checked-Source-Changes $ReceiptBefore $UnknownChange) -cne 'OTHER'){
        throw 'RELEASE_CHECKED_SOURCE_DIAGNOSTIC_SELFTEST_FAILED'
    }
    Write-Host 'FORTIS_INTEGRATIONS_SELFTEST_PASS';return
}
function Open-ReleaseControllerLock {
    $LockPath=Join-Path $ReleaseBase 'controller.lock'
    if((Test-Path -LiteralPath $LockPath) -and ((Get-Item -LiteralPath $LockPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'RELEASE_LOCK_REPARSE_POINT_DENIED'}
    try{return [IO.File]::Open($LockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch{throw 'RELEASE_CONTROLLER_ALREADY_RUNNING_OR_LOCK_UNAVAILABLE'}
}
if($Action -cin @('BackupCleanup','ReleaseStateCleanup')){
    $SelectionKey=if($Action -ceq 'BackupCleanup'){'BackupIds'}else{'RunIds'}
    $ArgumentError=if($Action -ceq 'BackupCleanup'){'BACKUP_CLEANUP_ARGUMENTS_INVALID'}else{'RELEASE_STATE_CLEANUP_ARGUMENTS_INVALID'}
    foreach($Key in $ForwardParameters.Keys){
        if($Key -notin @('Action',$SelectionKey,'Preview','SourceSha')){throw $ArgumentError}
    }
    $null=Get-BackupCleanupIds $ForwardParameters[$SelectionKey]
    if($SourceSha -cnotmatch '^[0-9a-f]{40}$'){throw 'RELEASE_APPROVED_SOURCE_SHA_REQUIRED'}
    $Git=(Get-Command git.exe -CommandType Application).Source
    if((Private-Process @('-C',$SourceRoot,'status','--porcelain') '' $Git)){throw 'RELEASE_WINDOWS_SOURCE_DIRTY'}
    if((Private-Process @('-C',$SourceRoot,'branch','--show-current') '' $Git) -cne 'main'){throw 'RELEASE_WINDOWS_MAIN_REQUIRED'}
    if((Private-Process @('-C',$SourceRoot,'rev-parse','HEAD') '' $Git) -cne $SourceSha){throw 'RELEASE_WINDOWS_SHA_MISMATCH'}
    Assert-DirectoryAcl $ReleaseBase
    $ControllerLock=Open-ReleaseControllerLock
    try {
        if($Action -ceq 'BackupCleanup'){Backup-Cleanup $BackupIds -PreviewOnly:$Preview}
        else{Release-State-Cleanup $RunIds -PreviewOnly:$Preview}
    } finally{$ControllerLock.Dispose();Write-ReleaseTiming 'ACTION_END'}
    return
}
if(-not (Test-Path -LiteralPath $ReleaseBase)){Protect-Directory $ReleaseBase}else{Assert-DirectoryAcl $ReleaseBase}
# Owner-local convenience only. All effects still pass the SAME protected
# Check / checked-image Apply / Backup / Promote controller state machine.
# Never turn a Core UNCERTAIN or CLAIMED job into a retry or completion.
$script:AutoCheckPointer=Join-Path $ReleaseBase 'auto-check.json'
$script:AutoConfigText=$null;$script:AutoProbeText=$null
if(($Bootstrap289 -or $BootstrapRegistryImage -or $BootstrapRegistryProfileSha256 -or $BootstrapReviewSha256 -or $BootstrapEvidenceSha256 -or $BootstrapReviewProofRecord) -and
   ($Auto -or $Action -cnotin @('Check','Apply') -or $AttemptRecord)){
    throw 'RELEASE_SUCCESSOR_BOOTSTRAP_EXACT_CHECK_REQUIRED'
}
if(($Corrective288 -or $CorrectiveRegistryImage -or $CorrectiveRegistryProfileSha256) -and
   ($Auto -or $Action -cnotin @('Check','Apply') -or $AttemptRecord)){
    throw 'RELEASE_CORRECTIVE_288_EXPLICIT_CHECK_REQUIRED'
}
if($Auto){
    if($Action -cnotin @('Check','Apply','Backup','Promote') -or
        $Config -or $Probes -or $Image -or $CheckedImageRecord -or $SourceSha -or
        $Build -or $Pull -or $CurrentRecord -or $AttemptRecord -or
        $PreserveUncertainRequests -or $PreserveClaimedJobs -or $PreserveApprovedRequest -or $AllowUncertainGrowth -or
        $EnableDynamicGitHubRepositories -or $EnableOwnerShell -or $EnableActionCoreNetwork -or $EnableObservatoryNetwork -or
        $CiControlRepositories -or $CdReadRepositories -or
        $ConfirmWorkerQuiescent -or $EmergencyRescueImage -or
        $EmergencyRescueArchiveSha256 -or $AcceptUnverifiedRestore -or
        $VaultVolume -cne 'fortis-review-secrets' -or $EnablePublisherMount -or $EnableMachinePowerShell -or
        $EnableRegistryMount -or $RegistryReleaseNonce -or $RegistryExpectedSourceDigest){
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
    Write-ReleaseTiming 'OWNER_QUIESCENCE_BEGIN'
    $OwnerQuiescence=Read-Host 'Independently verified no active workers? Type QUIESCENT'
    Write-ReleaseTiming 'OWNER_QUIESCENCE_END'
    if($OwnerQuiescence -cne 'QUIESCENT'){
        throw 'RELEASE_AUTO_QUIESCENCE_NOT_ATTESTED'
    }
    $ConfirmWorkerQuiescent=[switch]$true
    if($Action -eq 'Apply'){
        Write-ReleaseTiming 'OWNER_GO_BEGIN'
        $OwnerGo=Read-Host ('Apply checked Gateway image for '+$SourceSha+'? Type APPLY')
        Write-ReleaseTiming 'OWNER_GO_END'
        if($OwnerGo -cne 'APPLY'){throw 'RELEASE_AUTO_OWNER_GO_REQUIRED'}
    }
    if($Action -cin @('Backup','Promote')){
        Write-ReleaseTiming 'OWNER_GO_BEGIN'
        $OwnerGo=Read-Host ('Run protected '+$Action+'? Type '+$Action.ToUpperInvariant())
        Write-ReleaseTiming 'OWNER_GO_END'
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
# Exact image built by the owner RegistrySourceDigest action may be reused.
# This is a manual Registry-only Check, never Auto or an unpinned tag.
$script:RegistryPrebuiltCheck=([bool]$EnableRegistryMount -and $Action -ceq 'Check' -and
    -not $Auto -and -not $Build -and -not $Pull -and
    $Image -cmatch '^sha256:[0-9a-f]{64}$' -and $SourceSha -cmatch '^[0-9a-f]{40}$')
$ApprovedImageSource=($Build -or [bool]$CheckedImageRecord -or $script:RegistryPrebuiltCheck)
$OrdinaryPairRequested=[bool]($SuccessorRegistryImage -or $SuccessorRegistryProfileSha256)
if($OrdinaryPairRequested -and ((-not $script:RegistryPrebuiltCheck -and
   -not ($Action -ceq 'Apply' -and $CheckedImageRecord -and $EnableRegistryMount -and -not $Auto)) -or -not $ConfirmWorkerQuiescent -or
   $Bootstrap289 -or $Corrective288 -or $RegistryReturnContainerId -or $RegistryReturnNonce -or
   $AllowUncertainGrowth -or $EmergencyRequested -or $CurrentRecord -or $AttemptRecord -or
   $RegistryCrashRecovery -or $PreserveApprovedRequest -or $EnablePublisherMount -or
   $SuccessorRegistryImage -cnotmatch '^sha256:[0-9a-f]{64}$' -or
   $SuccessorRegistryProfileSha256 -cnotmatch '^[0-9a-f]{64}$')){
    throw 'RELEASE_SUCCESSOR_ORDINARY_EXACT_CHECK_REQUIRED'
}
if($Bootstrap289){
    if(-not $EnableRegistryMount -or
       (-not $script:RegistryPrebuiltCheck -and -not ($Action -ceq 'Apply' -and $CheckedImageRecord)) -or
       -not $ConfirmWorkerQuiescent -or $Corrective288 -or
       $RegistryReturnContainerId -or $RegistryReturnNonce -or $AllowUncertainGrowth -or
       $PreserveApprovedRequest -or $EmergencyRequested -or $CurrentRecord -or $AttemptRecord -or
       $RegistryCrashRecovery -or $EnablePublisherMount -or -not $BootstrapReviewProofRecord -or
       $BootstrapRegistryImage -cnotmatch '^sha256:[0-9a-f]{64}$' -or
       $BootstrapRegistryProfileSha256 -cnotmatch '^[0-9a-f]{64}$' -or
       $BootstrapReviewSha256 -cnotmatch '^[0-9a-f]{64}$' -or
       $BootstrapEvidenceSha256 -cnotmatch '^[0-9a-f]{64}$' -or $BootstrapReviewSha256 -ceq $BootstrapEvidenceSha256){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_EXACT_CHECK_REQUIRED'
    }
} elseif($BootstrapRegistryImage -or $BootstrapRegistryProfileSha256 -or $BootstrapReviewSha256 -or $BootstrapEvidenceSha256 -or $BootstrapReviewProofRecord){
    throw 'RELEASE_SUCCESSOR_BOOTSTRAP_EXACT_CHECK_REQUIRED'
}
if($Corrective288){
    if($Auto -or -not $EnableRegistryMount -or -not $ConfirmWorkerQuiescent -or
       $RegistryReturnContainerId -or $RegistryReturnNonce -or $AllowUncertainGrowth -or
       $PreserveApprovedRequest -or $EmergencyRequested -or $CurrentRecord -or $RegistryCrashRecovery -or
       (-not $script:RegistryPrebuiltCheck -and -not ($Action -ceq 'Apply' -and $CheckedImageRecord)) -or
       $CorrectiveRegistryImage -cnotmatch '^sha256:[0-9a-f]{64}$' -or
       $CorrectiveRegistryProfileSha256 -cnotmatch '^[0-9a-f]{64}$'){
        throw 'RELEASE_CORRECTIVE_288_EXPLICIT_CHECK_REQUIRED'
    }
} elseif($CorrectiveRegistryImage -or $CorrectiveRegistryProfileSha256){
    throw 'RELEASE_CORRECTIVE_288_EXPLICIT_CHECK_REQUIRED'
}
if($RegistryCrashRecovery -and
   ($Action -cnotin @('Check','Apply') -or -not $RegistryReturnContainerId -or -not $RegistryReturnNonce)){
    throw 'RELEASE_REGISTRY_CRASH_RECOVERY_REQUIRES_HANDOVER'
}
if($RegistryReturnContainerId -or $RegistryReturnNonce){
    if($Auto -or -not $EnableRegistryMount -or -not $ConfirmWorkerQuiescent -or
       $Action -cnotin @('Check','Apply') -or -not $ApprovedImageSource -or
       $Build -or $Pull -or $AttemptRecord -or $CurrentRecord -or $EmergencyRequested -or
       $AllowUncertainGrowth -or $PreserveApprovedRequest -or
       $RegistryReturnContainerId -cnotmatch '^[0-9a-f]{64}$' -or
       $RegistryReturnNonce -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
       $RegistryReturnNonce -ceq $RegistryReleaseNonce){
        throw 'RELEASE_REGISTRY_RETURN_REQUIRES_EXACT_CHECKED_HANDOVER'
    }
}
if($EnableActionCoreNetwork -and ($Auto -or $Action -cnotin @('Apply','Check') -or
    -not $ApprovedImageSource -or $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or
    $AttemptRecord -or $CurrentRecord)){
    throw 'RELEASE_ACTION_CORE_NETWORK_REQUIRES_APPROVED_IMAGE_BUILD'
}
if($EnableObservatoryNetwork -and ($Auto -or $Action -cnotin @('Apply','Check') -or
    -not $ApprovedImageSource -or $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or
    $AttemptRecord -or $CurrentRecord)){
    throw 'RELEASE_OBSERVATORY_NETWORK_REQUIRES_APPROVED_IMAGE_BUILD'
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
if($CdReadRepositories -and ($Auto -or $Action -cnotin @('Check','Apply') -or
    $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or $CurrentRecord -or $AttemptRecord -or
    -not $ConfirmWorkerQuiescent -or
    ($Action -eq 'Check' -and -not $Build) -or
    ($Action -eq 'Apply' -and (-not $CheckedImageRecord -or $Build)))) {
    throw 'RELEASE_CD_READ_REQUIRES_EXACT_OWNER_CHECKED_IMAGE'
}
if($CdReadRepositories -and ($CdReadRepositories -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}(,[A-Za-z0-9][A-Za-z0-9_.-]{0,99}){0,9}$' -or
    @($CdReadRepositories.Split(',')|Select-Object -Unique).Count -ne @($CdReadRepositories.Split(',')).Count)){
    throw 'RELEASE_CD_READ_REPOSITORIES_INVALID'
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
if($EnableMachinePowerShell -and ($Auto -or $Action -cnotin @('Check','Apply') -or
    $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or $AttemptRecord -or $CurrentRecord -or
    -not $ConfirmWorkerQuiescent -or
    ($Action -eq 'Check' -and -not $Build) -or
    ($Action -eq 'Apply' -and (-not $CheckedImageRecord -or $Build)))) {
    throw 'RELEASE_MACHINE_POWERSHELL_REQUIRES_EXACT_OWNER_CHECKED_IMAGE'
}
# Unlike default -Auto, Registry activation requires an explicit owner
# nonce, an exact owner source/image and a durable Check -> Apply binding.
if($EnableRegistryMount -and ($Auto -or $Action -cnotin @('Check','Apply') -or
    $SourceSha -cnotmatch '^[0-9a-f]{40}$' -or $AttemptRecord -or $CurrentRecord -or
    -not $ConfirmWorkerQuiescent -or
    $RegistryReleaseNonce -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
    $RegistryExpectedSourceDigest -cnotmatch '^[0-9a-f]{64}$' -or
    ($Action -eq 'Check' -and -not $Build -and -not $script:RegistryPrebuiltCheck) -or
    ($Action -eq 'Apply' -and (-not $CheckedImageRecord -or $Build)))){
    throw 'RELEASE_REGISTRY_REQUIRES_OWNER_CHECKED_IMAGE_AND_NONCE'
}
if(-not $EnableRegistryMount -and ($RegistryReleaseNonce -or $RegistryExpectedSourceDigest)){
    throw 'RELEASE_REGISTRY_NONCE_WITHOUT_EXPLICIT_ACTIVATION'
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
if($ConfirmWorkerQuiescent -and $Action -cnotin @('Check','Apply','Backup','Promote','Return')){
    throw 'RELEASE_QUIESCENCE_ACTION_INVALID'
}
if($Build -and ($Action -cnotin @('Apply','Check','RegistrySourceDigest') -or $AttemptRecord)){throw 'RELEASE_BUILD_ACTION_INVALID'}
if($Action -cin @('Backup','Promote') -and ($Config -or $Image -or $SourceSha -or $CurrentRecord -or $AttemptRecord -or $Pull -or $Build -or $Rotate -or $Service -or $CredentialName -or $Probes -or $EnableDynamicGitHubRepositories -or $EnableOwnerShell -or $EnableActionCoreNetwork -or $EnableObservatoryNetwork -or $EnableRegistryMount -or $RegistryReleaseNonce -or $RegistryExpectedSourceDigest -or $CiControlRepositories -or $CdReadRepositories -or $PreserveUncertainRequests -or $PreserveClaimedJobs -or $PreserveApprovedRequest -or $CheckedImageRecord -or $AllowUncertainGrowth)){throw 'PRIMARY_PROMOTION_ARGUMENTS_INVALID'}
# First owner-controlled image build for pre-seal source readback.
# It MUST NOT accept release arguments or silently activate Registry.
if($Action -eq 'RegistrySourceDigest' -and (
    -not $Build -or $Auto -or $Image -or $Config -or $CheckedImageRecord -or
    $CurrentRecord -or $AttemptRecord -or $Pull -or $Rotate -or $Service -or $CredentialName -or
    $Probes -or $EnableDynamicGitHubRepositories -or $EnableOwnerShell -or
    $EnablePublisherMount -or $EnableMachinePowerShell -or $EnableRegistryMount -or
    $RegistryReleaseNonce -or $RegistryExpectedSourceDigest -or
    $EnableActionCoreNetwork -or $EnableObservatoryNetwork -or $AllowUncertainGrowth -or
    $CiControlRepositories -or $CdReadRepositories -or $PreserveUncertainRequests -or
    $PreserveClaimedJobs -or $PreserveApprovedRequest -or $ConfirmWorkerQuiescent -or
    $EmergencyRescueImage -or $EmergencyRescueArchiveSha256 -or $AcceptUnverifiedRestore -or
    $VaultVolume -cne 'fortis-review-secrets')){
    throw 'RELEASE_REGISTRY_DIGEST_ARGUMENTS_INVALID'
}
if($Action -cin @('Check','Apply') -and -not $AttemptRecord){Get-SourceRecord -RetirementCheckOnly}
$script:ActionCoreNetworks=$null
if($EnableActionCoreNetwork -or $EnableObservatoryNetwork){
    Step 'GATEWAY_NETWORK_PREFLIGHT_READ_ONLY'
    $script:ActionCoreNetworks=Read-GatewayNetworkBoundary -ActionCore:([bool]$EnableActionCoreNetwork) -Observatory:([bool]$EnableObservatoryNetwork)
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
    Write-ReleaseTiming 'BUILD_ARCHIVE_BEGIN'
    $null=Private-Process @('-C',$SourceRoot,'archive','--format=zip',('--output='+$Zip),$SourceSha) '' $Git
    Write-ReleaseTiming 'BUILD_ARCHIVE_END'
    Write-ReleaseTiming 'BUILD_EXPAND_BEGIN'
    Expand-Archive -LiteralPath $Zip -DestinationPath $Context
    Write-ReleaseTiming 'BUILD_EXPAND_END'
    $Tag='fortis-approvals-gateway:extensions-'+$SourceSha.Substring(0,12)
    Write-ReleaseTiming 'BUILD_DOCKER_BEGIN'
    $null=Docker-Text @('build','--label',('org.opencontainers.image.revision='+$SourceSha),'-f',
        (Join-Path $Context 'fortis_approvals\deploy\Dockerfile-Gateway-Modularized-Candidate'),'-t',$Tag,$Context)
    Write-ReleaseTiming 'BUILD_DOCKER_END'
    $script:Image=@(Docker-Json @('image','inspect',$Tag))[0].Id
}
if($CheckedImageRecord -or $script:RegistryPrebuiltCheck){
    # Pinned Apply and prebuilt Registry Check require exact clean source.
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
    if($Action -ceq 'Return'){
        $PairedReturn=[bool]$script:R.PSObject.Properties['bootstrapOwnerGo']
        if($PairedReturn -ne [bool]$ConfirmWorkerQuiescent){throw 'RELEASE_QUIESCENCE_ACTION_INVALID'}
    }
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
    $script:PreserveApprovedExact=($null -ne $script:R.PSObject.Properties['registryReturn'])
    $CrashField=$script:R.PSObject.Properties['registryCrash']
    if($null -ne $CrashField){
        if(-not $script:PreserveApprovedExact -or -not $CrashField.Value){throw 'RELEASE_REGISTRY_CRASH_ATTEMPT_INVALID'}
        $script:RegistryCrash=$CrashField.Value
    }
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
if($Action -eq 'RegistrySourceDigest'){
    # Controller already proved clean Windows main, exact owner-reviewed SHA,
    # and the exact built image revision. Readback runs strictly offline.
    $Digest=Image-Registry-Source-Digest -ImageId $script:Image
    [ordered]@{schema='fortis-registry-source-digest-v1';sourceSha=$SourceSha
        imageId=$script:Image;gatewaySourceDigest=$Digest}|ConvertTo-Json -Compress
    return
}
$ControllerLock=Open-ReleaseControllerLock
try {
if($Action -eq 'Return' -or $AttemptRecord){
    Assert-ReleaseStateAttemptAvailable
    $SourceField=$script:R.PSObject.Properties['source']
    if($SourceField -and $SourceField.Value){Assert-ReleaseStateSourceAvailable $SourceField.Value.runtime}
    $ReserveField=$script:R.PSObject.Properties['registryReturn']
    if($ReserveField -and $ReserveField.Value){Assert-ReleaseStateSourceAvailable $ReserveField.Value}
} elseif($Action -cin @('Check','Apply')){
    Get-SourceRecord -RetirementCheckOnly
}
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
    $BootstrapAttempt=$script:R.PSObject.Properties['bootstrapOwnerGo']
    if($BootstrapAttempt -and $script:R.phase -ceq 'Prepared'){
        $Intent=Read-BootstrapFrozenIntent $script:R.source $script:R.bootstrapCheckRecord $script:R.bootstrapCheckHash
        if(-not $Intent.ContainsKey('ordinary')){$null=Read-BootstrapSeedSource $script:R.source}
        $Candidate=Read-BootstrapGatewayCandidate $Intent
        if(-not $Candidate){throw 'RELEASE_RESUME_NOT_READY_USE_RETURN'}
    }
    if($script:R.phase -cnotin @('Created','Staged')){
        # Complete with a still-unpublished current pointer: verify actual
        # active target first, then recover only the exact pointer.
        if($script:R.phase -cne 'Complete' -or -not ($BootstrapAttempt -or $script:R.PSObject.Properties['correctivePair'])){
            throw 'RELEASE_RESUME_NOT_READY_USE_RETURN'
        }
    }
    Resume-Target;return
}
if(-not $Config -and -not $Auto){throw 'RELEASE_PUBLIC_CONFIG_REQUIRED'}
$SourceForOwnerShell=Get-SourceRecord
$SuccessorContext=if(-not $OrdinaryPairRequested -or $Action -ceq 'Apply' -or
   (Test-Path -LiteralPath (Join-Path $ReleaseBase ('maintenance-'+$SourceForOwnerShell.runtime.runId+'.json')))){
    Read-SuccessorMaintenanceContext $SourceForOwnerShell
}
$OrdinaryCandidate=$null
$SuccessorMaintenance=$null
if($Action -ceq 'Apply'){$SuccessorMaintenance=$SuccessorContext}
if($AllowUncertainGrowth){
    $script:GrowthSourceVolume=$SourceForOwnerShell.runtime.stateVolume
}
$script:PublisherActivationVolume=Read-PublisherActivationVolume $SourceForOwnerShell.runtime
$PreviousPublisherDigest=Read-PublisherActivationDigest $SourceForOwnerShell.runtime
if($EnablePublisherMount){$script:PublisherActivationVolume='fortis-r7-publisher-activation'}
$RegistryPrior=Read-RegistryMountBinding $SourceForOwnerShell.runtime
if($RegistryPrior.readerVolume -and -not $EnableRegistryMount){
    # A routine release must not silently drop an owner-accepted Registry.
    # Existing protected Return/Backup/Promote remain separate recovery paths.
    throw 'RELEASE_REGISTRY_MOUNT_DOWNGRADE_REQUIRES_OWNER_REVIEW'
}
if($RegistryPrior.readerVolume -and $EnableRegistryMount -and
   $RegistryPrior.releaseNonce -ceq $RegistryReleaseNonce){
    # Reusing an old seal across a different Gateway release would destroy
    # per-release rollback isolation even when images share source bytes.
    throw 'RELEASE_REGISTRY_NONCE_REUSE_DENIED'
}
Initialize-RegistryReleaseBinding -Enabled ([bool]$EnableRegistryMount) -RequestedNonce $RegistryReleaseNonce
if($EnableRegistryMount){
    Step 'REGISTRY_NONCE_HISTORY_PREFLIGHT'
    $AllowedRegistryCheck=if($Action -eq 'Apply'){$CheckedImageRecord}
        elseif($SuccessorContext -and $SuccessorContext.PSObject.Properties['intentDigest']){
            Successor-CheckRecordPath $SuccessorContext.intent.authorization.attemptId
        }elseif($SuccessorContext){Successor-CheckRecordPath $SuccessorContext.draining.attempt.attemptId}
        else{''}
    Assert-Registry-Nonce-Fresh -Nonce $RegistryReleaseNonce -AllowedCheckRecord $AllowedRegistryCheck
    Step 'REGISTRY_SOURCE_DIGEST_IMAGE_PREFLIGHT'
    $script:RegistryGatewaySourceDigest=Image-Registry-Source-Digest -ImageId $script:Image
    if($script:RegistryGatewaySourceDigest -cne $RegistryExpectedSourceDigest){
        throw 'RELEASE_REGISTRY_SOURCE_DIGEST_MISMATCH'
    }
    Step 'REGISTRY_READER_SEAL_AND_PEER_PREFLIGHT'
    if($OrdinaryPairRequested){
        if($Action -ceq 'Apply'){
            $Context=Read-Private (Join-Path $ReleaseBase ('maintenance-'+$SourceForOwnerShell.runtime.runId+'.json'))
            $Check=Read-Private $CheckedImageRecord
            if(-not $SuccessorContext -or $Context.intentDigest -cne $Check.binding.ordinaryIntentDigest -or
               $Context.targetRegistryImage -cne $SuccessorRegistryImage -or
               $Context.intent.compatibility.registry.profileDigest -cne $SuccessorRegistryProfileSha256 -or
               $Context.targetNonce -cne $script:RegistryBoundReleaseNonce){
                throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
            }
            $OrdinaryCandidate=@{intent=$Context.intent}
        }elseif($SuccessorContext){
            if(-not $SuccessorContext.PSObject.Properties['intentDigest'] -or
               $SuccessorContext.targetRegistryImage -cne $SuccessorRegistryImage -or
               $SuccessorContext.intent.compatibility.registry.profileDigest -cne $SuccessorRegistryProfileSha256 -or
               $SuccessorContext.targetNonce -cne $script:RegistryBoundReleaseNonce){
                throw 'RELEASE_SUCCESSOR_ORDINARY_CONTEXT_CHANGED'
            }
            $OrdinaryCandidate=@{intent=$SuccessorContext.intent;intentDigest=$SuccessorContext.intentDigest
                pairDigest=$SuccessorContext.pairDigest}
        }else{
            $OrdinaryCandidate=Read-OrdinarySuccessorCompatibility $SourceForOwnerShell (Read-SuccessorPublication $SourceForOwnerShell).anchor
        }
        $script:RegistrySocketVolume='fortis-registry-read-'+$script:RegistryBoundReleaseNonce.Replace('-','')
        $script:RegistryProfileDigest=$OrdinaryCandidate.intent.compatibility.gateway.profileDigest
    } elseif($Bootstrap289){
        $script:BootstrapPair=Read-BootstrapCompatibility $SourceForOwnerShell
        $script:RegistrySocketVolume='fortis-registry-read-'+$script:RegistryBoundReleaseNonce.Replace('-','')
        $script:RegistryProfileDigest=$script:BootstrapPair.checked.gateway.profileDigest
    } else {
    $script:RegistryDelivery=Read-RegistrySuccessorDelivery $SourceForOwnerShell
    if($script:RegistryDelivery){
        if($Auto -or $RegistryReturnContainerId -or $SuccessorContext -or -not $ConfirmWorkerQuiescent){
            throw 'RELEASE_REGISTRY_SUCCESSOR_FIRST_TRANSITION_REQUIRED'
        }
        $script:RegistrySocketVolume='fortis-registry-read-'+$script:RegistryBoundReleaseNonce.Replace('-','')
        $script:RegistryProfileDigest=$script:RegistryDelivery.profileDigest
        if($Corrective288){$script:CorrectivePair=Read-CorrectiveRegistryPair $SourceForOwnerShell}
    } else {
        if($Corrective288){throw 'RELEASE_CORRECTIVE_288_COMPANION_REQUIRED'}
        $script:RegistryProfileDigest=Image-RegistryMount-Preflight `
            -ImageId $script:Image -ReleaseNonce $script:RegistryBoundReleaseNonce `
            -ReaderVolume $script:RegistryReaderVolume
    }
    }
}
$script:MachinePowerShellVolume=Read-MachinePowerShellVolume $SourceForOwnerShell.runtime
$PreviousMachineDigest=Read-MachinePowerShellDigest $SourceForOwnerShell.runtime
if($EnableMachinePowerShell){$script:MachinePowerShellVolume='fortis-r7-machine-powershell'}
$script:MachinePowerShellDigest=''
if($script:MachinePowerShellVolume){
    Step 'MACHINE_POWERSHELL_MATERIAL_PREFLIGHT'
    $script:MachinePowerShellDigest=Image-MachinePowerShell-Preflight -ImageId $script:Image
    if($PreviousMachineDigest -and $script:MachinePowerShellDigest -cne $PreviousMachineDigest){
        throw 'RELEASE_MACHINE_POWERSHELL_SOURCE_MATERIAL_CHANGED'
    }
}
$script:PublisherActivationDigest=''
if($script:PublisherActivationVolume){
    Step 'PUBLISHER_ACTIVATION_MATERIAL_PREFLIGHT'
    $script:PublisherActivationDigest=Image-PublisherMount-Preflight -ImageId $script:Image
    if($PreviousPublisherDigest -and $script:PublisherActivationDigest -cne $PreviousPublisherDigest){
        throw 'RELEASE_PUBLISHER_SOURCE_MATERIAL_CHANGED'
    }
}
if((Read-GatewayNetworks $SourceForOwnerShell.runtime) -and
   (Test-RecordedGatewayNetwork (Read-GatewayNetworks $SourceForOwnerShell.runtime) 'fortis-actioncore-net') -and -not $EnableActionCoreNetwork){
    throw 'RELEASE_ACTION_CORE_NETWORK_DOWNGRADE_DENIED'
}
if((Test-RecordedGatewayNetwork (Read-GatewayNetworks $SourceForOwnerShell.runtime) 'fortis-observatory-gw-net') -and -not $EnableObservatoryNetwork){
    throw 'RELEASE_OBSERVATORY_NETWORK_DOWNGRADE_DENIED'
}
$OwnerShellEnabled=((Read-OwnerShellFlag $SourceForOwnerShell.runtime) -or [bool]$EnableOwnerShell)
if($OwnerShellEnabled){
    Step 'OWNER_SHELL_MATERIAL_PREFLIGHT'
    Image-OwnerShell-Preflight
}
if($Auto){$ConfigText=$script:AutoConfigText}
else {$ConfigText=Get-Content -LiteralPath $Config -Raw}
$PublicConfig=ConvertFrom-Json -InputObject $ConfigText -ErrorAction Stop
# A valid image-owned Registry provider must be paired with the pinned
# owner reader. Never activate a hidden mount or a configured unbound API.
$HasRegistry=[bool](Read-RegistryProvider $PublicConfig)
if($HasRegistry -ne [bool]$EnableRegistryMount){
    throw 'RELEASE_REGISTRY_PROVIDER_AND_OWNER_MOUNT_MISMATCH'
}
if((Read-ActionCoreProvider $PublicConfig) -and -not $EnableActionCoreNetwork){
    throw 'RELEASE_ACTION_CORE_NETWORK_REQUIRED'
}
if($EnableActionCoreNetwork){Assert-ActionCoreConfig $ConfigText}
if((Read-ObservatoryProvider $PublicConfig) -and -not $EnableObservatoryNetwork){
    throw 'RELEASE_OBSERVATORY_NETWORK_REQUIRED'
}
if($EnableObservatoryNetwork){Assert-ObservatoryConfig $ConfigText}
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
if($OrdinaryPairRequested -or $Bootstrap289){
    $PairedProbeText=if($Probes){Get-Content -LiteralPath $Probes -Raw}else{'[]'}
    Assert-PairedReleaseProbes $SourceForOwnerShell $PairedProbeText
}
if($RegistryReturnContainerId){
    Step 'REGISTRY_RETURN_PREFLIGHT'
    $SourceForReturn=$SourceForOwnerShell
    $null=Registry-ReturnRuntime $SourceForReturn $RegistryReturnContainerId $RegistryReturnNonce ('0'*64)
    if($RegistryCrashRecovery){
        Assert-RegistryCrashSource $SourceForReturn
        Assert-RegistryCrashIncumbent $SourceForReturn
    }
    Assert-RegistryReturnConfiguration $SourceForReturn $Report
    Assert-Registry-Nonce-Fresh -Nonce $RegistryReturnNonce
    $ReturnDigest=Get-RegistryReturnSeal $SourceForOwnerShell $RegistryReturnNonce
    $script:RegistryReturn=Registry-ReturnRuntime $SourceForOwnerShell $RegistryReturnContainerId $RegistryReturnNonce $ReturnDigest
    Admit-Source (Container $SourceForOwnerShell.runtime.pilotId) $SourceForOwnerShell
}
# Ordinary Auto Apply can defer the full receipt to the read-only source
# admission below. Reject a changed binding immediately; manual/recovery
# paths retain their original full early audit.
if($Action -ceq 'Apply' -and $SuccessorMaintenance){
    $StopIntent=Verify-Checked-Image $SourceForOwnerShell $Report -PrepareSuccessorStop
    if(-not $OrdinaryPairRequested){
        # No unreviewed legacy/static maintenance path to paired Apply.
        $null=Save-SuccessorApplyStopIntent $StopIntent
        throw 'RELEASE_SUCCESSOR_STAGED_HANDOVER_UNAVAILABLE'
    }
} elseif($CheckedImageRecord){Verify-Checked-Image $SourceForOwnerShell $Report -BindingOnly:$Auto}
if($Bootstrap289 -and $Action -ceq 'Apply'){
    # Only the one exact #289 migration may enter the paired controller.
    # A protected Check and original owner review are mandatory, not GO:
    # Save-BootstrapPreparedAttempt obtains the separate APPLY confirmation,
    # repeats compatibility/state checks and persists the intent before stop.
    if(-not $CheckedImageRecord -or -not $script:BootstrapPair -or -not $BootstrapReviewProofRecord){
        throw 'RELEASE_SUCCESSOR_BOOTSTRAP_EXACT_CHECK_REQUIRED'
    }
}
if($Action -eq 'Check' -and $OrdinaryPairRequested){
    Assert-Previous-Image-Retained $SourceForOwnerShell
    if(Test-Path -LiteralPath $AttemptPointer){
        $Last=Read-Private (Read-Private $AttemptPointer).record
        if($Last.phase -cnotin @('Complete','Returned')){throw 'RELEASE_PRIOR_ATTEMPT_REQUIRES_RESUME_OR_RETURN'}
    }
    $Result=Prepare-SuccessorMaintenanceContext $SourceForOwnerShell $OrdinaryCandidate -Report $Report
    $Result|ConvertTo-Json -Depth 12
    return
}
if($Action -eq 'Check'){
    $CheckReceipt=$null;$MaintenanceSeal=$null;$MaintenanceTransitions=$null;$ResumeMaintenanceCheck=$false
    if($Build -or $script:RegistryPrebuiltCheck -or $script:PreserveUncertainRequests -or $script:PreserveClaimedJobs -or $script:PreserveApprovedRequest){
        $Source=Get-SourceRecord
        if(($script:PreserveClaimedJobs -or $script:PreserveApprovedRequest) -and
            -not $ConfirmWorkerQuiescent){throw 'RELEASE_PRESERVATION_REQUIRES_QUIESCENCE'}
        Step 'SOURCE_STATE_PREFLIGHT_READ_ONLY'
        $CurrentMaintenance=Read-SuccessorMaintenanceContext $Source
        if([bool]$SuccessorContext -ne [bool]$CurrentMaintenance -or
           ($SuccessorContext -and -not (Same-Json $SuccessorContext $CurrentMaintenance))){
            throw 'RELEASE_SUCCESSOR_MAINTENANCE_CONTEXT_CHANGED'
        }
        if($SuccessorContext){
            $Incumbent=Container $Source.runtime.pilotId
            if($Incumbent.State.Status -cne 'running'){throw 'RELEASE_SOURCE_NOT_RUNNING'}
            Admit-Source $Incumbent $Source
            Assert-OnlyWriter $Source.runtime.stateVolume $Incumbent.Id
            $Drain=Start-SuccessorMaintenanceCheck $Source $CurrentMaintenance
            $SuccessorMaintenance=$Drain.payload
            if($null -eq $SuccessorMaintenance){
                [ordered]@{status='MAINTENANCE_DRAINING';attemptId=$CurrentMaintenance.draining.attempt.attemptId
                    restrictionDigest=$CurrentMaintenance.draining.attempt.restrictionDigest
                    interlockDigest=$Drain.digest}|ConvertTo-Json -Depth 4
                return
            }
            $ResumeMaintenanceCheck=$Drain.resume
            if(-not $ResumeMaintenanceCheck){
                $Frozen=Read-SuccessorFreezeSeal $SuccessorMaintenance $Source.runtime.stateVolume 'fortis-r7-maintenance-interlock'
                $CheckReceipt=$Frozen.sourceReceipt
                $MaintenanceSeal=$Frozen.seal
                $MaintenanceTransitions=$Frozen.transitions
            }
        } elseif($AllowUncertainGrowth){
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
    if($script:RegistryCrash){Assert-RegistryCrashReceipt $CheckReceipt}
    if($Build -or $script:RegistryPrebuiltCheck){
        # Check may report READY only if the exact old image is retained,
        # or the full owner-accepted UC-GW-013 rescue gate has passed.
        # Do not defer the missing-image error until Apply SOURCE_ADMISSION.
        Assert-Previous-Image-Retained $Source
        if($Bootstrap289){
            $FreshBootstrap=Read-BootstrapCompatibility $Source -Recheck
            if(-not (Same-Json $FreshBootstrap $script:BootstrapPair)){
                throw 'RELEASE_SUCCESSOR_BOOTSTRAP_COMPATIBILITY_CHANGED'
            }
        }
        if($Corrective288){
            $FreshPair=Read-CorrectiveRegistryPair $Source
            if(-not (Same-Json $FreshPair $script:CorrectivePair)){
                throw 'RELEASE_CORRECTIVE_REGISTRY_PAIR_CHANGED'
            }
        }
        if($ResumeMaintenanceCheck){
            $Path=Successor-CheckRecordPath $SuccessorMaintenance.attemptId
        } else {
            $Path=Save-Checked-Image $Source $Report $CheckReceipt $SuccessorMaintenance $MaintenanceSeal $MaintenanceTransitions
        }
        if($SuccessorMaintenance){
            $Stored=Read-Private $Path
            if($Stored.schema -cne 'fortis-extension-image-check-v1' -or $Stored.phase -cne 'Ready'){
                throw 'RELEASE_SUCCESSOR_CHECK_RECORD_CHANGED'
            }
            Assert-Checked-Image-Binding $Stored.binding (Checked-Image-Binding $Source $Report $SuccessorMaintenance)
            $Digest=Complete-SuccessorMaintenanceCheck $Source $CurrentMaintenance $Stored
            $Report|Add-Member -NotePropertyName checkedMaintenance -NotePropertyValue (
                [ordered]@{phase='CHECK_SEALED';attemptId=$SuccessorMaintenance.attemptId
                    restrictionDigest=$SuccessorMaintenance.restrictionDigest;interlockDigest=$Digest})
        }
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
    if($Bootstrap289){
        $Report.status='BOOTSTRAP_CHECKED_ONLY'
        $Report|Add-Member -NotePropertyName compatibilityDigest -NotePropertyValue $script:BootstrapPair.compatibilityDigest
        $Report|Add-Member -NotePropertyName deploymentAuthorized -NotePropertyValue $false
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
if($OrdinaryPairRequested){
    $Rows=Read-OrdinarySuccessorSource $SourceForOwnerShell -PublicationRecovery
    $Native=(Read-Private $CheckedImageRecord).binding.ordinaryNativeRead
    if($Native.githubRead -ne $true -or $Native.gatewayId -cne $Rows.gateway.Id -or
       $Native.registryId -cne $Rows.registry.Id -or $Native.sourceRecordDigest -cne $SourceForOwnerShell.hash.ToLowerInvariant()){
        throw 'RELEASE_SUCCESSOR_ORDINARY_PREFLIGHT_CHANGED'
    }
    if($Rows.gateway.State.Status -ceq 'running'){Assert-NativeRepoRead}
    # A stopped held Gateway cannot answer a fresh HTTP request. The
    # exact protected Check contains its pre-begin typed read; the staged
    # target must independently pass the same native read before activation.
}else{Assert-NativeRepoRead}
Step 'SOURCE_ADMISSION'
$Source=Get-SourceRecord
if(($script:PreserveClaimedJobs -or $script:PreserveApprovedRequest) -and
    -not $ConfirmWorkerQuiescent){throw 'RELEASE_PRESERVATION_REQUIRES_QUIESCENCE'}
if($OrdinaryPairRequested){
    $Rows=Read-OrdinarySuccessorSource $Source -PublicationRecovery
    $Old=$Rows.gateway
}else{$Old=Container $Source.runtime.pilotId;Admit-Source $Old $Source}
if($script:RegistryCrash){
    if($Old.State.Status -cne 'exited'){throw 'RELEASE_REGISTRY_CRASH_SOURCE_RESTARTED'}
    Assert-RegistryCrashIncumbent $Source
} elseif($Old.State.Status -cne 'running' -and -not ($OrdinaryPairRequested -and
    $Old.State.Status -ceq 'exited')){
    throw 'RELEASE_SOURCE_NOT_RUNNING'
}
Step 'PREVIOUS_IMAGE_RETENTION_PREFLIGHT'
Assert-Previous-Image-Retained $Source
Assert-OnlyWriter $Source.runtime.stateVolume $Old.Id
Step 'SOURCE_STATE_PREFLIGHT'
$PreStopReceipt=if($OrdinaryPairRequested){
    # Verify-Checked-Image already obtained the fresh exact frozen seal
    # and receipt. The final owner GO repeats that independent comparison.
    (Read-Private $CheckedImageRecord).sourceReceipt
}elseif($Auto -and $CheckedImageRecord){
    # Fresh binding and full state/growth verification after read-only source
    # admission. Serialize this exact verified receipt, not an earlier cache.
    Verify-Checked-Image $Source $Report -ReturnReceipt
} else {
    Receipt $Source.runtime.stateVolume -Exact:$script:PreserveUncertainExact -ExactClaimed:$script:PreserveClaimedExact -ExactApproved:$script:PreserveApprovedExact
}
if($script:RegistryCrash){Assert-RegistryCrashReceipt $PreStopReceipt}
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
# The previously sealed, exact Registry nonce is protected by the Check
# binding and copied unchanged into the actual Gateway runtime record.
$Nonce=$(if($EnableRegistryMount){$RegistryReleaseNonce}
         else{[Guid]::NewGuid().ToString('D')})
$Runtime=[ordered]@{pilotId='';pilotName=('fortis-github-pilot-'+$RunId);image=$script:Image
    stateVolume=('fortis-github-pilot-state-'+$RunId);tokenVolume=$Source.runtime.tokenVolume
    owner=$Source.runtime.owner;repository=$Source.runtime.repository;filePrBranch=$Source.runtime.filePrBranch
    ciReads=$true;nativeWorktree=$true;requiredWorkflows=$Source.runtime.requiredWorkflows;bootstrapTask=$Source.runtime.bootstrapTask
    dynamicRepositories=((Read-DynamicRepositoriesFlag $Source.runtime) -or [bool]$EnableDynamicGitHubRepositories)
    ciControlRepositories=$(if($CiControlRepositories){$CiControlRepositories}else{Read-CiControlRepositories $Source.runtime})
    cdReadRepositories=$(if($CdReadRepositories){$CdReadRepositories}else{Read-CdReadRepositories $Source.runtime})
    preserveUncertainRequests=$script:PreserveUncertainRequests
    preserveClaimedJobs=$script:PreserveClaimedJobs
    preserveApprovedRequest=$script:PreserveApprovedRequest
    workerQuiescenceOwnerAttested=([bool]$ConfirmWorkerQuiescent)
    vaultVolume=$VaultVolume;extensionsConfig=$CompactConfig;releaseNonce=$Nonce
    publisherActivationVolume=$script:PublisherActivationVolume
    publisherActivationDigest=$script:PublisherActivationDigest
    machinePowerShellVolume=$script:MachinePowerShellVolume
    machinePowerShellDigest=$script:MachinePowerShellDigest
    registryReaderVolume=$script:RegistryReaderVolume
    registrySocketVolume=$script:RegistrySocketVolume
    registryReleaseNonce=$script:RegistryBoundReleaseNonce
    registryProfileDigest=$script:RegistryProfileDigest
    ownerShell=$OwnerShellEnabled;runId=$RunId}
if($script:RegistryDelivery){
    $Runtime.registryDelivery=$script:RegistryDelivery
    $Runtime.maintenanceGeneration=$script:RegistryDelivery.generation
}
if($EnableActionCoreNetwork){$Runtime.gatewayNetworks=$script:ActionCoreNetworks}
if($EnableObservatoryNetwork){$Runtime.gatewayNetworks=$script:ActionCoreNetworks}
$script:R=[ordered]@{schema='fortis-extension-release-v1';phase='Prepared';source=$Source;runtime=$Runtime
    productionBaseline=$Baseline;configurationDigest=$Report.configurationDigest;sourceReceipt=$null
    activated=$false;probesPassed=$false;probes=$ProbeText;failureStep='';failureMessage=''
    emergencyRecovery=[ordered]@{ownerAcceptedUnverifiedRestore=[bool]$AcceptUnverifiedRestore
        rescueImage=$EmergencyRescueImage;archiveSha256=$EmergencyRescueArchiveSha256.ToUpperInvariant()
        isolatedRestoreTested=$false}}
if($script:RegistryReturn){
    $script:R['registryReturn']=$script:RegistryReturn
    $script:R.sourceReceipt=$PreStopReceipt
}
if($script:RegistryCrash){$script:R['registryCrash']=$script:RegistryCrash}
if($script:CorrectivePair){
    $script:R['correctivePair']=$script:CorrectivePair
    $script:R['correctiveCheckRecord']=[IO.Path]::GetFullPath($CheckedImageRecord)
    $script:R['correctiveCheckHash']=(Get-FileHash -LiteralPath $CheckedImageRecord -Algorithm SHA256).Hash
    $script:R.sourceReceipt=$PreStopReceipt
}
Step 'PREPARE_RECORD_MODEL_READY'
# A 2026-11-13 owner Apply passed the Prepared Save but failed when
# sourceReceipt first entered the bounded serializer after docker stop.
# Prove the actual pre-stop receipt against this exact runtime/source DTO;
# on denial, leave the production source running and attempt.json untouched.
Step 'SOURCE_RECEIPT_SERIALIZATION_PREFLIGHT'
Assert-Release-Receipt-Serializable $script:R $PreStopReceipt
Step 'SOURCE_RECEIPT_SERIALIZATION_PREFLIGHT_PASS'
Save -FlushToDisk:([bool]$script:CorrectivePair)
Step 'PREPARED_RECORD_SAVED'
# Keep the original attempt pointer stable through the final pinned Check
# comparison. Its SHA256 is part of the Check binding; publishing our own
# new attempt pointer first would invalidate that binding before docker stop.
$RegistryStopAuthorized=$false
$SourceStopAttempted=$false
try {
    Step 'PUBLIC_ENV_PREFLIGHT'
    $EnvFile=Join-Path $Directory 'public.env'
    $EnvLines=@($Old.Config.Env|Where-Object{$_.StartsWith('FORTIS_') -and
        -not $_.StartsWith('FORTIS_EXTENSIONS_CONFIG=') -and
        -not $_.StartsWith('FORTIS_RELEASE_NONCE=') -and
        -not $_.StartsWith('FORTIS_GITHUB_NATIVE_MULTI_REPO=') -and
        -not $_.StartsWith('FORTIS_GITHUB_CI_CONTROL_REPOSITORIES=') -and
        -not $_.StartsWith('FORTIS_GITHUB_CD_READ_REPOSITORIES=') -and
        -not $_.StartsWith('FORTIS_OWNER_SHELL_CONFIG=')})
    if($Runtime.dynamicRepositories){$EnvLines+='FORTIS_GITHUB_NATIVE_MULTI_REPO=1'}
    if($Runtime.ciControlRepositories){$EnvLines+='FORTIS_GITHUB_CI_CONTROL_REPOSITORIES='+$Runtime.ciControlRepositories}
    if($Runtime.cdReadRepositories){$EnvLines+='FORTIS_GITHUB_CD_READ_REPOSITORIES='+$Runtime.cdReadRepositories}
    $EnvLines+=@(Extension-EnvLines $CompactConfig $Nonce)
    $EnvLines+=@(OwnerShell-EnvLines $Runtime.ownerShell)
    Check-OwnerShellEnv $EnvLines $Runtime.ownerShell
    [IO.File]::WriteAllText($EnvFile,(($EnvLines -join "`n")+"`n"),[Text.UTF8Encoding]::new($false))
    Check-ExtensionEnv $EnvLines $CompactConfig $Nonce
    Assert-PublicEnvFile $EnvFile $EnvLines
    if($EnableActionCoreNetwork -or $EnableObservatoryNetwork){
        Step 'ACTION_CORE_BOUNDARY_FINAL_PREFLIGHT'
        $FinalBoundary=Read-GatewayNetworkBoundary -ActionCore:([bool]$EnableActionCoreNetwork) -Observatory:([bool]$EnableObservatoryNetwork)
        if(-not (Same-Json $FinalBoundary $script:ActionCoreNetworks)){
            throw 'RELEASE_GATEWAY_BOUNDARY_CHANGED'
        }
    }
    if($script:RegistryReturn){
        $OwnerAction=if($script:RegistryCrash){'APPLY REGISTRY CRASH HANDOVER'}else{'APPLY REGISTRY HANDOVER'}
        if((Read-Host ('Type '+$OwnerAction)) -cne $OwnerAction){
            throw 'RELEASE_REGISTRY_HANDOVER_OWNER_GO_REQUIRED'
        }
    }
    if($script:CorrectivePair){
        if((Read-Host 'Type APPLY CORRECTIVE T4 288') -cne 'APPLY CORRECTIVE T4 288'){
            throw 'RELEASE_CORRECTIVE_288_OWNER_GO_REQUIRED'
        }
        $FreshPair=Read-CorrectiveRegistryPair $Source
        if(-not (Same-Json $FreshPair $script:CorrectivePair)){throw 'RELEASE_CORRECTIVE_REGISTRY_PAIR_CHANGED'}
        if((Get-FileHash -LiteralPath $CheckedImageRecord -Algorithm SHA256).Hash -cne $script:R.correctiveCheckHash){
            throw 'RELEASE_CORRECTIVE_ATTEMPT_CHANGED'
        }
    }
    if($Bootstrap289 -or $OrdinaryPairRequested){
        Step 'BOOTSTRAP_PREPARED_TRANSITION'
        Assert-Previous-Image-Retained $Source
        if($OrdinaryPairRequested){Save-OrdinaryPreparedAttempt $Source $Report $StopIntent}
        else{Save-BootstrapPreparedAttempt $Source $Report $CheckedImageRecord $BootstrapReviewProofRecord}
        $SourceStopAttempted=$true
        $Prepared=Invoke-BootstrapPreparedTransition
        $Runtime=$script:R.runtime
        if(-not (Same-Json $Prepared.delivery $Runtime.registryDelivery)){
            throw 'RELEASE_SUCCESSOR_BOOTSTRAP_RECEIVER_PROOF_CHANGED'
        }
        Step 'ATTEMPT_POINTER_SAVED'
    } else {
    Step 'STOP_SOURCE';Assert-Release-Production;Admit-Source (Container $Old.Id) $Source
    if($script:RegistryCrash){
        Assert-RegistryCrashIncumbent $Source
        Assert-RegistryCrashIncumbentQuiescent
    }
    if($script:RegistryDelivery){
        Step 'REGISTRY_SUCCESSOR_FINAL_PREFLIGHT'
        $FinalDelivery=Read-RegistrySuccessorDelivery $Source
        if($null -eq $FinalDelivery -or -not (Same-Json $FinalDelivery $script:RegistryDelivery)){
            throw 'RELEASE_REGISTRY_SUCCESSOR_DELIVERY_CHANGED'
        }
    }
    if($CheckedImageRecord){Verify-Checked-Image $Source $Report}
    Assert-Previous-Image-Retained $Source
    # Durable recovery pointer must exist before the first source effect,
    # but it is intentionally written AFTER the frozen Check binding audit.
    Write-Private $AttemptPointer @{schema=1;record=$script:RecordPath} -FlushToDisk:([bool]$script:CorrectivePair)
    Step 'ATTEMPT_POINTER_SAVED'
    if($script:CorrectivePair){$null=Read-CorrectiveAttemptPair}
    $RegistryStopAuthorized=[bool]$script:RegistryReturn
    Write-ReleaseTiming 'APPLY_STOP_REQUEST'
    $SourceStopAttempted=$true
    if($script:RegistryCrash){
        Step 'STOP_CRASH_INCUMBENT'
        $null=Docker-Text @('stop','--timeout','20',$script:RegistryCrash.incumbentId)
        if((Container $script:RegistryCrash.incumbentId).State.Status -cne 'exited'){
            throw 'RELEASE_REGISTRY_CRASH_INCUMBENT_STOP_UNCONFIRMED'
        }
        Assert-RegistryCrashPortsFree
    } else {
        $null=Docker-Text @('stop','--timeout','20',$Old.Id)
    }
    if((Container $Old.Id).State.Status -cne 'exited'){throw 'RELEASE_SOURCE_STOP_UNCONFIRMED'}
    Write-ReleaseTiming 'APPLY_SOURCE_EXITED'
    Assert-OnlyWriter $Source.runtime.stateVolume
    $FrozenReceipt=Receipt $Source.runtime.stateVolume -Exact:$script:PreserveUncertainExact -ExactClaimed:$script:PreserveClaimedExact -ExactApproved:$script:PreserveApprovedExact
    if($script:RegistryReturn){Assert-Checked-Source-Receipt $FrozenReceipt}
    $script:R.sourceReceipt=$FrozenReceipt
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
    if($script:CorrectivePair){Switch-CorrectiveRegistryPair}
    }
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
    if($Runtime.registryReaderVolume){
        Step 'PREPARE_STAGED_REGISTRY_COLLECTOR'
        Initialize-StagedRegistryCollector $Runtime
        Assert-SourceUnchanged
    }
    Step 'CREATE_STAGED'
    $Arguments=@('create','--pull=never','--name',$Runtime.pilotName,'--label',('io.fortis.review-update='+$RunId),
        '--restart','no','--init','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','100','--memory','512m','--memory-swap','1g','--network',$(if(Read-GatewayNetworks $Runtime){'fortis-gateway-egress'}else{'bridge'}),'--tmpfs','/tmp:rw,nosuid,nodev,size=16m',
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
    if($Runtime.machinePowerShellVolume){
        $Arguments+=@('--mount',('type=volume,source='+$Runtime.machinePowerShellVolume+
            ',target=/run/fortis-machine-powershell,readonly'))
    }
    if($script:RegistryDelivery){
        $Evidence='fortis-registry-source-evidence-'+$Runtime.registryReleaseNonce.Replace('-','')
        Assert-Volume $Evidence;Assert-OnlyWriter $Evidence
        $Arguments+=@('--mount',('type=volume,source='+$Evidence+',target=/run/fortis-registry-source-evidence,volume-nocopy'))
        if(Test-SuccessorLatestDelivery $script:RegistryDelivery){
            $Arguments+=@('--mount','type=volume,source=fortis-r7-maintenance-interlock-v2,target=/run/r7-maintenance,readonly,volume-nocopy',
                '--mount','type=volume,source=fortis-r7-maintenance-anchor,target=/run/r7-maintenance-anchor,readonly,volume-nocopy')
        } else {
            $Arguments+=@('--mount','type=volume,source=fortis-r7-maintenance-interlock,target=/run/r7-maintenance,readonly,volume-nocopy')
        }
    }
    if($Runtime.registryReaderVolume){
        $Arguments+=@('--mount',('type=volume,source='+$Runtime.registryReaderVolume+
            ',target=/run/r7-registry-reader,readonly'))
        $Arguments+=@('--mount',('type=volume,source='+$Runtime.registrySocketVolume+
            ',target=/run/fortis-registry-read,readonly'))
    }
    $Arguments+=@($script:Image)
    if($Bootstrap289 -or $OrdinaryPairRequested){
        $CreatedAck=''
        try {$CreatedAck=Docker-Text $Arguments}catch{Write-Warning 'RELEASE_SUCCESSOR_BOOTSTRAP_GATEWAY_CREATE_READBACK'}
        $Intent=Read-BootstrapFrozenIntent $Source $script:R.bootstrapCheckRecord $script:R.bootstrapCheckHash
        $Created=Read-BootstrapGatewayCandidate $Intent
        if(-not $Created -or $Created.State.Status -cne 'created' -or
           ($CreatedAck -and $CreatedAck -cne $Created.Id)){throw 'RELEASE_CREATED_ID_INVALID'}
    } else {
        $script:R.runtime.pilotId=Docker-Text $Arguments
        if($script:R.runtime.pilotId -cnotmatch '^[0-9a-f]{64}$'){throw 'RELEASE_CREATED_ID_INVALID'}
        $script:R.phase='Created';Save -FlushToDisk:([bool]$script:CorrectivePair)
    }
    Resume-Target
} catch {
    $Failure='step='+$script:Step+'; '+$_.Exception.Message
    $script:R.failureStep=$script:Step;$script:R.failureMessage=$Failure
    try{Save}catch{Write-Warning 'RELEASE_FAILURE_RECORD_NOT_SAVED'}
    $CanReturnSource=(-not $script:RegistryReturn -or $RegistryStopAuthorized) -and
        (-not $script:RegistryDelivery -or $SourceStopAttempted)
    if(($Bootstrap289 -or $OrdinaryPairRequested) -and -not $SourceStopAttempted){$CanReturnSource=$false}
    if($CanReturnSource){
        try{Return-Source}catch{Write-Warning ('RELEASE_RETURN_REQUIRES_REVIEW: '+$_.Exception.Message)}
    }
    throw ('RELEASE_FAILED: '+$Failure+'; record='+$script:RecordPath)
}

} finally { $ControllerLock.Dispose();Write-ReleaseTiming 'ACTION_END' }
