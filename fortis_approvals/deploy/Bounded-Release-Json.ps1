# Windows PowerShell 5.1 only. Strict JSON DTO for Gateway release records.
# Never hand arbitrary live PowerShell objects to ConvertTo-Json -Depth 25:
# adapters and nested members can grow without an effective object budget.
function ConvertTo-BoundedReleaseValue {
    param($Value, [hashtable]$Budget, [int]$Depth)

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
        if ($Value.Count -gt 256) { throw 'RELEASE_RECORD_JSON_OBJECT_TOO_LARGE' }
        $Map = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
        foreach ($Key in $Value.Keys) {
            if ($Key -isnot [string] -or $Key.Length -gt 128 -or $Map.ContainsKey($Key)) {
                throw 'RELEASE_RECORD_JSON_INVALID_KEY'
            }
            $Budget.chars = [int]$Budget.chars + $Key.Length
            if ($Budget.chars -gt 524288) { throw 'RELEASE_RECORD_JSON_CHAR_BUDGET_EXCEEDED' }
            $Map.Add($Key,(ConvertTo-BoundedReleaseValue -Value $Value[$Key] -Budget $Budget -Depth ($Depth+1)))
        }
        return ,$Map
    }
    if ($Value -is [pscustomobject]) {
        $Props = @($Value.PSObject.Properties)
        if ($Props.Count -gt 256) { throw 'RELEASE_RECORD_JSON_OBJECT_TOO_LARGE' }
        $Map = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
        foreach ($Prop in $Props) {
            if ($Prop.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or
                $Prop.Name.Length -gt 128 -or $Map.ContainsKey($Prop.Name)) {
                throw 'RELEASE_RECORD_JSON_INVALID_PROPERTY'
            }
            $Budget.chars = [int]$Budget.chars + $Prop.Name.Length
            if ($Budget.chars -gt 524288) { throw 'RELEASE_RECORD_JSON_CHAR_BUDGET_EXCEEDED' }
            $Map.Add($Prop.Name,(ConvertTo-BoundedReleaseValue -Value $Prop.Value -Budget $Budget -Depth ($Depth+1)))
        }
        return ,$Map
    }
    if ($Value -is [Collections.IList]) {
        if ($Value.Count -gt 8192) { throw 'RELEASE_RECORD_JSON_ARRAY_TOO_LARGE' }
        $Items = New-Object 'System.Collections.Generic.List[object]'
        foreach ($Item in $Value) {
            $Items.Add((ConvertTo-BoundedReleaseValue -Value $Item -Budget $Budget -Depth ($Depth+1)))
        }
        return ,$Items.ToArray()
    }
    throw 'RELEASE_RECORD_JSON_UNSUPPORTED_TYPE'
}

function ConvertTo-BoundedReleaseJson {
    param($Value)

    $Budget = @{ nodes=0; chars=0; watch=[Diagnostics.Stopwatch]::StartNew() }
    $Tree = ConvertTo-BoundedReleaseValue -Value $Value -Budget $Budget -Depth 0
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
