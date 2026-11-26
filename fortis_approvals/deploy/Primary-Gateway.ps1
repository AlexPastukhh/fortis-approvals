# Owner controller helpers. Loaded by Manage-Integrations.ps1 after admission functions.
function Release-Production-Baseline {
    $C=Container 'fortis-approvals-gateway'
    if($C.State.Status -ceq 'running'){return (Production-Baseline)}
    if($C.Image -cne $ProductionImage -or $C.State.Status -cne 'exited' -or
       $C.HostConfig.RestartPolicy.Name -cne 'no'){
        throw 'LEGACY_PRODUCTION_IDENTITY_INVALID'
    }
    'LEGACY_STOPPED:'+(ConvertTo-Json -InputObject ([ordered]@{
        id=$C.Id;image=$C.Image;mounts=$C.Mounts;ports=$C.HostConfig.PortBindings
    }) -Depth 12 -Compress)
}
function Assert-Release-Production {
    if((Release-Production-Baseline) -cne $script:R.productionBaseline){throw 'PILOT_PRODUCTION_CHANGED'}
}
function Backup-Primary {
    if(-not (Test-Path -LiteralPath $Pointer)){throw 'PRIMARY_CURRENT_RELEASE_REQUIRED'}
    $Source=Get-SourceRecord;$P=$Source.runtime;$C=Container $P.pilotId
    Admit $C $P
    if($C.State.Status -cne 'running' -or $C.State.Health.Status -cne 'healthy'){
        throw 'PRIMARY_BACKUP_NOT_HEALTHY'
    }
    Assert-OnlyWriter $P.stateVolume $C.Id
    $Id=[Guid]::NewGuid().ToString('N')
    $Name='fortis-gateway-backup-'+$Id
    $Directory=Join-Path $ReleaseBase ('primary-backup-'+$Id)
    $Stopped=$false;$Pass=$false
    try {
        $null=Docker-Text @('stop','--timeout','20',$C.Id);$Stopped=$true
        if((Container $C.Id).State.Status -cne 'exited'){throw 'PRIMARY_BACKUP_STOP_UNCONFIRMED'}
        Assert-OnlyWriter $P.stateVolume
        $Before=Receipt $P.stateVolume
        $null=Docker-Text @('volume','create','--label',('io.fortis.primary-backup='+$Id),$Name)
        Assert-Volume $Name
        $Clone=State-Helper @{action='clone';github=$true;native=$true;
            preserveUncertainIds=@(Parse-PreservedUncertainRequests $script:PreserveUncertainRequests);
            preserveClaimedIds=@(Parse-PreservedUncertainRequests $script:PreserveClaimedJobs);
            preserveApprovedIds=@(Approved-Ids)} @('--mount',
            ('type=volume,source='+$P.stateVolume+',target=/source,readonly'),
            '--mount',('type=volume,source='+$Name+',target=/target')) -Root
        if(-not (Same-Json $Clone $Before) -or -not (Same-Json (Receipt $P.stateVolume) $Before)){
            throw 'PRIMARY_BACKUP_CLONE_MISMATCH'
        }
        Protect-Directory $Directory
        Write-Private (Join-Path $Directory 'record.json') ([ordered]@{
            schema='fortis-primary-backup-v1';phase='Complete';sourceRecord=$Source.path
            sourceHash=$Source.hash;containerId=$C.Id;image=$P.image;stateVolume=$P.stateVolume
            backupVolume=$Name;receipt=$Before})
        Write-Private (Join-Path $ReleaseBase 'primary-backup.json') @{schema=1;record=(Join-Path $Directory 'record.json')}
        $Pass=$true
    } finally {
        if($Stopped){
            $Old=Container $C.Id
            if($Old.State.Status -ceq 'exited'){$null=Docker-Text @('start',$C.Id)}
            Wait-Healthy $C.Id;Admit (Container $C.Id) $P
        }
    }
    if($Pass){Write-Host ('FORTIS_PRIMARY_BACKUP_PASS '+$Name)}
}

# UC-GW-013 completion is NOT a second emergency release. This pure binding
# checker reads only the already Complete, owner-protected Apply record.
function Read-Emergency-Promote-Binding {
    param($Release,$Prior)
    if($null -eq $Release -or $null -eq $Prior -or
       $Release.schema -cne 'fortis-extension-release-v1' -or
       $Release.phase -cne 'Complete' -or
       $Release.activated -isnot [bool] -or -not $Release.activated -or
       $Release.probesPassed -isnot [bool] -or -not $Release.probesPassed -or
       $Prior.schema -cne 'fortis-primary-v1' -or $Prior.phase -cne 'Complete' -or
       $null -eq $Release.source -or $null -eq $Release.runtime -or
       $null -eq $Release.emergencyRecovery){
        throw 'RELEASE_EMERGENCY_PROMOTE_NOT_ATTESTED'
    }
    $Gate=$Release.emergencyRecovery
    if($Gate.ownerAcceptedUnverifiedRestore -isnot [bool] -or
       $Gate.ownerAcceptedUnverifiedRestore -ne $true -or
       $Gate.isolatedRestoreTested -isnot [bool] -or
       $Gate.isolatedRestoreTested -ne $false -or
       $Gate.rescueImage -isnot [string] -or
       $Gate.rescueImage -cnotmatch '^sha256:[0-9a-f]{64}$' -or
       $Gate.archiveSha256 -isnot [string] -or
       $Gate.archiveSha256 -cnotmatch '^[0-9A-F]{64}$'){
        throw 'RELEASE_EMERGENCY_PROMOTE_BINDING_INVALID'
    }
    # The old primary and old source are not retargeted to the rescue image.
    # A malformed, different or later source cannot inherit an earlier waiver.
    if($Release.source.path -cne $Prior.sourceRecord -or
       $Release.source.hash -cne $Prior.sourceHash -or
       -not (Same-Json $Release.source.runtime $Prior.runtime) -or
       $Release.runtime.pilotId -ceq $Prior.runtime.pilotId -or
       $Release.runtime.image -ceq $Prior.runtime.image -or
       $Gate.rescueImage -ceq $Prior.runtime.image -or
       $Gate.rescueImage -ceq $Release.runtime.image -or
       $Prior.runtime.pilotName -cne 'fortis-gateway' -or
       $Prior.runtime.restartPolicy -cne 'unless-stopped'){
        throw 'RELEASE_EMERGENCY_PROMOTE_SOURCE_CHANGED'
    }
    return @{rescueImage=$Gate.rescueImage;archiveSha256=$Gate.archiveSha256}
}

# Pure Windows 5.1 SelfTest: no protected state, Docker, credentials or network.
function Assert-Emergency-Promote-BindingSelfTest {
    $OldRuntime=[ordered]@{pilotId=('a'*64);pilotName='fortis-gateway'
        image=('sha256:'+('b'*64));stateVolume='old-volume'
        restartPolicy='unless-stopped';runId=('c'*32)}
    $Prior=[pscustomobject]@{schema='fortis-primary-v1';phase='Complete'
        sourceRecord='C:\fixture\old\record.json';sourceHash=('d'*64)
        runtime=$OldRuntime}
    $OldCopy=ConvertFrom-Json -InputObject (
        ConvertTo-Json -InputObject $OldRuntime -Compress -Depth 12)
    $Release=[pscustomobject]@{
        schema='fortis-extension-release-v1';phase='Complete'
        activated=$true;probesPassed=$true
        source=[pscustomobject]@{path=$Prior.sourceRecord;hash=$Prior.sourceHash
            runtime=$OldCopy}
        runtime=[pscustomobject]@{pilotId=('e'*64);image=('sha256:'+('f'*64))}
        emergencyRecovery=[pscustomobject]@{
            ownerAcceptedUnverifiedRestore=$true;isolatedRestoreTested=$false
            rescueImage=('sha256:'+('1'*64));archiveSha256=('A'*64)}
    }
    $Valid=Read-Emergency-Promote-Binding $Release $Prior
    if($Valid.rescueImage -cne ('sha256:'+('1'*64)) -or
       $Valid.archiveSha256 -cne ('A'*64)){
        throw 'RELEASE_EMERGENCY_PROMOTE_BINDING_SELFTEST_FAILED'
    }
    foreach($Case in @('no-consent','bad-archive','source-drift',
                       'source-image-substitution','false-restore-claim')){
        $Clone=ConvertFrom-Json -InputObject (
            ConvertTo-Json -InputObject $Release -Compress -Depth 20)
        switch($Case){
            'no-consent' {$Clone.emergencyRecovery.ownerAcceptedUnverifiedRestore=$false}
            'bad-archive' {$Clone.emergencyRecovery.archiveSha256='wrong'}
            'source-drift' {$Clone.source.hash=('0'*64)}
            'source-image-substitution' {$Clone.source.runtime.image=('sha256:'+('2'*64))}
            'false-restore-claim' {$Clone.emergencyRecovery.isolatedRestoreTested=$true}
        }
        $Rejected=$false
        try{$null=Read-Emergency-Promote-Binding $Clone $Prior}
        catch {
            if($_.Exception.Message -cnotmatch '^RELEASE_EMERGENCY_PROMOTE_'){
                throw
            }
            $Rejected=$true
        }
        if(-not $Rejected){
            throw ('RELEASE_EMERGENCY_PROMOTE_NEGATIVE_SELFTEST_FAILED '+$Case)
        }
    }
    Write-Host 'FORTIS_EMERGENCY_PROMOTE_BINDING_SELFTEST_PASS'
}

function Assert-Emergency-Promote-Rescue {
    param($Source,$Prior,$Previous)
    # Never add rescue flags to Promote, never consult the NEW backup pointer
    # as if it still referenced the historical source backup.
    if($Action -cne 'Promote' -or $Auto -or -not $ConfirmWorkerQuiescent -or
       $AcceptUnverifiedRestore -or $EmergencyRescueImage -or
       $EmergencyRescueArchiveSha256 -or $Previous.Id -cne $Prior.runtime.pilotId -or
       $Previous.Image -cne $Prior.runtime.image -or
       $Previous.State.Status -cne 'exited'){
        throw 'RELEASE_EMERGENCY_PROMOTE_NOT_AUTHORIZED'
    }
    $Release=Read-Private $Source.path
    if($Release.runtime.pilotId -cne $Source.runtime.pilotId -or
       $Release.runtime.image -cne $Source.runtime.image){
        throw 'RELEASE_EMERGENCY_PROMOTE_CURRENT_CHANGED'
    }
    $Binding=Read-Emergency-Promote-Binding $Release $Prior
    if((Get-FileHash -LiteralPath $Prior.sourceRecord -Algorithm SHA256).Hash -cne
       $Prior.sourceHash){
        throw 'RELEASE_EMERGENCY_PROMOTE_OLD_SOURCE_CHANGED'
    }

    # The historical backup used at Check/Apply is still owner-protected, but
    # primary-backup.json now points to the NEW P4 backup. Verify them separately.
    $Directories=@(Get-ChildItem -LiteralPath $ReleaseBase -Directory -Filter 'primary-backup-*')
    if($Directories.Count -gt 128){throw 'RELEASE_EMERGENCY_PROMOTE_BACKUP_SCAN_LIMIT'}
    $HistoricalBackupVerified=$false
    foreach($Directory in $Directories){
        if($Directory.Name -cnotmatch '^primary-backup-[0-9a-f]{32}$'){continue}
        $Path=Join-Path $Directory.FullName 'record.json'
        if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){continue}
        $Candidate=Read-Private $Path
        if($Candidate.sourceRecord -cne $Prior.sourceRecord -or
           $Candidate.sourceHash -cne $Prior.sourceHash){continue}
        if($Candidate.schema -cne 'fortis-primary-backup-v1' -or
           $Candidate.phase -cne 'Complete' -or
           $Candidate.containerId -cne $Prior.runtime.pilotId -or
           $Candidate.image -cne $Prior.runtime.image -or
           $Candidate.stateVolume -cne $Prior.runtime.stateVolume -or
           $Candidate.backupVolume -cnotmatch '^fortis-gateway-backup-[0-9a-f]{32}$' -or
           -not (Same-Json (Receipt $Candidate.backupVolume) $Candidate.receipt)){
            throw 'RELEASE_EMERGENCY_PROMOTE_OLD_BACKUP_INVALID'
        }
        $HistoricalBackupVerified=$true
    }
    if(-not $HistoricalBackupVerified){
        throw 'RELEASE_EMERGENCY_PROMOTE_OLD_BACKUP_MISSING'
    }

    # Content-hash verification and the same locked-down offline smoke as
    # emergency Apply; no Docker restore, run of the old Gateway or state write.
    $RecoveryDir=Join-Path $env:LOCALAPPDATA 'Fortis\GatewayRecovery'
    Assert-DirectoryAcl $RecoveryDir
    $Archive=Join-Path $RecoveryDir (
        'fortis-gateway-rescue-'+$Binding.rescueImage.Substring(7,12)+'.tar')
    $ArchiveItem=Get-Item -LiteralPath $Archive -Force -ErrorAction Stop
    if(($ArchiveItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
       -not (Test-Path -LiteralPath $Archive -PathType Leaf) -or
       (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash -cne
            $Binding.archiveSha256){
        throw 'RELEASE_EMERGENCY_PROMOTE_ARCHIVE_CHANGED'
    }
    $ImageInfo=@(Docker-Json @('image','inspect',$Binding.rescueImage))[0]
    if($null -eq $ImageInfo -or $ImageInfo.Id -cne $Binding.rescueImage){
        throw 'RELEASE_EMERGENCY_PROMOTE_RESCUE_IMAGE_CHANGED'
    }
    $Wrapper=Emergency-Rescue-Smoke-Argument
    $Smoke=Private-Process @('run','--rm','--pull=never','--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','64','--memory','256m','--tmpfs','/tmp:rw,noexec,nosuid,size=32m',
        '--entrypoint','python',$Binding.rescueImage,'-I','-B','-c',$Wrapper) ''
    foreach($Marker in @('IMAGE_OWNER_INCIDENT_IMPORT_PASS','IMAGE_EXTENSIONS_OFFLINE_PASS',
                         'IMAGE_NATIVE_GIT_IMPORT_PASS','IMAGE_SONAR_OFFLINE_SMOKE_PASS',
                         'IMAGE_GITHUB_NOT_REGISTERED_PASS')){
        if($Smoke -notmatch $Marker){throw 'RELEASE_EMERGENCY_PROMOTE_RESCUE_SMOKE_FAILED'}
    }
    Write-Host 'FORTIS_EMERGENCY_PROMOTE_RESCUE_VERIFIED'
    return [string]$Binding.rescueImage
}

function Get-PrimaryRegistryHandover {
    param($Applied,$Prior)
    $Origin=$Applied.source
    if($Applied.schema -cne 'fortis-extension-release-v1' -or $Applied.phase -cne 'Complete' -or
       $Applied.activated -ne $true -or -not $Origin){
        throw 'PRIMARY_PREVIOUS_REGISTRY_HANDOVER_UNBOUND'
    }

    if($Origin.path -ceq $Prior.sourceRecord){
        if($Origin.hash -cne $Prior.sourceHash -or -not (Same-Json $Origin.runtime $Prior.runtime) -or
           -not $Applied.registryReturn){
            throw 'PRIMARY_PREVIOUS_REGISTRY_HANDOVER_UNBOUND'
        }
        return @{source=$Origin;reserve=$Applied.registryReturn;used=$false;configurationDigest=''}
    }

    # The protected Apply source may be the reserve activated by an earlier
    # completed Return. Require both original owner records and the exact
    # runtime carried into Apply. A different current pointer proves nothing.
    $Run=$Origin.runtime.runId
    if($Run -cnotmatch '^[0-9a-f]{32}$' -or
       $Origin.path -cne (Join-Path $ReleaseBase ($Run+'\record.json')) -or
       $Origin.hash -cnotmatch '^[0-9A-Fa-f]{64}$' -or
       (Get-FileHash -LiteralPath $Origin.path -Algorithm SHA256).Hash -cne $Origin.hash){
        throw 'PRIMARY_RETURNED_REGISTRY_SOURCE_UNBOUND'
    }
    $Returned=Read-Private $Origin.path
    $AttemptPath=$Returned.registryReturnAttempt
    if($Returned.schema -cne 'fortis-extension-release-v1' -or $Returned.phase -cne 'Complete' -or
       $Returned.activated -ne $true -or $Returned.probesPassed -ne $true -or
       $Returned.retainedSourceRecord -cne $Prior.sourceRecord -or
       -not (Same-Json $Returned.runtime $Origin.runtime) -or
       $Returned.configurationDigest -cnotmatch '^[0-9a-f]{64}$' -or -not $AttemptPath){
        throw 'PRIMARY_RETURNED_REGISTRY_SOURCE_UNBOUND'
    }
    $Attempt=Read-Private $AttemptPath
    $AttemptRun=$Attempt.runtime.runId
    if($Attempt.schema -cne 'fortis-extension-release-v1' -or $Attempt.phase -cne 'Returned' -or
       $Attempt.activated -ne $false -or -not $Attempt.sourceReceipt -or
       $AttemptRun -cnotmatch '^[0-9a-f]{32}$' -or
       $AttemptPath -cne (Join-Path $ReleaseBase ($AttemptRun+'\record.json')) -or
       $Attempt.source.path -cne $Prior.sourceRecord -or $Attempt.source.hash -cne $Prior.sourceHash -or
       -not (Same-Json $Attempt.source.runtime $Prior.runtime) -or
       -not (Same-Json $Attempt.registryReturn $Returned.runtime) -or
       (Read-RegistryReturnSourceDigest $Attempt.source) -cne $Returned.configurationDigest){
        throw 'PRIMARY_RETURNED_REGISTRY_ATTEMPT_UNBOUND'
    }
    return @{source=$Attempt.source;reserve=$Attempt.registryReturn;used=$true;
        configurationDigest=$Returned.configurationDigest}
}

function Assert-PrimaryReturnedRegistrySourceSelfTest {
    & {
        $ReleaseBase=Join-Path $env:TEMP 'fortis-primary-return-fixture'
        $Prior=@{sourceRecord=(Join-Path $ReleaseBase ('a'*32+'\record.json'));sourceHash=('a'*64);
            runtime=@{runId=('a'*32);pilotId=('1'*64)}}
        $Origin=@{path=$Prior.sourceRecord;hash=$Prior.sourceHash;runtime=$Prior.runtime}
        $Reserve=@{runId=('b'*32);pilotId=('2'*64)}
        $AttemptPath=Join-Path $ReleaseBase ('c'*32+'\record.json')
        $ReservePath=Join-Path $ReleaseBase ('b'*32+'\record.json')
        $Returned=@{schema='fortis-extension-release-v1';phase='Complete';activated=$true;probesPassed=$true;
            runtime=$Reserve;registryReturnAttempt=$AttemptPath;retainedSourceRecord=$Prior.sourceRecord;
            configurationDigest=('d'*64)}
        $Attempt=@{schema='fortis-extension-release-v1';phase='Returned';activated=$false;
            runtime=@{runId=('c'*32)};source=$Origin;sourceReceipt=@{verified=$true};registryReturn=$Reserve}
        $Applied=@{schema='fortis-extension-release-v1';phase='Complete';activated=$true;
            source=$Origin;registryReturn=$Reserve}
        function Get-FileHash { param($LiteralPath,$Algorithm)
            if($LiteralPath -cne $ReservePath){throw 'TEST_UNEXPECTED_HASH_PATH'}
            return @{Hash=('b'*64)}
        }
        function Read-Private { param($Path)
            if($Path -ceq $ReservePath){return $Returned}
            if($Path -ceq $AttemptPath){return $Attempt}
            throw 'TEST_UNEXPECTED_RECORD_PATH'
        }
        function Read-RegistryReturnSourceDigest { param($Source)
            if($Source.path -cne $Prior.sourceRecord){throw 'TEST_UNEXPECTED_ORIGINAL_SOURCE'}
            return ('d'*64)
        }
        $Bound=Get-PrimaryRegistryHandover $Applied $Prior
        if($Bound.used -or $Bound.reserve.pilotId -cne $Reserve.pilotId){
            throw 'PRIMARY_DIRECT_REGISTRY_HANDOVER_SELFTEST_FAILED'
        }
        $Applied.source=@{path=$ReservePath;hash=('b'*64);runtime=$Reserve}
        $Applied.Remove('registryReturn')
        $Bound=Get-PrimaryRegistryHandover $Applied $Prior
        if(-not $Bound.used -or $Bound.source.path -cne $Prior.sourceRecord -or
           $Bound.reserve.pilotId -cne $Reserve.pilotId -or $Bound.configurationDigest -cne ('d'*64)){
            throw 'PRIMARY_RETURNED_REGISTRY_HANDOVER_SELFTEST_FAILED'
        }
        foreach($Invalid in @('bad-hash','bad-probes','bad-phase','bad-reserve')){
            $Applied.source.hash='b'*64
            $Returned.probesPassed=$true
            $Attempt.phase='Returned'
            $Attempt.registryReturn=$Reserve
            $Expected='PRIMARY_RETURNED_REGISTRY_SOURCE_UNBOUND'
            switch($Invalid){
                'bad-hash' {$Applied.source.hash='f'*64}
                'bad-probes' {$Returned.probesPassed=$false}
                'bad-phase' {$Attempt.phase='ReturningRegistrySource';$Expected='PRIMARY_RETURNED_REGISTRY_ATTEMPT_UNBOUND'}
                'bad-reserve' {$Attempt.registryReturn=@{runId=('b'*32);pilotId=('3'*64)};$Expected='PRIMARY_RETURNED_REGISTRY_ATTEMPT_UNBOUND'}
            }
            try {
                $null=Get-PrimaryRegistryHandover $Applied $Prior
                throw 'PRIMARY_RETURNED_REGISTRY_NEGATIVE_SELFTEST_FAILED'
            } catch {
                if($_.Exception.Message -cne $Expected){throw}
            }
        }
    }
    Write-Host 'FORTIS_PRIMARY_RETURNED_REGISTRY_SOURCE_SELFTEST_PASS'
}

# Explicit owner maintenance, never called by Backup or Promote.
# This source action operates only on registered, explicitly selected backup IDs.
function Get-BackupCleanupIds {
    param([string]$Selection)
    if(-not $Selection -or $Selection.Length -gt 4223){throw 'BACKUP_CLEANUP_IDS_REQUIRED'}
    $Ids=@($Selection -split ',')
    if($Ids.Count -gt 128){throw 'BACKUP_CLEANUP_ID_LIMIT'}
    foreach($Id in $Ids){
        if($Id -cnotmatch '^[0-9a-f]{32}$'){throw 'BACKUP_CLEANUP_ID_INVALID'}
    }
    if(@($Ids | Sort-Object -Unique).Count -ne $Ids.Count){throw 'BACKUP_CLEANUP_ID_DUPLICATE'}
    return @($Ids | Sort-Object)
}

function Assert-BackupCleanupCandidate {
    param([string]$Id,$Record,[string[]]$ProtectedSources,[string]$ProtectedBackupPath,[string]$RecordPath)
    if($Record.schema -cne 'fortis-primary-backup-v1' -or $Record.phase -cne 'Complete' -or
       $Record.backupVolume -cne ('fortis-gateway-backup-'+$Id) -or
       $Record.sourceHash -notmatch '^[0-9a-fA-F]{64}$' -or
       $Record.containerId -cnotmatch '^[0-9a-f]{64}$' -or
       $Record.image -cnotmatch '^sha256:[0-9a-f]{64}$' -or
       -not $Record.sourceRecord -or -not $Record.stateVolume -or -not $Record.receipt){
        throw 'BACKUP_CLEANUP_RECORD_INVALID'
    }
    if($RecordPath -ieq $ProtectedBackupPath -or $ProtectedSources -contains $Record.sourceRecord){
        throw 'BACKUP_CLEANUP_RECOVERY_PROTECTED'
    }
}

function Assert-BackupCleanupSelectionSelfTest {
    $Id='a'*32
    if((@(Get-BackupCleanupIds $Id)).Count -ne 1){throw 'BACKUP_CLEANUP_SELFTEST_FAILED'}
    foreach($Bad in @('','*',('a'*31),($Id+','+$Id),(' '+$Id))){
        $Rejected=$false
        try{$null=Get-BackupCleanupIds $Bad}catch{$Rejected=$true}
        if(-not $Rejected){throw 'BACKUP_CLEANUP_NEGATIVE_SELFTEST_FAILED'}
    }
    $Record=@{schema='fortis-primary-backup-v1';phase='Complete';backupVolume=('fortis-gateway-backup-'+$Id)
        sourceHash=('b'*64);containerId=('c'*64);image=('sha256:'+('d'*64));sourceRecord='historical'
        stateVolume='historical-state';receipt=@{sha256=@{fixture='digest'}}}
    Assert-BackupCleanupCandidate $Id $Record @('current','previous') 'current-backup' 'historical-backup'
    foreach($Protected in @('historical','HISTORICAL')){
        $Rejected=$false
        try{Assert-BackupCleanupCandidate $Id $Record @($Protected) 'current-backup' 'historical-backup'}
        catch{if($_.Exception.Message -cne 'BACKUP_CLEANUP_RECOVERY_PROTECTED'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'BACKUP_CLEANUP_PROTECTED_SELFTEST_FAILED'}
    }
    $Name='fortis-gateway-backup-'+$Id
    $Root='/var/lib/docker/volumes/'+$Name+'/_data'
    Assert-BackupCleanupUnheld $Name @([pscustomobject]@{Mounts=@([pscustomobject]@{Name='unrelated';Source='/unrelated'})})
    foreach($Mount in @([pscustomobject]@{Name=$Name;Source=$Root},[pscustomobject]@{Source=($Root+'/nested')},[pscustomobject]@{Source='/var/lib/docker/volumes'})){
        $Rejected=$false
        try{Assert-BackupCleanupUnheld $Name @([pscustomobject]@{Mounts=@($Mount)})}
        catch{if($_.Exception.Message -cne 'BACKUP_CLEANUP_VOLUME_HELD'){throw};$Rejected=$true}
        if(-not $Rejected){throw 'BACKUP_CLEANUP_HOLDER_SELFTEST_FAILED'}
    }
    Write-Host 'FORTIS_BACKUP_CLEANUP_SELECTION_SELFTEST_PASS'
}

# Enumerate the bounded owner record/evidence tree without following junctions.
function Get-BackupCleanupReferenceFiles {
    param([string]$Root)
    if(-not (Test-Path -LiteralPath $Root -PathType Container)){throw 'BACKUP_CLEANUP_REFERENCE_ROOT_MISSING'}
    $Pending=New-Object 'System.Collections.Generic.Queue[string]'
    $Pending.Enqueue($Root)
    $Count=0
    while($Pending.Count){
        $Directory=$Pending.Dequeue()
        if((Get-Item -LiteralPath $Directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'BACKUP_CLEANUP_REFERENCE_SCAN_INCOMPLETE'}
        foreach($Item in @(Get-ChildItem -LiteralPath $Directory -Force | Sort-Object FullName)){
            $Count++
            if($Count -gt 4096 -or ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)){
                throw 'BACKUP_CLEANUP_REFERENCE_SCAN_INCOMPLETE'
            }
            if($Item.PSIsContainer){$Pending.Enqueue($Item.FullName);continue}
            if($Item.Extension -in @('.json','.txt','.log','.ps1','.md')){
                if($Item.Length -gt 16MB){throw 'BACKUP_CLEANUP_REFERENCE_SCAN_INCOMPLETE'}
                $Item
            }
        }
    }
}

function Get-BackupCleanupVolumeIdentity {
    param([string]$Id)
    $Name='fortis-gateway-backup-'+$Id
    Assert-Volume $Name
    $V=@(Docker-Json @('volume','inspect',$Name))[0]
    if($V.Labels.'io.fortis.primary-backup' -cne $Id -or -not $V.CreatedAt){throw 'BACKUP_CLEANUP_VOLUME_PROVENANCE_INVALID'}
    return @{name=$Name;createdAt=$V.CreatedAt}
}
function Get-BackupCleanupContainerIds {
    return @((Docker-Text @('ps','-aq','--no-trunc')) -split '\r?\n' | Where-Object {$_} | Sort-Object)
}
function Assert-BackupCleanupUnheld {
    param([string]$Name,[object[]]$Holders)
    $Root='/var/lib/docker/volumes/'+$Name+'/_data'
    foreach($Holder in $Holders){
        foreach($Mount in @($Holder.Mounts)){
            $MountSource=[string]$Mount.Source
            $MountName=$Mount.PSObject.Properties['Name']
            if(($null -ne $MountName -and $MountName.Value -ceq $Name) -or ($MountSource -and
                ($MountSource -ceq $Root -or $MountSource.StartsWith($Root+'/',[StringComparison]::Ordinal) -or
                 $Root.StartsWith($MountSource.TrimEnd('/')+'/',[StringComparison]::Ordinal)))){
                throw 'BACKUP_CLEANUP_VOLUME_HELD'
            }
        }
    }
}

function Get-BackupCleanupIncidentHolds {
    param([string]$ContainerId,[string[]]$Ids)
    # Only the existing Core audit, read-only, no claim/close/reconcile.
    $Code=@'
import json, sqlite3, sys
ids = set(json.load(sys.stdin))
holds = set()
db = sqlite3.connect('file:/state/private/approvals.sqlite?mode=ro', uri=True, timeout=5)
try:
    db.execute('PRAGMA query_only=ON')
    for (raw,) in db.execute("SELECT detail FROM events WHERE state='CLOSED_UNCONFIRMED'"):
        detail = json.loads(raw)
        volume = detail.get('backupVolumeOwnerAttested')
        if isinstance(volume, str) and volume.startswith('fortis-gateway-backup-'):
            ident = volume[len('fortis-gateway-backup-'):]
            if ident in ids:
                holds.add(ident)
    print(json.dumps({'holds': sorted(holds)}))
finally:
    db.close()
'@
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<backup-cleanup-incident-read>','exec'))"
    $Payload=ConvertTo-Json -InputObject @($Ids) -Compress
    $Result=(Private-Process @('exec','-i','--user','10001:10001',$ContainerId,'python','-I','-B','-c',$Wrapper) $Payload)|ConvertFrom-Json
    if($null -eq $Result.holds){throw 'BACKUP_CLEANUP_INCIDENT_READ_INVALID'}
    if(@($Result.holds).Count){throw 'BACKUP_CLEANUP_INCIDENT_HOLD'}
}

function Get-BackupCleanupPlan {
    param([string[]]$Ids,[switch]$PinsOnly)
    $BackupPointer=Join-Path $ReleaseBase 'primary-backup.json'
    $Paths=@($Pointer,$PrimaryPointer,$AttemptPointer,$BackupPointer)
    $Pins=[ordered]@{}
    foreach($Path in $Paths){
        $null=Read-Private $Path
        $Pins[(Split-Path $Path -Leaf)]=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    }
    $Primary=Read-Private $PrimaryPointer
    $Current=(Read-Private $Pointer).record
    $AttemptPath=(Read-Private $AttemptPointer).record
    $Attempt=Read-Private $AttemptPath
    $Source=Get-SourceRecord
    if($Current -cne $Primary.sourceRecord -or $AttemptPath -cne $Current -or
       $Source.path -cne $Current -or $Attempt.phase -cne 'Complete' -or
       $Source.runtime.pilotName -cne 'fortis-gateway' -or
       $Source.runtime.restartPolicy -cne 'unless-stopped'){
        throw 'BACKUP_CLEANUP_PRIMARY_NOT_SETTLED'
    }
    $P=$Source.runtime
    $script:Image=$P.image
    $C=Container $P.pilotId
    Admit $C $P
    if($C.State.Status -cne 'running' -or $C.State.Health.Status -cne 'healthy'){
        throw 'BACKUP_CLEANUP_PRIMARY_NOT_HEALTHY'
    }
    Assert-OnlyWriter $P.stateVolume $C.Id
    $ProtectedSources=@($Current)
    $ProtectedHashes=@($Source.hash)
    $ProtectedContainers=@($P.pilotId)
    $ProtectedState=@($P.stateVolume)
    if($Primary.previousPrimaryRecord){
        $Previous=Read-Private $Primary.previousPrimaryRecord
        if($Previous.phase -cne 'Complete' -or $Previous.schema -cne 'fortis-extension-release-v1' -or
           -not $Previous.runtime.pilotId -or -not $Previous.runtime.stateVolume){
            throw 'BACKUP_CLEANUP_PREVIOUS_SOURCE_UNKNOWN'
        }
        $ProtectedSources+=@($Primary.previousPrimaryRecord)
        $ProtectedHashes+=@((Get-FileHash -LiteralPath $Primary.previousPrimaryRecord -Algorithm SHA256).Hash)
        $ProtectedContainers+=@($Previous.runtime.pilotId)
        $ProtectedState+=@($Previous.runtime.stateVolume)
    }
    $ProtectedBackupPath=(Read-Private $BackupPointer).record
    $CurrentBackup=Read-Private $ProtectedBackupPath
    if($CurrentBackup.backupVolume -cnotmatch '^fortis-gateway-backup-([0-9a-f]{32})$'){throw 'BACKUP_CLEANUP_CURRENT_BACKUP_INVALID'}
    $CurrentBackupId=$CurrentBackup.backupVolume.Substring('fortis-gateway-backup-'.Length)
    if($ProtectedBackupPath -ine (Join-Path $ReleaseBase ('primary-backup-'+$CurrentBackupId+'\record.json'))){throw 'BACKUP_CLEANUP_CURRENT_BACKUP_INVALID'}
    $null=Get-BackupCleanupVolumeIdentity $CurrentBackupId
    if($CurrentBackup.schema -cne 'fortis-primary-backup-v1' -or $CurrentBackup.phase -cne 'Complete' -or
       $CurrentBackup.sourceRecord -cne $Source.path -or $CurrentBackup.sourceHash -cne $Source.hash -or
       $CurrentBackup.containerId -cne $C.Id -or $CurrentBackup.image -cne $P.image -or
       $CurrentBackup.stateVolume -cne $P.stateVolume -or
       -not (Same-Json (Receipt $CurrentBackup.backupVolume) $CurrentBackup.receipt)){
        throw 'BACKUP_CLEANUP_CURRENT_BACKUP_INVALID'
    }
    # All current and predecessor backup records remain active recovery
    # dependencies, including equal-content duplicates. Verify their identities
    # and require an extant previous backup when there is a previous Primary.
    $ProtectedBackups=@()
    $PriorFound=(-not $Primary.previousPrimaryRecord)
    $CurrentFound=$false
    $Directories=@(Get-ChildItem -LiteralPath $ReleaseBase -Directory -Filter 'primary-backup-*' | Sort-Object Name)
    if($Directories.Count -gt 128){throw 'RELEASE_EMERGENCY_PROMOTE_BACKUP_SCAN_LIMIT'}
    foreach($Directory in $Directories){
        if($Directory.Name -cnotmatch '^primary-backup-([0-9a-f]{32})$'){continue}
        $ProtectedId=$Directory.Name.Substring('primary-backup-'.Length)
        $ProtectedPath=Join-Path $Directory.FullName 'record.json'
        if(-not (Test-Path -LiteralPath $ProtectedPath -PathType Leaf)){continue}
        $B=Read-Private $ProtectedPath
        if($ProtectedSources -notcontains $B.sourceRecord -and $ProtectedHashes -notcontains $B.sourceHash -and
           $ProtectedContainers -notcontains $B.containerId -and $ProtectedState -notcontains $B.stateVolume){continue}
        if($B.schema -cne 'fortis-primary-backup-v1' -or $B.phase -cne 'Complete' -or
           $B.backupVolume -cne ('fortis-gateway-backup-'+$ProtectedId) -or -not $B.receipt -or
           (Get-FileHash -LiteralPath $B.sourceRecord -Algorithm SHA256).Hash -ine $B.sourceHash){throw 'BACKUP_CLEANUP_PROTECTED_BACKUP_INVALID'}
        $Identity=Get-BackupCleanupVolumeIdentity $ProtectedId
        $ProtectedBackups+=@([ordered]@{id=$ProtectedId;createdAt=$Identity.createdAt
            recordHash=(Get-FileHash -LiteralPath $ProtectedPath -Algorithm SHA256).Hash})
        if($ProtectedPath -ieq $ProtectedBackupPath){$CurrentFound=$true}
        if($Primary.previousPrimaryRecord -and $B.sourceRecord -ieq $Primary.previousPrimaryRecord -and
           $B.containerId -ceq $Previous.runtime.pilotId -and $B.image -ceq $Previous.runtime.image -and
           $B.stateVolume -ceq $Previous.runtime.stateVolume){$PriorFound=$true}
    }
    if(-not $CurrentFound -or -not $PriorFound){throw 'BACKUP_CLEANUP_PROTECTED_BACKUP_MISSING'}
    if($PinsOnly){
        $PreviousVolume='';$PreviousId='';$PreviousImage=''
        if($Primary.previousPrimaryRecord){
            $Old=Container $Previous.runtime.pilotId
            $PreviousVolume=$Previous.runtime.stateVolume
            Assert-Volume $PreviousVolume
            $PreviousId=$Old.Id;$PreviousImage=$Old.Image
            if($Old.Id -cne $Previous.runtime.pilotId -or $Old.Image -cne $Previous.runtime.image -or
               $Old.State.Status -cne 'exited' -or $Old.HostConfig.RestartPolicy.Name -cne 'no' -or
               @($Old.Mounts | Where-Object {$_.Destination -ceq '/state' -and $_.Name -ceq $PreviousVolume}).Count -ne 1){
                throw 'RELEASE_STATE_CLEANUP_PREVIOUS_PRIMARY_CHANGED'
            }
        }
        return [ordered]@{primaryId=$C.Id;image=$C.Image;stateVolume=$P.stateVolume;pointers=$Pins
            sourceHash=$Source.hash;currentBackup=$CurrentBackup.backupVolume;protectedBackups=$ProtectedBackups
            previousId=$PreviousId;previousImage=$PreviousImage;previousVolume=$PreviousVolume
            previousRecordHash=$(if($PreviousId){$ProtectedHashes[1]}else{''})}
    }
    $HistoricalCleanupRecords=@()
    foreach($Directory in @(Get-ChildItem -LiteralPath $ReleaseBase -Directory -Filter 'primary-cleanup-*')){
        if($Directory.Name -cnotmatch '^primary-cleanup-[0-9a-f]{32}$'){throw 'BACKUP_CLEANUP_PRIOR_ATTEMPT_INVALID'}
        $EarlierPath=Join-Path $Directory.FullName 'record.json'
        $Earlier=Read-Private $EarlierPath
        if($Earlier.schema -cne 'fortis-backup-cleanup-v1' -or $Earlier.phase -cne 'Complete'){
            throw 'BACKUP_CLEANUP_PRIOR_ATTEMPT_REQUIRES_READBACK'
        }
        $EarlierSelected=@($Earlier.plan.selected | ForEach-Object {$_.id})
        $EarlierRemoved=@($Earlier.removed)
        if(-not $EarlierSelected.Count -or $EarlierSelected.Count -ne $EarlierRemoved.Count -or
           ($EarlierSelected -join ',') -cne ($EarlierRemoved -join ',')){
            throw 'BACKUP_CLEANUP_PRIOR_ATTEMPT_INVALID'
        }
        if(@($Ids | Where-Object {$EarlierRemoved -contains $_}).Count){
            throw 'BACKUP_CLEANUP_ID_ALREADY_RETIRED'
        }
        $HistoricalCleanupRecords+=@($EarlierPath)
    }
    $ContainerIds=@(Get-BackupCleanupContainerIds)
    $Holders=@(Inspect-Containers $ContainerIds)
    $Rows=@()
    foreach($Id in $Ids){
        $Path=Join-Path $ReleaseBase ('primary-backup-'+$Id+'\record.json')
        $Record=Read-Private $Path
        Assert-BackupCleanupCandidate $Id $Record $ProtectedSources $ProtectedBackupPath $Path
        if($ProtectedHashes -contains $Record.sourceHash -or $ProtectedContainers -contains $Record.containerId -or
           $ProtectedState -contains $Record.stateVolume){throw 'BACKUP_CLEANUP_RECOVERY_PROTECTED'}
        $Historical=Read-Private $Record.sourceRecord
        if($Historical.phase -cne 'Complete' -or $Historical.schema -cne 'fortis-extension-release-v1' -or
           $Historical.runtime.pilotId -cne $Record.containerId -or $Historical.runtime.image -cne $Record.image -or
           $Historical.runtime.stateVolume -cne $Record.stateVolume -or
           (Get-FileHash -LiteralPath $Record.sourceRecord -Algorithm SHA256).Hash -ine $Record.sourceHash){
            throw 'BACKUP_CLEANUP_HISTORICAL_SOURCE_CHANGED'
        }
        $Volume=Get-BackupCleanupVolumeIdentity $Id
        Assert-BackupCleanupUnheld $Volume.name $Holders
        $Rows+=@([ordered]@{id=$Id;volume=$Volume.name;createdAt=$Volume.createdAt
            recordHash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
            sourceHash=$Record.sourceHash;evidence=@()})
    }
    foreach($File in @(Get-BackupCleanupReferenceFiles $ReleaseBase)){
        # Completed cleanup records are immutable evidence, not new recovery
        # holds on the backups that were protected at the time.
        if($HistoricalCleanupRecords -contains $File.FullName){continue}
        $Content=Get-Content -LiteralPath $File.FullName -Raw
        if(-not $Content){continue}
        foreach($Row in $Rows){
            $Own=Join-Path $ReleaseBase ('primary-backup-'+$Row.id+'\record.json')
            if($File.FullName -ine $Own -and $Content.IndexOf($Row.id,[StringComparison]::OrdinalIgnoreCase) -ge 0){
                throw 'BACKUP_CLEANUP_RELEASE_RECORD_REFERENCE'
            }
        }
    }
    $EvidenceRoot=Join-Path $env:LOCALAPPDATA 'Fortis\OwnerEvidence'
    foreach($File in @(Get-BackupCleanupReferenceFiles $EvidenceRoot)){
        $Content=Get-Content -LiteralPath $File.FullName -Raw
        if(-not $Content){continue}
        foreach($Row in $Rows){
            if($Content.IndexOf($Row.id,[StringComparison]::OrdinalIgnoreCase) -ge 0){
                $Row.evidence+=@([ordered]@{path=$File.FullName.Substring($EvidenceRoot.Length+1)
                    sha256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash})
            }
        }
    }
    Get-BackupCleanupIncidentHolds $C.Id $Ids
    foreach($Path in $Paths){
        if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -cne $Pins[(Split-Path $Path -Leaf)]){
            throw 'BACKUP_CLEANUP_POINTER_CHANGED'
        }
    }
    if((@(Get-BackupCleanupContainerIds) -join ',') -cne ($ContainerIds -join ',')){throw 'BACKUP_CLEANUP_INVENTORY_CHANGED'}
    return [ordered]@{schema='fortis-backup-cleanup-preview-v1';primaryId=$C.Id;image=$C.Image
        stateVolume=$P.stateVolume;pointers=$Pins;sourceHash=$Source.hash;currentBackup=$CurrentBackup.backupVolume
        protected=$ProtectedBackups;containerIds=$ContainerIds;selected=$Rows}
}

function Backup-Cleanup {
    param([string]$Selection,[switch]$PreviewOnly)
    $Ids=@(Get-BackupCleanupIds $Selection)
    $Plan=Get-BackupCleanupPlan $Ids
    $Json=ConvertTo-Json -InputObject $Plan -Depth 12 -Compress
    if($Json.Length -gt 262144){throw 'BACKUP_CLEANUP_PREVIEW_LIMIT'}
    $Digest=Sha256-Utf8 $Json
    Write-Host $Json
    Write-Host ('FORTIS_BACKUP_CLEANUP_PREVIEW '+$Digest)
    if($PreviewOnly){return}
    # Exact owner decision includes evidence references and external holds that
    # cannot be inferred from Docker metadata. No confirmation switch or Auto.
    $Confirmation=Read-Host ('Review all evidence/holds, retained recovery and exclusive maintenance window. Type CLEANUP '+$Digest)
    if($Confirmation -cne ('CLEANUP '+$Digest)){throw 'BACKUP_CLEANUP_OWNER_GO_REQUIRED'}
    if(-not (Same-Json (Get-BackupCleanupPlan $Ids) $Plan)){throw 'BACKUP_CLEANUP_PREVIEW_CHANGED'}
    # The protected record preserves the precise selected set and partial
    # outcome without altering any existing release or backup receipt.
    $Directory=Join-Path $ReleaseBase ('primary-cleanup-'+[Guid]::NewGuid().ToString('N'))
    Protect-Directory $Directory
    $ResultPath=Join-Path $Directory 'record.json'
    $Result=[ordered]@{schema='fortis-backup-cleanup-v1';phase='Prepared';previewDigest=$Digest
        plan=$Plan;removed=@();failedId=''}
    Write-Private $ResultPath $Result
    try {
        foreach($Row in $Plan.selected){
            $Result.failedId=$Row.id
            # Container mounts cannot change without a new container identity.
            # The owner holds an exclusive maintenance window; the common
            # controller lock prevents competing releases, and Docker rejects
            # an in-use named volume. Never use force or prune.
            if((@(Get-BackupCleanupContainerIds) -join ',') -cne ($Plan.containerIds -join ',')){throw 'BACKUP_CLEANUP_INVENTORY_CHANGED'}
            $Volume=Get-BackupCleanupVolumeIdentity $Row.id
            $RecordPath=Join-Path $ReleaseBase ('primary-backup-'+$Row.id+'\record.json')
            if($Volume.createdAt -cne $Row.createdAt -or
               (Get-FileHash -LiteralPath $RecordPath -Algorithm SHA256).Hash -cne $Row.recordHash){throw 'BACKUP_CLEANUP_VOLUME_CHANGED'}
            $null=Docker-Text @('volume','rm',$Row.volume)
            $Remaining=@((Docker-Text @('volume','ls','-q')) -split '\r?\n')
            if($Remaining -ccontains $Row.volume){throw 'BACKUP_CLEANUP_VOLUME_STILL_PRESENT'}
            $Result.removed+=@($Row.id)
            $Result.failedId=''
            Write-Private $ResultPath $Result
        }
        $Remaining=@((Docker-Text @('volume','ls','-q')) -split '\r?\n')
        foreach($Row in $Plan.selected){
            if($Remaining -ccontains $Row.volume){throw 'BACKUP_CLEANUP_VOLUME_STILL_PRESENT'}
        }
        foreach($Name in $Plan.pointers.Keys){
            if((Get-FileHash -LiteralPath (Join-Path $ReleaseBase $Name) -Algorithm SHA256).Hash -cne $Plan.pointers[$Name]){
                throw 'BACKUP_CLEANUP_POINTER_CHANGED_AFTER_EFFECT'
            }
        }
        foreach($Protected in $Plan.protected){
            $Identity=Get-BackupCleanupVolumeIdentity $Protected.id
            $RecordPath=Join-Path $ReleaseBase ('primary-backup-'+$Protected.id+'\record.json')
            if($Identity.createdAt -cne $Protected.createdAt -or
               (Get-FileHash -LiteralPath $RecordPath -Algorithm SHA256).Hash -cne $Protected.recordHash){throw 'BACKUP_CLEANUP_PROTECTED_CHANGED_AFTER_EFFECT'}
        }
        $Final=Container $Plan.primaryId
        $FinalSource=Get-SourceRecord
        if($Final.Image -cne $Plan.image -or $Final.State.Status -cne 'running' -or $Final.State.Health.Status -cne 'healthy' -or
           $FinalSource.hash -cne $Plan.sourceHash -or $FinalSource.runtime.stateVolume -cne $Plan.stateVolume -or
           $Final.HostConfig.RestartPolicy.Name -cne 'unless-stopped' -or
           (@(Get-BackupCleanupContainerIds) -join ',') -cne ($Plan.containerIds -join ',')){
            throw 'BACKUP_CLEANUP_PRIMARY_CHANGED_AFTER_EFFECT'
        }
        $Result.phase='Complete'
        Write-Private $ResultPath $Result
    } catch {
        $Result.phase='RecoveryRequired'
        Write-Private $ResultPath $Result
        throw 'BACKUP_CLEANUP_OUTCOME_REQUIRES_READBACK'
    }
    Write-Host ('FORTIS_BACKUP_CLEANUP_VERIFIED '+($Result.removed -join ','))
}


# Validate the selected run and exact holder independently of reference admission.
function Assert-ReleaseStateCleanupCandidate {
    param([string]$Id,$Record,$Holder,[switch]$FormerPrimary)
    $Volume='fortis-github-pilot-state-'+$Id
    $ExpectedPhase=if($FormerPrimary){'Complete'}else{'Returned'}
    if($Record.schema -cne 'fortis-extension-release-v1' -or $Record.phase -cne $ExpectedPhase -or
       $Record.activated -isnot [bool] -or $Record.activated -ne [bool]$FormerPrimary -or
       $Record.probesPassed -isnot [bool] -or $Record.probesPassed -ne [bool]$FormerPrimary -or
       $Record.PSObject.Properties['registryReturn'] -or $Record.PSObject.Properties['registryCrash'] -or
       $Record.PSObject.Properties['registryReturnAttempt'] -or $Record.PSObject.Properties['retainedSourceRecord'] -or
       $Record.runtime.runId -cne $Id -or $Record.runtime.stateVolume -cne $Volume -or
       $Record.source.runtime.stateVolume -ceq $Volume -or
       $Record.runtime.pilotId -cnotmatch '^[0-9a-f]{64}$' -or
       $Record.runtime.pilotName -cne ('fortis-github-pilot-'+$Id) -or
       $Record.runtime.image -cnotmatch '^sha256:[0-9a-f]{64}$'){
        throw 'RELEASE_STATE_CLEANUP_RECORD_NOT_RETIRED_CANDIDATE'
    }
    if($Holder.Id -cne $Record.runtime.pilotId -or $Holder.Name -cne ('/'+$Record.runtime.pilotName) -or
       $Holder.Image -cne $Record.runtime.image -or $Holder.Config.Labels.'io.fortis.review-update' -cne $Id -or
       $Holder.HostConfig.RestartPolicy.Name -cne 'no' -or $Holder.State.Status -cnotin @('created','exited') -or
       $Holder.State.Running -ne $false -or ($FormerPrimary -and $Holder.State.Status -cne 'exited')){
        throw 'RELEASE_STATE_CLEANUP_HOLDER_INVALID'
    }
    $State=@($Holder.Mounts | Where-Object { $_.Destination -ceq '/state' })
    if($State.Count -ne 1 -or $State[0].Type -cne 'volume' -or $State[0].Name -cne $Volume -or
       $State[0].Source -cne ('/var/lib/docker/volumes/'+$Volume+'/_data') -or $State[0].RW -ne $true -or
       @($Holder.Mounts | Where-Object {$_.Type -ceq 'bind' -or ($_.Source -clike '/var/lib/docker/volumes/fortis-github-pilot-state-*' -and $_.Destination -cne '/state')}).Count){
        throw 'RELEASE_STATE_CLEANUP_HOLDER_MOUNT_INVALID'
    }
}

function Get-ReleaseStateRetirementPath {
    param([string]$Id)
    if($Id -cnotmatch '^[0-9a-f]{32}$'){throw 'RELEASE_STATE_CLEANUP_RUN_ID_INVALID'}
    return (Join-Path (Join-Path $ReleaseBase $Id) 'state-retirement.json')
}

function Assert-ReleaseStateAttemptAvailable {
    # Only normal release records can own a retirement receipt. Its presence
    # fences even a Prepared/partial cleanup from an explicit historical Return.
    $Id=$script:R.runtime.runId
    if($Id -cmatch '^[0-9a-f]{32}$' -and
       (Test-Path -LiteralPath (Get-ReleaseStateRetirementPath $Id))){
        throw 'RELEASE_STATE_CLEANUP_ATTEMPT_RETIRED_OR_REQUIRES_READBACK'
    }
}

function Get-ReleaseStateCleanupVolume {
    param([string]$Id)
    $Name='fortis-github-pilot-state-'+$Id
    Assert-Volume $Name
    $V=@(Docker-Json @('volume','inspect',$Name))[0]
    if($V.Labels.'io.fortis.release' -cne $Id -or -not $V.CreatedAt){
        throw 'RELEASE_STATE_CLEANUP_VOLUME_PROVENANCE_INVALID'
    }
    return [string]$V.CreatedAt
}

function Test-CompletedBackupCleanupReceipt {
    param([string]$Text,$Receipt)
    if($Receipt.schema -cne 'fortis-backup-cleanup-v1' -or $Receipt.phase -cne 'Complete' -or
       $Receipt.failedId -cne '' -or $Receipt.plan.schema -cne 'fortis-backup-cleanup-preview-v1' -or
       $Receipt.plan.containerIds -isnot [array] -or -not $Receipt.plan.containerIds.Count -or
       @($Receipt.plan.containerIds | Where-Object {$_ -isnot [string] -or $_ -cnotmatch '^[0-9a-f]{64}$'}).Count){
        return $false
    }
    $Selected=@($Receipt.plan.selected | ForEach-Object {$_.id})
    if(-not $Selected.Count -or @($Selected | Where-Object {$_ -cnotmatch '^[0-9a-f]{32}$'}).Count -or
       $Receipt.removed -isnot [array] -or ($Selected -join ',') -cne ($Receipt.removed -join ',')){
        return $false
    }
    # Match the writer exactly before projecting away any historical fields.
    return ((ConvertTo-Json -InputObject $Receipt -Depth 25) -ceq $Text)
}

function Get-ReleaseStateHolderReferenceText {
    param([string]$Text,$Receipt)
    if(-not (Test-CompletedBackupCleanupReceipt $Text $Receipt)){return $Text}
    $Receipt.plan.PSObject.Properties.Remove('containerIds')
    return (ConvertTo-Json -InputObject $Receipt -Depth 25)
}

function Test-ReleaseStateSourceBinding {
    param($Source,$Row,[string]$Path)
    return ($null -ne $Source -and $Source.path -ieq $Path -and
        $Source.hash -ceq $Row.recordHash -and $Source.runtime.runId -ceq $Row.id -and
        $Source.runtime.pilotId -ceq $Row.holderId -and $Source.runtime.stateVolume -ceq $Row.volume -and
        $Source.runtime.image -ceq $Row.holderImage -and
        $Source.runtime.pilotName -cin @('fortis-gateway',('fortis-github-pilot-'+$Row.id)) -and
        (-not $Source.runtime.PSObject.Properties['originalPilotName'] -or
         $Source.runtime.originalPilotName -ceq ('fortis-github-pilot-'+$Row.id)))
}

function Get-FormerPrimaryProof {
    param($Row,$Primary,[string]$PreviousPath)
    if($Row.holderId -cin @($Primary.primaryId,$Primary.previousId) -or
       $Row.volume -cin @($Primary.stateVolume,$Primary.previousVolume)){
        throw 'RELEASE_STATE_CLEANUP_PRIMARY_PROTECTED'
    }
    $TargetPath=Join-Path (Join-Path $ReleaseBase $Row.id) 'record.json'
    $Path=$PreviousPath
    $Hash=$Primary.previousRecordHash
    $Visited=@{}
    while($Path){
        if($Visited.Count -ge 4096 -or $Visited.ContainsKey($Path)){
            throw 'RELEASE_STATE_CLEANUP_LINEAGE_INVALID'
        }
        $Visited[$Path]=$true
        $Successor=Read-Private $Path
        if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -cne $Hash -or
           $Successor.schema -cne 'fortis-extension-release-v1' -or $Successor.phase -cne 'Complete' -or
           $Successor.activated -isnot [bool] -or -not $Successor.activated -or
           $Successor.probesPassed -isnot [bool] -or -not $Successor.probesPassed){
            throw 'RELEASE_STATE_CLEANUP_LINEAGE_INVALID'
        }
        $Field=$Successor.PSObject.Properties['source']
        if(-not $Field -or -not $Field.Value){break}
        $Source=$Field.Value
        $Run=$Source.runtime.runId
        if($Run -cnotmatch '^[0-9a-f]{32}$' -or $Source.hash -cnotmatch '^[0-9A-F]{64}$' -or
           $Source.path -ine (Join-Path (Join-Path $ReleaseBase $Run) 'record.json')){break}
        if($Source.path -ieq $TargetPath){
            if((Test-ReleaseStateSourceBinding $Source $Row $TargetPath) -and
               $Source.runtime.pilotName -ceq 'fortis-gateway' -and
               $Source.runtime.originalPilotName -ceq ('fortis-github-pilot-'+$Row.id) -and
               $Source.runtime.restartPolicy -ceq 'unless-stopped'){
                return $Hash
            }
            break
        }
        $Path=$Source.path
        $Hash=$Source.hash
    }
    throw 'RELEASE_STATE_CLEANUP_FORMER_PRIMARY_UNPROVEN'
}

function Get-HistoricalReleaseStateReferenceText {
    param([string]$Text,$Record,[string]$Path,$Row,$Primary,[string]$CurrentPath,[string]$AutoCheckPath)
    $TargetPath=Join-Path (Join-Path $ReleaseBase $Row.id) 'record.json'
    $Directory=Split-Path -Parent $Path
    $Name=Split-Path -Leaf $Directory
    if((Split-Path -Leaf $Path) -cne 'record.json' -or (Split-Path -Parent $Directory) -ine $ReleaseBase -or
       $Path -ieq $CurrentPath -or $Path -ieq $AutoCheckPath){return $Text}
    # Refuse to project a document if its parsed form lost any occurrences
    # of either identity (for example duplicate JSON keys).
    $Normalized=ConvertTo-Json -InputObject $Record -Depth 100 -Compress
    foreach($Identity in @($Row.id,$Row.holderId)){
        $Needle='(?i)'+$Identity
        if([regex]::Matches($Text,$Needle).Count -ne [regex]::Matches($Normalized,$Needle).Count){return $Text}
    }
    if($Name -cmatch '^[0-9a-f]{32}$' -and $Record.schema -ceq 'fortis-extension-release-v1'){
        $Emergency=$Record.PSObject.Properties['emergencyRecovery']
        if($Emergency -and $Emergency.Value -and $Emergency.Value.ownerAcceptedUnverifiedRestore -ne $false){
            return $Text
        }
        if($Record.phase -cnotin @('Complete','Returned') -or
           $Record.activated -isnot [bool] -or $Record.probesPassed -isnot [bool] -or
           $Record.activated -ne ($Record.phase -ceq 'Complete') -or $Record.probesPassed -ne $Record.activated -or
           $Record.PSObject.Properties['registryReturn'] -or $Record.PSObject.Properties['registryCrash'] -or
           $Record.PSObject.Properties['registryReturnAttempt'] -or $Record.PSObject.Properties['retainedSourceRecord'] -or
           -not $Record.PSObject.Properties['source'] -or
           -not (Test-ReleaseStateSourceBinding $Record.source $Row $TargetPath)){return $Text}
        $Record.source.PSObject.Properties.Remove('path')
        foreach($Key in @('runId','pilotId','stateVolume','pilotName','originalPilotName')){
            $Record.source.runtime.PSObject.Properties.Remove($Key)
        }
    } elseif($Name -cmatch '^image-check-[0-9a-f]{32}$' -and $Record.schema -ceq 'fortis-extension-image-check-v1'){
        $Binding=$Record.binding
        if($Record.phase -cne 'Ready' -or $Binding.sourceRecord -ine $TargetPath -or
           $Binding.sourceHash -cne $Row.recordHash -or $Binding.sourceRunId -cne $Row.id -or
           $Binding.sourceStateVolume -cne $Row.volume -or $Binding.sourceContainerId -cne $Row.holderId -or
           $Binding.sourceImage -cne $Row.holderImage -or
           $Binding.PSObject.Properties['registryReturn'] -or $Binding.PSObject.Properties['registryCrash'] -or
           $Binding.currentPointerHash -cnotmatch '^[0-9A-F]{64}$' -or
           $Binding.currentPointerHash -ceq $Primary.pointers['current.json']){return $Text}
        foreach($Key in @('sourceRecord','sourceRunId','sourceStateVolume','sourceContainerId')){
            $Binding.PSObject.Properties.Remove($Key)
        }
    } elseif($Name -cmatch '^primary-backup-[0-9a-f]{32}$' -and $Record.schema -ceq 'fortis-primary-backup-v1'){
        if($Record.phase -cne 'Complete' -or $Record.sourceRecord -ine $TargetPath -or
           $Record.sourceHash -cne $Row.recordHash -or $Record.stateVolume -cne $Row.volume -or
           $Record.containerId -cne $Row.holderId -or $Record.image -cne $Row.holderImage -or
           $Record.backupVolume -cne ('fortis-gateway-backup-'+$Name.Substring('primary-backup-'.Length)) -or
           $Record.backupVolume -ceq $Primary.currentBackup -or
           @($Primary.protectedBackups | Where-Object {$Name -ceq ('primary-backup-'+$_.id)}).Count){return $Text}
        foreach($Key in @('sourceRecord','stateVolume','containerId')){
            $Record.PSObject.Properties.Remove($Key)
        }
    } elseif($Name -cmatch '^primary-cleanup-[0-9a-f]{32}$' -and (Test-CompletedBackupCleanupReceipt $Text $Record)){
        $Record.plan.PSObject.Properties.Remove('containerIds')
        if($Record.plan.primaryId -ceq $Row.holderId -and $Record.plan.stateVolume -ceq $Row.volume -and
           $Record.plan.image -ceq $Row.holderImage -and $Record.plan.sourceHash -ceq $Row.recordHash){
            $Record.plan.PSObject.Properties.Remove('primaryId')
            $Record.plan.PSObject.Properties.Remove('stateVolume')
        }
    } else {return $Text}
    return (ConvertTo-Json -InputObject $Record -Depth 100 -Compress)
}

function Assert-ReleaseStateSourceAvailable {
    param($Runtime)
    if($null -ne $Runtime -and $Runtime.stateVolume -cmatch '^fortis-github-pilot-state-([0-9a-f]{32})$' -and
       (Test-Path -LiteralPath (Get-ReleaseStateRetirementPath $Matches[1]))){
        throw 'RELEASE_STATE_CLEANUP_SOURCE_RETIRED_OR_REQUIRES_READBACK'
    }
}

function Get-ReleaseStateCleanupPlan {
    param([string[]]$Ids)
    $Primary=Get-BackupCleanupPlan -PinsOnly
    $CurrentPath=(Read-Private $Pointer).record
    $PreviousPath=(Read-Private $PrimaryPointer).previousPrimaryRecord
    $AutoCheckPath=''
    $AutoCheck=Join-Path $ReleaseBase 'auto-check.json'
    $Primary.pointers['auto-check.json']=''
    if(Test-Path -LiteralPath $AutoCheck){
        $Auto=Read-Private $AutoCheck
        if($Auto.schema -cne 'fortis-auto-check-v1' -or -not $Auto.record){
            throw 'RELEASE_STATE_CLEANUP_AUTO_CHECK_INVALID'
        }
        $AutoCheckPath=$Auto.record
        $Check=Read-Private $AutoCheckPath
        if($Check.schema -cne 'fortis-extension-image-check-v1' -or $Check.phase -cne 'Ready'){
            throw 'RELEASE_STATE_CLEANUP_AUTO_CHECK_INVALID'
        }
        $Primary.pointers['auto-check.json']=(Get-FileHash -LiteralPath $AutoCheck -Algorithm SHA256).Hash
    }
    $ContainerIds=@(Get-BackupCleanupContainerIds)
    $Containers=@(Inspect-Containers $ContainerIds)
    $Rows=@(foreach($Id in $Ids){
        $Path=Join-Path (Join-Path $ReleaseBase $Id) 'record.json'
        $Retirement=Get-ReleaseStateRetirementPath $Id
        if(Test-Path -LiteralPath $Retirement){
            throw 'RELEASE_STATE_CLEANUP_PRIOR_ATTEMPT_REQUIRES_READBACK'
        }
        $Hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        $Record=Read-Private $Path
        $Holder=@($Containers | Where-Object {$_.Id -ceq $Record.runtime.pilotId})
        if($Holder.Count -ne 1){throw 'RELEASE_STATE_CLEANUP_EXPECTED_HOLDER_MISSING'}
        $FormerPrimary=($Record.phase -ceq 'Complete')
        Assert-ReleaseStateCleanupCandidate $Id $Record $Holder[0] -FormerPrimary:$FormerPrimary
        $Volume=$Record.runtime.stateVolume
        $CreatedAt=Get-ReleaseStateCleanupVolume $Id
        Assert-BackupCleanupUnheld $Volume @($Containers | Where-Object {$_.Id -cne $Holder[0].Id})
        $Row=[ordered]@{id=$Id;volume=$Volume;createdAt=$CreatedAt;recordHash=$Hash;holderId=$Holder[0].Id
            holderName=$Holder[0].Name;holderImage=$Holder[0].Image;holderStatus=$Holder[0].State.Status
            holderStartedAt=$Holder[0].State.StartedAt;holderFinishedAt=$Holder[0].State.FinishedAt;evidence=@()}
        if($FormerPrimary){
            $Row['formerPrimarySuccessorHash']=Get-FormerPrimaryProof $Row $Primary $PreviousPath
        }
        $Row
    })
    foreach($Directory in @(Get-ChildItem -LiteralPath $ReleaseBase -Directory -Force)){
        if($Directory.Name -cmatch '^(?:(?:image-check-|primary-backup-)?[0-9a-f]{32})$' -and
           -not (Test-Path -LiteralPath (Join-Path $Directory.FullName 'record.json') -PathType Leaf)){
            throw 'RELEASE_STATE_CLEANUP_REFERENCE_SCAN_INCOMPLETE'
        }
    }
    foreach($File in @(Get-BackupCleanupReferenceFiles $ReleaseBase)){
        $Text=Get-Content -LiteralPath $File.FullName -Raw
        if(-not $Text){continue}
        $HolderText=$Text
        if($File.Name -ceq 'record.json' -and $File.Directory.Name -cmatch '^primary-cleanup-[0-9a-f]{32}$' -and
           $File.Directory.Parent.FullName -ieq $ReleaseBase -and
           @($Rows | Where-Object {$Text.IndexOf($_.holderId,[StringComparison]::OrdinalIgnoreCase) -ge 0}).Count){
            # A completed backup cleanup inventories all containers at the
            # time without claiming them as recovery dependencies.
            $HolderText=Get-ReleaseStateHolderReferenceText $Text (Read-Private $File.FullName)
        }
        foreach($Row in $Rows){
            if($File.FullName -ieq (Join-Path (Join-Path $ReleaseBase $Row.id) 'record.json')){continue}
            $RunFound=$Text.IndexOf($Row.id,[StringComparison]::OrdinalIgnoreCase) -ge 0
            $HolderFound=$HolderText.IndexOf($Row.holderId,[StringComparison]::OrdinalIgnoreCase) -ge 0
            if(-not ($RunFound -or $HolderFound)){continue}
            if($Row.Contains('formerPrimarySuccessorHash') -and $File.Name -ceq 'record.json' -and
               $File.Directory.Parent.FullName -ieq $ReleaseBase -and
               $File.Directory.Name -cmatch '^(?:(?:image-check-|primary-backup-|primary-cleanup-)?[0-9a-f]{32})$'){
                $Remaining=Get-HistoricalReleaseStateReferenceText $Text (Read-Private $File.FullName) $File.FullName $Row $Primary $CurrentPath $AutoCheckPath
                $RunFound=$Remaining.IndexOf($Row.id,[StringComparison]::OrdinalIgnoreCase) -ge 0
                $HolderFound=$Remaining.IndexOf($Row.holderId,[StringComparison]::OrdinalIgnoreCase) -ge 0
            }
            if($RunFound -or $HolderFound){
                throw ('RELEASE_STATE_CLEANUP_PROTECTED_REFERENCE: '+$Row.id)
            }
        }
    }
    $EvidenceRoot=Join-Path $env:LOCALAPPDATA 'Fortis\OwnerEvidence'
    foreach($File in @(Get-BackupCleanupReferenceFiles $EvidenceRoot)){
        $Text=Get-Content -LiteralPath $File.FullName -Raw
        if(-not $Text){continue}
        foreach($Row in $Rows){
            if($Text.IndexOf($Row.id,[StringComparison]::OrdinalIgnoreCase) -ge 0 -or
               $Text.IndexOf($Row.holderId.Substring(0,12),[StringComparison]::OrdinalIgnoreCase) -ge 0){
                $Row.evidence+=@([ordered]@{path=$File.FullName.Substring($EvidenceRoot.Length+1)
                    sha256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash})
            }
        }
    }
    if((@(Get-BackupCleanupContainerIds) -join ',') -cne ($ContainerIds -join ',')){
        throw 'RELEASE_STATE_CLEANUP_INVENTORY_CHANGED'
    }
    foreach($Row in $Rows){
        # Reuse the read-only marker check used by Registry Return. A
        # Returned record alone cannot prove the volume is still inactive.
        if(-not $Row.Contains('formerPrimarySuccessorHash')){
            Assert-RegistryCandidateInactive @{runId=$Row.id;stateVolume=$Row.volume}
        }
        if((Get-ReleaseStateCleanupVolume $Row.id) -cne $Row.createdAt){
            throw 'RELEASE_STATE_CLEANUP_TARGET_CHANGED'
        }
    }
    return [ordered]@{schema='fortis-release-state-cleanup-preview-v1';primary=$Primary
        containerIds=$ContainerIds;selected=$Rows}
}

function Assert-ReleaseStateCleanupPins {
    param($Plan)
    foreach($Name in $Plan.primary.pointers.Keys){
        $Path=Join-Path $ReleaseBase $Name
        $Hash=if(Test-Path -LiteralPath $Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}else{''}
        if($Hash -cne $Plan.primary.pointers[$Name]){throw 'RELEASE_STATE_CLEANUP_POINTER_CHANGED'}
    }
    foreach($Row in $Plan.selected){
        $Path=Join-Path (Join-Path $ReleaseBase $Row.id) 'record.json'
        if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -cne $Row.recordHash){
            throw 'RELEASE_STATE_CLEANUP_RECORD_CHANGED'
        }
    }
}

function Release-State-Cleanup {
    param([string]$Selection,[switch]$PreviewOnly)
    $Ids=@(Get-BackupCleanupIds $Selection)
    $Plan=Get-ReleaseStateCleanupPlan $Ids
    Assert-ReleaseStateCleanupPins $Plan
    $Json=ConvertTo-Json -InputObject $Plan -Depth 12 -Compress
    if($Json.Length -gt 262144){throw 'RELEASE_STATE_CLEANUP_PREVIEW_LIMIT'}
    $Digest=Sha256-Utf8 $Json
    Write-Host $Json
    Write-Host ('FORTIS_RELEASE_STATE_CLEANUP_PREVIEW '+$Digest)
    if($PreviewOnly){return}
    $Confirmation=Read-Host ('Review referenced evidence and external recovery holds in an exclusive maintenance window. Type CLEANUP '+$Digest)
    if($Confirmation -cne ('CLEANUP '+$Digest)){throw 'RELEASE_STATE_CLEANUP_OWNER_GO_REQUIRED'}
    if(-not (Same-Json (Get-ReleaseStateCleanupPlan $Ids) $Plan)){throw 'RELEASE_STATE_CLEANUP_PREVIEW_CHANGED'}
    $ExpectedContainers=@($Plan.containerIds)
    $Receipts=@()
    foreach($Row in $Plan.selected){
        Assert-ReleaseStateCleanupPins $Plan
        if((@(Get-BackupCleanupContainerIds) -join ',') -cne ($ExpectedContainers -join ',')){
            throw 'RELEASE_STATE_CLEANUP_INVENTORY_CHANGED'
        }
        $Holder=Container $Row.holderId
        $Path=Join-Path (Join-Path $ReleaseBase $Row.id) 'record.json'
        Assert-ReleaseStateCleanupCandidate $Row.id (Read-Private $Path) $Holder -FormerPrimary:($Row.Contains('formerPrimarySuccessorHash'))
        if($Holder.State.Status -cne $Row.holderStatus -or $Holder.State.StartedAt -cne $Row.holderStartedAt -or
           $Holder.State.FinishedAt -cne $Row.holderFinishedAt -or (Get-ReleaseStateCleanupVolume $Row.id) -cne $Row.createdAt){
            throw 'RELEASE_STATE_CLEANUP_TARGET_CHANGED'
        }
        $ReceiptPath=Get-ReleaseStateRetirementPath $Row.id
        if(Test-Path -LiteralPath $ReceiptPath){throw 'RELEASE_STATE_CLEANUP_PRIOR_ATTEMPT_REQUIRES_READBACK'}
        $Result=[ordered]@{schema='fortis-release-state-retirement-v1';phase='Prepared';previewDigest=$Digest
            selected=$Row;holderRemoved=$false;volumeRemoved=$false}
        Write-Private $ReceiptPath $Result
        try {
            $null=Docker-Text @('container','rm',$Row.holderId)
            $ExpectedContainers=@($ExpectedContainers | Where-Object {$_ -cne $Row.holderId})
            $Observed=@(Get-BackupCleanupContainerIds)
            $Result.holderRemoved=($Observed -cnotcontains $Row.holderId)
            Write-Private $ReceiptPath $Result
            if(($Observed -join ',') -cne ($ExpectedContainers -join ',')){
                throw 'RELEASE_STATE_CLEANUP_HOLDER_REMOVAL_UNCONFIRMED'
            }
            if((Get-ReleaseStateCleanupVolume $Row.id) -cne $Row.createdAt){throw 'RELEASE_STATE_CLEANUP_TARGET_CHANGED'}
            $null=Docker-Text @('volume','rm',$Row.volume)
            $Remaining=(Docker-Text @('volume','ls','-q')) -split '\r?\n'
            $Result.volumeRemoved=($Remaining -cnotcontains $Row.volume)
            if(-not $Result.volumeRemoved){throw 'RELEASE_STATE_CLEANUP_VOLUME_STILL_PRESENT'}
            Write-Private $ReceiptPath $Result
            $Receipts+=@(@{path=$ReceiptPath;result=$Result})
        } catch {
            $Result.phase='RecoveryRequired'
            Write-Private $ReceiptPath $Result
            throw ('RELEASE_STATE_CLEANUP_OUTCOME_REQUIRES_READBACK: '+$Row.id)
        }
    }
    Assert-ReleaseStateCleanupPins $Plan
    $Final=Get-BackupCleanupPlan -PinsOnly
    $Final.pointers['auto-check.json']=$Plan.primary.pointers['auto-check.json']
    Assert-ReleaseStateCleanupPins $Plan
    if(-not (Same-Json $Plan.primary $Final) -or
       (@(Get-BackupCleanupContainerIds) -join ',') -cne ($ExpectedContainers -join ',')){
        throw 'RELEASE_STATE_CLEANUP_POSTCONDITIONS_REQUIRE_READBACK'
    }
    $Remaining=(Docker-Text @('volume','ls','-q')) -split '\r?\n'
    foreach($Row in $Plan.selected){
        if($Remaining -ccontains $Row.volume){throw 'RELEASE_STATE_CLEANUP_VOLUME_STILL_PRESENT'}
    }
    foreach($Receipt in $Receipts){
        $Receipt.result.phase='Complete'
        Write-Private $Receipt.path $Receipt.result
    }
    Write-Host ('FORTIS_RELEASE_STATE_CLEANUP_VERIFIED '+($Ids -join ','))
}


function Assert-ReleaseStateCleanupSelectionSelfTest {
    $Id='a'*32
    $Name='fortis-github-pilot-'+$Id
    $Volume='fortis-github-pilot-state-'+$Id
    $Record=[pscustomobject]@{schema='fortis-extension-release-v1';phase='Returned';activated=$false;probesPassed=$false
        source=@{runtime=@{stateVolume='prior-state'}}
        runtime=@{runId=$Id;pilotId=('b'*64);pilotName=$Name;stateVolume=$Volume;image=('sha256:'+('c'*64))}}
    $Holder=@{Id=$Record.runtime.pilotId;Name=('/'+$Name);Image=$Record.runtime.image
        Config=@{Labels=@{'io.fortis.review-update'=$Id}};HostConfig=@{RestartPolicy=@{Name='no'}}
        State=@{Status='exited';Running=$false};Mounts=@(@{Destination='/state';Name=$Volume;Type='volume';RW=$true
            Source=('/var/lib/docker/volumes/'+$Volume+'/_data')})}
    Assert-ReleaseStateCleanupCandidate $Id $Record $Holder
    foreach($Phase in @('Prepared','Created','Staged','Complete')){
        $Record.phase=$Phase
        try {
            Assert-ReleaseStateCleanupCandidate $Id $Record $Holder
            throw 'RELEASE_STATE_CLEANUP_SELECTION_SELFTEST_FAILED'
        } catch {if($_.Exception.Message -cne 'RELEASE_STATE_CLEANUP_RECORD_NOT_RETIRED_CANDIDATE'){throw}}
    }
    $Record.phase='Returned'
    $Record | Add-Member -NotePropertyName registryReturn -NotePropertyValue @{stateVolume='prior-state'}
    try {
        Assert-ReleaseStateCleanupCandidate $Id $Record $Holder
        throw 'RELEASE_STATE_CLEANUP_SELECTION_SELFTEST_FAILED'
    } catch {if($_.Exception.Message -cne 'RELEASE_STATE_CLEANUP_RECORD_NOT_RETIRED_CANDIDATE'){throw}}
    $Record.PSObject.Properties.Remove('registryReturn')
    $Holder.State.Status='running'
    try {
        Assert-ReleaseStateCleanupCandidate $Id $Record $Holder
        throw 'RELEASE_STATE_CLEANUP_SELECTION_SELFTEST_FAILED'
    } catch {if($_.Exception.Message -cne 'RELEASE_STATE_CLEANUP_HOLDER_INVALID'){throw}}

    $BackupId='c'*32
    $InventoryReceipt=[ordered]@{
        schema='fortis-backup-cleanup-v1';phase='Complete';previewDigest=('d'*64)
        plan=[ordered]@{schema='fortis-backup-cleanup-preview-v1';containerIds=@($Holder.Id)
            selected=@([ordered]@{id=$BackupId;createdAt='2026-11-26T01:02:03Z';evidence=@()})}
        removed=@($BackupId);failedId=''
    }
    $Text=ConvertTo-Json -InputObject $InventoryReceipt -Depth 25
    $Filtered=Get-ReleaseStateHolderReferenceText $Text (ConvertFrom-Json -InputObject $Text)
    if($Filtered.Contains($Holder.Id) -or -not $Filtered.Contains($BackupId)){
        throw 'RELEASE_STATE_CLEANUP_INVENTORY_SELFTEST_FAILED'
    }
    $InventoryReceipt.plan['primaryId']=$Holder.Id
    $Text=ConvertTo-Json -InputObject $InventoryReceipt -Depth 25
    $Filtered=Get-ReleaseStateHolderReferenceText $Text (ConvertFrom-Json -InputObject $Text)
    if(-not $Filtered.Contains($Holder.Id)){throw 'RELEASE_STATE_CLEANUP_INVENTORY_REFERENCE_SELFTEST_FAILED'}
    foreach($Phase in @('Prepared','RecoveryRequired','Complete')){
        $InventoryReceipt.phase=$Phase
        if($Phase -ceq 'Complete'){$InventoryReceipt.removed=@()}
        $Text=ConvertTo-Json -InputObject $InventoryReceipt -Depth 25
        if((Get-ReleaseStateHolderReferenceText $Text (ConvertFrom-Json -InputObject $Text)) -cne $Text){
            throw 'RELEASE_STATE_CLEANUP_UNVERIFIED_RECEIPT_SELFTEST_FAILED'
        }
    }
    $InventoryReceipt.removed=@($BackupId)
    $Text=ConvertTo-Json -InputObject $InventoryReceipt -Depth 25 -Compress
    if((Get-ReleaseStateHolderReferenceText $Text (ConvertFrom-Json -InputObject $Text)) -cne $Text){
        throw 'RELEASE_STATE_CLEANUP_NONCANONICAL_RECEIPT_SELFTEST_FAILED'
    }
    Write-Host 'FORTIS_RELEASE_STATE_CLEANUP_INVENTORY_SELFTEST_PASS'
    Write-Host 'FORTIS_RELEASE_STATE_CLEANUP_SELECTION_SELFTEST_PASS'
}

function Assert-FormerPrimaryRetirementSelfTest {
    & {
        $ReleaseBase='C:\fixture\GatewayReleases'
        $A='a'*32; $B='b'*32; $C='c'*32; $D='d'*32
        $Records=@{}
        $Hashes=@{}
        function Read-Private {param($Path) $Records[$Path]}
        function Get-FileHash {param($LiteralPath,$Algorithm) @{Hash=$Hashes[$LiteralPath]}}
        function New-StateFixture {
            param($Run,$Digit)
            [pscustomobject]@{id=$Run;volume=('fortis-github-pilot-state-'+$Run);recordHash=($Digit*64)
                holderId=($Run+$Run);holderImage=('sha256:'+('f'*64))}
        }
        function New-SourceFixture {
            param($Row)
            [pscustomobject]@{path=(Join-Path (Join-Path $ReleaseBase $Row.id) 'record.json')
                hash=$Row.recordHash;runtime=[pscustomobject]@{runId=$Row.id;pilotId=$Row.holderId
                image=$Row.holderImage;stateVolume=$Row.volume;pilotName='fortis-gateway'
                originalPilotName=('fortis-github-pilot-'+$Row.id);restartPolicy='unless-stopped'}}
        }
        $Old=New-StateFixture $A '1'
        $Prior=New-StateFixture $B '2'
        $Active=New-StateFixture $C '3'
        $Next=New-StateFixture $D '4'
        $PriorPath=(New-SourceFixture $Prior).path
        $ActivePath=(New-SourceFixture $Active).path
        $NextPath=(New-SourceFixture $Next).path
        $Records[$PriorPath]=[pscustomobject]@{schema='fortis-extension-release-v1';phase='Complete'
            activated=$true;probesPassed=$true;source=(New-SourceFixture $Old)}
        $Records[$ActivePath]=[pscustomobject]@{schema='fortis-extension-release-v1';phase='Complete'
            activated=$true;probesPassed=$true;source=(New-SourceFixture $Prior)}
        $Hashes[$PriorPath]=$Prior.recordHash
        $Hashes[$ActivePath]=$Active.recordHash
        $Pins=@{primaryId=$Active.holderId;stateVolume=$Active.volume;previousId=$Prior.holderId
            previousVolume=$Prior.volume;previousRecordHash=$Prior.recordHash;pointers=@{'current.json'=('0'*64)}
            currentBackup='current-backup';protectedBackups=@()}
        if((Get-FormerPrimaryProof $Old $Pins $PriorPath) -cne $Prior.recordHash){
            throw 'RELEASE_STATE_CLEANUP_FORMER_PRIMARY_SELFTEST_FAILED'
        }
        foreach($Protected in @($Prior,$Active)){
            try {
                $null=Get-FormerPrimaryProof $Protected $Pins $PriorPath
                throw 'RELEASE_STATE_CLEANUP_FORMER_PRIMARY_SELFTEST_FAILED'
            } catch {if($_.Exception.Message -cne 'RELEASE_STATE_CLEANUP_PRIMARY_PROTECTED'){throw}}
        }
        $PriorSource=$Records[$PriorPath].source
        $PriorSource.runtime.pilotName=$PriorSource.runtime.originalPilotName
        try {
            $null=Get-FormerPrimaryProof $Old $Pins $PriorPath
            throw 'RELEASE_STATE_CLEANUP_FORMER_PRIMARY_SELFTEST_FAILED'
        } catch {if($_.Exception.Message -cne 'RELEASE_STATE_CLEANUP_FORMER_PRIMARY_UNPROVEN'){throw}}
        $PriorSource.runtime.pilotName='fortis-gateway'
        $Text=ConvertTo-Json -InputObject $Records[$PriorPath] -Depth 10 -Compress
        $Remaining=Get-HistoricalReleaseStateReferenceText $Text (ConvertFrom-Json -InputObject $Text) $PriorPath $Old $Pins $ActivePath ''
        if($Remaining.Contains($Old.id) -or $Remaining.Contains($Old.holderId)){
            throw 'RELEASE_STATE_CLEANUP_HISTORICAL_SOURCE_SELFTEST_FAILED'
        }
        $Records[$PriorPath] | Add-Member -NotePropertyName registryReturn -NotePropertyValue $PriorSource.runtime
        $Text=ConvertTo-Json -InputObject $Records[$PriorPath] -Depth 10 -Compress
        $Remaining=Get-HistoricalReleaseStateReferenceText $Text (ConvertFrom-Json -InputObject $Text) $PriorPath $Old $Pins $ActivePath ''
        if($Remaining -cne $Text){throw 'RELEASE_STATE_CLEANUP_REGISTRY_HOLD_SELFTEST_FAILED'}
        $CheckPath=Join-Path (Join-Path $ReleaseBase ('image-check-'+('e'*32))) 'record.json'
        $Check=[ordered]@{schema='fortis-extension-image-check-v1';phase='Ready';binding=[ordered]@{
            sourceRecord=$PriorSource.path;sourceHash=$Old.recordHash;sourceRunId=$Old.id
            sourceStateVolume=$Old.volume;sourceContainerId=$Old.holderId;sourceImage=$Old.holderImage
            currentPointerHash=('1'*64)}}
        $Text=ConvertTo-Json -InputObject $Check -Depth 10 -Compress
        $Remaining=Get-HistoricalReleaseStateReferenceText $Text (ConvertFrom-Json -InputObject $Text) $CheckPath $Old $Pins $ActivePath ''
        if($Remaining.Contains($Old.id)){throw 'RELEASE_STATE_CLEANUP_STALE_CHECK_SELFTEST_FAILED'}
        $Remaining=Get-HistoricalReleaseStateReferenceText $Text (ConvertFrom-Json -InputObject $Text) $CheckPath $Old $Pins $ActivePath $CheckPath
        if($Remaining -cne $Text){throw 'RELEASE_STATE_CLEANUP_READY_HOLD_SELFTEST_FAILED'}
        $Check.binding.currentPointerHash=$Pins.pointers['current.json']
        $Text=ConvertTo-Json -InputObject $Check -Depth 10 -Compress
        $Remaining=Get-HistoricalReleaseStateReferenceText $Text (ConvertFrom-Json -InputObject $Text) $CheckPath $Old $Pins $ActivePath ''
        if($Remaining -cne $Text){throw 'RELEASE_STATE_CLEANUP_READY_HOLD_SELFTEST_FAILED'}
        $BackupId='f'*32
        $BackupPath=Join-Path (Join-Path $ReleaseBase ('primary-backup-'+$BackupId)) 'record.json'
        $Backup=[ordered]@{schema='fortis-primary-backup-v1';phase='Complete';sourceRecord=$PriorSource.path
            sourceHash=$Old.recordHash;stateVolume=$Old.volume;containerId=$Old.holderId;image=$Old.holderImage
            backupVolume=('fortis-gateway-backup-'+$BackupId)}
        $Text=ConvertTo-Json -InputObject $Backup -Depth 10 -Compress
        $Remaining=Get-HistoricalReleaseStateReferenceText $Text (ConvertFrom-Json -InputObject $Text) $BackupPath $Old $Pins $ActivePath ''
        if($Remaining.Contains($Old.id)){throw 'RELEASE_STATE_CLEANUP_HISTORICAL_BACKUP_SELFTEST_FAILED'}
        $Pins.protectedBackups=@(@{id=$BackupId})
        $Remaining=Get-HistoricalReleaseStateReferenceText $Text (ConvertFrom-Json -InputObject $Text) $BackupPath $Old $Pins $ActivePath ''
        if($Remaining -cne $Text){throw 'RELEASE_STATE_CLEANUP_BACKUP_HOLD_SELFTEST_FAILED'}
        $Pins.primaryId=$Next.holderId;$Pins.stateVolume=$Next.volume
        $Pins.previousId=$Active.holderId;$Pins.previousVolume=$Active.volume
        $Pins.previousRecordHash=$Active.recordHash
        if((Get-FormerPrimaryProof $Prior $Pins $ActivePath) -cne $Active.recordHash){
            throw 'RELEASE_STATE_CLEANUP_ROTATION_SELFTEST_FAILED'
        }
        $Text=ConvertTo-Json -InputObject $Records[$ActivePath] -Depth 10 -Compress
        $Remaining=Get-HistoricalReleaseStateReferenceText $Text (ConvertFrom-Json -InputObject $Text) $ActivePath $Prior $Pins $NextPath ''
        if($Remaining.Contains($Prior.id)){throw 'RELEASE_STATE_CLEANUP_ROTATION_SELFTEST_FAILED'}
        function Test-Path {param($LiteralPath) $LiteralPath -ieq (Get-ReleaseStateRetirementPath $A)}
        try {
            Assert-ReleaseStateSourceAvailable $PriorSource.runtime
            throw 'RELEASE_STATE_CLEANUP_SOURCE_FENCE_SELFTEST_FAILED'
        } catch {if($_.Exception.Message -cne 'RELEASE_STATE_CLEANUP_SOURCE_RETIRED_OR_REQUIRES_READBACK'){throw}}
        Assert-ReleaseStateSourceAvailable (New-SourceFixture $Prior).runtime
    }
    Write-Host 'FORTIS_RELEASE_STATE_CLEANUP_FORMER_PRIMARY_SELFTEST_PASS'
}

function Promote-Primary {
    if(-not (Test-Path -LiteralPath $Pointer)){throw 'PRIMARY_CURRENT_RELEASE_REQUIRED'}
    $Current=(Read-Private $Pointer).record
    $Source=Get-SourceRecord
    if($Source.path -cne $Current){throw 'PRIMARY_CURRENT_POINTER_MISMATCH'}
    $P=$Source.runtime;$C=Container $P.pilotId
    $BackupPointer=Join-Path $ReleaseBase 'primary-backup.json'
    if(-not (Test-Path -LiteralPath $BackupPointer)){throw 'PRIMARY_VERIFIED_BACKUP_REQUIRED'}
    $Backup=Read-Private ((Read-Private $BackupPointer).record)
    if($Backup.schema -cne 'fortis-primary-backup-v1' -or $Backup.phase -cne 'Complete' -or
       $Backup.sourceRecord -cne $Source.path -or $Backup.sourceHash -cne $Source.hash -or
       $Backup.containerId -cne $C.Id -or $Backup.image -cne $P.image -or
       $Backup.stateVolume -cne $P.stateVolume -or
       -not (Same-Json (Receipt $Backup.backupVolume) $Backup.receipt)){
        throw 'PRIMARY_BACKUP_RECEIPT_INVALID'
    }
    Admit $C $P
    if($C.State.Status -cne 'running' -or $C.State.Health.Status -cne 'healthy'){
        throw 'PRIMARY_NOT_HEALTHY'
    }
    Assert-OnlyWriter $P.stateVolume $C.Id
    if($P.pilotName -ceq 'fortis-gateway' -and $P.restartPolicy -ceq 'unless-stopped'){
        Write-Host 'FORTIS_PRIMARY_ALREADY_ACTIVE';return
    }
    if($P.pilotName -cne ('fortis-github-pilot-'+$P.runId) -or $P.restartPolicy){
        throw 'PRIMARY_SOURCE_NOT_ADMISSIBLE'
    }
    if(Test-Path -LiteralPath $AttemptPointer){
        $Attempt=Read-Private ((Read-Private $AttemptPointer).record)
        if($Attempt.phase -cnotin @('Complete','Returned')){throw 'PRIMARY_INCOMPLETE_RELEASE_ATTEMPT'}
    }
    $Prev=$null;$Prior=$null
    $Names=@((Docker-Text @('ps','-a','--format','{{.Names}}')) -split '\r?\n')
    if(Test-Path -LiteralPath $PrimaryPointer){
        $Prior=Read-Private $PrimaryPointer
        if($Prior.schema -cne 'fortis-primary-v1' -or $Prior.phase -cne 'Complete' -or
           $Prior.sourceRecord -ceq $Source.path -or
           (Get-FileHash -LiteralPath $Prior.sourceRecord -Algorithm SHA256).Hash -cne $Prior.sourceHash){
            throw 'PRIMARY_PREVIOUS_POINTER_INVALID'
        }
        $Prev=Container $Prior.runtime.pilotId
        if($Prev.State.Status -cne 'exited' -or
           $Prior.runtime.pilotName -cne 'fortis-gateway' -or
           $Prior.runtime.originalPilotName -cne ('fortis-github-pilot-'+$Prior.runtime.runId) -or
           $Names -ccontains $Prior.runtime.originalPilotName){
            throw 'PRIMARY_PREVIOUS_NOT_RETAINED'
        }
        $OldImageInfo=$null
        try {$OldImageInfo=@(Docker-Json @('image','inspect',$Prior.runtime.image))[0]}
        catch {$OldImageInfo=$null}
        if($null -ne $OldImageInfo){
            if($OldImageInfo.Id -cne $Prior.runtime.image){
                throw 'PRIMARY_PREVIOUS_IMAGE_CHANGED'
            }
            if((Test-Registry259ReturnSource $Prior.runtime) -or (Test-Registry262ReturnSource $Prior.runtime) -or
               (Test-Registry265ReturnSource $Prior.runtime) -or (Test-Registry268ReturnSource $Prior.runtime)){
                $Handover=Get-PrimaryRegistryHandover (Read-Private $Source.path) $Prior
                Assert-RegistryReturnInputs $Handover.source $Handover.reserve $Prev -AllowUsed:($Handover.used)
                if($Handover.used){
                    $ReturnedContainer=Container $Handover.reserve.pilotId
                    if($ReturnedContainer.State.Status -cne 'exited' -or
                       $ReturnedContainer.State.StartedAt -ceq '0001-01-01T00:00:00Z'){
                        throw 'PRIMARY_RETURNED_REGISTRY_RESERVE_NOT_FROZEN'
                    }
                    $GateInput=ConvertTo-Json -Compress -InputObject @{
                        nonce=$Handover.reserve.releaseNonce;configurationDigest=$Handover.configurationDigest}
                    $Gate=Image-CLI @('gate-record-status') $GateInput -StateVolume $Handover.reserve.stateVolume
                    if($Gate.active -ne $true){throw 'PRIMARY_RETURNED_REGISTRY_GATE_UNBOUND'}
                }
                Admit $Prev $Prior.runtime -AllowUnhealthy -RegistryReturnSource
            } else {
                Admit $Prev $Prior.runtime -AllowUnhealthy
            }
        } else {
            # UC-GW-013: only the exact already-accepted Complete Apply may
            # finish promotion. Verify historical backup and rescue BEFORE
            # touching either container name or restart policy.
            $Rescue=Assert-Emergency-Promote-Rescue $Source $Prior $Prev
            Admit $Prev $Prior.runtime -AllowUnhealthy -MountPreflightImageId $Rescue `
                -VerifiedPromoteRescueImage $Rescue
            Write-Host 'FORTIS_EMERGENCY_PROMOTE_PREVIOUS_ADMISSION_PASS'
        }
    } elseif($Names -ccontains 'fortis-gateway'){throw 'PRIMARY_NAME_OCCUPIED'}
    $Runtime=$P|ConvertTo-Json -Depth 25 -Compress|ConvertFrom-Json
    $Runtime|Add-Member -NotePropertyName originalPilotName -NotePropertyValue $P.pilotName
    $Runtime|Add-Member -NotePropertyName restartPolicy -NotePropertyValue 'unless-stopped'
    $Runtime.pilotName='fortis-gateway'
    $Record=[ordered]@{schema='fortis-primary-v1';phase='Complete';sourceRecord=$Source.path
        sourceHash=$Source.hash;runtime=$Runtime;previousPrimaryRecord=$(if($Prior){$Prior.sourceRecord}else{''})}
    $PreviousRenamed=$false;$TargetRenamed=$false
    try {
        if($Prev){
            $null=Docker-Text @('update','--restart=no',$Prev.Id)
            $null=Docker-Text @('rename',$Prev.Id,$Prior.runtime.originalPilotName)
            $PreviousRenamed=$true
        }
        $null=Docker-Text @('rename',$C.Id,'fortis-gateway');$TargetRenamed=$true
        $null=Docker-Text @('update','--restart=unless-stopped',$C.Id)
        Wait-Healthy $C.Id
        Admit (Container $C.Id) $Runtime
        Write-Private $PrimaryPointer $Record
        Write-Host 'FORTIS_PRIMARY_PROMOTED'
    } catch {
        $Failure=$_.Exception.Message
        try {
            if($TargetRenamed){
                $null=Docker-Text @('update','--restart=no',$C.Id)
                $null=Docker-Text @('rename',$C.Id,$P.pilotName)
            }
            if($PreviousRenamed){
                $null=Docker-Text @('rename',$Prev.Id,'fortis-gateway')
                $null=Docker-Text @('update','--restart=unless-stopped',$Prev.Id)
            }
        } catch {throw ('PRIMARY_PROMOTION_RECOVERY_REQUIRED: '+$Failure)}
        throw ('PRIMARY_PROMOTION_FAILED: '+$Failure)
    }
}
