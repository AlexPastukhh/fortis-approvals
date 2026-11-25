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
               (Test-Registry265ReturnSource $Prior.runtime)){
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
