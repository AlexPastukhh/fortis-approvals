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
        $Clone=State-Helper @{action='clone';github=$true;native=$true} @('--mount',
            ('type=volume,source='+$P.stateVolume+',target=/source,readonly'),
            ('type=volume,source='+$Name+',target=/target')) -Root
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
        Admit $Prev $Prior.runtime -AllowUnhealthy
        if($Prev.State.Status -cne 'exited' -or
           $Prior.runtime.pilotName -cne 'fortis-gateway' -or
           $Prior.runtime.originalPilotName -cne ('fortis-github-pilot-'+$Prior.runtime.runId) -or
           $Names -ccontains $Prior.runtime.originalPilotName){
            throw 'PRIMARY_PREVIOUS_NOT_RETAINED'
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
