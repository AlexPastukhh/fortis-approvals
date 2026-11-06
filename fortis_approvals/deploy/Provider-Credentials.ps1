# Dot-sourced by Manage-Integrations.ps1; existing images need no new package.
function Credential-Helper {
    param($Payload,[string]$TokenVolume='', [string]$StateVolume='', [switch]$Writable)
    $Identity='10001:10001';if($Writable){$Identity='0:0'}
    $Arguments=@('run','--rm','-i','--pull=never','--network','none','--read-only','--user',$Identity,
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','256m')
    if($Writable){$Arguments+=@('--cap-add','CHOWN','--cap-add','DAC_OVERRIDE')}
    if($TokenVolume){
        Assert-Volume $TokenVolume
        $Mount='type=volume,source='+$TokenVolume+',target=/rotation-token'
        if(-not $Writable){$Mount+=',readonly'}
        $Arguments+=@('--mount',$Mount)
    }
    if($StateVolume){Assert-Volume $StateVolume;$Arguments+=@('--mount',('type=volume,source='+$StateVolume+',target=/rotation-state,readonly'))}
    $Code=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'provider_credentials.py') -Raw
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<provider-credential-helper>','exec'))"
    $InputJson=ConvertTo-Json -InputObject $Payload -Depth 40 -Compress
    (Private-Process ($Arguments+@('--entrypoint','python',$script:Image,'-I','-B','-c',$Wrapper)) $InputJson) | ConvertFrom-Json
}
function Credential-Inventory {
    $Items=@()
    foreach($Id in @((Docker-Text @('ps','-aq','--no-trunc')) -split '\r?\n'|Where-Object{$_})){
        $Items+=@(Public-Inspect (Container $Id))
    }
    $Items
}
function Credential-Identity {
    param($Container)
    $Public=Public-Inspect $Container
    $Public.Remove('State')
    $Hash=[Security.Cryptography.SHA256]::Create()
    try {([BitConverter]::ToString($Hash.ComputeHash([Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-Json -InputObject $Public -Depth 40 -Compress))))).Replace('-','').ToLowerInvariant()}
    finally {$Hash.Dispose()}
}
function Restore-CredentialContainers {
    param($Rotation)
    foreach($Target in $Rotation.targets){
        $C=Container $Target.id
        if((Credential-Identity $C) -cne $Target.signature){throw 'CREDENTIAL_CONTAINER_CHANGED'}
        if($C.State.Status -ceq 'exited'){$null=Docker-Text @('start',$Target.id)}
        elseif($C.State.Status -cne 'running'){throw 'CREDENTIAL_RESTART_STATE_INVALID'}
        Wait-Healthy $Target.id
    }
}
function Credential-Readback {
    param([string]$Provider,$Runtime)
    $Settings=Code64 (ConvertTo-Json -InputObject @{service=$Provider;repository=$Runtime.repository} -Compress)
    $Code=@'
import base64,json,uuid
from fortis_approvals.clients.gateway_transport import GatewayTransport
s=json.loads(base64.b64decode('SETTINGS_BASE64'))
checks=[]
if s['service']=='github':
    from fortis_approvals.workflow.client import default_client
    c=default_client()
    assert c.gateway.post('/v1/workspace/capabilities',{})['repository']==s['repository']
    g=c.github
    g.list_branches(s['repository'],per_page=1)
    g.list_pull_requests(s['repository'],state='open',per_page=1)
    g.list_workflow_runs(s['repository'],per_page=1)
    checks.append({'role':'review','githubContentsPullRequestsActionsRead':True})
else:
    for role,port in [('review',19204),('production',19104)]:
        g=GatewayTransport(endpoint='https://host.docker.internal:'+str(port),allow_test_endpoint=True)
        r=g.post('/v1/reads',{'requestId':str(uuid.uuid4()),'service':'sonarcloud',
            'operation':'get_quality_gate','target':'AlexPastukhh_obs-planning-docs','params':{},
            'reason':'Owner token rotation readback'})
        assert r['data']['projectKey']=='AlexPastukhh_obs-planning-docs'
        checks.append({'role':role,'sonarQualityGateRead':True})
print(json.dumps({'checks':checks}))
'@
    Repo-JSON ($Code.Replace('SETTINGS_BASE64',$Settings))
}
function Assert-CredentialIdle {
    param($Targets,[string]$Provider)
    foreach($Target in $Targets){
        $Info=Credential-Helper @{action='idle';service=$Provider} -StateVolume $Target.stateVolume
        if(-not $Info.idle){throw ('CREDENTIAL_UNFINISHED_REQUESTS_'+$Target.role.ToUpperInvariant())}
    }
}
function Put-ProviderCredential {
    param([string]$Provider)
    if($Provider -cnotin @('github','sonarcloud') -or -not $Rotate -or $CredentialName -or
       $Config -or $Probes -or $AttemptRecord){throw 'CREDENTIAL_SERVICE_ARGUMENTS_INVALID'}
    $Git=(Get-Command git.exe -CommandType Application).Source
    if((Private-Process @('-C',$SourceRoot,'status','--porcelain') '' $Git) -or
       (Private-Process @('-C',$SourceRoot,'branch','--show-current') '' $Git) -cne 'main'){
        throw 'CREDENTIAL_CLEAN_WINDOWS_MAIN_REQUIRED'
    }
    $CredentialPointer=Join-Path $ReleaseBase 'credential-attempt.json'
    if(Test-Path -LiteralPath $CredentialPointer){
        $Previous=Read-Private ((Read-Private $CredentialPointer).record)
        if($Previous.schema -cne 'fortis-provider-credential-v1'){throw 'CREDENTIAL_RECORD_INVALID'}
        if($Previous.phase -cnotin @('Complete','FailedRestored','Recovered')){
            Restore-CredentialContainers $Previous
            $Previous.phase='Recovered'
            Write-Private ((Read-Private $CredentialPointer).record) $Previous
            Write-Host 'FORTIS_CREDENTIAL_INTERRUPTED_CONTAINERS_RESTORED'
        }
    }
    $Source=Get-SourceRecord;$Runtime=$Source.runtime
    if($script:Image -cne $Runtime.image){throw 'CREDENTIAL_CURRENT_IMAGE_REQUIRED'}
    if((Get-FileHash -LiteralPath $Source.path -Algorithm SHA256).Hash -cne $Source.hash){throw 'CREDENTIAL_SOURCE_RECORD_CHANGED'}
    $Review=Container $Runtime.pilotId;Admit $Review $Runtime
    $ProductionBefore=Production-Baseline
    $Production=Container 'fortis-approvals-gateway'
    $Volume=$Runtime.tokenVolume
    if($Provider -ceq 'sonarcloud'){$Volume='fortis-r7-sonar-token'}
    $Inventory=@(Credential-Inventory)
    $Plan=Credential-Helper @{action='plan';service=$Provider;tokenVolume=$Volume;
        reviewId=$Review.Id;productionId=$Production.Id;containers=$Inventory}
    foreach($Target in $Plan.targets){
        $C=Container $Target.id
        if($Target.role -ceq 'production' -and $Target.stateVolume -cne 'fortis-r7-state'){throw 'CREDENTIAL_PRODUCTION_STATE_CHANGED'}
        $Target|Add-Member -NotePropertyName signature -NotePropertyValue (Credential-Identity $C)
    }
    Assert-OnlyWriter $Volume
    Assert-CredentialIdle $Plan.targets $Provider
    $Before=Credential-Helper @{action='status'} -TokenVolume $Volume
    # Probe client wiring/old authorization before touching the runtime. An expired
    # old token may fail; it is deliberately not required for replacement.
    $null=Repo-JSON "import json;from fortis_approvals.workflow.client import default_client;c=default_client();print(json.dumps(c.gateway.post('/v1/workspace/capabilities',{})))"
    $Directory=Join-Path $ReleaseBase ('credential-'+[Guid]::NewGuid().ToString('N'))
    Protect-Directory $Directory
    $RotationPath=Join-Path $Directory 'record.json'
    $Rotation=[ordered]@{schema='fortis-provider-credential-v1';service=$Provider;phase='Prepared';
        sourceRecord=$Source.path;sourceRecordHash=$Source.hash;image=$script:Image;tokenVolume=$Volume;
        targets=@($Plan.targets);previousGeneration=$Before.generation;credentialChanged=$false;
        credentialWriteAttempted=$false;checks=@();failure=''}
    Write-Private $RotationPath $Rotation
    Write-Private $CredentialPointer @{schema=1;record=$RotationPath}
    Write-Host ('FORTIS_CREDENTIAL_TARGET '+$Provider+'; restart='+(@($Plan.targets.role)-join ','))
    $Secret=Read-Host ('New Gateway token for '+$Provider) -AsSecureString
    $Bstr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    $RestoreNeeded=$false;$Failure=''
    try {
        $Plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
        $Pattern='\A[A-Za-z0-9_]{30,512}\z'
        if($Provider -ceq 'sonarcloud'){$Pattern='\A[!-~]{12,4096}\z'}
        if($Plain -cnotmatch $Pattern){throw 'CREDENTIAL_FORMAT_INVALID'}
        if($Provider -ceq 'sonarcloud'){
            foreach($C in @($Review,$Production)){
                $Regions=@($C.Config.Env|Where-Object{$_.StartsWith('FORTIS_SONAR_REGION=')})
                if($Regions.Count -gt 1 -or ($Regions.Count -eq 1 -and $Regions[0] -cne 'FORTIS_SONAR_REGION=eu')){throw 'CREDENTIAL_SONAR_REGION_UNSUPPORTED'}
            }
        }
        $ProbeCode=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'provider_credentials.py') -Raw
        $ProbeInput=ConvertTo-Json -InputObject @{action='validate';service=$Provider;value=$Plain} -Compress
        $Auth=(Python-Code @('exec','-i','--user','10001:10001',$Review.Id) $ProbeCode $ProbeInput)|ConvertFrom-Json
        $ProbeInput=$null
        if(-not $Auth.authenticated){throw 'CREDENTIAL_AUTHENTICATION_FAILED'}
        $Rotation['authenticationPreflight']=$true

        $Rotation.phase='Stopping';Write-Private $RotationPath $Rotation;$RestoreNeeded=$true
        foreach($Target in $Plan.targets){
            $C=Container $Target.id
            if($C.State.Status -cne 'running' -or (Credential-Identity $C) -cne $Target.signature){throw 'CREDENTIAL_CONTAINER_CHANGED'}
            $null=Docker-Text @('stop','--time','30',$Target.id)
        }
        # Decisions submitted between preflight and stop must also block replacement.
        Assert-CredentialIdle $Plan.targets $Provider
        Assert-OnlyWriter $Volume
        $null=Credential-Helper @{action='plan';service=$Provider;tokenVolume=$Volume;stopped=$true;
            reviewId=$Review.Id;productionId=$Production.Id;containers=@(Credential-Inventory)}
        foreach($Target in $Plan.targets){if((Container $Target.id).State.Status -cne 'exited'){throw 'CREDENTIAL_TARGET_NOT_STOPPED'}}
        $Rotation.phase='Replacing';$Rotation.credentialWriteAttempted=$true;Write-Private $RotationPath $Rotation
        $Result=Credential-Helper @{action='replace';service=$Provider;value=$Plain;expectedGeneration=$Before.generation} -TokenVolume $Volume -Writable
        if($Result.status -cne 'REPLACED'){throw 'CREDENTIAL_REPLACE_UNCONFIRMED'}
        $Rotation.credentialChanged=$true;$Rotation['generation']=$Result.generation
        $Rotation.phase='Restarting';Write-Private $RotationPath $Rotation
        Restore-CredentialContainers $Rotation;$RestoreNeeded=$false
        $Rotation.phase='Verifying';Write-Private $RotationPath $Rotation
        $Checks=Credential-Readback $Provider $Runtime
        if($Provider -ceq 'github' -and (Production-Baseline) -cne $ProductionBefore){throw 'CREDENTIAL_PRODUCTION_CHANGED'}
        foreach($Target in $Plan.targets){if((Credential-Identity (Container $Target.id)) -cne $Target.signature){throw 'CREDENTIAL_CONTAINER_CHANGED'}}
        $Rotation.checks=@($Checks.checks);$Rotation.phase='Complete';Write-Private $RotationPath $Rotation
    } catch {
        $Failure=$_.Exception.Message
        if($Failure -cnotmatch '^[A-Z][A-Z0-9_:,-]*$'){$Failure='CREDENTIAL_ROTATION_FAILED'}
        if($Rotation.credentialWriteAttempted -and -not $Rotation.credentialChanged){$Rotation.credentialChanged='UNKNOWN'}
        $Rotation.failure=$Failure;$Rotation.phase='Failed';Write-Private $RotationPath $Rotation
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
        $Plain=$null;$ProbeInput=$null;$Secret.Dispose()
        if($RestoreNeeded){
            try {Restore-CredentialContainers $Rotation;$Rotation.phase='FailedRestored';Write-Private $RotationPath $Rotation}
            catch {$Failure='CREDENTIAL_CONTAINER_RECOVERY_REQUIRED';$Rotation.failure=$Failure;Write-Private $RotationPath $Rotation}
        } elseif($Failure){$Rotation.phase='FailedRestored';Write-Private $RotationPath $Rotation}
    }
    if($Failure){throw ($Failure+'; record='+$RotationPath+'; rerun the same Credential command to recover/retry')}
    [ordered]@{service=$Provider;record=$RotationPath;credentialChanged=$true;
        sameImagesAndConfiguration=$true;restarted=@($Plan.targets.role);checks=$Rotation.checks;
        providerWritePermissions='NOT_VERIFIED_BY_READBACK'}|ConvertTo-Json -Depth 8
    Write-Host 'FORTIS_PROVIDER_CREDENTIAL_ROTATED'
}
