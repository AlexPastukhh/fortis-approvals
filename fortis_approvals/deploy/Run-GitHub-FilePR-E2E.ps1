# Windows PowerShell 5.1. Extend the accepted isolated M1 pilot; preserve M1 for return.
[CmdletBinding()]
param(
    [ValidateSet('Start','Resume','Rollback','SelfTest')][string]$Mode='Start',
    [string]$PreviousRecord='', [string]$Record='', [string]$ExpectedSourceCommit='',
    [ValidateSet('FilePR','CIRead')][string]$ScenarioKind='FilePR',
    [long]$ExpectedWorkflowRunId=0, [switch]$ConfirmActionsReadPermission,
    [switch]$ConfirmPullRequestsPermission
)
$EntryMode=$Mode
. (Join-Path $PSScriptRoot 'Run-GitHub-Pilot-E2E.ps1') -Mode Functions -Record $Record -ExpectedSourceCommit $ExpectedSourceCommit
$Mode=$EntryMode

function Read-ProtectedRecord {
    param([string]$Path)
    $script:RecordPath=[IO.Path]::GetFullPath($Path)
    $Base=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Fortis\GitHubPilot'))
    if (-not $script:RecordPath.StartsWith($Base + '\',[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($script:RecordPath) -cne 'record.json') { throw 'FILE_PR_RECORD_PATH_INVALID' }
    Assert-RecordAcl
    $Value=Get-Content -LiteralPath $script:RecordPath -Raw | ConvertFrom-Json
    if ([IO.Path]::GetFileName((Split-Path $script:RecordPath -Parent)) -cne $Value.runId) { throw 'FILE_PR_RECORD_DIRECTORY_MISMATCH' }
    return $Value
}
function Assert-M1Record {
    param($Value)
    if ($Value.schema -ne 1 -or $Value.phase -cne 'Complete' -or $Value.scenario.phase -cne 'DONE' -or
        $Value.sourceCommit -cne 'cd9af3ca6e43ec03134477beb2b284a837c67236' -or
        $Value.image -cne 'sha256:605d6d031619dc894e0c4dba9a3f6cdd991f483a86147d48110ef18e1a455afe' -or
        $Value.owner -cne 'AlexPastukhh' -or $Value.repository -cne 'fortis-approvals' -or
        $Value.receipt.receiptVerified -ne $true -or $Value.receipt.ownerDecisionVerified -ne $true -or
        $Value.runId -cnotmatch '^[0-9a-f]{32}$' -or $Value.pilotId -cnotmatch '^[0-9a-f]{64}$' -or
        $Value.stateVolume -cne ('fortis-github-pilot-state-' + $Value.runId) -or
        $Value.tokenVolume -cne ('fortis-github-pilot-token-' + $Value.runId) -or
        $Value.pilotName -cne ('fortis-github-pilot-' + $Value.runId)) { throw 'FILE_PR_ACCEPTED_M1_REQUIRED' }
    $Id=([Guid]::ParseExact($Value.runId,'N')).ToString('D')
    if ($Value.scenario.runId -cne $Id -or $Value.scenario.sourceSha -cne $Value.sourceCommit -or
        $Value.scenario.approve.branch -cne ('fortis-e2e/' + $Id + '-approve')) { throw 'FILE_PR_M1_BRANCH_IDENTITY_INVALID' }
}
function Assert-M2Record {
    param($Value)
    Assert-M1Record $Value.previous
    if ($Value.schema -ne 2 -or $Value.phase -cne 'Complete' -or $Value.scenario.phase -cne 'DONE' -or
        $Value.sourceCommit -cne 'cf0553d0690a693fcc3e11ac8d3685f61aefe86d' -or
        $Value.image -cne 'sha256:2c1a6f5a8c079305711dda907bc245f1cbf0692181fd8be8a2b719a1fa6f2980' -or
        $Value.owner -cne 'AlexPastukhh' -or $Value.repository -cne 'fortis-approvals' -or
        $Value.receipt.receiptsVerified -ne $true -or $Value.receipt.ownerDecisionsVerified -ne $true -or
        $Value.runId -cnotmatch '^[0-9a-f]{32}$' -or $Value.pilotId -cnotmatch '^[0-9a-f]{64}$' -or
        $Value.pilotName -cne ('fortis-github-pilot-' + $Value.runId) -or
        $Value.stateVolume -cne ('fortis-github-pilot-state-' + $Value.runId) -or
        $Value.tokenVolume -cne $Value.previous.tokenVolume -or
        $Value.filePrBranch -cne $Value.previous.scenario.approve.branch -or
        $Value.scenario.branch -cne $Value.filePrBranch -or
        $Value.scenario.commitSha -cne 'a2cb4a59bf2251cc05301a9da17e3a9fd02a19ee' -or
        $Value.scenario.pullRequestNumber -ne 8) {throw 'CI_READ_ACCEPTED_M2_REQUIRED'}
}
function Previous-Expected {
    param([string]$Status)
    $P=$script:R.previous
    return @{id=$P.pilotId; name=$P.pilotName; image=$P.image; stateVolume=$P.stateVolume
        tokenVolume=$P.tokenVolume; owner=$P.owner; repository=$P.repository; status=$Status; filePrBranch=$P.filePrBranch}
}
function Admit-Previous {
    param([string]$Status)
    $null=Helper @{action='admit'; container=(Public-Inspect (Container $script:R.previous.pilotId))
        expected=(Previous-Expected $Status); pilot=$true} -Image $script:R.previous.image
}
function Assert-ExtensionPrepared {
    if ($script:R.phase -cne 'Prepared' -or $script:R.previousStopped -or $script:R.pilotId -or
        $script:R.sourceReceipt -or $script:R.scenario.phase -cne 'READ') { throw 'FILE_PR_SETUP_NOT_RESUMABLE_INSPECT_RECORD' }
    $Volumes=@((Docker-Text @('volume','ls','--format','{{.Name}}')) -split '\r?\n')
    $Names=@((Docker-Text @('ps','-a','--format','{{.Names}}')) -split '\r?\n')
    if ($Volumes -ccontains $script:R.stateVolume -or $Names -ccontains $script:R.pilotName) {
        throw 'FILE_PR_EXISTING_SETUP_RESOURCE_REQUIRES_INSPECTION'
    }
    Check-RepoSource; Assert-Production; Admit-Previous 'running'
}
function Return-M1 {
    if ($script:R.phase -cin @('ReturnedM1','ReturnedM2')) { Admit-Previous 'running'; Assert-Production; return }
    if ($script:R.pilotId) {
        $C=Container $script:R.pilotId
        if ($C.State.Status -cnotin @('created','exited','running')) { throw 'FILE_PR_RETURN_CONTAINER_STATE_UNKNOWN' }
        $E=Expected-Pilot $C.State.Status; $E.requireHealthy=$false
        $null=Helper @{action='admit';container=(Public-Inspect $C);expected=$E;pilot=$true}
        if ($C.State.Status -ceq 'running') { $null=Docker-Text @('stop','--timeout','20',$script:R.pilotId) }
        if ((Container $script:R.pilotId).State.Status -cnotin @('created','exited')) { throw 'FILE_PR_RETURN_STOP_UNCONFIRMED' }
    }
    Assert-Production
    Assert-OnlyWriter $script:R.previous.stateVolume $script:R.previous.pilotId
    $Original=Container $script:R.previous.pilotId
    if ($Original.State.Status -ceq 'running') {
        if ($script:R.previousStopped) { throw 'FILE_PR_M1_RESTARTED_OUTSIDE_RUN' }
        Admit-Previous 'running'
    } else {
        if (-not $script:R.previousStopped) { throw 'FILE_PR_M1_STOPPED_OUTSIDE_RUN' }
        Admit-Previous 'exited'
        if ($script:R.sourceReceipt) {
            $Current=Helper @{action='inspect';github=$true} -Image $script:R.previous.image -Mounts @('--mount',
                ('type=volume,source=' + $script:R.previous.stateVolume + ',target=/source,readonly'))
            if ((ConvertTo-Json $Current -Depth 12 -Compress) -cne (ConvertTo-Json $script:R.sourceReceipt -Depth 12 -Compress)) {
                throw 'FILE_PR_RETAINED_M1_STATE_CHANGED'
            }
        }
        $null=Docker-Text @('start',$script:R.previous.pilotId)
        Wait-Healthy $script:R.previous.pilotId; Admit-Previous 'running'
    }
    Assert-Production
    if ($script:R.ciReads) {$script:R.phase='ReturnedM2'} else {$script:R.phase='ReturnedM1'}
    Save-Record
    if ($script:R.ciReads) {Write-Host 'FORTIS_GITHUB_CI_RETURNED_TO_M2_PASS'}
    else {Write-Host 'FORTIS_GITHUB_FILE_PR_RETURNED_TO_M1_PASS'}
}
function Run-FilePRScenario {
    Admit-Pilot 'running'; Admit-Previous 'exited'; Assert-Production; Check-RepoSource
    Assert-OnlyWriter $script:R.stateVolume $script:R.pilotId
    $Deadline=[DateTime]::UtcNow.AddMinutes(15); $LastPrompt=''
    $WasDone=$script:R.scenario.phase -ceq 'DONE'
    while ($script:R.scenario.phase -cne 'DONE') {
        $InputJson=ConvertTo-Json $script:R.scenario -Depth 20 -Compress
        $Args=@('exec','-i','--user','1000:1000','--workdir','/workspace/repo/Repos/fortis-approvals',
            'fortis-repo-test','python3','-B','-m','fortis_approvals.integrations.github.repo_client.file_pr_scenario')
        $Step=(Private-Process $Args $InputJson) | ConvertFrom-Json
        $Before=ConvertTo-Json $script:R.scenario -Depth 20 -Compress
        $script:R.scenario=$Step.state
        if ($Before -cne (ConvertTo-Json $Step.state -Depth 20 -Compress)) { Save-Record }
        if ($Step.awaitOwner) {
            $Prompt=$Step.awaitOwner.decision + ':' + $Step.awaitOwner.requestId
            if ($Prompt -cne $LastPrompt) {
                Write-Host ('FILE_PR_OWNER_ACTION=' + $Step.awaitOwner.decision.ToUpperInvariant())
                Write-Host ('OPERATION=' + $Step.awaitOwner.operation)
                Write-Host ('REQUEST_ID=' + $Step.awaitOwner.requestId)
                Write-Host ('BRANCH=' + $script:R.filePrBranch)
                Write-Host 'OWNER_PORTAL=http://localhost:19203'
                Write-Host 'Use the existing owner device. Draft PR creation triggers the existing pull_request CI.'
                $LastPrompt=$Prompt
            }
            if ([DateTime]::UtcNow -gt $Deadline) { throw 'FILE_PR_OWNER_WAIT_TIMEOUT_RESUME_SAME_RECORD' }
            Start-Sleep -Seconds 3
        }
    }
    if ($WasDone) {
        $Args=@('exec','-i','--user','1000:1000','--workdir','/workspace/repo/Repos/fortis-approvals',
            'fortis-repo-test','python3','-B','-m','fortis_approvals.integrations.github.repo_client.file_pr_scenario')
        $Check=(Private-Process $Args (ConvertTo-Json $script:R.scenario -Depth 20 -Compress)) | ConvertFrom-Json
        if (-not $Check.complete) {throw 'FILE_PR_COMPLETED_READBACK_FAILED'}
    }
    $script:R.receipt=Helper @{action='file_pr_receipts';scenario=$script:R.scenario} -InsidePilot
    $Sonar=Read-SonarRegression
    Assert-Production; $script:R.phase='Complete'; Save-Record
    [ordered]@{sourceCommit=$script:R.sourceCommit;image=$script:R.image;runId=$script:R.scenario.runId
        branch=$script:R.scenario.branch;path=$script:R.scenario.path;commitSha=$script:R.scenario.commitSha
        pullRequestNumber=$script:R.scenario.pullRequestNumber;receiptsVerified=$script:R.receipt.receiptsVerified
        ownerDecisionsVerified=$script:R.receipt.ownerDecisionsVerified;sonarReadStatus=$Sonar.status
        productionBaselineUnchanged=$true;retainedM1=$true;record=$script:RecordPath} | ConvertTo-Json -Depth 6
    Write-Host 'FORTIS_GITHUB_FILE_PR_LIVE_E2E_PASS'
}

function Read-SonarRegression {
    $Code="import json,uuid;from fortis_approvals.clients.gateway_transport import GatewayTransport;g=GatewayTransport(endpoint='https://host.docker.internal:19204',allow_test_endpoint=True);r=g.post('/v1/reads',{'requestId':str(uuid.uuid4()),'service':'sonarcloud','operation':'get_quality_gate','target':'AlexPastukhh_obs-planning-docs','params':{},'reason':'File PR pilot Sonar regression'});print(json.dumps({'status':r['data']['status']}))"
    $Sonar=(Private-Process @('exec','--user','1000:1000','--workdir','/workspace/repo/Repos/fortis-approvals',
        'fortis-repo-test','python3','-B','-c',$Code) '') | ConvertFrom-Json
    return $Sonar
}
function Run-CIReadScenario {
    Admit-Pilot 'running'; Admit-Previous 'exited'; Assert-Production; Check-RepoSource
    Assert-OnlyWriter $script:R.stateVolume $script:R.pilotId
    $Args=@('exec','-i','--user','1000:1000','--workdir','/workspace/repo/Repos/fortis-approvals',
        'fortis-repo-test','python3','-B','-m','fortis_approvals.integrations.github.repo_client.ci_read_scenario')
    $Report=(Private-Process $Args (ConvertTo-Json $script:R.scenario -Depth 20 -Compress)) | ConvertFrom-Json
    # Verify the accepted M2 file/PR receipts survived the stopped-state clone.
    $script:R.receipt=Helper @{action='file_pr_receipts';scenario=$script:R.previous.scenario} -InsidePilot
    $Sonar=Read-SonarRegression
    Assert-Production
    $script:R.scenario.phase='DONE';$script:R.result=$Report;$script:R.phase='Complete';Save-Record
    [ordered]@{sourceCommit=$script:R.sourceCommit;image=$script:R.image;report=$Report
        m2ReceiptsPreserved=$script:R.receipt.receiptsVerified;sonarReadStatus=$Sonar.status
        productionBaselineUnchanged=$true;retainedM2=$true;record=$script:RecordPath} | ConvertTo-Json -Depth 10
    Write-Host 'FORTIS_GITHUB_CI_READ_LIVE_PASS'
}
function Run-SelectedScenario {
    if ($script:R.ciReads) {Run-CIReadScenario} else {Run-FilePRScenario}
}

if ($Mode -ceq 'SelfTest') {
    $P=[pscustomobject]@{schema=1;phase='Complete';sourceCommit='cd9af3ca6e43ec03134477beb2b284a837c67236'
        image='sha256:605d6d031619dc894e0c4dba9a3f6cdd991f483a86147d48110ef18e1a455afe';owner='AlexPastukhh';repository='fortis-approvals'
        runId='c6884d29cfc74dfc8cc80081720792df';pilotId=('a' * 64);pilotName='fortis-github-pilot-c6884d29cfc74dfc8cc80081720792df'
        stateVolume='fortis-github-pilot-state-c6884d29cfc74dfc8cc80081720792df';tokenVolume='fortis-github-pilot-token-c6884d29cfc74dfc8cc80081720792df'
        receipt=@{receiptVerified=$true;ownerDecisionVerified=$true}
        scenario=@{phase='DONE';sourceSha='cd9af3ca6e43ec03134477beb2b284a837c67236';runId='c6884d29-cfc7-4dfc-8cc8-0081720792df'
            approve=@{branch='fortis-e2e/c6884d29-cfc7-4dfc-8cc8-0081720792df-approve'}}}
    Assert-M1Record $P
    $M2=[pscustomobject]@{schema=2;phase='Complete';sourceCommit='cf0553d0690a693fcc3e11ac8d3685f61aefe86d'
        image='sha256:2c1a6f5a8c079305711dda907bc245f1cbf0692181fd8be8a2b719a1fa6f2980';owner='AlexPastukhh';repository='fortis-approvals'
        previous=$P;runId='22222222222242228222222222222222';pilotId=('c' * 64);pilotName='fortis-github-pilot-22222222222242228222222222222222'
        stateVolume='fortis-github-pilot-state-22222222222242228222222222222222';tokenVolume=$P.tokenVolume;filePrBranch=$P.scenario.approve.branch
        receipt=@{receiptsVerified=$true;ownerDecisionsVerified=$true}
        scenario=@{phase='DONE';branch=$P.scenario.approve.branch;commitSha='a2cb4a59bf2251cc05301a9da17e3a9fd02a19ee';pullRequestNumber=8}}
    Assert-M2Record $M2
    foreach ($Case in @('incomplete','bad-commit','bad-receipt','wrong-branch')) {
        $Bad=ConvertFrom-Json (ConvertTo-Json $M2 -Depth 20)
        switch ($Case) {
            'incomplete' {$Bad.phase='Running'}
            'bad-commit' {$Bad.scenario.commitSha='e' * 40}
            'bad-receipt' {$Bad.receipt.receiptsVerified=$false}
            'wrong-branch' {$Bad.filePrBranch='main'}
        }
        $Denied=$false
        try {Assert-M2Record $Bad} catch {$Denied=$true}
        if (-not $Denied) {throw 'CI_READ_M2_ADMISSION_SELFTEST_FAILED'}
    }
    foreach ($Case in @('incomplete','wrong-source','wrong-image','wrong-repo','wrong-state','wrong-branch')) {
        $Bad=ConvertFrom-Json (ConvertTo-Json $P -Depth 10)
        switch ($Case) {
            'incomplete' {$Bad.phase='Running'}
            'wrong-source' {$Bad.sourceCommit='b' * 40}
            'wrong-image' {$Bad.image='sha256:other'}
            'wrong-repo' {$Bad.repository='other'}
            'wrong-state' {$Bad.stateVolume='fortis-r7-state'}
            'wrong-branch' {$Bad.scenario.approve.branch='main'}
        }
        $Denied=$false
        try { Assert-M1Record $Bad } catch { $Denied=$true }
        if (-not $Denied) { throw 'FILE_PR_M1_ADMISSION_SELFTEST_FAILED' }
    }
    $script:R=@{previous=$P;previousStopped=$true;phase='Running';pilotId=('b' * 64);image='sha256:new';filePrBranch=$P.scenario.approve.branch
        stateVolume='new-state';tokenVolume=$P.tokenVolume;pilotName='new-pilot';owner=$P.owner;repository=$P.repository;sourceReceipt=@{hash='preserved'}}
    $script:NewState='running';$script:OldState='exited';$script:Actions=[Collections.Generic.List[string]]::new();$script:Changed=$false
    function Container {param([string]$Identity)
        $Status=$script:OldState
        if ($Identity -ceq $script:R.pilotId) {$Status=$script:NewState}
        elseif ($Identity -cne $script:R.previous.pilotId) {throw 'SELFTEST_CONTAINER_SCOPE'}
        return @{Id=$Identity;State=@{Status=$Status;Health=@{Status='healthy'}};Config=@{Env=@()};HostConfig=@{}}
    }
    function Public-Inspect {param($C) return $C}
    function Helper {param($Payload,[string[]]$Mounts=@(),[string]$Image='', [switch]$InsidePilot)
        if ($Payload.action -ceq 'inspect') {if ($script:Changed) {return @{hash='changed'}};return @{hash='preserved'}}
        if ($Payload.action -cne 'admit') {throw 'SELFTEST_HELPER_SCOPE'};return @{admission='PASS'}
    }
    function Admit-Previous {param([string]$Status) if ($Status -cne $script:OldState) {throw 'SELFTEST_OLD_STATE'}}
    function Assert-Production {}
    function Assert-OnlyWriter {param([string]$Volume,[string]$AllowedId='') if ($Volume -cne $script:R.previous.stateVolume) {throw 'SELFTEST_VOLUME_SCOPE'}}
    function Save-Record {}
    function Wait-Healthy {param([string]$Id) if ($Id -cne $script:R.previous.pilotId) {throw 'SELFTEST_HEALTH_SCOPE'}}
    function Docker-Text {param([string[]]$Arguments)
        if ($Arguments[0] -ceq 'stop' -and $Arguments[3] -ceq $script:R.pilotId) {$script:NewState='exited';$script:Actions.Add('stop-new')}
        elseif ($Arguments[0] -ceq 'start' -and $Arguments[1] -ceq $script:R.previous.pilotId) {$script:OldState='running';$script:Actions.Add('start-m1')}
        else {throw 'SELFTEST_LIFECYCLE_SCOPE'};return ''
    }
    Return-M1
    if (($script:Actions -join ',') -cne 'stop-new,start-m1') {throw 'FILE_PR_RETURN_SEQUENCE_SELFTEST_FAILED'}
    Return-M1
    if ($script:Actions.Count -ne 2) {throw 'FILE_PR_RETURN_REPLAY_SELFTEST_FAILED'}
    $script:R.phase='Running';$script:NewState='running';$script:OldState='exited';$script:Actions.Clear();$script:Changed=$true;$Denied=$false
    try {Return-M1} catch {if ($_.Exception.Message -ceq 'FILE_PR_RETAINED_M1_STATE_CHANGED') {$Denied=$true} else {throw}}
    if (-not $Denied -or ($script:Actions -join ',') -cne 'stop-new') {throw 'FILE_PR_CHANGED_M1_SELFTEST_FAILED'}
    $script:R.ciReads=$true;$script:R.phase='Running';$script:NewState='running';$script:OldState='exited';$script:Actions.Clear();$script:Changed=$false
    Return-M1
    if ($script:R.phase -cne 'ReturnedM2' -or ($script:Actions -join ',') -cne 'stop-new,start-m1') {throw 'CI_READ_RETURN_M2_SELFTEST_FAILED'}
    Return-M1
    if ($script:Actions.Count -ne 2) {throw 'CI_READ_RETURN_REPLAY_SELFTEST_FAILED'}
    $script:R.phase='Running';$script:NewState='running';$script:OldState='exited';$script:Actions.Clear();$script:Changed=$true;$Denied=$false
    try {Return-M1} catch {if ($_.Exception.Message -ceq 'FILE_PR_RETAINED_M1_STATE_CHANGED') {$Denied=$true} else {throw}}
    if (-not $Denied -or ($script:Actions -join ',') -cne 'stop-new') {throw 'CI_READ_CHANGED_M2_SELFTEST_FAILED'}
    Write-Host 'FORTIS_GITHUB_FILE_PR_WINDOWS_SELFTEST_PASS cases=18'
    return
}

Check-Package
$script:Helper64=Code64 (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'github_pilot_helpers.py') -Raw)
if ((Docker-Text @('info','--format','{{.OSType}}')) -cne 'linux') {throw 'PILOT_LINUX_DOCKER_ENGINE_REQUIRED'}
if ($Mode -ceq 'Start') {
    $IsCI=$ScenarioKind -ceq 'CIRead'
    if (-not $PreviousRecord -or $Record -or
        (-not $IsCI -and -not $ConfirmPullRequestsPermission) -or
        ($IsCI -and (-not $ConfirmActionsReadPermission -or $ExpectedWorkflowRunId -le 0))) {throw 'PILOT_PREVIOUS_RECORD_AND_REQUIRED_PERMISSION_ACK_REQUIRED'}
    $P=Read-ProtectedRecord $PreviousRecord
    if ($IsCI) {Assert-M2Record $P} else {Assert-M1Record $P}
    $Schema=2;if ($IsCI) {$Schema=3}
    $Id=[Guid]::NewGuid().ToString('N');$ScenarioId=([Guid]::ParseExact($Id,'N')).ToString('D')
    $script:RecordPath=Join-Path (Join-Path (Join-Path $env:LOCALAPPDATA 'Fortis\GitHubPilot') $Id) 'record.json'
    Protect-Directory (Split-Path $script:RecordPath -Parent)
    $script:R=[ordered]@{schema=$Schema;ciReads=$IsCI;result=$null;runId=$Id;phase='Prepared';sourceCommit=$ExpectedSourceCommit;previous=$P
        previousStopped=$false;productionBaseline=$P.productionBaseline;owner=$P.owner;repository=$P.repository
        filePrBranch=$P.scenario.approve.branch;image='';pilotId='';pilotName=('fortis-github-pilot-' + $Id)
        stateVolume=('fortis-github-pilot-state-' + $Id);tokenVolume=$P.tokenVolume;sourceReceipt=$null;receipt=$null
        scenario=[ordered]@{format='fortis-github-file-pr-v1';runId=$ScenarioId;owner=$P.owner;repository=$P.repository
            branch=$P.scenario.approve.branch;path=('docs/fortis-e2e/' + $P.scenario.runId + '.txt');expectedHeadSha=$P.scenario.sourceSha
            baseSha=$null;pushRequestId=[Guid]::NewGuid().ToString('D');prRequestId=[Guid]::NewGuid().ToString('D')
            phase='READ';commitSha=$null;pullRequestNumber=$null}}
    if ($IsCI) {
        $script:R.filePrBranch=$P.filePrBranch
        $script:R.scenario=[ordered]@{format='fortis-github-ci-read-v1';runId=$ScenarioId;owner=$P.owner;repository=$P.repository
            branch=$P.filePrBranch;headSha=$P.scenario.commitSha;pullRequestNumber=$P.scenario.pullRequestNumber
            workflowRunId=$ExpectedWorkflowRunId;phase='READ'}
    }
    Save-Record
} else {
    if (-not $Record) {throw 'FILE_PR_EXISTING_RECORD_REQUIRED'}
    $script:R=Read-ProtectedRecord $Record
    if ($ScenarioKind -ceq 'CIRead') {
        Assert-M2Record $script:R.previous
        if ($script:R.schema -ne 3 -or $script:R.ciReads -ne $true) {throw 'CI_READ_RECORD_KIND_INVALID'}
    } else {
        Assert-M1Record $script:R.previous
        if ($script:R.schema -ne 2 -or $script:R.ciReads) {throw 'FILE_PR_RECORD_KIND_INVALID'}
    }
    if ($script:R.sourceCommit -cne $ExpectedSourceCommit -or
        $script:R.runId -cnotmatch '^[0-9a-f]{32}$' -or $script:R.pilotName -cne ('fortis-github-pilot-' + $script:R.runId) -or
        $script:R.stateVolume -cne ('fortis-github-pilot-state-' + $script:R.runId) -or
        $script:R.tokenVolume -cne $script:R.previous.tokenVolume -or
        (($script:R.ciReads -and $script:R.filePrBranch -cne $script:R.previous.filePrBranch) -or
         (-not $script:R.ciReads -and $script:R.filePrBranch -cne $script:R.previous.scenario.approve.branch))) {throw 'FILE_PR_RECORD_IDENTITY_INVALID'}
}
Write-Host ('FILE_PR_RECORD=' + $script:RecordPath)
if ($Mode -ceq 'Rollback') {Return-M1;return}
if ($script:R.phase -cin @('Running','Complete')) {
    try {Run-SelectedScenario} catch {Write-Host 'FILE_PR_PAUSED_RESUME_SAME_RECORD_OR_ROLLBACK';throw};return
}
Assert-ExtensionPrepared
Build-PilotImage
Admit-Previous 'running';Assert-Production
foreach ($Name in @($script:R.previous.stateVolume,$script:R.tokenVolume,'fortis-r7-identity','fortis-r7-grant','fortis-r7-sonar-token')) {Assert-Volume $Name}
Assert-OnlyWriter $script:R.previous.stateVolume $script:R.previous.pilotId
# Verify the accepted M1 receipt in its running Gateway before stopping it.
$NewId=$script:R.pilotId
try {
    $script:R.pilotId=$script:R.previous.pilotId
    if ($script:R.ciReads) {
        $null=Helper @{action='file_pr_receipts';scenario=$script:R.previous.scenario} -InsidePilot
    } else {
        $C=$script:R.previous.scenario.approve
        $null=Helper @{action='receipt';expected=@{request_id=$C.requestId;repository=$script:R.repository
            branch=$C.branch;sha=$script:R.previous.scenario.sourceSha}} -InsidePilot
    }
} finally {$script:R.pilotId=$NewId}
Create-PilotVolume $script:R.stateVolume 'file-pr-isolated-state'
try {
    Admit-Previous 'running';Assert-Production
    $null=Docker-Text @('stop','--timeout','20',$script:R.previous.pilotId)
    $script:R.previousStopped=$true;Save-Record
    Admit-Previous 'exited';Assert-OnlyWriter $script:R.previous.stateVolume
    $script:R.sourceReceipt=Helper @{action='clone';github=$true} -Root -Mounts @('--mount',
        ('type=volume,source=' + $script:R.previous.stateVolume + ',target=/source,readonly'),
        '--mount',('type=volume,source=' + $script:R.stateVolume + ',target=/target'))
    $script:R.phase='StateCopied';Save-Record
    Create-PilotContainer
    $script:R.phase='Running';Save-Record
} catch {
    Write-Host ('FILE_PR_SETUP_FAILED_RECORD=' + $script:RecordPath)
    try {Return-M1} catch {Write-Host 'FILE_PR_RETURN_REQUIRES_INSPECTION';throw}
    throw
}
try {Run-SelectedScenario} catch {Write-Host 'FILE_PR_PAUSED_RESUME_SAME_RECORD_OR_ROLLBACK';throw}
