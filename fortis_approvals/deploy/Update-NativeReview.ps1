# Windows PowerShell 5.1. Owner-run update of the accepted native review only.
[CmdletBinding()]
param(
    [ValidateSet('Start','Rollback','SelfTest')][string]$Mode='Start',
    [string]$Record='',
    [string]$AnalysisConfig=''
)
$RequestedMode=$Mode; $RequestedRecord=$Record; $RequestedConfig=$AnalysisConfig
. (Join-Path $PSScriptRoot 'Run-GitHub-Pilot-E2E.ps1') -Mode Functions
$Mode=$RequestedMode; $Record=$RequestedRecord; $AnalysisConfig=$RequestedConfig
$Image='sha256:515ad033db0a4af7e2d29a3138d53d6a3f6e8e7909bd884145828bcc6ea28a4d'
$ImageRevision='2f88d92091e7d652ea0f33486fbeb38f2eaedd21'
$PreviousPath=Join-Path $env:LOCALAPPDATA 'Fortis\GitHubPilot\bf089ec8547f4a0bbc95004f692e70bf\record.json'
if (-not $Record) { $Record=Join-Path $env:LOCALAPPDATA 'Fortis\GitHubPilot\review-update-515ad033\record.json' }
$script:RecordPath=[IO.Path]::GetFullPath($Record)
$script:Helper64=Code64 (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'github_pilot_helpers.py') -Raw)

function Json-Items {
    param([string]$Text)
    # ConvertFrom-Json in Windows PowerShell 5.1 returns a root array as one object.
    # Explicit iteration prevents @(pipeline)[0] from retaining a nested array.
    $Parsed=ConvertFrom-Json -InputObject $Text
    foreach ($Item in $Parsed) { Write-Output $Item }
}
function Docker-Json {
    param([string[]]$Arguments)
    Json-Items (Docker-Text $Arguments)
}
function Run-Python {
    param([string]$Code,[string]$InputText='', [string[]]$Arguments=@())
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<review-update>','exec'))"
    Private-Process ($Arguments + @('python','-I','-B','-c',$Wrapper)) $InputText
}
function Image-Python {
    param([string]$Code,[string]$InputText='')
    # No state/credential mounts and no network for image/config validation.
    $Encoded=Code64 $Code
    $Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<review-update>','exec'))"
    Private-Process @('run','--rm','-i','--pull=never','--network','none','--read-only',
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64',
        '--memory','256m','--tmpfs','/tmp:rw,noexec,nosuid,size=32m,mode=1777','--entrypoint','python',$Image,'-I','-B','-c',$Wrapper) $InputText
}
function Same-Json {
    param($Left,$Right)
    (ConvertTo-Json -InputObject $Left -Depth 25 -Compress) -ceq (ConvertTo-Json -InputObject $Right -Depth 25 -Compress)
}
function Check-PreviousRecord {
    $SavedPath=$script:RecordPath
    try {
        $script:RecordPath=$PreviousPath; Assert-RecordAcl
        $P=Get-Content -LiteralPath $PreviousPath -Raw | ConvertFrom-Json
    } finally { $script:RecordPath=$SavedPath }
    if ($P.schema -ne 4 -or $P.phase -cne 'Complete' -or $P.scenario.phase -cne 'DONE' -or
        $P.pilotId -cne '065ad0fff10264f210e766db3c672566c4300f3e24d6fd21e2fbb7774f77c4e7' -or
        $P.image -cne 'sha256:e3ef9029a13284f5baadc7c1529c5d3b94a67fc9c045be1ed91950937c46c5f1' -or
        $P.pilotName -cne 'fortis-github-pilot-bf089ec8547f4a0bbc95004f692e70bf' -or
        $P.stateVolume -cne 'fortis-github-pilot-state-bf089ec8547f4a0bbc95004f692e70bf' -or
        $P.tokenVolume -cne 'fortis-github-pilot-token-c6884d29cfc74dfc8cc80081720792df' -or
        $P.owner -cne 'AlexPastukhh' -or $P.repository -cne 'fortis-approvals' -or
        $P.nativeWorktree -ne $true -or $P.ciReads -ne $true -or
        $P.requiredWorkflows -cne '408327525' -or $P.bootstrapTask -cne 'gateway-worktree-native-git-20261106' -or
        $P.sourceCommit -cne '06791650ca86617e5c9f951439ef8cc53ec98847' -or
        $P.sourceWorktree -cne '/workspace/repo/Worktrees/fortis-approvals/gateway-worktree-native-git-20261106') {
        throw 'UPDATE_ACCEPTED_NATIVE_RECORD_REQUIRED'
    }
    return $P
}
function Admit-Update {
    param($C,$P,[switch]$Candidate,[switch]$AllowUnhealthy)
    $E=@{id=$P.pilotId;name=$P.pilotName;image=$P.image;stateVolume=$P.stateVolume;tokenVolume=$P.tokenVolume
        owner=$P.owner;repository=$P.repository;filePrBranch=$P.filePrBranch;ciReads=$P.ciReads
        nativeWorktree=$P.nativeWorktree;requiredWorkflows=$P.requiredWorkflows;bootstrapTask=$P.bootstrapTask
        status=$C.State.Status;requireHealthy=(-not $AllowUnhealthy)}
    $Public=Public-Inspect $C
    if ($Candidate) {
        if ($C.Config.Labels.'io.fortis.review-update' -cne $script:R.runId) { throw 'UPDATE_CONTAINER_PROVENANCE_INVALID' }
        $Entries=@($Public.Config.Env | Where-Object { $_.StartsWith('FORTIS_ANALYSIS_REVIEW_CONFIG=') })
        if ($script:R.analysisConfig) {
            if ($Entries.Count -ne 1 -or $Entries[0] -cne ('FORTIS_ANALYSIS_REVIEW_CONFIG=' + $script:R.analysisConfig)) {
                throw 'UPDATE_ANALYSIS_CONFIG_CHANGED'
            }
            $Public.Config.Env=@($Public.Config.Env | Where-Object { -not $_.StartsWith('FORTIS_ANALYSIS_REVIEW_CONFIG=') })
        } elseif ($Entries.Count) { throw 'UPDATE_UNEXPECTED_ANALYSIS_CONFIG' }
    }
    $null=Helper @{action='admit';container=$Public;expected=$E;pilot=$true} -Image $Image
}
function Source-Receipt {
    Helper @{action='inspect';github=$true} -Image $script:R.previous.image -Mounts @('--mount',
        ('type=volume,source=' + $script:R.previous.stateVolume + ',target=/source,readonly'))
}
function Check-RetainedSource {
    if ((Get-FileHash -LiteralPath $PreviousPath -Algorithm SHA256).Hash -cne $script:R.previousRecordHash) {
        throw 'UPDATE_PREVIOUS_RECORD_CHANGED'
    }
    Assert-OnlyWriter $script:R.previous.stateVolume
    if ($script:R.sourceReceipt -and -not (Same-Json (Source-Receipt) $script:R.sourceReceipt)) {
        throw 'UPDATE_RETAINED_STATE_CHANGED'
    }
}
function Find-Candidate {
    $Names=(Docker-Text @('ps','-a','--format','{{.Names}}')) -split '\r?\n'
    if ($Names -cnotcontains $script:R.pilotName) {
        if ($script:R.pilotId) { throw 'UPDATE_RECORDED_CONTAINER_MISSING' }
        return $null
    }
    $C=Container $script:R.pilotName
    Admit-Update $C $script:R -Candidate -AllowUnhealthy
    if (-not $script:R.pilotId) { $script:R.pilotId=$C.Id; Save-Record }
    return $C
}
function Assert-UpdateRecord {
    $P=Check-PreviousRecord
    if ($script:R.schema -ne 5 -or $script:R.image -cne $Image -or $script:R.imageRevision -cne $ImageRevision -or
        $script:R.runId -cnotmatch '^[0-9a-f]{32}$' -or
        $script:R.pilotName -cne ('fortis-github-pilot-' + $script:R.runId) -or
        $script:R.stateVolume -cne ('fortis-github-pilot-state-' + $script:R.runId) -or
        ($script:R.pilotId -and $script:R.pilotId -cnotmatch '^[0-9a-f]{64}$') -or
        $script:R.phase -cnotin @('Prepared','Stopping','Stopped','Cloning','Creating','Created','Starting','Complete','Returned') -or
        -not (Same-Json $script:R.previous $P) -or
        $script:R.previousRecordHash -cne (Get-FileHash -LiteralPath $PreviousPath -Algorithm SHA256).Hash) {
        throw 'UPDATE_RECORD_IDENTITY_INVALID'
    }
    foreach ($Key in @('owner','repository','tokenVolume','filePrBranch','ciReads','nativeWorktree','requiredWorkflows','bootstrapTask')) {
        if ($script:R.$Key -cne $P.$Key) { throw 'UPDATE_NATIVE_CONFIG_CHANGED' }
    }
}
function Return-Previous {
    Assert-UpdateRecord
    if ($script:R.phase -ceq 'Complete') { throw 'UPDATE_COMPLETE_RETURN_REQUIRES_NEW_REVIEW' }
    Assert-Production
    $C=Find-Candidate
    if ($C) {
        if ($C.State.Status -cnotin @('created','exited','running')) { throw 'UPDATE_CANDIDATE_STATUS_UNKNOWN' }
        if ($C.State.Status -ceq 'running') { $null=Docker-Text @('stop','--timeout','20',$C.Id) }
        $C=Container $C.Id; Admit-Update $C $script:R -Candidate -AllowUnhealthy
        if ($C.State.Status -cnotin @('created','exited')) { throw 'UPDATE_CANDIDATE_STOP_UNCONFIRMED' }
    }
    $Old=Container $script:R.previous.pilotId
    if ($Old.State.Status -ceq 'running') {
        if ($script:R.stopIntent -and $script:R.phase -cne 'Returned') { throw 'UPDATE_PREVIOUS_RESTARTED_OUTSIDE_RUN' }
        Admit-Update $Old $script:R.previous
    } else {
        if (-not $script:R.stopIntent -or $Old.State.Status -cne 'exited') { throw 'UPDATE_PREVIOUS_STATUS_UNKNOWN' }
        Admit-Update $Old $script:R.previous; Check-RetainedSource
        $null=Docker-Text @('start',$Old.Id)
        Wait-Healthy $Old.Id; Admit-Update (Container $Old.Id) $script:R.previous
    }
    Assert-Production
    $script:R.phase='Returned'; Save-Record
    Write-Host 'FORTIS_REVIEW_UPDATE_RETURNED_PREVIOUS'
}
function Create-Replacement {
    $CreateArguments=@('create','--pull=never','--name',$script:R.pilotName,'--restart','no','--init',
        '--label',('io.fortis.review-update=' + $script:R.runId),
        '--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','100','--memory','512m','--memory-swap','1g','--network','bridge',
        '--tmpfs','/tmp:rw,nosuid,nodev,size=16m',
        '--publish','127.0.0.1:19203:19103','--publish','127.0.0.1:19204:19104',
        '--mount',('type=volume,source=' + $script:R.stateVolume + ',target=/state'),
        '--mount',('type=volume,source=' + $script:R.tokenVolume + ',target=/run/github-token,readonly'),
        '--mount','type=volume,source=fortis-r7-identity,target=/run/r7-identity,readonly',
        '--mount','type=volume,source=fortis-r7-grant,target=/run/r7-grant,readonly',
        '--mount','type=volume,source=fortis-r7-sonar-token,target=/run/r7-sonar-token,readonly',
        '--health-cmd','python -m fortis_approvals.r7_unified_server health',
        '--health-interval','20s','--health-timeout','5s','--health-retries','3','--health-start-period','20s')
    $Old=Container $script:R.previous.pilotId
    Admit-Update $Old $script:R.previous
    foreach ($Entry in @($Old.Config.Env | Where-Object { $_.StartsWith('FORTIS_') })) { $CreateArguments+=@('--env',$Entry) }
    # Keep JSON out of native argv: PowerShell 5.1 quoting must not corrupt it.
    $EnvFile=Join-Path (Split-Path $script:RecordPath -Parent) 'analysis.env'
    $CreatedEnv=$false
    try {
        if ($script:R.analysisConfig) {
            if (Test-Path -LiteralPath $EnvFile) { throw 'UPDATE_ENV_FILE_ALREADY_EXISTS' }
            [IO.File]::WriteAllText($EnvFile,('FORTIS_ANALYSIS_REVIEW_CONFIG=' + $script:R.analysisConfig + "`n"),[Text.UTF8Encoding]::new($false))
            $CreatedEnv=$true
            $CreateArguments+=@('--env-file',$EnvFile)
        }
        $script:R.phase='Creating'; Save-Record
        $script:R.pilotId=Docker-Text ($CreateArguments + @($script:R.image))
        if ($script:R.pilotId -cnotmatch '^[0-9a-f]{64}$') { throw 'UPDATE_CREATED_ID_INVALID' }
        $script:R.phase='Created'; Save-Record
    } finally { if ($CreatedEnv -and (Test-Path -LiteralPath $EnvFile)) { Remove-Item -LiteralPath $EnvFile -Force } }
    Admit-Update (Container $script:R.pilotId) $script:R -Candidate
}
function Check-Clients {
    $Code=@'
import json,sys,uuid
sys.path.insert(0,'/workspace/repo/Repos/fortis-approvals')
from fortis_approvals.workflow.client import WorkflowTransport
from fortis_approvals.integrations.github.repo_client.client import GitHubClient
g=WorkflowTransport(endpoint='https://host.docker.internal:19204',allow_test_endpoint=True)
caps=g.post('/v1/workspace/capabilities',{})
assert caps['owner']=='AlexPastukhh' and caps['repository']=='fortis-approvals'
assert caps['gitHubCredentialInRepo'] is False and caps['branchPrefix']=='task/'
branches=GitHubClient(gateway=g).list_branches('fortis-approvals')
assert any(x['name']=='main' for x in branches['items'])
r=g.post('/v1/reads',dict(requestId=str(uuid.uuid4()),service='sonarcloud',operation='get_quality_gate',target='AlexPastukhh_obs-planning-docs',params={},reason='Review image update read-only regression'))
assert r['data']['status'] in ('OK','ERROR','WARN','NONE')
print(json.dumps(dict(nativeCapabilities=True,githubRead=True,sonarRead=True)))
'@
    $script:R.clientChecks=(Run-Python $Code '' @('exec','-i','--user','1000:1000','fortis-repo-test')) | ConvertFrom-Json
}
function Test-Local {
    $Items=@(Json-Items '[{"Id":"one"},{"Id":"two"}]')
    $One=@(Json-Items '[{"Id":"one"}]')
    if ($Items.Count -ne 2 -or $Items[0].Id -cne 'one' -or $Items[1].Id -cne 'two' -or
        $One.Count -ne 1 -or $One[0].Id -cne 'one' -or @(Json-Items '[]').Count -ne 0) {
        throw 'UPDATE_JSON_ARRAY_SELFTEST_FAILED'
    }
    $InputProbe='{"binding":{"workflows":{"408327525":".github/workflows/source-ci.yml"}},"items":[1,2]}'
    $Echo='[Console]::Out.Write([Console]::In.ReadToEnd())'
    $EncodedEcho=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Echo))
    $OutputProbe=Private-Process @('-NoProfile','-NonInteractive','-EncodedCommand',$EncodedEcho) $InputProbe (Join-Path $PSHOME 'powershell.exe')
    if ($OutputProbe -cne $InputProbe) { throw 'UPDATE_PRIVATE_PROCESS_SELFTEST_FAILED' }
    $SavedPath=$script:RecordPath; $SavedR=$script:R
    $Directory=Join-Path $env:TEMP ('fortis-review-update-selftest-' + [Guid]::NewGuid().ToString('N'))
    $CreatedDirectory=$false
    try {
        Protect-Directory $Directory; $CreatedDirectory=$true
        $script:RecordPath=Join-Path $Directory 'record.json'; $script:R=@{phase='Prepared';stopIntent=$false}
        Save-Record; $script:R.phase='Stopped'; Save-Record
        $Read=Get-Content -LiteralPath $script:RecordPath -Raw | ConvertFrom-Json
        if ($Read.phase -cne 'Stopped' -or $Read.stopIntent -ne $false) { throw 'UPDATE_RECORD_SELFTEST_FAILED' }
    } finally {
        $script:RecordPath=$SavedPath; $script:R=$SavedR
        if ($CreatedDirectory -and (Test-Path -LiteralPath $Directory)) { Remove-Item -LiteralPath $Directory -Recurse -Force }
    }
}

if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or
    $PSVersionTable.PSEdition -cne 'Desktop') { throw 'UPDATE_WINDOWS_POWERSHELL_51_REQUIRED' }
Test-Local
if ($Mode -eq 'SelfTest') { Write-Host 'FORTIS_REVIEW_UPDATE_SELFTEST_PASS'; return }
if ($Mode -eq 'Rollback') {
    Assert-RecordAcl
    $script:R=Get-Content -LiteralPath $script:RecordPath -Raw | ConvertFrom-Json
    Return-Previous; return
}
if (Test-Path -LiteralPath $script:RecordPath) { throw 'UPDATE_RECORD_EXISTS_USE_ROLLBACK_OR_INSPECT' }
$Previous=Check-PreviousRecord
$Baseline=Production-Baseline
Admit-Update (Container $Previous.pilotId) $Previous
Assert-OnlyWriter $Previous.stateVolume $Previous.pilotId
foreach ($Name in @($Previous.stateVolume,$Previous.tokenVolume,'fortis-r7-identity','fortis-r7-grant','fortis-r7-sonar-token')) { Assert-Volume $Name }
$Images=@(Docker-Json @('image','inspect',$Image))
if ($Images.Count -ne 1 -or $Images[0].Id -cne $Image -or
    $Images[0].Config.Labels.'org.opencontainers.image.revision' -cne $ImageRevision) { throw 'UPDATE_IMAGE_IDENTITY_INVALID' }
$Smoke="import sys;sys.path.insert(0, '/opt/fortis')`n" + (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'image_offline_smoke.py') -Raw) + @'

from fortis_approvals.integrations.analysis_review import AnalysisReviewConfig
from fortis_approvals.integrations.sonarcloud.gateway.analysis_transport import SonarAnalysisTransport
from fortis_approvals.integrations.github.gateway.analysis_adapter import AnalysisGitHubAdapter
print('IMAGE_ANALYSIS_REVIEW_IMPORT_PASS')
'@
$SmokeResult=Image-Python $Smoke
foreach ($Marker in @('IMAGE_NATIVE_GIT_IMPORT_PASS','IMAGE_SONAR_OFFLINE_SMOKE_PASS','IMAGE_GITHUB_IMPORT_PASS',
    'IMAGE_GITHUB_NOT_REGISTERED_PASS','IMAGE_ANALYSIS_REVIEW_IMPORT_PASS')) {
    if (($SmokeResult -split '\r?\n') -cnotcontains $Marker) { throw 'UPDATE_IMAGE_SMOKE_FAILED' }
}
$Config=''
if ($AnalysisConfig) {
    $Raw=Get-Content -LiteralPath $AnalysisConfig -Raw
    $Validate=@'
import json,sys
sys.path.insert(0,'/opt/fortis')
from fortis_approvals.integrations.analysis_review import AnalysisReviewConfig
raw=sys.stdin.read(); c=AnalysisReviewConfig.from_environment({'FORTIS_ANALYSIS_REVIEW_CONFIG':raw})
c.check_endpoints('http://localhost:19203','host.docker.internal:19204')
assert c.owner=='AlexPastukhh' and all(b['projectKey']=='AlexPastukhh_obs-planning-docs' for b in c.bindings.values())
print(json.dumps(json.loads(raw),separators=(',',':')))
'@
    $Config=Image-Python $Validate $Raw
}
$RunId=[Guid]::NewGuid().ToString('N')
$script:R=[ordered]@{schema=5;runId=$RunId;phase='Prepared';stopIntent=$false;pilotId=''
    pilotName=('fortis-github-pilot-' + $RunId);stateVolume=('fortis-github-pilot-state-' + $RunId)
    image=$Image;imageRevision=$ImageRevision;previous=$Previous;previousRecordHash=(Get-FileHash -LiteralPath $PreviousPath -Algorithm SHA256).Hash
    productionBaseline=$Baseline;sourceReceipt=$null;analysisConfig=$Config;clientChecks=$null
    owner=$Previous.owner;repository=$Previous.repository;tokenVolume=$Previous.tokenVolume;filePrBranch=$Previous.filePrBranch
    ciReads=$true;nativeWorktree=$true;requiredWorkflows=$Previous.requiredWorkflows;bootstrapTask=$Previous.bootstrapTask}
if (((Docker-Text @('volume','ls','--format','{{.Name}}')) -split '\r?\n') -ccontains $script:R.stateVolume -or
    ((Docker-Text @('ps','-a','--format','{{.Names}}')) -split '\r?\n') -ccontains $script:R.pilotName) {
    throw 'UPDATE_PLANNED_RESOURCE_EXISTS'
}
Protect-Directory (Split-Path $script:RecordPath -Parent); Save-Record
try {
    Assert-UpdateRecord
    Assert-Production; Admit-Update (Container $Previous.pilotId) $Previous
    Assert-OnlyWriter $Previous.stateVolume $Previous.pilotId
    $script:R.phase='Stopping'; $script:R.stopIntent=$true; Save-Record
    $null=Docker-Text @('stop','--timeout','20',$Previous.pilotId)
    $Old=Container $Previous.pilotId; Admit-Update $Old $Previous
    if ($Old.State.Status -cne 'exited') { throw 'UPDATE_OLD_STOP_UNCONFIRMED' }
    $script:R.phase='Stopped'; Save-Record
    Assert-OnlyWriter $Previous.stateVolume
    $script:R.sourceReceipt=Source-Receipt; Save-Record
    $script:R.phase='Cloning'; Save-Record
    $null=Docker-Text @('volume','create','--label',('io.fortis.review-update=' + $RunId),$script:R.stateVolume)
    Assert-Volume $script:R.stateVolume; Assert-OnlyWriter $script:R.stateVolume
    $V=@(Docker-Json @('volume','inspect',$script:R.stateVolume))[0]
    if ($V.Labels.'io.fortis.review-update' -cne $RunId) { throw 'UPDATE_STATE_PROVENANCE_INVALID' }
    $Cloned=Helper @{action='clone';github=$true} -Root -Mounts @('--mount',
        ('type=volume,source=' + $Previous.stateVolume + ',target=/source,readonly'),'--mount',
        ('type=volume,source=' + $script:R.stateVolume + ',target=/target'))
    if (-not (Same-Json $Cloned $script:R.sourceReceipt)) { throw 'UPDATE_CLONE_RECEIPT_MISMATCH' }
    Check-RetainedSource; Assert-Production
    Create-Replacement
    Assert-OnlyWriter $script:R.stateVolume
    $script:R.phase='Starting'; Save-Record
    $null=Docker-Text @('start',$script:R.pilotId)
    Wait-Healthy $script:R.pilotId; Admit-Update (Container $script:R.pilotId) $script:R -Candidate
    Assert-OnlyWriter $script:R.stateVolume $script:R.pilotId
    Check-Clients; Check-RetainedSource; Assert-Production
    $script:R.phase='Complete'; Save-Record
    [ordered]@{image=$Image;record=$script:RecordPath;review='http://localhost:19203';previousRetained=$true
        productionUnchanged=$true;analysisProfileConfigured=[bool]$Config;newOperationsLiveVerified=$false
        checks=$script:R.clientChecks} | ConvertTo-Json -Depth 5
    Write-Host 'FORTIS_REVIEW_IMAGE_UPDATE_PASS'
    if (-not $Config) { Write-Host 'ANALYSIS_OPERATIONS_DISABLED_CONFIGURATION_PENDING' }
} catch {
    $Failure=$_.Exception.Message
    try { Return-Previous } catch { Write-Warning ('UPDATE_RETURN_INCOMPLETE: ' + $_.Exception.Message) }
    throw ('REVIEW_UPDATE_FAILED: ' + $Failure + '; record=' + $script:RecordPath)
}
