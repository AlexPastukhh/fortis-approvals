# Windows PowerShell 5.1. Owner-only review controller; tokens never enter argv.
[CmdletBinding()]
param(
    [ValidateSet('Apply','Credential','Check','Return','SelfTest')][string]$Action='Check',
    [string]$Config='', [string]$Image='', [string]$SourceSha='', [string]$CurrentRecord='',
    [string]$AttemptRecord='', [string]$CredentialName='', [switch]$Rotate,
    [ValidateSet('github','sonarcloud')][string]$Service='',
    [switch]$Build, [switch]$Pull,
    [string]$VaultVolume='fortis-review-secrets', [string]$Probes=''
)
$ForwardParameters=@{}+ $PSBoundParameters
. (Join-Path $PSScriptRoot 'Run-GitHub-Pilot-E2E.ps1') -Mode Functions
$ErrorActionPreference='Stop'
$ReleaseBase=Join-Path $env:LOCALAPPDATA 'Fortis\GatewayReleases'
$Pointer=Join-Path $ReleaseBase 'current.json'
$AttemptPointer=Join-Path $ReleaseBase 'attempt.json'
$script:Step='PREFLIGHT';$script:Image=$Image

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
function Save { Save-Record }
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
function State-Helper {
    param($Payload,[string[]]$Mounts=@(),[switch]$Root)
    $Identity='10001:10001';if($Root){$Identity='0:0'}
    $Arguments=@('run','--rm','-i','--pull=never','--network','none','--read-only','--user',$Identity,
        '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','256m',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=32m')
    if($Root){$Arguments+=@('--cap-add','CHOWN','--cap-add','DAC_OVERRIDE')}
    $Code="import runpy;runpy.run_path('/opt/fortis/operator/state_helpers.py',run_name='__main__')"
    $Encoded=Code64 $Code;$Wrapper="import base64;exec(compile(base64.b64decode('$Encoded'),'<state-helper>','exec'))"
    (Private-Process ($Arguments+$Mounts+@('--entrypoint','python',$script:Image,'-I','-B','-c',$Wrapper)) (ConvertTo-Json -InputObject $Payload -Depth 25 -Compress)) | ConvertFrom-Json
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
            bootstrapTask=$Value.bootstrapTask;vaultVolume='';extensionsConfig='';releaseNonce='';runId=$Value.runId}
    } else {throw 'RELEASE_SOURCE_PROFILE_UNSUPPORTED'}
    return @{path=$Path;hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;runtime=$P}
}
function Admit {
    param($C,$P,[switch]$AllowUnhealthy)
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
        vaultVolume=$P.vaultVolume;status=$C.State.Status;requireHealthy=(-not $AllowUnhealthy)}
    $null=State-Helper @{action='admit';container=$Public;expected=$Expected;pilot=$true}
}
function Admit-ReturnCandidate {
    param($C,$P)
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
function Receipt {
    param([string]$Volume)
    State-Helper @{action='inspect';github=$true;native=$true} @('--mount',('type=volume,source='+$Volume+',target=/source,readonly'))
}
function Same-Json {param($A,$B) (ConvertTo-Json -InputObject $A -Compress -Depth 25) -ceq (ConvertTo-Json -InputObject $B -Compress -Depth 25)}
function Assert-SourceUnchanged {
    if((Get-FileHash -LiteralPath $script:R.source.path -Algorithm SHA256).Hash -cne $script:R.source.hash){throw 'RELEASE_SOURCE_RECORD_CHANGED'}
    Assert-OnlyWriter $script:R.source.runtime.stateVolume
    if($script:R.sourceReceipt -and -not (Same-Json (Receipt $script:R.source.runtime.stateVolume) $script:R.sourceReceipt)){throw 'RELEASE_SOURCE_STATE_CHANGED'}
}
function Return-Source {
    if($script:R.phase -ceq 'Complete' -or $script:R.activated){throw 'RELEASE_ACTIVE_RETURN_REQUIRES_REVIEW'}
    Assert-Production
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
    Assert-Production;$script:R.phase='Returned';Save
    Write-Host 'FORTIS_INTEGRATIONS_RETURNED_SOURCE'
}
function Resume-Target {
    $P=$script:R.runtime;$C=Container $P.pilotName;Admit $C $P -AllowUnhealthy
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
        $script:R.probesPassed=$true;Save
        Assert-SourceUnchanged;Assert-Production
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

. (Join-Path $PSScriptRoot 'Provider-Credentials.ps1')

if($Service -and $Action -cne 'Credential'){throw 'CREDENTIAL_SERVICE_ACTION_INVALID'}
if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or $PSVersionTable.PSEdition -cne 'Desktop'){throw 'RELEASE_WINDOWS_POWERSHELL_51_REQUIRED'}
if(@(Json-Items '[{"Id":"one"},{"Id":"two"}]').Count -ne 2 -or @(Json-Items '[{"Id":"one"}]')[0].Id -cne 'one'){throw 'RELEASE_JSON_SELFTEST_FAILED'}
if($Action -eq 'SelfTest'){
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
    $Index=[array]::IndexOf($Forwarded,'-SourceSha')
    if($Forwarded.Count -ne 3 -or $Forwarded -cnotcontains '-Build' -or $Index -lt 0 -or
       $Forwarded[$Index+1] -cne 'a value with spaces'){throw 'RELEASE_NATIVE_ARGUMENT_SELFTEST_FAILED'}
    Write-Host 'FORTIS_INTEGRATIONS_SELFTEST_PASS';return
}
if(-not (Test-Path -LiteralPath $ReleaseBase)){Protect-Directory $ReleaseBase}else{Assert-DirectoryAcl $ReleaseBase}
if($Pull -and -not $Build){throw 'RELEASE_PULL_REQUIRES_BUILD'}
if($Build -and ($Action -cnotin @('Apply','Check') -or $AttemptRecord)){throw 'RELEASE_BUILD_ACTION_INVALID'}
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
if($Action -eq 'Return' -or $AttemptRecord){
    if(-not $AttemptRecord){$AttemptRecord=(Read-Private $AttemptPointer).record}
    $script:RecordPath=[IO.Path]::GetFullPath($AttemptRecord);$script:R=Read-Private $script:RecordPath
    if($script:R.schema -cne 'fortis-extension-release-v1'){throw 'RELEASE_ATTEMPT_SCHEMA_INVALID'}
    if($script:Image -and $script:Image -cne $script:R.runtime.image){throw 'RELEASE_ATTEMPT_IDENTITY_MISMATCH'}
    $script:Image=$script:R.runtime.image;$VaultVolume=$script:R.runtime.vaultVolume
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
if($Action -eq 'Return' -or $AttemptRecord){
    if($Action -eq 'Return'){Return-Source;return}
    if($script:R.phase -cnotin @('Created','Staged')){throw 'RELEASE_RESUME_NOT_READY_USE_RETURN'}
    Resume-Target;return
}
if(-not $Config){throw 'RELEASE_PUBLIC_CONFIG_REQUIRED'}
$ConfigText=Get-Content -LiteralPath $Config -Raw
Step 'CONFIG_AND_CREDENTIAL_PREFLIGHT'
$Report=Image-CLI @('check') $ConfigText
if($Action -eq 'Apply'){
    foreach($Alias in @($Report.missingCredentials)){Put-Credential $Alias}
    $Report=Image-CLI @('check') $ConfigText
}
if($Report.status -cne 'READY'){throw 'RELEASE_CONFIG_OR_CREDENTIAL_NOT_READY'}
if($Action -eq 'Check'){$Report|ConvertTo-Json -Depth 12;return}
if(Test-Path -LiteralPath $AttemptPointer){
    $Last=Read-Private (Read-Private $AttemptPointer).record
    if($Last.phase -cnotin @('Complete','Returned')){throw 'RELEASE_PRIOR_ATTEMPT_REQUIRES_RESUME_OR_RETURN'}
}
Step 'IMAGE_OFFLINE_SMOKE'
$Smoke=Private-Process @('run','--rm','--pull=never','--network','none','--read-only','--cap-drop','ALL',
    '--security-opt','no-new-privileges:true','--pids-limit','64','--memory','256m',
    '--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--entrypoint','python',$script:Image,'-I','-B',
    '/opt/fortis/operator/image_smoke.py') ''
foreach($Marker in @('IMAGE_NATIVE_GIT_IMPORT_PASS','IMAGE_SONAR_OFFLINE_SMOKE_PASS','IMAGE_GITHUB_NOT_REGISTERED_PASS','IMAGE_EXTENSIONS_OFFLINE_PASS')){
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
$Source=Get-SourceRecord;$Old=Container $Source.runtime.pilotId;Admit $Old $Source.runtime
if($Old.State.Status -cne 'running'){throw 'RELEASE_SOURCE_NOT_RUNNING'}
Assert-OnlyWriter $Source.runtime.stateVolume $Old.Id
Step 'SOURCE_STATE_PREFLIGHT';$null=Receipt $Source.runtime.stateVolume
$Baseline=Production-Baseline
$RunId=[Guid]::NewGuid().ToString('N');$Directory=Join-Path $ReleaseBase $RunId;Protect-Directory $Directory
$script:RecordPath=Join-Path $Directory 'record.json'
$ConfigObject=ConvertFrom-Json -InputObject $ConfigText
$CompactConfig=ConvertTo-Json -InputObject $ConfigObject -Compress -Depth 20
$ProbeText='[]';if($Probes){$ProbeText=Get-Content -LiteralPath $Probes -Raw}
$Nonce=[Guid]::NewGuid().ToString('D')
$Runtime=[ordered]@{pilotId='';pilotName=('fortis-github-pilot-'+$RunId);image=$script:Image
    stateVolume=('fortis-github-pilot-state-'+$RunId);tokenVolume=$Source.runtime.tokenVolume
    owner=$Source.runtime.owner;repository=$Source.runtime.repository;filePrBranch=$Source.runtime.filePrBranch
    ciReads=$true;nativeWorktree=$true;requiredWorkflows=$Source.runtime.requiredWorkflows;bootstrapTask=$Source.runtime.bootstrapTask
    vaultVolume=$VaultVolume;extensionsConfig=$CompactConfig;releaseNonce=$Nonce;runId=$RunId}
$script:R=[ordered]@{schema='fortis-extension-release-v1';phase='Prepared';source=$Source;runtime=$Runtime
    productionBaseline=$Baseline;configurationDigest=$Report.configurationDigest;sourceReceipt=$null
    activated=$false;probesPassed=$false;probes=$ProbeText;failureStep='';failureMessage=''}
Save;Write-Private $AttemptPointer @{schema=1;record=$script:RecordPath}
try {
    Step 'PUBLIC_ENV_PREFLIGHT'
    $EnvFile=Join-Path $Directory 'public.env'
    $EnvLines=@($Old.Config.Env|Where-Object{$_.StartsWith('FORTIS_') -and -not $_.StartsWith('FORTIS_EXTENSIONS_CONFIG=') -and -not $_.StartsWith('FORTIS_RELEASE_NONCE=')})
    $EnvLines+=@(Extension-EnvLines $CompactConfig $Nonce)
    [IO.File]::WriteAllText($EnvFile,(($EnvLines -join "`n")+"`n"),[Text.UTF8Encoding]::new($false))
    Check-ExtensionEnv $EnvLines $CompactConfig $Nonce
    Assert-PublicEnvFile $EnvFile $EnvLines
    Step 'STOP_SOURCE';Assert-Production;Admit (Container $Old.Id) $Source.runtime
    $null=Docker-Text @('stop','--timeout','20',$Old.Id)
    if((Container $Old.Id).State.Status -cne 'exited'){throw 'RELEASE_SOURCE_STOP_UNCONFIRMED'}
    Assert-OnlyWriter $Source.runtime.stateVolume
    $script:R.sourceReceipt=Receipt $Source.runtime.stateVolume;Save
    Step 'CLONE_STATE'
    $null=Docker-Text @('volume','create','--label',('io.fortis.release='+$RunId),$Runtime.stateVolume)
    Assert-Volume $Runtime.stateVolume;Assert-OnlyWriter $Runtime.stateVolume
    if(@(Docker-Json @('volume','inspect',$Runtime.stateVolume))[0].Labels.'io.fortis.release' -cne $RunId){throw 'RELEASE_STATE_VOLUME_PROVENANCE_INVALID'}
    $Clone=State-Helper @{action='clone';github=$true;native=$true} @('--mount',
        ('type=volume,source='+$Source.runtime.stateVolume+',target=/source,readonly'),'--mount',
        ('type=volume,source='+$Runtime.stateVolume+',target=/target')) -Root
    if(-not (Same-Json $Clone $script:R.sourceReceipt)){throw 'RELEASE_STATE_CLONE_MISMATCH'}
    Assert-SourceUnchanged
    Step 'CREATE_STAGED'
    $Arguments=@('create','--pull=never','--name',$Runtime.pilotName,'--label',('io.fortis.review-update='+$RunId),
        '--restart','no','--init','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','100','--memory','512m','--memory-swap','1g','--network','bridge','--tmpfs','/tmp:rw,nosuid,nodev,size=16m',
        '--env-file',$EnvFile,'--publish','127.0.0.1:19203:19103','--publish','127.0.0.1:19204:19104',
        '--mount',('type=volume,source='+$Runtime.stateVolume+',target=/state'),
        '--mount',('type=volume,source='+$Runtime.tokenVolume+',target=/run/github-token,readonly'),
        '--mount','type=volume,source=fortis-r7-identity,target=/run/r7-identity,readonly',
        '--mount','type=volume,source=fortis-r7-grant,target=/run/r7-grant,readonly',
        '--mount','type=volume,source=fortis-r7-sonar-token,target=/run/r7-sonar-token,readonly',
        '--mount',('type=volume,source='+$VaultVolume+',target=/run/fortis-secrets,readonly'),
        '--health-cmd','python -m fortis_approvals.r7_unified_server health','--health-interval','20s','--health-timeout','5s',
        '--health-retries','3','--health-start-period','20s',$script:Image)
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
