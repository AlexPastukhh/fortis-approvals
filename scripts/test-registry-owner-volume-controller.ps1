# Actual Windows PowerShell 5.1 fixture tests. No Docker or Git commands.
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'WINDOWS_POWERSHELL_5_REQUIRED' }
function docker { throw 'TEST_DOCKER_CALL_FORBIDDEN' }
function git { throw 'TEST_GIT_CALL_FORBIDDEN' }
foreach ($file in @('registry_owner_volume_controller.ps1','registry_owner_volume_preflight.ps1')) {
    $tokens=$null; $errors=$null
    $null=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file),[ref]$tokens,[ref]$errors)
    if (@($errors).Count -ne 0) { throw ($errors | Out-String) }
}
# Dot-source only the no-effect Plan branch to load the pure functions.
. (Join-Path $PSScriptRoot 'registry_owner_volume_controller.ps1') -Action Plan
$layout=@(New-Layout '9c2a71ef')
Need ($layout.Count -eq 3 -and $layout[2].Mode -eq 1480 -and $layout[2].Gid -eq 10001) 'FIXTURE_LAYOUT_INVALID'
$RegistryImageId='sha256:'+('a'*64)
$OperationId='12345678-1234-1234-1234-123456789abc'
$payload='Zml4dHVyZQ=='
$prepareName='fixture-prepare';$inspectName='fixture-inspect'
$rw=New-HelperArgs 'Prepare' $prepareName $RegistryImageId $layout $payload $OperationId
$ro=New-HelperArgs 'Inspect' $inspectName $RegistryImageId $layout $payload $OperationId
Need ($rw -ccontains '0:10001' -and $rw -ccontains 'CHOWN' -and $rw -ccontains 'FOWNER') 'FIXTURE_PREPARE_CAPS'
Need ($ro -ccontains '20002:20002' -and $ro -cnotcontains '--cap-add' -and $ro -ccontains 'ALL') 'FIXTURE_INSPECT_CAPS'
foreach ($row in $layout) {
    $mount='type=volume,src='+$row.Name+',dst='+$row.Destination+',volume-nocopy'
    Need ($rw -ccontains $mount -and $ro -ccontains ($mount+',readonly')) 'FIXTURE_MOUNT_ARGUMENTS'
}
Need ($null -eq (Optional-Prop ([pscustomobject]@{Type='bind'}) 'Name')) 'FIXTURE_OPTIONAL_PROP'
# Fixture inspect object with omitted optional HostConfig and mount ReadOnly fields.
function Assert-Volume { param([string]$Name) return ('/docker/volumes/'+$Name+'/_data') }
function Docker-Object { param([string[]]$Arguments) return $script:fixture }
function Assert-Rejected {
    param([scriptblock]$Block,[string]$Expected)
    $caught=$false
    try { & $Block } catch { if ($_.Exception.Message -notmatch [regex]::Escape($Expected)) { throw }; $caught=$true }
    if (-not $caught) { throw ('EXPECTED_REJECTION_'+$Expected) }
}
$helperId='b'*64
foreach ($phase in @('Prepare','Inspect')) {
    $readOnly=($phase -ceq 'Inspect');$name=$prepareName;$user='0:10001'
    if ($readOnly) { $name=$inspectName;$user='20002:20002' }
    $mounts=@();$requested=@()
    foreach ($row in $layout) {
        $mounts+=[pscustomobject]@{Type='volume';Name=$row.Name;Destination=$row.Destination;Driver='local';RW=(-not $readOnly);Source=(Assert-Volume $row.Name)}
        $m=[ordered]@{Type='volume';Source=$row.Name;Target=$row.Destination;VolumeOptions=[pscustomobject]@{NoCopy=$true}}
        if ($readOnly) { $m.ReadOnly=$true }
        $requested+=[pscustomobject]$m
    }
    $hostConfig=[ordered]@{Privileged=$false;ReadonlyRootfs=$true;AutoRemove=$false;NetworkMode='none';PidMode='';UsernsMode='';UTSMode='';IpcMode='private';CgroupnsMode='private';RestartPolicy=[pscustomobject]@{Name='no'};PidsLimit=64;Memory=134217728;CapDrop=@('ALL');LogConfig=[pscustomobject]@{Type='json-file';Config=[pscustomobject]@{'max-size'='1m';'max-file'='1'}};SecurityOpt=@('no-new-privileges:true');Mounts=$requested}
    if (-not $readOnly) { $hostConfig.CapAdd=@('CAP_CHOWN','CAP_FOWNER') }
    $script:fixture=[pscustomobject]@{Id=$helperId;Name=('/'+$name);Image=$RegistryImageId;State=[pscustomobject]@{Status='created'};HostConfig=[pscustomobject]$hostConfig;Mounts=$mounts;Config=[pscustomobject]@{User=$user;Labels=[pscustomobject]@{'fortis.registry.owner-operation'=$OperationId;'fortis.registry.owner-phase'=$phase};Entrypoint=@('python');Cmd=@('-I','-B','-c',"exec(__import__('base64').b64decode(__import__('sys').argv[1]))",$payload)}}
    Assert-Helper $helperId $phase $name $payload 'created'
    $fixture.Mounts[0].RW=$readOnly
    Assert-Rejected { Assert-Helper $helperId $phase $name $payload 'created' } 'HELPER_MOUNT_INVALID'
    $fixture.Mounts[0].RW=(-not $readOnly)
    $fixture.HostConfig.Mounts[0].VolumeOptions.NoCopy=$false
    Assert-Rejected { Assert-Helper $helperId $phase $name $payload 'created' } 'HELPER_NOCOPY_OR_RO_INVALID'
}
$roots=@();$inode=1
foreach ($row in $layout) { $roots+=[pscustomobject]@{path=$row.Destination;uid=$row.Uid;gid=$row.Gid;mode=$row.Mode;device=42;inode=$inode};$inode++ }
$receipt=[pscustomobject]@{result='E13B_VOLUME_ROOT_INSPECT_READONLY_PASS';roots=$roots}
$line=$receipt | ConvertTo-Json -Depth 5 -Compress
$verified=Read-RootReceipt @($line) 'E13B_VOLUME_ROOT_INSPECT_READONLY_PASS'
Need ($verified.roots.Count -eq 3) 'FIXTURE_RECEIPT_INVALID'
$receipt.roots[2].mode=456
$bad=$receipt | ConvertTo-Json -Depth 5 -Compress
Assert-Rejected { Read-RootReceipt @($bad) 'E13B_VOLUME_ROOT_INSPECT_READONLY_PASS' } 'HELPER_RECEIPT_STAT_INVALID'
Write-Output 'E13B_WINDOWS_VOLUME_CONTROLLER_FIXTURES_PASS'
