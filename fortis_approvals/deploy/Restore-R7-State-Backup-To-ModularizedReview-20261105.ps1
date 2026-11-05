param(
    [string]$BackupDir = 'C:\Users\alexa\AppData\Local\Fortis\Backups\R7-pre-cutover-20261105-175200-c879d04aa14b4126b4f5a56932ade799'
)

$ErrorActionPreference = 'Stop'
$TargetVolume = 'fortis-r7-state-review-20261105'
$HelperImage = 'fortis-approvals-gateway:modularized-review-3355941'
$TargetOrigin = 'http://localhost:19203'

if (-not (Test-Path -LiteralPath $BackupDir -PathType Container)) {
    throw 'R7_BACKUP_DIRECTORY_MISSING'
}
$ManifestPath = Join-Path $BackupDir 'manifest.json'
$HashPath = Join-Path $BackupDir 'manifest.sha256'
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $HashPath -PathType Leaf)) {
    throw 'R7_BACKUP_MANIFEST_MISSING'
}

$Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$HashLine = (Get-Content -LiteralPath $HashPath -Raw).Trim()
if ($HashLine -notmatch '^([0-9a-f]{64})(?:\s+.*)?$') {
    throw 'R7_BACKUP_MANIFEST_HASH_FILE_INVALID'
}
$ExpectedManifestHash = $Matches[1]
$ActualManifestHash = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ActualManifestHash -cne $ExpectedManifestHash) {
    throw 'R7_BACKUP_MANIFEST_HASH_MISMATCH'
}

$ExpectedFiles = @(
    '.fortis-r7-unified-v1',
    'approvals.sqlite',
    'owner.sqlite',
    'sonar-receipts.sqlite'
)
$ActualFiles = @($Manifest.sha256.PSObject.Properties.Name | Sort-Object)
if (Compare-Object ($ExpectedFiles | Sort-Object) $ActualFiles) {
    throw 'R7_BACKUP_FILE_SET_MISMATCH'
}
foreach ($Property in $Manifest.sha256.PSObject.Properties) {
    $File = Join-Path $BackupDir $Property.Name
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
        throw ('R7_BACKUP_FILE_MISSING:' + $Property.Name)
    }
    $Hash = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Hash -cne $Property.Value) {
        throw ('R7_BACKUP_FILE_HASH_MISMATCH:' + $Property.Name)
    }
}
if ($Manifest.ownerBindingPass -ne $true -or
    $Manifest.databases.'approvals.sqlite'.events -ne 18 -or
    $Manifest.databases.'approvals.sqlite'.requestStates.EXECUTED -ne 3 -or
    $Manifest.databases.'approvals.sqlite'.requestStates.REJECTED -ne 3 -or
    $Manifest.databases.'owner.sqlite'.credentialsActive -ne 1 -or
    $Manifest.databases.'sonar-receipts.sqlite'.receipts -ne 3) {
    throw 'R7_BACKUP_EXPECTED_STATE_MISMATCH'
}

$Volumes = @(& docker.exe volume ls --format '{{.Name}}')
if ($LASTEXITCODE -ne 0) { throw 'DOCKER_VOLUME_LIST_FAILED' }
if ($Volumes -ccontains $TargetVolume) {
    throw 'R7_REVIEW_VOLUME_ALREADY_EXISTS_NO_OVERWRITE'
}
$Images = @(& docker.exe image ls --format '{{.Repository}}:{{.Tag}}')
if ($LASTEXITCODE -ne 0) { throw 'DOCKER_IMAGE_LIST_FAILED' }
if ($Images -cnotcontains $HelperImage) {
    throw 'R7_RESTORE_HELPER_IMAGE_MISSING'
}

$VolumeResult = & docker.exe volume create $TargetVolume
if ($LASTEXITCODE -ne 0 -or $VolumeResult.Trim() -cne $TargetVolume) {
    throw 'R7_REVIEW_VOLUME_CREATE_FAILED'
}

$PythonSource = @'
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat

backup = Path("/backup")
volume = Path("/state")
private = volume / "private"
expected = {
    ".fortis-r7-unified-v1",
    "approvals.sqlite",
    "owner.sqlite",
    "sonar-receipts.sqlite",
}
target_origin = "http://localhost:19203"
source_origin = "http://localhost:19103"

manifest_bytes = (backup / "manifest.json").read_bytes()
hash_line = (backup / "manifest.sha256").read_text().strip().split()
if len(hash_line) < 1:
    raise SystemExit("R7_MANIFEST_HASH_LINE_INVALID")
if hashlib.sha256(manifest_bytes).hexdigest() != hash_line[0]:
    raise SystemExit("R7_MANIFEST_HASH_MISMATCH")
manifest = json.loads(manifest_bytes)
if set(manifest.get("sha256", {})) != expected:
    raise SystemExit("R7_BACKUP_FILE_SET_MISMATCH")
if manifest.get("ownerBindingPass") is not True:
    raise SystemExit("R7_OWNER_BINDING_NOT_VERIFIED")
if any(volume.iterdir()):
    raise SystemExit("R7_TARGET_VOLUME_NOT_EMPTY")

def read_db(path):
    db = sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True)
    try:
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise SystemExit("R7_BACKUP_DATABASE_INTEGRITY_FAILED:" + path.name)
        return db
    except BaseException:
        db.close()
        raise

for name, expected_hash in manifest["sha256"].items():
    source = backup / name
    if source.is_symlink() or not source.is_file():
        raise SystemExit("R7_BACKUP_FILE_INVALID:" + name)
    if hashlib.sha256(source.read_bytes()).hexdigest() != expected_hash:
        raise SystemExit("R7_BACKUP_FILE_HASH_MISMATCH:" + name)

marker = (backup / ".fortis-r7-unified-v1").read_bytes()
if marker != b"fortis-r7-unified-v1\n":
    raise SystemExit("R7_BACKUP_MARKER_INVALID")

approvals = read_db(backup / "approvals.sqlite")
try:
    states = dict(approvals.execute(
        "SELECT state, COUNT(*) FROM requests GROUP BY state"))
    events = approvals.execute("SELECT COUNT(*) FROM events").fetchone()[0]
finally:
    approvals.close()
if states != {"EXECUTED": 3, "REJECTED": 3} or events != 18:
    raise SystemExit("R7_BACKUP_APPROVAL_HISTORY_MISMATCH")

owner = read_db(backup / "owner.sqlite")
try:
    config = dict(owner.execute("SELECT setting,value FROM config"))
    credentials = owner.execute(
        "SELECT COUNT(*) FROM credentials WHERE active=1").fetchone()[0]
finally:
    owner.close()
if config != {"origin": source_origin, "rpId": "localhost", "owner": "owner"}:
    raise SystemExit("R7_BACKUP_OWNER_BINDING_MISMATCH")
if credentials != 1:
    raise SystemExit("R7_BACKUP_CREDENTIAL_COUNT_MISMATCH")

receipts = read_db(backup / "sonar-receipts.sqlite")
try:
    receipt_count = receipts.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
finally:
    receipts.close()
if receipt_count != 3:
    raise SystemExit("R7_BACKUP_SONAR_RECEIPTS_MISMATCH")

private.mkdir(mode=0o700)
os.chown(private, 10001, 10001)
os.chmod(private, 0o700)
for name in sorted(expected):
    destination = private / name
    shutil.copyfile(backup / name, destination)
    os.chown(destination, 10001, 10001)
    os.chmod(destination, 0o600)

owner_path = private / "owner.sqlite"
db = sqlite3.connect(owner_path)
try:
    db.execute("BEGIN IMMEDIATE")
    changed = db.execute(
        "UPDATE config SET value=? WHERE setting='origin' AND value=?",
        (target_origin, source_origin)).rowcount
    if changed != 1:
        raise SystemExit("R7_REVIEW_OWNER_ORIGIN_MIGRATION_FAILED")
    db.commit()
    if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        raise SystemExit("R7_REVIEW_OWNER_DATABASE_INTEGRITY_FAILED")
    config = dict(db.execute("SELECT setting,value FROM config"))
    credentials = db.execute(
        "SELECT COUNT(*) FROM credentials WHERE active=1").fetchone()[0]
finally:
    db.close()
if config != {"origin": target_origin, "rpId": "localhost", "owner": "owner"}:
    raise SystemExit("R7_REVIEW_OWNER_BINDING_INVALID")
if credentials != 1:
    raise SystemExit("R7_REVIEW_CREDENTIAL_COUNT_MISMATCH")

for name in expected:
    path = private / name
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 10001 or
            stat.S_IMODE(info.st_mode) != 0o600):
        raise SystemExit("R7_REVIEW_FILE_PERMISSIONS_INVALID:" + name)
if private.stat().st_uid != 10001 or stat.S_IMODE(private.stat().st_mode) != 0o700:
    raise SystemExit("R7_REVIEW_DIRECTORY_PERMISSIONS_INVALID")

print("R7_BACKUP_MANIFEST_AND_DATABASES_VERIFIED")
print("R7_REVIEW_STATE_RESTORED")
print("REQUESTS_EXECUTED=3")
print("REQUESTS_REJECTED=3")
print("EVENTS=18")
print("SONAR_RECEIPTS=3")
print("ACTIVE_WEBAUTHN_CREDENTIALS=1")
print("REVIEW_OWNER_ORIGIN=" + target_origin)
print("R7_REVIEW_VOLUME_RESTORE_PASS")
'@

$EncodedPython = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($PythonSource)
)
$PythonCommand = "import base64;exec(compile(base64.b64decode('$EncodedPython'),'<r7-review-restore>','exec'))"

$RunArguments = @(
    'run', '--rm', '--pull=never',
    '--network', 'none',
    '--read-only',
    '--user', '0:0',
    '--cap-drop', 'ALL',
    '--cap-add', 'CHOWN',
    '--cap-add', 'DAC_OVERRIDE',
    '--security-opt', 'no-new-privileges:true',
    '--pids-limit', '64',
    '--memory', '128m',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m',
    '--mount', "type=volume,source=$TargetVolume,target=/state",
    '--mount', "type=bind,source=$BackupDir,target=/backup,readonly",
    '--entrypoint', 'python',
    $HelperImage,
    '-c', $PythonCommand
)

$PreviousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $Output = @(& docker.exe @RunArguments 2>&1)
    $RestoreExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $PreviousPreference
}
$Output | ForEach-Object { Write-Host ([string]$_) }
if ($RestoreExitCode -ne 0) {
    throw 'R7_REVIEW_STATE_RESTORE_FAILED_VOLUME_LEFT_FOR_INSPECTION'
}

$VolumeInspect = @(& docker.exe volume inspect $TargetVolume)
if ($LASTEXITCODE -ne 0) { throw 'R7_REVIEW_VOLUME_INSPECT_FAILED' }
Write-Host 'FORTIS_R7_REVIEW_STATE_VOLUME_READY'
Write-Host "VOLUME=$TargetVolume"
Write-Host 'PRODUCTION_STATE_CHANGED=NO'
Write-Host 'PRODUCTION_CONTAINER_CHANGED=NO'
Write-Host 'CANDIDATE_STARTED=NO'
