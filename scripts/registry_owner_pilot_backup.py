"""One-shot schema-3 genesis snapshot / independent restore, owner-only.

Executed in the existing pinned Registry image by the manual pilot bootstrap.
No live writer, host bind, networking, production installation or new grant.
Only the fixed inactive state/config files may be read. All SQLite work uses
private tmpfs copies, since SQLite WAL mode may need to create SHM even on RO.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

sys.path.insert(0, '/opt/fortis')
from fortis_approvals.core import canonical, loads_strict
from fortis_approvals.registry import owner_functional_v1_bootstrap as boot
from fortis_approvals.registry.functional_v1_journal import FunctionalV1CandidateJournal
from fortis_approvals.registry.state_journal import _need, _uuid

MAX_DB = 2_000_000  # bootstrap genesis, not the general production backup tool
MAX_INPUT = 3_000_000
ROOT = Path('/run/fortis-pilot-scratch')
STATE = Path('/run/fortis-registry-state')
CONFIG = Path('/run/fortis-registry-runtime')
SOCKET = Path('/run/fortis-registry-read')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode(value, limit):
    _need(type(value) is str and len(value) <= (limit + 2) // 3 * 4,
          'PILOT_BACKUP_INPUT_BOUNDS')
    data = base64.b64decode(value, validate=True)
    _need(0 < len(data) <= limit, 'PILOT_BACKUP_INPUT_BOUNDS')
    return data


def encode(data):
    return base64.b64encode(data).decode('ascii')


def read_file(path, limit):
    return boot._file(path, limit=limit, owner_uid=20002, owner_gid=20002,
                      parent_mode=0o700)


def put(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def expect_mount(path, read_only):
    _need(bool(os.statvfs(path).f_flag & os.ST_RDONLY) == read_only,
          'PILOT_BACKUP_MOUNT_ACCESS')


def no_plan(_):
    raise RuntimeError('PILOT_BACKUP_GENESIS_ONLY')


def run(envelope, action, recovery_sha, spec_sha):
    boot._runtime_confinement()
    _need(bool(os.statvfs('/').f_flag & os.ST_RDONLY), 'PILOT_BACKUP_ROOT_NOT_RO')
    _need(action in ('Backup', 'Restore') and type(envelope) is dict
          and set(envelope) == ({'recovery', 'spec', 'backupId'} if action == 'Backup'
                               else {'recovery', 'spec', 'backupId', 'files'}),
          'PILOT_BACKUP_ENVELOPE')
    _need(_uuid(envelope['backupId']), 'PILOT_BACKUP_ID')
    source = decode(envelope['recovery'], 30_000)
    _need(digest(source) == recovery_sha, 'PILOT_BACKUP_RECOVERY_PIN')
    # Exact accepted source module, not arbitrary code or user-provided path.
    modname = 'fortis_approvals.registry.recovery_snapshot'
    module = types.ModuleType(modname)
    module.__package__ = modname.rpartition('.')[0]
    sys.modules[modname] = module
    exec(compile(source, modname, 'exec'), module.__dict__)
    boot._private_directory(ROOT, 20002, 20002, 0o700)
    expect_mount(ROOT, False)
    spec_bytes = decode(envelope['spec'], 4096)
    _need(digest(spec_bytes) == spec_sha, 'PILOT_BACKUP_SPEC_PIN')
    specpath = ROOT / 'spec.json'
    put(specpath, spec_bytes)
    spec, actual = boot._load_spec(specpath)
    _need(actual == spec_sha, 'PILOT_BACKUP_SPEC_PIN')
    expected_config = canonical(boot._config(spec)).encode('utf-8')
    backup_id = envelope['backupId']
    dest = ROOT / 'snapshot'
    dest.mkdir(mode=0o700)
    dbpath, mpath = module._paths(dest, backup_id)
    if action == 'Backup':
        for path in (STATE, CONFIG, SOCKET):
            expect_mount(path, True)
        boot._directories(spec)
        # Inactive genesis only: no WAL/SHM, extra files, or socket. Check again
        # after capture, never silently discard an outstanding WAL.
        def capture():
            _need(set(STATE.iterdir()) == {STATE / 'registry.sqlite'}
                  and set(CONFIG.iterdir()) == {CONFIG / 'profile.json'}
                  and not any(SOCKET.iterdir()), 'PILOT_BACKUP_NOT_INACTIVE_GENESIS')
            db = read_file(STATE / 'registry.sqlite', MAX_DB)
            config = read_file(CONFIG / 'profile.json', 2048)
            _need(config == expected_config, 'PILOT_BACKUP_CONFIG_CHANGED')
            return db, config
        raw, config = capture()
        staged = ROOT / 'source'
        staged.mkdir(mode=0o700)
        path = staged / 'registry.sqlite'
        put(path, raw)
        store = FunctionalV1CandidateJournal(path, instance_id=spec['instanceId'],
                    scope=spec['scope'], plan_reader=no_plan)
        checkpoint, cursor, counts = module._local_state(store)
        _need(checkpoint == store.initial and cursor == spec['scope']['baselineSha']
              and not any(counts.values()), 'PILOT_BACKUP_NOT_GENESIS')
        receipt = module.create_inactive_local_backup(store=store, directory=dest,
                                                       backup_id=backup_id)
        _need(capture() == (raw, config), 'PILOT_BACKUP_SOURCE_CHANGED')
        files = {'sqlite': encode(read_file(dbpath, MAX_DB)),
                 'manifest': encode(read_file(mpath, 12000)),
                 'config': encode(config)}
        return {'result': 'PILOT_GENESIS_BACKUP_CREATED', 'receipt': receipt,
                'files': files}
    # New independent container, no original volumes. Materialize the owner
    # retained bytes in fresh tmpfs and verify with the existing backup code.
    _need(all(not p.exists() for p in (STATE, CONFIG, SOCKET)),
          'PILOT_RESTORE_LIVE_PATH_PRESENT')
    files = envelope['files']
    _need(type(files) is dict and set(files) == {'sqlite', 'manifest', 'config'},
          'PILOT_RESTORE_FILES')
    put(dbpath, decode(files['sqlite'], MAX_DB))
    put(mpath, decode(files['manifest'], 12000))
    _need(decode(files['config'], 2048) == expected_config, 'PILOT_RESTORE_CONFIG_CHANGED')
    put(dest / 'profile.json', expected_config)
    receipt = module.verify_inactive_local_backup(directory=dest, backup_id=backup_id,
                instance_id=spec['instanceId'], scope=spec['scope'], plan_reader=no_plan)
    store = FunctionalV1CandidateJournal(dbpath, instance_id=spec['instanceId'],
                scope=spec['scope'], plan_reader=no_plan)
    _need(receipt['localCheckpoint'] == store.initial
          and receipt['candidateCursor'] == spec['scope']['baselineSha'],
          'PILOT_RESTORE_NOT_GENESIS')
    return {'result': 'PILOT_INDEPENDENT_INACTIVE_RESTORE_PASS', 'receipt': receipt,
            'configSha256': digest(expected_config)}


if __name__ == '__main__':
    try:
        data = sys.stdin.buffer.read(MAX_INPUT + 1)
        _need(0 < len(data) <= MAX_INPUT and len(sys.argv) == 4, 'PILOT_BACKUP_INPUT_BOUNDS')
        print(canonical(run(loads_strict(data), *sys.argv[1:])))
    except Exception as exc:
        # Never echo DB bytes, spec contents or arbitrary native error strings.
        print('PILOT_BACKUP_STOP_' + type(exc).__name__, file=sys.stderr)
        sys.exit(2)
