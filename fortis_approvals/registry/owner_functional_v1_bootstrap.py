"""Owner-invoked E1.3b Registry schema-3 bootstrap core, not host admission.

This is designed to be invoked in a separately owner-reviewed, non-root,
networkless one-shot container with exact pre-provisioned private mounts.
Preview is read-only. Provision is a DISTINCT, owner-approved one-time effect;
Verify performs an inactive read-only replay, not a restore test. Nothing here
creates Docker volumes, changes ownership, starts Registry, seals Gateway,
or grants READ/WRITE. A failed partial provision is STOP, never auto-retry.
"""
import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

from ..core import Denied, canonical, loads_strict
from .functional_v1_journal import FunctionalV1CandidateJournal
from .state_journal import _scope, _uuid, _need

SPEC_PATH = Path('/run/fortis-registry-bootstrap/spec.json')
STATE_PATH = Path('/run/fortis-registry-state/registry.sqlite')
CONFIG_PATH = Path('/run/fortis-registry-runtime/profile.json')
SOCKET_PATH = Path('/run/fortis-registry-read/reader.sock')
_SPEC_FIELDS = frozenset({
    'schemaVersion', 'instanceId', 'scope', 'registryUid', 'registryGid',
    'readerUid', 'readerGid',
})
_MAX_SPEC = 4096


def _disabled(_):
    raise Denied('REGISTRY_BOOTSTRAP_WRITE_DISABLED')


def _runtime_confinement():
    """Refuse privileged execution even when an owner supplied valid paths."""
    try:
        fields = {}
        with open('/proc/self/status', encoding='ascii') as handle:
            for line in handle:
                key, sep, value = line.partition(':')
                if sep and key in {'CapInh', 'CapPrm', 'CapEff', 'CapBnd',
                                   'CapAmb', 'NoNewPrivs', 'Seccomp', 'TracerPid'}:
                    _need(key not in fields, 'REGISTRY_BOOTSTRAP_PROCESS_INVALID')
                    fields[key] = value.strip()
        _need(set(fields) == {'CapInh', 'CapPrm', 'CapEff', 'CapBnd',
                               'CapAmb', 'NoNewPrivs', 'Seccomp', 'TracerPid'}
              and all(int(fields[k], 16) == 0 for k in
                      ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))
              and fields['NoNewPrivs'] == '1'
              and fields['Seccomp'] == '2'
              and fields['TracerPid'] == '0',
              'REGISTRY_BOOTSTRAP_PROCESS_UNSAFE')
    except Denied:
        raise
    except (OSError, ValueError):
        raise Denied('REGISTRY_BOOTSTRAP_PROCESS_UNAVAILABLE') from None


def _private_directory(path, uid, gid, mode):
    _need(path.is_absolute() and path.parent.resolve() == path.parent
          and path.resolve() == path,
          'REGISTRY_BOOTSTRAP_DIRECTORY_ALIAS')
    try:
        row = path.lstat()
    except OSError:
        raise Denied('REGISTRY_BOOTSTRAP_DIRECTORY_MISSING') from None
    _need(stat.S_ISDIR(row.st_mode) and not stat.S_ISLNK(row.st_mode)
          and (row.st_uid, row.st_gid) == (uid, gid)
          and stat.S_IMODE(row.st_mode) == mode,
          'REGISTRY_BOOTSTRAP_DIRECTORY_INVALID')


def _file(path, *, limit, owner_uid, owner_gid, parent_mode):
    _private_directory(path.parent, owner_uid, owner_gid, parent_mode)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            row = os.fstat(fd)
            _need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1
                  and (row.st_uid, row.st_gid) == (owner_uid, owner_gid)
                  and stat.S_IMODE(row.st_mode) == 0o600,
                  'REGISTRY_BOOTSTRAP_FILE_INVALID')
            data = os.read(fd, limit + 1)
            _need(0 < len(data) <= limit and len(data) == row.st_size,
                  'REGISTRY_BOOTSTRAP_FILE_INVALID')
        finally:
            os.close(fd)
    except OSError:
        raise Denied('REGISTRY_BOOTSTRAP_FILE_MISSING') from None
    return data


def _load_spec(path):
    uid, gid = os.geteuid(), os.getegid()
    _need(uid > 1 and gid > 1, 'REGISTRY_BOOTSTRAP_ROOT_DENIED')
    raw = _file(path, limit=_MAX_SPEC, owner_uid=uid, owner_gid=gid,
                parent_mode=0o700)
    try:
        value = loads_strict(raw)
        _need(canonical(value).encode('utf-8') == raw
              and type(value) is dict and set(value) == _SPEC_FIELDS
              and type(value['schemaVersion']) is int
              and value['schemaVersion'] == 1
              and _uuid(value['instanceId']),
              'REGISTRY_BOOTSTRAP_SPEC_INVALID')
        scope = _scope(value['scope'])
        _need(type(value['registryUid']) is int
              and type(value['registryGid']) is int
              and type(value['readerUid']) is int
              and type(value['readerGid']) is int
              and all(1 < value[k] < 2**31 for k in
                      ('registryUid', 'registryGid', 'readerUid', 'readerGid'))
              and value['registryUid'] != value['readerUid']
              and value['registryGid'] != value['readerGid']
              and os.getresuid() == (value['registryUid'],) * 3
              and os.getresgid() == (value['registryGid'],) * 3
              and os.getgroups() in ([], [value['registryGid']]),
              'REGISTRY_BOOTSTRAP_IDENTITY_DENIED')
        return {**value, 'scope': scope}, hashlib.sha256(raw).hexdigest()
    except Denied:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise Denied('REGISTRY_BOOTSTRAP_SPEC_INVALID') from None


def _absent(path):
    _need(not path.exists() and not path.is_symlink(),
          'REGISTRY_BOOTSTRAP_EXISTING_STATE_STOP')


def _directories(spec):
    _private_directory(STATE_PATH.parent, spec['registryUid'],
                       spec['registryGid'], 0o700)
    _private_directory(CONFIG_PATH.parent, spec['registryUid'],
                       spec['registryGid'], 0o700)
    _private_directory(SOCKET_PATH.parent, spec['registryUid'],
                       spec['readerGid'], 0o2710)
    _need(STATE_PATH.parent != CONFIG_PATH.parent
          and STATE_PATH.parent != SOCKET_PATH.parent
          and CONFIG_PATH.parent != SOCKET_PATH.parent,
          'REGISTRY_BOOTSTRAP_PATH_COLLISION')


def _config(spec):
    return {
        'schemaVersion': 1,
        'instanceId': spec['instanceId'],
        'scope': spec['scope'],
        'registryStatePath': str(STATE_PATH),
        'socketPath': str(SOCKET_PATH),
        'readerUid': spec['readerUid'],
        'readerGid': spec['readerGid'],
    }


def run(action, *, spec_path=SPEC_PATH, expected_spec_sha256=None):
    """Source-only lifecycle; Provision must have its OWN owner GO."""
    _need(action in ('Preview', 'Provision', 'Verify'),
          'REGISTRY_BOOTSTRAP_ACTION_DENIED')
    _runtime_confinement()
    spec, digest = _load_spec(Path(spec_path))
    if expected_spec_sha256 is not None:
        _need(type(expected_spec_sha256) is str
              and len(expected_spec_sha256) == 64
              and all(c in '0123456789abcdef' for c in expected_spec_sha256)
              and expected_spec_sha256 == digest,
              'REGISTRY_BOOTSTRAP_SPEC_PIN_CHANGED')
    else:
        _need(action == 'Preview', 'REGISTRY_BOOTSTRAP_SPEC_PIN_REQUIRED')

    if action == 'Preview':
        # No mkdir, chmod, chown, SQLite connection or socket bind here.
        _absent(STATE_PATH)
        _absent(CONFIG_PATH)
        _absent(SOCKET_PATH)
        return {
            'result': 'SOURCE_ONLY_REGISTRY_BOOTSTRAP_PREVIEW',
            'specSha256': digest,
            'instanceId': spec['instanceId'],
            'registryUid': spec['registryUid'],
            'registryGid': spec['registryGid'],
            'readerUid': spec['readerUid'],
            'readerGid': spec['readerGid'],
            'statePath': str(STATE_PATH),
            'runtimeConfigPath': str(CONFIG_PATH),
            'socketPath': str(SOCKET_PATH),
            'requiresIndependentOwnerProvisionGO': True,
            'hostAccepted': False,
            'admissionAllowed': False,
        }

    _directories(spec)
    _absent(SOCKET_PATH)  # This tool never starts the listener.
    if action == 'Provision':
        _absent(STATE_PATH)
        _absent(CONFIG_PATH)
        _need(not any(CONFIG_PATH.parent.iterdir()),
              'REGISTRY_BOOTSTRAP_CONFIG_NOT_EMPTY')
        # Existing immutable base scope/instance are owner-selected inputs.
        # No automatic cleanup on partial success or unknown commit outcome.
        FunctionalV1CandidateJournal.initialize(
            STATE_PATH, instance_id=spec['instanceId'], scope=spec['scope'],
            plan_reader=_disabled)
        data = canonical(_config(spec)).encode('utf-8')
        fd = os.open(CONFIG_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, 'wb') as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            parent_fd = os.open(CONFIG_PATH.parent, os.O_RDONLY |
                                os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except Exception:
            # Keep potentially partial state for owner investigation.
            raise
        # Verify independently in a subsequent owner-reviewed invocation.
        result = 'SOURCE_ONLY_REGISTRY_BOOTSTRAP_PROVISIONED'
    else:
        _need(set(CONFIG_PATH.parent.iterdir()) == {CONFIG_PATH},
              'REGISTRY_BOOTSTRAP_CONFIG_NOT_EXACT')
        raw = _file(CONFIG_PATH, limit=2048,
                    owner_uid=spec['registryUid'], owner_gid=spec['registryGid'],
                    parent_mode=0o700)
        _need(raw == canonical(_config(spec)).encode('utf-8'),
              'REGISTRY_BOOTSTRAP_CONFIG_CHANGED')
        store = FunctionalV1CandidateJournal(
            STATE_PATH, instance_id=spec['instanceId'], scope=spec['scope'],
            plan_reader=_disabled)
        with store._read_only_db() as db:
            head, cursor, seen, active, previous_collector = store._state(db)
            _need(head['revision'] == 0 and not seen and not active
                  and previous_collector is None
                  and cursor == spec['scope']['baselineSha'],
                  'REGISTRY_BOOTSTRAP_GENESIS_MISMATCH')
        result = 'SOURCE_ONLY_REGISTRY_BOOTSTRAP_VERIFIED'
    return {'result': result, 'specSha256': digest,
            'instanceId': spec['instanceId'], 'hostAccepted': False,
            'admissionAllowed': False, 'registryServiceStarted': False}


def prepare_successor(expected_profile_sha256, *, transition_evidence_sha256=None, source_sha=None):
    """Migrate the dedicated inactive clone mounted by the owner wrapper."""
    from .local_candidate_read_service import (
        _check_successor_profile, _load_owner_config, _readonly_owner_runtime)
    from .release_event_journal import ReleaseEventJournal

    _runtime_confinement()
    uid, gid = os.geteuid(), os.getegid()
    _need(uid > 1 and gid > 1 and os.getresuid() == (uid,) * 3
          and os.getresgid() == (gid,) * 3 and os.getgroups() in ([], [gid]),
          'REGISTRY_BOOTSTRAP_IDENTITY_DENIED')
    config = _load_owner_config(str(CONFIG_PATH), allow_semantic=True)
    root = _readonly_owner_runtime(str(CONFIG_PATH))
    _check_successor_profile(config, expected_profile_sha256)
    _need(config['registryStatePath'] == str(STATE_PATH)
          and config['socketPath'] == str(SOCKET_PATH),
          'REGISTRY_BOOTSTRAP_SUCCESSOR_PATH_CHANGED')
    _private_directory(STATE_PATH.parent, uid, gid, 0o700)
    pins = config['semantic']
    _need(type(pins) is dict and 'legacyWitness' in pins and 'transitionDigest' in pins,
          'REGISTRY_BOOTSTRAP_SUCCESSOR_PINS_REQUIRED')
    stage = None
    pending = transition_evidence_sha256 is None
    if not pending:
        from .protected_transition import reviewed_transition, account_on_clone, staged_domain

        request = reviewed_transition(root, config, expected_evidence_sha256=transition_evidence_sha256,
                                      expected_source_sha=source_sha)

        def stage(journal, db):
            nonlocal accepted
            accepted = account_on_clone(staged_domain(journal,root,pins),db,request)

    accepted = None
    transitional = ReleaseEventJournal.migrate_clone(
        FunctionalV1CandidateJournal(STATE_PATH, instance_id=config['instanceId'],
                                     scope=config['scope'], plan_reader=_disabled),
        expected_legacy=pins['legacyWitness'], transition_digest=pins['transitionDigest'],
        stage=stage)
    checkpoint = transitional.release_checkpoint()
    _need(checkpoint['snapshotRevision'] == 0 and checkpoint['sourceTransitionPending'] is pending,
          'REGISTRY_BOOTSTRAP_SUCCESSOR_READBACK_CHANGED')
    receipt = {'result': 'SOURCE_ONLY_REGISTRY_SUCCESSOR_PREPARED',
               'profileSha256': expected_profile_sha256,
               'transitionDigest': transitional.transition_digest,
               'legacyPrefixDigest': checkpoint['legacy']['prefixDigest'],
               'sourceTransitionPending': pending, 'hostAccepted': False, 'admissionAllowed': False}
    if not pending:
        observed = staged_domain(transitional,root,pins).source_operation(request['operationId'])
        _need(observed is not None and observed == accepted,
              'REGISTRY_BOOTSTRAP_SUCCESSOR_READBACK_CHANGED')
        receipt['sourceTransitionReceipt'] = observed
        receipt['transitionEvidenceSha256'] = transition_evidence_sha256
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', required=True,
                        choices=('Preview', 'Provision', 'Verify'))
    parser.add_argument('--expected-spec-sha256')
    args = parser.parse_args(argv)
    import json
    output = run(args.action, expected_spec_sha256=args.expected_spec_sha256)
    print(json.dumps(output, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Denied, OSError, ValueError) as exc:
        print('REGISTRY_BOOTSTRAP_STOP: ' + str(exc), file=sys.stderr)
        sys.exit(1)
