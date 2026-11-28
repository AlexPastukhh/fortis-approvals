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
from ..integrations.registry_contracts.maintenance_contract import (
    bootstrap_compatibility_digest, bootstrap_pair_authorization, bootstrap_phase_plan)
from .functional_v1_journal import FunctionalV1CandidateJournal
from .state_journal import _scope, _uuid, _need

SPEC_PATH = Path('/run/fortis-registry-bootstrap/spec.json')
STATE_PATH = Path('/run/fortis-registry-state/registry.sqlite')
CONFIG_PATH = Path('/run/fortis-registry-runtime/profile.json')
SOCKET_PATH = Path('/run/fortis-registry-read/reader.sock')
# The accepted #289 Registry profile/volume pair, not a configurable source.
_BOOTSTRAP_INCUMBENT_PROFILE='8f299ab091d1e16e32cc5c905922b3d4e7ee95ca7ac21e17a9654b7aa0757b86'
_BOOTSTRAP_INCUMBENT_CONFIG=Path('/run/fortis-registry-incumbent-runtime/profile.json')
_BOOTSTRAP_INCUMBENT_STATE=Path('/run/fortis-registry-incumbent-state/registry.sqlite')
_BOOTSTRAP_INSTALLED_STATE=STATE_PATH
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


def _successor_inputs(expected_profile_sha256):
    from .local_candidate_read_service import (
        _check_successor_profile, _load_owner_config, _readonly_owner_runtime)

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
    return config, root, pins


def prepare_successor(expected_profile_sha256, *, transition_evidence_sha256=None, source_sha=None):
    """Migrate the dedicated inactive clone mounted by the owner wrapper."""
    from .release_event_journal import ReleaseEventJournal

    config, root, pins = _successor_inputs(expected_profile_sha256)
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


def account_delivery_repair(expected_profile_sha256, *, repair_evidence_sha256, source_sha,
                            predecessor_revision=1):
    """Append one exact owner-reviewed delivery edge to the inactive Registry."""
    from . import source_event_journal as sources
    from .protected_transition import reviewed_delivery_repair, staged_domain
    from .release_event_journal import ReleaseEventJournal
    from ..integrations.registry_contracts import semantic_contract as sc

    config, root, pins = _successor_inputs(expected_profile_sha256)
    journal = ReleaseEventJournal(
        STATE_PATH, instance_id=config['instanceId'], scope=config['scope'],
        expected_legacy=pins['legacyWitness'], transition_digest=pins['transitionDigest'])
    domain = staged_domain(journal, root, pins)
    sc.need(type(predecessor_revision) is int and predecessor_revision in (1, 2),
            'SOURCE_DELIVERY_REPAIR_SCOPE')
    operations = domain.snapshot()['sourceOperations']
    transition = sources.delivery_repair_predecessor(operations)
    retained = sources.delivery_repair_predecessor(operations, predecessor_revision)
    request = sources.request(reviewed_delivery_repair(
        root, config, expected_evidence_sha256=repair_evidence_sha256,
        expected_source_sha=source_sha, retained_transition=transition,
        retained_predecessor=retained), journal)
    with journal._db() as db:
        view = domain._project(db)
        prior = sources.delivery_repair_predecessor(view['sourceOperations'], predecessor_revision)
        exact_retry = request['operationId'] in view['sourceOperations']
        sc.need(prior == retained
                and sources.delivery_repair_predecessor(view['sourceOperations']) == transition
                and not view['operations']
                and view['sourceRevision'] == predecessor_revision + int(exact_retry),
                'SOURCE_DELIVERY_REPAIR_STAGED_STATE_CHANGED')
        receipt = sources.append(journal, db, request, view['operations'])
        domain._project(db)
    if predecessor_revision == 2:
        # The candidate is offline and exclusively mounted. Read back the
        # committed receipt through one final normal connection so SQLite
        # itself checkpoints/closes its WAL before the immutable preview.
        # Never unlink SQLite sidecars or ignore a pending WAL.
        with journal._db() as db:
            row = domain._project(db)['sourceOperations'].get(request['operationId'])
            sc.need(row is not None and row[1] == receipt,'SOURCE_DELIVERY_REPAIR_READBACK_CHANGED')
        sc.need(not any(p.exists() or p.is_symlink() for p in
                    (Path(str(STATE_PATH)+suffix) for suffix in ('-wal','-shm','-journal'))),
                'REGISTRY_CORRECTIVE_PREVIEW_UNCHECKPOINTED')
    else:
        sc.need(domain.source_operation(request['operationId']) == receipt,
                'SOURCE_DELIVERY_REPAIR_READBACK_CHANGED')
    return {'result': 'SOURCE_ONLY_REGISTRY_DELIVERY_REPAIR_ACCOUNTED',
            'profileSha256': expected_profile_sha256, 'repairEvidenceSha256': repair_evidence_sha256,
            'transitionDigest': journal.transition_digest,
            'legacyPrefixDigest': journal.expected_legacy['prefixDigest'],
            'predecessorReceipt': retained[1], 'sourceRepairReceipt': receipt,
            'hostAccepted': False, 'admissionAllowed': False}


def _bootstrap_clone(config,root,pins,review):
    """Prepare or verify the exact inactive clone against the retained source.

    A read-only scratch replay before/after copy is staging evidence only.
    The host must separately prove stopped-source equality before handover.
    """
    from .local_candidate_read_service import _load_owner_config,_check_successor_profile
    from .protected_transition import (
        bootstrap_prefix,stage_bootstrap_registry,staged_domain,_corrective_snapshot_copy,
        _check_owner_readonly_mount)
    from .release_event_journal import ReleaseEventJournal
    from ..integrations.registry_contracts import semantic_contract as sc

    source_root=_BOOTSTRAP_INCUMBENT_CONFIG.parent
    _check_owner_readonly_mount(source_root)
    _check_owner_readonly_mount(_BOOTSTRAP_INCUMBENT_STATE.parent)
    for old,new in ((source_root,root),(_BOOTSTRAP_INCUMBENT_STATE.parent,STATE_PATH.parent)):
        a,b=old.stat(),new.stat()
        sc.need((a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino),'SOURCE_BOOTSTRAP_CLONE_ALIAS')
    incumbent=_load_owner_config(str(_BOOTSTRAP_INCUMBENT_CONFIG),allow_semantic=True)
    _check_successor_profile(incumbent,_BOOTSTRAP_INCUMBENT_PROFILE)
    sc.need(incumbent['registryStatePath']==str(_BOOTSTRAP_INSTALLED_STATE)
            and all(incumbent[k]==config[k] for k in
                    ('schemaVersion','instanceId','scope','socketPath','readerUid','readerGid')),
            'SOURCE_BOOTSTRAP_INCUMBENT_CHANGED')
    old_pins=incumbent['semantic']
    sc.need(all(old_pins[k]==pins[k] for k in
                ('legacyWitness','transitionDigest','legacyProfileDigest','successorProfileDigest',
                 'internalActor','readGrants'))
            and all(incumbent['sourceWrite'][k]==config['sourceWrite'][k] for k in
                ('ownerActor','ownerName','target','policyAuthorityDigest','validatorRevision',
                 'impactBinding','buildPins')),
            'SOURCE_BOOTSTRAP_RUNTIME_PINS_CHANGED')
    journal=ReleaseEventJournal(_BOOTSTRAP_INCUMBENT_STATE,instance_id=incumbent['instanceId'],
        scope=incumbent['scope'],expected_legacy=old_pins['legacyWitness'],
        transition_digest=old_pins['transitionDigest'])
    if not list(STATE_PATH.parent.iterdir()):
        stage_bootstrap_registry(journal,source_root,old_pins,target=STATE_PATH,
                                 expected_prefix=review['prefix'])
    else:
        # A previous invocation may already have copied/accounted the clone.
        # Never overwrite it; prove the incumbent still matches the review.
        with _corrective_snapshot_copy(journal) as copy:
            view=staged_domain(copy,source_root,old_pins).snapshot()
            sc.need(view['sourceRevision']==3 and bootstrap_prefix(view,copy)==review['prefix'],
                    'SOURCE_BOOTSTRAP_REVIEW_CHANGED')


def account_bootstrap_migration(expected_profile_sha256, *, review_sha256, evidence_sha256,
                                source_sha, owner_review_raw):
    """One #289 delivery migration on an independently prepared inactive clone.

    Host admission, fresh clone identity, independent review/evidence pins and
    writer exclusion remain obligations of the owner controller. Not a live
    semantic operation or a replacement for protected Check/Apply.
    """
    from . import source_event_journal as sources
    from .protected_transition import (bootstrap_prefix, reviewed_bootstrap_migration,
                                       read_bootstrap_review, verify_bootstrap_owner_review, _pinned_bootstrap_material, staged_domain)
    from .release_event_journal import ReleaseEventJournal
    from ..integrations.registry_contracts import semantic_contract as sc
    from ..r7_registry_reader_mount import _exact_mountinfo

    config, root, pins = _successor_inputs(expected_profile_sha256)
    sc.need(_exact_mountinfo(Path('/proc/self/mountinfo').read_bytes(),STATE_PATH.parent,b'rw')
            and not os.statvfs(STATE_PATH.parent).f_flag & os.ST_RDONLY,
            'SOURCE_BOOTSTRAP_CLONE_MOUNT_REQUIRED')
    review=read_bootstrap_review(root,review_sha256)
    evidence=_pinned_bootstrap_material(root,'bootstrap-evidence.json',evidence_sha256)
    sc.need(evidence.get('reviewDigest')==review_sha256,'SOURCE_BOOTSTRAP_REVIEW_CHANGED')
    verify_bootstrap_owner_review(review,owner_review_raw,merged_at=evidence.get('mergedAt'))
    _bootstrap_clone(config,root,pins,review)
    journal=ReleaseEventJournal(STATE_PATH,instance_id=config['instanceId'],scope=config['scope'],
        expected_legacy=pins['legacyWitness'],transition_digest=pins['transitionDigest'])
    domain=staged_domain(journal,root,pins)
    before=domain.snapshot()
    prefix=bootstrap_prefix(before,journal)
    req=reviewed_bootstrap_migration(root,config,expected_review_sha256=review_sha256,
        expected_evidence_sha256=evidence_sha256,expected_source_sha=source_sha,
        view=before,store=journal)
    with journal._db() as db:
        view=domain._project(db)
        retry=req['operationId'] in view['sourceOperations']
        sc.need(bootstrap_prefix(view,journal)==prefix and view['sourceRevision']==3+int(retry),
                'SOURCE_BOOTSTRAP_STATE_CHANGED')
        receipt=sources.append(journal,db,req,view['operations'])
        domain._project(db)
    # Full replay on a final normal connection also checkpoints any WAL before
    # the owner takes the staged readback. Never discard an existing WAL.
    with journal._db() as db:
        view=domain._project(db)
        row=view['sourceOperations'].get(req['operationId'])
        sc.need(bootstrap_prefix(view,journal)==prefix and view['sourceRevision']==4
                and view['sourceCursor']==source_sha and row is not None and row[1]==receipt,
                'SOURCE_BOOTSTRAP_READBACK_CHANGED')
        checkpoint={'sourceRevision':view['sourceRevision'],'sourceCursor':view['sourceCursor'],
                    'snapshotRevision':view['snapshotRevision'],'eventDigest':view['eventDigest']}
    sc.need(not any(p.exists() or p.is_symlink() for p in
                (Path(str(STATE_PATH)+suffix) for suffix in ('-wal','-shm','-journal'))),
            'SOURCE_BOOTSTRAP_CLONE_UNCHECKPOINTED')
    return {'result':'SOURCE_ONLY_REGISTRY_BOOTSTRAP_MIGRATION_ACCOUNTED',
            'profileSha256':expected_profile_sha256,'reviewSha256':review_sha256,
            'evidenceSha256':evidence_sha256,'prefix':prefix,'sourceMigrationReceipt':receipt,
            'checkpoint':checkpoint,'hostAccepted':False,'admissionAllowed':False}


def _bootstrap_pair_inputs(expected_profile_sha256, *, review_sha256, evidence_sha256, source_sha, writable, recovery=False):
    from . import source_event_journal as sources
    from .protected_transition import (read_bootstrap_review,staged_domain,
                                       bootstrap_source_prefix,_pinned_bootstrap_material,_corrective_snapshot_copy)
    from .release_event_journal import ReleaseEventJournal
    from ..integrations.registry_contracts import semantic_contract as sc
    from ..integrations.registry.read_contract import private_planner_key
    from ..r7_registry_reader_mount import _exact_mountinfo

    config,root,pins=_successor_inputs(expected_profile_sha256)
    mode=b'rw' if writable else b'ro'
    sc.need(_exact_mountinfo(Path('/proc/self/mountinfo').read_bytes(),STATE_PATH.parent,mode)
            and bool(os.statvfs(STATE_PATH.parent).f_flag & os.ST_RDONLY)==(not writable),
            'SOURCE_BOOTSTRAP_PAIR_MOUNT_REQUIRED')
    # No socket, no writer credentials and no generic protected operation.
    review=read_bootstrap_review(root,review_sha256)
    evidence=_pinned_bootstrap_material(root,'bootstrap-evidence.json',evidence_sha256)
    sc.hex_id(source_sha,40)
    journal=ReleaseEventJournal(STATE_PATH,instance_id=config['instanceId'],scope=config['scope'],
        expected_legacy=pins['legacyWitness'],transition_digest=pins['transitionDigest'],
        immutable_snapshot=not writable)
    # A killed writer can leave committed WAL frames. Never delete or ignore
    # them. The existing stable RO main/WAL copy is needed only for recovery
    # with sidecars; an ordinary checkpointed clone uses the immutable read.
    sc.need(not recovery or not writable,'SOURCE_BOOTSTRAP_PAIR_MOUNT_REQUIRED')
    sidecars=any(p.exists() or p.is_symlink() for p in
                 (Path(str(STATE_PATH)+suffix) for suffix in ('-wal','-shm','-journal')))
    if recovery and sidecars:
        with _corrective_snapshot_copy(journal) as copy:
            domain=staged_domain(copy,root,pins)
            view=domain.snapshot()
    else:
        domain=staged_domain(journal,root,pins)
        view=domain.snapshot()
    prior=sources.bootstrap_predecessor(view['sourceOperations'])
    ident=sources.bootstrap_migration_id(prior[1]['operationId'],source_sha)
    row=view['sourceOperations'].get(ident)
    sc.need(view['sourceRevision']==4 and view['sourceCursor']==source_sha and row is not None
            and row[0]['kind']==sources.BOOTSTRAP_MIGRATION
            and row[0]['proposal']==review['proposal'] and row[0]['evidenceDigest']==evidence_sha256
            and evidence['reviewDigest']==review_sha256 and evidence['observation']==row[0]['observation']
            and row[0]['transition']['reviewDigest']==review_sha256
            and review['authorityDigest']==config['sourceWrite']['policyAuthorityDigest']
            and view['profileDigest']==pins['successorProfileDigest'],
            'SOURCE_BOOTSTRAP_PAIR_SOURCE_CHANGED')
    # Verify the retained prefix even on exact begin readback. The source
    # accounting path itself remains restricted to pre-product journals.
    sc.need(bootstrap_source_prefix(view,journal)==review['prefix'],'SOURCE_BOOTSTRAP_PAIR_SOURCE_CHANGED')
    private_planner_key(root/'semantic-peer.key',pins['peerKeyDigest'])
    private_planner_key(root/'semantic-frame.key',pins['frameKeyDigest'])
    binding={'instanceId':config['instanceId'],'scopeDigest':sc.digest(config['scope']),
        'profileDigest':pins['successorProfileDigest'],'generation':pins['generation'],
        'internalActor':pins['internalActor'],'peerKeyDigest':pins['peerKeyDigest'],
        'frameKeyDigest':pins['frameKeyDigest'],'socketPath':config['socketPath'],
        'readerUid':config['readerUid'],'readerGid':config['readerGid'],
        'authorityDigest':config['sourceWrite']['policyAuthorityDigest'],
        'interlockDigest':config['sourceWrite']['interlockDigest']}
    sc.need('latestPin' not in config['sourceWrite'] and binding['peerKeyDigest']!=binding['frameKeyDigest'],
            'SOURCE_BOOTSTRAP_PAIR_PROFILE_CHANGED')
    return domain,view,review,row[1],binding


def _bootstrap_review_witness(review):
    from ..integrations.registry_contracts import semantic_contract as sc
    # The independent pre-merge proof can bind the complete review
    # without a circular dependency on the proof file's own digest.
    return {**{k:review[k] for k in ('authorityWitnessDigest','primaryRecordDigest','gatewayBackupDigest',
                    'registryBackupDigest','ownerReviewProofDigest')},
            'reviewContentDigest':sc.digest({k:v for k,v in review.items() if k!='ownerReviewProofDigest'})}


def _bootstrap_candidate(domain,view,review,receipt,binding,profile):
    from .protected_transition import bootstrap_prefix
    from .release_domain import key
    from ..integrations.registry_contracts import semantic_contract as sc
    from ..integrations.registry_contracts.maintenance_contract import paired_subjects

    sc.need(bootstrap_prefix(view,domain.store)==review['prefix'] and view['sourceRevision']==4,
            'SOURCE_BOOTSTRAP_PAIR_SOURCE_CHANGED')
    items={}
    for role,subject in paired_subjects(domain.store.scope['repository']).items():
        state=view['states'].get(key(subject))
        sc.need(state is not None and state['desired'] is not None
                and state['desired']['evidenceVerified'] is True
                and state['desired']['sourceRevision']==4
                and state['desired']['sourceEventDigest']==receipt['eventDigest']
                and state['desired']['source']['sourceSha']==view['sourceCursor'],
                'SOURCE_BOOTSTRAP_PAIR_DESIRED_CHANGED')
        desired=state['desired']
        items[role]={'subject':subject,'source':desired['source'],
            'expected':{'targetRevision':state['targetRevision'],'desiredRecordId':desired['recordId'],
                        'catalogSha256':view['catalogSha256']}}
    return {'result':'BOOTSTRAP_REGISTRY_MATERIAL_ONLY','profileDigest':profile,'binding':binding,
            'checkpoint':{k:view[k] for k in ('sourceRevision','sourceCursor','snapshotRevision','eventDigest','profileDigest')},
            'items':items,'sourceMigrationReceipt':receipt,
            'review':_bootstrap_review_witness(review)}


def verify_bootstrap_backup(expected_digest, *, root=Path('/run/fortis-registry-backup')):
    from .local_candidate_read_service import _owner_runtime_bytes
    from .protected_transition import _pinned_bootstrap_material
    from ..r7_registry_reader_mount import _check_owner_readonly_mount
    from ..integrations.registry_contracts import semantic_contract as sc
    from ..workflow.common import MAX_BUNDLE
    import re
    _check_owner_readonly_mount(root)
    manifest=_pinned_bootstrap_material(root,'manifest.json',expected_digest)
    sc.fields(manifest,('schema','checkpoint','databaseSha256','databaseBytes','configHashes'))
    sc.need(manifest['schema']=='fortis-registry-v4-local-backup-v1'
            and manifest['checkpoint']['sourceRevision']==3
            and manifest['checkpoint']['sourceCursor']=='073d6f8701595e499eac5a1fa0cbe90accb05819'
            and {p.name for p in root.iterdir()}=={'state','config','manifest.json'}
            and {p.name for p in (root/'state').iterdir()}=={'registry.sqlite'},
            'SOURCE_BOOTSTRAP_BACKUP_CHANGED')
    raw=_owner_runtime_bytes(root/'state'/'registry.sqlite',64*1024*1024)
    sc.need(len(raw)==manifest['databaseBytes'] and hashlib.sha256(raw).hexdigest()==manifest['databaseSha256'],
            'SOURCE_BOOTSTRAP_BACKUP_CHANGED')
    hashes=manifest['configHashes']
    sc.need(type(hashes) is dict and 0<len(hashes)<=32
            and set(hashes)=={p.name for p in (root/'config').iterdir()}
            and all(re.fullmatch(r'[a-z0-9._-]{1,128}',name) for name in hashes),
            'SOURCE_BOOTSTRAP_BACKUP_CHANGED')
    for name,pin in hashes.items():
        sc.need(hashlib.sha256(_owner_runtime_bytes(root/'config'/name,MAX_BUNDLE)).hexdigest()==pin,
                'SOURCE_BOOTSTRAP_BACKUP_CHANGED')
    sc.need(_pinned_bootstrap_material(root,'manifest.json',expected_digest)==manifest,
            'SOURCE_BOOTSTRAP_BACKUP_CHANGED')
    return expected_digest


def inspect_bootstrap_pair(expected_profile_sha256, *, review_sha256, evidence_sha256, source_sha):
    """Pre-effect Check: independently replay the inactive accounted clone."""
    data=_bootstrap_pair_inputs(expected_profile_sha256,review_sha256=review_sha256,
        evidence_sha256=evidence_sha256,source_sha=source_sha,writable=False)
    return _bootstrap_candidate(*data,expected_profile_sha256)


def inspect_ordinary_pair(expected_profile_sha256, *, incumbent_profile_sha256, source_sha, normal):
    """Check retained target package against a stable RO copy of live state.

    The new package must replay all existing source and release events.
    No snapshot is installed and no accounting/hold is created by this read.
    The live writer independently CAS-checks this exact replay at begin.
    """
    from .local_candidate_read_service import _load_owner_config, _check_successor_profile
    from .protected_transition import staged_domain, _corrective_snapshot_copy
    from .release_event_journal import ReleaseEventJournal
    from .release_domain import key
    from ..r7_registry_reader_mount import _check_owner_readonly_mount
    from ..integrations.registry.read_contract import private_planner_key
    from ..extensions.maintenance_interlock_reader import read_latest_interlock, InterlockReservations
    from ..integrations.registry_contracts import semantic_contract as sc
    from ..integrations.registry_contracts.maintenance_contract import paired_subjects, validate_record
    config,root,pins=_successor_inputs(expected_profile_sha256)
    old_root=_BOOTSTRAP_INCUMBENT_CONFIG.parent
    _check_owner_readonly_mount(old_root)
    _check_owner_readonly_mount(STATE_PATH.parent)
    old=_load_owner_config(str(_BOOTSTRAP_INCUMBENT_CONFIG),allow_semantic=True)
    _check_successor_profile(old,incumbent_profile_sha256)
    old_pins=old['semantic']
    sc.need(old['sourceWrite'].get('latestPin') is True and config=={**old,'semantic':{
        **old_pins,'peerKeyDigest':pins['peerKeyDigest'],'frameKeyDigest':pins['frameKeyDigest']}}
        and len({pins['peerKeyDigest'],pins['frameKeyDigest'],old_pins['peerKeyDigest'],old_pins['frameKeyDigest']})==4,
        'SOURCE_ORDINARY_PAIR_PROFILE_CHANGED')
    for path,semantic in ((root,pins),(old_root,old_pins)):
        private_planner_key(path/'semantic-peer.key',semantic['peerKeyDigest'])
        private_planner_key(path/'semantic-frame.key',semantic['frameKeyDigest'])
    normal=validate_record(normal);sc.hex_id(source_sha,40)
    scope=dict(instance_id=config['instanceId'],scope_digest=sc.digest(config['scope']),generation=pins['generation'])
    def phase():
        actual,projection=read_latest_interlock(**scope)
        sc.need(actual==normal and actual['phase']=='NORMAL' and projection['registryDigest'] is None,
                'SOURCE_ORDINARY_PAIR_PHASE_CHANGED')
    journal=ReleaseEventJournal(STATE_PATH,instance_id=config['instanceId'],scope=config['scope'],
        expected_legacy=pins['legacyWitness'],transition_digest=pins['transitionDigest'])
    with InterlockReservations().exclusive() as exclusive:
        sc.need(exclusive,'SOURCE_ORDINARY_PAIR_BUSY')
        phase()
        with _corrective_snapshot_copy(journal) as copy:
            domain=staged_domain(copy,root,pins);view=domain.snapshot()
            holds=domain._maintenance_snapshot(view)
            sc.need(not view['sourceTransitionPending'] and not holds['holds'],
                    'SOURCE_ORDINARY_PAIR_HOLD_REMAINS')
            items={}
            for role,subject in paired_subjects(config['scope']['repository']).items():
                state=view['states'].get(key(subject));desired=state['desired'] if state else None
                sc.need(desired is not None and desired['evidenceVerified'] is True
                        and desired['source']['sourceSha']==source_sha,
                        'SOURCE_ORDINARY_PAIR_DESIRED_CHANGED')
                items[role]={'subject':subject,'source':desired['source'],
                    'expected':{'targetRevision':state['targetRevision'],'desiredRecordId':desired['recordId'],
                                'catalogSha256':view['catalogSha256']}}
            checkpoint={k:view[k] for k in ('sourceRevision','sourceCursor','snapshotRevision','eventDigest','profileDigest')}
        phase()
    binding={'instanceId':config['instanceId'],'scopeDigest':scope['scope_digest'],
        'profileDigest':pins['successorProfileDigest'],'generation':pins['generation'],
        'internalActor':pins['internalActor'],'peerKeyDigest':pins['peerKeyDigest'],
        'frameKeyDigest':pins['frameKeyDigest'],'socketPath':config['socketPath'],
        'readerUid':config['readerUid'],'readerGid':config['readerGid'],
        'authorityDigest':config['sourceWrite']['policyAuthorityDigest'],
        'interlockDigest':config['sourceWrite']['interlockDigest']}
    return {'result':'ORDINARY_REGISTRY_MATERIAL_ONLY','profileDigest':expected_profile_sha256,
            'incumbentProfileDigest':incumbent_profile_sha256,'binding':binding,
            'checkpoint':checkpoint,'items':items,'holdSnapshot':holds}


def _bootstrap_pair_intent(expected_profile_sha256, *, review_sha256, evidence_sha256,
                           source_sha, checked, authorization, writable, recovery=False):
    from ..integrations.registry_contracts import semantic_contract as sc
    from ..integrations.registry_contracts.maintenance_contract import paired_begin,paired_operation_id

    sc.fields(checked,('gateway','registry','artifacts'))
    sc.fields(authorization,('schemaVersion','attemptId','checkDigest','compatibilityDigest',
        'sourceRecordDigest','frozenSourceReceiptDigest','seedDigest','recordedAt','ownerGoDigest','targetGeneration'))
    sc.need(type(authorization['schemaVersion']) is int and authorization['schemaVersion']==1)
    sc.uuid_id(authorization['attemptId']);sc.revision(authorization['recordedAt'])
    for k in ('checkDigest','compatibilityDigest','sourceRecordDigest','frozenSourceReceiptDigest','seedDigest','ownerGoDigest','targetGeneration'):
        sc.hex_id(authorization[k],64)
    sc.need(authorization['compatibilityDigest']==bootstrap_compatibility_digest(checked),
            'SOURCE_BOOTSTRAP_PAIR_CHECK_CHANGED')
    registry=checked['registry']
    domain,view,review,receipt,binding=_bootstrap_pair_inputs(expected_profile_sha256,
        review_sha256=review_sha256,evidence_sha256=evidence_sha256,source_sha=source_sha,writable=writable,recovery=recovery)
    sc.need(binding==registry['binding'] and registry['profileDigest']==expected_profile_sha256
            and receipt==registry['sourceMigrationReceipt']
            and registry['review']==_bootstrap_review_witness(review),
            'SOURCE_BOOTSTRAP_PAIR_CHECK_CHANGED')
    pair=paired_begin({'schemaVersion':1,'attemptId':authorization['attemptId'],
        'checkpoint':registry['checkpoint'],'items':registry['items'],'artifacts':checked['artifacts'],
        'controllerReceiptDigest':sc.digest(authorization),
        'compatibilityReadbackDigest':authorization['compatibilityDigest']},domain.store.scope['repository'])
    # The controller identity is fixed, not a semantic actor selected by a
    # request. Readback only accepts the exact original begin at the tip.
    actor='owner-release-controller'
    ids=[paired_operation_id(pair['attemptId'],role) for role in ('registry','gateway')]
    return domain,view,registry,review,receipt,binding,pair,actor,ids


def _bootstrap_pair_result(domain,view,pair,actor,ids,authorization,seed):
    from ..integrations.registry_contracts import semantic_contract as sc
    from ..integrations.registry_contracts.maintenance_contract import validate_record

    seed=validate_record(seed)
    sc.need(sc.digest(seed)==authorization['seedDigest']
            and seed['generation']!=authorization['targetGeneration'],
            'SOURCE_BOOTSTRAP_PAIR_SEED_CHANGED')
    sc.need(list(view['operations'])==ids and all(
        view['operations'][i][0]['pair']==pair
        and view['operations'][i][0]['actor']==actor
        and view['operations'][i][0]['kind']=='PROTECTED_PAIRED_BEGIN'
        for i in ids),'SOURCE_BOOTSTRAP_PAIR_CHECK_CHANGED')
    receipts=[view['operations'][i][1] for i in ids]
    holds=domain._maintenance_snapshot(view)
    sc.need(len(holds['holds'])==2 and all(h['pairDigest']==sc.digest(pair) for h in holds['holds']),
            'SOURCE_BOOTSTRAP_PAIR_CHECK_CHANGED')
    phases=bootstrap_phase_plan(seed,authorization,pair,receipts,holds)
    return {'result':'BOOTSTRAP_PAIR_BEGIN_ACCOUNTED_ONLY','pair':pair,'receipts':receipts,
            'holdSnapshot':holds,'registryDigest':sc.digest(holds),'phasePlan':phases,
            'hostAccepted':False,'admissionAllowed':False}


def read_bootstrap_pair(expected_profile_sha256, *, review_sha256, evidence_sha256,
                        source_sha, checked, authorization, seed):
    """Exact offline readback before receiver provisioning, including lost ACK.

    Original seed is independently retained by the controller; current phase
    publication is a separate proof. No writable mounts or journal effect.
    """
    domain,view,_,_,_,_,pair,actor,ids=_bootstrap_pair_intent(
        expected_profile_sha256,review_sha256=review_sha256,evidence_sha256=evidence_sha256,
        source_sha=source_sha,checked=checked,authorization=authorization,writable=False,recovery=True)
    return _bootstrap_pair_result(domain,view,pair,actor,ids,authorization,seed)



def seal_bootstrap_registry_material(expected_profile_sha256, *, review_sha256, evidence_sha256,
                                     source_sha, checked, authorization, seed, begin, publication,
                                     verify_only, expected_target, target=Path('/target'),ordinary=None):
    """Final Registry configuration only; the journal remains RO.

    This is the same exact begin replay and phase proof, not another writer
    or a listener startup. Original prepared files remain intact for retry.
    """
    from .protected_transition import _retained_source_evidence, _pinned_bootstrap_material
    from .local_candidate_read_service import _load_owner_config, _check_successor_profile
    from ..r7_registry_reader_mount import _seal_bootstrap_material
    from ..integrations.registry_contracts import semantic_contract as sc
    from ..integrations.registry_contracts.maintenance_contract import bootstrap_final_handoff, staged_registry_profile
    from ..extensions.maintenance_interlock_reader import read_latest_interlock
    from ..workflow.common import MAX_BUNDLE
    config,root,pins=_successor_inputs(expected_profile_sha256)
    if ordinary is None:
        domain,view,_,_,_,binding,pair,actor,ids=_bootstrap_pair_intent(
            expected_profile_sha256,review_sha256=review_sha256,evidence_sha256=evidence_sha256,
            source_sha=source_sha,checked=checked,authorization=authorization,writable=False,recovery=True)
        actual=_bootstrap_pair_result(domain,view,pair,actor,ids,authorization,seed)
        sc.need(actual==begin,'SOURCE_BOOTSTRAP_FINAL_PROOF_CHANGED')
        final=bootstrap_final_handoff(checked,authorization,seed,actual,publication)
    else:
        from .protected_transition import staged_domain, _corrective_snapshot_copy
        from .release_event_journal import ReleaseEventJournal
        from ..integrations.registry_contracts.maintenance_seal import ordinary_handover
        from ..extensions.maintenance_interlock_reader import read_controller_begin
        sc.fields(ordinary,('intent','check','sourceReceipt','stop'))
        intent=ordinary['intent']
        sc.need(checked==intent['compatibility'] and authorization==intent['authorization']
                and seed==intent['normal'] and expected_profile_sha256==checked['registry']['profileDigest']
                and expected_target==checked['roots']['registry'],
                'SOURCE_ORDINARY_FINAL_PROOF_CHANGED')
        final=ordinary_handover(intent,begin,ordinary['check'],ordinary['sourceReceipt'],ordinary['stop'],publication)
        binding=checked['registry']['binding']
        journal=ReleaseEventJournal(STATE_PATH,instance_id=config['instanceId'],scope=config['scope'],
            expected_legacy=pins['legacyWitness'],transition_digest=pins['transitionDigest'])
        with _corrective_snapshot_copy(journal) as copy:
            domain=staged_domain(copy,root,pins)
            view=domain.snapshot()
            actual=domain.protected_pair_begin_readback(begin['pair'],actor='owner-release-controller')
            sc.need(all(actual[k]==begin[k] for k in ('receipts','checkpoint','holdSnapshot')),
                    'SOURCE_ORDINARY_FINAL_PROOF_CHANGED')
        # Historical evidence is retained exactly, not re-issued for the
        # new ordinary source. Its hashes come from the original journal.
        from . import source_event_journal as sources
        history=sorted(view['sourceOperations'].values(),key=lambda row:row[1]['sourceRevision'])
        sc.need(len(history)>=4 and history[3][0]['kind']==sources.BOOTSTRAP_MIGRATION,
                'SOURCE_ORDINARY_FINAL_PROOF_CHANGED')
        migration=history[3][0]
        review_sha256=migration['transition']['reviewDigest']
        evidence_sha256=migration['evidenceDigest']
        sc.need(read_controller_begin(expected_digest=sc.digest(intent))['intent']==intent,
                'SOURCE_ORDINARY_FINAL_PROOF_CHANGED')
    def phase():
        record,projection=read_latest_interlock(instance_id=binding['instanceId'],
            scope_digest=binding['scopeDigest'],generation=binding['generation'])
        sc.need(record==publication['record'] and projection['interlockDigest']==publication['digest']
                and projection['registryDigest']==publication['registryDigest'],
                'SOURCE_BOOTSTRAP_FINAL_PUBLICATION_CHANGED')
        if ordinary is not None:
            sc.need(read_controller_begin(expected_digest=sc.digest(intent))['intent']==intent,
                    'SOURCE_ORDINARY_FINAL_PROOF_CHANGED')
    phase()
    projected=staged_registry_profile(config,handoff=final['handoff'],staged_record=final['record'])
    source_pins={'profile.json':expected_profile_sha256,
        'legacy-release-profile.json':pins['legacyProfileDigest'],
        'successor-release-profile.json':pins['successorProfileDigest'],
        'semantic-peer.key':pins['peerKeyDigest'],'semantic-frame.key':pins['frameKeyDigest'],
        'bootstrap-review.json':review_sha256,'bootstrap-evidence.json':evidence_sha256}
    rows=sorted(view['sourceOperations'].values(),key=lambda row:row[1]['sourceRevision'])
    for prefix,row in zip(('transition','delivery-repair','delivery-repair-2'),rows[:3]):
        name=prefix+'-evidence.json'
        evidence=_retained_source_evidence(root,name,row[0])
        source_pins[name]=row[0]['evidenceDigest']
        source_pins[prefix+'-main.bundle']=evidence['bundleSha256']
    evidence=_pinned_bootstrap_material(root,'bootstrap-evidence.json',evidence_sha256)
    source_pins['bootstrap-main.bundle']=evidence['bundleSha256']
    limits={n:MAX_BUNDLE if n.endswith('.bundle') else 32 if n.endswith('.key')
            else 65536 if n=='profile.json' else 262144 for n in source_pins}
    hashes=_seal_bootstrap_material(root,target,limits,source_pins,
        {'profile.json':sc.canonical(projected).encode()},verify_only=verify_only,expected_target=expected_target)
    phase()
    if verify_only:
        received=_load_owner_config(str(target/'profile.json'),allow_semantic=True)
        _check_successor_profile(received,hashes['profile.json'])
        sc.need(received==projected,'SOURCE_BOOTSTRAP_FINAL_PROOF_CHANGED')
    return {'profileDigest':hashes['profile.json'],'profile':config,
            'generation':projected['semantic']['generation'],'fileHashes':hashes,
            'handoff':final['handoff']}

def begin_bootstrap_pair(expected_profile_sha256, *, review_sha256, evidence_sha256,
                         source_sha, checked, authorization):
    """Private one-shot controller writer; never an RPC or owner approval.

    Only the existing owner controller may supply the independently durable
    Check/stop authorization after actual frozen-source proof and seed.
    Recompute Registry replay and the mounted independent anchor, not merely
    the hashes in the supplied pair. The host owns authentication of its
    protected attempt and physical Docker exclusion.
    """
    from ..integrations.registry_contracts import semantic_contract as sc
    from ..extensions.maintenance_interlock_reader import read_latest_interlock,InterlockReservations

    domain,view,registry,review,receipt,binding,pair,actor,ids=_bootstrap_pair_intent(
        expected_profile_sha256,review_sha256=review_sha256,evidence_sha256=evidence_sha256,
        source_sha=source_sha,checked=checked,authorization=authorization,writable=True)
    pins={'instance_id':binding['instanceId'],'scope_digest':binding['scopeDigest'],'generation':binding['generation']}
    def verify_seed():
        from ..integrations.registry_contracts.maintenance_contract import validate_record
        rec,projection=read_latest_interlock(**pins)
        rec=validate_record(rec)
        sc.need(rec['phase']=='NORMAL' and rec['sequence']==0
                and rec['generation']==binding['generation']
                and rec['generation']!=authorization['targetGeneration']
                and sc.digest(rec)==projection['interlockDigest']==authorization['seedDigest']==binding['interlockDigest'],
                'SOURCE_BOOTSTRAP_PAIR_SEED_CHANGED')
        return rec
    with InterlockReservations().exclusive() as exclusive:
        sc.need(exclusive,'SOURCE_BOOTSTRAP_PAIR_WRITER_BUSY')
        verify_seed()
        view=domain.snapshot()
        if not view['operations']:
            sc.need(_bootstrap_candidate(domain,view,review,receipt,binding,expected_profile_sha256)==registry,
                    'SOURCE_BOOTSTRAP_PAIR_CHECK_CHANGED')
            def verify(req):
                verify_seed()
                return req['kind']=='PROTECTED_PAIRED_BEGIN' and req['actor']==actor and req['pair']==pair
            domain._protected_verify=verify
        else:
            sc.need(list(view['operations'])==ids and all(view['operations'][i][0]['pair']==pair for i in ids),
                    'SOURCE_BOOTSTRAP_PAIR_CHECK_CHANGED')
        result=domain.protected_begin_pair(pair,actor=actor,recorded_at=authorization['recordedAt'])
        sc.need(type(result) is list and [r['operationId'] for r in result]==ids,
                'SOURCE_BOOTSTRAP_PAIR_OUTCOME_UNKNOWN')
        # Open/close a real SQLite transaction to checkpoint the inactive
        # journal; never delete sidecars. Independently replay the result.
        with domain.store._db() as db:
            view=domain._project(db)
            recovered=_bootstrap_pair_result(domain,view,pair,actor,ids,authorization,verify_seed())
            sc.need(recovered['receipts']==result,'SOURCE_BOOTSTRAP_PAIR_CHECK_CHANGED')
        verify_seed()
    return recovered


def read_ordinary_return(expected_profile_sha256, *, intent, begin, check, source_receipt, stop, publication):
    from .protected_transition import staged_domain, _corrective_snapshot_copy
    from .release_event_journal import ReleaseEventJournal
    from ..extensions.maintenance_interlock_reader import read_latest_interlock, read_controller_begin, InterlockReservations
    from ..integrations.registry_contracts import maintenance_seal, semantic_contract as sc
    from ..integrations.registry_contracts.maintenance_contract import ordinary_pair_intent
    config,root,pins=_successor_inputs(expected_profile_sha256)
    pair=ordinary_pair_intent(intent)
    sc.need(expected_profile_sha256==intent['compatibility']['registry']['incumbentProfileDigest']
            and config['sourceWrite'].get('latestPin') is True
            and pins['generation']==intent['normal']['generation'],
            'SOURCE_ORDINARY_RETURN_CHANGED')
    def phase():
        record,projection=read_latest_interlock(instance_id=config['instanceId'],
            scope_digest=sc.digest(config['scope']),generation=publication['record']['generation'])
        sc.need(record==publication['record'] and projection['interlockDigest']==publication['digest']
                and projection['registryDigest']==begin['registryDigest']
                and read_controller_begin(expected_digest=sc.digest(intent))['intent']==intent,
                'SOURCE_ORDINARY_RETURN_CHANGED')
    journal=ReleaseEventJournal(STATE_PATH,instance_id=config['instanceId'],scope=config['scope'],
        expected_legacy=pins['legacyWitness'],transition_digest=pins['transitionDigest'])
    with InterlockReservations().exclusive() as exclusive:
        sc.need(exclusive,'SOURCE_ORDINARY_RETURN_BUSY')
        phase()
        with _corrective_snapshot_copy(journal) as copy:
            domain=staged_domain(copy,root,pins)
            actual=domain.protected_pair_begin_readback(pair,actor='owner-release-controller')
        recovery=maintenance_seal.ordinary_return_record(intent,begin,check,source_receipt,stop,publication,actual)
        phase()
    return {'record':recovery,'registryDigest':begin['registryDigest'],'checkpoint':actual['checkpoint']}

def frozen_pair_backup(expected_profile_sha256, *, pair, holds, phase_record,
                       verify_only, expected_target, target=Path('/target'),ordinary=None):
    """Bounded frozen SQLite copy for staging or pre-close reserve.

    Reuse the confined copy/replay primitive. This is not a new general
    backup/restore service, and does not claim independent host DR.
    """
    from .protected_transition import staged_domain, _corrective_snapshot_copy, _stage_registry_snapshot
    from .release_event_journal import ReleaseEventJournal
    from ..r7_registry_reader_mount import _check_owner_readonly_mount, _exact_mountinfo
    from ..extensions.maintenance_interlock_reader import read_latest_interlock, InterlockReservations
    from ..integrations.registry_contracts import semantic_contract as sc
    from ..integrations.registry_contracts.maintenance_contract import paired_begin, hold_snapshot, matching_holds, validate_record
    from .release_domain import key
    from .state_journal import _private
    sc.need(type(verify_only) is bool)
    config,root,pins=_successor_inputs(expected_profile_sha256)
    pair=paired_begin(pair,config['scope']['repository'])
    holds=hold_snapshot(holds);record=validate_record(phase_record)
    if ordinary is not None:
        from ..integrations.registry_contracts.maintenance_seal import ordinary_handover
        from ..extensions.maintenance_interlock_reader import read_controller_begin
        sc.fields(ordinary,('intent','begin','check','sourceReceipt','stop','publication'))
        intent=ordinary['intent'];begin=ordinary['begin']
        final=ordinary_handover(intent,begin,ordinary['check'],ordinary['sourceReceipt'],ordinary['stop'],ordinary['publication'])
        sc.need(pair==begin['pair'] and holds==begin['holdSnapshot']
                and expected_profile_sha256==intent['compatibility']['registry']['profileDigest']
                and record==ordinary['stop']['next']
                and expected_target==intent['compatibility']['roots']['state']
                and record['phase']=='APPLY_STOP',
                'SOURCE_ORDINARY_HANDOVER_CHANGED')
    sc.need(config['schemaVersion']==3 and config['sourceWrite'].get('latestPin') is True
            and (ordinary is not None or record['phase'] in ('BACKUP_FROZEN','PROMOTE_FROZEN') or
                 (verify_only and record['phase']=='RECOVERY_HOLD' and
                  record['generation']==record['attempt']['targetGeneration']))
            and pins['generation']==record['generation']
            and matching_holds(holds['holds'],record['attempt'])
            and record['attempt']['attemptId']==pair['attemptId']
            and all(h.get('pairDigest')==sc.digest(pair) for h in holds['holds']),
            'SOURCE_PAIRED_BACKUP_CHANGED')
    _check_owner_readonly_mount(STATE_PATH.parent)
    sc.need(_exact_mountinfo(Path('/proc/self/mountinfo').read_bytes(),STATE_PATH.parent,b'ro'),
            'SOURCE_PAIRED_BACKUP_MOUNT_REQUIRED')
    _private(target,True)
    sc.fields(expected_target,('device','inode'))
    def target_pin():
        row=target.stat(follow_symlinks=False)
        sc.need(all(type(expected_target[k]) is int and 0<=expected_target[k]<2**64 for k in ('device','inode'))
                and (row.st_dev,row.st_ino)==(expected_target['device'],expected_target['inode'])
                and (row.st_uid,row.st_gid)==(os.geteuid(),os.getegid())
                and stat.S_IMODE(row.st_mode)==0o700,
                'SOURCE_PAIRED_BACKUP_TARGET_CHANGED')
    target_pin()
    sc.need(target.is_absolute() and target.resolve()==target
            and (target.stat().st_dev,target.stat().st_ino)!=(STATE_PATH.parent.stat().st_dev,STATE_PATH.parent.stat().st_ino)
            and _exact_mountinfo(Path('/proc/self/mountinfo').read_bytes(),target,b'ro' if verify_only else b'rw')
            and bool(os.statvfs(target).f_flag & os.ST_RDONLY)==verify_only,
            'SOURCE_PAIRED_BACKUP_MOUNT_REQUIRED')
    scope={'instance_id':config['instanceId'],'scope_digest':sc.digest(config['scope']),'generation':pins['generation']}
    def phase():
        actual,projection=read_latest_interlock(**scope)
        sc.need(actual==record and projection['interlockDigest']==sc.digest(record)
                and projection['registryDigest']==sc.digest(holds),'SOURCE_PAIRED_BACKUP_PHASE_CHANGED')
        if ordinary is not None:
            sc.need(read_controller_begin(expected_digest=sc.digest(intent))['intent']==intent,
                    'SOURCE_ORDINARY_HANDOVER_CHANGED')
    def checkpoint(domain,view):
        if ordinary is not None:
            actual=domain.protected_pair_begin_readback(pair,actor='owner-release-controller')
            sc.need(all(actual[k]==begin[k] for k in ('receipts','checkpoint','holdSnapshot')),
                    'SOURCE_ORDINARY_HANDOVER_CHANGED')
        sc.need(domain._maintenance_snapshot(view)==holds and
                all(view[k]==pair['checkpoint'][k] for k in ('sourceCursor','sourceRevision','profileDigest')),
                'SOURCE_PAIRED_BACKUP_CHANGED')
        coverage={}
        for role,item in pair['items'].items():
            active=view['states'][key(item['subject'])]['activeAttempt']
            sc.need(active is not None and active.get('pairDigest')==sc.digest(pair),'SOURCE_PAIRED_BACKUP_CHANGED')
            coverage[role]=active['coveredRecordIds']
        return {'checkpoint':{k:view[k] for k in pair['checkpoint']},'holdSnapshot':holds,'coverage':coverage}
    def journal(path):
        return ReleaseEventJournal(path,instance_id=config['instanceId'],scope=config['scope'],
            expected_legacy=pins['legacyWitness'],transition_digest=pins['transitionDigest'])
    source=journal(STATE_PATH);dest=target/STATE_PATH.name
    with InterlockReservations().exclusive() as exclusive:
        sc.need(exclusive,'SOURCE_PAIRED_COMPLETION_WRITER_BUSY')
        phase()
        with _corrective_snapshot_copy(source) as copy:
            domain=staged_domain(copy,root,pins);expected=checkpoint(domain,domain.snapshot())
        if not verify_only and not list(target.iterdir()):
            _stage_registry_snapshot(source,root,pins,target=dest,expected_checkpoint=expected,checkpoint=checkpoint)
        sc.need(set(p.name for p in target.iterdir())=={dest.name},'SOURCE_PAIRED_BACKUP_CHANGED')
        _private(dest)
        with _corrective_snapshot_copy(journal(dest)) as copy:
            domain=staged_domain(copy,root,pins)
            sc.need(checkpoint(domain,domain.snapshot())==expected,'SOURCE_PAIRED_BACKUP_CHANGED')
        fd=os.open(dest,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            sha=hashlib.sha256()
            while True:
                block=stream.read(1048576)
                if not block:break
                sha.update(block)
            after=os.fstat(stream.fileno())
            sc.need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                    (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),
                    'SOURCE_PAIRED_BACKUP_CHANGED')
        phase()
        target_pin()
        result={**expected,'result':'PAIRED_FROZEN_LOCAL_STATE_RESERVE_ONLY' if ordinary is None else 'PAIRED_STAGED_STATE_COPY_ONLY',
                'profileDigest':expected_profile_sha256,'databaseSha256':sha.hexdigest(),
                'databaseBytes':before.st_size}
        if ordinary is not None:result['final']=final
        return result


def complete_frozen_pair(expected_profile_sha256, *, pair, holds, pending, evidence,
                         recorded_at, readback):
    """Owner-controller-only offline close and independently replayed NORMAL.

    The host owns the durable proof, full actual receiver observations and
    physical exclusion. This entrypoint accepts no public request or socket.
    On an uncertain write the host invokes only the RO path first.
    """
    import time
    from .protected_transition import staged_domain, _corrective_snapshot_copy
    from .release_event_journal import ReleaseEventJournal
    from ..r7_registry_reader_mount import _exact_mountinfo
    from ..extensions.maintenance_interlock_reader import read_latest_interlock, InterlockReservations
    from ..integrations.registry_contracts import semantic_contract as sc
    from ..integrations.registry_contracts.maintenance_evidence import paired_completion_params, paired_normal_record

    sc.need(type(readback) is bool)
    config,root,pins=_successor_inputs(expected_profile_sha256)
    sc.need(config['schemaVersion']==3 and config['sourceWrite'].get('latestPin') is True
            and pins['generation']==pending['generation']
            and pins['successorProfileDigest']==pair['checkpoint']['profileDigest'],
            'SOURCE_PAIRED_COMPLETION_PROFILE_CHANGED')
    mode=b'ro' if readback else b'rw'
    sc.need(_exact_mountinfo(Path('/proc/self/mountinfo').read_bytes(),STATE_PATH.parent,mode)
            and bool(os.statvfs(STATE_PATH.parent).f_flag & os.ST_RDONLY)==readback,
            'SOURCE_PAIRED_COMPLETION_MOUNT_REQUIRED')
    sc.revision(recorded_at)
    params=paired_completion_params(pending,pair,holds,evidence,now=recorded_at)
    # Time freshness is required for a NEW write. An exact durable original
    # readback can recover after a long interruption without new observations.
    actor='owner-release-controller'
    scope={'instance_id':config['instanceId'],'scope_digest':sc.digest(config['scope']),
           'generation':pins['generation']}
    def phase():
        record,projection=read_latest_interlock(**scope)
        sc.need(record==pending and projection['interlockDigest']==sc.digest(pending)
                and projection['registryDigest']==sc.digest(holds),
                'SOURCE_PAIRED_COMPLETION_PHASE_CHANGED')
    journal=ReleaseEventJournal(STATE_PATH,instance_id=config['instanceId'],scope=config['scope'],
        expected_legacy=pins['legacyWitness'],transition_digest=pins['transitionDigest'])
    def recover(domain):
        actual=domain.protected_complete_pair_readback(pair,params,actor=actor)
        return {'readback':actual,'normal':paired_normal_record(pending,pair,evidence,actual)}
    with InterlockReservations().exclusive() as exclusive:
        sc.need(exclusive,'SOURCE_PAIRED_COMPLETION_WRITER_BUSY')
        phase()
        if readback:
            with _corrective_snapshot_copy(journal) as copy:
                domain=staged_domain(copy,root,pins)
                view=domain.snapshot()
                _,obs,items=domain._paired_completion_requests(pair,params,actor=actor)
                reqs=obs+domain._paired_close_requests(pair,items,actor=actor)
                # Absence is an explicit, independently replayed outcome,
                # not an exception classifier. Any partial/conflicting
                # receipt or changed hold goes through exact close replay.
                if not any(req['operationId'] in view['operations'] for req in reqs):
                    actual=domain._maintenance_snapshot(view)
                    sc.need(actual==holds and all(view[k]==pair['checkpoint'][k]
                            for k in ('sourceCursor','sourceRevision','profileDigest')),
                            'SOURCE_PAIRED_COMPLETION_CHECKPOINT_CHANGED')
                    witness={'result':'PROTECTED_PAIR_COMPLETION_NOT_APPLIED',
                             'pairDigest':sc.digest(pair),'pendingDigest':sc.digest(pending),
                             'holdSnapshot':actual,'checkpoint':{k:view[k] for k in pair['checkpoint']}}
                    from ..integrations.registry_contracts.maintenance_evidence import paired_recovery_record
                    now=int(time.time())
                    expired=any(now-row['observedAt']>300 for row in evidence['observations'].values())
                    result={'notApplied':witness,'recovery':paired_recovery_record(pending,pair,holds,evidence,witness,now=now)
                            if expired else None}
                else:
                    result=recover(domain)
        else:
            domain=staged_domain(journal,root,pins)
            # Do not retry an already applied operation: exact replay can
            # recover it with original receipts. New writes require full
            # unchanged hold snapshot and fresh independently observed proof.
            view=domain.snapshot()
            if domain._maintenance_snapshot(view)!=holds:
                result=recover(domain)
            else:
                sc.need(recorded_at<=int(time.time()),'SOURCE_PAIRED_COMPLETION_OBSERVATION_TIME')
                paired_completion_params(pending,pair,holds,evidence,now=int(time.time()))
                _,obs,items=domain._paired_completion_requests(pair,params,actor=actor)
                reqs=obs+domain._paired_close_requests(pair,items,actor=actor)
                def verify(req):
                    phase()
                    return req in reqs
                domain._protected_verify=verify
                actual=domain.protected_complete_pair(pair,params,actor=actor,recorded_at=recorded_at)
                sc.need(actual.get('result')=='PROTECTED_PAIR_COMPLETION_READBACK_ONLY',
                        'SOURCE_PAIRED_COMPLETION_OUTCOME_UNKNOWN')
                with journal._db() as db:
                    domain._project(db)
                result=recover(domain)
                sc.need(result['readback']==actual,'SOURCE_PAIRED_COMPLETION_CHANGED')
        phase()
        return result


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
