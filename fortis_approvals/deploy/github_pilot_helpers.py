"""Operator-only helpers for an isolated GitHub pilot; standard library only.

No Docker access. No provider or database bytes are printed. Token input is
accepted only on the private provisioning pipe, never in command arguments.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import uuid

DBS = ('approvals.sqlite', 'owner.sqlite', 'sonar-receipts.sqlite')
MARKER = '.fortis-r7-unified-v1'
FILES = frozenset((MARKER, *DBS))
REVIEW_IMAGE = 'sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84'
CREDENTIALS = {'fortis-r7-identity': '/run/r7-identity', 'fortis-r7-grant': '/run/r7-grant',
               'fortis-r7-sonar-token': '/run/r7-sonar-token'}


def require(condition, code):
    if not condition: raise RuntimeError(code)


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


VISUAL_MEDIA_DIR = 'native-git/visual-media'

NATIVE_DIRS = ('native-git', 'native-git/artifacts', 'native-git/git',
               'native-git/git/runner', 'native-git/git/runner/home',
               'native-git/git/runner/empty-hooks')


def native_files(root, *, uid, gid):
    """Admit old and PNG-MVP native layouts, never unlisted transient files."""
    visual_dir = root / VISUAL_MEDIA_DIR
    # The PNG-MVP Store creates this directory on startup. Older accepted
    # volumes do not have it, so its absence must remain backward compatible.
    visual_present = visual_dir.exists() or visual_dir.is_symlink()
    expected = {'native-git': {'artifacts', 'workflow.sqlite', 'git'} |
                ({'visual-media'} if visual_present else set()),
        'native-git/git': {'runner'},
        'native-git/git/runner': {'home', 'empty-hooks', 'empty.config'},
        'native-git/git/runner/home': set(), 'native-git/git/runner/empty-hooks': set()}
    for name in NATIVE_DIRS + ((VISUAL_MEDIA_DIR,) if visual_present else ()):
        directory = root / name
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid and
                stat.S_IMODE(info.st_mode) == 0o700, 'PILOT_NATIVE_DIRECTORY_INVALID')
        if name in expected:
            require({p.name for p in directory.iterdir()} == expected[name],
                    'PILOT_NATIVE_UNKNOWN_FILES_OR_TEMPORARY_GIT_STATE')
    files = {'native-git/workflow.sqlite', 'native-git/git/runner/empty.config'}
    for artifact in (root / 'native-git/artifacts').iterdir():
        require(re.fullmatch('[0-9a-f]{64}\.bundle', artifact.name) is not None,
                'PILOT_NATIVE_ARTIFACT_NAME_INVALID')
        files.add('native-git/artifacts/' + artifact.name)
    if visual_present:
        for media in visual_dir.iterdir():
            require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-[0-4]-[0-9a-f]{64}\.png',
                                 media.name) is not None, 'PILOT_VISUAL_MEDIA_FILENAME_INVALID')
            files.add(VISUAL_MEDIA_DIR + '/' + media.name)
    return files


def validate_uncertain_ids(value):
    # A reviewed release can preserve *only* explicitly pinned, terminally
    # non-dispatched unknown outcomes. No global skip or implicit wildcard.
    require(type(value) is list and len(value) <= 20 and
            len(value) == len(set(value)) and all(
                type(x) is str and bool(re.fullmatch(
                    r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',x))
                and str(uuid.UUID(x)) == x for x in value),
            'PILOT_UNCERTAIN_SCOPE_INVALID')
    return frozenset(value)


def inspect_state(volume, *, uid=10001, gid=10001, github=False, native=False,
                  preserve_uncertain_ids=None, require_exact_uncertain=False,
                  preserve_claimed_ids=None, require_exact_claimed=False,
                  preserve_approved_ids=None, require_exact_approved=False):
    permitted = validate_uncertain_ids(
        [] if preserve_uncertain_ids is None else preserve_uncertain_ids)
    claimed_permitted = validate_uncertain_ids(
        [] if preserve_claimed_ids is None else preserve_claimed_ids)
    require(len(claimed_permitted)<=3,'PILOT_CLAIMED_SCOPE_INVALID')
    require(type(require_exact_uncertain) is bool and type(require_exact_claimed) is bool,
            'PILOT_UNCERTAIN_SCOPE_INVALID')
    require(native or not claimed_permitted,'PILOT_CLAIMED_REQUIRES_NATIVE')
    approved_permitted=validate_uncertain_ids(
        [] if preserve_approved_ids is None else preserve_approved_ids)
    # Bounded exact owner-reviewed set, not a wildcard or auto-admission.
    require(len(approved_permitted)<=20,'PILOT_APPROVED_SCOPE_TOO_LARGE')
    require(type(require_exact_approved) is bool,'PILOT_APPROVED_SCOPE_INVALID')
    require(not approved_permitted or (native and github),'PILOT_APPROVED_REQUIRES_NATIVE_GITHUB')
    files = FILES | ({'github-receipts.sqlite'} if github else set())
    require(not native or github, 'PILOT_NATIVE_REQUIRES_GITHUB_STATE')
    databases = DBS + (('github-receipts.sqlite',) if github else ())
    if native: databases += ('native-git/workflow.sqlite',)
    volume = Path(volume)
    root = volume / 'private'
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid and
            stat.S_IMODE(info.st_mode) == 0o700, 'PILOT_STATE_DIRECTORY_INVALID')
    require({p.name for p in root.iterdir()} == files | ({'native-git'} if native else set()),
            'PILOT_SOURCE_UNKNOWN_FILES_OR_JOURNAL')
    if native: files |= native_files(root, uid=uid, gid=gid)
    for name in files:
        info = (root / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_gid == gid and
                stat.S_IMODE(info.st_mode) == 0o600, 'PILOT_SOURCE_FILE_INVALID')
        if native: require(info.st_nlink == 1, 'PILOT_NATIVE_HARDLINK_DENIED')
    if native:
        require((root / 'native-git/git/runner/empty.config').read_bytes() == b'', 'PILOT_NATIVE_RUNNER_CONFIG_NOT_EMPTY')
        for name in files:
            if name.startswith('native-git/artifacts/'):
                artifact = root / name
                require(0 < artifact.stat().st_size <= 24 * 1024 * 1024 and
                        file_hash(artifact) == artifact.name[:-7], 'PILOT_NATIVE_ARTIFACT_DIGEST_MISMATCH')
    require((root / MARKER).read_bytes() == b'fortis-r7-unified-v1\n', 'PILOT_SOURCE_MARKER_INVALID')
    connections = {}
    try:
        for name in databases:
            db = sqlite3.connect((root / name).absolute().as_uri() + '?mode=ro', uri=True)
            connections[name] = db
            require(db.execute('PRAGMA journal_mode').fetchone()[0] == 'delete', 'PILOT_SOURCE_JOURNAL_MODE_UNKNOWN')
            require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'PILOT_SOURCE_INTEGRITY_FAILED')
        a, o, receipts = (connections[name] for name in DBS)
        binding = dict(o.execute('SELECT setting,value FROM config'))
        require(binding == {'origin': 'http://localhost:19203', 'rpId': 'localhost', 'owner': 'owner'},
                'PILOT_REVIEW_OWNER_BINDING_INVALID')
        active = o.execute('SELECT COUNT(*) FROM credentials WHERE active=1').fetchone()[0]
        require(active >= 1, 'PILOT_EXISTING_OWNER_CREDENTIAL_REQUIRED')
        # In-flight actions and unreviewed unknowns can never be carried into
        # an image. A scoped owner-reviewed opt-in preserves uncertain rows and
        # their immutable IDs/receipts verbatim; never rewrites their outcome.
        # No PENDING or DISPATCHED carryover. One exact owner-authorized,
        # pre-dispatch APPROVED may cross an image boundary unchanged so that
        # the *new* owner Portal can cancel it atomically after activation.
        require(a.execute(
            "SELECT COUNT(*) FROM requests WHERE state IN ('PENDING','DISPATCHED')"
        ).fetchone()[0] == 0,'PILOT_REVIEW_HAS_UNFINISHED_REQUESTS')
        approved_id_rows=list(a.execute("SELECT id FROM requests WHERE state='APPROVED'"))
        approved_ids={r[0] for r in approved_id_rows}
        require(len(approved_id_rows)==len(approved_ids),
                'PILOT_APPROVED_DUPLICATE_REQUEST_IDS')
        if approved_ids and not approved_permitted:
            # A nonempty approved set without an owner-pinned allowlist:
            # either flag was omitted or was lost in the Windows path.
            raise RuntimeError('PILOT_APPROVED_PRESERVATION_SCOPE_EMPTY')
        unexpected=approved_ids-approved_permitted
        if unexpected:
            if approved_ids & approved_permitted:
                raise RuntimeError('PILOT_APPROVED_ADDITIONAL_REQUESTS_PRESENT')
            raise RuntimeError('PILOT_APPROVED_EXPECTED_REQUEST_MISMATCH')
        if require_exact_approved:
            require(approved_ids==approved_permitted,'PILOT_APPROVED_SET_CHANGED')
        if approved_ids:
            approved_rows=list(a.execute(
                "SELECT id,actor,payload,result,failure FROM requests WHERE state='APPROVED'"))
            columns={x[1] for x in a.execute('PRAGMA table_info(events)')}
            require({'request_id','seq','state'}<=columns,
                    'PILOT_APPROVED_AUDIT_SCHEMA_INVALID')
            require(native and github,'PILOT_APPROVED_REQUIRES_NATIVE_GITHUB')
            jobs=connections['native-git/workflow.sqlite']
            # Each explicitly named request must still be pre-dispatch.
            # Never invoke an adapter, reconcile, reset jobs or mutate Core.
            for request_id,actor,payload,result,failure in approved_rows:
                require(type(actor) is str and bool(actor) and
                        result is None and failure is None,
                        'PILOT_APPROVED_RECORD_INVALID')
                try: intent=json.loads(payload)
                except (TypeError,ValueError):
                    raise RuntimeError('PILOT_APPROVED_PAYLOAD_INVALID') from None
                require(type(intent) is dict and
                        type(intent.get('service')) is str and
                        bool(intent['service']) and
                        type(intent.get('operation')) is str and
                        bool(intent['operation']) and
                        type(intent.get('target')) is str and
                        bool(intent['target']) and
                        type(intent.get('params')) is dict,
                        'PILOT_APPROVED_PAYLOAD_INVALID')
                states=[x[0] for x in a.execute(
                    'SELECT state FROM events WHERE request_id=? ORDER BY seq',
                    (request_id,))]
                require(states in (['APPROVED'],['PENDING','APPROVED']),
                        'PILOT_APPROVED_WAS_DISPATCHED_OR_REWRITTEN')
                require(jobs.execute('SELECT 1 FROM jobs WHERE id=?',
                                     (request_id,)).fetchone() is None,
                        'PILOT_APPROVED_WORKER_JOB_PRESENT')
                require(connections['github-receipts.sqlite'].execute(
                    'SELECT 1 FROM receipts WHERE request_id=?',
                    (request_id,)).fetchone() is None,
                        'PILOT_APPROVED_GITHUB_RECEIPT_PRESENT')
                require(connections['sonar-receipts.sqlite'].execute(
                    'SELECT 1 FROM receipts WHERE request_id=?',
                    (request_id,)).fetchone() is None,
                        'PILOT_APPROVED_SONAR_RECEIPT_PRESENT')
        unknown_count=a.execute(
            "SELECT COUNT(*) FROM requests WHERE state='UNCERTAIN'").fetchone()[0]
        # Historic offline fixtures contain only a state column. An actual
        # uncertain entry must have an exact immutable request ID to preserve.
        if unknown_count:
            require('id' in {r[1] for r in a.execute('PRAGMA table_info(requests)')},
                    'PILOT_UNCERTAIN_REQUEST_ID_REQUIRED')
            unresolved = frozenset(row[0] for row in a.execute(
                "SELECT id FROM requests WHERE state='UNCERTAIN'"))
            require(len(unresolved)==unknown_count,
                    'PILOT_UNCERTAIN_REQUEST_IDS_INVALID')
        else:
            unresolved=frozenset()
        require(unresolved <= permitted,'PILOT_REVIEW_HAS_UNREVIEWED_UNCERTAIN')
        if require_exact_uncertain:
            require(unresolved == permitted,'PILOT_REVIEW_UNCERTAIN_SET_CHANGED')
        summary = {'requests': a.execute('SELECT COUNT(*) FROM requests').fetchone()[0],
                   'uncertainRequestIds':sorted(unresolved),
                        'approvedRequestIds':sorted(approved_ids),
                        'requestStates': dict(a.execute('SELECT state,COUNT(*) FROM requests GROUP BY state')),
            'events': a.execute('SELECT COUNT(*) FROM events').fetchone()[0],
            'receipts': receipts.execute('SELECT COUNT(*) FROM receipts').fetchone()[0],
            'credentialsActive': active, 'credentialsTotal': o.execute('SELECT COUNT(*) FROM credentials').fetchone()[0]}
        if native:
            db = connections['native-git/workflow.sqlite']
            tables = {r[0] for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            has_visual = (root / VISUAL_MEDIA_DIR).is_dir()
            require(tables == ({'artifacts', 'tasks', 'jobs', 'visual_media'} if has_visual
                               else {'artifacts', 'tasks', 'jobs'}), 'PILOT_NATIVE_SCHEMA_UNKNOWN')
            if has_visual:
                # Files and rows are a closed, byte-preserved pair: do not lose
                # attachments, silently drop unknown paths or follow symlinks.
                media_files = {name for name in files if name.startswith(VISUAL_MEDIA_DIR + '/')}
                media_rows = db.execute(
                    'SELECT request_id,actor,repo,run_id,idx,sha,size,name FROM visual_media').fetchall()
                require(len(media_rows) <= 5000, 'PILOT_VISUAL_MEDIA_LIMIT')
                expected_files = set()
                for ident, actor, repo, run_id, idx, sha, size, name in media_rows:
                    require(type(ident) is str and bool(re.fullmatch(
                                r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', ident)) and
                            type(actor) is str and bool(actor) and
                            repo == 'visual-workspace' and
                            type(run_id) is str and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}',run_id)) and
                            type(idx) is int and 0 <= idx < 5 and
                            type(sha) is str and bool(re.fullmatch('[0-9a-f]{64}',sha)) and
                            type(size) is int and 24 <= size <= 10*1024*1024 and
                            type(name) is str and 1 <= len(name) <= 120,
                            'PILOT_VISUAL_MEDIA_ROW_INVALID')
                    rel = VISUAL_MEDIA_DIR + '/' + ident + '-' + str(idx) + '-' + sha + '.png'
                    require(rel in media_files, 'PILOT_VISUAL_MEDIA_FILE_MISSING')
                    path = root / rel
                    content = path.read_bytes()
                    require(len(content) == size and
                            content.startswith(b'\x89PNG\r\n\x1a\n') and content[12:16] == b'IHDR' and
                            hashlib.sha256(content).hexdigest() == sha,
                            'PILOT_VISUAL_MEDIA_DIGEST_MISMATCH')
                    expected_files.add(rel)
                require(expected_files == media_files, 'PILOT_VISUAL_MEDIA_UNREGISTERED_FILE')
            states = dict(db.execute('SELECT state,COUNT(*) FROM jobs GROUP BY state'))
            require(set(states) <= {'DONE', 'FAILED', 'CLAIMED'},
                    'PILOT_NATIVE_HAS_UNFINISHED_JOBS')
            claim_count=states.get('CLAIMED',0)
            if claim_count:
                columns={row[1] for row in db.execute('PRAGMA table_info(jobs)')}
                require({'id','actor','payload','state','claim','result','error'} <= columns,
                        'PILOT_CLAIMED_JOB_SCHEMA_INVALID')
                claims=list(db.execute(
                    "SELECT id,actor,payload,claim,result,error FROM jobs WHERE state='CLAIMED'"))
                claimed_ids={row[0] for row in claims}
                require(len(claims)==len(claimed_ids)==claim_count,
                        'PILOT_CLAIMED_JOB_IDS_INVALID')
                require(claimed_ids <= claimed_permitted,
                        'PILOT_NATIVE_HAS_UNREVIEWED_CLAIMED_JOBS')
                for job_id,job_actor,raw,claim,result,error in claims:
                    try:
                        job_payload=json.loads(raw)
                    except (TypeError,ValueError):
                        raise RuntimeError('PILOT_CLAIMED_JOB_RECORD_INVALID') from None
                    approval=a.execute(
                        'SELECT actor,state,payload FROM requests WHERE id=?',
                        (job_id,)).fetchone()
                    require(approval is not None and approval[1] in
                            ('UNCERTAIN','CLOSED_UNCONFIRMED'),
                            'PILOT_CLAIMED_APPROVAL_NOT_UNCERTAIN')
                    if approval[1]=='UNCERTAIN':
                        require(job_id in permitted,
                                'PILOT_CLAIMED_SCOPE_NOT_UNCERTAIN')
                    else:
                        # A user may administratively close an unknown-outcome
                        # request without rewriting its worker job. Such a
                        # claimed job must remain explicitly scoped and have
                        # a durable closure event before byte-for-byte carryover.
                        audit=a.execute(
                            "SELECT detail FROM events WHERE request_id=? "
                            "AND state='CLOSED_UNCONFIRMED' ORDER BY seq DESC LIMIT 1",
                            (job_id,)).fetchone()
                        require(audit is not None,
                                'PILOT_CLAIMED_CLOSURE_AUDIT_MISSING')
                        try:closure=json.loads(audit[0])
                        except (TypeError,ValueError):
                            raise RuntimeError('PILOT_CLAIMED_CLOSURE_AUDIT_INVALID') from None
                        require(type(closure) is dict and
                                type(closure.get('owner')) is str and
                                bool(closure['owner']) and
                                closure.get('remoteEffectVerified') is False,
                                'PILOT_CLAIMED_CLOSURE_AUDIT_INVALID')
                    try:
                        request=json.loads(approval[2])
                    except (TypeError,ValueError):
                        raise RuntimeError('PILOT_CLAIMED_JOB_RECORD_INVALID') from None
                    require(
                        type(job_actor) is str and job_actor == approval[0] and
                        type(job_payload) is dict and type(request) is dict and
                        job_payload.get('requestId')==job_id and
                        job_payload.get('service')=='workspace' and
                        job_payload.get('operation')=='create_task' and
                        request.get('service')=='workspace' and
                        request.get('operation')=='create_task' and
                        type(job_payload.get('target')) is str and
                        job_payload.get('target')==request.get('target') and
                        job_payload.get('params')==request.get('params') and
                        type(claim) is str and bool(re.fullmatch(
                            r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',claim)) and
                        result is None and error is None,
                        'PILOT_CLAIMED_JOB_RECORD_INVALID')
            else:
                claimed_ids=set()
            if require_exact_claimed:
                require(claimed_ids==claimed_permitted,
                        'PILOT_CLAIMED_JOB_SET_CHANGED')
            for (digest,) in db.execute('SELECT digest FROM artifacts'):
                require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest) and
                        'native-git/artifacts/' + digest + '.bundle' in files, 'PILOT_NATIVE_ARTIFACT_UNAVAILABLE')
            summary['native'] = {'tasks': db.execute('SELECT COUNT(*) FROM tasks').fetchone()[0],
                'artifacts': db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],
                'jobStates': states, 'preservedClaimedIds':sorted(claimed_ids)}
        if github: summary['githubReceipts'] = connections['github-receipts.sqlite'].execute('SELECT COUNT(*) FROM receipts').fetchone()[0]
    finally:
        for db in connections.values(): db.close()
    return {'sha256': {name: file_hash(root / name) for name in sorted(files)}, 'summary': summary}


def clone_state(source, target, *, uid=10001, gid=10001, github=False,
                native=False, preserve_uncertain_ids=None, preserve_claimed_ids=None,
                preserve_approved_ids=None, require_exact_approved=False):
    source, target = Path(source), Path(target)
    require(not source.is_symlink() and not target.is_symlink() and source.is_dir() and target.is_dir(), 'PILOT_VOLUME_ROOT_INVALID')
    require(source.resolve() != target.resolve() and not any(target.iterdir()), 'PILOT_CLONE_TARGET_NOT_EMPTY')
    before = inspect_state(source, uid=uid, gid=gid, github=github, native=native,
                           preserve_uncertain_ids=preserve_uncertain_ids,
                           preserve_claimed_ids=preserve_claimed_ids,
                           preserve_approved_ids=preserve_approved_ids,
                           require_exact_approved=require_exact_approved)
    files = set(before['sha256'])
    private = target / 'private'
    private.mkdir(mode=0o700)
    if native:
        for name in NATIVE_DIRS + ((VISUAL_MEDIA_DIR,) if
                (source / 'private' / VISUAL_MEDIA_DIR).is_dir() else ()):
            (private / name).mkdir(mode=0o700)
    for name in sorted(files):
        descriptor = os.open(private / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write((source / 'private' / name).read_bytes())
            output.flush(); os.fsync(output.fileno())
        os.chmod(private / name, 0o600)
        os.chown(private / name, uid, gid)
    native_dirs = NATIVE_DIRS + ((VISUAL_MEDIA_DIR,) if native and
        (source / 'private' / VISUAL_MEDIA_DIR).is_dir() else ())
    for directory in ([private] + [private / name for name in native_dirs] if native else [private]):
        os.chmod(directory, 0o700); os.chown(directory, uid, gid)
    require(inspect_state(target, uid=uid, gid=gid, github=github, native=native,
                           preserve_uncertain_ids=preserve_uncertain_ids,
                           preserve_claimed_ids=preserve_claimed_ids,
                           preserve_approved_ids=preserve_approved_ids,
                           require_exact_approved=require_exact_approved) == before,
            'PILOT_CLONE_VERIFICATION_FAILED')
    require(inspect_state(source, uid=uid, gid=gid, github=github, native=native,
                          preserve_uncertain_ids=preserve_uncertain_ids,
                          preserve_claimed_ids=preserve_claimed_ids,
                          preserve_approved_ids=preserve_approved_ids,
                          require_exact_approved=require_exact_approved) == before,
            'PILOT_SOURCE_CHANGED_DURING_CLONE')
    return before


def provision_token(token, volume='/provision', *, uid=10001, gid=10001):
    require(type(token) is str and bool(re.fullmatch(r'[A-Za-z0-9_]{20,4096}', token)), 'PILOT_CREDENTIAL_FORMAT_INVALID')
    root = Path(volume)
    require(root.is_dir() and not root.is_symlink() and not any(root.iterdir()), 'PILOT_CREDENTIAL_VOLUME_NOT_EMPTY')
    os.chmod(root, 0o700)
    descriptor = os.open(root / 'token', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(token.encode('ascii') + b'\n'); output.flush(); os.fsync(output.fileno())
    os.chmod(root / 'token', 0o600); os.chown(root / 'token', uid, gid); os.chown(root, uid, gid)
    return {'credentialProvisioned': True, 'uid': uid, 'mode': '0600'}


GATEWAY_EGRESS_NETWORK = 'fortis-gateway-egress'
GATEWAY_ACTION_NETWORK = 'fortis-actioncore-net'


def admit_gateway_networks(container, expected, *, pilot):
    """Guard exact Docker endpoint IDs; do not trust NetworkMode alone."""
    host = container['HostConfig']
    actual = container.get('NetworkSettings', {}).get('Networks')
    wanted = expected.get('gatewayNetworks')
    if wanted is None:
        # Legacy primary or isolated review: keep the prior bridge contract.
        require(host['NetworkMode'] == 'bridge', 'PILOT_RESOURCE_OR_NETWORK_MISMATCH')
        if actual is not None:
            require(type(actual) is dict and set(actual) == {'bridge'},
                    'PILOT_UNREVIEWED_NETWORK_ATTACHMENT')
        return
    require(pilot and type(wanted) is dict and set(wanted) ==
            {GATEWAY_EGRESS_NETWORK, GATEWAY_ACTION_NETWORK} and
            all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v)
                for v in wanted.values()) and len(set(wanted.values())) == 2,
            'PILOT_GATEWAY_NETWORK_RECORD_INVALID')
    require(host['NetworkMode'] == GATEWAY_EGRESS_NETWORK,
            'PILOT_RESOURCE_OR_NETWORK_MISMATCH')
    pending = expected.get('allowPendingActionNetwork') is True
    if pending:
        # Return-only escape for a never-started candidate interrupted between
        # docker create and controller-owned network connect. Not live admission.
        require(expected.get('status') == 'created' and type(actual) is dict and
                set(actual) == {GATEWAY_EGRESS_NETWORK},
                'PILOT_PENDING_NETWORK_NOT_PRISTINE')
    else:
        require(type(actual) is dict and set(actual) == set(wanted),
                'PILOT_UNREVIEWED_NETWORK_ATTACHMENT')
    for name in actual:
        endpoint = actual[name]
        require(type(endpoint) is dict and endpoint.get('NetworkID') == wanted[name],
                'PILOT_GATEWAY_NETWORK_ID_MISMATCH')


def admit(container, expected, *, pilot):
    require(container['Id'] == expected['id'] if expected.get('id') else bool(re.fullmatch('[0-9a-f]{64}', container['Id'])),
            'PILOT_CONTAINER_ID_MISMATCH')
    require(container['Name'] == '/' + expected['name'] and container['Image'] == expected['image'], 'PILOT_CONTAINER_IDENTITY_MISMATCH')
    config, host = container['Config'], container['HostConfig']
    require(config['User'] == '10001:10001' and config.get('WorkingDir') == '/opt/fortis' and config['Cmd'] == ['python', '-m', 'fortis_approvals.r7_unified_server'] and
            config.get('Entrypoint') in (None, []), 'PILOT_COMMAND_OR_USER_MISMATCH')
    require(host['ReadonlyRootfs'] is True and host['Privileged'] is False and host['AutoRemove'] is False and
            host['Init'] is True and host['CapDrop'] == ['ALL'] and not host.get('CapAdd'), 'PILOT_SECURITY_MISMATCH')
    require(host['SecurityOpt'] in (['no-new-privileges'], ['no-new-privileges:true']), 'PILOT_SECURITY_OPTIONS_MISMATCH')
    restart = expected.get('restartPolicy', 'no')
    require(restart == 'no' or (pilot and expected['name'] == 'fortis-gateway' and restart == 'unless-stopped'),
            'PILOT_RESTART_POLICY_DENIED')
    require(host['PidsLimit'] == 100 and host['Memory'] == 536870912 and
            host['RestartPolicy'] == {'Name': restart, 'MaximumRetryCount': 0}, 'PILOT_RESOURCE_OR_NETWORK_MISMATCH')
    admit_gateway_networks(container, expected, pilot=pilot)
    require(host['PortBindings'] == {'19103/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19203'}],
                                   '19104/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19204'}]}, 'PILOT_PORTS_MISMATCH')
    require(host.get('Tmpfs') == {'/tmp': 'rw,nosuid,nodev,size=16m'} and
            host.get('MemorySwap') == 1073741824 and host.get('ShmSize') == 67108864,
            'PILOT_TMPFS_OR_RESOURCE_MISMATCH')
    health = config.get('Healthcheck', {})
    require(health.get('Test') == ['CMD-SHELL', 'python -m fortis_approvals.r7_unified_server health'] and
            health.get('Interval') == 20000000000 and health.get('Timeout') == 5000000000 and
            health.get('StartPeriod') == 20000000000 and health.get('Retries') == 3, 'PILOT_HEALTH_POLICY_MISMATCH')
    for key in ('Binds', 'VolumesFrom', 'Devices', 'DeviceRequests', 'PidMode', 'UsernsMode'):
        require(not host.get(key), 'PILOT_UNREVIEWED_HOST_ACCESS')
    require(host.get('IpcMode') == 'private', 'PILOT_IPC_MISMATCH')
    desired = {('volume', expected['stateVolume'], '/state', True)}
    desired |= {('volume', name, path, False) for name, path in CREDENTIALS.items()}
    if expected.get('vaultVolume'):
        require(bool(re.fullmatch('fortis-review-secrets(?:-[a-z0-9-]{1,48})?', expected['vaultVolume'])), 'PILOT_VAULT_VOLUME_INVALID')
        desired.add(('volume', expected['vaultVolume'], '/run/fortis-secrets', False))
    if pilot:
        require(bool(re.fullmatch('fortis-github-pilot-state-[0-9a-f]{32}', expected['stateVolume'])), 'PILOT_DEDICATED_STATE_REQUIRED')
        require(bool(re.fullmatch('fortis-github-pilot-token-[0-9a-f]{32}', expected['tokenVolume'])), 'PILOT_DEDICATED_TOKEN_REQUIRED')
        desired.add(('volume', expected['tokenVolume'], '/run/github-token', False))
    else:
        require(expected['stateVolume'] == 'fortis-r7-state-review-20261105' and container['Image'] == REVIEW_IMAGE,
                'PILOT_ORIGINAL_REVIEW_REQUIRED')
    mounts = [(m['Type'], m.get('Name'), m['Destination'], m['RW']) for m in container['Mounts']]
    require(len(mounts) == len(desired) and set(mounts) == desired, 'PILOT_MOUNT_CONFIGURATION_MISMATCH')
    for mount in container['Mounts']:
        require(mount['Source'] == '/var/lib/docker/volumes/' + mount['Name'] + '/_data', 'PILOT_VOLUME_ALIAS_UNKNOWN')
    public = [item.split('=', 1) for item in config.get('Env', []) if item.startswith('FORTIS_')]
    env = dict(public)
    require(len(public) == len(env), 'PILOT_DUPLICATE_ENVIRONMENT')
    required = {'FORTIS_OWNER_ORIGIN': 'http://localhost:19203', 'FORTIS_MACHINE_HOST': 'host.docker.internal:19204',
                'FORTIS_SONAR_REGION': 'eu', 'FORTIS_SONAR_ORGANIZATIONS': 'alexpastukhh',
                'FORTIS_SONAR_PROJECT_KEY': 'AlexPastukhh_obs-planning-docs'}
    if pilot:
        required.update(FORTIS_GITHUB_PILOT='1', FORTIS_GITHUB_OWNER=expected['owner'],
                        FORTIS_GITHUB_REPOSITORY=expected['repository'], FORTIS_GITHUB_BRANCH_PREFIX='fortis-e2e/')
    if pilot and expected.get('filePrBranch'):
        require(bool(re.fullmatch('fortis-e2e/[0-9a-f-]{36}-approve', expected['filePrBranch'])), 'PILOT_FILE_PR_BRANCH_INVALID')
        required['FORTIS_GITHUB_FILE_PR_BRANCH'] = expected['filePrBranch']
    if pilot and expected.get('ciReads'):
        require(bool(expected.get('filePrBranch')), 'PILOT_CI_REQUIRES_FILE_PR_SCOPE')
        required['FORTIS_GITHUB_CI_READS'] = '1'
    if pilot and expected.get('nativeWorktree'):
        require(expected.get('ciReads') and expected.get('requiredWorkflows') == '408327525' and
                bool(re.fullmatch('[a-z0-9][a-z0-9-]{0,99}',expected.get('bootstrapTask',''))), 'PILOT_NATIVE_CONFIGURATION_INVALID')
        required.update(FORTIS_GITHUB_NATIVE_WORKTREE='1',FORTIS_GITHUB_REQUIRED_WORKFLOWS=expected['requiredWorkflows'],
                        FORTIS_GITHUB_BOOTSTRAP_TASK=expected['bootstrapTask'])
    multi=expected.get('dynamicRepositories',False)
    require(type(multi) is bool and (not multi or pilot and expected.get('nativeWorktree') is True),
            'PILOT_DYNAMIC_REPOSITORIES_CONFIGURATION_INVALID')
    if multi:required['FORTIS_GITHUB_NATIVE_MULTI_REPO']='1'
    ci_repos=expected.get('ciControlRepositories','')
    require(type(ci_repos) is str and (not ci_repos or bool(re.fullmatch(
        r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}(?:,[A-Za-z0-9][A-Za-z0-9_.-]{0,99}){0,19}',ci_repos))) and
        (not ci_repos or len(ci_repos.split(','))==len(set(ci_repos.split(',')))),
        'PILOT_CI_CONTROL_CONFIG_INVALID')
    if ci_repos:
        require(pilot and expected.get('nativeWorktree') is True,
                'PILOT_CI_CONTROL_REQUIRES_NATIVE')
        required['FORTIS_GITHUB_CI_CONTROL_REPOSITORIES']=ci_repos
    owner_shell=expected.get('ownerShell',False)
    require(type(owner_shell) is bool and (not owner_shell or pilot and bool(expected.get('vaultVolume'))),
            'PILOT_OWNER_SHELL_CONFIGURATION_INVALID')
    if owner_shell:
        required['FORTIS_OWNER_SHELL_CONFIG']='{"port":10443,"serverCA":"/run/fortis-secrets/owner-shell/server-ca.pem","clientCert":"/run/fortis-secrets/owner-shell/client.pem","clientKey":"/run/fortis-secrets/owner-shell/client.key","secretFile":"/run/fortis-secrets/owner-shell/secret.txt"}'
    require(env == required, 'PILOT_PUBLIC_CONFIGURATION_MISMATCH')
    require(container['State']['Status'] == expected['status'], 'PILOT_CONTAINER_STATUS_MISMATCH')
    if expected['status'] == 'running' and expected.get('requireHealthy', True):
        require(container['State'].get('Health', {}).get('Status') == 'healthy', 'PILOT_CONTAINER_NOT_HEALTHY')
    return {'admission': 'PASS'}


def verify_receipt(request_id, repository, branch, sha, root='/state/private'):
    require(type(request_id) is str and bool(re.fullmatch('[0-9a-f-]{36}', request_id)), 'PILOT_RECEIPT_REQUEST_ID_INVALID')
    root = Path(root)
    with sqlite3.connect((root / 'github-receipts.sqlite').absolute().as_uri() + '?mode=ro', uri=True) as db:
        row = db.execute('SELECT result FROM receipts WHERE request_id=?', (request_id,)).fetchone()
    require(row is not None, 'PILOT_RECEIPT_MISSING')
    expected = {'requestId': request_id, 'operation': 'create_branch', 'repository': repository, 'branch': branch, 'sha': sha}
    require(json.loads(row[0]) == expected, 'PILOT_RECEIPT_MISMATCH')
    with sqlite3.connect((root / 'approvals.sqlite').absolute().as_uri() + '?mode=ro', uri=True) as db:
        row = db.execute('SELECT state,payload,decision,owner FROM requests WHERE id=?', (request_id,)).fetchone()
    require(row is not None and row[0] == 'EXECUTED' and row[2] == 'approve' and row[3] == 'owner',
            'PILOT_CORE_OWNER_EXECUTION_NOT_CONFIRMED')
    payload = json.loads(row[1])
    require(payload['service'] == 'github' and payload['operation'] == 'create_branch' and payload['target'] == repository and
            payload['params'] == {'branch': branch, 'sourceSha': sha}, 'PILOT_CORE_PAYLOAD_MISMATCH')
    return {'receiptVerified': True, 'ownerDecisionVerified': True, **expected}


def verify_file_pr_receipts(scenario, root='/state/private'):
    require(scenario['phase'] == 'DONE', 'FILE_PR_RECEIPTS_REQUIRE_DONE')
    root = Path(root)
    with sqlite3.connect((root / 'github-receipts.sqlite').absolute().as_uri() + '?mode=ro', uri=True) as receipts, \
         sqlite3.connect((root / 'approvals.sqlite').absolute().as_uri() + '?mode=ro', uri=True) as core:
        for kind, operation in (('push', 'push_files'), ('pr', 'create_pull_request')):
            ident = scenario[kind + 'RequestId']
            require(bool(re.fullmatch('[0-9a-f-]{36}', ident)), 'FILE_PR_RECEIPT_ID_INVALID')
            row = receipts.execute('SELECT result FROM receipts WHERE request_id=?', (ident,)).fetchone()
            require(row is not None, 'FILE_PR_RECEIPT_MISSING')
            result = json.loads(row[0])
            require(result['requestId'] == ident and result['operation'] == operation and
                    result['repository'] == scenario['repository'], 'FILE_PR_RECEIPT_MISMATCH')
            if kind == 'push':
                require(set(result) == {'requestId','operation','repository','branch','sha','paths'} and
                        result['branch'] == scenario['branch'] and result['sha'] == scenario['commitSha'] and
                        result['paths'] == [scenario['path']], 'FILE_PR_PUSH_RECEIPT_MISMATCH')
                text = 'Fortis Gateway file/PR E2E\nRun: ' + scenario['runId'] + '\nBranch: ' + scenario['branch'] + '\n'
                params = dict(branch=scenario['branch'], expectedHeadSha=scenario['expectedHeadSha'],
                    message='test: add Gateway file/PR E2E evidence', files=[dict(path=scenario['path'], content=text)])
            else:
                pr = result['pullRequest']
                require(set(result) == {'requestId','operation','repository','pullRequest'} and
                        pr['number'] == scenario['pullRequestNumber'] and pr['draft'] is True and
                        pr['state'] == 'open' and pr['merged'] is False and
                        pr['head'] == dict(ref=scenario['branch'], sha=scenario['commitSha']) and
                        pr['base'] == dict(ref='main', sha=scenario['baseSha']), 'FILE_PR_PULL_RECEIPT_MISMATCH')
                params = dict(head=scenario['branch'], base='main', title='[Gateway E2E] ' + scenario['runId'],
                    body='Gateway E2E evidence only. Do not merge. Opening this draft triggers the existing pull_request CI.', draft=True)
            row = core.execute('SELECT state,payload,decision,owner FROM requests WHERE id=?', (ident,)).fetchone()
            require(row is not None and row[0] == 'EXECUTED' and row[2:] == ('approve','owner'), 'FILE_PR_OWNER_EXECUTION_MISSING')
            payload = json.loads(row[1])
            require(payload['service'] == 'github' and payload['operation'] == operation and
                    payload['target'] == scenario['repository'] and payload['params'] == params, 'FILE_PR_CORE_PAYLOAD_MISMATCH')
    return dict(receiptsVerified=True, ownerDecisionsVerified=True, pushRequestId=scenario['pushRequestId'],
                prRequestId=scenario['prRequestId'], commitSha=scenario['commitSha'], pullRequestNumber=scenario['pullRequestNumber'])


def main():
    value = json.load(sys.stdin)
    action = value['action']
    if action == 'provision': result = provision_token(value['token'])
    elif action == 'clone': result = clone_state(
        '/source','/target',github=value.get('github',False),native=value.get('native',False),
        preserve_uncertain_ids=value.get('preserveUncertainIds',[]),
        preserve_claimed_ids=value.get('preserveClaimedIds',[]),
        preserve_approved_ids=value.get('preserveApprovedIds',[]),
        require_exact_approved=value.get('requireExactApproved',False))
    elif action == 'inspect': result = inspect_state(
        '/source',github=value.get('github',False),native=value.get('native',False),
        preserve_uncertain_ids=value.get('preserveUncertainIds',[]),
        require_exact_uncertain=value.get('requireExactUncertain',False),
        preserve_claimed_ids=value.get('preserveClaimedIds',[]),
        require_exact_claimed=value.get('requireExactClaimed',False),
        preserve_approved_ids=value.get('preserveApprovedIds',[]),
        require_exact_approved=value.get('requireExactApproved',False))
    elif action == 'admit': result = admit(value['container'], value['expected'], pilot=value['pilot'])
    elif action == 'receipt': result = verify_receipt(**value['expected'])
    elif action == 'file_pr_receipts': result = verify_file_pr_receipts(value['scenario'])
    else: raise RuntimeError('PILOT_HELPER_ACTION_DENIED')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__': main()
