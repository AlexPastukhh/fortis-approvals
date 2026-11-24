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


_LOCAL_POLICY_TABLES = {
    'owner_local_policy_meta': ('id','schema_version','revision','gate'),
    'owner_local_denials': ('actor','service','operation','target','decision'),
    'owner_local_policy_events': ('request_id','at','owner','change','expected_revision','applied_revision'),
}


_POLICY_V2_TABLES = {
    'owner_local_policy_v2_meta': ('id','revision','authority','legacy_digest'),
    'owner_local_policy_v2_rules': ('coordinate','policy'),
    'owner_local_policy_v2_events': ('revision','request_id','at','owner','change'),
}

_POLICY_V2_EPOCH_TABLE = 'owner_local_policy_v2_authority_epochs'
_POLICY_V2_EPOCH_COLUMNS = ('id','through_revision','old_authority',
                            'new_authority','old_choices')


def _policy_json(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))


def _read_approval_spend_schema(db, code):
    # Operator-side independent check: the same one-use uniqueness required
    # by the installed Gateway must survive protected backup/restore.
    columns=tuple((row[1],row[2],row[3],row[5]) for row in
                  db.execute('PRAGMA table_info(owner_read_approval_spent)'))
    primary_keys=tuple((row[2],row[3]) for row in
                       db.execute('PRAGMA index_list(owner_read_approval_spent)')
                       if row[3]=='pk')
    require(columns==(('request_id','TEXT',0,1),
                      ('actor','TEXT',1,0),('used_at','INTEGER',1,0)) and
            primary_keys==((1,'pk'),),code)


def _legacy_local_policy_receipt(db):
    # V1 receipt shape and digest remain exactly backward compatible.
    for table, columns in _LOCAL_POLICY_TABLES.items():
        require(tuple(row[1] for row in db.execute('PRAGMA table_info('+table+')')) == columns,
                'PILOT_LOCAL_POLICY_SCHEMA_INVALID')
    meta = db.execute('SELECT * FROM owner_local_policy_meta').fetchall()
    require(len(meta)==1 and meta[0][:2]==(1,1) and
            type(meta[0][2]) is int and meta[0][2]>=0 and meta[0][3]=='READY',
            'PILOT_LOCAL_POLICY_NOT_READY')
    revision = meta[0][2]
    denials = db.execute('SELECT * FROM owner_local_denials ORDER BY actor,service,operation,target').fetchall()
    events = db.execute('SELECT * FROM owner_local_policy_events ORDER BY applied_revision').fetchall()
    require(len(denials)==len(events)==revision, 'PILOT_LOCAL_POLICY_AUDIT_MISMATCH')
    actual = set()
    for actor,service,operation,target,decision in denials:
        require(all(type(x) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',x)
                    for x in (actor,service,operation,target)) and decision=='DENY'
                and (service,operation)==('sonarcloud','accept_issue'),
                'PILOT_LOCAL_POLICY_SCOPE_INVALID')
        actual.add((actor,service,operation,target))
    recorded = set()
    for index,(ident,at,owner,raw,prior,applied) in enumerate(events):
        try:
            change=json.loads(raw)
            coord=tuple(change[k] for k in ('actor','provider','operation','target'))
            valid=(str(uuid.UUID(ident))==ident and type(at) is int and at>=0 and
                   type(owner) is str and bool(owner) and prior==index and applied==index+1 and
                   change['requestId']==ident and change['expectedRevision']==prior and
                   change['newPolicy']=='DENY' and change['purpose']=='OWNER_LOCAL_EXACT_DENY_APPLY_V1' and
                   coord in actual and coord not in recorded)
        except (ValueError,TypeError,KeyError,AttributeError):
            valid=False
        require(valid,'PILOT_LOCAL_POLICY_AUDIT_MISMATCH')
        recorded.add(coord)
    require(actual==recorded,'PILOT_LOCAL_POLICY_AUDIT_MISMATCH')
    digest=hashlib.sha256(json.dumps([meta,denials,events],
        ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    return {'revision':revision,'sha256':digest}


def _local_policy_receipt(db):
    # Standalone state helper: no provider, runtime or credential imports.
    names = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE name GLOB 'owner_local_*'")}
    if not names:
        return None
    v1, v2 = set(_LOCAL_POLICY_TABLES), set(_POLICY_V2_TABLES)
    require(names in (v1,v2,v1|v2,v2|{_POLICY_V2_EPOCH_TABLE},
                       v1|v2|{_POLICY_V2_EPOCH_TABLE}),
            'PILOT_LOCAL_POLICY_SCHEMA_INVALID')
    legacy = _legacy_local_policy_receipt(db) if v1 <= names else None
    if not v2 <= names:
        return legacy
    for table,columns in _POLICY_V2_TABLES.items():
        require(tuple(row[1] for row in db.execute('PRAGMA table_info('+table+')'))==columns,
                'PILOT_LOCAL_POLICY_SCHEMA_INVALID')
    meta = db.execute('SELECT * FROM owner_local_policy_v2_meta').fetchall()
    require(len(meta)==1 and meta[0][0]==1 and type(meta[0][1]) is int and
            meta[0][1]>=0 and type(meta[0][2]) is str and
            re.fullmatch(r'[a-f0-9]{64}',meta[0][2]) is not None and
            meta[0][3]==(legacy['sha256'] if legacy else 'NONE'),
            'PILOT_LOCAL_POLICY_V2_BINDING_INVALID')
    revision,authority = meta[0][1:3]
    epochs=[]
    if _POLICY_V2_EPOCH_TABLE in names:
        require(tuple(row[1] for row in db.execute(
                'PRAGMA table_info('+_POLICY_V2_EPOCH_TABLE+')')) ==
                _POLICY_V2_EPOCH_COLUMNS, 'PILOT_LOCAL_POLICY_SCHEMA_INVALID')
        epochs=db.execute('SELECT * FROM '+_POLICY_V2_EPOCH_TABLE+
                          ' ORDER BY id').fetchall()
    old_end=-1
    next_auth=None
    for idx,(id,through,prior,current,choices) in enumerate(epochs,1):
        require(id==idx and type(through) is int and old_end<=through<=revision
                and all(type(x) is str and re.fullmatch(r'[0-9a-f]{64}',x)
                        for x in (prior,current))
                and (next_auth is None or prior==next_auth),
                'PILOT_LOCAL_POLICY_V2_EPOCH_INVALID')
        try: parsed=json.loads(choices)
        except (ValueError,TypeError): parsed=None
        require(type(parsed) is list and bool(parsed) and choices==_policy_json(parsed),
                'PILOT_LOCAL_POLICY_V2_EPOCH_INVALID')
        old_end=through
        next_auth=current
    require(next_auth is None or next_auth==authority,
            'PILOT_LOCAL_POLICY_V2_EPOCH_INVALID')
    rules = db.execute('SELECT * FROM owner_local_policy_v2_rules ORDER BY coordinate').fetchall()
    events = db.execute('SELECT * FROM owner_local_policy_v2_events ORDER BY revision').fetchall()
    require(len(events)==revision,'PILOT_LOCAL_POLICY_V2_AUDIT_MISMATCH')
    def coordinate(value):
        require(type(value) is list and len(value) in (3,4) and all(
            type(x) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',x)
            for x in value),'PILOT_LOCAL_POLICY_V2_COORDINATE_INVALID')
        return _policy_json(value)
    actual = {}
    for raw,policy in rules:
        key=coordinate(json.loads(raw))
        require(raw==key and policy in ('DENY','ASK','ALLOW') and key not in actual,
                'PILOT_LOCAL_POLICY_V2_RULE_INVALID')
        actual[key]=policy
    replay = {}
    seen_ids = set()
    fields = {'actor','provider','operation','scope','target','expectedPolicy',
              'desiredPolicy','expectedRevision','expectedPolicyVersion','reasonCode',
              'purpose','requestId','authorityDigest','sourceDigest',
              'credentialGenerationDigest','expiresAt'}
    for index,(seq,ident,at,owner,raw) in enumerate(events,1):
        try:
            change=json.loads(raw)
            parts=[change[k] for k in ('actor','provider','operation')]
            if change['scope']=='exact':
                parts.append(change['target'])
            elif change['scope']!='actor' or change['target'] is not None:
                raise ValueError('scope')
            key=coordinate(parts)
            valid=(type(change) is dict and set(change)==fields and raw==_policy_json(change)
                   and seq==index and str(uuid.UUID(ident))==ident and ident not in seen_ids
                   and type(at) is int and at>=0 and type(owner) is str and bool(owner)
                   and change['purpose']=='OWNER_UNIFIED_POLICY_APPLY_V2'
                   and change['requestId']==ident and type(change['expectedRevision']) is int
                   and change['expectedRevision']==index-1 and change['authorityDigest']==next(
                       (era[2] for era in epochs if index<=era[1]),
                       authority)
                   and type(change['expectedPolicyVersion']) is str
                   and change['expectedPolicyVersion'].endswith('|owner-policy-v2:'+str(index-1))
                   and all(type(change[k]) is str and re.fullmatch(r'[a-f0-9]{64}',change[k])
                           for k in ('sourceDigest','credentialGenerationDigest'))
                   and type(change['reasonCode']) is str and re.fullmatch(r'[A-Z][A-Z0-9_]{1,79}',change['reasonCode'])
                   and type(change['expiresAt']) is int and at < change['expiresAt']
                   and change['expectedPolicy'] in ('DENY','ASK','ALLOW')
                   and change['desiredPolicy'] in ('DENY','ASK','ALLOW')
                   and change['expectedPolicy']!=change['desiredPolicy']
                   and (key not in replay or replay[key]==change['expectedPolicy']))
        except (ValueError,TypeError,KeyError,AttributeError):
            valid=False
        require(valid,'PILOT_LOCAL_POLICY_V2_AUDIT_MISMATCH')
        replay[key]=change['desiredPolicy']
        seen_ids.add(ident)
    require(actual==replay,'PILOT_LOCAL_POLICY_V2_AUDIT_MISMATCH')
    # Full live authority/first-event old policy replay is checked by the
    # installed R7 Core. This independent receipt binds all SQL rows.
    sha=hashlib.sha256(_policy_json(
        [legacy,meta,rules,events]+([epochs] if epochs else [])).encode()).hexdigest()
    return {'revision':revision,'sha256':sha,'schemaVersion':2,'legacy':legacy}


REGISTRY_STATE_DIR = 'registry-functional-v1'
_REGISTRY_FILES = {'capture.json','collector.json','capture.sqlite','collector.sqlite'}
_REGISTRY_DIRS = {'git-initialize','git-initialize/home','git-initialize/empty-hooks'}
_BARE_DIRS = {'objects','objects/info','objects/pack','refs','refs/heads','refs/tags'}
_BARE_CONFIG = b'[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n'


def registry_tree(root, *, uid, gid):
    """Private, inactive Collector evidence + bounded fixed Git object caches.

    No arbitrary walk of a user-selected path. Exclude credentials, hooks,
    alternates, replacements, temp files, links and unknown journals. Compact
    tree digest avoids thousands of object entries in Windows release records.
    Actual journal chains/pins are checked by the installed Gateway on startup.
    """
    base = root / REGISTRY_STATE_DIR
    if not base.exists() and not base.is_symlink():
        return None
    rows=[];total=0
    required = {('',True), *((x,False) for x in _REGISTRY_FILES),
                *((x,True) for x in _REGISTRY_DIRS),
                ('git-initialize/empty.config',False)}
    for repo in ('source.git','validator.git'):
        required |= {(repo,True),(repo+'/HEAD',False),(repo+'/config',False)}
        required |= {(repo+'/'+d,True) for d in _BARE_DIRS}

    def allowed(name, directory):
        if (name,directory) in required:
            return True
        repo,sep,rel=name.partition('/')
        if not sep or repo not in ('source.git','validator.git'):
            return False
        if directory:
            return re.fullmatch(r'objects/[0-9a-f]{2}',rel) is not None
        return (rel in ('refs/heads/verified-main','packed-refs','objects/info/packs')
                or re.fullmatch(r'objects/[0-9a-f]{2}/[0-9a-f]{38}',rel) is not None
                or re.fullmatch(r'objects/pack/pack-[0-9a-f]{40}\.(pack|idx|rev)',rel) is not None)

    def walk(path,name):
        nonlocal total
        info=path.lstat()
        directory=stat.S_ISDIR(info.st_mode)
        mode=stat.S_IMODE(info.st_mode)
        require(info.st_uid==uid and info.st_gid==gid and allowed(name,directory)
                and (directory and mode in (0o700,0o755) or
                     stat.S_ISREG(info.st_mode) and info.st_nlink==1
                     and mode in (0o400,0o444,0o600,0o644)),
                'PILOT_REGISTRY_COLLECTOR_TREE_INVALID')
        if name=='' or name in ('source.git','validator.git') or name in _REGISTRY_DIRS:
            require(directory and mode==0o700,'PILOT_REGISTRY_COLLECTOR_PRIVATE_ROOT')
        if name in _REGISTRY_FILES or name=='git-initialize/empty.config':
            require(not directory and mode==0o600,'PILOT_REGISTRY_COLLECTOR_PRIVATE_FILE')
        require(len(rows)<8192,'PILOT_REGISTRY_COLLECTOR_TREE_LIMIT')
        if directory:
            rows.append((name,mode,None,0))
            for item in sorted(path.iterdir(),key=lambda x:x.name):
                walk(item,name+'/'+item.name if name else item.name)
        else:
            total+=info.st_size
            require(info.st_size<=268435456 and total<=536870912,
                    'PILOT_REGISTRY_COLLECTOR_BYTES_LIMIT')
            if name.endswith('/config'):
                require(info.st_size==len(_BARE_CONFIG) and path.read_bytes()==_BARE_CONFIG,
                        'PILOT_REGISTRY_COLLECTOR_GIT_CONFIG')
            if name.endswith('/HEAD'):
                require(info.st_size<=64 and path.read_bytes() in (
                    b'ref: refs/heads/master\n',b'ref: refs/heads/main\n'),
                    'PILOT_REGISTRY_COLLECTOR_GIT_HEAD')
            if name=='git-initialize/empty.config':
                require(info.st_size==0,'PILOT_REGISTRY_COLLECTOR_GIT_CONFIG')
            if name in ('capture.json','collector.json'):
                require(0<info.st_size<=1024,'PILOT_REGISTRY_COLLECTOR_PIN')
            hasher=hashlib.sha256()
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as stream:
                opened=os.fstat(stream.fileno())
                require((opened.st_dev,opened.st_ino,opened.st_size)==
                        (info.st_dev,info.st_ino,info.st_size),
                        'PILOT_REGISTRY_COLLECTOR_FILE_CHANGED')
                while chunk:=stream.read(1048576):hasher.update(chunk)
                require(os.fstat(stream.fileno()).st_size==info.st_size,
                        'PILOT_REGISTRY_COLLECTOR_FILE_CHANGED')
            rows.append((name,mode,hasher.hexdigest(),info.st_size))
    walk(base,'')
    require(required <= {(name,sha is None) for name,_,sha,_ in rows},
            'PILOT_REGISTRY_COLLECTOR_TREE_INCOMPLETE')
    return rows


def registry_tree_receipt(rows):
    return {'sha256':hashlib.sha256(_policy_json(rows).encode()).hexdigest(),
            'entries':len(rows),'bytes':sum(r[3] for r in rows)}


def clone_registry_tree(source,target,rows,*,uid,gid):
    # Source writer is stopped by the protected controller. Do not copy
    # through arbitrary links or overwrite a partial target.
    import shutil
    for name,mode,sha,size in rows:
        src=source / REGISTRY_STATE_DIR / name
        dst=target / REGISTRY_STATE_DIR / name
        if sha is None:
            dst.mkdir(mode=0o700)
            # The clone helper has CHOWN and DAC_OVERRIDE, but chmod still
            # requires ownership. Set the mode before transferring ownership.
            os.chmod(dst,mode)
            os.chown(dst,uid,gid)
        else:
            fd=os.open(dst,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            inp=os.open(src,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'wb') as out, os.fdopen(inp,'rb') as stream:
                shutil.copyfileobj(stream,out,length=1048576)
                out.flush()
                os.fchmod(out.fileno(),mode)
                os.fchown(out.fileno(),uid,gid)
                os.fsync(out.fileno())
    require(registry_tree(target,uid=uid,gid=gid)==rows
            and registry_tree(source,uid=uid,gid=gid)==rows,
            'PILOT_REGISTRY_COLLECTOR_CLONE_MISMATCH')


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
    collector = registry_tree(root,uid=uid,gid=gid) if native else None
    require({p.name for p in root.iterdir()} == files | ({'native-git'} if native else set()) |
            ({REGISTRY_STATE_DIR} if collector is not None else set()),
            'PILOT_SOURCE_UNKNOWN_FILES_OR_JOURNAL')
    if native: files |= native_files(root, uid=uid, gid=gid)
    if collector is not None:
        databases += tuple(REGISTRY_STATE_DIR+'/'+n for n in ('capture.sqlite','collector.sqlite'))
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
        if collector is not None:
            for name in ('capture.sqlite','collector.sqlite'):
                check=connections[REGISTRY_STATE_DIR+'/'+name]
                require(check.execute('PRAGMA user_version').fetchone()==(1,),
                        'PILOT_REGISTRY_COLLECTOR_SCHEMA')
            summary['registryCollector']=registry_tree_receipt(collector)
        local_policy = _local_policy_receipt(a)
        if local_policy is not None:
            summary['localPolicy'] = local_policy
        # One-use ASK receipt consumption is security state, never ambient
        # UNCERTAIN growth. Its digest is bound to the full source snapshot
        # and must be byte-identical when the protected state is cloned.
        spent_names={x[0] for x in a.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='owner_read_approval_spent'")}
        if spent_names:
            require(spent_names == {'owner_read_approval_spent'},
                    'PILOT_READ_APPROVAL_SCHEMA_INVALID')
            _read_approval_spend_schema(a,'PILOT_READ_APPROVAL_SCHEMA_INVALID')
            spent=list(a.execute('SELECT request_id,actor,used_at '
                                  'FROM owner_read_approval_spent ORDER BY request_id'))
            require(len(spent)<=100000 and all(
                    type(ident) is str and type(actor) is str and actor and
                    type(at) is int and at>0 and
                    str(uuid.UUID(ident))==ident
                    for ident,actor,at in spent),
                    'PILOT_READ_APPROVAL_RECEIPT_INVALID')
            for ident,actor,at in spent:
                request=a.execute('SELECT payload,actor,state FROM requests WHERE id=?',
                                  (ident,)).fetchone()
                require(request is not None and request[1]==actor and
                        request[2]=='EXECUTED' and
                        json.loads(request[0]).get('service')=='read-authorization',
                        'PILOT_READ_APPROVAL_ORPHAN_RECEIPT')
            summary['readApprovalSpendReceipt']={
                'count':len(spent),
                'sha256':hashlib.sha256(_policy_json(spent).encode()).hexdigest()}
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
    collector=registry_tree(source/'private',uid=uid,gid=gid) if native else None
    if collector is not None:
        require(registry_tree_receipt(collector)==before['summary'].get('registryCollector'),
                'PILOT_REGISTRY_COLLECTOR_SOURCE_CHANGED')
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
    if collector is not None:
        clone_registry_tree(source/'private',private,collector,uid=uid,gid=gid)
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




# Manual, owner-opted monotone Core growth. This is NOT a wildcard for
# historical rows or other receipts: only brand-new, fully audited UNCERTAIN
# requests can extend the source snapshot. Every old SQL row is sealed by
# prefix digest; other state files must remain byte-identical.
def _core_growth_witness(volume):
    root=Path(volume)/'private'
    path=root/'approvals.sqlite'
    db=sqlite3.connect(path.absolute().as_uri()+'?mode=ro',uri=True)
    try:
        expected={
            'requests':('id','fingerprint','actor','payload','snapshot','state',
                        'policy_version','created_at','expires_at','decision',
                        'owner','result','failure'),
            'events':('seq','request_id','at','state','detail')}
        # Other Core tables/schema changes cannot be normalized as growth.
        names={x[0] for x in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        local_policy = _local_policy_receipt(db)
        extra = (names & (set(_LOCAL_POLICY_TABLES)|set(_POLICY_V2_TABLES)|
                            {_POLICY_V2_EPOCH_TABLE})
                 if local_policy is not None else set())
        # The guarded V3 native READ-ASK receipt adds one strictly
        # bounded, append-only spent-ID table to Core state.
        if 'owner_read_approval_spent' in names:
            _read_approval_spend_schema(db,'PILOT_GROWTH_CORE_SCHEMA_CHANGED')
            extra.add('owner_read_approval_spent')
        require(names==set(expected)|extra,'PILOT_GROWTH_CORE_SCHEMA_CHANGED')
        for table,names in expected.items():
            current=tuple(row[1] for row in db.execute('PRAGMA table_info('+table+')'))
            require(current==names,'PILOT_GROWTH_CORE_SCHEMA_CHANGED')
        limits={table:db.execute('SELECT COALESCE(MAX(rowid),0) FROM '+table).fetchone()[0]
                for table in expected}
        counts={table:db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
                for table in expected}
        result=_core_prefix_digest(db,limits,counts)
        result['schemaSha256']=_core_schema_digest(db)
        return result
    finally:
        db.close()


def _core_schema_digest(db):
    rows=db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "ORDER BY type,name,tbl_name,sql").fetchall()
    require(rows and all(type(item) in (str,type(None))
                         for row in rows for item in row),
            'PILOT_GROWTH_CORE_SCHEMA_CHANGED')
    return hashlib.sha256(json.dumps(
        rows,ensure_ascii=False,separators=(',',':')).encode('utf-8')).hexdigest()


def _core_prefix_digest(db, limits, counts):
    require(type(limits) is dict and set(limits)=={'requests','events'} and
            type(counts) is dict and set(counts)=={'requests','events'} and
            all(type(value) is int and 0<=value<=10000000
                for value in list(limits.values())+list(counts.values())),
            'PILOT_GROWTH_WITNESS_INVALID')
    digest=hashlib.sha256(b'fortis-append-only-core-v1\x00')
    for table in ('requests','events'):
        old_rows=db.execute('SELECT rowid,* FROM '+table+
                            ' WHERE rowid <= ? ORDER BY rowid',
                            (limits[table],)).fetchall()
        require(len(old_rows)==counts[table],'PILOT_GROWTH_CORE_PREFIX_CHANGED')
        for row in old_rows:
            # Strict Core schema: only TEXT, INTEGER and NULL are admitted.
            require(all(type(v) in (int,str,type(None)) for v in row),
                    'PILOT_GROWTH_CORE_ROW_INVALID')
            raw=json.dumps(row,ensure_ascii=False,separators=(',',':')).encode('utf-8')
            digest.update(len(raw).to_bytes(4,'big'))
            digest.update(raw)
    return {'schema':'fortis-core-growth-v1','limits':limits,
            'counts':counts,'prefixSha256':digest.hexdigest()}


def _actual_uncertain_ids(volume):
    db=sqlite3.connect((Path(volume)/'private'/'approvals.sqlite').absolute().as_uri()+
                       '?mode=ro',uri=True)
    try:
        rows=[x[0] for x in db.execute(
            "SELECT id FROM requests WHERE state='UNCERTAIN' ORDER BY id")]
        require(len(rows)<=20,'PILOT_UNCERTAIN_SCOPE_INVALID')
        validate_uncertain_ids(rows)
        return rows
    finally:
        db.close()


def uncertain_growth_snapshot(volume, *, github, native, preserve_claimed_ids,
                              preserve_approved_ids, require_exact_claimed,
                              require_exact_approved, uid=10001, gid=10001):
    require(github is True and native is True,
            'PILOT_GROWTH_REQUIRES_FULL_STATE')
    for _ in range(3):
        ids=_actual_uncertain_ids(volume)
        original=inspect_state(
            volume,uid=uid,gid=gid,github=True,native=True,preserve_uncertain_ids=ids,
            require_exact_uncertain=True,preserve_claimed_ids=preserve_claimed_ids,
            require_exact_claimed=require_exact_claimed,
            preserve_approved_ids=preserve_approved_ids,
            require_exact_approved=require_exact_approved)
        witness=_core_growth_witness(volume)
        if (original==inspect_state(
                volume,uid=uid,gid=gid,github=True,native=True,preserve_uncertain_ids=ids,
                require_exact_uncertain=True,preserve_claimed_ids=preserve_claimed_ids,
                require_exact_claimed=require_exact_claimed,
                preserve_approved_ids=preserve_approved_ids,
                require_exact_approved=require_exact_approved) and
                witness==_core_growth_witness(volume)):
            require(original['summary']['requests']==witness['counts']['requests']
                    and original['summary']['events']==witness['counts']['events'],
                    'PILOT_GROWTH_SNAPSHOT_INCONSISTENT')
            return {'receipt':original,'witness':witness,'uncertainIds':ids}
    raise RuntimeError('PILOT_GROWTH_SOURCE_BUSY')


def review_uncertain_growth(volume, *, original, witness, github, native,
                            preserve_claimed_ids, preserve_approved_ids,
                            require_exact_claimed, require_exact_approved, uid=10001, gid=10001):
    require(github is True and native is True and type(original) is dict and
            set(original)=={'sha256','summary'} and type(witness) is dict and
            set(witness)=={'schema','limits','counts','prefixSha256','schemaSha256'} and
            witness['schema']=='fortis-core-growth-v1',
            'PILOT_GROWTH_RECORD_INVALID')
    require(all(type(witness[name]) is str and
                re.fullmatch('[0-9a-f]{64}',witness[name])
                for name in ('prefixSha256','schemaSha256')),
            'PILOT_GROWTH_WITNESS_INVALID')
    ids=_actual_uncertain_ids(volume)
    old=validate_uncertain_ids(original['summary'].get('uncertainRequestIds'))
    added=set(ids)-old
    require(old <= set(ids) and len(added)<=20 and len(ids)<=20,
            'PILOT_GROWTH_UNCERTAIN_REMOVED_OR_OVERFLOW')
    if not added:
        current=inspect_state(volume,uid=uid,gid=gid,github=True,native=True,preserve_uncertain_ids=ids,
                              require_exact_uncertain=True,preserve_claimed_ids=preserve_claimed_ids,
                              require_exact_claimed=require_exact_claimed,preserve_approved_ids=preserve_approved_ids,
                              require_exact_approved=require_exact_approved)
        require(current==original,'PILOT_GROWTH_OTHER_STATE_CHANGED')
        return {'receipt':current,'uncertainIds':ids,'addedCount':0}
    with sqlite3.connect((Path(volume)/'private'/'approvals.sqlite').absolute().as_uri()+
                         '?mode=ro',uri=True) as db:
        expected=_core_prefix_digest(db,witness['limits'],witness['counts'])
        require(expected['prefixSha256']==witness['prefixSha256'] and
                expected['counts']==witness['counts'] and
                expected['limits']==witness['limits'],
                'PILOT_GROWTH_CORE_PREFIX_CHANGED')
        require(_core_schema_digest(db)==witness['schemaSha256'],
                'PILOT_GROWTH_CORE_SCHEMA_CHANGED')
        added_requests=list(db.execute(
            'SELECT id,state FROM requests WHERE rowid > ? ORDER BY rowid',
            (witness['limits']['requests'],)))
        require(len(added_requests)==len(added) and
                {row[0] for row in added_requests}==added and
                all(row[1]=='UNCERTAIN' for row in added_requests),
                'PILOT_GROWTH_NEW_REQUEST_NOT_UNCERTAIN')
        added_events=list(db.execute(
            'SELECT request_id,state FROM events WHERE rowid > ? ORDER BY rowid',
            (witness['limits']['events'],)))
        require(len(added_events)>=len(added) and
                {row[0] for row in added_events}==added and
                all(row[1] in ('PENDING','APPROVED','DISPATCHED','UNCERTAIN')
                    for row in added_events),
                'PILOT_GROWTH_NEW_AUDIT_INVALID')
        for ident in added:
            last=[s for request_id,s in added_events if request_id==ident]
            require(last and last[-1]=='UNCERTAIN',
                    'PILOT_GROWTH_NEW_AUDIT_INVALID')
    current=inspect_state(
        volume,uid=uid,gid=gid,github=True,native=True,preserve_uncertain_ids=ids,
        require_exact_uncertain=True,preserve_claimed_ids=preserve_claimed_ids,
        require_exact_claimed=require_exact_claimed,
        preserve_approved_ids=preserve_approved_ids,
        require_exact_approved=require_exact_approved)
    before_hashes=original['sha256']
    after_hashes=current['sha256']
    require(type(before_hashes) is dict and
            set(after_hashes)==set(before_hashes) and
            all(after_hashes[k]==v for k,v in before_hashes.items()
                if k!='approvals.sqlite') and
            after_hashes['approvals.sqlite']!=before_hashes['approvals.sqlite'],
            'PILOT_GROWTH_OTHER_STATE_CHANGED')
    before=original['summary']
    after=current['summary']
    permitted_changes={'requests','events','uncertainRequestIds','requestStates'}
    require(set(before)==set(after) and
            all(after[k]==v for k,v in before.items()
                if k not in permitted_changes) and
            after['requests']==before['requests']+len(added) and
            after['events']==before['events']+len(added_events) and
            after['uncertainRequestIds']==ids,'PILOT_GROWTH_SUMMARY_CHANGED')
    states=dict(before['requestStates'])
    states['UNCERTAIN']=states.get('UNCERTAIN',0)+len(added)
    require(after['requestStates']==states,'PILOT_GROWTH_OTHER_STATE_CHANGED')
    # Re-validate the old immutable SQL prefix plus the complete current
    # receipt: this must not silently admit a concurrent second insertion.
    with sqlite3.connect((Path(volume)/'private'/'approvals.sqlite').absolute().as_uri()+
                         '?mode=ro',uri=True) as db:
        repeated=_core_prefix_digest(db,witness['limits'],witness['counts'])
        require(repeated['prefixSha256']==witness['prefixSha256'],
                'PILOT_GROWTH_CORE_PREFIX_CHANGED')
        require(_core_schema_digest(db)==witness['schemaSha256'],
                'PILOT_GROWTH_CORE_SCHEMA_CHANGED')
    fresh=inspect_state(
        volume,uid=uid,gid=gid,github=True,native=True,preserve_uncertain_ids=ids,
        require_exact_uncertain=True,preserve_claimed_ids=preserve_claimed_ids,
        require_exact_claimed=require_exact_claimed,
        preserve_approved_ids=preserve_approved_ids,
        require_exact_approved=require_exact_approved)
    require(fresh==current,'PILOT_GROWTH_SOURCE_BUSY')
    return {'receipt':current,'uncertainIds':ids,'addedCount':len(added)}

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
GATEWAY_OBSERVATORY_NETWORK = 'fortis-observatory-gw-net'


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
    # Three fixed owner-reviewed layouts only: Action Core, Observatory, or both.
    # Never allow a caller-defined network name, arbitrary third attachment,
    # duplicate endpoint ID, or implicit downgrade to legacy bridge.
    names = set(wanted) if type(wanted) is dict else set()
    expected_sets = (
        {GATEWAY_EGRESS_NETWORK, GATEWAY_ACTION_NETWORK},
        {GATEWAY_EGRESS_NETWORK, GATEWAY_OBSERVATORY_NETWORK},
        {GATEWAY_EGRESS_NETWORK, GATEWAY_ACTION_NETWORK,
         GATEWAY_OBSERVATORY_NETWORK},
    )
    require(pilot and names in expected_sets and
            all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v)
                for v in wanted.values()) and
            len(set(wanted.values())) == len(wanted),
            'PILOT_GATEWAY_NETWORK_RECORD_INVALID')
    require(host['NetworkMode'] == GATEWAY_EGRESS_NETWORK,
            'PILOT_RESOURCE_OR_NETWORK_MISMATCH')
    pending = expected.get('allowPendingActionNetwork') is True
    if pending:
        # Return-only escape for a never-started candidate interrupted between
        # docker create and controller-owned network connect. Not live admission.
        # Only a never-started, controller-created candidate may have a
        # *subset* of the reviewed endpoints during ordered attachments.
        require(expected.get('status') == 'created' and type(actual) is dict and
                GATEWAY_EGRESS_NETWORK in actual and
                set(actual) <= names and len(actual) < len(wanted),
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
    # Optional owner-approved publisher machine principal, introduced only by
    # a protected checked Gateway release. Unknown/dynamic/host volumes fail
    # before the container can be admitted. No environment-based opt-in.
    publisher_volume = expected.get('publisherActivationVolume', '')
    require(type(publisher_volume) is str and publisher_volume in
            ('', 'fortis-r7-publisher-activation'), 'PILOT_PUBLISHER_VOLUME_INVALID')
    if publisher_volume:
        require(pilot, 'PILOT_PUBLISHER_REQUIRES_PROTECTED_RELEASE')
        desired.add(('volume', publisher_volume, '/run/r7-publisher-activation', False))
    # A new PowerShell machine identity is only a protected owner release
    # mount. Never admit a caller-supplied host path, arbitrary volume or RW.
    machine_volume = expected.get('machinePowerShellVolume', '')
    require(type(machine_volume) is str and machine_volume in
            ('', 'fortis-r7-machine-powershell'), 'PILOT_MACHINE_POWERSHELL_VOLUME_INVALID')
    if machine_volume:
        require(pilot, 'PILOT_MACHINE_POWERSHELL_REQUIRES_PROTECTED_RELEASE')
        desired.add(('volume', machine_volume, '/run/fortis-machine-powershell', False))
    # E1.3b protected Registry source: two DISTINCT readonly mounts.
    # The activation profile MUST be versioned by the exact owner release
    # nonce. A mutable *shared* profile volume would break old-image rollback:
    # the previously admitted Gateway's immutable nonce/source pin must stay
    # available when a new Gateway release is checked. The AF_UNIX volume is
    # stable across those releases, but never includes Registry SQLite.
    reg_nonce = expected.get('registryReleaseNonce', '')
    reg_profile = expected.get('registryReaderVolume', '')
    reg_socket = expected.get('registrySocketVolume', '')
    require(type(reg_nonce) is str and
            (reg_nonce == '' or bool(re.fullmatch(
                r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
                reg_nonce))) and
            type(reg_profile) is str and type(reg_socket) is str and
            bool(reg_profile) == bool(reg_socket) == bool(reg_nonce) and
            reg_socket in ('', 'fortis-registry-read') and
            reg_profile == (('fortis-r7-registry-reader-' +
                             reg_nonce.replace('-', '')) if reg_nonce else ''),
            'PILOT_REGISTRY_VOLUME_PAIR_DENIED')
    if reg_profile:
        require(pilot, 'PILOT_REGISTRY_REQUIRES_PROTECTED_RELEASE')
        desired.add(('volume', reg_profile, '/run/r7-registry-reader', False))
        desired.add(('volume', reg_socket, '/run/fortis-registry-read', False))
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
    # P4: protected owner record is the only source of a Deployments READ
    # allowlist. An unpinned environment flag, even with a token, is denied.
    cd_repos=expected.get('cdReadRepositories','')
    require(type(cd_repos) is str and (not cd_repos or bool(re.fullmatch(
        r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}(?:,[A-Za-z0-9][A-Za-z0-9_.-]{0,99}){0,9}',cd_repos))) and
        (not cd_repos or len(cd_repos.split(','))==len({
            repo.casefold() for repo in cd_repos.split(',')})),
        'PILOT_CD_READ_CONFIG_INVALID')
    if cd_repos:
        require(pilot and expected.get('nativeWorktree') is True and
                (multi or cd_repos == expected['repository']),
                'PILOT_CD_READ_REQUIRES_NATIVE_SCOPE')
        required['FORTIS_GITHUB_CD_READ_REPOSITORIES']=cd_repos
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
    elif action == 'uncertain_growth_snapshot': result = uncertain_growth_snapshot(
        '/source',github=value.get('github',False),native=value.get('native',False),
        preserve_claimed_ids=value.get('preserveClaimedIds',[]),
        preserve_approved_ids=value.get('preserveApprovedIds',[]),
        require_exact_claimed=value.get('requireExactClaimed',False),
        require_exact_approved=value.get('requireExactApproved',False))
    elif action == 'uncertain_growth_review': result = review_uncertain_growth(
        '/source',original=value['original'],witness=value['witness'],
        github=value.get('github',False),native=value.get('native',False),
        preserve_claimed_ids=value.get('preserveClaimedIds',[]),
        preserve_approved_ids=value.get('preserveApprovedIds',[]),
        require_exact_claimed=value.get('requireExactClaimed',False),
        require_exact_approved=value.get('requireExactApproved',False))
    elif action == 'admit': result = admit(value['container'], value['expected'], pilot=value['pilot'])
    elif action == 'receipt': result = verify_receipt(**value['expected'])
    elif action == 'file_pr_receipts': result = verify_file_pr_receipts(value['scenario'])
    else: raise RuntimeError('PILOT_HELPER_ACTION_DENIED')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__': main()
