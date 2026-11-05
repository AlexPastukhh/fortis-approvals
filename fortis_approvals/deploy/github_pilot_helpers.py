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


def inspect_state(volume, *, uid=10001, gid=10001, github=False):
    files = FILES | ({'github-receipts.sqlite'} if github else set())
    databases = DBS + (('github-receipts.sqlite',) if github else ())
    volume = Path(volume)
    root = volume / 'private'
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid and
            stat.S_IMODE(info.st_mode) == 0o700, 'PILOT_STATE_DIRECTORY_INVALID')
    require({p.name for p in root.iterdir()} == files, 'PILOT_SOURCE_UNKNOWN_FILES_OR_JOURNAL')
    for name in files:
        info = (root / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_gid == gid and
                stat.S_IMODE(info.st_mode) == 0o600, 'PILOT_SOURCE_FILE_INVALID')
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
        require(a.execute("SELECT COUNT(*) FROM requests WHERE state IN ('PENDING','APPROVED','DISPATCHED','UNCERTAIN')").fetchone()[0] == 0,
                'PILOT_REVIEW_HAS_UNFINISHED_REQUESTS')
        summary = {'requests': a.execute('SELECT COUNT(*) FROM requests').fetchone()[0],
            'requestStates': dict(a.execute('SELECT state,COUNT(*) FROM requests GROUP BY state')),
            'events': a.execute('SELECT COUNT(*) FROM events').fetchone()[0],
            'receipts': receipts.execute('SELECT COUNT(*) FROM receipts').fetchone()[0],
            'credentialsActive': active, 'credentialsTotal': o.execute('SELECT COUNT(*) FROM credentials').fetchone()[0]}
        if github: summary['githubReceipts'] = connections['github-receipts.sqlite'].execute('SELECT COUNT(*) FROM receipts').fetchone()[0]
    finally:
        for db in connections.values(): db.close()
    return {'sha256': {name: file_hash(root / name) for name in sorted(files)}, 'summary': summary}


def clone_state(source, target, *, uid=10001, gid=10001, github=False):
    files = FILES | ({'github-receipts.sqlite'} if github else set())
    source, target = Path(source), Path(target)
    require(not source.is_symlink() and not target.is_symlink() and source.is_dir() and target.is_dir(), 'PILOT_VOLUME_ROOT_INVALID')
    require(source.resolve() != target.resolve() and not any(target.iterdir()), 'PILOT_CLONE_TARGET_NOT_EMPTY')
    before = inspect_state(source, uid=uid, gid=gid, github=github)
    private = target / 'private'
    private.mkdir(mode=0o700)
    for name in sorted(files):
        descriptor = os.open(private / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write((source / 'private' / name).read_bytes())
            output.flush(); os.fsync(output.fileno())
        os.chmod(private / name, 0o600)
        os.chown(private / name, uid, gid)
    os.chmod(private, 0o700); os.chown(private, uid, gid)
    require(inspect_state(target, uid=uid, gid=gid, github=github) == before, 'PILOT_CLONE_VERIFICATION_FAILED')
    require(inspect_state(source, uid=uid, gid=gid, github=github) == before, 'PILOT_SOURCE_CHANGED_DURING_CLONE')
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
    require(host['NetworkMode'] == 'bridge' and host['PidsLimit'] == 100 and host['Memory'] == 536870912 and
            host['RestartPolicy'] == {'Name': 'no', 'MaximumRetryCount': 0}, 'PILOT_RESOURCE_OR_NETWORK_MISMATCH')
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
    elif action == 'clone': result = clone_state('/source', '/target', github=value.get('github', False))
    elif action == 'inspect': result = inspect_state('/source', github=value.get('github', False))
    elif action == 'admit': result = admit(value['container'], value['expected'], pilot=value['pilot'])
    elif action == 'receipt': result = verify_receipt(**value['expected'])
    elif action == 'file_pr_receipts': result = verify_file_pr_receipts(value['scenario'])
    else: raise RuntimeError('PILOT_HELPER_ACTION_DENIED')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__': main()
