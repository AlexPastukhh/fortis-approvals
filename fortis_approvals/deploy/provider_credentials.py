"""Owner-only credential rotation helpers. Stdlib, no Docker access; one closed owner-only authentication GET.

The controller supplies this reviewed source over a private pipe to the existing
image. Only metadata/codes leave the helper; previous token bytes are never read.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
from urllib import request
import stat
import sys
import time
import uuid

SERVICES = {'github': '/run/github-token', 'sonarcloud': '/run/r7-sonar-token'}
TERMINAL = frozenset(('EXECUTED', 'REJECTED', 'DENIED', 'EXPIRED', 'STALE', 'REVOKED'))


def require(condition, code):
    if not condition:
        raise RuntimeError('CREDENTIAL_' + code)


def service_name(value):
    require(type(value) is str and value in SERVICES, 'SERVICE_INVALID')
    return value


def validate_token(service, value):
    service_name(service)
    pattern = r'[A-Za-z0-9_]{30,512}' if service == 'github' else r'[!-~]{12,4096}'
    require(type(value) is str and re.fullmatch(pattern, value) is not None, 'FORMAT_INVALID')
    return value.encode('ascii') + b'\n'


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('CREDENTIAL_AUTHENTICATION_FAILED')


def validate_authentication(service, value, *, opener=None):
    """Owner-only preflight inside Gateway, not an additional machine operation."""
    validate_token(service, value)
    url = ('https://api.github.com/user' if service == 'github' else
           'https://sonarcloud.io/api/authentication/validate')
    headers = {'Authorization': 'Bearer ' + value, 'Accept': 'application/json'}
    if service == 'github':
        headers['X-GitHub-Api-Version'] = '2022-11-28'
    try:
        client = opener or request.build_opener(request.ProxyHandler({}),
            request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
        with client.open(request.Request(url, method='GET', headers=headers), timeout=12) as response:
            require(response.status == 200, 'AUTHENTICATION_FAILED')
            raw = response.read(65537)
            require(len(raw) <= 65536, 'AUTHENTICATION_FAILED')
            data = json.loads(raw)
            require(type(data) is dict and (type(data.get('id')) is int and data['id'] > 0
                if service == 'github' else data.get('valid') is True), 'AUTHENTICATION_FAILED')
    except Exception:
        raise RuntimeError('CREDENTIAL_AUTHENTICATION_FAILED') from None
    return {'authenticated': True}


def plan(value):
    service = service_name(value['service'])
    volume = value['tokenVolume']
    require(type(volume) is str and (re.fullmatch(r'fortis-github-pilot-token-[0-9a-f]{32}', volume)
            if service == 'github' else volume == 'fortis-r7-sonar-token'), 'VOLUME_INVALID')
    expected = {value['reviewId']}
    allow_stopped_production = value.get('allowStoppedProduction', False)
    require(type(allow_stopped_production) is bool, 'TARGETS_INVALID')
    require(value['reviewId'] != value['productionId'], 'TARGETS_INVALID')
    if service == 'sonarcloud' and not allow_stopped_production:
        expected.add(value['productionId'])
    require(len(expected) == (1 if service == 'github' or allow_stopped_production else 2), 'TARGETS_INVALID')
    stopped = value.get('stopped', False)
    require(type(stopped) is bool, 'PHASE_INVALID')
    found = set()
    targets = []
    root = '/var/lib/docker/volumes/' + volume + '/_data'
    for container in value['containers']:
        mounts = container['Mounts']
        affected = []
        for mount in mounts:
            source = mount.get('Source', '')
            alias = mount.get('Name') == volume or (source and
                (source == root or source.startswith(root + '/') or root.startswith(source.rstrip('/') + '/')))
            if alias:
                affected.append(mount)
        if not affected:
            continue
        require(all(m.get('RW') is False for m in affected), 'UNEXPECTED_TOKEN_WRITER')
        status = container['State']['Status']
        if status in ('created', 'exited', 'dead') and (container['Id'] not in expected or
                (allow_stopped_production and container['Id'] == value['productionId'])):
            continue  # Retained/retired containers remain stopped; never start them here.
        require(container['Id'] in expected and status == ('exited' if stopped else 'running'),
                'UNEXPECTED_TOKEN_CONSUMER')
        require(len(affected) == 1 and affected[0].get('Type') == 'volume' and
                affected[0].get('Name') == volume and affected[0]['Destination'] == SERVICES[service],
                'TOKEN_MOUNT_INVALID')
        state = [m for m in mounts if m['Destination'] == '/state']
        require(len(state) == 1 and state[0].get('Type') == 'volume' and state[0].get('RW') is True,
                'STATE_MOUNT_INVALID')
        require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', state[0].get('Name', '')) is not None,
                'STATE_VOLUME_INVALID')
        require(container['Id'] not in found, 'DUPLICATE_CONTAINER')
        found.add(container['Id'])
        targets.append({'id': container['Id'], 'stateVolume': state[0]['Name'],
                        'role': 'review' if container['Id'] == value['reviewId'] else 'production'})
    require(found == expected, 'TARGETS_MISSING')
    return {'service': service, 'tokenVolume': volume, 'targets': targets}


def _private(path, *, directory=False, uid=10001, gid=10001):
    info = path.lstat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) and
            info.st_uid == uid and info.st_gid == gid and
            stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600), 'FILE_INSECURE')
    return info


def _generation(info):
    return hashlib.sha256(json.dumps([info.st_dev, info.st_ino, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns]).encode('ascii')).hexdigest()


def token_status(root, *, uid=10001, gid=10001):
    root = Path(root)
    _private(root, directory=True, uid=uid, gid=gid)
    info = _private(root / 'token', uid=uid, gid=gid)
    return {'generation': _generation(info)}


def replace_token(root, service, value, expected, *, uid=10001, gid=10001):
    raw = validate_token(service, value)
    require(type(expected) is str and re.fullmatch(r'[0-9a-f]{64}', expected) is not None, 'GENERATION_INVALID')
    root = Path(root)
    require(token_status(root, uid=uid, gid=gid)['generation'] == expected, 'TOKEN_CHANGED')
    temporary = root / ('.rotation-' + uuid.uuid4().hex)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), uid, gid)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        require(token_status(root, uid=uid, gid=gid)['generation'] == expected, 'TOKEN_CHANGED')
        os.replace(temporary, root / 'token')
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    return {'status': 'REPLACED', **token_status(root, uid=uid, gid=gid)}


def idle_state(root, service, *, uid=10001, gid=10001):
    """Read-only Core check before stop and again after all affected runtimes stop."""
    service_name(service)
    root = Path(root)
    _private(root, directory=True, uid=uid, gid=gid)
    marker = root / '.fortis-r7-unified-v1'
    _private(marker, uid=uid, gid=gid)
    require(marker.read_bytes() == b'fortis-r7-unified-v1\n', 'STATE_MARKER_INVALID')
    path = root / 'approvals.sqlite'
    _private(path, uid=uid, gid=gid)
    counts = {}
    with sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True) as db:
        db.execute('PRAGMA query_only=ON')
        for state, payload, expires in db.execute('SELECT state,payload,expires_at FROM requests'):
            # Drain the whole runtime before restart, including local worker jobs.
            # Core cannot approve/execute an expired PENDING/APPROVED intent.
            require(type(json.loads(payload)) is dict, 'STATE_PAYLOAD_INVALID')
            expired = state in ('PENDING', 'APPROVED') and expires <= int(time.time())
            if state not in TERMINAL and not expired:
                counts[state] = counts.get(state, 0) + 1
    return {'idle': not counts, 'blockers': counts}


def main():
    try:
        value = json.load(sys.stdin)
        action = value['action']
        if action == 'plan':
            result = plan(value)
        elif action == 'validate':
            result = validate_authentication(value['service'], value['value'])
        elif action == 'status':
            result = token_status('/rotation-token')
        elif action == 'replace':
            result = replace_token('/rotation-token', value['service'], value['value'], value['expectedGeneration'])
        elif action == 'idle':
            result = idle_state('/rotation-state/private', value['service'])
        else:
            raise RuntimeError('CREDENTIAL_ACTION_INVALID')
        print(json.dumps(result, separators=(',', ':')))
    except Exception as exc:
        code = str(exc)
        if not re.fullmatch(r'CREDENTIAL_[A-Z_]+', code):
            code = 'CREDENTIAL_HELPER_FAILED'
        print(json.dumps({'error': code}), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
