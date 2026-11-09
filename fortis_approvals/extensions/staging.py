"""Owner-controlled release gate. No machine/owner HTTP route opens the gate.

A root-owned, read-only activation record lives outside /state/private so it is
not copied into the next business-state snapshot. A new release nonce stages it
again. This prevents automatic startup return from discarding new mutations.
"""
import io
import os
import re
from pathlib import Path
import stat
import uuid

from ..core import Denied, canonical, loads_strict
from ..repo_ingress import RepoIngress
from .model import check

MARKER = '/state/.fortis-release-activation.json'


class ReleaseGate:
    def __init__(self, nonce, digest, *, marker=MARKER):
        check(type(nonce) is str and str(uuid.UUID(nonce)) == nonce, 'RELEASE_NONCE_INVALID')
        check(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'RELEASE_DIGEST_INVALID')
        self.nonce, self.digest, self.marker = nonce, digest, Path(marker)

    def ready(self):
        try:
            fd = os.open(self.marker, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as source:
                info = os.fstat(source.fileno())
                if not (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                        stat.S_IMODE(info.st_mode) == 0o444 and info.st_size <= 512): return False
                value = loads_strict(source.read(513))
            return value == {'schemaVersion': 1, 'nonce': self.nonce, 'configurationDigest': self.digest}
        except (OSError, ValueError, TypeError): return False

    def activate(self):
        check(os.geteuid() == 0, 'RELEASE_OWNER_ROOT_REQUIRED')
        check(self.marker.parent.is_dir() and not self.marker.parent.is_symlink(), 'RELEASE_MARKER_PARENT_INVALID')
        temporary = self.marker.parent / ('.activation-' + uuid.uuid4().hex)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
            with os.fdopen(fd, 'w') as output:
                output.write(canonical({'schemaVersion': 1, 'nonce': self.nonce, 'configurationDigest': self.digest}))
                output.flush(); os.fsync(output.fileno()); os.fchmod(output.fileno(), 0o444)
            os.replace(temporary, self.marker)
        finally:
            if temporary.exists(): temporary.unlink()
        check(self.ready(), 'RELEASE_ACTIVATION_UNCONFIRMED')


class StagedMachine:
    def __init__(self, delegate, base, runtime, gate):
        self.delegate, self.base, self.runtime, self.gate = delegate, base, runtime, gate
        self.broker = base.broker

    def __call__(self, env, start):
        if self.gate.ready(): return self.delegate(env, start)
        try:
            check(self.base._environment(env), 'RELEASE_MACHINE_ROUTE_DENIED')
            method, path = env.get('REQUEST_METHOD'), env.get('PATH_INFO', '')
            if method == 'GET': return self.delegate(env, start)  # actor-owned status or ordinary 404
            credential, actor = self.base._credential(env)
            allowed = path in ('/v1/reads', '/v1/integrations/catalog', '/v1/workspace/capabilities', '/v1/workspace/details')
            if path in ('/v1/integrations/call', '/v1/integrations/result'):
                length = env.get('CONTENT_LENGTH', '')
                check(type(length) is str and length.isdecimal() and not length.startswith('0') and
                      0 < int(length) <= self.base.max_bytes, 'RELEASE_BODY_LIMIT')
                raw = env['wsgi.input'].read(int(length))
                check(len(raw) == int(length), 'RELEASE_BODY_LIMIT')
                copied = dict(env); copied['wsgi.input'] = io.BytesIO(raw)
                body = self.base._body(copied)
                env = dict(env); env['wsgi.input'] = io.BytesIO(raw)
                if path.endswith('/result'):
                    allowed = body.get('reconcile', False) is False
                else:
                    key = (body.get('service'), body.get('operation'))
                    op = self.runtime.operations.get(key)
                    allowed = bool(op and op.kind == 'read' and
                        self.runtime.core._policy(actor, {'service': key[0], 'operation': key[1],
                            'target': body.get('target')}) == 'ALLOW')
            if not allowed: return RepoIngress._reply(start, 403, {'error': 'RELEASE_STAGED_MUTATIONS_BLOCKED'})
            return self.delegate(env, start)
        except Exception:
            return RepoIngress._reply(start, 403, {'error': 'RELEASE_STAGED_DENIED'})


class StagedOwner:
    def __init__(self, delegate, gate):
        self.delegate, self.gate = delegate, gate

    def __call__(self, env, start):
        if not self.gate.ready() and env.get('REQUEST_METHOD') != 'GET':
            return self.delegate._reply(start, 403, {'error': 'RELEASE_STAGED_OWNER_WRITES_BLOCKED'})
        return self.delegate(env, start)
