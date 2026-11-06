"""Gateway-only named credentials, atomic rotation and public readiness.

No machine endpoint provisions secrets. Owner tooling mounts this volume RW;
runtime mounts it RO. A random generation, never a token hash, binds previews.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import uuid

from ..core import Denied, canonical, loads_strict

NAME = re.compile(r'[a-z][a-z0-9-]{0,47}\Z')


def require(value, code):
    if not value:
        raise Denied(code)


def name(value):
    require(type(value) is str and NAME.fullmatch(value), 'CREDENTIAL_NAME_INVALID')
    return value


def value_check(value):
    require(type(value) is str and 1 <= len(value.encode('utf-8')) <= 8192 and
            not any(ord(c) < 32 or ord(c) == 127 for c in value), 'CREDENTIAL_VALUE_INVALID')
    return value


class Secret:
    __slots__ = ('generation', '_value')

    def __init__(self, generation, value):
        self.generation, self._value = generation, value

    def __repr__(self):
        return '<GatewaySecret REDACTED>'

    def reveal(self):
        return self._value


class CredentialVault:
    def __init__(self, root='/run/fortis-secrets', *, uid=10001, gid=10001):
        self.root = Path(root)
        self.uid, self.gid = uid, gid
        require(self.root.is_absolute(), 'CREDENTIAL_ROOT_INVALID')
        require(not any(self.root == p or p in self.root.parents for p in
                        (Path('/workspace/repo'), Path('/workspace/repos'))), 'CREDENTIAL_ROOT_IN_WORKSPACE')

    def _directory(self):
        info = self.root.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid and info.st_gid == self.gid and
                stat.S_IMODE(info.st_mode) == 0o700, 'CREDENTIAL_ROOT_PERMISSIONS')

    def initialize(self):
        """Owner-only CLI: initialize an already mounted, empty volume root."""
        require(os.geteuid() in (0, self.uid), 'CREDENTIAL_PROVISIONING_IDENTITY')
        info = self.root.lstat()
        require(stat.S_ISDIR(info.st_mode), 'CREDENTIAL_ROOT_INVALID')
        try:
            self._directory()
        except Denied:
            require(not any(self.root.iterdir()) and info.st_uid == os.geteuid(), 'CREDENTIAL_ROOT_NOT_EMPTY')
            os.chmod(self.root, 0o700)
            os.chown(self.root, self.uid, self.gid)
        self._directory()

    def get(self, alias):
        name(alias)
        self._directory()
        descriptor = os.open(self.root / (alias + '.json'), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                    info.st_uid == self.uid and info.st_gid == self.gid and
                    stat.S_IMODE(info.st_mode) == 0o600 and 1 <= info.st_size <= 65536,
                    'CREDENTIAL_FILE_PERMISSIONS')
            raw = stream.read(65537)
        try:
            data = loads_strict(raw)
            require(type(data) is dict and set(data) == {'schemaVersion', 'generation', 'value'} and
                    type(data['schemaVersion']) is int and data['schemaVersion'] == 1,
                    'CREDENTIAL_FILE_SCHEMA')
            require(type(data['generation']) is str and
                    str(uuid.UUID(data['generation'])) == data['generation'], 'CREDENTIAL_GENERATION_INVALID')
            value_check(data['value'])
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise Denied('CREDENTIAL_FILE_INVALID') from None
        return Secret(data['generation'], data['value'])

    def readiness(self, alias):
        name(alias)
        try:
            self.get(alias)
        except FileNotFoundError:
            return {'configured': True, 'ready': False, 'status': 'MISSING'}
        except (OSError, Denied):
            return {'configured': True, 'ready': False, 'status': 'INVALID'}
        return {'configured': True, 'ready': True, 'status': 'READY'}

    @contextmanager
    def _lock(self):
        descriptor = os.open(self.root / '.provision.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'a+b') as lock:
            info = os.fstat(lock.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid() and
                    stat.S_IMODE(info.st_mode) == 0o600, 'CREDENTIAL_LOCK_INVALID')
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def provision(self, alias, value, *, expected_generation=None):
        """Create only, or rotate with an explicit generation CAS. Never print value."""
        name(alias); value_check(value); self._directory()
        require(os.geteuid() in (0, self.uid), 'CREDENTIAL_PROVISIONING_IDENTITY')
        with self._lock():
            try:
                current = self.get(alias)
            except FileNotFoundError:
                current = None
            if current is None:
                require(expected_generation is None, 'CREDENTIAL_ROTATION_TARGET_MISSING')
            else:
                require(expected_generation == current.generation, 'CREDENTIAL_EXISTS_OR_GENERATION_CHANGED')
            generation = str(uuid.uuid4())
            temporary = self.root / ('.' + alias + '.' + uuid.uuid4().hex + '.tmp')
            try:
                descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
                    output.write(canonical({'schemaVersion': 1, 'generation': generation, 'value': value}))
                    output.flush(); os.fsync(output.fileno())
                    os.fchmod(output.fileno(), 0o600); os.fchown(output.fileno(), self.uid, self.gid)
                os.replace(temporary, self.root / (alias + '.json'))
                directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                if temporary.exists(): temporary.unlink()
        return {'name': alias, 'generation': generation, 'status': 'PROVISIONED'}
