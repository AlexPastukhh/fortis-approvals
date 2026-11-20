"""Phase 6B.2 independent signed witness for an INERT prepared policy event.

Source-only. No Core integration, machine ingress, owner HTTP route or apply.
The signer secret must be owned by a separate trusted owner process, never
provided by a model, machine request, shared Repo mount or DB metadata.
This file does not grant a new policy and cannot lift a PREPARED barrier.
"""
import hashlib
import hmac
import os
from pathlib import Path
import stat
import uuid

from ..core import Denied, Stale, canonical, loads_strict
from .owner_policy_active_store_phase6b import ProtectedActivePolicyStoreCandidate

_PURPOSE = 'PHASE6B_PREPARED_WITNESS_V1'
_FIELDS = frozenset(('purpose', 'requestId', 'auditHeadHash',
                     'auditSequence', 'revision', 'baselineDigest',
                     'sourceDigest', 'credentialGenerationDigest',
                     'policyVersion'))
_WRAPPER = frozenset(('payload', 'hmacSha256'))
_MAX_BYTES = 8192


def _private_file(path, *, require_existing=True):
    path = Path(path)
    parent = path.parent
    if (not path.is_absolute() or path.name in ('', '.', '..') or
            not parent.is_dir() or parent.is_symlink() or
            Path(os.path.realpath(parent)) != parent or
            str(parent).startswith(('/workspace/repo/', '/workspace/repos/'))):
        raise Denied('PHASE6B2_PROTECTED_WITNESS_PARENT_REQUIRED')
    info = parent.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise Denied('PHASE6B2_PROTECTED_WITNESS_PARENT_PERMISSIONS')
    if require_existing or path.exists() or path.is_symlink():
        try:
            stat_info = path.lstat()
        except FileNotFoundError:
            raise Denied('PHASE6B2_WITNESS_MISSING') from None
        if (not stat.S_ISREG(stat_info.st_mode) or
                stat_info.st_uid != os.geteuid() or stat_info.st_nlink != 1 or
                stat_info.st_mode & 0o077 or stat_info.st_mode & 0o600 != 0o600):
            raise Denied('PHASE6B2_WITNESS_FILE_UNSAFE')
    return path


class OwnerPolicyAuditWitnessCandidate:
    """Owner-injected cryptographic witness, separate from untrusted DB chain."""

    def __init__(self, path, *, store, owner_signing_key):
        if type(store) is not ProtectedActivePolicyStoreCandidate:
            raise Denied('PHASE6B2_EXACT_STORE_REQUIRED')
        if (type(owner_signing_key) is not bytes or
                not 32 <= len(owner_signing_key) <= 128):
            raise Denied('PHASE6B2_TRUSTED_OWNER_KEY_REQUIRED')
        self.path = _private_file(path, require_existing=False)
        if self.path.parent == store.path.parent:
            raise Denied('PHASE6B2_SEPARATE_ANCHOR_PATH_REQUIRED')
        self.store = store
        self._key = owner_signing_key

    def _expected(self, *, request_id, audit_head):
        try:
            if type(request_id) is not str or str(uuid.UUID(request_id)) != request_id:
                raise ValueError('UUID')
        except (TypeError, ValueError, AttributeError):
            raise Denied('PHASE6B2_REQUEST_ID_INVALID') from None
        snap = self.store.snapshot()
        if (snap['gate'] != 'PREPARED' or
                snap['revision'] != 0 or snap['auditSequence'] != 1 or
                snap['pendingRequestId'] != request_id or
                snap['auditHeadHash'] != audit_head or
                snap['canApply'] is not False or
                snap['runtimeIntegration'] != 'NOT_CONNECTED'):
            raise Stale('PHASE6B2_PREPARED_IDENTITY_STALE')
        return {'purpose': _PURPOSE, 'requestId': request_id,
                'auditHeadHash': audit_head, 'auditSequence': snap['auditSequence'],
                'revision': snap['revision'], 'baselineDigest': snap['baselineDigest'],
                'sourceDigest': self.store.source_digest,
                'credentialGenerationDigest': self.store.credential_generation_digest,
                'policyVersion': self.store.policy_version}

    def _mac(self, payload):
        message = ('FORTIS_OWNER_POLICY_WITNESS_V1\n'+canonical(payload)).encode('utf-8')
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def verify(self, *, request_id, audit_head):
        """Verify immutable signature AND exact current protected SQLite snapshot."""
        expected = self._expected(request_id=request_id,audit_head=audit_head)
        _private_file(self.path)
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_uid != os.geteuid() or info.st_mode & 0o077 or
                    info.st_mode & 0o600 != 0o600 or info.st_size > _MAX_BYTES):
                raise Denied('PHASE6B2_WITNESS_FILE_UNSAFE')
            raw = os.read(fd,_MAX_BYTES+1)
        finally:
            os.close(fd)
        if len(raw) > _MAX_BYTES:
            raise Denied('PHASE6B2_WITNESS_TOO_LARGE')
        try:
            wrapper = loads_strict(raw.decode('utf-8'))
            if (type(wrapper) is not dict or set(wrapper) != _WRAPPER or
                    type(wrapper['payload']) is not dict or
                    set(wrapper['payload']) != _FIELDS or
                    type(wrapper['hmacSha256']) is not str or
                    wrapper['payload'] != expected or
                    not hmac.compare_digest(wrapper['hmacSha256'],
                                            self._mac(wrapper['payload'])) or
                    raw != (canonical(wrapper)+'\n').encode('utf-8')):
                raise Denied('PHASE6B2_WITNESS_BINDING_OR_SIGNATURE_INVALID')
        except (UnicodeDecodeError, ValueError, TypeError, KeyError):
            raise Denied('PHASE6B2_WITNESS_BINDING_OR_SIGNATURE_INVALID') from None
        return {'kind':_PURPOSE, 'requestId':request_id,
                'auditHeadHash':audit_head,'signatureVerified':True,
                'databaseMatchesWitness':True, 'canApply':False,
                'activePolicyChanged':False}

    def attest_prepared(self, *, request_id, audit_head):
        """Write-once external witness. Never updates active policy or clears gate."""
        payload=self._expected(request_id=request_id,audit_head=audit_head)
        wrapper={'payload':payload,'hmacSha256':self._mac(payload)}
        raw=(canonical(wrapper)+'\n').encode('utf-8')
        if len(raw)>_MAX_BYTES:
            raise Denied('PHASE6B2_WITNESS_TOO_LARGE')
        _private_file(self.path,require_existing=False)
        try:
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        except FileExistsError:
            return {**self.verify(request_id=request_id,audit_head=audit_head),
                    'alreadyWitnessed':True}
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            # Crash before fsync may leave an incomplete file: fail closed,
            # never erase/replace it or treat it as permission to apply.
            directory_fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            # Do not remove a possibly durable witness after uncertain write.
            raise
        return {**self.verify(request_id=request_id,audit_head=audit_head),
                'alreadyWitnessed':False}
