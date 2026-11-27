"""Durable exact-merge evidence shared by protected Gateway and Registry volumes."""
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import tempfile

from ...core import Denied
from ...workflow.common import MAX_BUNDLE
from . import semantic_contract as sc
from .source_lineage_contract import observation

MOUNT = Path('/run/fortis-registry-source-evidence')
_MAX_HEADER = 32768


def check_directory(root, *, uid, gid, readonly):
    sc.need(root.resolve() == root, 'SOURCE_EVIDENCE_MOUNT_DENIED')
    row = root.lstat()
    mode = b'ro' if readonly else b'rw'
    matches = [fields for line in Path('/proc/self/mountinfo').read_bytes().splitlines()
               if len(fields := line.split(b' - ', 1)[0].split()) > 5
               and fields[4] == os.fsencode(root)]
    sc.need(stat.S_ISDIR(row.st_mode) and row.st_uid == uid and row.st_gid == gid
            and stat.S_IMODE(row.st_mode) == 0o2750 and len(matches) == 1
            and mode in matches[0][5].split(b',')
            and bool(os.statvfs(root).f_flag & os.ST_RDONLY) == readonly,
            'SOURCE_EVIDENCE_MOUNT_DENIED')


def mount_binding(root, *, uid, gid, readonly):
    check_directory(root, uid=uid, gid=gid, readonly=readonly)
    row = root.stat()
    return {'device':row.st_dev, 'inode':row.st_ino}


def evidence_path(root, merge):
    sc.hex_id(merge, 40)
    return root/(merge+'.proof')


def make_header(proposal, observed, body, bundle):
    sc.need(type(body) is str and 0 < len(body.encode()) <= 20000
            and hashlib.sha256(body.encode()).hexdigest() == proposal['bodyDigest']
            and type(bundle) is bytes and 0 < len(bundle) <= MAX_BUNDLE,
            'SOURCE_EVIDENCE_CONTENT_DENIED')
    return {'schemaVersion':1, 'observation':observation(observed, proposal),
            'body':body, 'bundleDigest':hashlib.sha256(bundle).hexdigest()}


def read_evidence(root, merge, *, uid, gid):
    try:
        fd = os.open(evidence_path(root,merge), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            row = os.fstat(stream.fileno())
            sc.need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1
                    and row.st_uid == uid and row.st_gid == gid
                    and stat.S_IMODE(row.st_mode) == 0o640
                    and 0 < row.st_size <= _MAX_HEADER + MAX_BUNDLE,
                    'SOURCE_EVIDENCE_FILE_DENIED')
            raw = stream.readline(_MAX_HEADER+1)
            sc.need(raw.endswith(b'\n') and len(raw) <= _MAX_HEADER, 'SOURCE_EVIDENCE_FILE_DENIED')
            header = sc.loads_strict(raw[:-1])
            sc.fields(header, ('schemaVersion','observation','body','bundleDigest'))
            sc.need(type(header['schemaVersion']) is int and header['schemaVersion'] == 1
                    and sc.canonical(header).encode()+b'\n' == raw, 'SOURCE_EVIDENCE_FILE_DENIED')
            bundle = stream.read(MAX_BUNDLE+1)
            sc.need(0 < len(bundle) <= MAX_BUNDLE and len(raw)+len(bundle) == row.st_size
                    and hashlib.sha256(bundle).hexdigest() == header['bundleDigest'],
                    'SOURCE_EVIDENCE_FILE_DENIED')
            return header,bundle
    except (OSError, ValueError, KeyError, TypeError) as exc:
        if isinstance(exc, Denied):
            raise
        raise Denied('SOURCE_EVIDENCE_UNAVAILABLE') from None


def publish_evidence(root, header, bundle, *, uid, gid):
    path = evidence_path(root, header['observation']['mergeSha'])
    raw = sc.canonical(header).encode()+b'\n'
    sc.need(len(raw)<=_MAX_HEADER,'SOURCE_EVIDENCE_CONTENT_DENIED')
    directory = os.open(root,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(directory,fcntl.LOCK_EX)
        # Cooperating publishers on this protected volume serialize the
        # absence check and atomic rename. Readers only see complete files.
        if not os.path.lexists(path):
            fd, staged = tempfile.mkstemp(prefix='.proof-', dir=root)
            try:
                with os.fdopen(fd,'wb') as stream:
                    os.fchmod(stream.fileno(),0o640)
                    row = os.fstat(stream.fileno())
                    sc.need((row.st_uid,row.st_gid)==(uid,gid),'SOURCE_EVIDENCE_FILE_DENIED')
                    stream.write(raw)
                    stream.write(bundle)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.rename(staged,path)
            finally:
                Path(staged).unlink(missing_ok=True)
        prior, data = read_evidence(root, header['observation']['mergeSha'], uid=uid, gid=gid)
        sc.need(prior == header and data == bundle, 'SOURCE_EVIDENCE_PUBLICATION_CHANGED')
        os.fsync(directory)
    finally:
        os.close(directory)
