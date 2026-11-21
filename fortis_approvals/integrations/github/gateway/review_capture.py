"""Source-only private pre-merge body observation journal.

No machine ingress, grant, owner approval inference or production path.
The owner must provision the private directory and authenticate callers in
future composition. A saved observation is not an attested review cutoff.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid

from ....core import Conflict, Denied, Stale, canonical
from .post_merge_reader import PILOT_REPOSITORY

MAX_ROWS = 1000
MAX_JOURNAL_PAYLOAD_BYTES = 32_000_000
GENESIS = '0' * 64
_SCHEMA = """
CREATE TABLE captures (
    revision INTEGER PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL,
    payload TEXT NOT NULL,
    previous_digest TEXT NOT NULL,
    event_digest TEXT NOT NULL UNIQUE
);
PRAGMA user_version=1;
"""


def _need(ok, code):
    if not ok:
        raise Denied(code)


def _hash(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def _uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except (ValueError, TypeError):
        return False


def _hex(value, width):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(width) + '}', value) is not None


def _private(path, *, directory):
    info = path.stat(follow_symlinks=False)
    _need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
          and info.st_uid == os.geteuid()
          and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
          and (directory or info.st_nlink == 1), 'P5_CAPTURE_STORAGE_PERMISSIONS')


class ReviewCaptureStore:
    """Explicit isolated journal; not an owner approval or authoritative Registry."""

    def __init__(self, path):
        self.path = Path(path)
        _need(self.path.is_absolute() and self.path.parent.resolve() == self.path.parent,
              'P5_CAPTURE_STORAGE_PATH')
        self._check_path()

    @classmethod
    def initialize(cls, path):
        path = Path(path)
        _need(path.is_absolute() and path.parent.resolve() == path.parent,
              'P5_CAPTURE_STORAGE_PATH')
        _private(path.parent, directory=True)
        # Exclusive creation only; never recreate, reset, migrate or overwrite.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        store = cls(path)
        with store._db(initialize=True) as db:
            db.executescript(_SCHEMA)
        return store

    def _check_path(self):
        try:
            _need(self.path.parent.resolve() == self.path.parent, 'P5_CAPTURE_STORAGE_PATH')
            _private(self.path.parent, directory=True)
            _private(self.path, directory=False)
        except OSError:
            raise Denied('P5_CAPTURE_STORAGE_UNAVAILABLE') from None

    @contextmanager
    def _db(self, *, initialize=False):
        self._check_path()
        db = None
        try:
            # Open existing database only. No implicit empty-store fallback.
            db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=5)
            db.execute('PRAGMA synchronous=FULL')
            if not initialize:
                _need(db.execute('PRAGMA user_version').fetchone() == (1,),
                      'P5_CAPTURE_SCHEMA_INVALID')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except sqlite3.Error:
            if db is not None:
                db.rollback()
            raise Denied('P5_CAPTURE_STORAGE_UNAVAILABLE') from None
        finally:
            if db is not None:
                db.close()

    @staticmethod
    def _checked(db):
        _need(db.execute('PRAGMA quick_check').fetchone() == ('ok',),
              'P5_CAPTURE_INTEGRITY_INVALID')
        _need(db.execute('SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM captures').fetchone()[0]
              <= MAX_JOURNAL_PAYLOAD_BYTES, 'P5_CAPTURE_LIMIT')
        rows = db.execute(
            'SELECT revision,operation_id,fingerprint,payload,previous_digest,event_digest '
            'FROM captures ORDER BY revision LIMIT ?', (MAX_ROWS + 1,)).fetchall()
        _need(len(rows) <= MAX_ROWS, 'P5_CAPTURE_LIMIT')
        previous = GENESIS
        for expected, (revision, op, fingerprint, payload, prev, event) in enumerate(rows, 1):
            try:
                value = json.loads(payload)
                _need(type(value) is dict and canonical(value) == payload and
                      _hash(value['request']) == fingerprint and
                      value['request']['operationId'] == op and
                      hashlib.sha256(value['body'].encode('utf-8')).hexdigest() ==
                      value['request']['bodySha256'], 'P5_CAPTURE_INTEGRITY_INVALID')
                request = value['request']
                if request.get('captureKind') == 'body-path-ci-catalog-v1':
                    bundle = value['bundle']
                    _need(value['bundleDigest'] == _hash(bundle) and
                          value['baseSha'] == request['baseSha'] and
                          bundle['pathCi']['pr']['headSha'] == request['headSha'] and
                          bundle['pathCi']['pr']['baseSha'] == request['baseSha'] and
                          bundle['pathCi']['pr']['bodySha256'] == request['bodySha256'] and
                          bundle['pathCi']['number'] == request['number'] and
                          bundle['pathCi']['repository'] == request['repository'] and
                          bundle['catalog']['headSha'] == request['headSha'],
                          'P5_CAPTURE_INTEGRITY_INVALID')
                else:
                    _need('captureKind' not in request and 'bundle' not in value and
                          'bundleDigest' not in value, 'P5_CAPTURE_INTEGRITY_INVALID')
                digest = _hash([revision, op, fingerprint, value, prev])
            except (KeyError, TypeError, ValueError, UnicodeError, AttributeError):
                raise Denied('P5_CAPTURE_INTEGRITY_INVALID') from None
            _need(revision == expected and prev == previous and event == digest,
                  'P5_CAPTURE_INTEGRITY_INVALID')
            previous = event
        return rows, {'revision': len(rows), 'eventDigest': previous}

    @staticmethod
    def _receipt(row):
        revision, op, fingerprint, payload, prev, event = row
        value = json.loads(payload)
        receipt = {'result': 'PRE_MERGE_OBSERVATION_RETAINED',
                'operationId': op, 'revision': revision, 'eventDigest': event,
                'requestDigest': fingerprint, 'repository': value['request']['repository'],
                'number': value['request']['number'], 'headSha': value['request']['headSha'],
                'bodySha256': value['request']['bodySha256'],
                'capturedAt': value['capturedAt'],
                'reviewAttested': False, 'evidenceVerified': False,
                'admissionAllowed': False, 'deploymentAllowed': False}

        if 'bundleDigest' in value:
            receipt.update(result='PRE_MERGE_BUNDLE_RETAINED', bundleDigest=value['bundleDigest'],
                           historicalPolicyVerified=False, requiredPolicySatisfied=False)
        return receipt

    def checkpoint(self, *, expected=None):
        """Compare with a separately retained checkpoint, not an authenticity proof."""
        with self._db() as db:
            _, actual = self._checked(db)
            if expected is not None and expected != actual:
                raise Denied('P5_CAPTURE_CHECKPOINT_MISMATCH')
            return actual

    def operation(self, operation_id):
        _need(_uuid(operation_id), 'P5_CAPTURE_OPERATION_INVALID')
        with self._db() as db:
            rows, _ = self._checked(db)
            return next((self._receipt(row) for row in rows if row[1] == operation_id), None)

    def retained_material(self, operation_id, *, expected_checkpoint):
        """Internal read for later collector, never a machine response.

        A current independently retained checkpoint is mandatory. Matching
        it proves consistency only, not owner authorization or source origin.
        """
        _need(_uuid(operation_id) and type(expected_checkpoint) is dict,
              'P5_CAPTURE_REQUEST_INVALID')
        with self._db() as db:
            rows, actual = self._checked(db)
            _need(expected_checkpoint == actual, 'P5_CAPTURE_CHECKPOINT_MISMATCH')
            row = next((item for item in rows if item[1] == operation_id), None)
            _need(row is not None, 'P5_CAPTURE_NOT_FOUND')
            return json.loads(row[3])

    def capture(self, adapter, *, operation_id, expected_revision, number,
                expected_head_sha, expected_body_sha256):
        """Retain the observed open PR body. No caller-supplied body or review flag."""
        return self._capture(adapter, operation_id=operation_id, expected_revision=expected_revision,
                             number=number, expected_head_sha=expected_head_sha,
                             expected_body_sha256=expected_body_sha256, expected_base_sha=None)

    def capture_bundle(self, adapter, *, operation_id, expected_revision, number,
                       expected_head_sha, expected_base_sha, expected_body_sha256):
        """Retain body, pinned catalog, path/CI observations in one append."""
        _need(_hex(expected_base_sha, 40) and expected_base_sha != expected_head_sha,
              'P5_CAPTURE_REQUEST_INVALID')
        return self._capture(adapter, operation_id=operation_id, expected_revision=expected_revision,
                             number=number, expected_head_sha=expected_head_sha,
                             expected_body_sha256=expected_body_sha256, expected_base_sha=expected_base_sha)

    def _capture(self, adapter, *, operation_id, expected_revision, number,
                 expected_head_sha, expected_body_sha256, expected_base_sha):
        _need(_uuid(operation_id) and type(expected_revision) is int and
              0 <= expected_revision <= MAX_ROWS and type(number) is int and
              0 < number <= 1_000_000 and _hex(expected_head_sha, 40) and
              _hex(expected_body_sha256, 64), 'P5_CAPTURE_REQUEST_INVALID')
        repo = adapter._repo(PILOT_REPOSITORY)
        request = {'operationId': operation_id, 'repository': adapter.owner + '/' + repo,
                   'number': number, 'headSha': expected_head_sha,
                   'bodySha256': expected_body_sha256, 'expectedRevision': expected_revision}
        if expected_base_sha is not None:
            request.update(captureKind='body-path-ci-catalog-v1', baseSha=expected_base_sha)
        fingerprint = _hash(request)

        def replay_or_preflight(db):
            rows, checkpoint = self._checked(db)
            prior = next((row for row in rows if row[1] == operation_id), None)
            if prior is not None:
                if prior[2] != fingerprint:
                    raise Conflict('P5_CAPTURE_OPERATION_CONFLICT')
                return self._receipt(prior), checkpoint
            if checkpoint['revision'] != expected_revision:
                raise Stale('P5_CAPTURE_REVISION_STALE')
            _need(len(rows) < MAX_ROWS, 'P5_CAPTURE_LIMIT')
            return None, checkpoint

        with self._db() as db:
            prior, _ = replay_or_preflight(db)
            if prior is not None:
                return prior
        # No network I/O while holding SQLite's write lock.
        def read():
            value = adapter._release_impact_pr_evidence(repo, number, expected_head_sha)
            _need(value['bodySha256'] == expected_body_sha256 and
                  hashlib.sha256(value['body'].encode('utf-8')).hexdigest() == expected_body_sha256,
                  'P5_CAPTURE_BODY_CHANGED')
            _need(value['headRepository'] == request['repository'] and
                  value['baseRepository'] == request['repository'] and
                  value['number'] == number and value['headSha'] == expected_head_sha,
                  'P5_CAPTURE_SOURCE_MISMATCH')
            return value

        first = read()
        bundle = None
        if expected_base_sha is not None:
            _need(first['baseSha'] == expected_base_sha, 'P5_CAPTURE_BASE_CHANGED')
            from .premerge_bundle import collect_bundle
            bundle = collect_bundle(adapter, number=number, head=expected_head_sha,
                                    base=expected_base_sha, body=first['body'],
                                    body_sha=expected_body_sha256, branch=first['headBranch'])
        if read() != first:
            raise Stale('P5_CAPTURE_OBSERVATION_CHANGED')
        payload = {'request': request, 'body': first['body'],
                   'baseSha': first['baseSha'], 'headBranch': first['headBranch'],
                   'capturedAt': datetime.now(timezone.utc).isoformat()}
        if bundle is not None:
            payload.update(bundle=bundle, bundleDigest=_hash(bundle))
        serialized = canonical(payload)
        with self._db() as db:
            prior, checkpoint = replay_or_preflight(db)
            if prior is not None:
                return prior
            total = db.execute('SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM captures').fetchone()[0]
            _need(total + len(serialized.encode('utf-8')) <= MAX_JOURNAL_PAYLOAD_BYTES,
                  'P5_CAPTURE_LIMIT')
            revision = expected_revision + 1
            prev = checkpoint['eventDigest']
            event = _hash([revision, operation_id, fingerprint, payload, prev])
            row = (revision, operation_id, fingerprint, serialized, prev, event)
            db.execute('INSERT INTO captures VALUES(?,?,?,?,?,?)', row)
            return self._receipt(row)
