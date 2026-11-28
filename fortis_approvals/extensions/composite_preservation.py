"""Explicit companion-schema preservation checks on isolated/staged copies.

The protected controller can project the new schema on an isolated copy
and verify the same receipt while preparing the stopped source clone.
"""
from contextlib import closing, contextmanager
import os
import sqlite3
import stat
from pathlib import Path
from tempfile import TemporaryDirectory

from ..core import Denied, canonical
from ..integrations.registry_contracts.semantic_contract import digest, hex_id, need
from ..incidents import IncidentCore
from . import composite_journal as journal
from .transition_authority import _rows_digest

_MAX_PARENTS = 10000
_GROUPS = ('begin_release_group', 'report_release_results')
_PARENT_SQL = ("((json_extract(payload,'$.service')='registry' "
               "AND json_extract(payload,'$.operation') IN (?,?)) OR "
               "(json_extract(payload,'$.service')='release' AND "
               "json_extract(payload,'$.operation')='merge_and_register'))")


def _schema(db):
    return [list(row) for row in db.execute(
        'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name,tbl_name,sql')]


def _core_rows(db):
    return digest({
        'requests': _rows_digest(db.execute('SELECT rowid,* FROM requests ORDER BY rowid')),
        'events': _rows_digest(db.execute('SELECT rowid,* FROM events ORDER BY rowid')),
        'eventsSequence': _rows_digest(db.execute(
            "SELECT name,seq FROM sqlite_sequence WHERE name='events'")),
    })


def _read_transaction(db):
    need(db.in_transaction and db.execute('PRAGMA query_only').fetchone()[0] == 1,
         'COMPOSITE_PRESERVATION_READ_ONLY_REQUIRED')


def legacy_schema_witness(db):
    """Extra exact source pin; not the existing full protected state receipt."""
    _read_transaction(db)
    need(not journal._schema_rows(db), 'COMPOSITE_SCHEMA_ALREADY_PRESENT')
    return {'schemaDigest': digest(_schema(db)), 'coreRowsDigest': _core_rows(db)}


def install_checked(db, *, expected):
    """Add only the reviewed companion schema in caller's write transaction.

    The expected legacy witness must be independently pinned from a verified
    clone. Existing complete source inspection, owner GO and authority epoch
    preservation are separate prerequisites. A mismatch raises; caller must
    roll back the entire transaction, not commit a partial migration.
    """
    journal._write_transaction(db)
    need(type(expected) is dict and set(expected) == {'schemaDigest', 'coreRowsDigest'},
         'COMPOSITE_PRESERVATION_PIN_INVALID')
    for value in expected.values():
        hex_id(value, 64)
    before = _schema(db)
    need(digest(before) == expected['schemaDigest']
         and _core_rows(db) == expected['coreRowsDigest'],
         'COMPOSITE_PRESERVATION_SOURCE_CHANGED')
    # No historical composite requests without their companion records.
    need(not db.execute(
        "SELECT 1 FROM requests WHERE "+_PARENT_SQL+" LIMIT 1", _GROUPS).fetchone(),
         'COMPOSITE_LEGACY_PARENT_PRESENT')
    journal.install_schema(db)
    after = _schema(db)
    original = [row for row in after if row[2] not in journal._TABLES]
    need(original == before and _core_rows(db) == expected['coreRowsDigest'],
         'COMPOSITE_PRESERVATION_PREFIX_CHANGED')
    return {'result': 'COMPOSITE_SCHEMA_ADDED_ONLY',
            'beforeSchemaDigest': expected['schemaDigest'],
            'afterSchemaDigest': digest(after),
            'coreRowsDigest': expected['coreRowsDigest']}


def inspect_companion(db):
    """Full bounded journal replay and parent coverage on a read-only snapshot.

    Local structural/evidence accounting only. No provider lookup, no
    normalization as permitted UNCERTAIN growth, no independent receipt
    authentication. Refuse missing/orphaned instances or events.
    """
    _read_transaction(db)
    journal.check_schema(db)
    expected = [r[0] for r in db.execute(
        "SELECT id FROM requests WHERE "+_PARENT_SQL+" ORDER BY id LIMIT ?",
        (*_GROUPS, _MAX_PARENTS + 1))]
    actual = [r[0] for r in db.execute(
        'SELECT parent_id FROM composite_instances ORDER BY parent_id LIMIT ?',
        (_MAX_PARENTS + 1,))]
    need(len(expected) <= _MAX_PARENTS and expected == actual,
         'COMPOSITE_PRESERVATION_PARENT_COVERAGE')
    need(not db.execute(
        'SELECT 1 FROM composite_step_events e LEFT JOIN composite_instances i '
        'ON i.parent_id=e.parent_id WHERE i.parent_id IS NULL LIMIT 1').fetchone(),
         'COMPOSITE_PRESERVATION_ORPHAN_EVENT')
    counts = {}
    for ident in actual:
        view = journal.inspect(db, ident)
        state = view['parentState']
        need(state in IncidentCore.STATES, 'COMPOSITE_PRESERVATION_PARENT_STATE')
        counts[state] = counts.get(state, 0) + 1
        if state == 'EXECUTED':
            result = {'kind': 'COMPOSITE_CONFIRMED', 'parentId': ident,
                      'receipts': [s['receipt'] for s in view['steps']]}
            raw = db.execute('SELECT result FROM requests WHERE id=?', (ident,)).fetchone()[0]
            need(raw is not None and canonical(result) == raw,
                 'COMPOSITE_PRESERVATION_PARENT_RECEIPT')
    from . import merge_capture
    merge_capture.inspect(db)
    return {
        'schemaVersion': journal.SCHEMA_VERSION,
        'schemaDigest': digest(_schema(db)),
        'parents': len(actual), 'parentStates': counts,
        'mergeCaptures': _rows_digest(db.execute('SELECT * FROM composite_merge_captures ORDER BY parent_id')),
        'instances': _rows_digest(db.execute(
            'SELECT * FROM composite_instances ORDER BY parent_id')),
        'events': _rows_digest(db.execute(
            'SELECT * FROM composite_step_events ORDER BY parent_id,seq')),
    }


def sealed_companion(path, *, expected_schema_digest, expected_companion_digest):
    """Read the successor companion witness on the protected state mount."""
    hex_id(expected_schema_digest,64)
    hex_id(expected_companion_digest,64)
    path=Path(path)
    need(path.is_absolute() and path.resolve()==path and path.is_file(),
         'COMPOSITE_PRESERVATION_STATE_PATH')
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
    try:
        db.row_factory=sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        need([tuple(row) for row in db.execute('PRAGMA quick_check')]==[('ok',)],
             'COMPOSITE_PRESERVATION_INTEGRITY')
        witness=inspect_companion(db)
        need(witness['schemaDigest']==expected_schema_digest
             and digest(witness)==expected_companion_digest,
             'COMPOSITE_PRESERVATION_PIN_CHANGED')
        return witness
    finally:
        db.close()


def _companion_path(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path and path.is_file(),
         'COMPOSITE_PRESERVATION_STATE_PATH')
    return path


def _prepare_companion(db, *, legacy, expected_digest, verify_history):
    hex_id(expected_digest, 64)
    with db:
        db.row_factory = sqlite3.Row
        db.execute('BEGIN IMMEDIATE')
        if not journal._schema_rows(db):
            install_checked(db, expected=legacy)
        need(_core_rows(db) == legacy['coreRowsDigest'], 'COMPOSITE_PRESERVATION_PREFIX_CHANGED')
        db.execute('PRAGMA query_only=ON')
        try:
            need(digest(inspect_companion(db)) == expected_digest,
                 'COMPOSITE_PRESERVATION_PIN_CHANGED')
            if verify_history is not None:
                verify_history(db)
        finally:
            db.execute('PRAGMA query_only=OFF')


def projection_source_bytes(source):
    return (source.execute('PRAGMA page_size').fetchone()[0]
            * source.execute('PRAGMA page_count').fetchone()[0])


@contextmanager
def projection_copy(source, *, scratch_root=None):
    """Copy a pinned read transaction into private disposable SQLite storage."""
    _read_transaction(source)
    size = projection_source_bytes(source)
    if scratch_root is None:
        available = 64 * 1024 * 1024
        if not 0 < size <= available:
            raise Denied(f'COMPOSITE_PRESERVATION_STATE_LIMIT sourceBytes={size} availableBytes={available}')
        with closing(sqlite3.connect(':memory:')) as copy:
            source.backup(copy)
            yield copy
        return

    root = Path(scratch_root)
    need(root.is_absolute() and root.resolve() == root and root.is_dir(),
         'COMPOSITE_PRESERVATION_SCRATCH_DENIED')
    info = root.stat()
    need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
         'COMPOSITE_PRESERVATION_SCRATCH_DENIED')
    space = os.statvfs(root)
    # Reserve room for the additive schema and SQLite's temporary pages.
    available = max(0, space.f_bavail * space.f_frsize - 8 * 1024 * 1024)
    if not 0 < size <= available:
        raise Denied(f'COMPOSITE_PRESERVATION_STATE_LIMIT sourceBytes={size} availableBytes={available}')
    with TemporaryDirectory(prefix='registry-copy-', dir=root) as directory:
        with closing(sqlite3.connect(Path(directory) / 'state.sqlite')) as copy:
            source.backup(copy)
            yield copy


def inspect_staged_successor(path, *, expected_digest, verify_history, require_empty=True, require_quiescent=False):
    """Replay the exact staged witness; the initial cutover requires no parents."""
    hex_id(expected_digest, 64)
    need(callable(verify_history) and type(require_empty) is bool and type(require_quiescent) is bool,
         'COMPOSITE_PRESERVATION_PIN_INVALID')
    path = _companion_path(path)
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        authority = verify_history(db)
        companion = inspect_companion(db)
        need((not require_empty or companion['parents'] == 0)
             and digest(companion) == expected_digest, 'COMPOSITE_PRESERVATION_PIN_CHANGED')
        if require_quiescent:
            from ..integrations.registry_contracts.maintenance_seal import require_quiescent_companion
            require_quiescent_companion(companion)
        return {'schemaDigest':companion['schemaDigest'], 'companionDigest':expected_digest,
                'authorityWitnessDigest':digest(authority)}


def project_staged_companion(path, *, expected_digest, verify_history=None, scratch_root=None):
    """Prove the proposed schema and history on a private disposable copy."""
    path = _companion_path(path)
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as source:
        source.execute('PRAGMA query_only=ON')
        source.execute('BEGIN')
        need(source.execute('PRAGMA quick_check').fetchall() == [('ok',)],
             'COMPOSITE_PRESERVATION_INTEGRITY')
        legacy = legacy_schema_witness(source)
        with projection_copy(source, scratch_root=scratch_root) as copy:
            _prepare_companion(copy, legacy=legacy, expected_digest=expected_digest,
                               verify_history=verify_history)
        return legacy


def prepare_staged_companion(path, *, legacy, expected_digest, verify_history=None):
    """The controller supplies its exclusive clone and exact pre-stop witness."""
    path = _companion_path(path)
    need(type(legacy) is dict and set(legacy) == {'schemaDigest','coreRowsDigest'},
         'COMPOSITE_PRESERVATION_PIN_INVALID')
    for pin in legacy.values():
        hex_id(pin,64)
    with closing(sqlite3.connect(path.as_uri()+'?mode=rw', uri=True)) as db:
        _prepare_companion(db, legacy=legacy, expected_digest=expected_digest,
                           verify_history=verify_history)
