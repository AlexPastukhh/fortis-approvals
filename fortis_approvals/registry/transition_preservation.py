"""Offline v3 logical-prefix witness for a reviewed successor migration.

Uses existing v3 replay and strict schema checks. Not a live state probe,
backup, external anchor, migration, or host admission.
"""
from ..core import Denied
from ..integrations.registry_contracts.semantic_contract import digest, need
from ..integrations.registry_contracts.transition_contract import validate_registry_witness
from .functional_v1_journal import FunctionalV1CandidateJournal

# Static reviewed queries, never SQL or table names supplied by a caller.
_QUERIES = (
    ('meta', 'SELECT * FROM meta ORDER BY instance_id'),
    ('operations', 'SELECT * FROM operations ORDER BY revision'),
    ('records', 'SELECT * FROM records ORDER BY record_id'),
    ('supersessions', 'SELECT * FROM supersessions ORDER BY from_record_id'),
)


def legacy_prefix_witness(journal):
    """Compare exact stored SQL values, including original receipt text.

    Only for a known inactive isolated v3 source or verified clone. The
    existing read-only DB context validates file mode and exact schema.
    No authority follows from a matching locally replayable prefix.
    """
    need(type(journal) is FunctionalV1CandidateJournal,
         'TRANSITION_LEGACY_JOURNAL_REQUIRED')
    with journal._read_only_db() as db:
        return prefix_in_transaction(journal, db)


def prefix_in_transaction(journal, db, *, replay=None):
    """Replay legacy rows in an already schema-validated transaction."""
    head, cursor, _, _, _ = journal._state(db) if replay is None else replay
    table_digests = {}
    for table, query in _QUERIES:
        rows = db.execute(query).fetchall()
        table_digests[table] = {'count': len(rows), 'digest': digest(rows)}
    schema = db.execute(
        "SELECT name,sql FROM sqlite_master WHERE name NOT LIKE "
        "'sqlite_autoindex_%' AND name IN ('meta','operations','records','supersessions') ORDER BY name"
    ).fetchall()
    return {
        'schemaVersion': 3, 'instanceId': journal.instance_id,
        'scopeDigest': head['scopeDigest'],
        'genesisDigest': journal.initial['eventDigest'],
        'revision': head['revision'], 'eventDigest': head['eventDigest'],
        'cursorSha': cursor,
        'prefixDigest': digest({'schema': schema, 'tables': table_digests}),
    }


def compare_legacy_prefix(expected, observed):
    """Exact comparison only; the expected witness must be independently pinned."""
    if validate_registry_witness(expected) != validate_registry_witness(observed):
        raise Denied('TRANSITION_LEGACY_PREFIX_CHANGED')
    return 'LEGACY_PREFIX_MATCH_ONLY'
