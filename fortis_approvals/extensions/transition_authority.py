"""Offline comparison of an existing Core/policy history across one epoch.

The caller supplies an already validated trusted Core composition and a
read-only transaction on its isolated copy. No installation, authority
upgrade, grant, database opening, or live endpoint is provided here.
This witness is additional to, not a substitute for, the full protected
state inspection and source/target schema migration contract.
"""
import hashlib

from ..core import Denied, canonical
from ..integrations.registry_contracts.semantic_contract import digest, hex_id, need
from .owner_policy_engine_v2 import UnifiedPolicyCore, _EPOCHS, _names


def _rows_digest(rows):
    h = hashlib.sha256(b'fortis-transition-rows-v1\x00')
    count = 0
    for row in rows:
        values = list(row)
        need(all(type(v) in (str, int, type(None)) for v in values),
             'TRANSITION_CORE_ROW_INVALID')
        raw = canonical(values).encode('utf-8')
        h.update(len(raw).to_bytes(8, 'big'))
        h.update(raw)
        count += 1
        need(count <= 10_000_000, 'TRANSITION_CORE_ROW_LIMIT')
    return {'count': count, 'digest': h.hexdigest()}


def _choices_digest(authority):
    return digest([[list(key), sorted(choices)]
                   for key, choices in sorted(authority.choices.items())])


def stored_authority_witness(db):
    """Hash exact policy and Core storage in a caller-owned read snapshot."""
    need(db.in_transaction and db.execute('PRAGMA query_only').fetchone()[0] == 1,
         'TRANSITION_READ_ONLY_WITNESS_REQUIRED')
    need([tuple(row) for row in db.execute('PRAGMA quick_check')] == [('ok',)],
         'TRANSITION_CORE_INTEGRITY')
    meta = db.execute(
        'SELECT revision,authority,legacy_digest FROM owner_local_policy_v2_meta WHERE id=1'
    ).fetchone()
    need(meta is not None, 'TRANSITION_AUTHORITY_WITNESS_INVALID')
    rev, authority, legacy_digest = meta
    epochs = [list(row) for row in db.execute(
        'SELECT * FROM owner_local_policy_v2_authority_epochs ORDER BY id'
    )] if _EPOCHS in _names(db) else []
    # Preserve the existing requests/events schema and raw stored SQL values.
    schema = [list(row) for row in db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE tbl_name IN ('requests','events') ORDER BY type,name")]
    core_rows = {
        'requests': _rows_digest(db.execute('SELECT rowid,* FROM requests ORDER BY rowid')),
        'events': _rows_digest(db.execute('SELECT rowid,* FROM events ORDER BY rowid')),
        'eventsSequence': _rows_digest(db.execute(
            "SELECT name,seq FROM sqlite_sequence WHERE name='events'")),
    }
    unchanged = {
        'legacyDigest': legacy_digest,
        'rules': _rows_digest(db.execute(
            'SELECT * FROM owner_local_policy_v2_rules ORDER BY coordinate')),
        'events': _rows_digest(db.execute(
            'SELECT * FROM owner_local_policy_v2_events ORDER BY revision')),
    }
    return {
        'coreHistoryDigest': digest({'schema': schema, 'tables': core_rows}),
        'policy': {
            'revision': rev, 'authorityDigest': authority,
            'historyDigest': digest({'unchanged': unchanged, 'epochs': epochs}),
        },
        'unchangedPolicyDigest': digest(unchanged),
        'epochCount': len(epochs),
        'epochDigest': digest(epochs),
        'previousEpochDigest': digest(epochs[:-1]) if epochs else None,
        'lastEpoch': ({
            'id': epochs[-1][0], 'throughRevision': epochs[-1][1],
            'oldAuthorityDigest': epochs[-1][2], 'newAuthorityDigest': epochs[-1][3],
            'oldChoicesDigest': hashlib.sha256(epochs[-1][4].encode('utf-8')).hexdigest(),
        } if epochs else None),
    }


def authority_witness(core, db):
    """Bind exact storage and the trusted Core's current compiled admission."""
    from .composite_successor import CompositeUnifiedCore
    need(type(core) in (UnifiedPolicyCore, CompositeUnifiedCore) and core.authority is not None,
         'TRANSITION_READ_ONLY_WITNESS_REQUIRED')
    witness = stored_authority_witness(db)
    rev, _, _ = core._snapshot(db)
    need(witness['policy']['revision'] == rev
         and witness['policy']['authorityDigest'] == core.authority.sha,
         'TRANSITION_AUTHORITY_WITNESS_INVALID')
    return {**witness, 'choicesDigest': _choices_digest(core.authority)}


def compare_authority_epoch(before, after, *, expected_successor_digest):
    """Require one exact epoch append and no change to preserved history.

    The expected successor and snapshots must be independently trusted.
    This checks preservation, not whether new authority choices are safe.
    """
    hex_id(expected_successor_digest, 64)
    try:
        old, new = before['policy'], after['policy']
        tail = after['lastEpoch']
        need(old['authorityDigest'] != expected_successor_digest
             and new['authorityDigest'] == expected_successor_digest
             and new['revision'] == old['revision']
             and before['coreHistoryDigest'] == after['coreHistoryDigest']
             and before['unchangedPolicyDigest'] == after['unchangedPolicyDigest']
             and after['epochCount'] == before['epochCount'] + 1
             and after['previousEpochDigest'] == before['epochDigest']
             and tail == {'id': after['epochCount'], 'throughRevision': old['revision'],
                          'oldAuthorityDigest': old['authorityDigest'],
                          'newAuthorityDigest': expected_successor_digest,
                          'oldChoicesDigest': before['choicesDigest']},
             'TRANSITION_AUTHORITY_HISTORY_CHANGED')
    except (KeyError, TypeError, AttributeError):
        raise Denied('TRANSITION_AUTHORITY_WITNESS_INVALID') from None
    return 'AUTHORITY_HISTORY_MATCH_ONLY'
