"""Observatory V1 typed Gateway provider: first verified read-only surface.

Only fixed service/registry targets. No write endpoint is enabled until its
running Observatory contract, ACL/replay receipts and transport are accepted.
This provider is not automatically enabled by source packaging.
"""
import re

from ...extensions.model import Operation, Provider, check
from ...extensions.http import Route
from ...integrations.review_schema import object_schema
from .transport import ObservatoryTransport


_CHAT_ID = re.compile(r'[A-Za-z0-9-]{8,100}\Z')
_SESSION_ID = re.compile(r'rs_[a-f0-9]{32}\Z')
_MAX_SESSIONS = 200


def _no_params(value):
    object_schema({})(value)


def _health_result(value):
    check(type(value) is dict and set(value) == {'ok', 'service', 'mode'} and
          value['ok'] is True and value['service'] == 'fortis-observatory-api' and
          value['mode'] == 'staging_only', 'OBS_HEALTH_SCHEMA')


def _sessions_result(value):
    check(type(value) is dict and set(value) == {'ok', 'sessions'} and
          value['ok'] is True and type(value['sessions']) is list and
          len(value['sessions']) <= _MAX_SESSIONS, 'OBS_SESSIONS_SCHEMA')
    found = set()
    for row in value['sessions']:
        check(type(row) is dict and set(row) == {'conversation_id', 'session_id'} and
              type(row['conversation_id']) is str and
              _CHAT_ID.fullmatch(row['conversation_id']) and
              (row['session_id'] is None or
               type(row['session_id']) is str and _SESSION_ID.fullmatch(row['session_id'])),
              'OBS_SESSION_ENTRY_INVALID')
        check(row['conversation_id'] not in found, 'OBS_SESSION_DUPLICATE')
        found.add(row['conversation_id'])


def _assert_target(ctx, allowed):
    check(ctx.target == allowed, 'OBS_TARGET_DENIED')


def _read_health(ctx):
    _assert_target(ctx, 'service')
    raw = ctx.call('health')
    result = {
        'ok': raw.get('ok'),
        'service': raw.get('service'),
        'mode': raw.get('mode'),
    }
    _health_result(result)
    return result


def _list_sessions(ctx):
    _assert_target(ctx, 'registry')
    raw = ctx.call('sessions')
    check(raw.get('ok') is True and
          type(raw.get('sessions')) is list and
          len(raw['sessions']) <= _MAX_SESSIONS, 'OBS_SESSIONS_UPSTREAM_INVALID')
    sessions = []
    for row in raw['sessions']:
        check(type(row) is dict, 'OBS_SESSION_ENTRY_INVALID')
        sessions.append({
            'conversation_id': row.get('conversation_id'),
            'session_id': row.get('session_id'),
        })
    result = {'ok': True, 'sessions': sessions}
    _sessions_result(result)
    return result


PROVIDER = Provider('observatory', (
    Operation(
        'health', 'Check Observatory V1 API health (read-only)', 'read',
        _no_params, _health_result, _read_health,
        credential='api', routes=('health',)),
    Operation(
        'list_sessions', 'List authorized Observatory sessions (read-only)', 'read',
        _no_params, _sessions_result, _list_sessions,
        credential='api', routes=('sessions',)),
), api=ObservatoryTransport((
    Route('health', 'GET', '/v1/health', readonly=True),
    Route('sessions', 'GET', '/v1/sessions', readonly=True),
)))
