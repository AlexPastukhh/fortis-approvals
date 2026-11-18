"""UNREGISTERED, fail-closed private P4 ASK snapshot admission.

A future trusted adapter must supply two independent read-only capabilities:
lookup(repo, authenticated_actor, preview_id) -> original Windows persisted
principal-bound snapshot; observe(repo, authenticated_actor) -> fresh verified
source preconditions. No such channel is registered here. This module never
signs, calls HTTP POST, reserves a worker, or grants any Windows Git effect.
"""
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
import re
import time

from fortis_approvals.core import Denied
from fortis_approvals.extensions.model import check
from fortis_approvals.integrations.mirror import read_v2

PARAMS = frozenset(('previewId','expectedHead','targetSha','configGeneration'))


@dataclass(frozen=True)
class BoundAskPreview:
    actor: str
    repo: str
    read_request_id: str
    preview_id: str
    expected_head: str
    target_sha: str
    generation: str
    origin: str
    expires_at: int

    def execute_params(self):
        return MappingProxyType({
            'previewId': self.preview_id, 'expectedHead': self.expected_head,
            'targetSha': self.target_sha, 'configGeneration': self.generation})


def epoch(value):
    read_v2.timestamp(value)
    try:
        result = datetime.fromisoformat(value.replace('Z','+00:00'))
        check(result.tzinfo is not None and result.utcoffset().total_seconds() == 0,
              'MIRROR_ASK_TIMESTAMP_INVALID')
        return int(result.timestamp())
    except (ValueError, TypeError, OverflowError):
        raise Denied('MIRROR_ASK_TIMESTAMP_INVALID') from None


def approval(ctx):
    row = ctx.runtime.core._read(ctx.request_id)
    request = row.get('request')
    check(row.get('state') == 'DISPATCHED' and row.get('decision') == 'approve' and
          type(row.get('owner')) is str and bool(row['owner']) and
          row.get('actor') == ctx.authenticated_actor and
          type(request) is dict and request.get('requestId') == ctx.request_id and
          request.get('service') == 'mirror' and
          request.get('operation') == 'execute_windows_pull_v2' and
          request.get('target') == ctx.target and request.get('params') == ctx.params,
          'MIRROR_ASK_APPROVAL_REQUIRED')


def admit_private_ask(ctx, *, lookup=None, observe=None, now=None):
    """Validate source evidence only; neither callable may come from a user.

    Caller must be trusted Gateway operation code. Both capabilities are
    deliberately required; public READ preview or caller-supplied params are
    never a fallback. Windows must independently preflight before reservation.
    """
    check(ctx.phase in ('preview','execute') and ctx.provider.name == 'mirror' and
          ctx.operation.name == 'execute_windows_pull_v2' and
          ctx.operation.kind == 'write' and
          type(ctx.authenticated_actor) is str and
          re.fullmatch(r'[A-Za-z0-9_.:-]{1,120}',ctx.authenticated_actor) and
          type(ctx.target) is str and
          re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,119}',ctx.target),
          'MIRROR_ASK_PHASE_DENIED')
    check(type(ctx.params) is dict and set(ctx.params) == PARAMS,
          'MIRROR_ASK_PARAMS_INVALID')
    read_v2.uuid4(ctx.request_id)
    read_v2.uuid4(ctx.params['previewId'])
    read_v2.sha(ctx.params['expectedHead'])
    read_v2.sha(ctx.params['targetSha'])
    read_v2.revision(ctx.params['configGeneration'])
    check(ctx.params['expectedHead'] != ctx.params['targetSha'],
          'MIRROR_ASK_PARAMS_INVALID')
    check(callable(lookup) and callable(observe),
          'MIRROR_ASK_TRUSTED_SOURCE_UNAVAILABLE')
    if ctx.phase == 'execute':
        approval(ctx)  # Core approval must predate all upstream interactions.
    clock = int(time.time()) if now is None else now
    check(type(clock) is int and 0 <= clock < 4102444800,
          'MIRROR_ASK_TIMESTAMP_INVALID')

    # Only authenticated Core context selects the repo, actor and preview ID.
    stored = lookup(ctx.target,ctx.authenticated_actor,ctx.params['previewId'])
    check(type(stored) is dict and set(stored) == {
        'readRequestId','origin','snapshot'},
        'MIRROR_ASK_PRIVATE_LOOKUP_INVALID')
    read_id,origin,snapshot = stored['readRequestId'],stored['origin'],stored['snapshot']
    read_v2.uuid4(read_id)
    check(read_id != ctx.request_id and type(origin) is str and
          origin in (f'https://github.com/AlexPastukhh/{ctx.target}',
                     f'https://github.com/AlexPastukhh/{ctx.target}.git') and
          type(snapshot) is dict,'MIRROR_ASK_PRIVATE_LOOKUP_INVALID')
    read_v2.preview(snapshot)
    check(snapshot['repoId'] == ctx.target and
          snapshot['originIdentity'] == 'AlexPastukhh/' + ctx.target and
          snapshot['blockers'] == [] and
          all(snapshot[k] == value for k,value in ctx.params.items()),
          'MIRROR_ASK_PREVIEW_MISMATCH')
    expires = epoch(snapshot['expiresAt'])
    check(clock < expires,'MIRROR_ASK_PREVIEW_EXPIRED')

    fresh = observe(ctx.target,ctx.authenticated_actor)
    check(type(fresh) is dict and set(fresh) == {
        'repoId','origin','available','windowsHead','dockerHead',
        'targetSha','sourceEvidence','checkedAt'}, 'MIRROR_ASK_STALE')
    check(fresh['repoId'] == ctx.target and fresh['origin'] == origin and
          fresh['available'] is True and
          fresh['windowsHead'] == snapshot['expectedHead'] and
          fresh['dockerHead'] == snapshot['targetSha'] and
          fresh['targetSha'] == snapshot['targetSha'], 'MIRROR_ASK_STALE')
    check(type(fresh['sourceEvidence']) is dict and
          set(fresh['sourceEvidence']) == {'windows','docker','github'},
          'MIRROR_ASK_STALE')
    for name in ('windows','docker','github'):
        before,after = snapshot['sourceEvidence'][name],fresh['sourceEvidence'][name]
        check(type(after) is dict and set(after) == set(before) and
              all(after.get(k) == before.get(k) for k in
                  ('verification','branch','head','clean','errorCode')) and
              after['verification'] == 'VERIFIED' and
              after['branch'] == 'main' and after['errorCode'] is None,
              'MIRROR_ASK_STALE')
    age = clock - epoch(fresh['checkedAt'])
    check(0 <= age <= 20,'MIRROR_ASK_STALE')
    return BoundAskPreview(
        actor=ctx.authenticated_actor,repo=ctx.target,
        read_request_id=read_id,preview_id=ctx.params['previewId'],
        expected_head=ctx.params['expectedHead'],
        target_sha=ctx.params['targetSha'],
        generation=ctx.params['configGeneration'],
        origin=origin,expires_at=expires)
