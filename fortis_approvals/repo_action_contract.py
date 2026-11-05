"""Fortis Repo -> trusted Approvals: typed *intent*, NOT a remote executor.

Stage-1 source contract only. This module has no listener, Sonar credential,
HTTP client, Docker integration, owner approval or privileged executor.
A trusted host may later mount it behind a separate authenticated ingress.
Repository callers MUST NOT send action-level policy, approvals, tokens,
URLs, methods, raw executor params, snapshots or fingerprints.
"""
from copy import deepcopy
import json
import re
import uuid

from .core import Denied, canonical
from .integrations.sonarcloud.contract import (
    SONAR_ACTION_OPERATIONS, SONAR_READ_OPERATIONS,
    validate_sonar_action, validate_sonar_read,
)
from .integrations.github.contract import (
    GITHUB_ACTION_OPERATIONS, GITHUB_READ_OPERATIONS,
    validate_github_action, validate_github_read, validate_github_read_projection,
)

INTENT_FIELDS = frozenset({'requestId', 'service', 'operation', 'target',
                           'params', 'reason'})
# Provider operations are registered by their own integration contracts.
# Reads and mutations remain separate authorization surfaces.
OPERATIONS = frozenset(
    SONAR_ACTION_OPERATIONS | GITHUB_ACTION_OPERATIONS |
    {('synthetic', 'set_free'), ('synthetic', 'set_ask'),
     ('synthetic', 'set_deny')}
)
READ_OPERATIONS = frozenset(SONAR_READ_OPERATIONS | GITHUB_READ_OPERATIONS)
_TARGET = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}')

def _envelope(value, allowed_operations):
    # Shared strict envelope; no method/URL/owner/token/policy input.
    if type(value) is not dict or set(value) != INTENT_FIELDS:
        raise Denied('REPO_INTENT_SCHEMA_DENIED')
    try:
        ident = str(uuid.UUID(value['requestId']))
    except (TypeError, KeyError, ValueError, AttributeError):
        raise Denied('REPO_REQUEST_ID_DENIED') from None
    if value['requestId'] != ident:
        raise Denied('REPO_REQUEST_ID_DENIED')
    action = (value['service'], value['operation'])
    if any(type(v) is not str for v in action) or action not in allowed_operations:
        raise Denied('REPO_OPERATION_NOT_SUPPORTED')
    if (type(value['target']) is not str or
            not _TARGET.fullmatch(value['target'])):
        raise Denied('REPO_TARGET_DENIED')
    if (type(value['reason']) is not str or
            not 0 < len(value['reason'].strip()) <= 1500):
        raise Denied('REPO_REASON_DENIED')
    params = value['params']
    if type(params) is not dict:
        raise Denied('REPO_PARAMS_DENIED')
    return action, params


def _checked_copy(value):
    try:
        service = value.get('service')
        limit = 524288 if service == 'github' else 32768
        if len(canonical(value).encode('utf-8')) > limit:
            raise Denied('REPO_INTENT_TOO_LARGE')
        # R7 GitHub typed writes may carry bounded text-file batches. The
        # ingress cap is 512 KiB; keep the escaped JSON envelope below 500 KiB.
        if (service == 'github' and
                len(json.dumps(value, ensure_ascii=True,
                               separators=(',', ':')).encode('ascii')) > 500000):
            raise Denied('GITHUB_REQUEST_TOO_LARGE_FOR_INGRESS')
    except Denied:
        raise
    except (UnicodeError, ValueError, TypeError):
        raise Denied('REPO_INTENT_UTF8_DENIED') from None
    return deepcopy(value)


def validate_intent(value):
    """Validate one provider-specific action intent; never a READ query."""
    action, params = _envelope(value, OPERATIONS)
    if action in SONAR_ACTION_OPERATIONS:
        validate_sonar_action(action[1], value['target'], params)
    elif action in GITHUB_ACTION_OPERATIONS:
        validate_github_action(action[1], value['target'], params)
    else:
        if (set(params) != {'value', 'expectedVersion'} or
            type(params['value']) is not str or len(params['value']) > 1000 or
            type(params['expectedVersion']) is not int or
            not 0 <= params['expectedVersion'] <= 2_147_483_647):
            raise Denied('REPO_SYNTHETIC_PARAMS_DENIED')
    return _checked_copy(value)


def validate_read_query(value):
    """Validate a typed provider READ envelope; no token or transport here."""
    action, params = _envelope(value, READ_OPERATIONS)
    if action in SONAR_READ_OPERATIONS:
        validate_sonar_read(action[1], value['target'], params)
    elif action in GITHUB_READ_OPERATIONS:
        validate_github_read(action[1], value['target'], params)
    return _checked_copy(value)


class RepoIntentBroker:
    """In-process contract implementation; no network route is installed.

    The *ingress grant* used in Core.client is not a Sonar token. The trusted
    host owns the adapters, policy and per-actor grant scopes. The Repo actor
    cannot select an owner or choose the Core policy. Action responses contain
    ID/state ONLY. Sonar read queries are validated/authorized as a separate
    R3 source supports an optional trusted GET-only reader at /v1/reads;
    synthetic-only and production-unadmitted deployments have no reader.
    """
    def __init__(self, core, *, actor_operations, actor_read_operations=None,
                 read_adapter=None, read_adapters=None):
        self.core = core
        adapters = {} if read_adapters is None else dict(read_adapters)
        if read_adapter is not None:
            from .integrations.sonarcloud.gateway.read_adapter import SonarReadAdapter
            if not isinstance(read_adapter, SonarReadAdapter):
                raise ValueError('REPO_TRUSTED_READ_ADAPTER_INVALID')
            adapters.setdefault('sonarcloud', read_adapter)
        if any(type(service) is not str or not service or
               not callable(getattr(adapter, 'read', None))
               for service, adapter in adapters.items()):
            raise ValueError('REPO_TRUSTED_READ_ADAPTER_INVALID')
        self.read_adapters = adapters
        # Backward-compatible attribute used by the existing Sonar composition.
        self.read_adapter = adapters.get('sonarcloud')
        if (type(actor_operations) is not dict or
                not all(type(actor) is str and actor and
                        type(ops) in (frozenset, set, tuple) and ops and
                        all(type(op) is tuple and len(op) == 2 and op in OPERATIONS
                            for op in ops)
                        for actor, ops in actor_operations.items())):
            raise ValueError('REPO_TRUSTED_GRANTS_INVALID')
        self.actor_operations = {actor: frozenset(ops)
                                 for actor, ops in actor_operations.items()}
        reads = {} if actor_read_operations is None else actor_read_operations
        if (type(reads) is not dict or
                not all(type(actor) is str and actor and
                        type(ops) in (frozenset, set, tuple) and ops and
                        all(type(op) is tuple and op in READ_OPERATIONS
                            for op in ops)
                        for actor, ops in reads.items())):
            raise ValueError('REPO_TRUSTED_READ_GRANTS_INVALID')
        self.actor_read_operations = {actor: frozenset(ops)
                                      for actor, ops in reads.items()}

    def authorize_read(self, ingress_credential, query):
        """R1 typed authorization preflight; R2 adds the read execution route.

        No request is dispatched, persisted or sent to Sonar here.
        """
        actor = self.core.auth.authenticate(ingress_credential)
        request = validate_read_query(query)
        action = (request['service'], request['operation'])
        if action not in self.actor_read_operations.get(actor, ()):
            raise Denied('REPO_READ_GRANT_DENIED')
        if self.core._policy(actor, request) != 'ALLOW':
            raise Denied('REPO_SONAR_READ_ALLOW_REQUIRED')
        return request

    def read(self, ingress_credential, query):
        """Authenticated, policy-bound provider READ through a typed adapter."""
        request = self.authorize_read(ingress_credential, query)
        service = request['service']
        adapter = self.read_adapters.get(service)
        if adapter is None:
            raise Denied('REPO_READ_ADAPTER_UNAVAILABLE')
        result = adapter.read(request)
        if service == 'github':
            validate_github_read_projection(request['operation'], result)
        else:
            # Sonar's long-standing nested projection checks are retained.
            public_fields = {
                'list_projects': frozenset(('operation', 'projects', 'page',
                    'pageSize', 'total', 'hasMore', 'nextPage', 'complete',
                    'organization')),
                'list_issues': frozenset(('operation', 'issues', 'page',
                    'pageSize', 'total', 'hasMore', 'nextPage', 'coverage',
                    'projectKey')),
                'get_issue': frozenset(('operation', 'issue', 'projectKey')),
                'get_quality_gate': frozenset(('operation', 'projectKey',
                    'status', 'conditions', 'scope', 'prShaBinding')),
            }
            if (type(result) is not dict or
                    set(result) != public_fields[request['operation']] or
                    result.get('operation') != request['operation']):
                raise Denied('REPO_READ_PROJECTION_DENIED')
            issue_fields = frozenset(('key', 'projectKey', 'status', 'severity',
                'type', 'rule', 'message', 'component', 'line', 'updateDate'))
            operation = request['operation']
            if operation == 'list_projects':
                rows = result['projects']
                if (type(rows) is not list or len(rows) > 100 or
                        any(type(row) is not dict or set(row) != {'key'}
                            for row in rows)):
                    raise Denied('REPO_READ_PROJECTION_DENIED')
            elif operation in ('list_issues', 'get_issue'):
                rows = (result['issues'] if operation == 'list_issues'
                        else [result['issue']])
                if (type(rows) is not list or len(rows) > 100 or
                        any(type(row) is not dict or set(row) != issue_fields
                            for row in rows)):
                    raise Denied('REPO_READ_PROJECTION_DENIED')
            elif operation == 'get_quality_gate':
                conditions = result['conditions']
                allowed_condition = frozenset(('status','metricKey',
                    'actualValue','errorThreshold','warningThreshold'))
                if (type(conditions) is not list or len(conditions) > 100 or
                        any(type(row) is not dict or
                            not {'status', 'metricKey'} <= set(row) or
                            not set(row) <= allowed_condition for row in conditions)):
                    raise Denied('REPO_READ_PROJECTION_DENIED')
        return {'requestId': request['requestId'], 'service': service,
                'operation': request['operation'], 'data': result}

    @staticmethod
    def _public_result(row):
        # Never expose Core's snapshots, Issue messages, actor identity,
        # policy fingerprint, Sonar credential or remote API response here.
        return {'requestId': row['requestId'], 'state': row['state']}

    def submit(self, ingress_credential, intent):
        # Authenticate and authorize the actor BEFORE any remote GET.
        actor = self.core.auth.authenticate(ingress_credential)
        request = validate_intent(intent)
        action = (request['service'], request['operation'])
        if action not in self.actor_operations.get(actor, ()):
            raise Denied('REPO_GRANT_DENIED')
        adapter = self.core.adapters.get(action[0])
        if adapter is None:
            raise Denied('REPO_ADAPTER_UNAVAILABLE')
        params = request['params']
        if action == ('sonarcloud', 'accept_issue'):
            from .integrations.sonarcloud.gateway.sonar import SonarIssueAdapter
            # Scope and exact readback digest are trusted-adapter outputs,
            # not caller-supplied fingerprints or a guessed version.
            if not isinstance(adapter, SonarIssueAdapter):
                raise Denied('REPO_SONAR_ADAPTER_DENIED')
            # Fail closed BEFORE remote lookup if the trusted policy already
            # denies this operation, or if Sonar ASK was downgraded to ALLOW.
            # The actual server-derived digest is checked again below.
            provisional = {
                'requestId': request['requestId'], 'service': 'sonarcloud',
                'operation': 'accept_issue', 'target': request['target'],
                'params': {'projectKey': params['projectKey'],
                           'transition': 'accept',
                           'expectedIssueSha256': '0' * 64},
                'expectedVersion': 0, 'reason': request['reason'],
            }
            if self.core._policy(actor, provisional) != 'ASK':
                raise Denied('REPO_SONAR_ASK_REQUIRED')
            issue = adapter.read_issue(params['projectKey'], request['target'])
            body = {
                'requestId': request['requestId'],
                'service': 'sonarcloud', 'operation': 'accept_issue',
                'target': request['target'],
                'params': {'projectKey': params['projectKey'],
                           'transition': 'accept',
                           'expectedIssueSha256': issue['sha256']},
                'expectedVersion': 0, 'reason': request['reason'],
            }
            # Fortis Sonar mutation policy is mandatory ASK. This check is
            # a front-door defense; the trusted Core/executor must ALSO pin
            # the rule and never accept caller-supplied policy.
            if self.core._policy(actor, body) != 'ASK':
                raise Denied('REPO_SONAR_ASK_REQUIRED')
        elif action in GITHUB_ACTION_OPERATIONS:
            body = {
                'requestId': request['requestId'],
                'service': 'github', 'operation': action[1],
                'target': request['target'], 'params': params,
                'expectedVersion': 0, 'reason': request['reason'],
            }
        else:
            body = {
                'requestId': request['requestId'],
                'service': request['service'],
                'operation': request['operation'],
                'target': request['target'],
                'params': {'value': params['value']},
                'expectedVersion': params['expectedVersion'],
                'reason': request['reason'],
            }
        return self._public_result(self.core.client(ingress_credential, 'submit', body))

    def status(self, ingress_credential, request_id):
        # Same actor-only Core access. No generic DB or owner history reads.
        if (type(request_id) is not str or
                not re.fullmatch(r'[0-9a-f-]{36}', request_id)):
            raise Denied('REPO_REQUEST_ID_DENIED')
        return self._public_result(self.core.client(ingress_credential, 'status', request_id))
