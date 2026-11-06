"""Owner-approved single-issue edits with frozen state and durable readback."""
import hashlib
from types import SimpleNamespace

from ....core import Denied, Stale, canonical
from ...review_schema import require, fields
from ..analysis_contract import ACTION_NAMES, TRANSITIONS, validate_action
from .analysis_reader import AnalysisReader
from .sonar import SonarIssueAdapter, SonarTransportError


class SonarReviewAdapter(SonarIssueAdapter):
    """Extended mutations are opt-in; legacy accept remains wire-compatible."""

    def _current(self, project, issue):
        # AnalysisReader is reused only as a typed projection, never as a second
        # authorization boundary. Scope was established by _check_project.
        adapter = SimpleNamespace(_reader=self.transport)
        return AnalysisReader(adapter)._issue(project, issue, {})

    def build_intent(self, request):
        operation, params = request['operation'], request['params']
        validate_action(operation, request['target'], params)
        key = self._check_project(params['projectKey']); issue_key = self._check_issue_key(request['target'])
        current = self._current(key, issue_key)
        return dict(requestId=request['requestId'], service='sonarcloud', operation=operation,
                    target=issue_key, expectedVersion=0, reason=request['reason'],
                    params={**params, 'expectedIssueSha256': hashlib.sha256(canonical(current).encode()).hexdigest()})

    def _bound(self, request):
        require(request.get('service') == 'sonarcloud' and type(request.get('expectedVersion')) is int and
                request['expectedVersion'] == 0)
        operation = request['operation']; require(operation in ACTION_NAMES | {'accept_issue'})
        p = request['params']; fields(p, ('projectKey', 'expectedIssueSha256'), ('comment', 'assignee', 'tags'))
        require(type(p['expectedIssueSha256']) is str and self.SHA256.fullmatch(p['expectedIssueSha256']))
        validate_action(operation, request['target'], {k: v for k, v in p.items() if k != 'expectedIssueSha256'})
        key = self._check_project(p['projectKey']); issue_key = self._check_issue_key(request['target'])
        current = self._current(key, issue_key)
        if hashlib.sha256(canonical(current).encode()).hexdigest() != p['expectedIssueSha256']:
            raise Stale('SONAR_ISSUE_CHANGED')
        if operation in TRANSITIONS:
            transition = TRANSITIONS[operation][0]
            require(transition in current['transitions'], 'SONAR_TRANSITION_UNAVAILABLE')
        return key, issue_key, current

    def prepare(self, request):
        if request['operation'] == 'accept_issue' and 'transition' in request['params']:
            return super().prepare(request)
        key, issue_key, before = self._bound(request)
        p = request['params']; op = request['operation']
        return dict(operation=op, projectKey=key, issueKey=issue_key, before=before,
                    after={**({'status': TRANSITIONS[op][1]} if op in TRANSITIONS else {}),
                           **{k: p[k] for k in ('assignee', 'tags') if k in p}},
                    comment=p.get('comment', request['reason'] if op in TRANSITIONS else None),
                    limitation='PROVIDER_HAS_NO_ATOMIC_COMPARE_AND_SWAP')

    def apply(self, request):
        if request['operation'] == 'accept_issue' and 'transition' in request['params']:
            return super().apply(request)
        prior = self.receipt(request['requestId'])
        if prior is not None:
            return prior
        key, issue_key, before = self._bound(request)
        op, p = request['operation'], request['params']
        comment = p.get('comment', request['reason'])
        if op in TRANSITIONS:
            route = '/api/issues/do_transition'
            outgoing = dict(issue=issue_key, transition=TRANSITIONS[op][0], comment=comment)
        elif op == 'add_issue_comment':
            route = '/api/issues/add_comment'; outgoing = dict(issue=issue_key, text=p['comment'])
        elif op == 'assign_issue':
            route = '/api/issues/assign'; outgoing = dict(issue=issue_key, assignee=p['assignee'])
        elif op == 'set_issue_tags':
            route = '/api/issues/set_tags'; outgoing = dict(issue=issue_key, tags=','.join(p['tags']))
        else:
            raise Denied('SONAR_REVIEW_ACTION_DENIED')
        response = self.transport.call('POST', route, outgoing)
        require(type(response) is dict, 'SONAR_WRITE_RESPONSE_INVALID')
        after = self._current(key, issue_key)
        confirmed = False
        if op in TRANSITIONS:
            confirmed = after['status'] == TRANSITIONS[op][1]
        elif op == 'add_issue_comment':
            # A matching pre-existing comment is not evidence of this append.
            old_ids = {x['key'] for x in before['comments']}
            confirmed = any(x['key'] not in old_ids and x['text'] == p['comment'] for x in after['comments'])
        elif op == 'assign_issue':
            confirmed = (after['assignee'] or '') == p['assignee']
        elif op == 'set_issue_tags':
            confirmed = set(after['tags']) == set(p['tags'])
        if not confirmed:
            raise SonarTransportError('SONAR_REVIEW_READBACK_UNCONFIRMED')
        result = dict(requestId=request['requestId'], operation=op, projectKey=key, issueKey=issue_key,
                      beforeSha256=p['expectedIssueSha256'],
                      afterSha256=hashlib.sha256(canonical(after).encode()).hexdigest(),
                      status=after['status'])
        with self._db() as db:
            db.execute('INSERT INTO receipts(request_id,result) VALUES(?,?)',
                       (request['requestId'], canonical(result)))
        return result
