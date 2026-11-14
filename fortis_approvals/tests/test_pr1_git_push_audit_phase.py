"""Offline bounded Git push phase regression (no GitHub or Owner Portal effects)."""
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from fortis_approvals.core import Authenticator, Core
from fortis_approvals.workflow.error_diagnostics import category, observe_adapter
from fortis_approvals.workflow.git_backend import GitPushFailure, GIT_PUSH_PHASES, GIT_PUSH_FAILURE_CODES
from fortis_approvals.workflow.incident_read import diagnose

class Adapter:
    def __init__(self,exc):self.exc=exc;self.core=None
    def prepare(self,request):return {'immutable':True}
    @observe_adapter('GITHUB_ADAPTER')
    def apply(self,request):raise self.exc
    def confirm(self,ident,result):return False

class AuditPhaseTests(unittest.TestCase):
    def run_case(self,exc):
        with tempfile.TemporaryDirectory() as d:
            a=Adapter(exc)
            core=Core(Path(d)/'core.sqlite',adapters={'github':a},
                policies={('actor','github','push_commits'):'ALLOW'},
                authenticator=Authenticator({'fixture':'actor'}))
            a.core=core
            ident=str(uuid.uuid4())
            row=core.submit('actor',dict(requestId=ident,service='github',
                operation='push_commits',target='repo',params={},
                expectedVersion=0,reason='offline regression'))
            events=[dict(state=e['state'],at=e['at'],detail=json.loads(e['detail']))
                    for e in core.events(ident)]
            return row,events,diagnose(dict(request=row,worker=None,receipt=None,events=events))

    def test_every_phase_stays_uncertain_but_preserves_bounded_phase(self):
        for phase in sorted(GIT_PUSH_PHASES):
            with self.subTest(phase=phase):
                row,events,diagnosis=self.run_case(GitPushFailure(phase,'GIT_OUTCOME_TIMEOUT'))
                expected={'stage':'GITHUB_ADAPTER','code':'GIT_OUTCOME_TIMEOUT','phase':phase}
                self.assertEqual((row['state'],row['failure']),
                                 ('UNCERTAIN','REMOTE_OUTCOME_UNCONFIRMED'))
                self.assertIsNone(row['result'])
                self.assertEqual([x['state'] for x in events],
                                 ['APPROVED','DISPATCHED','ERROR_OBSERVED','UNCERTAIN'])
                self.assertEqual(events[-2]['detail'],expected)
                self.assertEqual(diagnosis['coreError'],expected)
                self.assertEqual(diagnosis['originalEffect'],'UNCONFIRMED')

    def test_codes_are_closed(self):
        for code in GIT_PUSH_FAILURE_CODES:
            self.assertEqual(category(GitPushFailure('push',code)),code)

    def test_generic_error_keeps_two_fields(self):
        row,events,diagnosis=self.run_case(RuntimeError('SECRET-STDER R'))
        self.assertEqual(events[-2]['detail'],{'stage':'GITHUB_ADAPTER','code':'RUNTIME_ERROR'})
        self.assertEqual(diagnosis['coreError'],events[-2]['detail'])
        self.assertEqual(row['state'],'UNCERTAIN')

    def test_tampered_exception_phase_not_published(self):
        exc=GitPushFailure('push','GIT_OUTCOME_TIMEOUT');exc.phase='SECRET'
        row,events,diagnosis=self.run_case(exc)
        self.assertEqual(events[-2]['detail'],
                         {'stage':'GITHUB_ADAPTER','code':'GIT_PUSH_STEP_UNCONFIRMED'})
        self.assertEqual(diagnosis['coreError'],events[-2]['detail'])

    def test_reader_rejects_invalid_diagnostic(self):
        row,events,diagnosis=self.run_case(GitPushFailure('push','GIT_OUTCOME_TIMEOUT'))
        for bogus in (
            {'stage':'GITHUB_ADAPTER','code':'GIT_OUTCOME_TIMEOUT','phase':'invalid'},
            {'stage':'GITHUB_ADAPTER','code':'GITHUB_HTTP_403','phase':'push'},
            {'stage':'GITHUB_ADAPTER','code':'GIT_OUTCOME_TIMEOUT','phase':'push','secret':'x'},
        ):
            changed=[dict(e) for e in events];changed[-2]['detail']=bogus
            self.assertIsNone(diagnose(dict(request=row,worker=None,receipt=None,events=changed))['coreError'])

if __name__=='__main__':unittest.main()
