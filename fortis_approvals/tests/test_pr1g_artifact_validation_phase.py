"""PR1G: a generic 403 at git/artifact has a bounded *validation* stage."""
import base64
from contextlib import contextmanager
from io import BytesIO
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.workflow.git_backend import GitHubGitBackend
from fortis_approvals.workflow.ingress import NativeIngress
from fortis_approvals.workflow.artifact_diagnostics import (
    ARTIFACT_FAILURE_HEADER, ARTIFACT_PHASE_HEADER,
    ARTIFACT_VALIDATION_PHASES, bounded_artifact_error, bounded_artifact_phase)
from fortis_approvals.workflow.client import WorkflowTransport
from fortis_approvals.tests.test_pr1f_closure import (
    GRANT, OfflineIngressBase, HTTPFail)

HEAD='e'*40
BASE='f'*40

class GitArtifactPhaseTests(unittest.TestCase):
    def _backend(self,root):
        backend=GitHubGitBackend(root/'git',owner='offline',
              repositories={'fortis-approvals'})
        @contextmanager
        def fake_credentials(repo):
            yield None
        backend.credentials=fake_credentials
        return backend

    def test_real_validator_marks_fetch_main_failure_without_credential_or_network(self):
        with tempfile.TemporaryDirectory() as td:
            backend=self._backend(Path(td))
            def no_network(*a):
                raise Denied('GIT_COMMAND_FAILED')
            backend._fetch=no_network
            with self.assertRaises(Denied) as raised:
                backend.validate('fortis-approvals',dict(
                    task='fixture',branch='task/fixture',baseSha=BASE),None,HEAD,b'data')
            self.assertEqual(raised.exception.args,('GIT_COMMAND_FAILED',))
            self.assertEqual(bounded_artifact_phase(raised.exception),'FETCH_MAIN')
            self.assertEqual(bounded_artifact_error(raised.exception),'GIT_COMMAND_FAILED')

    def test_setup_failure_is_bounded_and_does_not_expose_token_error(self):
        with tempfile.TemporaryDirectory() as td:
            backend=self._backend(Path(td))
            backend.credentials=lambda repo: (_ for _ in ()).throw(
                Denied('SENSITIVE-GITHUB-TOKEN-ERROR'))
            with self.assertRaises(Denied) as caught:
                backend.validate('fortis-approvals',dict(
                    task='fixture',branch='task/fixture',baseSha=BASE),None,HEAD,b'data')
            self.assertEqual(bounded_artifact_phase(caught.exception),'SETUP')
            self.assertEqual(bounded_artifact_error(caught.exception),
                             'GIT_ARTIFACT_REJECTION_UNCLASSIFIED')

    def test_other_stage_tags_are_distinct_and_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            backend=self._backend(Path(td))
            backend._fetch=lambda *a:None
            backend.git.text=lambda cmd,**kw: BASE if cmd[0]=='rev-parse' else ''
            backend.refs=lambda repo: (_ for _ in ()).throw(Denied('GIT_COMMAND_FAILED'))
            with self.assertRaises(Denied) as raised:
                backend.validate('fortis-approvals',dict(
                    task='fixture',branch='task/fixture',baseSha=BASE),None,HEAD,b'data')
            self.assertEqual(bounded_artifact_phase(raised.exception),'READ_REMOTE_REFS')
            exc=Denied('GIT_COMMAND_FAILED')
            exc.artifact_phase='SECRET-OUTPUT'
            self.assertIsNone(bounded_artifact_phase(exc))
            self.assertNotIn('SECRET-OUTPUT',ARTIFACT_VALIDATION_PHASES)

    def test_native_artifact_route_preserves_old_json_and_adds_fixed_phase(self):
        exc=Denied('GIT_COMMAND_FAILED')
        exc.artifact_phase='FETCH_MAIN'
        fake_backend=SimpleNamespace(validate=lambda *a: (_ for _ in ()).throw(exc))
        gh=SimpleNamespace(_access=lambda repo:repo,task=lambda repo,task:
            dict(task=task,branch='task/'+task,baseSha=BASE),
            backend=fake_backend)
        broker=SimpleNamespace(core=SimpleNamespace(auth=Authenticator({GRANT:'actor'})))
        native=NativeIngress(OfflineIngressBase(broker.core),
            github=gh,workspace=None,store=None,actor='actor')
        payload=json.dumps(dict(repository='fortis-approvals',task='fixture',
            expectedHeadSha=None,newSha=HEAD,
            bundle=base64.b64encode(b'SYNTHETIC-LOCAL-BUNDLE').decode())).encode()
        env={'HTTP_HOST':'offline.example','QUERY_STRING':'',
             'PATH_INFO':'/v1/git/artifact','REQUEST_METHOD':'POST',
             'wsgi.url_scheme':'https','HTTP_AUTHORIZATION':'Bearer '+GRANT,
             'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(payload)),
             'wsgi.input':BytesIO(payload)}
        outputs=[]
        body=b''.join(native(env,lambda status,headers:outputs.append(
            (int(status[:3]),dict(headers)))))
        status,headers=outputs[0]
        self.assertEqual(status,403)
        self.assertEqual(json.loads(body),{'error':'WORKFLOW_DENIED'})
        self.assertEqual(headers[ARTIFACT_FAILURE_HEADER],'GIT_COMMAND_FAILED')
        self.assertEqual(headers[ARTIFACT_PHASE_HEADER],'FETCH_MAIN')
        self.assertEqual(headers['X-Fortis-Diagnostic-Contract'],'2')
        self.assertNotIn('NO_EFFECT',json.dumps(headers))
        with tempfile.TemporaryDirectory() as td:
            grant=Path(td)/'grant'; cert=Path(td)/'cert'
            grant.write_text(GRANT);grant.chmod(0o600);cert.write_text('offline')
            for phase,expected in (
                ('FETCH_MAIN','FORTIS_ARTIFACT_GIT_COMMAND_FAILED_FETCH_MAIN'),
                ('SECRET-HEADER','FORTIS_HTTP_403'),
            ):
                with self.subTest(phase=phase):
                    copied=dict(headers)
                    copied[ARTIFACT_PHASE_HEADER]=phase
                    client=WorkflowTransport(endpoint='http://localhost:19915',
                        grant_path=str(grant),certificate_path=str(cert),
                        opener=HTTPFail(403,copied,body))
                    with self.assertRaises(Denied) as caught:
                        client.post('/v1/git/artifact',{'offline':'test'})
                    self.assertEqual(str(caught.exception),expected)

    def test_stages_are_observations_not_outcome_proof(self):
        self.assertIn('FETCH_MAIN',ARTIFACT_VALIDATION_PHASES)
        self.assertIn('BUNDLE_IMPORT',ARTIFACT_VALIDATION_PHASES)
        self.assertNotIn('REMOTE_EFFECT_NOT_EXECUTED',ARTIFACT_VALIDATION_PHASES)
        self.assertNotIn('SAFE_TO_RETRY',ARTIFACT_VALIDATION_PHASES)

if __name__=='__main__':
    unittest.main()
