"""Process diagnosis, real Git quarantine reuse and bounded wire failures."""
from io import BytesIO
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from fortis_approvals.core import Denied
from fortis_approvals.diagnostic_contract import DIAGNOSTIC_VERSION_HEADER
from fortis_approvals.clients.gateway_transport import GatewayTransport
from fortis_approvals.clients.retries import RetryPolicy, transient
from fortis_approvals.workflow.common import Git, GitCommandFailure, GitCommandTimeout, git_failure_code
from fortis_approvals.workflow.git_backend import GitPushFailure
from fortis_approvals.workflow.error_diagnostics import category
from test_native_workflow import GitFixture, git


class ProcessDiagnosis(unittest.TestCase):
    def test_reported_failures_and_unknown_remain_distinct(self):
        cases = {
            b'fatal: Authentication failed for PRIVATE-TOKEN': 'GIT_AUTH_FAILURE_REPORTED',
            b'fatal: The requested URL returned error: 403': 'GIT_REMOTE_ACCESS_DENIED',
            b'fatal: The requested URL returned error: 429': 'GIT_RATE_LIMIT_REPORTED',
            b'fatal: SSL certificate problem: PRIVATE': 'GIT_TLS_FAILURE_REPORTED',
            b'fatal: unable to access PRIVATE: Could not resolve host: PRIVATE': 'GIT_NETWORK_FAILURE_REPORTED',
            b'fatal: No space left on device': 'GIT_RESOURCE_FAILURE_REPORTED',
            b'fatal: The requested URL returned error: 503': 'GIT_UPSTREAM_HTTP_FAILURE',
            b'PRIVATE-MARKER unusual failure': 'GIT_COMMAND_FAILED',
        }
        for message, code in cases.items():
            self.assertEqual(git_failure_code(message,128),code)
        self.assertEqual(git_failure_code(b'out of memory',-9),'GIT_PROCESS_SIGNALLED')

    def test_runner_never_exports_stderr_or_command(self):
        with tempfile.TemporaryDirectory() as name:
            runner=Git(Path(name)/'runner')
            def process(*args, **kwargs):
                kwargs['stderr'].write(b'fatal: Authentication failed for PRIVATE-TOKEN')
                return SimpleNamespace(returncode=128,communicate=lambda *a,**k:None)
            with patch('fortis_approvals.workflow.common.subprocess.Popen',side_effect=process), \
                    self.assertLogs('fortis_approvals.workflow.common',level='ERROR') as logs:
                with self.assertRaises(GitCommandFailure) as caught:
                    runner.run(['PRIVATE-COMMAND'])
            self.assertEqual(str(caught.exception),'GIT_AUTH_FAILURE_REPORTED')
            self.assertEqual(caught.exception.returncode,128)
            self.assertNotIn('PRIVATE',repr(caught.exception)+repr(logs.output))

    def test_timeout_is_observed_not_inferred_from_elapsed_time(self):
        with tempfile.TemporaryDirectory() as name:
            runner=Git(Path(name)/'runner')
            def expired(*args,**kwargs):raise subprocess.TimeoutExpired('PRIVATE-COMMAND',1)
            process=SimpleNamespace(pid=123,returncode=-9,communicate=expired,wait=lambda:None)
            with patch('fortis_approvals.workflow.common.subprocess.Popen',return_value=process), \
                    patch('fortis_approvals.workflow.common.os.killpg'), \
                    self.assertLogs('fortis_approvals.workflow.common',level='ERROR') as logs:
                with self.assertRaises(GitCommandTimeout):runner.run(['PRIVATE-COMMAND'])
            self.assertNotIn('PRIVATE',repr(logs.output))


class TransferEfficiency(unittest.TestCase):
    def candidate(self, name):
        fixture=GitFixture(name)
        git(fixture.primary,'checkout','-b','task/efficient')
        (fixture.primary/'change.md').write_text('verified content\n')
        git(fixture.primary,'add','change.md')
        git(fixture.primary,'commit','-m','candidate')
        head=git(fixture.primary,'rev-parse','HEAD')
        bundle=Path(name)/'candidate.bundle'
        git(fixture.primary,'bundle','create',str(bundle),'refs/heads/task/efficient')
        return fixture,head,bundle.read_bytes()

    def test_real_push_fetches_main_once_and_cleans_quarantine(self):
        with tempfile.TemporaryDirectory() as name:
            fixture,head,data=self.candidate(name)
            task={'task':'efficient','branch':'task/efficient','baseSha':fixture.base}
            with patch.object(fixture.backend,'_fetch',wraps=fixture.backend._fetch) as fetch:
                result=fixture.backend.push('sandbox',task,None,head,data)
            self.assertEqual(result['newSha'],head)
            self.assertEqual(fixture.backend.refs('sandbox')['task/efficient'],head)
            self.assertEqual(sum(call.args[2]=='main' for call in fetch.call_args_list),1)
            self.assertFalse(any(p.name.startswith('git-validate-') for p in fixture.backend.root.iterdir()))
            self.assertFalse(fixture.helper_marker.exists())

    def test_remote_race_still_fails_lease_without_overwriting(self):
        with tempfile.TemporaryDirectory() as name:
            fixture,head,data=self.candidate(name)
            task={'task':'efficient','branch':'task/efficient','baseSha':fixture.base}
            original=fixture.backend.git.run
            def run(args,**kwargs):
                if args[0]=='push':
                    git(fixture.remote,'update-ref','refs/heads/task/efficient',fixture.base)
                return original(args,**kwargs)
            with patch.object(fixture.backend.git,'run',side_effect=run):
                with self.assertRaises(GitPushFailure) as caught:
                    fixture.backend.push('sandbox',task,None,head,data)
            self.assertEqual(caught.exception.phase,'push')
            self.assertEqual(fixture.backend.refs('sandbox')['task/efficient'],fixture.base)

    def test_nested_validation_phase_and_safe_reason_are_preserved(self):
        failure=GitCommandFailure('GIT_NETWORK_FAILURE_REPORTED',returncode=128,elapsed_ms=12)
        failure.artifact_phase='FETCH_MAIN'
        from fortis_approvals.workflow.git_backend import push_phase
        with self.assertRaises(GitPushFailure) as caught:
            with push_phase('revalidate'):
                raise failure
        self.assertEqual(caught.exception.validation_phase,'FETCH_MAIN')
        self.assertEqual(category(caught.exception),'GIT_NETWORK_FAILURE_REPORTED')


class GitWireFailures(unittest.TestCase):
    def test_fetch_and_artifact_errors_have_safe_codes_and_retry_categories(self):
        cases=[('GIT_NETWORK_FAILURE_REPORTED',True),('GIT_OUTCOME_TIMEOUT',True),
               ('GIT_AUTH_FAILURE_REPORTED',False),('GIT_REMOTE_ACCESS_DENIED',False),
               ('GIT_RESOURCE_FAILURE_REPORTED',False),('GIT_TLS_FAILURE_REPORTED',False)]
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'grant').write_text('f'*48);(root/'grant').chmod(0o600)
            (root/'cert').write_text('fixture')
            for route,prefix in [('/v1/git/fetch','FORTIS_FETCH_'),('/v1/git/artifact','FORTIS_ARTIFACT_')]:
                for code,retry in cases:
                    headers={DIAGNOSTIC_VERSION_HEADER:'2',
                             'X-Fortis-Artifact-Diagnostic':code,'X-Fortis-Artifact-Phase':'FETCH_MAIN'}
                    class Opener:
                        def open(self,request,timeout):
                            raise HTTPError(request.full_url,500,'synthetic',headers,BytesIO(b'PRIVATE'))
                    transport=GatewayTransport(endpoint='http://localhost:19123',opener=Opener(),
                        grant_path=str(root/'grant'),certificate_path=str(root/'cert'),read_attempts=1)
                    transport.post_paths=transport.post_paths|{route}
                    with self.assertRaises(Denied) as caught:transport.post(route,{})
                    self.assertEqual(str(caught.exception),prefix+code+'_FETCH_MAIN')
                    self.assertEqual(transient(caught.exception),retry)
                    self.assertNotIn('PRIVATE',str(caught.exception))


if __name__=='__main__':unittest.main()
