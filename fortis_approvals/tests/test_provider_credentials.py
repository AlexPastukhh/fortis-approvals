"""Deterministic owner-helper checks, not Docker/Windows emulation."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('provider_credentials', ROOT / 'fortis_approvals/deploy/provider_credentials.py')
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class CredentialTests(unittest.TestCase):
    def directory(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        root.chmod(0o700)
        return root

    def token(self):
        root = self.directory()
        (root / 'token').write_bytes(b'previous_fake_token_for_offline_test\n')
        (root / 'token').chmod(0o600)
        return root

    @property
    def identity(self):
        return {'uid': os.geteuid(), 'gid': os.getegid()}

    def fixture(self, service='github'):
        volume = 'fortis-github-pilot-token-' + 'a' * 32 if service == 'github' else 'fortis-r7-sonar-token'
        def container(ident, role, state='running'):
            return {'Id': ident, 'State': {'Status': state}, 'Mounts': [
                {'Type':'volume','Name':volume,'Source':'/var/lib/docker/volumes/'+volume+'/_data',
                 'Destination':HELPER.SERVICES[service],'RW':False},
                {'Type':'volume','Name':'state-'+role,'Destination':'/state','RW':True}]}
        containers = [container('review', 'review')]
        if service == 'sonarcloud':
            containers.append(container('production', 'production'))
        containers.append(container('retained', 'retained', 'exited'))
        return {'service':service,'tokenVolume':volume,'reviewId':'review','productionId':'production','containers':containers}

    def test_plan_selects_review_only_or_both_sonar_consumers(self):
        for service, roles in [('github', ['review']), ('sonarcloud', ['review','production'])]:
            with self.subTest(service=service):
                self.assertEqual([x['role'] for x in HELPER.plan(self.fixture(service))['targets']], roles)

    def test_unknown_active_reader_writer_or_bind_alias_is_rejected(self):
        for variant in ('reader', 'writer', 'bind'):
            with self.subTest(variant=variant):
                value = self.fixture()
                extra = json.loads(json.dumps(value['containers'][0])); extra['Id']='unknown'
                if variant == 'writer':extra['Mounts'][0]['RW']=True
                if variant == 'bind':
                    extra['Mounts'][0]['Type']='bind';extra['Mounts'][0].pop('Name')
                value['containers'].append(extra)
                with self.assertRaisesRegex(RuntimeError, 'CREDENTIAL_UNEXPECTED_TOKEN_'):
                    HELPER.plan(value)

    def test_wrong_volume_mount_readonly_state_missing_target_or_paused_denied(self):
        for variant in ('volume','mount','state','missing','paused'):
            with self.subTest(variant=variant):
                value=self.fixture()
                if variant=='volume':value['tokenVolume']='arbitrary'
                elif variant=='mount':value['containers'][0]['Mounts'][0]['Destination']='/wrong'
                elif variant=='state':value['containers'][0]['Mounts'][1]['RW']=False
                elif variant=='missing':value['containers']=[]
                else:value['containers'][0]['State']['Status']='paused'
                with self.assertRaisesRegex(RuntimeError, 'CREDENTIAL_'):HELPER.plan(value)

    def test_stopped_recheck_rejects_restart_or_new_consumer(self):
        value=self.fixture('sonarcloud');value['stopped']=True
        for row in value['containers']:row['State']['Status']='exited'
        self.assertEqual(len(HELPER.plan(value)['targets']),2)
        value['containers'][0]['State']['Status']='running'
        with self.assertRaises(RuntimeError):HELPER.plan(value)
        value['containers'][0]['State']['Status']='exited'
        extra=json.loads(json.dumps(value['containers'][0]));extra['Id']='unexpected';extra['State']['Status']='running'
        value['containers'].append(extra)
        with self.assertRaises(RuntimeError):HELPER.plan(value)

    def auth_response(self, data, status=200):
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,limit):return data[:limit]
        response=Response();response.status=status
        return response

    def test_auth_preflight_uses_only_fixed_get_and_does_not_return_identity(self):
        from unittest.mock import Mock
        for service,url,data in [('github','https://api.github.com/user',b'{"id":1,"login":"private-user"}'),
                ('sonarcloud','https://sonarcloud.io/api/authentication/validate',b'{"valid":true}')]:
            with self.subTest(service=service):
                opener=Mock();opener.open.return_value=self.auth_response(data)
                self.assertEqual(HELPER.validate_authentication(service,'fake_token_for_offline_authentication',opener=opener),{'authenticated':True})
                args,kwargs=opener.open.call_args
                self.assertEqual(args[0].full_url,url);self.assertEqual(args[0].method,'GET')
                self.assertEqual(kwargs['timeout'],12)

    def test_auth_rejects_invalid_oversize_or_malformed_provider_responses(self):
        from unittest.mock import Mock
        for data in [b'{"valid":false}',b'{"valid":1}',b'[]',b'null',b'{bad',b'x'*65537]:
            opener=Mock();opener.open.return_value=self.auth_response(data)
            with self.assertRaisesRegex(RuntimeError,'CREDENTIAL_AUTHENTICATION_FAILED'):
                HELPER.validate_authentication('sonarcloud','fake_token_for_offline_authentication',opener=opener)

    def test_auth_errors_never_expose_response_or_token(self):
        from unittest.mock import Mock
        opener=Mock();opener.open.side_effect=OSError('SECRET_UNTRUSTED_RESPONSE')
        with self.assertRaisesRegex(RuntimeError,'^CREDENTIAL_AUTHENTICATION_FAILED$'):
            HELPER.validate_authentication('github','fake_token_for_offline_authentication',opener=opener)

    def test_auth_http_error_and_redirect_are_denied(self):
        from unittest.mock import Mock
        opener=Mock();opener.open.return_value=self.auth_response(b'{"id":1}',302)
        with self.assertRaises(RuntimeError):HELPER.validate_authentication('github','fake_token_for_offline_authentication',opener=opener)
        with self.assertRaises(RuntimeError):HELPER.NoRedirect().redirect_request(None,None,302,'',{},'https://untrusted')

    def test_atomic_replace_changes_generation_and_preserves_private_metadata(self):
        root=self.token();before=HELPER.token_status(root,**self.identity)
        result=HELPER.replace_token(root,'github','new_fake_github_token_for_offline_test',before['generation'],**self.identity)
        self.assertEqual(result['status'],'REPLACED')
        self.assertNotEqual(result['generation'],before['generation'])
        self.assertEqual((root/'token').read_bytes(),b'new_fake_github_token_for_offline_test\n')
        self.assertEqual((root/'token').stat().st_mode & 0o777,0o600)
        self.assertEqual(set(p.name for p in root.iterdir()),{'token'})

    def test_existing_token_contents_are_never_read(self):
        root=self.token()
        with patch.object(Path,'read_bytes',side_effect=AssertionError('old secret read')):
            generation=HELPER.token_status(root,**self.identity)['generation']
            HELPER.replace_token(root,'sonarcloud','new_sonar_token',generation,**self.identity)

    def test_stale_generation_and_invalid_token_leave_original_unchanged(self):
        root=self.token();raw=(root/'token').read_bytes();generation=HELPER.token_status(root,**self.identity)['generation']
        for expected,token in [('0'*64,'new_fake_github_token_for_offline_test'),(generation,'invalid\nvalue')]:
            with self.assertRaisesRegex(RuntimeError,'CREDENTIAL_'):
                HELPER.replace_token(root,'github',token,expected,**self.identity)
            self.assertEqual((root/'token').read_bytes(),raw)
            self.assertEqual(len(list(root.iterdir())),1)

    def test_replace_failure_cleans_temp_and_keeps_old_file(self):
        root=self.token();raw=(root/'token').read_bytes();generation=HELPER.token_status(root,**self.identity)['generation']
        with patch.object(HELPER.os,'replace',side_effect=OSError('offline failure')):
            with self.assertRaises(OSError):
                HELPER.replace_token(root,'github','new_fake_github_token_for_offline_test',generation,**self.identity)
        self.assertEqual((root/'token').read_bytes(),raw)
        self.assertEqual(len(list(root.iterdir())),1)

    def test_symlinks_wrong_owner_and_world_readable_files_are_denied(self):
        root=self.token()
        with self.assertRaises(RuntimeError):HELPER.token_status(root,uid=os.geteuid()+1,gid=os.getegid())
        (root/'token').chmod(0o644)
        with self.assertRaises(RuntimeError):HELPER.token_status(root,**self.identity)
        (root/'token').unlink();(root/'token').symlink_to('/missing')
        with self.assertRaises(RuntimeError):HELPER.token_status(root,**self.identity)
        link=root/'alias';link.symlink_to(root, target_is_directory=True)
        with self.assertRaises(RuntimeError):HELPER.token_status(link,**self.identity)

    def state(self):
        root=self.directory();(root/'.fortis-r7-unified-v1').write_bytes(b'fortis-r7-unified-v1\n')
        (root/'.fortis-r7-unified-v1').chmod(0o600)
        with sqlite3.connect(root/'approvals.sqlite') as db:
            db.execute('CREATE TABLE requests(state TEXT,payload TEXT,expires_at INTEGER)')
        (root/'approvals.sqlite').chmod(0o600)
        return root

    def test_idle_check_drains_other_services_and_unknown_states_without_writes(self):
        root=self.state();now=int(time.time())
        with sqlite3.connect(root/'approvals.sqlite') as db:
            db.executemany('INSERT INTO requests VALUES(?,?,?)',[
                ('EXECUTED','{"service":"github"}',now-10),
                ('PENDING','{"service":"sonarcloud"}',now+100),
                ('DISPATCHED','{"service":"workspace"}',now-10),
                ('UNCERTAIN','{"service":"github"}',now-10),
                ('UNKNOWN','{"service":"github"}',now-10),
                ('PENDING','{"service":"github"}',now-10),
                ('APPROVED','{"service":"github"}',now-10)])
        before=(root/'approvals.sqlite').read_bytes()
        self.assertEqual(HELPER.idle_state(root,'github',**self.identity),
            {'idle':False,'blockers':{'PENDING':1,'DISPATCHED':1,'UNCERTAIN':1,'UNKNOWN':1}})
        self.assertEqual((root/'approvals.sqlite').read_bytes(),before)

    def test_terminal_and_expired_unexecuted_requests_do_not_block(self):
        root=self.state()
        with sqlite3.connect(root/'approvals.sqlite') as db:
            db.executemany('INSERT INTO requests VALUES(?,?,?)',[(x,'{"service":"github"}',0) for x in HELPER.TERMINAL|{'PENDING','APPROVED'}])
        self.assertTrue(HELPER.idle_state(root,'sonarcloud',**self.identity)['idle'])

    def test_missing_or_insecure_state_is_not_treated_as_idle(self):
        root=self.state();(root/'approvals.sqlite').chmod(0o644)
        with self.assertRaises(RuntimeError):HELPER.idle_state(root,'github',**self.identity)
        (root/'approvals.sqlite').unlink()
        with self.assertRaises(OSError):HELPER.idle_state(root,'github',**self.identity)

    def test_cli_errors_do_not_echo_secret_or_arbitrary_exception(self):
        secret='DO_NOT_EXPOSE_SECRET'
        out,err=io.StringIO(),io.StringIO()
        with patch.object(HELPER.sys,'stdin',io.StringIO(json.dumps({'action':'replace','value':secret}))), \
             contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit):HELPER.main()
        self.assertNotIn(secret,out.getvalue()+err.getvalue())
        self.assertEqual(json.loads(err.getvalue()),{'error':'CREDENTIAL_HELPER_FAILED'})


if __name__=='__main__':unittest.main()
