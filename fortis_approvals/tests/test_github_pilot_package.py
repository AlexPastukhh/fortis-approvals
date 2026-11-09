"""Offline preservation, deployment admission and resumable scenario regressions."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.repo_client.pilot_scenario import advance, new_run

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('pilot_helpers', ROOT / 'fortis_approvals/deploy/github_pilot_helpers.py')
HELPERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPERS)
SHA = 'a' * 40


class PrimaryBackupCliRegressionTests(unittest.TestCase):
    def test_primary_backup_clone_uses_two_explicit_mount_options(self):
        source = (ROOT / 'fortis_approvals/deploy/Primary-Gateway.ps1').read_text()
        backup = source.split('function Backup-Primary {', 1)[1].split('function Promote-Primary {', 1)[0]
        clone = backup.split("$Clone=State-Helper @{action='clone'", 1)[1].split(' -Root', 1)[0]
        self.assertEqual(clone.count("'--mount'"), 2, 'Docker requires --mount before each mount specification')
        self.assertIn('target=/source,readonly', clone)
        self.assertIn('target=/target', clone)

    def test_state_helper_rejects_unpaired_mount_arguments(self):
        source = (ROOT / 'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()
        helper = source.split('function State-Helper {', 1)[1].split('function Ensure-Vault {', 1)[0]
        self.assertIn('RELEASE_STATE_MOUNT_PAIR_INVALID', helper)
        self.assertIn("$Mounts[$Index] -cne '--mount'", helper)


class StateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pilot-package-offline-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source, self.target = self.root / 'source', self.root / 'target'
        self.source.mkdir(); self.target.mkdir()
        private = self.source / 'private'
        private.mkdir(mode=0o700)
        (private / HELPERS.MARKER).write_bytes(b'fortis-r7-unified-v1\n')
        with sqlite3.connect(private / 'approvals.sqlite') as db:
            db.executescript("CREATE TABLE requests(id TEXT PRIMARY KEY,state TEXT); CREATE TABLE events(value TEXT); INSERT INTO requests VALUES ('11111111-1111-4111-8111-111111111111','REJECTED'); INSERT INTO events VALUES ('preserved');")
        with sqlite3.connect(private / 'owner.sqlite') as db:
            db.executescript('CREATE TABLE config(setting TEXT,value TEXT); CREATE TABLE credentials(active INTEGER,data BLOB); CREATE TABLE invitations(data BLOB);')
            db.executemany('INSERT INTO config VALUES (?,?)', [('origin','http://localhost:19203'),('rpId','localhost'),('owner','owner')])
            db.execute('INSERT INTO credentials VALUES (?,?)', (1,b'offline public credential with counter'))
            db.execute('INSERT INTO invitations VALUES (?)', (b'offline invitation',))
        with sqlite3.connect(private / 'sonar-receipts.sqlite') as db:
            db.executescript("CREATE TABLE receipts(value TEXT); INSERT INTO receipts VALUES ('preserved');")
        for path in private.iterdir(): path.chmod(0o600)
        self.identity = {'uid': os.geteuid(), 'gid': os.getegid()}

    def test_clone_preserves_all_bytes_binding_credentials_history_and_permissions(self):
        receipt = HELPERS.clone_state(self.source, self.target, **self.identity)
        self.assertEqual(receipt, HELPERS.inspect_state(self.source, **self.identity))
        self.assertEqual(receipt, HELPERS.inspect_state(self.target, **self.identity))
        for name in HELPERS.FILES:
            self.assertEqual((self.source/'private'/name).read_bytes(), (self.target/'private'/name).read_bytes())
        self.assertEqual(receipt['summary']['credentialsActive'], 1)
        self.assertEqual(receipt['summary']['requests'], 1)

    def test_clone_of_accepted_github_pilot_preserves_provider_receipt_bytes(self):
        github=self.source/'private'/'github-receipts.sqlite'
        with sqlite3.connect(github) as db:
            db.execute('CREATE TABLE receipts(request_id TEXT,result TEXT)')
            db.execute('INSERT INTO receipts VALUES (?,?)',('offline-request','offline-receipt'))
        github.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError,'UNKNOWN_FILES'):
            HELPERS.inspect_state(self.source,**self.identity)
        receipt=HELPERS.clone_state(self.source,self.target,github=True,**self.identity)
        self.assertEqual(receipt['summary']['githubReceipts'],1)
        self.assertEqual(github.read_bytes(),(self.target/'private'/'github-receipts.sqlite').read_bytes())

    def test_existing_target_is_not_overwritten(self):
        sentinel = self.target/'keep'
        sentinel.write_text('preserve')
        with self.assertRaisesRegex(RuntimeError, 'TARGET_NOT_EMPTY'):
            HELPERS.clone_state(self.source, self.target, **self.identity)
        self.assertEqual(sentinel.read_text(), 'preserve')

    def test_journal_or_unfinished_request_blocks_copy_before_target_write(self):
        journal=self.source/'private'/'owner.sqlite-journal'
        journal.write_bytes(b'offline journal')
        with self.assertRaisesRegex(RuntimeError, 'UNKNOWN_FILES_OR_JOURNAL'):
            HELPERS.clone_state(self.source, self.target, **self.identity)
        self.assertEqual(list(self.target.iterdir()), [])
        journal.unlink()
        with sqlite3.connect(self.source/'private'/'approvals.sqlite') as db:
            db.execute("INSERT INTO requests VALUES (?,?)",('22222222-2222-4222-8222-222222222222','DISPATCHED'))
        with self.assertRaisesRegex(RuntimeError, 'UNFINISHED_REQUESTS'):
            HELPERS.clone_state(self.source, self.target, **self.identity)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_uncertain_requires_exact_owner_scope_and_copies_only_same_bytes(self):
        unknown='55555555-5555-4555-8555-555555555555'
        another='66666666-6666-4666-8666-666666666666'
        with sqlite3.connect(self.source/'private'/'approvals.sqlite') as db:
            db.execute('INSERT INTO requests VALUES (?,?)',(unknown,'UNCERTAIN'))
        with self.assertRaisesRegex(RuntimeError,'UNREVIEWED_UNCERTAIN'):
            HELPERS.inspect_state(self.source,**self.identity)
        with self.assertRaisesRegex(RuntimeError,'UNREVIEWED_UNCERTAIN'):
            HELPERS.inspect_state(self.source,preserve_uncertain_ids=[another],**self.identity)
        with self.assertRaisesRegex(RuntimeError,'UNCERTAIN_SET_CHANGED'):
            HELPERS.inspect_state(self.source,preserve_uncertain_ids=[unknown,another],
                                  require_exact_uncertain=True,**self.identity)
        self.assertEqual(HELPERS.inspect_state(
            self.source,preserve_uncertain_ids=[unknown],require_exact_uncertain=True,
            **self.identity)['summary']['uncertainRequestIds'],[unknown])
        with self.assertRaisesRegex(RuntimeError,'UNREVIEWED_UNCERTAIN'):
            HELPERS.clone_state(self.source,self.target,**self.identity)
        self.assertEqual(list(self.target.iterdir()),[])
        copied=HELPERS.clone_state(self.source,self.target,
                                  preserve_uncertain_ids=[unknown],**self.identity)
        self.assertEqual(copied['summary']['uncertainRequestIds'],[unknown])
        self.assertEqual(
            (self.source/'private'/'approvals.sqlite').read_bytes(),
            (self.target/'private'/'approvals.sqlite').read_bytes())
        with sqlite3.connect(self.target/'private'/'approvals.sqlite') as db:
            self.assertEqual(db.execute('SELECT state FROM requests WHERE id=?',
                                        (unknown,)).fetchone()[0],'UNCERTAIN')

    def test_uncertain_opt_in_rejects_active_execution_and_invalid_ids(self):
        unknown='55555555-5555-4555-8555-555555555555'
        with sqlite3.connect(self.source/'private'/'approvals.sqlite') as db:
            db.executemany('INSERT INTO requests VALUES (?,?)',[(unknown,'UNCERTAIN'),
                ('77777777-7777-4777-8777-777777777777','PENDING')])
        with self.assertRaisesRegex(RuntimeError,'UNFINISHED_REQUESTS'):
            HELPERS.inspect_state(self.source,preserve_uncertain_ids=[unknown],**self.identity)
        for bad in ([unknown,unknown],['not-a-uuid'],[],['11111111-1111-4111-8111-111111111111',5]):
            if not bad:continue
            with self.assertRaisesRegex(RuntimeError,'UNCERTAIN_SCOPE_INVALID'):
                HELPERS.inspect_state(self.source,preserve_uncertain_ids=bad,**self.identity)

    def test_private_credential_is_not_echoed_and_existing_volume_is_not_adopted(self):
        volume=self.root/'credential'; volume.mkdir()
        token='OFFLINE_SYNTHETIC_CREDENTIAL_00000000001'
        result=HELPERS.provision_token(token,volume,**self.identity)
        self.assertNotIn(token,json.dumps(result))
        self.assertEqual((volume/'token').stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(RuntimeError,'VOLUME_NOT_EMPTY'):
            HELPERS.provision_token(token,volume,**self.identity)


    def test_receipt_requires_owner_approved_core_execution(self):
        root=self.root/'receipt-check';root.mkdir()
        ident='11111111-1111-4111-8111-111111111111'
        expected=dict(requestId=ident,operation='create_branch',repository='sandbox',branch='fortis-e2e/test',sha=SHA)
        with sqlite3.connect(root/'github-receipts.sqlite') as db:
            db.execute('CREATE TABLE receipts(request_id TEXT,result TEXT)')
            db.execute('INSERT INTO receipts VALUES (?,?)',(ident,json.dumps(expected)))
        payload=dict(service='github',operation='create_branch',target='sandbox',params={'branch':'fortis-e2e/test','sourceSha':SHA})
        with sqlite3.connect(root/'approvals.sqlite') as db:
            db.execute('CREATE TABLE requests(id TEXT,state TEXT,payload TEXT,decision TEXT,owner TEXT)')
            db.execute('INSERT INTO requests VALUES (?,?,?,?,?)',(ident,'EXECUTED',json.dumps(payload),'approve','owner'))
        self.assertTrue(HELPERS.verify_receipt(ident,'sandbox','fortis-e2e/test',SHA,root)['ownerDecisionVerified'])
        with sqlite3.connect(root/'approvals.sqlite') as db:db.execute('UPDATE requests SET decision=NULL')
        with self.assertRaisesRegex(RuntimeError,'OWNER_EXECUTION_NOT_CONFIRMED'):
            HELPERS.verify_receipt(ident,'sandbox','fortis-e2e/test',SHA,root)


class AdmissionTests(unittest.TestCase):
    def fixture(self):
        ident='1'*32
        expected=dict(id='a'*64,name='fortis-github-pilot-'+ident,image='sha256:'+'b'*64,
            stateVolume='fortis-github-pilot-state-'+ident,tokenVolume='fortis-github-pilot-token-'+ident,
            owner='PilotOwner',repository='sandbox',status='created')
        mounts=[dict(Type='volume',Name=expected['stateVolume'],Destination='/state',RW=True)]
        mounts += [dict(Type='volume',Name=name,Destination=path,RW=False) for name,path in HELPERS.CREDENTIALS.items()]
        mounts += [dict(Type='volume',Name=expected['tokenVolume'],Destination='/run/github-token',RW=False)]
        for mount in mounts:mount['Source']='/var/lib/docker/volumes/'+mount['Name']+'/_data'
        env=dict(FORTIS_OWNER_ORIGIN='http://localhost:19203',FORTIS_MACHINE_HOST='host.docker.internal:19204',
            FORTIS_SONAR_REGION='eu',FORTIS_SONAR_ORGANIZATIONS='alexpastukhh',FORTIS_SONAR_PROJECT_KEY='AlexPastukhh_obs-planning-docs',
            FORTIS_GITHUB_PILOT='1',FORTIS_GITHUB_OWNER='PilotOwner',FORTIS_GITHUB_REPOSITORY='sandbox',FORTIS_GITHUB_BRANCH_PREFIX='fortis-e2e/')
        c=dict(Id=expected['id'],Name='/'+expected['name'],Image=expected['image'],Mounts=mounts,
            State={'Status':'created'},Config=dict(User='10001:10001',WorkingDir='/opt/fortis',
                Cmd=['python','-m','fortis_approvals.r7_unified_server'],Entrypoint=None,
                Env=[k+'='+v for k,v in env.items()],Healthcheck=dict(Test=['CMD-SHELL','python -m fortis_approvals.r7_unified_server health'],
                Interval=20000000000,Timeout=5000000000,StartPeriod=20000000000,Retries=3)),
            HostConfig=dict(ReadonlyRootfs=True,Privileged=False,AutoRemove=False,Init=True,CapDrop=['ALL'],CapAdd=None,
                SecurityOpt=['no-new-privileges:true'],NetworkMode='bridge',PidsLimit=100,Memory=536870912,
                MemorySwap=1073741824,ShmSize=67108864,Tmpfs={'/tmp':'rw,nosuid,nodev,size=16m'},
                RestartPolicy={'Name':'no','MaximumRetryCount':0},PortBindings={
                '19103/tcp':[{'HostIp':'127.0.0.1','HostPort':'19203'}],
                '19104/tcp':[{'HostIp':'127.0.0.1','HostPort':'19204'}]},IpcMode='private'))
        return c,expected

    def test_exact_pilot_is_admitted(self):
        c,e=self.fixture()
        self.assertEqual(HELPERS.admit(c,e,pilot=True),{'admission':'PASS'})

    def test_primary_restart_requires_exact_name_and_policy(self):
        c,e=self.fixture()
        c['Name']='/fortis-gateway'
        c['HostConfig']['RestartPolicy']={'Name':'unless-stopped','MaximumRetryCount':0}
        e['name']='fortis-gateway';e['restartPolicy']='unless-stopped'
        self.assertEqual(HELPERS.admit(c,e,pilot=True),{'admission':'PASS'})
        for mutate in (lambda: e.update(name='fortis-other'),
                       lambda: e.update(restartPolicy='always'),
                       lambda: c['HostConfig']['RestartPolicy'].update(Name='always')):
            c,e=self.fixture()
            c['Name']='/fortis-gateway';e['name']='fortis-gateway';e['restartPolicy']='unless-stopped'
            c['HostConfig']['RestartPolicy']={'Name':'unless-stopped','MaximumRetryCount':0}
            mutate()
            with self.assertRaises(RuntimeError):HELPERS.admit(c,e,pilot=True)

    def test_ci_runtime_environment_is_explicit_and_requires_file_pr_scope(self):
        c,e=self.fixture();e['ciReads']=True
        with self.assertRaisesRegex(RuntimeError,'CI_REQUIRES_FILE_PR'):HELPERS.admit(c,e,pilot=True)
        e['filePrBranch']='fortis-e2e/11111111-1111-4111-8111-111111111111-approve'
        with self.assertRaisesRegex(RuntimeError,'PUBLIC_CONFIGURATION'):HELPERS.admit(c,e,pilot=True)
        c['Config']['Env'] += ['FORTIS_GITHUB_FILE_PR_BRANCH='+e['filePrBranch'],'FORTIS_GITHUB_CI_READS=1']
        self.assertEqual(HELPERS.admit(c,e,pilot=True),{'admission':'PASS'})

    def test_native_runtime_scope_and_required_workflow_are_explicit(self):
        c,e=self.fixture()
        e.update(filePrBranch='fortis-e2e/11111111-1111-4111-8111-111111111111-approve',ciReads=True,
                 nativeWorktree=True,requiredWorkflows='408327525',bootstrapTask='source-bootstrap')
        c['Config']['Env'] += ['FORTIS_GITHUB_FILE_PR_BRANCH='+e['filePrBranch'],'FORTIS_GITHUB_CI_READS=1']
        with self.assertRaisesRegex(RuntimeError,'PUBLIC_CONFIGURATION'):HELPERS.admit(c,e,pilot=True)
        c['Config']['Env'] += ['FORTIS_GITHUB_NATIVE_WORKTREE=1','FORTIS_GITHUB_REQUIRED_WORKFLOWS=408327525',
                               'FORTIS_GITHUB_BOOTSTRAP_TASK=source-bootstrap']
        self.assertEqual(HELPERS.admit(c,e,pilot=True),{'admission':'PASS'})
        e['requiredWorkflows']='1'
        with self.assertRaisesRegex(RuntimeError,'NATIVE_CONFIGURATION'):HELPERS.admit(c,e,pilot=True)

    def test_dynamic_repository_flag_requires_exact_protected_expected_environment(self):
        c,e=self.fixture()
        e.update(filePrBranch='fortis-e2e/11111111-1111-4111-8111-111111111111-approve',
                 ciReads=True,nativeWorktree=True,requiredWorkflows='408327525',
                 bootstrapTask='source-bootstrap')
        c['Config']['Env'] += [
            'FORTIS_GITHUB_FILE_PR_BRANCH='+e['filePrBranch'], 'FORTIS_GITHUB_CI_READS=1',
            'FORTIS_GITHUB_NATIVE_WORKTREE=1', 'FORTIS_GITHUB_REQUIRED_WORKFLOWS=408327525',
            'FORTIS_GITHUB_BOOTSTRAP_TASK=source-bootstrap']
        # Legacy primary remains valid with the flag entirely absent.
        self.assertEqual(HELPERS.admit(c,e,pilot=True),{'admission':'PASS'})
        # An operator cannot silently opt in without the protected release record.
        c['Config']['Env'].append('FORTIS_GITHUB_NATIVE_MULTI_REPO=1')
        with self.assertRaisesRegex(RuntimeError,'PILOT_PUBLIC_CONFIGURATION_MISMATCH'):
            HELPERS.admit(c,e,pilot=True)
        # A protected opt-in is invalid until exactly the expected env exists.
        e['dynamicRepositories']=True
        self.assertEqual(HELPERS.admit(c,e,pilot=True),{'admission':'PASS'})
        c['Config']['Env'][-1]='FORTIS_GITHUB_NATIVE_MULTI_REPO=0'
        with self.assertRaisesRegex(RuntimeError,'PILOT_PUBLIC_CONFIGURATION_MISMATCH'):
            HELPERS.admit(c,e,pilot=True)
        c['Config']['Env'][-1]='FORTIS_GITHUB_NATIVE_MULTI_REPO=1'
        c['Config']['Env'].append('FORTIS_GITHUB_NATIVE_MULTI_REPO=1')
        with self.assertRaisesRegex(RuntimeError,'PILOT_DUPLICATE_ENVIRONMENT'):
            HELPERS.admit(c,e,pilot=True)
        c['Config']['Env'].pop()
        e['dynamicRepositories']='true'
        with self.assertRaisesRegex(RuntimeError,'PILOT_DYNAMIC_REPOSITORIES_CONFIGURATION_INVALID'):
            HELPERS.admit(c,e,pilot=True)
        e['dynamicRepositories']=True
        e['nativeWorktree']=False
        with self.assertRaisesRegex(RuntimeError,'PILOT_DYNAMIC_REPOSITORIES_CONFIGURATION_INVALID'):
            HELPERS.admit(c,e,pilot=True)

    def test_ci_control_scope_requires_record_and_exact_public_environment(self):
        c,e=self.fixture()
        e.update(filePrBranch='fortis-e2e/11111111-1111-4111-8111-111111111111-approve',
                 ciReads=True,nativeWorktree=True,requiredWorkflows='408327525',
                 bootstrapTask='source-bootstrap',dynamicRepositories=True)
        c['Config']['Env']+=['FORTIS_GITHUB_FILE_PR_BRANCH='+e['filePrBranch'],
            'FORTIS_GITHUB_CI_READS=1','FORTIS_GITHUB_NATIVE_WORKTREE=1',
            'FORTIS_GITHUB_REQUIRED_WORKFLOWS=408327525',
            'FORTIS_GITHUB_BOOTSTRAP_TASK=source-bootstrap',
            'FORTIS_GITHUB_NATIVE_MULTI_REPO=1']
        self.assertEqual(HELPERS.admit(c,e,pilot=True),{'admission':'PASS'})
        c['Config']['Env'].append('FORTIS_GITHUB_CI_CONTROL_REPOSITORIES=rd-graphs')
        with self.assertRaisesRegex(RuntimeError,'PUBLIC_CONFIGURATION_MISMATCH'):
            HELPERS.admit(c,e,pilot=True)
        e['ciControlRepositories']='rd-graphs'
        self.assertEqual(HELPERS.admit(c,e,pilot=True),{'admission':'PASS'})
        c['Config']['Env'][-1]='FORTIS_GITHUB_CI_CONTROL_REPOSITORIES=other'
        with self.assertRaisesRegex(RuntimeError,'PUBLIC_CONFIGURATION_MISMATCH'):
            HELPERS.admit(c,e,pilot=True)
        c['Config']['Env'][-1]='FORTIS_GITHUB_CI_CONTROL_REPOSITORIES=rd-graphs'
        e['ciControlRepositories']='rd-graphs,rd-graphs'
        with self.assertRaisesRegex(RuntimeError,'PILOT_CI_CONTROL_CONFIG_INVALID'):
            HELPERS.admit(c,e,pilot=True)
        e['ciControlRepositories']='rd-graphs'
        e['dynamicRepositories']=False
        c['Config']['Env'].remove('FORTIS_GITHUB_NATIVE_MULTI_REPO=1')
        e['nativeWorktree']=False
        with self.assertRaisesRegex(RuntimeError,'PILOT_CI_CONTROL_REQUIRES_NATIVE'):
            HELPERS.admit(c,e,pilot=True)

    def test_production_state_writable_credentials_and_exposed_ports_are_denied(self):
        for mutate in (lambda c:c['Mounts'][0].update(Name='fortis-r7-state'),
                       lambda c:c['Mounts'][-1].update(RW=True),
                       lambda c:c['HostConfig']['PortBindings']['19104/tcp'][0].update(HostIp='0.0.0.0'),
                       lambda c:c['HostConfig'].update(Privileged=True)):
            c,e=self.fixture();mutate(c)
            with self.assertRaises(RuntimeError):HELPERS.admit(c,e,pilot=True)

    def test_unhealthy_rollback_relaxes_only_health_not_mount_admission(self):
        c,e=self.fixture();c['State']={'Status':'running','Health':{'Status':'unhealthy'}};e['status']='running'
        with self.assertRaisesRegex(RuntimeError,'NOT_HEALTHY'):HELPERS.admit(c,e,pilot=True)
        e['requireHealthy']=False
        HELPERS.admit(c,e,pilot=True)
        c['Mounts'][-1]['RW']=True
        with self.assertRaises(RuntimeError):HELPERS.admit(c,e,pilot=True)


class ScenarioClient:
    def __init__(self):
        self.refs={'main':SHA};self.requests={};self.lose_reply=False
    def get_repository(self,repo):return {'repository':dict(full_name='PilotOwner/sandbox',default_branch='main',archived=False,disabled=False)}
    def list_branches(self,repo,**kwargs):return {'items':[{'name':name,'sha':sha} for name,sha in self.refs.items()]}
    def create_branch(self,repo,branch,sha,*,request_id,reason):
        if request_id not in self.requests:self.requests[request_id]=dict(state='PENDING',branch=branch,sha=sha,reason=reason)
        row=self.requests[request_id]
        assert (row['branch'],row['sha'],row['reason'])==(branch,sha,reason)
        if self.lose_reply:self.lose_reply=False;raise TimeoutError('offline lost submit response')
        return {'requestId':request_id,'state':row['state']}
    def status(self,ident):return {'requestId':ident,'state':self.requests[ident]['state']}
    def decide(self,ident,state):
        row=self.requests[ident];row['state']=state
        if state in ('EXECUTED','UNCERTAIN'):self.refs[row['branch']]=row['sha']


class ScenarioTests(unittest.TestCase):
    def run_to_approve(self):
        client=ScenarioClient();state=new_run('PilotOwner','sandbox')
        state=advance(state,client)['state'];state=advance(state,client)['state']
        self.assertEqual(advance(state,client)['awaitOwner']['decision'],'reject')
        client.decide(state['reject']['requestId'],'REJECTED')
        state=advance(state,client)['state'];state=advance(state,client)['state']
        return client,state

    def test_pinned_sha_and_completed_replay(self):
        client,state=self.run_to_approve();client.refs['main']='b'*40
        client.decide(state['approve']['requestId'],'EXECUTED')
        result=advance(state,client)
        self.assertTrue(result['complete']);self.assertEqual(result['state']['sourceSha'],SHA)
        self.assertEqual(len(client.requests),2)

    def test_lost_submit_response_reuses_the_same_request(self):
        client=ScenarioClient();state=advance(new_run('PilotOwner','sandbox'),client)['state']
        client.lose_reply=True
        with self.assertRaises(TimeoutError):advance(state,client)
        result=advance(state,client)
        self.assertEqual(result['state']['reject']['requestId'],state['reject']['requestId'])
        self.assertEqual(len(client.requests),1)

    def test_uncertain_result_stops_without_new_request(self):
        client,state=self.run_to_approve();client.decide(state['approve']['requestId'],'UNCERTAIN')
        with self.assertRaisesRegex(Denied,'RECONCILIATION_REQUIRED'):advance(state,client)
        self.assertEqual(len(client.requests),2)
