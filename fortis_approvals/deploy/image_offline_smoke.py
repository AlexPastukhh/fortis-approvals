"""Offline smoke of installed Gateway modules; no real tokens/state/network."""
import json
import sys
from pathlib import Path

# -I scripts under /opt/fortis/operator need an explicit package root.
if "__file__" in globals() and Path(__file__).parent.name == "operator":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tempfile
import uuid

from fortis_approvals.r7_unified_candidate import build_r7_unified_candidate
from fortis_approvals.incidents import IncidentCore, IncidentOwnerWebAuthn, IncidentOwnerPortal
from fortis_approvals.integrations.github.registration import register_github_integration
from fortis_approvals.integrations.github.pilot import GitHubPilotConfig, config_from_environment
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport


class FakeSonar:
    def __init__(self):
        self.calls = []

    def call(self, method, path, params):
        if method != 'GET':
            raise AssertionError('OFFLINE_UPSTREAM_WRITE_FORBIDDEN')
        self.calls.append(path)
        if path == '/api/components/search':
            return {'paging': {'total': 1, 'pageIndex': int(params['p']),
                               'pageSize': int(params['ps'])},
                    'components': [{'key': 'offline_project', 'organization': 'offline_org',
                                    'qualifier': 'TRK'}]}
        if path == '/api/qualitygates/project_status':
            return {'projectStatus': {'status': 'OK', 'conditions': []}}
        raise AssertionError('OFFLINE_UNEXPECTED_ROUTE')


def smoke():
    with tempfile.TemporaryDirectory(prefix='fortis-image-offline-') as tmp:
        state = Path(tmp) / 'private'
        state.mkdir(mode=0o700)
        remote = FakeSonar()
        grant = 'OFFLINE-ONLY-SYNTHETIC-MACHINE-GRANT-00001'
        core, _, _, ingress = build_r7_unified_candidate(
            state=state, owner_origin='http://localhost:19203',
            ingress_host='host.docker.internal:19204', ingress_grant=grant,
            sonar_transport=remote, organizations=('offline_org',),
            project_keys=('offline_project',))
        assert isinstance(core, IncidentCore)
        assert IncidentOwnerWebAuthn and IncidentOwnerPortal
        print('IMAGE_OWNER_INCIDENT_IMPORT_PASS')
        result = ingress.broker.read(grant, {
            'requestId': str(uuid.uuid4()), 'service': 'sonarcloud',
            'operation': 'get_quality_gate', 'target': 'offline_project',
            'params': {}, 'reason': 'Offline fake Sonar image smoke'})
        assert result['data']['status'] == 'OK', result
        assert '/api/qualitygates/project_status' in remote.calls
        assert 'github' not in core.adapters
        assert 'github' not in ingress.broker.read_adapters
        assert config_from_environment({}) is None
        assert GitHubPilotConfig
        assert callable(register_github_integration)
        assert GitHubAdapter and GitHubHTTPTransport
    from fortis_approvals.workflow.git_backend import GitHubGitBackend
    from fortis_approvals.workflow.runtime import install
    import subprocess
    assert subprocess.check_output(['git','--version']).startswith(b'git version ')
    assert GitHubGitBackend and install
    from fortis_approvals.extensions.cli import check_config
    from fortis_approvals.extensions.client import IntegrationClient
    from fortis_approvals.extensions.staging import ReleaseGate
    empty = check_config({'schemaVersion': 1, 'providers': {}})
    assert empty['status'] == 'READY' and empty['operations'] == []
    assert IntegrationClient and ReleaseGate
    # Exercise the exact opt-in selector and guarded composition in the
    # installed package, not just the default IncidentCore path. No real
    # credentials, listeners, owner enrollment or provider effects.
    smoke_owner_local_deny()
    smoke_owner_policy_v2()
    print('IMAGE_EXTENSIONS_OFFLINE_PASS')
    print('IMAGE_NATIVE_GIT_IMPORT_PASS')
    print('IMAGE_SONAR_OFFLINE_SMOKE_PASS')
    print('IMAGE_GITHUB_IMPORT_PASS')
    print('IMAGE_GITHUB_NOT_REGISTERED_PASS')


def smoke_owner_local_deny():
    from fortis_approvals.r7_unified_server import _owner_release_local_deny
    from fortis_approvals.extensions.runtime import ExtensionConfig
    from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
    from fortis_approvals.extensions.owner_policy_local_bundle_phase6c3 import OwnerLocalDenyInventoryPortal
    from fortis_approvals.extensions.staging import StagedOwner, StagedMachine, ReleaseGate
    from fortis_approvals.r7_unified_candidate import ACTOR
    from io import BytesIO
    config = ExtensionConfig({'schemaVersion':1,'providers':{},
                              'ownerLocalDeny':'SONAR_ACCEPT_ISSUE_V1'})
    nonce = str(uuid.uuid4())
    grant = 'OFFLINE-ONLY-SYNTHETIC-MACHINE-GRANT-00001'
    selector = _owner_release_local_deny(config, nonce, grant, 'offline-sonar-token')
    assert selector.runtime_sonar_only
    with tempfile.TemporaryDirectory(prefix='fortis-image-local-deny-') as tmp:
        root = Path(tmp)
        state = root / 'private'
        state.mkdir(mode=0o700)
        remote = FakeSonar()
        core, owner, portal, ingress = build_r7_unified_candidate(
            state=state, owner_origin='http://localhost:19203',
            ingress_host='host.docker.internal:19204', ingress_grant=grant,
            sonar_transport=remote, organizations=('offline_org',),
            project_keys=('offline_project',), extensions=config,
            local_deny_source_opt_in=selector)
        assert type(core) is LocalDenyCore
        assert type(portal) is OwnerLocalDenyInventoryPortal
        assert portal.core is core and portal.auth is owner
        assert portal._local_deny_apply.core is core
        assert portal._local_deny_apply.runtime_sonar_only
        assert ingress.base.broker.core is core
        assert core.policy_version.endswith('|owner-local-deny:0')
        assert portal._local_deny_apply.editable_coordinate((ACTOR,'sonarcloud','accept_issue','OFFLINE-1'))
        assert not portal._local_deny_apply.editable_coordinate((ACTOR,'github','push_commits','offline'))
        gate = ReleaseGate(nonce, portal._extension_runtime.digest, marker=root/'unactivated.json')
        staged_owner = StagedOwner(portal, gate)
        staged_machine = StagedMachine(ingress, ingress.base, portal._extension_runtime, gate)
        assert staged_machine.broker.core is core and not gate.ready()
        statuses = []
        body = b''.join(staged_owner({
            'REQUEST_METHOD':'POST','PATH_INFO':'/v1/owner/policy/local-deny/begin',
            'wsgi.input':BytesIO(b'')
        }, lambda status, headers: statuses.append(status)))
        assert statuses[0].startswith('403 ')
        assert json.loads(body)['error']=='RELEASE_STAGED_OWNER_WRITES_BLOCKED'
        with core._db() as db:
            assert core._local_revision(db)==0
            assert db.execute('SELECT COUNT(*) FROM owner_local_denials').fetchone()[0]==0
        assert not remote.calls
    print('IMAGE_OWNER_LOCAL_DENY_OPT_IN_PASS')


def smoke_owner_policy_v2():
    from fortis_approvals.r7_unified_server import _owner_release_unified_policy
    from fortis_approvals.extensions.runtime import ExtensionConfig
    from fortis_approvals.extensions.owner_policy_engine_v2 import UnifiedPolicyCore
    from fortis_approvals.extensions.owner_policy_editor_v2 import UnifiedPolicyPortal
    from fortis_approvals.extensions.staging import StagedOwner, ReleaseGate
    from fortis_approvals.r7_unified_candidate import ACTOR
    import sqlite3
    from io import BytesIO
    config=ExtensionConfig({'schemaVersion':1,'providers':{},'ownerPolicyEditor':'UNIFIED_V2'})
    nonce=str(uuid.uuid4())
    selector=_owner_release_unified_policy(config,nonce,lambda:'b'*64)
    grant='OFFLINE-ONLY-SYNTHETIC-MACHINE-GRANT-00001'
    pilot=GitHubPilotConfig('OfflineOwner','offline_repo',
        file_pr_branch='fortis-e2e/'+str(uuid.uuid4())+'-approve',
        ci_reads=True,native_worktree=True,required_workflows=(1,),dynamic_repositories=True)
    github=GitHubHTTPTransport('OFFLINE_TEST_TOKEN_NOT_A_REAL_SECRET_00001')
    with tempfile.TemporaryDirectory(prefix='fortis-image-owner-policy-v2-') as tmp:
        root=Path(tmp);state=root/'private';state.mkdir(mode=0o700)
        remote=FakeSonar()
        core,owner,portal,ingress=build_r7_unified_candidate(
            state=state,owner_origin='http://localhost:19203',
            ingress_host='host.docker.internal:19204',ingress_grant=grant,
            sonar_transport=remote,organizations=('offline_org',),
            project_keys=('offline_project',),extensions=config,
            github_pilot=pilot,github_transport=github,
            unified_policy_source_opt_in=selector)
        assert type(core) is UnifiedPolicyCore and type(portal) is UnifiedPolicyPortal
        assert portal.core is core and portal.editor.core is core and ingress.base.broker.core is core
        assert core.policy_version.endswith('|owner-policy-v2:0')
        choices=core.authority.choices
        assert choices[(ACTOR,'github','create_pull_request')]=={'DENY','ASK','ALLOW'}
        assert choices[(ACTOR,'github','merge_pull_request')]=={'DENY','ASK'}
        assert choices[(ACTOR,'workspace','commit')]=={'DENY','ASK','ALLOW'}
        assert choices[(ACTOR,'sonarcloud','get_quality_gate')]=={'DENY','ALLOW'}
        assert choices[(ACTOR,'sonarcloud','accept_issue')]=={'DENY','ASK'}
        assert (ACTOR,'github','push_commits') not in choices
        gate=ReleaseGate(nonce,portal._extension_runtime.digest,marker=root/'unactivated.json')
        staged=StagedOwner(portal,gate)
        statuses=[]
        body=b''.join(staged({'REQUEST_METHOD':'POST','PATH_INFO':'/v1/owner/policy/editor/begin',
            'wsgi.input':BytesIO(b'')},lambda status,headers:statuses.append(status)))
        assert statuses[0].startswith('403 ')
        assert json.loads(body)['error']=='RELEASE_STAGED_OWNER_WRITES_BLOCKED'
        assert not remote.calls
        with core._db() as db:
            assert core._snapshot(db)[0]==0
    print('IMAGE_OWNER_POLICY_V2_OPT_IN_PASS')


if __name__ == '__main__':
    smoke()
