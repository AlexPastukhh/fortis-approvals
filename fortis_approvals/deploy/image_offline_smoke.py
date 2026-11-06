"""Offline smoke of installed Gateway modules; no real tokens/state/network."""
import json
from pathlib import Path
import tempfile
import uuid

from fortis_approvals.r7_unified_candidate import build_r7_unified_candidate
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
    print('IMAGE_NATIVE_GIT_IMPORT_PASS')
    print('IMAGE_SONAR_OFFLINE_SMOKE_PASS')
    print('IMAGE_GITHUB_IMPORT_PASS')
    print('IMAGE_GITHUB_NOT_REGISTERED_PASS')


if __name__ == '__main__':
    smoke()
