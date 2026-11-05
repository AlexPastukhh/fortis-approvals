"""One typed Sonar GET through the review Gateway; no owner or provider token use."""
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path('/workspace/repo/Worktrees/fortis-approvals/candidate-origin-overrides-20261105')
ENDPOINT = 'https://host.docker.internal:19204'
PROJECT = 'AlexPastukhh_obs-planning-docs'


def run(expected_files):
    if not ROOT.is_dir() or ROOT.is_symlink():
        raise RuntimeError('REVIEW_REPO_SOURCE_ROOT_INVALID')
    for name, expected_hash in expected_files.items():
        path = ROOT / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
            raise RuntimeError('REVIEW_REPO_SOURCE_HASH_MISMATCH:' + name)
    sys.path.insert(0, str(ROOT))
    from fortis_approvals.integrations.sonarcloud.repo_client import client
    from fortis_approvals.clients import gateway_transport
    if (Path(client.__file__).resolve() != ROOT / 'fortis_approvals/integrations/sonarcloud/repo_client/client.py' or
            Path(gateway_transport.__file__).resolve() != ROOT / 'fortis_approvals/clients/gateway_transport.py'):
        raise RuntimeError('REVIEW_REPO_IMPORTED_WRONG_SOURCE')
    client.ENDPOINT = ENDPOINT
    client.ALLOW_TEST_ENDPOINTS = True
    request_id = str(uuid.uuid4())
    result = client.call('sonar.get_quality_gate', target=PROJECT, request_id=request_id)
    if (result['requestId'] != request_id or result['service'] != 'sonarcloud' or
            result['operation'] != 'get_quality_gate' or type(result['data']) is not dict):
        raise RuntimeError('REVIEW_SONAR_GET_RESPONSE_INVALID')
    print(json.dumps({'requestId': request_id, 'endpoint': ENDPOINT,
        'service': 'sonarcloud', 'operation': 'get_quality_gate',
        'qualityGateStatus': result['data'].get('status'), 'upstreamMutation': False}, sort_keys=True))
    print('FORTIS_REVIEW_MACHINE_TLS_GET_PASS')
