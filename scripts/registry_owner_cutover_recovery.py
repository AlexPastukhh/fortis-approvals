"""Windows owner-only preparation of the paused Functional V1 cutover."""
import argparse
import os
from pathlib import Path
import uuid

from registry_owner_pilot_bootstrap import (
    ENDPOINT, MAX_DB, ROOT, command, docker, git, loads_strict, need, obj,
    owner_go, put, raw, read, real_dir, sha,
)
from fortis_approvals.integrations.github.gateway.forward_lineage import (
    _CUTOVER_253, _CUTOVER_254, _CUTOVER_255, _CUTOVER_RECOVERY_IMPACT,
    _POST_255_GAP, cutover_start,
)
from fortis_approvals.integrations.github.gateway.functional_review_runtime import (
    FunctionalRegistryConfiguration,
)

_ORIGINAL_CONFIG = 'e61c8cb893cc988f7e78a46a39197788094084609cd436f20b5c78351f73829a'
_PRIOR_RECOVERY_CONFIG = '581381a958f9d2736810c657524582497eea71db13fa478971e136d8c822059b'
_OPERATION = 'dfba6213-f83f-42ca-a136-d269289dcc09'


def prepare(args):
    need(os.name == 'nt' and ROOT == (Path.home()/'Repos'/'fortis-approvals').resolve(),
         'WINDOWS_OWNER_SOURCE_REQUIRED')
    session = real_dir(args.session_dir)
    need(session.name == 'pilot-bootstrap' and session.parent.name == _OPERATION
         and not session.is_relative_to(ROOT), 'CUTOVER_RECOVERY_SESSION')
    original = read(session/'functional.json', 16384)
    need(sha(original) == _ORIGINAL_CONFIG, 'CUTOVER_RECOVERY_ORIGINAL_CONFIG')
    config = loads_strict(original)
    receipt = config['bootstrapReceipt']
    need(loads_strict(read(session/'final-receipt.json', 4096)) == receipt,
         'CUTOVER_RECOVERY_ORIGINAL_RECEIPT')
    backup_root = real_dir(args.backup_dir)
    need(not backup_root.is_relative_to(ROOT) and not backup_root.is_relative_to(session.parent),
         'CUTOVER_RECOVERY_BACKUP_LOCATION')
    prefix = 'registry-' + receipt['backupId']
    backup = real_dir(backup_root/prefix)
    files = {'sqlite': (prefix+'.sqlite', MAX_DB),
             'manifest': (prefix+'.manifest.json', 12000), 'config': ('profile.json', 2048)}
    need(all(sha(read(backup/name, limit)) == receipt['fileDigests'][kind]
             for kind, (name, limit) in files.items())
         and sha(read(backup/'spec.json', 4096)) == receipt['specSha256'],
         'CUTOVER_RECOVERY_BACKUP_MISMATCH')

    readback = loads_strict(read(Path(args.gateway_readback), 4096))
    need(type(readback) is dict and set(readback) == {
        'schema', 'sourceSha', 'imageId', 'gatewaySourceDigest'}
        and readback['schema'] == 'fortis-registry-source-digest-v1',
        'CUTOVER_RECOVERY_GATEWAY_READBACK')
    recovery = {'number': args.pull_request, 'headSha': args.pull_request_head,
                'mergeSha': readback['sourceSha'], 'impact': _CUTOVER_RECOVERY_IMPACT}
    if args.post_255:
        prior = read(session/'functional-cutover-recovery.json', 16384)
        need(sha(prior) == _PRIOR_RECOVERY_CONFIG, 'CUTOVER_RECOVERY_PRIOR_CONFIG')
        prior_release = loads_strict(prior)['cutoverRecovery']['release']
        gap = {'disposition': _POST_255_GAP,
               'merges': [_CUTOVER_253, _CUTOVER_254, _CUTOVER_255, recovery]}
    else:
        gap = {'disposition': 'OWNER_REVIEWED_PRE_CAPTURE_GAP', 'merges': [_CUTOVER_253, recovery]}
    baseline = config['baseline']
    source = cutover_start(gap, baseline['baselineSha'])
    release = {'releaseNonce': str(uuid.uuid4()), 'validatorRevision': config['validatorRevision'],
               'registryImageId': args.registry_image_id, 'gatewayImageId': readback['imageId'],
               'gatewaySourceDigest': readback['gatewaySourceDigest']}
    if args.post_255:
        need(all(release[key] != prior_release[key] for key in
                 ('releaseNonce', 'registryImageId', 'gatewayImageId', 'gatewaySourceDigest')),
             'CUTOVER_RECOVERY_PRIOR_RELEASE_REUSE')
    config['cutoverRecovery'] = {'gap': gap, 'release': release}
    FunctionalRegistryConfiguration(config, read(session/'planner.key', 32),
                                    scope_digest=receipt['scopeDigest'])
    need(git('rev-parse', 'HEAD').strip().decode() == source
         and git('branch', '--show-current').strip() == b'main'
         and not git('status', '--porcelain=v1', '--untracked-files=all'),
         'SOURCE_NOT_CLEAN_EXACT_MAIN')
    parent = baseline['baselineSha']
    for row in gap['merges']:
        head, merge = row['headSha'], row['mergeSha']
        need(git('--no-replace-objects', 'rev-list', '--parents', '-n', '1', merge).decode().split()
             == [merge, parent, head]
             and git('--no-replace-objects', 'merge-base', parent, head).decode().strip() == parent
             and git('rev-parse', merge+'^{tree}') == git('rev-parse', head+'^{tree}')
             and sha(git('show', merge+':release/targets.yaml')) == baseline['catalogSha256'],
             'CUTOVER_RECOVERY_GIT_LINEAGE')
        parent = merge
    need(not os.environ.get('DOCKER_HOST')
         and os.environ.get('DOCKER_CONTEXT', 'desktop-linux') == 'desktop-linux'
         and command(['docker', 'context', 'show']).strip() == b'desktop-linux'
         and docker('context', 'inspect', 'desktop-linux', '--format',
                    '{{.Endpoints.docker.Host}}').decode().strip() == ENDPOINT,
         'CUTOVER_RECOVERY_DOCKER_CONTEXT')
    for name, user in (('registryImageId', '20002:20002'), ('gatewayImageId', '10001:10001')):
        image_id = release[name]
        image = obj('image', 'inspect', image_id)
        need(image['Id'] == image_id and image['Os'] == 'linux' and image['Architecture'] == 'amd64'
             and image['Config']['User'] == user
             and image['Config']['Labels']['org.opencontainers.image.revision'] == source,
             'CUTOVER_RECOVERY_IMAGE_PIN')

    out = session/('functional-cutover-post-255.json' if args.post_255 else 'functional-cutover-recovery.json')
    need(not out.exists() and not out.is_symlink(), 'CUTOVER_RECOVERY_CONFIG_EXISTS')
    print(raw({'sourceSha': source, 'scopeDigest': receipt['scopeDigest'],
               'instanceId': receipt['instanceId'], 'backupId': receipt['backupId'],
               **config['cutoverRecovery']}).decode())
    print('Review exact merged PRs and CI, release impact, retained backup and new immutable image IDs.')
    if args.post_255:
        print('Confirm the retained Windows readback: Registry genesis, empty capture and collector journals, original backup.')
    owner_go('POST 255 CUTOVER RECOVERY CONFIG' if args.post_255 else 'CUTOVER RECOVERY CONFIG', _OPERATION)
    data = raw(config)
    put(out, data)
    print(raw({'result': 'CUTOVER_RECOVERY_CONFIG_RETAINED', 'sourceSha': source,
               'functionalConfigSha256': sha(data), 'releaseNonce': release['releaseNonce']}).decode())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Prepare only the owner-private cutover recovery config.')
    parser.add_argument('--session-dir', required=True)
    parser.add_argument('--backup-dir', required=True)
    parser.add_argument('--gateway-readback', required=True)
    parser.add_argument('--registry-image-id', required=True)
    parser.add_argument('--post-255', action='store_true')
    parser.add_argument('--pull-request', required=True, type=int)
    parser.add_argument('--pull-request-head', required=True)
    try:
        prepare(parser.parse_args())
    except Exception as exc:
        raise SystemExit(f'CUTOVER_RECOVERY_STOP: {type(exc).__name__}: {exc}') from None
