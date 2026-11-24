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
    _CUTOVER_253, _CUTOVER_254, _CUTOVER_255, _CUTOVER_256, _CUTOVER_257, _CUTOVER_258,
    _CUTOVER_259, _CUTOVER_260, _CUTOVER_261, _CUTOVER_RECOVERY_IMPACT, _CUTOVER_HANDOVER_IMPACT,
    _POST_255_GAP, cutover_start,
)
from fortis_approvals.integrations.github.gateway.functional_review_runtime import (
    FunctionalRegistryConfiguration, _CUTOVER_259_CONFIG_SHA256,
)

_ORIGINAL_CONFIG = 'e61c8cb893cc988f7e78a46a39197788094084609cd436f20b5c78351f73829a'
_PRIOR_RECOVERY_CONFIG = '581381a958f9d2736810c657524582497eea71db13fa478971e136d8c822059b'
_POST_255_RECOVERY_CONFIG = 'dfe86abc3fa4daaedfc9c307c3722f55ee7725c07942fb2afac3e699831308b0'
_POST_256_RECOVERY_CONFIG = 'c9504883cbe9f350d68292f93c49098ab9a734d43081c2bc1fd551123cae0940'
_POST_257_RECOVERY_CONFIG = 'a3aa4d746d262233b5af59c497ae586f15ba1642d5cc992645d024828c8e2b32'
_POST_260_RECOVERY_CONFIG = 'ed5cf9d79680dfca892bf621f243df8ab480a94b963ee52c9214b8ab95e796dd'
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
    prefix = [_CUTOVER_253]
    disposition = 'OWNER_REVIEWED_PRE_CAPTURE_GAP'
    prior_releases = []
    output_name = 'functional-cutover-recovery.json'
    confirm_label = 'CUTOVER RECOVERY CONFIG'
    if any((args.post_255, args.post_256, args.post_257, args.post_258, args.post_260, args.post_261)):
        prior = read(session/'functional-cutover-recovery.json', 16384)
        need(sha(prior) == _PRIOR_RECOVERY_CONFIG, 'CUTOVER_RECOVERY_PRIOR_CONFIG')
        prior_releases.append(loads_strict(prior)['cutoverRecovery']['release'])
        prefix.extend((_CUTOVER_254, _CUTOVER_255))
        disposition = _POST_255_GAP
        output_name = 'functional-cutover-post-255.json'
        confirm_label = 'POST 255 CUTOVER RECOVERY CONFIG'
    if any((args.post_256, args.post_257, args.post_258, args.post_260, args.post_261)):
        prior = read(session/'functional-cutover-post-255.json', 16384)
        need(sha(prior) == _POST_255_RECOVERY_CONFIG, 'CUTOVER_RECOVERY_POST_255_CONFIG')
        prior_releases.append(loads_strict(prior)['cutoverRecovery']['release'])
        prefix.append(_CUTOVER_256)
        recovery['impact'] = _CUTOVER_HANDOVER_IMPACT
        output_name = 'functional-cutover-post-256.json'
        confirm_label = 'POST 256 CUTOVER RECOVERY CONFIG'
    if args.post_257 or args.post_258 or args.post_260 or args.post_261:
        prior = read(session/'functional-cutover-post-256.json', 16384)
        need(sha(prior) == _POST_256_RECOVERY_CONFIG, 'CUTOVER_RECOVERY_POST_256_CONFIG')
        prior_releases.append(loads_strict(prior)['cutoverRecovery']['release'])
        prefix.append(_CUTOVER_257)
        output_name = 'functional-cutover-post-257.json'
        confirm_label = 'POST 257 CUTOVER RECOVERY CONFIG'
    if args.post_258 or args.post_260 or args.post_261:
        prior = read(session/'functional-cutover-post-257.json', 16384)
        need(sha(prior) == _POST_257_RECOVERY_CONFIG, 'CUTOVER_RECOVERY_POST_257_CONFIG')
        prior_releases.append(loads_strict(prior)['cutoverRecovery']['release'])
        prefix.append(_CUTOVER_258)
        output_name = 'functional-cutover-post-258.json'
        confirm_label = 'POST 258 CUTOVER RECOVERY CONFIG'
    if args.post_260 or args.post_261:
        prior = read(session/'functional-cutover-post-258.json', 16384)
        need(sha(prior) == _CUTOVER_259_CONFIG_SHA256, 'CUTOVER_RECOVERY_POST_258_CONFIG')
        prior_releases.append(loads_strict(prior)['cutoverRecovery']['release'])
        prefix.extend((_CUTOVER_259, _CUTOVER_260))
        output_name = 'functional-cutover-post-260.json'
        confirm_label = 'POST 260 CUTOVER RECOVERY CONFIG'
    if args.post_261:
        prior = read(session/'functional-cutover-post-260.json', 16384)
        need(sha(prior) == _POST_260_RECOVERY_CONFIG, 'CUTOVER_RECOVERY_POST_260_CONFIG')
        prior_releases.append(loads_strict(prior)['cutoverRecovery']['release'])
        prefix.append(_CUTOVER_261)
        output_name = 'functional-cutover-post-261.json'
        confirm_label = 'POST 261 CUTOVER RECOVERY CONFIG'
    gap = {'disposition': disposition, 'merges': [*prefix, recovery]}
    baseline = config['baseline']
    source = cutover_start(gap, baseline['baselineSha'])
    release = {'releaseNonce': str(uuid.uuid4()), 'validatorRevision': config['validatorRevision'],
               'registryImageId': args.registry_image_id, 'gatewayImageId': readback['imageId'],
               'gatewaySourceDigest': readback['gatewaySourceDigest']}
    for prior_release in prior_releases:
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

    out = session/output_name
    need(not out.exists() and not out.is_symlink(), 'CUTOVER_RECOVERY_CONFIG_EXISTS')
    print(raw({'sourceSha': source, 'scopeDigest': receipt['scopeDigest'],
               'instanceId': receipt['instanceId'], 'backupId': receipt['backupId'],
               **config['cutoverRecovery']}).decode())
    print('Review exact merged PRs and CI, release impact, retained backup and new immutable image IDs.')
    if prior_releases:
        print('Confirm the retained Windows readback: Registry genesis, empty capture and collector journals, original backup.')
    owner_go(confirm_label, _OPERATION)
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
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--post-255', action='store_true')
    mode.add_argument('--post-256', action='store_true')
    mode.add_argument('--post-257', action='store_true')
    mode.add_argument('--post-258', action='store_true')
    mode.add_argument('--post-260', action='store_true')
    mode.add_argument('--post-261', action='store_true')
    parser.add_argument('--pull-request', required=True, type=int)
    parser.add_argument('--pull-request-head', required=True)
    try:
        prepare(parser.parse_args())
    except Exception as exc:
        raise SystemExit(f'CUTOVER_RECOVERY_STOP: {type(exc).__name__}: {exc}') from None
