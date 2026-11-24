"""Owner-run Windows Functional V1 genesis workflow. Never runs from Repo AI.

Uses existing owner bootstrap for Preview/Provision and a separate, inactive
backup/restore readback. No automatic retry, mount adoption, rebuild or grants.
Requires Python 3.11+, existing Windows clean source, private evidence/backup
areas and the owner's independently selected component/resource mapping.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fortis_approvals.core import canonical, loads_strict
from fortis_approvals.integrations.github.gateway.p5_ci_binding import policy
from fortis_approvals.registry.state_journal import _scope

# Closed catalog projection for this pilot. Drift stops rather than guessing
# new targets or physical topology. Raw Git blob, not checkout CRLF bytes.
CATALOG_SHA = 'c277e85bdf54deb37679de535ff58e08017314af8b370ffea2ded741f038561a'
TARGETS = {'fortis-gateway': 'production', 'fortis-registry-pilot': 'non-production',
           'gateway-owner-controller': 'windows-owner', 'release-label-publisher': 'production'}
REPOSITORY = 'AlexPastukhh/fortis-approvals'
ENDPOINT = 'npipe:////./pipe/dockerDesktopLinuxEngine'
REVIEW_PINS = {'Prepare': 'fbffabc359fa7460b1a0be36a34f4df3fc3612fc5acd4ad1b1abe27177be911a',
               'Inspect': '13a1b4475cc1021965478f0328b534074977076390c1f8781602eca7e06da502'}
RECEIPT_PINS = {'Prepare': '2ca5fb4e93469e8795ff4baf9f7ae10e2530ada071391687890bc789b3e7838d',
                'Inspect': 'e18ee5aa3698a42a541641e5344a281a66eeb24e0e46c79616df09ad0d22c6f6'}
MAX_DB = 2_000_000
DIAGNOSTIC_DIR = None


def need(ok, marker):
    if not ok:
        raise RuntimeError(marker)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def raw(value):
    return canonical(value).encode('ascii')


def pin(value, n=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % n, value) is not None


def ident(value):
    return isinstance(value, str) and re.fullmatch('[a-z0-9][a-z0-9._/-]{0,127}', value) is not None and '//' not in value and '..' not in value


def checked_mapping(mapping):
    need(type(mapping) is dict and set(mapping) == {'bindings', 'components'}, 'MAPPING_FIELDS')
    bindings, components = mapping['bindings'], mapping['components']
    need(type(bindings) is list and type(components) is list and len(bindings) == len(components) == len(TARGETS), 'MAPPING_COUNT')
    graph = {}
    for row in components:
        need(type(row) is dict and set(row) == {'id', 'resources', 'requires'} and ident(row['id']) and row['id'] not in graph, 'MAPPING_COMPONENT')
        for key in ('resources', 'requires'):
            values = row[key]
            need(type(values) is list and (key != 'resources' or values) and all(ident(v) for v in values) and values == sorted(set(values)), 'MAPPING_LIST')
        graph[row['id']] = row
    used, targets = set(), set()
    for row in bindings:
        need(type(row) is dict and set(row) == {'targetId', 'environment', 'componentId'} and row['targetId'] in TARGETS and row['targetId'] not in targets and row['environment'] == TARGETS[row['targetId']] and row['componentId'] in graph and row['componentId'] not in used, 'MAPPING_TARGET')
        used.add(row['componentId']); targets.add(row['targetId'])
    def visit(key, active):
        need(key in graph and key not in active, 'MAPPING_CYCLE_OR_UNKNOWN')
        for child in graph[key]['requires']:
            visit(child, active | {key})
    for key in graph:
        visit(key, set())
    return {'bindings': sorted(bindings, key=lambda x: x['targetId']),
            'components': sorted(components, key=lambda x: x['id'])}


def compose(proposal, approved_at):
    """Pure scope composition; approval is the caller's actual owner review.

    Acceptance reference is explicitly pilot-only, NOT accepted live enrollment.
    Do not use it as authority for E2 ingestion or production release.
    """
    mapping = checked_mapping(proposal['mapping'])
    need(pin(proposal['baselineSha'], 40) and proposal['catalogSha256'] == CATALOG_SHA, 'PILOT_BASELINE')
    for key in ('instanceId', 'enrollmentId'):
        need(str(uuid.UUID(proposal[key])) == proposal[key], 'PILOT_UUID')
    need(type(approved_at) is int and approved_at > 0 and type(proposal['maxReviewToMergeSeconds']) is int and 0 < proposal['maxReviewToMergeSeconds'] <= 86400 and type(proposal['clockToleranceSeconds']) is int and 0 <= proposal['clockToleranceSeconds'] <= 60, 'PILOT_POLICY_LIMITS')
    need(proposal['profile'] == policy(), 'PILOT_POLICY_PROFILE_CHANGED')
    acceptance = {'schemaVersion': 1, 'decision': 'OWNER_PILOT_SCOPE_ONLY',
                  'approvedAt': approved_at, 'proposalDigest': sha(raw(proposal)),
                  'enrollmentAccepted': False, 'admissionAllowed': False}
    common = {'schemaVersion': 1, 'repository': REPOSITORY, 'enrollmentId': proposal['enrollmentId'], 'baselineSha': proposal['baselineSha']}
    binding = {**common, 'catalogSha256': CATALOG_SHA, **mapping}
    baseline = {**common, 'catalogSha256': CATALOG_SHA, 'bindingDigest': sha(raw(binding)), 'acceptanceReceiptDigest': sha(raw(acceptance))}
    reference = {**common, 'revision': 1, 'previousDigest': '0'*64,
                 'acceptanceReceiptDigest': sha(raw(acceptance)), 'effectiveAt': approved_at,
                 'maxReviewToMergeSeconds': proposal['maxReviewToMergeSeconds'],
                 'clockToleranceSeconds': proposal['clockToleranceSeconds'], 'profile': proposal['profile']}
    scope = _scope({**{k: baseline[k] for k in ('repository','enrollmentId','baselineSha','catalogSha256','bindingDigest')},
                    'baselineDigest': sha(raw(baseline)), 'policyReferenceDigest': sha(raw(reference))})
    spec = {'schemaVersion': 1, 'instanceId': proposal['instanceId'], 'scope': scope,
            'registryUid': 20002, 'registryGid': 20002, 'readerUid': 10001, 'readerGid': 10001}
    return {'proposal.json': proposal, 'pilot-acceptance.json': acceptance, 'binding.json': binding,
            'baseline.json': baseline, 'policy-reference.json': reference, 'spec.json': spec}


def command(args, data=None):
    # No shell, fetch, credential lookup or Docker context fallback.
    p = subprocess.run(args, cwd=ROOT, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    if p.returncode:
        # Save bounded diagnostics privately, not to the chat/console.
        if DIAGNOSTIC_DIR is not None:
            put(DIAGNOSTIC_DIR / 'native-failure.json', raw({'program':Path(args[0]).name,'exitCode':p.returncode,'stdoutBase64':b64(p.stdout[:65536]),'stderrBase64':b64(p.stderr[:65536])}))
        raise RuntimeError('NATIVE_EXIT_%d_%s_STOP_NO_RETRY' % (p.returncode, Path(args[0]).name))
    if len(p.stdout) > 3_000_000 or p.stderr:
        if DIAGNOSTIC_DIR is not None:
            put(DIAGNOSTIC_DIR / 'native-failure.json', raw({'program':Path(args[0]).name,'exitCode':p.returncode,'stderrBase64':b64(p.stderr[:65536])}))
        raise RuntimeError('NATIVE_OUTPUT_UNEXPECTED_STOP')
    return p.stdout


def git(*args):
    return command(['git', '-C', str(ROOT), *args])


def docker(*args, data=None):
    return command(['docker', '--context', 'desktop-linux', *args], data)


def obj(*args):
    return loads_strict(docker(*args, '--format', '{{json .}}'))


def real_dir(path):
    path = Path(path)
    need(path.is_absolute() and path.is_dir(), 'OWNER_DIRECTORY_REQUIRED')
    for p in (path, *path.parents):
        st = p.lstat()
        need(not p.is_symlink() and not getattr(st, 'st_file_attributes', 0) & 0x400, 'OWNER_DIRECTORY_REPARSE')
    return path.resolve()


def read(path, limit):
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and not getattr(st, 'st_file_attributes', 0) & 0x400 and 0 < st.st_size <= limit, 'OWNER_FILE_INVALID')
    result = path.read_bytes()
    need(len(result) == st.st_size, 'OWNER_FILE_CHANGED')
    return result


def put(path, data):
    with path.open('xb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    need(read(path, len(data)) == data, 'OWNER_FILE_READBACK')


def reviewed(evidence):
    records = {}
    for phase in ('Prepare', 'Inspect'):
        data = read(evidence / (phase.lower() + '-review.json'), 16384)
        need(sha(data) == REVIEW_PINS[phase], 'VOLUME_REVIEW_PIN')
        records[phase] = loads_strict(data)
        need(records[phase]['decision'] == phase, 'VOLUME_REVIEW_PHASE')
        log = read(evidence / 'retained-helper-receipts' / (phase+'.log'), 16384)
        need(sha(log) == RECEIPT_PINS[phase], 'VOLUME_RECEIPT_PIN')
    p, i = records.values()
    need({**p, 'decision': 'Inspect'} == i and p['operationId'] == evidence.name and p['context'] == 'desktop-linux' and p['dockerEndpoint'] == ENDPOINT, 'VOLUME_REVIEW_SCOPE')
    for filename, field in (('host-identity.txt','hostIdentityEvidenceSha256'), ('writer-fence.txt','exclusiveWriterFenceEvidenceSha256'), ('image-provenance.txt','imageProvenanceEvidenceSha256')):
        need(sha(read(evidence/filename, 1048576)) == p[field], 'OWNER_EVIDENCE_PIN')
    return p


def preflight(review, source):
    need(pin(source, 40) and git('rev-parse','HEAD').decode().strip() == source and git('branch','--show-current').strip() == b'main' and not git('status','--porcelain=v1','--untracked-files=all'), 'SOURCE_NOT_CLEAN_EXACT_MAIN')
    need(sha(git('show','HEAD:release/targets.yaml')) == CATALOG_SHA, 'CATALOG_DRIFT_STOP')
    need(not os.environ.get('DOCKER_HOST') and os.environ.get('DOCKER_CONTEXT','desktop-linux') == 'desktop-linux' and command(['docker','context','show']).strip() == b'desktop-linux', 'DOCKER_CONTEXT_CHANGED')
    need(docker('context','inspect','desktop-linux','--format','{{.Endpoints.docker.Host}}').decode().strip() == ENDPOINT, 'DOCKER_ENDPOINT_CHANGED')
    need(docker('info','--format','{{.OSType}}').strip() == b'linux', 'DOCKER_ENGINE_CHANGED')
    img = obj('image','inspect',review['registryImageId'])
    need(img['Id'] == review['registryImageId'] and img['Config']['User'] == '20002:20002' and img['Os'] == 'linux' and img['Architecture'] == 'amd64' and img['Config']['Labels']['org.opencontainers.image.revision'] == review['imageSourceSha'] and not img['Config'].get('Volumes'), 'IMAGE_PIN_CHANGED')
    for name, key, user in (('fortis-gateway','gateway','10001:10001'),('fortis-repo-test','repo','1000:1000')):
        c = obj('container','inspect',name); h = c['HostConfig']
        need(c['Id'] == review[key+'ContainerId'] and c['Image'] == review[key+'ImageId'] and c['Config']['User'] == user and c['State']['Status'] == 'running' and h['ReadonlyRootfs'] and not h['Privileged'] and not h['PidMode'] and not h['UsernsMode'] and any(x in ('no-new-privileges','no-new-privileges:true') for x in h['SecurityOpt']), 'PEER_BASELINE_CHANGED')
        if key == 'gateway': need(c['State']['Health']['Status'] == 'healthy', 'GATEWAY_NOT_HEALTHY')
    names = volume_names(review)
    paths = []
    for name in names:
        v = obj('volume','inspect',name)
        need(v['Name'] == name and v['Driver'] == v['Scope'] == 'local' and not v.get('Options') and v['Labels']['fortis.registry.owner-operation'] == review['operationId'] and v['Mountpoint'], 'VOLUME_PIN_CHANGED')
        paths.append(v['Mountpoint'])
        need(not docker('ps','-aq','--no-trunc','--filter','volume='+name).strip(), 'VOLUME_ATTACHMENT_CONFLICT')
    need(len(set(paths)) == 3, 'VOLUME_ALIAS')
    # Repeat bounded active process census; peer/root/other-writer proof was
    # independently reviewed previously. No claim of permanent Engine lock.
    for cid in docker('ps','-q','--no-trunc').decode().splitlines():
        c = obj('container','inspect',cid); h = c['HostConfig']
        need(not h['Privileged'] and not h['PidMode'] and not h.get('Devices') and not h.get('DeviceRequests') and set(h.get('CapAdd') or []) <= {'CAP_NET_BIND_SERVICE','NET_BIND_SERVICE'}, 'ACTIVE_PRIVILEGE_CHANGED')
        for m in c['Mounts']:
            if m['Type'] == 'bind':
                need(not m['RW'] and m['Destination'] == '/etc/caddy/Caddyfile' and c['Name'] == '/rdg-personal-proxy-1', 'ACTIVE_BIND_CHANGED')
    return names


def volume_names(review):
    suffix = review['ownerSuffix']
    need(re.fullmatch('[0-9a-f]{8,32}',suffix), 'VOLUME_SUFFIX')
    return ('fortis-registry-state-e13b-'+suffix, 'fortis-registry-config-e13b-'+suffix, 'fortis-registry-read')


def owner_go(label, operation):
    expected = 'GO '+label+' '+operation
    print('Confirm reviewed scope, private storage and current exclusive writer fence. No concurrent Docker changes.')
    need(input('Enter '+expected+': ') == expected, 'OWNER_GO_NOT_GRANTED')


def bootstrap(action, review, source, specpath, digest, session):
    names = preflight(review, source)
    launcher = ROOT/'fortis_approvals'/'deploy'/'Registry-Owner-Bootstrap.ps1'
    args = ['powershell.exe','-NoProfile','-File',str(launcher),'-Action',action,'-SourceRoot',str(ROOT),'-SourceSha',source,'-RegistryImageId',review['registryImageId'],'-SpecPath',str(specpath),'-ExpectedSpecSha256',digest,'-StateVolume',names[0],'-ConfigVolume',names[1],'-SocketVolume',names[2]]
    if action == 'Provision': args += ['-ConfirmProvision']
    result = command(args)
    put(session/(action.lower()+'.log'),result)
    rows = [loads_strict(line) for line in result.splitlines() if line.startswith(b'{')]
    expected = {'Preview':'SOURCE_ONLY_REGISTRY_BOOTSTRAP_PREVIEW','Provision':'SOURCE_ONLY_REGISTRY_BOOTSTRAP_PROVISIONED'}[action]
    need(len(rows) == 1 and rows[0]['result'] == expected and rows[0]['specSha256'] == digest and rows[0]['hostAccepted'] is False and rows[0]['admissionAllowed'] is False and rows[0]['instanceId'] == loads_strict(read(specpath,4096))['instanceId'], 'BOOTSTRAP_RECEIPT')
    preflight(review,source)
    return rows[0]


def b64(data): return base64.b64encode(data).decode('ascii')


def unb64(value, limit):
    need(type(value) is str and len(value) <= (limit+2)//3*4, 'BACKUP_BOUNDS')
    data = base64.b64decode(value, validate=True)
    need(0 < len(data) <= limit, 'BACKUP_BOUNDS')
    return data


def root_readback(review, source, evidence, session):
    names = preflight(review, source)
    payload = git('show','HEAD:scripts/registry_owner_volume_inspect_roots.py')
    need(sha(payload) == review['inspectPayloadSha256'], 'ROOT_INSPECT_PAYLOAD_CHANGED')
    args = ['run','--rm','--pull=never','--network=none','--read-only','--user','20002:20002','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','128m']
    for name, dest in zip(names,('/run/fortis-registry-state','/run/fortis-registry-runtime','/run/fortis-registry-read')):
        args += ['--mount',f'type=volume,src={name},dst={dest},volume-nocopy,readonly']
    args += ['--entrypoint','python',review['registryImageId'],'-I','-B','-c',"exec(__import__('base64').b64decode(__import__('sys').argv[1]))",b64(payload)]
    actual = loads_strict(docker(*args))
    previous = loads_strict(read(evidence/'retained-helper-receipts'/'Inspect.log',16384))
    need(actual == previous and actual['result'] == 'E13B_VOLUME_ROOT_INSPECT_READONLY_PASS', 'ROOT_IDENTITY_OR_EMPTY_CHANGED')
    put(session/'root-readback.json',raw(actual))
    preflight(review,source)


def backup_run(action, review, source, envelope, spec_sha, helper, recovery_sha):
    names = preflight(review, source)
    # Source bytes read from exact clean Git object and independently displayed
    # before owner GO. Fixed entrypoint, no shell, no unreviewed input code.
    args = ['run','-i','--rm','--pull=never','--network=none','--read-only','--user','20002:20002','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','128m','--tmpfs','/run/fortis-pilot-scratch:rw,nosuid,nodev,noexec,size=16m,uid=20002,gid=20002,mode=0700']
    if action == 'Backup':
        for name, dest in zip(names,('/run/fortis-registry-state','/run/fortis-registry-runtime','/run/fortis-registry-read')):
            args += ['--mount',f'type=volume,src={name},dst={dest},volume-nocopy,readonly']
    args += ['--entrypoint','python',review['registryImageId'],'-I','-B','-c',"exec(__import__('base64').b64decode(__import__('sys').argv.pop(1)))",b64(helper),action,recovery_sha,spec_sha]
    result = loads_strict(docker(*args, data=raw(envelope)))
    preflight(review,source)
    return result


def execute(args):
    global DIAGNOSTIC_DIR
    need(os.name == 'nt' and sys.version_info >= (3,11) and ROOT == (Path.home()/'Repos'/'fortis-approvals').resolve(), 'WINDOWS_OWNER_SOURCE_REQUIRED')
    evidence = real_dir(args.evidence_dir)
    backup_root = real_dir(args.backup_dir)
    need(not backup_root.is_relative_to(ROOT) and not evidence.is_relative_to(ROOT) and not backup_root.is_relative_to(evidence) and not evidence.is_relative_to(backup_root), 'OWNER_STORAGE_NOT_SEPARATE')
    review = reviewed(evidence)
    source = args.source_sha
    preflight(review,source)
    session = evidence/'pilot-bootstrap'
    need(not session.exists(), 'BOOTSTRAP_SESSION_EXISTS_STOP_NO_RETRY')
    helper = git('show','HEAD:scripts/registry_owner_pilot_backup.py')
    recovery = git('show','HEAD:fortis_approvals/registry/recovery_snapshot.py')
    need(len(helper) <= 12000 and len(recovery) <= 30000, 'PAYLOAD_BOUNDS')
    if args.mapping:
        mapping = checked_mapping(loads_strict(read(Path(args.mapping), 16384)))
    else:
        bindings, components = [], []
        print('Enter owner-selected logical component and resource identities, NOT inferred installed state. Shared resources may repeat.')
        for target, env in sorted(TARGETS.items()):
            print(target+' / '+env)
            component = input('Component ID: ').strip()
            resources = sorted(set(input('Resource IDs (comma separated): ').replace(' ','').split(',')))
            requires = sorted(set(filter(None,input('Required component IDs (comma separated, blank if none): ').replace(' ','').split(','))))
            bindings.append({'targetId':target,'environment':env,'componentId':component})
            components.append({'id':component,'resources':resources,'requires':requires})
        mapping = checked_mapping({'bindings':bindings,'components':components})
    proposal = {'repository':REPOSITORY,'instanceId':str(uuid.uuid4()),'enrollmentId':str(uuid.uuid4()),'baselineSha':source,'catalogSha256':CATALOG_SHA,'mapping':mapping,'profile':policy(),'maxReviewToMergeSeconds':args.max_review_to_merge_seconds,'clockToleranceSeconds':args.clock_tolerance_seconds,'volumeOperationId':review['operationId'],'registryImageId':review['registryImageId'],'backupHelperSha256':sha(helper),'recoverySourceSha256':sha(recovery),'mode':'NON_PRODUCTION_PILOT_ONLY'}
    print(json.dumps(proposal,indent=2));print('Owner-only backup destination:',backup_root)
    print('Verify actual mapping, current remote main and policy/time values, encrypted private storage/ACLs; no production deployment or final enrollment.')
    compose(proposal,int(time.time()))  # reject invalid proposal before GO
    owner_go('PILOT PREVIEW',review['operationId'])
    preflight(review,source)
    records = compose(proposal,int(time.time()))
    session.mkdir()
    DIAGNOSTIC_DIR = session
    for name, record in records.items(): put(session/name,raw(record))
    specpath = session/'spec.json'; spec = raw(records['spec.json']); spec_sha = sha(spec)
    preview = bootstrap('Preview',review,source,specpath,spec_sha,session)
    print(json.dumps(preview,indent=2)); print('Spec SHA256:',spec_sha)
    owner_go('PILOT PROVISION',review['operationId'])
    need(read(specpath,4096) == spec, 'SPEC_CHANGED')
    put(session/'provision-go.json',raw({'decision':'OWNER_PILOT_PROVISION','operationId':review['operationId'],'specSha256':spec_sha,'confirmedAt':int(time.time())}))
    root_readback(review,source,evidence,session)
    provision = bootstrap('Provision',review,source,specpath,spec_sha,session)
    print(json.dumps(provision,indent=2))
    backup_id = str(uuid.uuid4()); dest = backup_root/('registry-'+backup_id)
    print('Verify inactive genesis via separate tmpfs snapshot, retain DB/config/manifest to',dest,'and independently restore in a second isolated container with no live mounts.')
    owner_go('PILOT BACKUP RESTORE',review['operationId'])
    need(read(specpath,4096) == spec, 'SPEC_CHANGED')
    preflight(review,source); dest.mkdir()
    put(session/'backup-go.json',raw({'decision':'OWNER_PILOT_BACKUP_RESTORE','operationId':review['operationId'],'specSha256':spec_sha,'backupId':backup_id,'confirmedAt':int(time.time())}))
    envelope = {'recovery':b64(recovery),'spec':b64(spec),'backupId':backup_id}
    result = backup_run('Backup',review,source,envelope,spec_sha,helper,sha(recovery))
    need(result['result'] == 'PILOT_GENESIS_BACKUP_CREATED' and set(result['files']) == {'sqlite','manifest','config'}, 'BACKUP_RECEIPT')
    paths = {'sqlite':dest/('registry-'+backup_id+'.sqlite'),'manifest':dest/('registry-'+backup_id+'.manifest.json'),'config':dest/'profile.json'}
    limits = {'sqlite':MAX_DB,'manifest':12000,'config':2048}
    pins = {}
    for k,p in paths.items():
        data = unb64(result['files'][k],limits[k]);put(p,data);pins[k]=sha(data)
    manifest = loads_strict(read(paths['manifest'],12000))
    need(manifest['sqliteSha256']==pins['sqlite'] and manifest['sqliteBytes']==paths['sqlite'].stat().st_size and result['receipt']['manifestDigest']==pins['manifest'], 'BACKUP_MANIFEST_PIN_MISMATCH')
    put(dest/'spec.json',spec)
    put(session/'backup-receipt.json',raw({'backupId':backup_id,'fileDigests':pins,'receipt':result['receipt']}))
    # Read back retained owner bytes, not the in-memory first-container output.
    files = {}
    for k,p in paths.items():
        data=read(p,limits[k]);need(sha(data)==pins[k],'BACKUP_RETAINED_BYTES_CHANGED');files[k]=b64(data)
    need(read(dest/'spec.json',4096)==spec,'BACKUP_SPEC_CHANGED')
    restored = backup_run('Restore',review,source,{**envelope,'files':files},spec_sha,helper,sha(recovery))
    need(restored['result']=='PILOT_INDEPENDENT_INACTIVE_RESTORE_PASS' and restored['receipt']==result['receipt'] and restored['configSha256']==pins['config'],'RESTORE_RECEIPT_CHANGED')
    for k,p in paths.items(): need(sha(read(p,limits[k]))==pins[k],'BACKUP_RETAINED_BYTES_CHANGED')
    put(session/'restore-receipt.json',raw(restored))
    final={'result':'PILOT_SCHEMA3_GENESIS_BACKUP_RESTORE_PASS','instanceId':records['spec.json']['instanceId'],'scopeDigest':sha(raw(records['spec.json']['scope'])),'specSha256':spec_sha,'sourceSha':source,'backupId':backup_id,'fileDigests':pins,'hostAccepted':False,'enrollmentAccepted':False,'admissionAllowed':False,'registryServiceStarted':False,'rollbackProtected':False}
    put(session/'final-receipt.json',raw(final));print(canonical(final))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-sha',required=True);p.add_argument('--evidence-dir',required=True);p.add_argument('--backup-dir',required=True)
    p.add_argument('--mapping',help='Optional owner-reviewed JSON with bindings/components; otherwise enter actual mapping interactively.')
    p.add_argument('--max-review-to-merge-seconds',type=int,required=True);p.add_argument('--clock-tolerance-seconds',type=int,required=True)
    args=p.parse_args()
    try: execute(args)
    except (Exception, KeyboardInterrupt) as exc:
        # No cleanup/retry even when native completion is uncertain.
        print('PILOT_STOP_NO_RETRY:',type(exc).__name__,str(exc) if isinstance(exc,RuntimeError) else '',file=sys.stderr);return 2
    return 0


if __name__=='__main__': sys.exit(main())
