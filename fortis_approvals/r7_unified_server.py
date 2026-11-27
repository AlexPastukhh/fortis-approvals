"""Owner-review SOURCE ONLY R7: Sonar READ + WebAuthn ASK/EXECUTE server.

Not a permitted deployment by itself. Sonar POST requires the exact owner
WebAuthn approval; the machine ingress has no decision or execute route.
No tokens are included; no Docker/host changes. R7 uses its own private state
and must NEVER attach old A3/R5/G2/G4 volumes or auto-provision credentials.
"""
import hashlib
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
from threading import Thread
from urllib.request import Request, urlopen
from wsgiref.simple_server import make_server

from .a3_server import TLSRepoServer
from .r5_read_server import _private_ascii, _organizations
from .r7_unified_candidate import build_r7_unified_candidate
from .server import OwnerHTTPServer, OwnerRequestHandler
from .integrations.sonarcloud.gateway.sonar import SonarHTTPTransport


OWNER_PORT = 19103
MACHINE_PORT = 19104
OWNER_ORIGIN = 'http://localhost:19103'
MACHINE_HOST = 'host.docker.internal:19104'


def runtime_endpoints():
    """Return validated public Host/Origin values for the fixed internal ports.

    Side-by-side review containers publish 19103/19104 on alternate host
    ports. The browser Origin and machine Host must match those host ports,
    while the processes continue listening on the image's fixed ports.
    """
    owner_origin = os.environ.get('FORTIS_OWNER_ORIGIN', OWNER_ORIGIN)
    machine_host = os.environ.get('FORTIS_MACHINE_HOST', MACHINE_HOST)
    owner_match = re.fullmatch(r'http://localhost:([0-9]{4,5})', owner_origin)
    machine_match = re.fullmatch(
        r'host\.docker\.internal:([0-9]{4,5})', machine_host)
    if (not owner_match or not 1024 <= int(owner_match.group(1)) <= 65535):
        raise RuntimeError('R7_OWNER_ORIGIN_INVALID')
    if (not machine_match or not 1024 <= int(machine_match.group(1)) <= 65535):
        raise RuntimeError('R7_MACHINE_HOST_INVALID')
    return owner_origin, machine_host


def _owner_release_local_deny(extensions, release_nonce, grant, sonar_token):
    # The owner controller already seals the full config and activates its
    # root-owned release gate. No new machine route, grant or environment toggle.
    if extensions is None or 'ownerLocalDeny' not in extensions.value:
        return None
    if extensions.value['ownerLocalDeny'] != 'SONAR_ACCEPT_ISSUE_V1':
        raise RuntimeError('R7_LOCAL_DENY_MODE_INVALID')
    import uuid
    if (type(release_nonce) is not str or
            str(uuid.UUID(release_nonce)) != release_nonce):
        raise RuntimeError('R7_LOCAL_DENY_REVIEWED_RELEASE_REQUIRED')
    from .core import canonical
    from .extensions.owner_policy_r7_optin_phase6c4 import R7LocalDenySourceOptIn
    source = _installed_policy_source_digest()
    # Bind the actual admitted Sonar credential and machine grant. Only
    # the combined digest is retained; raw credential bytes never leave R7.
    credentials = hashlib.sha256(canonical({
        'purpose':'OWNER_LOCAL_DENY_SONAR_RUNTIME_V1',
        'grant':grant,'sonarToken':sonar_token}).encode()).hexdigest()
    return R7LocalDenySourceOptIn(source, credentials, runtime_sonar_only=True)


def _installed_policy_source_digest():
    from .core import canonical
    root = Path(__file__).resolve().parent
    files = sorted(p for p in root.rglob('*')
                   if p.is_file() and (p.suffix == '.py' or 'static' in p.relative_to(root).parts)
                   and '__pycache__' not in p.parts)
    if not files:
        raise RuntimeError('R7_LOCAL_DENY_SOURCE_REQUIRED')
    manifest = []
    for path in files:
        if path.is_symlink():
            raise RuntimeError('R7_LOCAL_DENY_SOURCE_SYMLINK')
        manifest.append([path.relative_to(root).as_posix(),
                         hashlib.sha256(path.read_bytes()).hexdigest()])
    return hashlib.sha256(canonical(manifest).encode()).hexdigest()


def _owner_release_unified_policy(extensions, release_nonce, credential_generation):
    if extensions is None or 'ownerPolicyEditor' not in extensions.value:
        return None
    import uuid
    if (extensions.value['ownerPolicyEditor'] != 'UNIFIED_V2' or
            type(release_nonce) is not str or str(uuid.UUID(release_nonce)) != release_nonce):
        raise RuntimeError('R7_UNIFIED_POLICY_REVIEWED_RELEASE_REQUIRED')
    from .extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
    return R7UnifiedPolicySourceOptIn(_installed_policy_source_digest(),credential_generation,
        allow_label_policy_upgrade=extensions.value.get('ownerPolicyAuthorityUpgrade')=='OWNER_LABELS_V1',
        allow_all_method_policy_upgrade=extensions.value.get('ownerPolicyAuthorityUpgrade')=='OWNER_ALL_METHODS_V1')


def _runtime_policy_generation(*, owner, runtime, grant, sonar_token,
                               publisher_grant, github_transport, machine_shell,
                               grant_path, sonar_token_path):
    # Never return secrets or a reusable assertion. Bind loaded identities
    # and current protected material; missing/rotated material stops edits.
    from .core import Denied, canonical
    from .integrations.github.gateway.transport import _read_token
    if (_private_ascii(grant_path,max_size=257)!=grant or
            _private_ascii(sonar_token_path,max_size=4097)!=sonar_token):
        raise Denied('R7_UNIFIED_POLICY_RESTART_REQUIRED')
    material={'grant':grant,'sonar':sonar_token,'publisherGrant':publisher_grant}
    if github_transport is not None:
        if _read_token()!=github_transport._token:
            raise Denied('R7_UNIFIED_POLICY_RESTART_REQUIRED')
        material['github']=github_transport._token
    if machine_shell is not None:
        material['machineShell']=[machine_shell.actor,machine_shell.target,
            machine_shell.executor_git_sha,machine_shell.executor_identity,
            machine_shell.transport.key.hex(),machine_shell.transport.bearer]
    with owner._db() as db:
        keys=[[r['id'],bytes(r['data']).hex(),r['active']]
              for r in db.execute('SELECT id,data,active FROM credentials ORDER BY id')]
    if not any(row[2]==1 for row in keys):
        raise Denied('R7_UNIFIED_POLICY_OWNER_KEY_REQUIRED')
    credentials=[]
    for service,aliases in sorted(runtime.credentials.items()):
        for role,alias in sorted(aliases.items()):
            try:
                secret=runtime.vault.get(alias)
                credentials.append([service,role,alias,secret.generation,
                                    hashlib.sha256(secret.reveal().encode()).hexdigest()])
            except (Denied,OSError):
                # A disabled configured alias may legitimately be absent.
                # This is identity data, never authority to make it ready.
                credentials.append([service,role,alias,'UNAVAILABLE'])
    material.update(ownerKeys=keys,extensionCredentials=credentials,
                    configurationDigest=runtime.digest)
    return hashlib.sha256(canonical(material).encode()).hexdigest()


_MAINTENANCE_INTERLOCK_MOUNT = Path('/run/r7-maintenance')


def create_servers(*, state, grant_path, sonar_token_path, cert_path,
                   key_path,region,organizations,project_key,
                   bind_host='0.0.0.0', github_pilot=None, analysis_review=None, extensions=None, release_nonce=None,
                   publisher_profile=None, publisher_grant=None,
                   machine_shell=None, registry_candidate_reader=None,
                   reviewed_registry_successor=None):
    # This trusted Python-only source composition never grants Registry via
    # another route, even if a caller supplied a reader without the matching
    # registered image-owned extension. Refuse before creating owner state.
    extension_registry = (extensions is not None and
                          'registry' in extensions.value['providers'])
    if extension_registry != (registry_candidate_reader is not None):
        raise RuntimeError('R7_REGISTRY_RELEASE_MOUNT_MISMATCH')
    successor_configuration = getattr(registry_candidate_reader, '_successor_config', None)
    if (reviewed_registry_successor is None and successor_configuration is None
            and getattr(registry_candidate_reader, '_semantic_transport', None) is not None):
        raise RuntimeError('R7_REGISTRY_SUCCESSOR_REVIEWED_BINDING_REQUIRED')
    if successor_configuration is not None and reviewed_registry_successor is not None:
        raise RuntimeError('R7_REGISTRY_SUCCESSOR_MOUNT_OVERRIDE_DENIED')
    if reviewed_registry_successor is not None:
        from .extensions.composite_successor import ReviewedRegistrySuccessor
        if release_nonce is None:
            raise RuntimeError('R7_REGISTRY_SUCCESSOR_STAGED_RELEASE_REQUIRED')
        if type(reviewed_registry_successor) is not ReviewedRegistrySuccessor:
            raise RuntimeError('R7_REGISTRY_SUCCESSOR_REVIEWED_BINDING_REQUIRED')
        reviewed_registry_successor.verify_startup(registry_candidate_reader)
    if reviewed_registry_successor is None and successor_configuration is None and (
            _MAINTENANCE_INTERLOCK_MOUNT.exists() or _MAINTENANCE_INTERLOCK_MOUNT.is_symlink()):
        raise RuntimeError('R7_MAINTENANCE_REVIEWED_STARTUP_REQUIRED')
    # P1 requires exactly one owner-pinned project; no organization-wide fallback.
    if (type(project_key) is not str or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', project_key)):
        raise RuntimeError('R7_P1_EXACT_PROJECT_KEY_REQUIRED')
    # Owner-only confidential provisioning: read exact private files; never print.
    grant = _private_ascii(grant_path,max_size=257)
    if len(grant) < 32:
        raise RuntimeError('R7_MACHINE_GRANT_INVALID')
    sonar_token = _private_ascii(sonar_token_path,max_size=4097)
    if len(sonar_token) < 12 or sonar_token == grant:
        raise RuntimeError('R7_SONAR_TOKEN_INVALID')
    if publisher_grant is not None and publisher_grant in (grant, sonar_token):
        raise RuntimeError('R7_PUBLISHER_CREDENTIAL_REUSE_DENIED')
    transport = SonarHTTPTransport(region=region,bearer_token=sonar_token)
    owner_origin, machine_host = runtime_endpoints()
    github_transport = None
    identity = {}
    unified = _owner_release_unified_policy(
        extensions,release_nonce,lambda: _runtime_policy_generation(
            owner=identity['owner'],runtime=identity['runtime'],grant=grant,
            sonar_token=sonar_token,publisher_grant=publisher_grant,
            github_transport=github_transport,machine_shell=machine_shell,
            grant_path=grant_path,sonar_token_path=sonar_token_path))
    if unified is not None and (github_pilot is not None or analysis_review is not None):
        from .integrations.github.gateway.transport import GitHubHTTPTransport
        github_transport = GitHubHTTPTransport.from_file()
    if successor_configuration is not None:
        from .extensions.successor_runtime import ProtectedRegistrySuccessor
        if (type(successor_configuration) is not ProtectedRegistrySuccessor or unified is None
                or not unified.allow_all_method_policy_upgrade or analysis_review is not None
                or github_pilot is None or not github_pilot.native_worktree
                or not github_pilot.ci_reads
                or release_nonce != registry_candidate_reader._release_nonce):
            raise RuntimeError('R7_REGISTRY_SUCCESSOR_REVIEWED_BINDING_REQUIRED')
        reviewed_registry_successor = successor_configuration.compose(
            registry_candidate_reader, state=state, project_key=project_key,
            github_pilot=github_pilot, credential_generation=unified.credential_generation)
        reviewed_registry_successor.verify_startup(registry_candidate_reader)
    _,owner_auth,portal,ingress = build_r7_unified_candidate(
        state=state,owner_origin=owner_origin,ingress_host=machine_host,
        ingress_grant=grant,sonar_transport=transport,
        organizations=organizations,region=region,
        project_keys=(project_key,), github_pilot=github_pilot, analysis_review=analysis_review,
        extensions=extensions, publisher_profile=publisher_profile, publisher_grant=publisher_grant,
        machine_shell=machine_shell,github_transport=github_transport,
        registry_candidate_reader=registry_candidate_reader,
        reviewed_registry_successor=reviewed_registry_successor,
        local_deny_source_opt_in=_owner_release_local_deny(
            extensions, release_nonce, grant, sonar_token),
        unified_policy_source_opt_in=unified)
    if unified is not None:
        identity.update(owner=owner_auth,runtime=portal._extension_runtime)
    if release_nonce is not None:
        from .extensions.staging import ReleaseGate, StagedMachine, StagedOwner
        runtime = getattr(portal, '_extension_runtime', None)
        if runtime is None: raise RuntimeError('RELEASE_EXTENSION_CONFIG_REQUIRED')
        base = ingress.base  # ExtensionIngress retains the original auth/TLS-contract base.
        gate = ReleaseGate(release_nonce, runtime.digest)
        ingress = StagedMachine(ingress, base, runtime, gate,
                                block_staged_registry_reads=reviewed_registry_successor is not None)
        portal = StagedOwner(portal, gate)
    cert = Path(cert_path)
    if cert.is_symlink() or not cert.is_file():
        raise RuntimeError('R7_PUBLIC_CERT_REQUIRED')
    key = Path(key_path)
    if (key.is_symlink() or not key.is_file() or
            key.stat().st_uid != os.geteuid() or
            stat.S_IMODE(key.stat().st_mode) != 0o600):
        raise RuntimeError('R7_PRIVATE_KEY_REQUIRED')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(certfile=str(cert),keyfile=str(key))
    if reviewed_registry_successor is not None:
        reviewed_registry_successor.verify_startup(registry_candidate_reader)
    owner = make_server(bind_host,OWNER_PORT,portal,
                        server_class=OwnerHTTPServer,
                        handler_class=OwnerRequestHandler)
    try:
        machine = make_server(bind_host,MACHINE_PORT,ingress,
                              server_class=TLSRepoServer,
                              handler_class=OwnerRequestHandler)
        machine.tls_context = context
    except BaseException:
        owner.server_close()
        raise
    return owner,machine


def health(*,cert_path,owner_origin=None,machine_host=None):
    if owner_origin is None or machine_host is None:
        owner_origin, machine_host = runtime_endpoints()
    from urllib.parse import urlsplit
    request = Request(
        'http://127.0.0.1:%d/' % OWNER_PORT,
        headers={'Host':urlsplit(owner_origin).netloc})
    with urlopen(request,timeout=2) as response:
        if response.status != 200:
            raise RuntimeError('R7_OWNER_NOT_READY')
    context = ssl.create_default_context(cafile=str(cert_path))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection(('127.0.0.1',MACHINE_PORT),timeout=2) as raw:
        raw.settimeout(2)
        with context.wrap_socket(raw,server_hostname='host.docker.internal') as tls:
            tls.sendall((
                'GET /no-such-machine-route HTTP/1.1\r\n'
                'Host: %s\r\nConnection: close\r\n\r\n'
                % machine_host).encode('ascii'))
            if not tls.recv(128).startswith(b'HTTP/1.0 404 '):
                raise RuntimeError('R7_MACHINE_NOT_READY')


def main():
    command=sys.argv[1:]
    if command==['preflight-imports']:
        from .r7_unified_candidate import build_r7_unified_candidate
        from .integrations.sonarcloud.gateway.sonar import SonarHTTPTransport, SonarIssueAdapter
        print('FORTIS_R7_UNIFIED_READ_ASK_EXECUTE_IMPORTS_PASS')
        print('FORTIS_R7_SONAR_POST=OWNER_WEBAUTHN_APPROVAL_REQUIRED')
        return
    if command==['health']:
        owner_origin, machine_host = runtime_endpoints()
        health(cert_path='/run/r7-identity/server.crt',
               owner_origin=owner_origin,machine_host=machine_host)
        return
    if command:
        raise SystemExit('Usage: r7_unified_server [preflight-imports|health]')
    if os.geteuid()!=10001:
        raise RuntimeError('R7_RUNTIME_MUST_BE_UNPRIVILEGED')
    from .integrations.github.pilot import config_from_environment
    github_pilot = config_from_environment(os.environ)
    from .integrations.analysis_review import AnalysisReviewConfig
    analysis_review = AnalysisReviewConfig.from_environment(os.environ)
    from .extensions.runtime import ExtensionConfig
    extensions = ExtensionConfig.from_environment(os.environ)
    release_nonce = os.environ.get('FORTIS_RELEASE_NONCE')
    # Registry is bound solely from an owner-installed immutable fixed mount.
    # The prior R7 candidate image does not package this new module; when no
    # Registry is selected and no owner mount exists, do not import it. This
    # preserves old Sonar-only image startup without weakening Registry STOP.
    has_registry = (extensions is not None and
                    'registry' in extensions.value['providers'])
    registry_candidate_reader = None
    reader_mount = Path('/run/r7-registry-reader')
    if has_registry or reader_mount.exists() or reader_mount.is_symlink():
        from .r7_registry_reader_mount import load_owner_registry_reader
        registry_candidate_reader = load_owner_registry_reader(
            expected_release_nonce=release_nonce,
            expected_source_digest=_installed_policy_source_digest())
    if has_registry != (registry_candidate_reader is not None):
        raise RuntimeError('R7_REGISTRY_RELEASE_MOUNT_MISMATCH')
    region=os.environ.get('FORTIS_SONAR_REGION','eu')
    organizations=_organizations(os.environ.get('FORTIS_SONAR_ORGANIZATIONS',''))
    project_key=os.environ.get('FORTIS_SONAR_PROJECT_KEY','')
    owner_origin, machine_host = runtime_endpoints()
    # Only an explicit owner-private read-only mount activates the second actor.
    # Missing mount means disabled; no environment, Repo or PR fallback.
    from .integrations.github.publisher_owner_mount import load_owner_publisher_mount
    publisher_profile, publisher_grant = load_owner_publisher_mount()
    # Owner-sealed fixed source path; NO environment/AI toggle or credential
    # provisioning. Absence leaves all machine PowerShell routes DENY.
    from .powershell_owner_mount import load_machine_shell_mount
    from .r7_unified_candidate import ACTOR as PRIMARY_MACHINE_ACTOR
    machine_shell = load_machine_shell_mount(expected_actor=PRIMARY_MACHINE_ACTOR)
    owner,machine=create_servers(
        state='/state/private',
        grant_path='/run/r7-grant/grant',
        sonar_token_path='/run/r7-sonar-token/token',
        cert_path='/run/r7-identity/server.crt',
        key_path='/run/r7-identity/server.key',
        region=region,organizations=organizations,
        project_key=project_key, github_pilot=github_pilot, analysis_review=analysis_review,
        extensions=extensions, release_nonce=release_nonce,
        publisher_profile=publisher_profile, publisher_grant=publisher_grant,
        machine_shell=machine_shell,
        registry_candidate_reader=registry_candidate_reader)
    try:
        Thread(target=owner.serve_forever,daemon=True,
               name='r7-owner-portal').start()
        print('FORTIS_R7_READ_ASK_EXECUTE_CANDIDATE_READY '
              'owner='+owner_origin+' '
              'machine=https://'+machine_host+' '
              'sonar_write=OWNER_WEBAUTHN_APPROVAL_REQUIRED',flush=True)
        machine.serve_forever()
    finally:
        owner.shutdown()
        machine.shutdown()
        owner.server_close()
        machine.server_close()


if __name__=='__main__':
    main()
