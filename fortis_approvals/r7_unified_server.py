"""Owner-review SOURCE ONLY R7: Sonar READ + WebAuthn ASK/EXECUTE server.

Not a permitted deployment by itself. Sonar POST requires the exact owner
WebAuthn approval; the machine ingress has no decision or execute route.
No tokens are included; no Docker/host changes. R7 uses its own private state
and must NEVER attach old A3/R5/G2/G4 volumes or auto-provision credentials.
"""
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


def create_servers(*, state, grant_path, sonar_token_path, cert_path,
                   key_path,region,organizations,project_key,
                   bind_host='0.0.0.0', github_pilot=None, analysis_review=None, extensions=None, release_nonce=None,
                   publisher_profile=None, publisher_grant=None,
                   machine_shell=None):
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
    _,_,portal,ingress = build_r7_unified_candidate(
        state=state,owner_origin=owner_origin,ingress_host=machine_host,
        ingress_grant=grant,sonar_transport=transport,
        organizations=organizations,region=region,
        project_keys=(project_key,), github_pilot=github_pilot, analysis_review=analysis_review,
        extensions=extensions, publisher_profile=publisher_profile, publisher_grant=publisher_grant,
        machine_shell=machine_shell)
    if release_nonce is not None:
        from .extensions.staging import ReleaseGate, StagedMachine, StagedOwner
        runtime = getattr(portal, '_extension_runtime', None)
        if runtime is None: raise RuntimeError('RELEASE_EXTENSION_CONFIG_REQUIRED')
        base = ingress.base  # ExtensionIngress retains the original auth/TLS-contract base.
        gate = ReleaseGate(release_nonce, runtime.digest)
        ingress = StagedMachine(ingress, base, runtime, gate)
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
        machine_shell=machine_shell)
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
