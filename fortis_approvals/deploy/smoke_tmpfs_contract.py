"""Admission only for the owner-inspected r3 container and proven empty tmpfs."""
ID = 'd35f999783872ed11225b52fffee534f93777dcd757b326044aa2521dc7bd1f3'
NAME = '/fortis-gateway-candidate-smoke-r3-20261105'
IMAGE = 'sha256:a2fd23c3def0609ed254cd796f40fb51cc4a5a103f0486bb0052d44d76b23267'
CMD = ['-c', 'mkdir -m 700 /state/private && exec python -m fortis_approvals.r7_unified_server']
CREDS = {('/run/r7-identity', 'fortis-r7-identity'), ('/run/r7-grant', 'fortis-r7-grant'),
         ('/run/r7-sonar-token', 'fortis-r7-sonar-token')}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def inspect_tmpfs(container):
    require((container['Id'], container['Name'], container['Image']) == (ID, NAME, IMAGE),
            'R3_EXACT_IDENTITY_MISMATCH')
    config, host = container['Config'], container['HostConfig']
    require(config['User'] == '10001:10001' and config['Entrypoint'] == ['/bin/sh'] and
            config['Cmd'] == CMD, 'R3_OBSERVED_COMMAND_MISMATCH')
    require(host['ReadonlyRootfs'] is True and host['Privileged'] is False and
            host['AutoRemove'] is False and not host.get('Binds') and not host.get('Devices') and
            not host.get('VolumesFrom') and host.get('PidMode', '') == '' and
            host.get('IpcMode') == 'private' and host['NetworkMode'] == 'bridge',
            'R3_HOST_ACCESS_UNKNOWN')
    tmpfs = host.get('Tmpfs') or {}
    require('/state' in tmpfs and set(tmpfs) <= {'/state', '/tmp'} and
            isinstance(tmpfs['/state'], str) and 'ro' not in tmpfs['/state'].split(','),
            'R3_STATE_TMPFS_NOT_CONFIRMED')
    mounts = container['Mounts']
    volumes = [m for m in mounts if m['Type'] == 'volume']
    others = [m for m in mounts if m['Type'] != 'volume']
    require(len(volumes) == 3 and
            {(m['Destination'], m['Name']) for m in volumes} == CREDS and
            all(m['RW'] is False for m in volumes), 'R3_CREDENTIAL_OR_STATE_MOUNT_MISMATCH')
    require(all(m['Type'] == 'tmpfs' and m['Destination'] in tmpfs for m in others),
            'R3_UNKNOWN_WRITABLE_MOUNT')
    require(host['PortBindings'] == {
        '19103/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19203'}],
        '19104/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19204'}]} and
            container['State']['Status'] == 'running', 'R3_PORT_OR_STATUS_MISMATCH')
    return {'inspection': 'PASS', 'containerId': ID, 'state': 'tmpfs; data probe required'}


def admit_empty_stop(container, report):
    inspect_tmpfs(container)
    require(report.get('uid') == 10001 and report.get('gid') == 10001 and
            report.get('integrity') == 'ok for all three databases' and
            report.get('stableRead') is True and report.get('empty') is True and
            report.get('counts') == {'requests': 0, 'events': 0, 'receipts': 0,
                'credentialsTotal': 0, 'credentialsActive': 0, 'invitationsTotal': 0,
                'eventSequenceRows': 0}, 'R3_STATE_NOT_PROVEN_EMPTY_DO_NOT_STOP')
    return {'admission': 'PASS', 'containerId': ID,
            'action': 'stop exact r3 ID; discard only confirmed empty tmpfs; retain all named volumes'}
