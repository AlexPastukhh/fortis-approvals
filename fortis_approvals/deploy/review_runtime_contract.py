"""Inspect-only admission of the isolated Gateway before and after start."""
IMAGE_ID = 'sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84'
NAME = '/fortis-gateway-modularized-review-20261105'
STATE = 'fortis-r7-state-review-20261105'
MOUNTS = {('/state', STATE): True,
          ('/run/r7-identity', 'fortis-r7-identity'): False,
          ('/run/r7-grant', 'fortis-r7-grant'): False,
          ('/run/r7-sonar-token', 'fortis-r7-sonar-token'): False}
ENV = {'FORTIS_OWNER_ORIGIN': 'http://localhost:19203',
       'FORTIS_MACHINE_HOST': 'host.docker.internal:19204',
       'FORTIS_SONAR_REGION': 'eu', 'FORTIS_SONAR_ORGANIZATIONS': 'alexpastukhh',
       'FORTIS_SONAR_PROJECT_KEY': 'AlexPastukhh_obs-planning-docs'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate(container, *, expected_status):
    require(container['Name'] == NAME and container['Image'] == IMAGE_ID,
            'REVIEW_CONTAINER_IDENTITY_MISMATCH')
    config, host = container['Config'], container['HostConfig']
    require(config['Image'] == IMAGE_ID and config['User'] == '10001:10001',
            'REVIEW_IMAGE_REFERENCE_OR_USER_MISMATCH')
    require(config.get('Entrypoint') in (None, []) and
            config['Cmd'] == ['python', '-m', 'fortis_approvals.r7_unified_server'] and
            config['WorkingDir'] == '/opt/fortis', 'REVIEW_ENTRYPOINT_MISMATCH')
    env = {}
    for value in config['Env']:
        key, _, data = value.partition('=')
        require(key not in env, 'REVIEW_DUPLICATE_ENVIRONMENT')
        env[key] = data
    require(all(env.get(k) == v for k, v in ENV.items()), 'REVIEW_ENDPOINT_OR_SCOPE_MISMATCH')
    require(host['ReadonlyRootfs'] is True and host['Privileged'] is False and
            host['Init'] is True and host['PidsLimit'] == 100 and host['Memory'] == 536870912 and
            host['RestartPolicy']['Name'] == 'no' and
            host['CapDrop'] == ['ALL'] and not host.get('CapAdd') and
            any(v in ('no-new-privileges', 'no-new-privileges:true') for v in host['SecurityOpt']) and
            host['NetworkMode'] in ('default', 'bridge'), 'REVIEW_SECURITY_MISMATCH')
    require(not host.get('Binds') and not host.get('Devices') and
            not host.get('VolumesFrom') and not host.get('ExtraHosts') and
            host.get('PidMode', '') == '' and host.get('IpcMode') != 'host',
            'REVIEW_UNEXPECTED_HOST_ACCESS')
    require(set(host['Tmpfs']) == {'/tmp'}, 'REVIEW_TMPFS_MISMATCH')
    tmpfs_count = 0
    seen = set()
    for mount in container['Mounts']:
        if mount['Type'] == 'tmpfs':
            require(mount['Destination'] == '/tmp' and mount['RW'] is True and
                    not mount.get('Name'), 'REVIEW_UNEXPECTED_TMPFS_MOUNT')
            tmpfs_count += 1
            require(tmpfs_count == 1, 'REVIEW_DUPLICATE_TMPFS_MOUNT')
            continue
        key = (mount['Destination'], mount.get('Name'))
        require(mount['Type'] == 'volume' and key in MOUNTS and key not in seen and
                mount['RW'] is MOUNTS[key], 'REVIEW_VOLUME_OR_ACCESS_MISMATCH')
        seen.add(key)
    require(seen == set(MOUNTS), 'REVIEW_MOUNTS_MISSING')
    expected_ports = {'19103/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19203'}],
                      '19104/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19204'}]}
    require(host['PortBindings'] == expected_ports, 'REVIEW_PORT_BINDINGS_MISMATCH')
    health = config['Healthcheck']
    require(health['Test'] == ['CMD-SHELL', 'python -m fortis_approvals.r7_unified_server health'] and
            health['Interval'] == 20000000000 and health['Timeout'] == 5000000000 and
            health['Retries'] == 3 and health['StartPeriod'] == 20000000000,
            'REVIEW_HEALTHCHECK_MISMATCH')
    require(container['State']['Status'] == expected_status, 'REVIEW_CONTAINER_STATUS_MISMATCH')
    if expected_status == 'running':
        require(container['State']['Health']['Status'] == 'healthy', 'REVIEW_NOT_HEALTHY')
    return {'verification': 'PASS', 'status': expected_status, 'imageId': IMAGE_ID,
            'stateVolume': STATE, 'credentialMounts': 'RO', 'ports': '19203/19204'}


def port_claims(containers, ports=(19203, 19204)):
    """Use exact host TCP bindings, and report stopped containers separately."""
    targets = {str(p) for p in ports}
    claims = []
    for container in containers:
        status = container['State']['Status']
        bindings = container['HostConfig'].get('PortBindings') or {}
        for internal_port, published in bindings.items():
            if not internal_port.endswith('/tcp'):
                continue
            for binding in published or []:
                if binding['HostPort'] not in targets:
                    continue
                claims.append({'name': container['Name'], 'status': status,
                    'hostIp': binding['HostIp'], 'hostPort': binding['HostPort'],
                    'containerPort': internal_port,
                    'blocking': status not in ('created', 'exited')})
    return claims


def admit_smoke_stop(container):
    """Only the known dated smoke blocker, with isolated retained named state."""
    import re
    require(container['Name'] == '/fortis-gateway-candidate-smoke-r3-20261105' and
            re.fullmatch(r'[0-9a-f]{64}', container['Id']) is not None,
            'SMOKE_BLOCKER_IDENTITY_UNKNOWN')
    require(container['Image'] in (
        'sha256:a2fd23c3def0609ed254cd796f40fb51cc4a5a103f0486bb0052d44d76b23267', IMAGE_ID),
        'SMOKE_BLOCKER_IMAGE_UNKNOWN')
    config, host = container['Config'], container['HostConfig']
    require(config['User'] == '10001:10001' and config.get('Entrypoint') in (None, []) and
            config['Cmd'] == ['python', '-m', 'fortis_approvals.r7_unified_server'],
            'SMOKE_BLOCKER_PROCESS_UNKNOWN')
    require(host['ReadonlyRootfs'] is True and host['Privileged'] is False and
            host['AutoRemove'] is False and not host.get('Binds') and
            not host.get('VolumesFrom') and not host.get('Devices') and
            host.get('PidMode', '') == '' and host.get('IpcMode') != 'host' and
            host['NetworkMode'] not in ('host', 'none'),
            'SMOKE_BLOCKER_HOST_ACCESS_OR_AUTOREMOVE_UNKNOWN')
    require(host['PortBindings'] == {
        '19103/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19203'}],
        '19104/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19204'}]},
        'SMOKE_BLOCKER_PORTS_CHANGED')
    require(container['State']['Status'] == 'running', 'SMOKE_BLOCKER_NOT_RUNNING')
    volumes = [m for m in container['Mounts'] if m['Type'] == 'volume']
    other = [m for m in container['Mounts'] if m['Type'] != 'volume']
    require(len(volumes) == 4 and (not other or len(other) == 1 and
            other[0]['Type'] == 'tmpfs' and other[0]['Destination'] == '/tmp'),
            'SMOKE_BLOCKER_UNEXPECTED_MOUNT')
    credentials = {(dest, name): rw for (dest, name), rw in MOUNTS.items() if dest != '/state'}
    states = [m for m in volumes if m['Destination'] == '/state']
    require(len(states) == 1 and states[0]['RW'] is True, 'SMOKE_BLOCKER_STATE_UNKNOWN')
    state = states[0]['Name']
    require(state not in ('fortis-r7-state', STATE) and
            re.fullmatch(r'fortis-(?:r7-|gateway-).*?(?:smoke|clone|candidate).*20261105', state) is not None,
            'SMOKE_BLOCKER_STATE_NOT_ISOLATED_TEST_VOLUME')
    actual = {(m['Destination'], m['Name']): m['RW'] for m in volumes if m['Destination'] != '/state'}
    require(actual == credentials, 'SMOKE_BLOCKER_CREDENTIAL_MOUNTS_UNKNOWN')
    return {'admission': 'PASS', 'containerId': container['Id'], 'name': container['Name'],
            'imageId': container['Image'], 'stateVolumeRetained': state,
            'action': 'stop this container ID only; preserve container and all volumes'}
