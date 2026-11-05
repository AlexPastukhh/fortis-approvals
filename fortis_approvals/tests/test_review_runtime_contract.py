"""Mutated Docker inspect fixtures must not admit Production state or host access."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'deploy/review_runtime_contract.py'
spec = importlib.util.spec_from_file_location('review_contract', PATH)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


def fixture():
    return {'Name': contract.NAME, 'Image': contract.IMAGE_ID,
        'Config': {'Image': contract.IMAGE_ID, 'User': '10001:10001', 'Entrypoint': None,
            'Cmd': ['python', '-m', 'fortis_approvals.r7_unified_server'], 'WorkingDir': '/opt/fortis',
            'Env': [k + '=' + v for k, v in contract.ENV.items()],
            'Healthcheck': {'Test': ['CMD-SHELL', 'python -m fortis_approvals.r7_unified_server health'],
                'Interval': 20000000000, 'Timeout': 5000000000, 'Retries': 3, 'StartPeriod': 20000000000}},
        'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'Init': True,
            'PidsLimit': 100, 'Memory': 536870912, 'RestartPolicy': {'Name': 'no'},
            'CapDrop': ['ALL'], 'CapAdd': None, 'SecurityOpt': ['no-new-privileges:true'],
            'NetworkMode': 'default', 'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=16m'},
            'PortBindings': {'19103/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19203'}],
                             '19104/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19204'}]}},
        'Mounts': [{'Type': 'volume', 'Destination': dest, 'Name': name, 'RW': rw}
                   for (dest, name), rw in contract.MOUNTS.items()],
        'State': {'Status': 'created'}}


class ReviewRuntimeContractTests(unittest.TestCase):
    def test_created_and_healthy_running_instances_admitted(self):
        data = fixture()
        self.assertEqual(contract.validate(data, expected_status='created')['verification'], 'PASS')
        data['State'] = {'Status': 'running', 'Health': {'Status': 'healthy'}}
        self.assertEqual(contract.validate(data, expected_status='running')['status'], 'running')

    def test_mutated_identity_security_endpoints_and_mounts_rejected(self):
        mutations = [
            lambda d: d.update(Image='sha256:other'),
            lambda d: d['Config'].update(Image='mutable-tag'),
            lambda d: d['Config'].update(User='0:0'),
            lambda d: d['Config']['Env'].append('FORTIS_MACHINE_HOST=host.docker.internal:19104'),
            lambda d: d['Config']['Env'].__setitem__(0, 'FORTIS_OWNER_ORIGIN=http://localhost:19103'),
            lambda d: d['Mounts'][0].update(Name='fortis-r7-state'),
            lambda d: d['Mounts'][1].update(RW=True),
            lambda d: d['Mounts'].append({'Type': 'bind', 'Destination': '/host', 'RW': True}),
            lambda d: d['HostConfig'].update(Privileged=True),
            lambda d: d['HostConfig'].update(CapAdd=['SYS_ADMIN']),
            lambda d: d['HostConfig'].update(ReadonlyRootfs=False),
            lambda d: d['HostConfig'].update(NetworkMode='host'),
            lambda d: d['HostConfig'].update(PidMode='host'),
            lambda d: d['HostConfig'].update(Binds=['/:/host']),
            lambda d: d['HostConfig']['PortBindings']['19103/tcp'][0].update(HostIp='0.0.0.0'),
            lambda d: d['HostConfig']['PortBindings']['19104/tcp'][0].update(HostPort='19104'),
            lambda d: d['Config']['Healthcheck'].update(Test=['CMD', 'true']),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                data = deepcopy(fixture())
                mutate(data)
                with self.assertRaises(RuntimeError):
                    contract.validate(data, expected_status='created')

    def test_optional_docker_tmpfs_inspect_entry_is_bounded(self):
        data = fixture()
        data['Mounts'].append({'Type': 'tmpfs', 'Destination': '/tmp', 'RW': True})
        contract.validate(data, expected_status='created')
        data['Mounts'][-1]['Destination'] = '/run'
        with self.assertRaisesRegex(RuntimeError, 'UNEXPECTED_TMPFS'):
            contract.validate(data, expected_status='created')

    def test_starting_is_not_healthy(self):
        data = fixture()
        data['State'] = {'Status': 'running', 'Health': {'Status': 'starting'}}
        with self.assertRaisesRegex(RuntimeError, 'NOT_HEALTHY'):
            contract.validate(data, expected_status='running')


class ReviewPortClaimTests(unittest.TestCase):
    @staticmethod
    def item(status='running', host_port='19203', internal='19103/tcp', name='/other'):
        return {'Name': name, 'State': {'Status': status}, 'HostConfig': {
            'PortBindings': {internal: [{'HostIp': '127.0.0.1', 'HostPort': host_port}]}}}

    def test_production_host_ports_and_internal_port_matches_do_not_conflict(self):
        items = [self.item(host_port='19103', name='/production'),
                 self.item(host_port='19303', internal='19203/tcp')]
        self.assertEqual(contract.port_claims(items), [])

    def test_stopped_bindings_are_reported_without_being_active_conflicts(self):
        for status in ('created', 'exited'):
            with self.subTest(status=status):
                claims = contract.port_claims([self.item(status=status)])
                self.assertEqual(claims[0]['hostPort'], '19203')
                self.assertEqual(claims[0]['name'], '/other')
                self.assertFalse(claims[0]['blocking'])

    def test_active_and_uncertain_states_block_with_identity(self):
        for status in ('running', 'restarting', 'paused', 'dead', 'removing', 'unknown'):
            with self.subTest(status=status):
                claims = contract.port_claims([self.item(status=status)])
                self.assertTrue(claims[0]['blocking'])
                self.assertEqual(claims[0]['status'], status)

    def test_udp_and_unpublished_ports_do_not_conflict_with_tcp(self):
        self.assertEqual(contract.port_claims([self.item(internal='19103/udp')]), [])
        self.assertEqual(contract.port_claims([{'Name': '/none', 'State': {'Status': 'running'},
            'HostConfig': {'PortBindings': None}}]), [])

    def test_same_running_container_reports_both_exact_host_ports(self):
        data = self.item()
        data['HostConfig']['PortBindings']['19104/tcp'] = [{'HostIp': '127.0.0.1', 'HostPort': '19204'}]
        claims = contract.port_claims([data])
        self.assertEqual({v['hostPort'] for v in claims}, {'19203', '19204'})
        self.assertTrue(all(v['blocking'] for v in claims))


class SmokeStopAdmissionTests(unittest.TestCase):
    @staticmethod
    def smoke():
        data = fixture()
        data['Id'] = 'b' * 64
        data['Name'] = '/fortis-gateway-candidate-smoke-r3-20261105'
        data['State']['Status'] = 'running'
        data['HostConfig']['AutoRemove'] = False
        data['Mounts'][0]['Name'] = 'fortis-r7-state-candidate-smoke-r3-20261105'
        return data

    def test_only_isolated_known_smoke_is_admitted(self):
        data = self.smoke()
        receipt = contract.admit_smoke_stop(data)
        self.assertEqual(receipt['containerId'], 'b' * 64)
        self.assertEqual(receipt['stateVolumeRetained'], data['Mounts'][0]['Name'])

    def test_production_review_state_unknown_images_and_auto_removal_rejected(self):
        mutations = [
            lambda d: d.update(Name='/fortis-approvals-gateway'),
            lambda d: d.update(Image='sha256:unknown'),
            lambda d: d.update(Image='sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402'),
            lambda d: d['Mounts'][0].update(Name='fortis-r7-state'),
            lambda d: d['Mounts'][0].update(Name=contract.STATE),
            lambda d: d['Mounts'][0].update(Name='fortis-other-production-state'),
            lambda d: d['Mounts'][1].update(RW=True),
            lambda d: d['Mounts'].append({'Type': 'bind', 'Destination': '/host'}),
            lambda d: d['HostConfig'].update(AutoRemove=True),
            lambda d: d['HostConfig'].update(Privileged=True),
            lambda d: d['Config'].update(User='0:0'),
            lambda d: d['Config'].update(Cmd=['something-else']),
            lambda d: d['HostConfig']['PortBindings']['19103/tcp'][0].update(HostPort='19103'),
        ]
        for index, change in enumerate(mutations):
            with self.subTest(mutation=index):
                data = self.smoke()
                change(data)
                with self.assertRaises(RuntimeError):
                    contract.admit_smoke_stop(data)
