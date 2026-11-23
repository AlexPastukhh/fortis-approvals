"""E1.3b SOURCE-ONLY: exact Gateway pilot admission of two Registry mounts.

The owner Check/Apply script is deliberately NOT yet granted a Registry
activation flag. This tests Python admission only, not host approval or GO.
"""
from pathlib import Path
import unittest
import copy

from fortis_approvals.deploy import github_pilot_helpers as helper
from fortis_approvals.tests import test_github_pilot_package as fixture

_ROOT=Path(__file__).resolve().parents[2]
_PS=(_ROOT/'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()
_PROFILE='fortis-r7-registry-reader'
_SOCKET='fortis-registry-read'


def _mount(name, destination, rw=False):
    return dict(Type='volume',Name=name,Destination=destination,RW=rw,
                Source='/var/lib/docker/volumes/'+name+'/_data')


class RegistryExactMountAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.container,self.expected=fixture.AdmissionTests().fixture()
        self.container=copy.deepcopy(self.container)
        self.expected=copy.deepcopy(self.expected)

    def activate(self):
        self.expected['registryReaderVolume']=_PROFILE
        self.expected['registrySocketVolume']=_SOCKET
        self.container['Mounts'].extend((
            _mount(_PROFILE,'/run/r7-registry-reader'),
            _mount(_SOCKET,'/run/fortis-registry-read')))

    def test_legacy_without_registry_volume_remains_accepted(self):
        self.assertEqual(helper.admit(self.container,self.expected,pilot=True),
                         {'admission':'PASS'})

    def test_explicit_exact_pair_is_readonly_and_pilot_only(self):
        self.activate()
        self.assertEqual(helper.admit(self.container,self.expected,pilot=True),
                         {'admission':'PASS'})
        self.expected['registryReaderVolume']=''
        with self.assertRaises(RuntimeError):
            helper.admit(self.container,self.expected,pilot=True)
        self.expected['registryReaderVolume']=_PROFILE
        self.expected['registrySocketVolume']=''
        with self.assertRaises(RuntimeError):
            helper.admit(self.container,self.expected,pilot=True)

    def test_wrong_names_and_extra_or_missing_mounts_denied(self):
        for field in ('registryReaderVolume','registrySocketVolume'):
            for wrong in (None, True, '../../secrets', '/run/r7-registry-reader',
                          'fortis-review-secrets', 'fortis-registry-read-other'):
                self.setUp()
                self.activate()
                self.expected[field]=wrong
                with self.subTest(field=field,wrong=wrong), self.assertRaises(RuntimeError):
                    helper.admit(self.container,self.expected,pilot=True)
        self.setUp();self.activate();self.container['Mounts'].pop()
        with self.assertRaises(RuntimeError):
            helper.admit(self.container,self.expected,pilot=True)
        self.setUp();self.activate()
        self.container['Mounts'].append(_mount('fortis-rogue','/run/arbitrary'))
        with self.assertRaises(RuntimeError):
            helper.admit(self.container,self.expected,pilot=True)

    def test_wrong_mount_type_permission_destination_source_denied(self):
        for index in (-1,-2):
            for field,wrong in (('RW',True),('Type','bind'),
                                ('Destination','/run/r7-identity'),
                                ('Source','/var/lib/host/private'),
                                ('Name','fortis-gateway-root')):
                self.setUp();self.activate()
                self.container['Mounts'][index][field]=wrong
                with self.subTest(index=index,field=field),self.assertRaises(RuntimeError):
                    helper.admit(self.container,self.expected,pilot=True)

    def test_shared_pid_host_pid_or_other_privileged_access_still_denied(self):
        for field,value in (('PidMode','container:another'),('PidMode','host'),
                            ('UsernsMode','host'),('Privileged',True),
                            ('CapAdd',['SYS_ADMIN'])):
            self.setUp();self.activate()
            self.container['HostConfig'][field]=value
            with self.subTest(field=field),self.assertRaises(RuntimeError):
                helper.admit(self.container,self.expected,pilot=True)

    def test_owner_controller_does_not_implicitly_activate_registry(self):
        # Do not mistake helper allowlist for owner-approved Windows deploy.
        self.assertNotIn('EnableRegistryMount',_PS)
        self.assertNotIn('registryReaderVolume=$script:',_PS)
        self.assertNotIn('registrySocketVolume=$script:',_PS)


if __name__=='__main__': unittest.main()
