"""E1.3 source-only Registry immutable mount: no host or owner GO.

The actual mountinfo/UID/device/peer checks MUST be rerun under separate
non-Production host identities; local tests replace only those host seams.
"""
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied, canonical
from fortis_approvals import r7_registry_reader_mount as mount
from fortis_approvals import r7_unified_server as server
from fortis_approvals.extensions.runtime import ExtensionConfig
from fortis_approvals.integrations.registry.candidate_gateway import GatewayRegistryUnixCandidateRead


def incumbent_286_ci_profile():
    # The retained profile is independent of later CI changes.
    rows = [
        ('Source CI', 408327525, '.github/workflows/source-ci.yml',
         ['offline-tests', 'audit-projections'],
         'f5a5ae93f28673bc9c981ba5702565ba91f115f1fe52d60aca3324a0fbd9fab1'),
        ('Fortis Release Impact', 414303977, '.github/workflows/release-impact.yml',
         ['release-impact'],
         'e141908e8aeadf41088e7998842f72dea52ea4332346a5e3bd084e7de7d65218'),
        ('P5 Retained Impact', 425664934, '.github/workflows/p5-retained-impact.yml',
         ['p5-retained-impact'],
         '432fd4be8191eb85eb6e9d3f11249dd33b8d192a233807adbdc1835811ea4e3d'),
    ]
    return {
        'schemaVersion': 1, 'kind': 'P5_SOURCE_POLICY_CANDIDATE',
        'repository': 'fortis-approvals', 'baseRef': 'main',
        'workflows': [dict(name=name, ident=ident, path=path, jobs=jobs, sha256=sha256)
                      for name, ident, path, jobs, sha256 in rows],
        'appId': 15368, 'appSlug': 'github-actions',
    }

def functional_mount_config(*, baseline_sha='a'*40, catalog_sha='b'*64, validator_revision='d'*40,
                            instance_id=None, ci_profile=None):
    from fortis_approvals.integrations.github.gateway.p5_ci_binding import policy
    from fortis_approvals.integrations.registry.read_contract import REPOSITORY
    common={'schemaVersion':1,'repository':REPOSITORY,'enrollmentId':str(uuid.uuid4()),
            'baselineSha':baseline_sha}
    def digest(v):return hashlib.sha256(canonical(v).encode()).hexdigest()
    binding={**common,'catalogSha256':catalog_sha,'bindings':[],'components':[]}
    baseline={**common,'catalogSha256':catalog_sha,'bindingDigest':digest(binding),
              'acceptanceReceiptDigest':'c'*64}
    reference={**common,'revision':1,'previousDigest':'0'*64,'acceptanceReceiptDigest':'c'*64,
               'effectiveAt':1700000000,'maxReviewToMergeSeconds':3600,'clockToleranceSeconds':10,
               'profile':policy() if ci_profile is None else ci_profile}
    decision = None
    if instance_id is not None:
        decision = {'schemaVersion':1, 'decision':'OWNER_FUNCTIONAL_V1_BOUNDARY_APPROVED',
                    'approvedAt':reference['effectiveAt'], 'proposalDigest':'e'*64,
                    'enrollmentAccepted':False, 'admissionAllowed':False, 'activationRequired':True,
                    'instanceId':instance_id, **{k:baseline[k] for k in (
                        'enrollmentId','baselineSha','catalogSha256','bindingDigest')},
                    'cutover':{'releaseNonce':str(uuid.uuid4()), 'validatorRevision':validator_revision,
                        'registryImageId':'sha256:'+'b'*64, 'gatewayImageId':'sha256:'+'c'*64,
                        'gatewaySourceDigest':'d'*64}}
        baseline['acceptanceReceiptDigest'] = reference['acceptanceReceiptDigest'] = digest(decision)
    scope={k:baseline[k] for k in ('repository','enrollmentId','baselineSha','catalogSha256','bindingDigest')}
    scope.update(baselineDigest=digest(baseline),policyReferenceDigest=digest(reference))
    config={'schemaVersion':1,'collectorInstanceId':str(uuid.uuid4()),'validatorRevision':validator_revision,
            'baseline':baseline,'binding':binding,'policyReference':reference}
    if decision is not None:
        receipt = {'result':'PILOT_SCHEMA3_GENESIS_BACKUP_RESTORE_PASS',
            'instanceId':instance_id, 'scopeDigest':digest(scope), 'specSha256':'b'*64,
            'sourceSha':baseline_sha, 'backupId':str(uuid.uuid4()),
            'fileDigests':{k:'c'*64 for k in ('sqlite','manifest','config')},
            **dict.fromkeys(('hostAccepted','enrollmentAccepted','admissionAllowed',
                            'registryServiceStarted','rollbackProtected'),False)}
        config.update(schemaVersion=2, boundaryDecision=decision, bootstrapReceipt=receipt)
    return config, scope


class RegistryTrustedMountTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='r7-registry-owned-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'mounted-owner-profile'
        self.root.mkdir(mode=0o700)
        self.nonce = str(uuid.uuid4())
        self.source = 'a'*64
        self.profile = {
            'schemaVersion': 2, 'enabled': True,
            'purpose': 'registry-candidate-read-v1',
            'releaseNonce': self.nonce, 'gatewaySourceDigest': self.source,
            'instanceId': str(uuid.uuid4()), 'scopeDigest': 'b'*64,
            'socketPath': '/run/fortis-registry-read/reader.sock',
            'registryUid': os.geteuid()+11, 'registryGid': os.getegid()+12,
            'registryPidfdInode': 233, 'registryKernelBootId': mount._boot_id(),
            'readerUid': os.geteuid(),
            'readerGid': os.getegid(), 'socketDevice': 55,
            'socketInode': 66,
        }
        self.write()

    def write(self, data=None, raw=None):
        f=self.root/'profile.json'
        f.write_bytes(canonical(self.profile if data is None else data).encode()
                      if raw is None else raw)
        f.chmod(0o600)

    def load(self, *, nonce=None, source=None, socket_ok=True):
        with patch.object(mount, '_check_owner_readonly_mount', return_value=None), \
             patch.object(GatewayRegistryUnixCandidateRead, '_check_identity',
                          return_value=None), \
             patch.object(GatewayRegistryUnixCandidateRead, '_check_socket',
                          side_effect=(lambda: (55,66)) if socket_ok
                          else Denied('REGISTRY_CANDIDATE_SOCKET_CHANGED')):
            return mount.load_owner_registry_reader(
                root=self.root,
                expected_release_nonce=self.nonce if nonce is None else nonce,
                expected_source_digest=self.source if source is None else source)

    def test_source_only_optin_missing_disabled_valid_profile_readonly_reader(self):
        self.assertIsNone(mount.load_owner_registry_reader(
            root=self.root/'not-installed', expected_release_nonce=self.nonce,
            expected_source_digest=self.source))
        if os.geteuid() == 0 or os.getegid() == 0:
            self.skipTest('Root may not use an owner Registry reader mount')
        reader=self.load()
        self.assertIs(type(reader),GatewayRegistryUnixCandidateRead)
        self.assertEqual(str(reader._path),self.profile['socketPath'])
        self.assertEqual(reader._registry,(0,os.geteuid()+11,os.getegid()+12))
        self.assertEqual(reader._owner_pidfd,(233,mount._boot_id()))
        self.assertEqual(reader._reader,(os.geteuid(),os.getegid()))
        self.assertEqual(reader._endpoint,(55,66))

    def test_functional_profile_seals_scope_and_private_planner_key(self):
        from fortis_approvals.integrations.github.gateway.functional_review_runtime import FunctionalRegistryConfiguration
        config, scope = functional_mount_config()
        def digest(v):return hashlib.sha256(canonical(v).encode()).hexdigest()
        raw=canonical(config).encode()
        key=os.urandom(32)
        for name,data in (('functional.json',raw),('planner.key',key)):
            file=self.root/name;file.write_bytes(data);file.chmod(0o600)
        self.profile.update(schemaVersion=3,purpose='registry-functional-local-candidate-v1',
            scopeDigest=digest(scope),functionalConfigSha256=hashlib.sha256(raw).hexdigest(),
            plannerKeySha256=hashlib.sha256(key).hexdigest())
        self.write()
        reader=self.load()
        self.assertIs(type(reader._functional_config),FunctionalRegistryConfiguration)
        self.assertEqual(reader._functional_config.digest,digest(config))
        (self.root/'planner.key').write_bytes(os.urandom(32))
        with self.assertRaises(Denied):self.load()
        (self.root/'planner.key').write_bytes(key)
        (self.root/'functional.json').write_bytes(canonical({**config,'validatorRevision':'e'*40}).encode())
        with self.assertRaises(Denied):self.load()
        (self.root/'functional.json').write_bytes(raw)
        self.profile['scopeDigest']='f'*64;self.write()
        with self.assertRaises(Denied):self.load()

        # A managed release seals identity to existing protected material.
        # Boot/process/socket coordinates never enter the immutable digest.
        self.profile['scopeDigest'] = digest(scope)
        for field in mount._LIVE_PEER_FIELDS:
            del self.profile[field]
        self.profile['schemaVersion'] = 4
        self.write()
        with patch.object(mount, '_boot_id', side_effect=AssertionError), \
             patch.object(mount, '_check_live_peer') as live:
            reader = self.load()
            self.assertIsNone(reader._owner_pidfd)
            self.assertEqual(reader._peer_key, key)
            live.assert_called_once_with(reader)
        self.profile['socketInode'] = 77
        self.write()
        with self.assertRaises(Denied):
            self.load()

    def test_real_kernel_pidfd_owner_mode_rejects_wrong_process(self):
        # One-UID source-only fixture: kernel pidfd is real but owner seal is
        # synthetic. Cross-UID/cross-namespace admission is an owner host gate.
        from fortis_approvals.integrations.registry.owner_pinned_pidfd import _boot_id
        import socket
        fd=os.pidfd_open(os.getpid())
        try:
            actual_inode=os.fstat(fd).st_ino
        finally:
            os.close(fd)
        with patch.object(GatewayRegistryUnixCandidateRead,
                          '_check_identity', return_value=None):
            reader=GatewayRegistryUnixCandidateRead(
                socket_path='/run/fortis-registry-read/reader.sock',
                instance_id=self.profile['instanceId'],scope_digest='b'*64,
                registry_uid=os.geteuid(), registry_gid=os.getegid(),
                registry_pidfd_inode=actual_inode,
                registry_boot_id=_boot_id(),
                reader_uid=os.geteuid()+11,reader_gid=os.getegid()+12,
                socket_device=55,socket_inode=66)
        self.assertEqual(reader._owner_pidfd,(actual_inode,_boot_id()))
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            self.assertEqual(reader._peer(left),
                             (os.geteuid(),os.getegid(),actual_inode))
            reader._owner_pidfd=(actual_inode+1,_boot_id())
            with self.assertRaisesRegex(Denied,'REGISTRY_PIDFD_PROCESS_NOT_PINNED'):
                reader._peer(left)
        finally:
            left.close();right.close()
        # Owner-mode may NOT be silently combined with numeric PID fallback.
        with patch.object(GatewayRegistryUnixCandidateRead,
                          '_check_identity',return_value=None):
            with self.assertRaisesRegex(Denied,'CONFIG_DENIED'):
                GatewayRegistryUnixCandidateRead(
                    socket_path='/run/fortis-registry-read/reader.sock',
                    instance_id=self.profile['instanceId'],scope_digest='b'*64,
                    registry_uid=os.geteuid(),registry_gid=os.getegid(),
                    registry_pid=1,registry_pidfd_inode=actual_inode,
                    registry_boot_id=_boot_id(), reader_uid=os.geteuid()+11,
                    reader_gid=os.getegid()+12,socket_device=55,socket_inode=66)

    def test_return_preflight_requires_same_sealed_material_and_live_replacement(self):
        old = {**self.profile, 'schemaVersion': 3,
               'functionalConfigSha256': 'd'*64, 'plannerKeySha256': 'e'*64}
        nonce = str(uuid.uuid4())
        new = {**old, 'releaseNonce': nonce, 'socketInode': 99, 'registryPidfdInode': 255}
        live = object()
        rows = {mount.RETAINED_MOUNT: (object(), old, '1'*64),
                mount.MOUNT: (live, new, '2'*64)}
        params = dict(source_nonce=self.nonce, source_profile_digest='1'*64,
                      return_nonce=nonce, source_digest=self.source)
        with patch.object(mount, '_load_sealed_registry_reader',
                          side_effect=lambda root, *_args, **_kwargs: rows[root]), \
             patch.object(mount, '_check_live_peer') as verify:
            self.assertEqual(mount.reviewed_registry_return_profile(**params), '2'*64)
            verify.assert_called_once_with(live)
            verify.reset_mock()
            for field in ('plannerKeySha256', 'functionalConfigSha256', 'scopeDigest',
                          'instanceId', 'gatewaySourceDigest', 'registryKernelBootId'):
                with self.subTest(field=field):
                    deltas = {**new, field: 'changed'}
                    rows[mount.MOUNT] = (live, deltas, '3'*64)
                    with self.assertRaisesRegex(Denied, 'RETURN_PROFILE_DENIED'):
                        mount.reviewed_registry_return_profile(**params)
            verify.assert_not_called()
            rows[mount.MOUNT] = (live, new, '2'*64)
            with self.assertRaisesRegex(Denied, 'RETURN_PROFILE_DENIED'):
                mount.reviewed_registry_return_profile(**{**params, 'source_profile_digest':'0'*64})
            verify.side_effect = Denied('REGISTRY_PIDFD_PROCESS_NOT_PINNED')
            with self.assertRaisesRegex(Denied, 'REGISTRY_PIDFD_PROCESS_NOT_PINNED'):
                mount.reviewed_registry_return_profile(**params)

    def test_crash_return_pins_historical_boot_and_authenticates_new_peer(self):
        previous, current = str(uuid.uuid4()), str(uuid.uuid4())
        nonce = str(uuid.uuid4())
        old = {**self.profile, 'schemaVersion': 3, 'registryKernelBootId': previous,
               'functionalConfigSha256': 'd'*64, 'plannerKeySha256': 'e'*64}
        new = {**old, 'releaseNonce': nonce, 'registryKernelBootId': current,
               'registryPidfdInode': 18, 'socketDevice': 26, 'socketInode': 31}
        live = object()

        def load(root, *_args, historical_boot_id=None):
            if root == mount.RETAINED_MOUNT:
                self.assertEqual(historical_boot_id, previous)
                return object(), old, '1'*64
            self.assertIsNone(historical_boot_id)
            return live, new, '2'*64

        params = dict(source_nonce=self.nonce, source_profile_digest='1'*64,
                      return_nonce=nonce, source_digest=self.source,
                      crash_boot_ids={'previous': previous, 'current': current})
        with patch.object(mount, '_boot_id', return_value=current), \
             patch.object(mount, '_load_sealed_registry_reader', side_effect=load), \
             patch.object(mount, '_check_live_peer') as check:
            self.assertEqual(mount.reviewed_registry_return_profile(**params), '2'*64)
            check.assert_called_once_with(live)
            check.reset_mock()
            for boot in (previous, 'invalid'):
                with self.assertRaisesRegex(Denied, 'RETURN_CRASH_BOOT_DENIED'):
                    mount.reviewed_registry_return_profile(
                        **{**params, 'crash_boot_ids': {'previous': previous, 'current': boot}})
            with self.assertRaisesRegex(Denied, 'RETURN_PROFILE_DENIED'):
                mount.reviewed_registry_return_profile(**{**params, 'source_profile_digest': '0'*64})
            new['functionalConfigSha256'] = 'f'*64
            with self.assertRaisesRegex(Denied, 'RETURN_PROFILE_DENIED'):
                mount.reviewed_registry_return_profile(**params)
            check.assert_not_called()

    def test_reviewed_registry_mount_digest_fails_closed_without_peer_and_source(self):
        from hashlib import sha256
        if os.geteuid() == 0:
            self.skipTest('Root cannot load Registry owner profile')
        with patch.object(mount, '_check_owner_readonly_mount',return_value=None), \
             patch.object(GatewayRegistryUnixCandidateRead,
                          '_check_identity',return_value=None), \
             patch.object(GatewayRegistryUnixCandidateRead,
                          '_check_socket',return_value=(55,66)):
            with self.assertRaisesRegex(Denied,'MOUNT_PEER_UNAVAILABLE'):
                mount.reviewed_registry_reader_mount_digest(
                    root=self.root,expected_release_nonce=self.nonce,
                    expected_source_digest=self.source)
            with self.assertRaisesRegex(Denied,'MOUNT_PROFILE_DENIED'):
                mount.reviewed_registry_reader_mount_digest(
                    root=self.root,expected_release_nonce=str(uuid.uuid4()),
                    expected_source_digest=self.source)
        with self.assertRaisesRegex(Denied,'MOUNT_NOT_ENABLED'):
            mount.reviewed_registry_reader_mount_digest(
                root=self.root/'absent', expected_release_nonce=self.nonce,
                expected_source_digest=self.source)

    def test_exact_mountinfo_parser_requires_single_ro_mount_point(self):
        path=os.fsencode(self.root)
        row=lambda x,opts: b'24 3 8:1 / '+x+b' '+opts+b' - ext4 /dev/data rw\n'
        self.assertTrue(mount._exact_readonly_mountinfo(row(path,b'ro,relatime'),self.root))
        self.assertFalse(mount._exact_readonly_mountinfo(row(path,b'rw,relatime'),self.root))
        self.assertFalse(mount._exact_readonly_mountinfo(row(path+b'/child',b'ro'),self.root))
        self.assertFalse(mount._exact_readonly_mountinfo(row(path+b'-extra',b'ro'),self.root))
        self.assertFalse(mount._exact_readonly_mountinfo(row(path,b'ro')*2,self.root))
        self.assertFalse(mount._exact_readonly_mountinfo(b'',self.root))
        self.assertFalse(mount._exact_readonly_mountinfo(row(path,b'ro')+b'x'*524288,self.root))
        with self.assertRaisesRegex(Denied,'READONLY_REQUIRED'):
            mount._check_owner_readonly_mount(self.root)

    def test_mode_symlink_and_unreviewed_extra_file_fail_closed(self):
        if os.geteuid()==0:self.skipTest('Root cannot load Registry mount')
        self.root.chmod(0o755)
        with self.assertRaisesRegex(Denied,'DIRECTORY_DENIED'):self.load()
        self.root.chmod(0o700)
        (self.root/'rogue').write_text('x')
        with self.assertRaisesRegex(Denied,'FILES_DENIED'):self.load()
        (self.root/'rogue').unlink()
        (self.root/'profile.json').chmod(0o644)
        with self.assertRaisesRegex(Denied,'FILE_DENIED'):self.load()
        self.write()
        symlink=Path(self.tmp.name)/'symlink'
        symlink.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(Denied,'DIRECTORY_DENIED'):
            mount.load_owner_registry_reader(root=symlink,
                expected_release_nonce=self.nonce,expected_source_digest=self.source)

    def test_signature_nonce_scope_and_unsafe_fields_denied(self):
        if os.geteuid()==0:self.skipTest('Root cannot load Registry mount')
        for change in (
            {'enabled':False}, {'schemaVersion':True},
            {'schemaVersion':1}, {'registryPid':233},
            {'registryPidfdInode':0},
            {'registryKernelBootId':'00000000-0000-0000-0000-000000000000'},
            {'releaseNonce':str(uuid.uuid4())},
            {'gatewaySourceDigest':'z'*64},
            {'purpose':'registry-writer-v1'},
            {'socketPath':'/tmp/../escape'},
            {'readerUid':self.profile['registryUid']},
            {'registryGid':self.profile['readerGid']},
            {'unsafeRequestActor':'owner'},
        ):
            with self.subTest(change=change):
                self.write(self.profile|change)
                with self.assertRaises(Denied):self.load()
        self.write()
        for v in ('{"enabled":true,"enabled":false}',
                  canonical(self.profile)+'\n'):
            with self.subTest(noncanonical=v[:18]):
                self.write(raw=v.encode())
                with self.assertRaises(Denied):self.load()
        self.write()
        with self.assertRaises(Denied):self.load(nonce=str(uuid.uuid4()))
        with self.assertRaises(Denied):self.load(source='c'*64)
        with self.assertRaises(Denied):self.load(socket_ok=False)

    def test_registry_image_is_private_and_catalog_explicit(self):
        root=Path(__file__).resolve().parents[2]
        recipe=(root/'fortis_approvals/deploy/Dockerfile-Registry-Read-Candidate').read_text()
        catalog=(root/'release/targets.yaml').read_text()
        gateway=(root/'fortis_approvals/deploy/Dockerfile-Gateway-Modularized-Candidate').read_text()
        assert 'USER ${REGISTRY_UID}:${REGISTRY_GID}' in recipe
        self.assertIn('--owner-config',recipe)
        self.assertIn('/run/fortis-registry-runtime/profile.json',recipe)
        self.assertIn('local_candidate_read_service',recipe)
        self.assertNotIn('EXPOSE ',recipe)
        self.assertNotIn('VOLUME ',recipe)
        self.assertNotIn('CMD ["bash"',recipe)
        self.assertIn('r7_registry_reader_mount.py',gateway)
        self.assertIn('registry-candidate-reader-image',catalog)
        self.assertIn('fortis-registry-pilot',catalog)
        self.assertIn('environments: [non-production]',catalog)
        after=catalog.split('noDeploymentPaths:',1)[1]
        for name in ('functional_v1_journal.py', 'state_journal.py',
                     'state_journal_v2.py','local_candidate_read_service.py',
                     'boundary.py'):
            self.assertNotIn('  - fortis_approvals/registry/'+name+'\n', after)
        # Verify every explicit source file in the new image COPY commands
        # exists in the *actual* build context; no accidental package omission.
        instructions=[]
        normalized=recipe.replace('\\\n',' ')
        for row in normalized.splitlines():
            if row.startswith('COPY '):
                pieces=row.split()[1:]
                assert len(pieces)>=2, row
                instructions.extend(pieces[:-1])
        self.assertTrue(instructions)
        for path in instructions:
            self.assertTrue((root/path).is_file(),path)
        # Recreate only the actual Dockerfile COPY-layer package in an
        # isolated temporary tree. No Docker build, socket, DB, grants or GO.
        with tempfile.TemporaryDirectory(prefix='registry-image-import-') as folder:
            destination=Path(folder)/'opt/fortis'
            for path in instructions:
                source=root/path
                parts=path.split('/')
                # The COPY destination groups each module by its package;
                # locate the corresponding final COPY command for this file.
                for logical in normalized.splitlines():
                    if logical.startswith('COPY ') and path in logical.split()[1:-1]:
                        target=logical.split()[-1]
                        break
                else:
                    self.fail('COPY entry missing: '+path)
                to=Path(folder)/target.lstrip('/')/source.name
                to.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source,to)
            cmd=[sys.executable,'-B','-I','-c',
                 'import sys;sys.path.insert(0,'+repr(str(destination))+');'
                 'from fortis_approvals.registry import local_candidate_read_service;'
                 'from fortis_approvals.registry.semantic_unix_service import owner_semantic_reader;'
                 'from fortis_approvals.registry.protected_source_write import ProtectedSourceWrite;'
                 'from fortis_approvals.registry.release_domain import ReleaseDomain;'
                 'from fortis_approvals.registry.release_event_journal import ReleaseEventJournal;'
                 'print("INACTIVE_REGISTRY_IMAGE_IMPORT_PASS")']
            result=subprocess.run(cmd, capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('INACTIVE_REGISTRY_IMAGE_IMPORT_PASS',result.stdout)

    def test_trusted_server_rejects_unbound_or_mismatched_extension_before_state(self):
        options={'schemaVersion':1,'providers':{'registry':{'credentials':{},
          'operations':{'candidate_head':{'policy':'DENY',
                                          'targets':['fortis-approvals']}}}}}
        config=ExtensionConfig(options)
        kw=dict(state='/not-created',grant_path='/missing-grant',
                sonar_token_path='/missing-token',cert_path='/missing-cert',
                key_path='/missing-key',region='eu',organizations=('test',),
                project_key='exact-project')
        with self.assertRaisesRegex(RuntimeError,'R7_REGISTRY_RELEASE_MOUNT_MISMATCH'):
            server.create_servers(**kw,extensions=config)
        with self.assertRaisesRegex(RuntimeError,'R7_REGISTRY_RELEASE_MOUNT_MISMATCH'):
            server.create_servers(**kw,registry_candidate_reader=object())
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(server,'_MAINTENANCE_INTERLOCK_MOUNT',Path(directory)):
                with self.assertRaisesRegex(RuntimeError,'R7_MAINTENANCE_REVIEWED_STARTUP_REQUIRED'):
                    server.create_servers(**kw)
        self.assertFalse(Path('/not-created').exists())


if __name__=='__main__':unittest.main()
