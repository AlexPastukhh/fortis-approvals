"""Offline owner storage denial probe, and two-role source review only.

Synthetic role impersonation is confined to unit tests; a real host must
execute the OS-open probe under its actual, independently deployed UIDs.
"""
import copy
import errno
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied, Stale
from fortis_approvals.registry import owner_storage_denial as p
from fortis_approvals.tests import test_registry_owner_runtime_isolation as runtime_fixture


class StorageDenialTests(unittest.TestCase):
    setUp=runtime_fixture.RuntimeIsolationTests.setUp

    def _evidence(self,role,*,error='EACCES'):
        pid=os.getpid()
        layout=copy.deepcopy(self.layout)
        layout[role+'Pid']=pid
        if role=='registry':layout['repoPid']=pid+50
        else:layout['registryPid']=pid+50
        if layout['ownerPid']==pid:layout['ownerPid']=pid+60
        row=copy.deepcopy(self.procs[role])
        row['pid']=pid
        scope=copy.deepcopy(self.peer)
        layout['peerProfileDigest']=p._hash(scope)
        layout_digest=p._hash(layout)
        uid=scope['registryUid'] if role=='registry' else layout['repoUid']
        gid=scope['registryGid'] if role=='registry' else layout['repoGid']
        with patch.object(p.os,'geteuid',return_value=uid),\
             patch.object(p.os,'getegid',return_value=gid),\
             patch.object(p.os,'getuid',return_value=uid),\
             patch.object(p.os,'getgid',return_value=gid),\
             patch.object(p,'_boot_id',return_value=layout['bootId']),\
             patch.object(p,'_read_process',return_value=row),\
             patch.object(p,'_denied_open',return_value=error):
            value=p.observe_storage_denial(
                role=role,peer_profile_reader=lambda:copy.deepcopy(scope),
                expected_peer_profile_digest=p._hash(scope),
                layout_reader=lambda:copy.deepcopy(layout),
                expected_layout_digest=layout_digest)
        return value,layout

    def _review(self,reg,repo):
        return p.compose_storage_denial_review(
            registry_observation=reg,repo_observation=repo,
            peer_profile_reader=lambda:copy.deepcopy(self.peer),
            expected_peer_profile_digest=p._hash(self.peer),
            layout_reader=lambda:copy.deepcopy(self.layout),
            expected_layout_digest=p._hash(self.layout))

    def _pair(self):
        # Two distinct synthetic host processes with expected PIDs.
        observations={}
        for role in ('registry','repo'):
            row=copy.deepcopy(self.procs[role])
            evidence={'schemaVersion':1,'format':'registry-owner-storage-denial-v1',
                      'role':role,'instanceId':self.peer['instanceId'],
                      'scopeDigest':self.peer['scopeDigest'],
                      'enrollmentReceiptDigest':self.peer['enrollmentReceiptDigest'],
                      'peerProfileDigest':p._hash(self.peer),
                      'layoutDigest':p._hash(self.layout),
                      'bootId':self.layout['bootId'],
                      'ownerStatePath':self.layout['ownerStatePath'],
                      'process':row,
                      'attempts':{k:'EACCES' for k in p._ATTEMPT_NAMES}}
            observations[role]={
                'result':'OWNER_STORAGE_DENIAL_OBSERVATION_CANDIDATE',
                'evidence':evidence,'evidenceDigest':p._hash(evidence),
                **{k:False for k in p._REQUIRED_FALSE}}
        return observations['registry'],observations['repo']

    def test_true_os_open_of_accessible_regular_file_fails(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        path=Path(temp.name)/'owner.sqlite'
        path.write_bytes(b'unchanged')
        with self.assertRaisesRegex(Denied,'REGISTRY_DENIAL_STORAGE_ACCESSIBLE'):
            p._denied_open(str(path),os.O_RDWR)
        self.assertEqual(path.read_bytes(),b'unchanged')

    def test_missing_path_or_symlink_does_not_prove_denial(self):
        with self.assertRaisesRegex(Denied,'REGISTRY_DENIAL_NOT_PROVEN'):
            p._denied_open(str(self.root/'absent.sqlite'),os.O_RDONLY)
        temp=self.root/'target.sqlite';temp.write_bytes(b'data')
        linked=self.root/'linked.sqlite';linked.symlink_to(temp)
        with self.assertRaisesRegex(Denied,'REGISTRY_DENIAL_NOT_PROVEN'):
            p._denied_open(str(linked),os.O_RDONLY)

    def test_real_open_failure_accepts_only_eacces_or_eperm(self):
        for error,expected in ((errno.EACCES,'EACCES'),(errno.EPERM,'EPERM')):
            with patch.object(p.os,'open',side_effect=PermissionError(error,'forbidden')):
                self.assertEqual(p._denied_open('/owner/private.sqlite',os.O_RDWR),expected)
        for error in (errno.ENOENT,errno.EISDIR,errno.EROFS,errno.ENOTDIR,errno.ELOOP):
            with patch.object(p.os,'open',side_effect=OSError(error,'bad')):
                with self.subTest(error=error),self.assertRaisesRegex(
                        Denied,'REGISTRY_DENIAL_NOT_PROVEN'):
                    p._denied_open('/owner/private.sqlite',os.O_RDONLY)

    def test_role_source_positive_is_always_candidate(self):
        for role in ('registry','repo'):
            value,layout=self._evidence(role)
            self.assertEqual(value['result'],'OWNER_STORAGE_DENIAL_OBSERVATION_CANDIDATE')
            self.assertEqual(value['evidenceDigest'],p._hash(value['evidence']))
            self.assertEqual(value['evidence']['process']['pid'],os.getpid())
            self.assertEqual(value['evidence']['attempts'],{k:'EACCES' for k in p._ATTEMPT_NAMES})
            self.assertTrue(all(value[k] is False for k in p._REQUIRED_FALSE))
            self.assertEqual(value['evidence']['layoutDigest'],p._hash(layout))

    def test_wrong_real_current_uid_stops_before_attempt(self):
        with self.assertRaisesRegex(Denied,'REGISTRY_DENIAL_ACTOR_IDENTITY'):
            p.observe_storage_denial(
                role='registry',
                peer_profile_reader=lambda:copy.deepcopy(self.peer),
                expected_peer_profile_digest=p._hash(self.peer),
                layout_reader=lambda:copy.deepcopy(self.layout),
                expected_layout_digest=p._hash(self.layout))

    def test_role_user_input_cannot_force_owner_or_advance(self):
        with self.assertRaisesRegex(Denied,'REGISTRY_DENIAL_ROLE_INVALID'):
            p._role_identity('owner',self.layout,self.peer)
        with self.assertRaisesRegex(Denied,'REGISTRY_DENIAL_ROLE_INVALID'):
            p._role_identity('checkpoint.advance',self.layout,self.peer)

    def test_denied_open_attempts_cover_dir_read_db_read_db_rw(self):
        calls=[]
        def fake(path,flags):
            calls.append((path,flags))
            return 'EPERM'
        with patch.object(p,'_denied_open',side_effect=fake):
            value=p._attempts(Path('/var/owner/state.sqlite'))
        self.assertEqual(set(value),set(p._ATTEMPT_NAMES))
        self.assertEqual([x[0] for x in calls],
                         ['/var/owner','/var/owner/state.sqlite','/var/owner/state.sqlite'])
        self.assertEqual(calls[2][1],os.O_RDWR)
        self.assertEqual(calls[1][1],os.O_RDONLY)
        self.assertEqual(calls[0][1]&os.O_DIRECTORY,os.O_DIRECTORY)

    def test_review_two_roles_still_not_host_attestation(self):
        registry,repo=self._pair()
        result=self._review(registry,repo)
        self.assertEqual(result['result'],'OWNER_STORAGE_DENIAL_REVIEW_CANDIDATE')
        self.assertEqual(result['observationDigest'],p._hash(result['observation']))
        self.assertTrue(all(result[k] is False for k in p._REQUIRED_FALSE))
        self.assertEqual(self._review(registry,repo),result)

    def test_review_rejects_missing_or_duplicate_role(self):
        registry,repo=self._pair()
        with self.assertRaisesRegex(Denied,'REGISTRY_DENIAL_EVIDENCE_INVALID'):
            self._review(registry,registry)
        with self.assertRaisesRegex(Denied,'REGISTRY_DENIAL_EVIDENCE_INVALID'):
            self._review(repo,repo)

    def test_review_rejects_missing_attempts_or_wrong_result(self):
        registry,repo=self._pair()
        for which in ('missing','fake','bool','status'):
            bad=copy.deepcopy(registry)
            if which=='missing':bad['evidence']['attempts'].pop('ownerDbReadWrite')
            if which=='fake':bad['evidence']['attempts']['ownerDbReadWrite']='ENOENT'
            if which=='bool':bad['admissionAllowed']=True
            if which=='status':bad['result']='APPROVED'
            bad['evidenceDigest']=p._hash(bad['evidence'])
            with self.subTest(which=which),self.assertRaisesRegex(
                    Denied,'REGISTRY_DENIAL_EVIDENCE_INVALID'):
                self._review(bad,repo)

    def test_review_rejects_wrong_scope_or_unbound_original_digest(self):
        registry,repo=self._pair()
        for key,value in (('scopeDigest','f'*64),
                          ('enrollmentReceiptDigest','f'*64),
                          ('ownerStatePath','/tmp/malicious.sqlite'),
                          ('peerProfileDigest','f'*64),
                          ('bootId',str(uuid.uuid4()))):
            bad=copy.deepcopy(registry)
            bad['evidence'][key]=value
            bad['evidenceDigest']=p._hash(bad['evidence'])
            with self.subTest(key=key),self.assertRaisesRegex(
                    Denied,'REGISTRY_DENIAL_EVIDENCE_INVALID'):
                self._review(bad,repo)

    def test_review_rejects_shared_process_runtime(self):
        registry,repo=self._pair()
        for field in ('mountNamespace','cgroup'):
            bad=copy.deepcopy(repo)
            bad['evidence']['process'][field]=registry['evidence']['process'][field]
            bad['evidenceDigest']=p._hash(bad['evidence'])
            with self.subTest(field=field),self.assertRaisesRegex(
                    Denied,'REGISTRY_DENIAL_ROLE_NOT_SEPARATED'):
                self._review(registry,bad)

    def test_review_rejects_forbidden_process_capability(self):
        registry,repo=self._pair()
        for field,value in (('capEff',1),('capBnd',1),('noNewPrivs',0),
                            ('tracerPid',100),('gids',[0,0,0,0])):
            bad=copy.deepcopy(repo)
            bad['evidence']['process'][field]=value
            bad['evidenceDigest']=p._hash(bad['evidence'])
            with self.subTest(field=field),self.assertRaisesRegex(
                    Denied,'REGISTRY_DENIAL_PROCESS_IDENTITY'):
                self._review(registry,bad)

    def test_review_profile_change_blocked(self):
        registry,repo=self._pair()
        calls=[0]
        def changing():
            calls[0]+=1
            out=copy.deepcopy(self.layout)
            if calls[0]>1:out['repoPid']+=9
            return out
        with self.assertRaises(Denied):
            p.compose_storage_denial_review(
                registry_observation=registry,repo_observation=repo,
                peer_profile_reader=lambda:copy.deepcopy(self.peer),
                expected_peer_profile_digest=p._hash(self.peer),
                layout_reader=changing,
                expected_layout_digest=p._hash(self.layout))

    def test_denied_open_can_never_write_to_owner_file(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        state=Path(temp.name)/'state.sqlite';state.write_bytes(b'invariant')
        for flags in (os.O_RDONLY,os.O_RDWR):
            with self.assertRaisesRegex(Denied,'REGISTRY_DENIAL_STORAGE_ACCESSIBLE'):
                p._denied_open(str(state),flags)
        self.assertEqual(state.read_bytes(),b'invariant')
