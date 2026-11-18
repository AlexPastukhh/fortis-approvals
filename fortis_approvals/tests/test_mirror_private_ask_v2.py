"""Offline private P4 ASK snapshot checks; no registered WRITE."""
from copy import deepcopy
from datetime import datetime,timezone
from types import SimpleNamespace
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.integrations.mirror.private_ask_v2 import (
    admit_private_ask, BoundAskPreview)
from fortis_approvals.integrations.mirror.extension import PROVIDER

NOW=1800000000
REPO='fortis-approvals'
ACTOR='repo:fixture'
READ_ID='32345678-1234-4123-8123-123456789012'
WRITE_ID='12345678-1234-4123-8123-123456789012'
PREVIEW_ID='22345678-1234-4123-8123-123456789012'
OLD,NEW,GEN='a'*40,'b'*40,'c'*64


def ts(n):
    return datetime.fromtimestamp(n,timezone.utc).isoformat(timespec='seconds')


class PrivateAskTests(unittest.TestCase):
    def setUp(self):
        self.params=dict(previewId=PREVIEW_ID,expectedHead=OLD,
                         targetSha=NEW,configGeneration=GEN)
        self.snapshot={
            'repoId':REPO,'previewId':PREVIEW_ID,'originIdentity':'AlexPastukhh/'+REPO,
            'expectedHead':OLD,'targetSha':NEW,'dockerHead':NEW,
            'configGeneration':GEN,'checkedAt':ts(NOW-40),'expiresAt':ts(NOW+80),
            'blockers':[],
            'sourceEvidence':{
                x:{'verification':'VERIFIED','checkedAt':ts(NOW-40),
                   'head':OLD if x=='windows' else NEW,'branch':'main',
                   'clean':True,'errorCode':None}
                for x in ('windows','docker','github')}}
        self.stored={'readRequestId':READ_ID,
                     'origin':'https://github.com/AlexPastukhh/'+REPO+'.git',
                     'snapshot':self.snapshot}
        self.fresh={'repoId':REPO,'origin':self.stored['origin'],
                    'available':True,'windowsHead':OLD,'dockerHead':NEW,
                    'targetSha':NEW,'checkedAt':ts(NOW-2),
                    'sourceEvidence':{
                        k:{**v,'checkedAt':ts(NOW-2)}
                        for k,v in self.snapshot['sourceEvidence'].items()}}
        self.row={'state':'DISPATCHED','decision':'approve','owner':'offline-owner',
                  'actor':ACTOR,'request':{'requestId':WRITE_ID,'service':'mirror',
                  'operation':'execute_windows_pull_v2','target':REPO,
                  'params':self.params}}
        self.ctx=SimpleNamespace(phase='preview',target=REPO,
                  params=deepcopy(self.params),request_id=WRITE_ID,
                  authenticated_actor=ACTOR,provider=SimpleNamespace(name='mirror'),
                  operation=SimpleNamespace(name='execute_windows_pull_v2',
                                            kind='write'),
                  runtime=SimpleNamespace(core=SimpleNamespace(
                      _read=lambda _:self.row)))
        self.seen=[]

    def lookup(self,repo,actor,pid):
        self.seen.append(('lookup',repo,actor,pid))
        return deepcopy(self.stored)

    def observe(self,repo,actor):
        self.seen.append(('observe',repo,actor))
        return deepcopy(self.fresh)

    def check(self):
        return admit_private_ask(self.ctx,lookup=self.lookup,
                                 observe=self.observe,now=NOW)

    def test_frozen_original_identity_before_and_after_core_approval(self):
        bound=self.check()
        self.assertIsInstance(bound,BoundAskPreview)
        self.assertEqual((bound.actor,bound.read_request_id),(ACTOR,READ_ID))
        self.assertEqual(dict(bound.execute_params()),self.params)
        with self.assertRaises(TypeError):
            bound.execute_params()['targetSha']='e'*40
        self.ctx.phase='execute'
        self.assertEqual(self.check(),bound)
        self.assertEqual([r[0] for r in self.seen],
                         ['lookup','observe','lookup','observe'])

    def test_no_trusted_channel_or_registered_write_is_fail_closed(self):
        with self.assertRaisesRegex(Denied,'MIRROR_ASK_TRUSTED_SOURCE_UNAVAILABLE'):
            admit_private_ask(self.ctx,now=NOW)
        self.assertEqual(self.seen,[])
        self.assertTrue(all(x.kind=='read' for x in PROVIDER.operations))
        self.assertNotIn('execute_windows_pull_v2',PROVIDER.api.routes)

    def test_public_actor_approval_and_phase_never_reach_private_lookup(self):
        for key,value in [('authenticated_actor',None),
                          ('authenticated_actor','bad space'),('phase','reconcile')]:
            old=getattr(self.ctx,key);setattr(self.ctx,key,value)
            with self.assertRaises(Denied):self.check()
            setattr(self.ctx,key,old)
        for key in ('actor','approved','origin','expiresAt','proof','requestId'):
            self.ctx.params={**self.params,key:True}
            with self.assertRaises(Denied):self.check()
        self.assertEqual(self.seen,[])

    def test_owner_approval_revalidated_before_private_source(self):
        self.ctx.phase='execute'
        for key,value in [('state','PENDING'),('decision','reject'),
                          ('owner',None),('actor','foreign')]:
            old=self.row[key];self.row[key]=value
            with self.assertRaisesRegex(Denied,'MIRROR_ASK_APPROVAL_REQUIRED'):
                self.check()
            self.row[key]=old
        self.assertEqual(self.seen,[])

    def test_changed_immutable_identity_denied(self):
        for key,value in [('previewId','42345678-1234-4123-8123-123456789012'),
                          ('expectedHead','d'*40),('targetSha','e'*40),
                          ('configGeneration','f'*64)]:
            self.ctx.params={**self.params,key:value}
            with self.assertRaisesRegex(Denied,'MIRROR_ASK_PREVIEW_MISMATCH'):
                self.check()
            self.ctx.params=deepcopy(self.params)
        self.assertEqual(self.snapshot['expiresAt'],ts(NOW+80))

    def test_source_moved_or_stale_denied(self):
        for key,value in [('available',False),('targetSha','f'*40),
                          ('windowsHead','c'*40),('origin','https://evil.invalid'),
                          ('checkedAt',ts(NOW-50))]:
            old=self.fresh[key];self.fresh[key]=value
            with self.assertRaisesRegex(Denied,'MIRROR_ASK_STALE'):
                self.check()
            self.fresh[key]=old
        old=self.fresh['sourceEvidence']['github']['head']
        self.fresh['sourceEvidence']['github']['head']='d'*40
        with self.assertRaisesRegex(Denied,'MIRROR_ASK_STALE'):
            self.check()
        self.fresh['sourceEvidence']['github']['head']=old

    def test_expiry_and_fake_private_lookup_denied(self):
        self.stored['origin']='https://evil.invalid'
        with self.assertRaisesRegex(Denied,'MIRROR_ASK_PRIVATE_LOOKUP_INVALID'):
            self.check()
        self.stored['origin']='https://github.com/AlexPastukhh/'+REPO+'.git'
        self.stored['readRequestId']=WRITE_ID
        with self.assertRaisesRegex(Denied,'MIRROR_ASK_PRIVATE_LOOKUP_INVALID'):
            self.check()
        self.stored['readRequestId']=READ_ID
        self.snapshot['expiresAt']=ts(NOW)
        with self.assertRaises(Denied):self.check()

    def test_distinct_trusted_lookup_and_fresh_observation(self):
        self.assertEqual(self.check().target_sha,NEW)
        self.assertEqual(self.seen,[
            ('lookup',REPO,ACTOR,PREVIEW_ID),('observe',REPO,ACTOR)])
