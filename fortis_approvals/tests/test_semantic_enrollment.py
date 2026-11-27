"""Reviewed semantic scope and owner-only principal, no live credential."""
import unittest
from fortis_approvals.core import Authenticator,Denied
from fortis_approvals.extensions.semantic_enrollment import SemanticEnrollment,OwnerPrincipalAuth
from fortis_approvals.extensions.composite_authority import reviewed_additive_authority
from fortis_approvals.extensions.owner_policy_engine_v2 import PolicyAdmission
from fortis_approvals.tests import test_composite_authority as fixture
from fortis_approvals.integrations.registry_contracts import semantic_contract as sc


class SemanticEnrollmentTests(unittest.TestCase):
    def test_owner_principal_not_machine_credential(self):
        machine=Authenticator({'machine':'agent-1'})
        active={'owner':True}
        auth=OwnerPrincipalAuth(machine,owners={'owner':'owner-only'},active_owner=lambda n:active[n])
        self.assertEqual(auth.authenticate('machine'),'agent-1')
        self.assertEqual(auth.owner_actor('owner'),'owner-only')
        with self.assertRaises(Denied):auth.authenticate('owner-only')
        active['owner']=False
        self.assertFalse(auth.active('owner-only'))
        self.assertIsNone(auth.owner_actor('owner'))
        with self.assertRaises(Denied):
            OwnerPrincipalAuth(machine,owners={'owner':'agent-1'},active_owner=lambda _:True)


class AuthorityTests(unittest.TestCase):
    setUp=fixture.ContextAuthorityTests.setUp
    make_core=fixture.ContextAuthorityTests.make_core

    def test_new_semantic_coordinate_explicit_pin_and_default_deny(self):
        old_coord=(fixture.ACTOR,'synthetic','set_free','record')
        old=self.make_core('old-sem.sqlite',{old_coord:'ALLOW'})
        old.install_policy_authority({old_coord:{'DENY','ALLOW'}},scope_binding={'origin':'synthetic'})
        coord=(fixture.ACTOR,'registry','list_components','scope')
        row=dict(zip(('actor','service','operation','target'),coord))
        row['subject']={'repository':'Owner/repo'}
        value={'schemaVersion':1,'sourceDigest':fixture.SOURCE,'grants':[row]}
        enrollment=SemanticEnrollment([row],source_digest=fixture.SOURCE,expected_digest=sc.digest(value))
        scope={**self.scope,'semanticScope':enrollment.sha}
        policies={old_coord:'ALLOW',fixture.PARENT:'DENY',fixture.CHILD:'DENY',coord:'DENY'}
        choices={old_coord:{'DENY','ALLOW'},fixture.PARENT:fixture.CHOICES,fixture.CHILD:fixture.CHOICES,coord:fixture.CHOICES}
        core=self.make_core('sem.sqlite',policies)
        pin=PolicyAdmission(core,choices,scope_binding=scope).sha
        args=dict(predecessor=old.authority,enrollment=self.enrollment,choices=choices,scope_binding=scope,
                  expected_predecessor_digest=old.authority.sha,expected_successor_digest=pin)
        candidate=reviewed_additive_authority(core,**args,semantic_enrollment=enrollment)
        self.assertEqual(candidate.baseline[coord],'DENY')
        self.assertTrue(enrollment.allows(*coord,{'repository':'Owner/repo'}))
        self.assertFalse(enrollment.allows(*coord,{'repository':'Owner/other'}))
        with self.assertRaises(Denied):reviewed_additive_authority(core,**args)
        with self.assertRaises(Denied):SemanticEnrollment([row],source_digest=fixture.SOURCE,expected_digest='f'*64)
