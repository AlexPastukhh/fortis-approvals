"""P4 signing roles: offline-only, no Windows, upstream, keys or deployment."""
import base64
from dataclasses import replace
import hashlib
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import uuid

from fortis_approvals.core import Authenticator, Core, Denied, canonical
from fortis_approvals.extensions.model import Operation, Provider
from fortis_approvals.extensions.http import Route
from fortis_approvals.extensions.runtime import Context, ExtensionConfig, ExtensionRuntime
from fortis_approvals.extensions.vault import CredentialVault, Secret
from fortis_approvals.integrations.mirror.signing import DOMAIN, sign_dispatch_identity
from fortis_approvals.integrations.review_schema import object_schema
from test_core import SyntheticOwnerVerifier

EMPTY = object_schema({})
EXECUTE_PARAMS = object_schema({'previewId': lambda value: None,
    'expectedHead': lambda value: None, 'targetSha': lambda value: None,
    'configGeneration': lambda value: None})
KEY = 'offline-owner-pin'
TOKEN = 'OFFLINE_P4_WRITE_BEARER'
GRANT = 'OFFLINE-MIRROR-P4-GRANT'


def identity():
    return dict(issuer='fortis-gateway', audience='fortis-mirror', service='mirror',
                operation='execute_windows_pull_v2',
                requestId='12345678-1234-4123-8123-123456789012', actor='fixture',
                repoId='fortis-approvals', previewId='22345678-1234-4123-8123-123456789012',
                expectedHead='a' * 40, targetSha='b' * 40, configGeneration='c' * 64)


class ProofBuilderTests(unittest.TestCase):
    def setUp(self):
        self.identity = identity()
        self.secret = Secret('offline-generation', base64.urlsafe_b64encode(b'\x05' * 32).decode('ascii').rstrip('='))

    def make(self, *, now=1800000000, expiry=1800000060):
        return sign_dispatch_identity(self.identity, key_id=KEY, secret=self.secret,
            now=now, preview_expires_at=expiry)

    def test_closed_identity_and_time_fail_before_signing(self):
        for change in ({'actor': 'not allowed!'}, {'requestId': 'no-uuid'},
                       {'repoId': 'x/y'}, {'expectedHead': 'B' * 40},
                       {'targetSha': 'a' * 40}, {'issuer': 'caller'},
                       {'configGeneration': 'c' * 63}, {'extra': 'ignored'}):
            with self.subTest(change=change), self.assertRaises(Denied):
                self.make_with_identity({**self.identity, **change})
        for now, exp in [(1800000060, 1800000060), (1800000000, 1799999999),
                         (True, 1800000060), (1800000000, False),
                         (4102444801, 4102444802)]:
            with self.subTest(now=now, expiry=exp), self.assertRaises(Denied):
                self.make(now=now, expiry=exp)
        with self.assertRaises(Denied):
            sign_dispatch_identity(self.identity, key_id='wrong key!', secret=self.secret,
                now=1800000000, preview_expires_at=1800000040)

    def make_with_identity(self, value):
        return sign_dispatch_identity(value, key_id=KEY, secret=self.secret,
            now=1800000000, preview_expires_at=1800000060)

    def test_noncanonical_private_seed_rejected_without_leaking_bytes(self):
        for bad in ['=', 'A' * 42 + 'B', 'A' * 42, 'A' * 44, 'A' * 41 + '==']:
            with self.subTest(seed_len=len(bad)), self.assertRaises(Denied):
                sign_dispatch_identity(self.identity, key_id=KEY,
                    secret=Secret('generation', bad), now=1800000000,
                    preview_expires_at=1800000060)

    @unittest.skipUnless(importlib.util.find_spec('cryptography'), 'cryptography unavailable in Repo Docker')
    def test_real_ed25519_signature_domain_fingerprint_and_tamper(self):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        result = self.make(now=1800000000, expiry=1800000050)
        self.assertEqual(set(result), {'schemaVersion', 'keyId', 'claims', 'signature'})
        self.assertEqual((result['schemaVersion'], result['keyId']), (1, KEY))
        claims = result['claims'];self.assertEqual((claims['issuedAt'], claims['expiresAt']), (1800000000, 1800000050))
        self.assertEqual(claims['fingerprint'], hashlib.sha256(canonical(self.identity).encode('ascii')).hexdigest())
        signed = DOMAIN + canonical(claims).encode('ascii')
        signature = base64.urlsafe_b64decode(result['signature'] + '==')
        self.assertEqual(len(signature), 64)
        key = Ed25519PrivateKey.from_private_bytes(b'\x05' * 32)
        key.public_key().verify(signature, signed)
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(signature, signed.replace(b'fortis-approvals', b'some-other-repo'))


class SigningRolesTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        vault_root = self.root / 'vault';vault_root.mkdir(mode=0o700)
        self.vault = CredentialVault(vault_root, uid=os.geteuid(), gid=os.getegid())
        self.vault.provision('mirror-read', 'OFFLINE_P4_READ_BEARER')
        self.write_secret = self.vault.provision('mirror-write', TOKEN)
        self.sign_secret = self.vault.provision('mirror-sign', base64.urlsafe_b64encode(b'\x05'*32).decode('ascii').rstrip('='))
        self.owner = SyntheticOwnerVerifier()
        self.core = Core(self.root/'core.sqlite', adapters={}, policies={},
            authenticator=Authenticator({GRANT: 'fixture'}),owner_verifier=self.owner)
        self.portal = SimpleNamespace(strong_operations=frozenset())
        self.seen = []
        self.parameters = dict(previewId=str(uuid.uuid4()), expectedHead='a'*40,
            targetSha='b'*40, configGeneration='c'*64)
        self.read = Operation('get_read', 'offline read', 'read', EMPTY, EMPTY,
            lambda ctx: {}, credential='link')
        self.write = Operation('execute_windows_pull_v2', 'offline WRITE (no upstream)',
            'write', EXECUTE_PARAMS, lambda v: None, self.execute,
            preview=self.preview, preview_result=EMPTY,
            credential='write_link', signing_credential='signer', signing_key_id=KEY)
        self.provider = Provider('mirror', (self.read,self.write))
        self.settings={'schemaVersion': 1, 'providers': {'mirror': {'credentials': {
            'link': 'mirror-read', 'write_link': 'mirror-write', 'signer': 'mirror-sign'},
            'operations': {'get_read': {'policy':'DENY', 'targets':['fortis-approvals']},
                           'execute_windows_pull_v2': {'policy':'ASK','targets':['fortis-approvals']}}}}}
        self.runtime = self.build()

    def build(self, settings=None):
        return ExtensionRuntime(ExtensionConfig(self.settings if settings is None else settings),
            providers=(self.provider,),actors=('fixture',),default_actor='fixture',vault=self.vault).install(
                self.core,self.portal)

    def preview(self, ctx):
        self.seen.append(('preview',ctx.phase,ctx.authenticated_actor))
        return {}

    def execute(self, ctx):
        self.seen.append(('execute',ctx.phase,ctx.authenticated_actor))
        ctx.sign_mirror_dispatch(ctx.params,preview_expires_at=int(time.time())+50)
        return {}

    def body(self):
        return dict(requestId=str(uuid.uuid4()),service='mirror',operation='execute_windows_pull_v2',
            target='fortis-approvals',params=dict(self.parameters),reason='offline source-only test')

    def decide(self,request_id,decision):
        row=self.core._read(request_id)
        proof=self.owner.proof(request_id,row['fingerprint'],decision)
        return self.core.owner_decide(request_id,decision,proof)

    def test_ask_reject_and_read_do_not_sign(self):
        body=self.body()
        with patch('fortis_approvals.integrations.mirror.signing.sign_dispatch_identity') as signer:
            row=self.runtime.call(GRANT,body)
            self.assertEqual('PENDING',row['state'])
            self.assertNotIn('execute',repr(self.seen))
            self.assertIn('signingGeneration',self.core._read(body['requestId'])['preview'])
            self.assertEqual('REJECTED',self.decide(body['requestId'],'reject')['state'])
            signer.assert_not_called()
        self.assertEqual(self.core.path.read_bytes().find(TOKEN.encode()),-1)

    def test_approved_execution_only_signs_once_after_core_revalidation(self):
        body=self.body()
        with patch('fortis_approvals.integrations.mirror.signing.sign_dispatch_identity',return_value={'fake':'offline'}) as signer:
            row=self.runtime.call(GRANT,body); self.assertEqual(row['state'],'PENDING')
            signer.assert_not_called()
            self.assertEqual('EXECUTED',self.decide(body['requestId'],'approve')['state'])
            signer.assert_called_once()
            kw=signer.call_args.kwargs
            self.assertEqual(kw['key_id'],KEY)
            self.assertEqual(signer.call_args.args[0]['actor'],'fixture')
            self.assertEqual(signer.call_args.args[0]['requestId'],body['requestId'])
            self.assertEqual(self.seen[-1],('execute','execute','fixture'))
            self.assertEqual('EXECUTED',self.runtime.call(GRANT,body)['state'])
            signer.assert_called_once()

    def test_rotation_preapproval_stales_and_never_signs(self):
        body=self.body();row=self.runtime.call(GRANT,body);self.assertEqual(row['state'],'PENDING')
        self.vault.provision('mirror-sign', base64.urlsafe_b64encode(b'\x06'*32).decode('ascii').rstrip('='),
            expected_generation=self.sign_secret['generation'])
        with patch('fortis_approvals.integrations.mirror.signing.sign_dispatch_identity') as signer:
            self.assertEqual('STALE',self.decide(row['requestId'],'approve')['state'])
            signer.assert_not_called()

    def test_transport_rotation_and_missing_signer_fail_closed(self):
        body=self.body();row=self.runtime.call(GRANT,body);self.assertEqual(row['state'],'PENDING')
        self.vault.provision('mirror-write', 'OFFLINE_ROTATED_WRITE_BEARER',
                             expected_generation=self.write_secret['generation'])
        with patch('fortis_approvals.integrations.mirror.signing.sign_dispatch_identity') as signer:
            self.assertEqual('STALE',self.decide(row['requestId'],'approve')['state'])
            signer.assert_not_called()
        broken={'schemaVersion':1, 'providers': {'mirror': {
            'credentials': {'link':'mirror-read','write_link':'mirror-write'},
            'operations': self.settings['providers']['mirror']['operations']}}}
        with self.assertRaisesRegex(Denied,'INTEGRATION_SIGNING_CREDENTIAL_BINDING_MISSING'):
            ExtensionRuntime(ExtensionConfig(broken),providers=(self.provider,),
                actors=('fixture',),default_actor='fixture',vault=self.vault)

    def test_signer_seed_and_bearer_cannot_leak_through_results(self):
        body=self.body()
        context=Context(self.runtime,self.provider,self.write,{**body,'expectedVersion':0},
                        'preview',authenticated_actor='fixture')
        for secret in ('mirror-sign','mirror-write'):
            with self.subTest(secret=secret),self.assertRaisesRegex(Denied,'INTEGRATION_SECRET_OUTPUT_DENIED'):
                context.safe({'unexpected':{'value':self.vault.get(secret).reveal()}})
        self.assertEqual(context.safe({'public':'safe'}),{'public':'safe'})
        read_ctx=Context(self.runtime,self.provider,self.read,{**body,'operation':'get_read',
            'params':{},'expectedVersion':0},'execute',authenticated_actor='fixture')
        self.assertIsNone(read_ctx.signing_generation)
        with self.assertRaisesRegex(Denied,'MIRROR_SIGNING_PHASE_DENIED'):
            read_ctx.sign_mirror_dispatch(self.parameters,preview_expires_at=int(time.time())+40)

    def test_invalid_definition_policy_and_credential_collisions(self):
        with self.assertRaises(Denied):
            replace(self.read, signing_credential='signer', signing_key_id=KEY)
        with self.assertRaises(Denied):
            replace(self.write, signing_credential='write_link')
        with self.assertRaises(Denied):
            replace(self.write, signing_key_id=None)
        with self.assertRaises(Denied):
            replace(self.write, signing_key_id='invalid key')
        for collide, code in [('link','INTEGRATION_READ_WRITE_ROLE_COLLISION'),
                               ('signer','INTEGRATION_SIGNING_ROLE_COLLISION')]:
            config = {'schemaVersion': 1, 'providers': {'mirror': {'credentials': {
                **self.settings['providers']['mirror']['credentials'],
                'write_link' if collide=='link' else 'signer': 'mirror-read' if collide=='link' else 'mirror-write'},
                'operations':self.settings['providers']['mirror']['operations']}}}
            with self.subTest(collide=collide),self.assertRaisesRegex(Denied,code):
                ExtensionRuntime(ExtensionConfig(config),providers=(self.provider,),
                    actors=('fixture',),default_actor='fixture',vault=self.vault)
        config = {'schemaVersion':1,'providers':{'mirror':{**self.settings['providers']['mirror'],
            'operations': {**self.settings['providers']['mirror']['operations'],
                'execute_windows_pull_v2':{'policy':'ALLOW','targets':['fortis-approvals']}}}}}
        with self.assertRaisesRegex(Denied,'INTEGRATION_SIGNING_REQUIRES_ASK'):
            ExtensionRuntime(ExtensionConfig(config),providers=(self.provider,),
                actors=('fixture',),default_actor='fixture',vault=self.vault)

    def test_preapproval_and_reconcile_cannot_sign(self):
        body=self.body();row=self.runtime.call(GRANT,body)
        for phase in ('preview','reconcile'):
            with self.subTest(phase=phase):
                ctx=Context(self.runtime,self.provider,self.write,{**body,'expectedVersion':0},phase,
                    authenticated_actor='fixture')
                with self.assertRaisesRegex(Denied,'MIRROR_SIGNING_PHASE_DENIED'):
                    ctx.sign_mirror_dispatch(self.parameters,preview_expires_at=int(time.time())+40)
        self.assertEqual('PENDING',row['state'])

    def test_write_transport_requires_one_matching_proof_and_no_second_post(self):
        # Even a valid WRITE bearer cannot reach a provider's POST without
        # exactly the proof returned by the authorized signer. No retry after
        # a possible lost ACK in the same execution context.
        mock_call = Mock(return_value={'fixture': True})
        write = replace(self.write, routes=('dispatch',))
        provider = Provider('mirror', (self.read, write), api=SimpleNamespace(
            routes={'dispatch': Route('dispatch','POST','/gateway/v2/fixture',readonly=False)},
            call=mock_call))
        request={**self.body(),'expectedVersion':0}
        ctx=Context(self.runtime,provider,write,request,'execute',authenticated_actor='fixture')
        body={'requestId':ctx.request_id,'repoId':ctx.target,'actor':'fixture',
              **self.parameters,'proof': {'fixture':'signed-only'}}
        with self.assertRaisesRegex(Denied,'MIRROR_SIGNED_DISPATCH_REQUIRED'):
            ctx.call('dispatch',body=body)
        mock_call.assert_not_called()
        ctx._signed_dispatch={'fixture':'signed-only'}  # simulated post-approval signer output
        with self.assertRaisesRegex(Denied,'MIRROR_SIGNED_DISPATCH_REQUIRED'):
            ctx.call('dispatch',body={**body,'actor':'other'})
        mock_call.assert_not_called()
        self.assertEqual(ctx.call('dispatch',body=body),{'fixture':True})
        self.assertEqual(mock_call.call_count,1)
        with self.assertRaisesRegex(Denied,'MIRROR_SIGNED_DISPATCH_REQUIRED'):
            ctx.call('dispatch',body=body)
        self.assertEqual(mock_call.call_count,1)

    def test_mismatch_in_signed_params_cannot_change_preview(self):
        body=self.body();row=self.runtime.call(GRANT,body)
        ctx=Context(self.runtime,self.provider,self.write,{**body,'expectedVersion':0},'execute',
            authenticated_actor='fixture')
        with self.assertRaisesRegex(Denied,'MIRROR_SIGNING_IDENTITY_INVALID'):
            ctx.sign_mirror_dispatch({**self.parameters,'targetSha':'f'*40},
                                     preview_expires_at=int(time.time())+40)
        with self.assertRaisesRegex(Denied,'MIRROR_SIGNING_APPROVAL_REQUIRED'):
            ctx.sign_mirror_dispatch(self.parameters,preview_expires_at=int(time.time())+40)

    def test_public_ask_body_cannot_supply_actor_approval_or_dispatch_identity(self):
        """Only the authenticated Core scope, never incoming params, owns actor."""
        body = self.body()
        with patch('fortis_approvals.integrations.mirror.signing.sign_dispatch_identity') as signer:
            for extra in ({'actor': 'foreign'}, {'approved': True},
                          {'repoId': 'foreign'}, {'requestId': body['requestId']},
                          {'signingKeyId': KEY}, {'proof': {'fixture': True}}):
                candidate = {**body, 'params': {**self.parameters, **extra}}
                with self.subTest(extra=extra), self.assertRaisesRegex(
                        Denied, 'INTEGRATION_SCHEMA_INVALID'):
                    self.runtime.call(GRANT, candidate)
            signer.assert_not_called()
        with self.assertRaisesRegex(Denied, 'REQUEST_NOT_AVAILABLE'):
            self.core._read(body['requestId'])
        self.assertEqual(self.seen, [])

    def test_authenticated_ask_actor_and_policy_revalidated_before_owner_approval(self):
        """Preflight actor comes from authenticated scope, not the requested SHA."""
        body = self.body()
        row = self.runtime.call(GRANT, body)
        self.assertEqual(row['state'], 'PENDING')
        self.assertEqual(self.seen, [('preview', 'preview', 'fixture')])
        self.assertEqual(self.core._read(body['requestId'])['actor'], 'fixture')
        # A changed trusted Core policy while owner approval is pending must
        # fail BEFORE signing, without changing the original pending receipt.
        self.core.policies[('fixture', 'mirror', 'execute_windows_pull_v2',
                            'fortis-approvals')] = 'DENY'
        with patch('fortis_approvals.integrations.mirror.signing.sign_dispatch_identity') as signer:
            with self.assertRaisesRegex(Denied, 'OWNER_POLICY_CHANGED'):
                self.decide(body['requestId'], 'approve')
            signer.assert_not_called()
        self.assertEqual(self.core._read(body['requestId'])['state'], 'PENDING')

    def _synthetic_dispatched_row(self, request_id):
        """Strictly offline source-fixture: model the already-approved Core row.

        Direct SQLite mutation is NEVER available to a client, Gateway route
        or the real owner-decision protocol. This isolates the signer's second
        approval/actor check and the pre-transport revocation check.
        """
        with self.core._db() as db:
            db.execute('UPDATE requests SET state=?,decision=?,owner=? WHERE id=?',
                       ('DISPATCHED', 'approve', 'offline-owner', request_id))
        row = self.core._read(request_id)
        self.assertEqual((row['state'], row['decision'], row['owner']),
                         ('DISPATCHED', 'approve', 'offline-owner'))

    def test_signer_refuses_forged_actor_even_if_core_row_is_dispatched(self):
        body = self.body()
        self.assertEqual(self.runtime.call(GRANT, body)['state'], 'PENDING')
        self._synthetic_dispatched_row(body['requestId'])
        # A Context reconstructed with a foreign actor (not from the Core)
        # cannot obtain proof even if all params and request UUID match.
        context = Context(self.runtime, self.provider, self.write,
                          {**body, 'expectedVersion': 0}, 'execute',
                          authenticated_actor='foreign')
        with patch('fortis_approvals.integrations.mirror.signing.sign_dispatch_identity') as signer:
            with self.assertRaisesRegex(Denied, 'MIRROR_SIGNING_APPROVAL_REQUIRED'):
                context.sign_mirror_dispatch(
                    self.parameters, preview_expires_at=int(time.time()) + 50)
            signer.assert_not_called()

    def test_signer_or_write_bearer_revoked_after_signing_blocks_http_dispatch(self):
        """A signed proof is not a reusable POST capability after rotation."""
        request = self.body()
        self.assertEqual(self.runtime.call(GRANT, request)['state'], 'PENDING')
        self._synthetic_dispatched_row(request['requestId'])
        write = replace(self.write, routes=('dispatch',))
        mock_http = Mock(return_value={'fixture': True})
        provider = Provider('mirror', (self.read, write), api=SimpleNamespace(
            routes={'dispatch': Route('dispatch', 'POST',
                                     '/gateway/v2/repositories/{repo_id}/pull',
                                     readonly=False)},
            call=mock_http))
        for alias in ('mirror-sign', 'mirror-write'):
            with self.subTest(rotated_alias=alias):
                context = Context(
                    self.runtime, provider, write,
                    {**request, 'expectedVersion': 0}, 'execute',
                    authenticated_actor='fixture')
                with patch('fortis_approvals.integrations.mirror.signing.sign_dispatch_identity',
                           return_value={'fixture': 'offline-signed'}) as signer:
                    proof = context.sign_mirror_dispatch(
                        self.parameters, preview_expires_at=int(time.time()) + 50)
                    signer.assert_called_once()
                body = {'requestId':context.request_id, 'repoId':context.target,
                        'actor':'fixture', **self.parameters, 'proof':proof}
                old = self.vault.get(alias)
                self.vault.provision(alias,
                    ('OFFLINE_REVOKED_SIGNING_SEED' if alias == 'mirror-sign'
                     else 'OFFLINE_ROTATED_WRITE_CREDENTIAL'),
                    expected_generation=old.generation)
                with self.assertRaisesRegex(Denied, 'MIRROR_SIGNING_CREDENTIAL_REVOKED'):
                    context.call('dispatch', body=body)
                mock_http.assert_not_called()
