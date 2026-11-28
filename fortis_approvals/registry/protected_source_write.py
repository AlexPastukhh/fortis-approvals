"""Owner-configured verification of ordinary merge accounting in Registry."""
import os
from pathlib import Path
import stat
import tempfile

from ..extensions.maintenance_interlock_reader import InterlockReservations, read_owner_interlock, read_latest_interlock
from ..extensions.successor_impact import SuccessorImpact
from ..integrations.github.publisher_source import import_source_bundle
from ..integrations.registry_contracts import merge_evidence as proof, semantic_contract as sc
from ..r7_registry_reader_mount import _check_owner_readonly_mount
from ..workflow.common import Git

SOURCE_MOUNT = Path('/run/fortis-registry-source')


class ProtectedSourceWrite:
    def __init__(self, value, *, journal, generation, internal, profile_digest, producer_uid):
        fields=('ownerActor','ownerName','target','policyAuthorityDigest','interlockDigest',
                'validatorRevision','impactBinding','buildPins')
        dynamic='latestPin' in value
        sc.fields(value,fields+('latestPin',) if dynamic else fields)
        sc.need(not dynamic or value['latestPin'] is True,'REGISTRY_SOURCE_WRITER_SCOPE')
        for field in ('ownerActor', 'ownerName', 'target'):
            sc.name(value[field])
        sc.need(value['ownerActor'] != internal and type(value['impactBinding']) is dict
                and type(value['buildPins']) is dict, 'REGISTRY_SOURCE_WRITER_SCOPE')
        for field in ('policyAuthorityDigest', 'interlockDigest'):
            sc.hex_id(value[field], 64)
        sc.hex_id(value['validatorRevision'], 40)
        self._root = SOURCE_MOUNT
        self._identity = dict(uid=producer_uid, gid=os.getegid())
        self._repository = journal.scope['repository']
        self._pins = dict(instance_id=journal.instance_id,
                          scope_digest=journal.expected_legacy['scopeDigest'],
                          generation=generation)
        self._dynamic=dynamic
        self._config = sc.loads_strict(sc.canonical(value))
        self._internal = internal
        self._profile_digest = profile_digest
        self.reservations = InterlockReservations()
        self._check_source()
        # A staged reader can open a verified frozen state. New source
        # effects and the read-only preflight are restricted to NORMAL.
        self._phase()

    def _phase(self):
        if self._dynamic:
            return read_latest_interlock(**self._pins)[0]
        return read_owner_interlock(**self._pins,expected_digest=self._config['interlockDigest'])

    def _checked_controller_begin(self,expected_digest=None):
        from ..extensions.maintenance_interlock_reader import read_controller_begin
        from ..integrations.registry_contracts.maintenance_contract import ordinary_pair_intent
        sc.need(self._dynamic and self._root==SOURCE_MOUNT,'MAINTENANCE_CONTROLLER_BEGIN_DENIED')
        projection=read_controller_begin(expected_digest=expected_digest)
        intent=projection['intent']
        pair=ordinary_pair_intent(intent)
        binding=intent['compatibility']['registry']['binding']
        sc.need(binding['generation']==self._pins['generation']
                and binding['profileDigest']==self._profile_digest
                and binding['authorityDigest']==self._config['policyAuthorityDigest']
                and binding['instanceId']==self._pins['instance_id']
                and binding['scopeDigest']==self._pins['scope_digest']
                and binding['internalActor']==self._internal,
                'MAINTENANCE_CONTROLLER_BEGIN_CHANGED')
        return intent,pair,projection['revoked']

    def _begin_result(self,intent,pair,result):
        from ..integrations.registry_contracts.maintenance_contract import paired_draining_record
        auth=intent['authorization']
        draining=paired_draining_record(intent['normal'],pair,result['receipts'],result['holdSnapshot'],
                       target_generation=auth['targetGeneration'],recorded_at=auth['recordedAt'])
        return {'result':'PROTECTED_PAIR_BEGIN_READBACK_ONLY','intentDigest':sc.digest(intent),
                'pair':pair,**result,'draining':draining,
                'registryDigest':sc.digest(result['holdSnapshot'])}

    def verify_startup(self,domain,current):
        if self._dynamic:
            from ..integrations.registry_contracts.maintenance_contract import latest_startup
            record,projection=read_latest_interlock(**self._pins)
            holds=domain._maintenance_snapshot(current)
            if record['phase']=='DRAINING' or (record['phase']=='NORMAL' and
                    any(h['stateFreeze'] for h in holds['holds'])):
                # The sole Registry writer may recover the private readback
                # channel after a committed begin and lost DRAINING publication.
                # Never relax Gateway startup, or accept an arbitrary hold.
                with self.reservations.exclusive() as exclusive:
                    sc.need(exclusive,'MAINTENANCE_CONTROLLER_BEGIN_BUSY')
                    intent,pair,revoked=self._checked_controller_begin()
                    result=domain.protected_pair_begin_readback(pair,actor='owner-release-controller')
                    sc.need(result['receipts'] is not None and result['holdSnapshot']==holds,
                            'MAINTENANCE_CONTROLLER_BEGIN_CHANGED')
                    begin=self._begin_result(intent,pair,result)
                    sc.need((record==intent['normal'] and projection['registryDigest'] is None)
                            or (record==begin['draining'] and projection['registryDigest']==begin['registryDigest']),
                            'MAINTENANCE_CONTROLLER_BEGIN_CHANGED')
                    sc.need(read_latest_interlock(**self._pins)==(record,projection)
                            and self._checked_controller_begin()==(intent,pair,revoked),
                            'MAINTENANCE_CONTROLLER_BEGIN_CHANGED')
            else:
                latest_startup(record,projection,holds)

    def controller_begin(self,domain,body):
        """Fixed internal trigger; the owner mount, not the peer key, authorizes.

        A live Registry remains the only writer. Exclusive cross-process
        reservation prevents a new Core effect or source write during begin.
        Readback is a distinct operation and never calls the writer.
        """
        import time
        sc.need(self._dynamic and self._root==SOURCE_MOUNT,'MAINTENANCE_CONTROLLER_BEGIN_DENIED')
        sc.fields(body,('intentDigest','readback'))
        sc.need(type(body['readback']) is bool)
        actor='owner-release-controller'
        with self.reservations.exclusive() as exclusive:
            sc.need(exclusive,'MAINTENANCE_CONTROLLER_BEGIN_BUSY')
            def checked():
                intent,pair,revoked=self._checked_controller_begin(body['intentDigest'])
                sc.need(self._phase()==intent['normal'],'MAINTENANCE_CONTROLLER_BEGIN_CHANGED')
                return intent,pair,revoked
            intent,pair,revoked=checked()
            auth=intent['authorization']
            result=domain.protected_pair_begin_readback(pair,actor=actor)
            if result['receipts'] is None:
                exact=(result['checkpoint']==pair['checkpoint']
                       and result['holdSnapshot']==intent['compatibility']['registry']['holdSnapshot'])
                now=int(time.time())
                fresh=auth['recordedAt']<=now<=auth['recordedAt']+300
                if body['readback']:
                    return {'result':'PROTECTED_PAIR_BEGIN_NOT_APPLIED','intentDigest':body['intentDigest'],
                            'exactPredecessor':exact,'revoked':revoked,'expired':now>auth['recordedAt']+300,**result}
                sc.need(not revoked and exact and fresh,
                        'MAINTENANCE_CONTROLLER_BEGIN_STALE')
                previous=domain._protected_verify
                try:
                    def verify(req):
                        return (checked()==(intent,pair,revoked) and req['kind']=='PROTECTED_PAIRED_BEGIN'
                                and req['actor']==actor and req['pair']==pair)
                    domain._protected_verify=verify
                    written=domain.protected_begin_pair(pair,actor=actor,recorded_at=auth['recordedAt'])
                finally:
                    domain._protected_verify=previous
                result=domain.protected_pair_begin_readback(pair,actor=actor)
                sc.need(type(written) is list and written==result['receipts'],
                        'MAINTENANCE_CONTROLLER_BEGIN_OUTCOME_UNKNOWN')
            sc.need(checked()==(intent,pair,revoked),'MAINTENANCE_CONTROLLER_BEGIN_CHANGED')
            return self._begin_result(intent,pair,result)

    def _check_source(self):
        sc.need(self._root.resolve() == self._root, 'REGISTRY_SOURCE_EVIDENCE_MOUNT')
        _check_owner_readonly_mount(self._root)
        directory = self._root/'validator.git'
        sc.need(directory.is_dir() and directory.resolve() == directory
                and stat.S_ISDIR(directory.lstat().st_mode), 'REGISTRY_SOURCE_EVIDENCE_MOUNT')
        proof.check_directory(proof.MOUNT, readonly=True, **self._identity)

    def delivery_binding(self):
        return {**proof.mount_binding(proof.MOUNT, readonly=True, **self._identity),
                'policyAuthorityDigest':self._config['policyAuthorityDigest'],
                'interlockDigest':sc.digest(self._phase()) if self._dynamic else self._config['interlockDigest']}

    def authorize(self, actor, action, body):
        config = self._config
        if action == 'SOURCE_PREFLIGHT':
            return (actor == self._internal
                    and self._phase()['phase'] == 'NORMAL')
        if action not in ('SOURCE_REGISTER', 'SOURCE_LOOKUP') or actor != config['ownerActor']:
            return False
        ctx = body['context']
        proposal = body['request']['proposal'] if action == 'SOURCE_REGISTER' else body['proposal']
        return (ctx['owner'] == config['ownerName'] and ctx['target'] == config['target']
                and ctx['policyAuthorityDigest'] == config['policyAuthorityDigest']
                and proposal['repository'] == self._repository
                and proposal['profileDigest'] == self._profile_digest
                and (action == 'SOURCE_LOOKUP'
                     or self._phase()['phase'] == 'NORMAL'))

    def verify(self, request):
        config = self._config
        sc.need(request['kind'] == 'MERGE', 'REGISTRY_SOURCE_WRITER_SCOPE')

        self._check_source()
        proposal, observed = request['proposal'], request['observation']
        merge = observed['mergeSha']
        header, bundle = proof.read_evidence(proof.MOUNT, merge, **self._identity)
        body = header['body']
        sc.need(header == proof.make_header(proposal, observed, body, bundle),
                'REGISTRY_SOURCE_EVIDENCE_CHANGED')
        with tempfile.TemporaryDirectory(prefix='registry-source-proof-') as tmp:
            scratch = Path(tmp)
            git = Git(scratch/'git')
            repository = scratch/'source.git'
            git.run(['init','--bare','--template=',repository])
            source = scratch/'main.bundle'
            source.write_bytes(bundle)
            import_source_bundle(git,repository,source,expected=merge,target='main')
            verifier = SuccessorImpact(
                validator_repository=self._root/'validator.git',
                validator_revision=config['validatorRevision'],
                source_repository=repository, state_root=scratch,
                repository=self._repository, binding=config['impactBinding'],
                build_pins=config['buildPins'], profile_digest=self._profile_digest)
            return verifier.verify_registered_merge(request, read_merged_body=lambda *_:body)
