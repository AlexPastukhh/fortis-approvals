"""Owner-configured verification of ordinary merge accounting in Registry."""
import os
from pathlib import Path
import stat
import tempfile

from ..extensions.maintenance_interlock_reader import InterlockReservations, read_owner_interlock
from ..extensions.successor_impact import SuccessorImpact
from ..integrations.github.publisher_source import import_source_bundle
from ..integrations.registry_contracts import merge_evidence as proof, semantic_contract as sc
from ..r7_registry_reader_mount import _check_owner_readonly_mount
from ..workflow.common import Git

SOURCE_MOUNT = Path('/run/fortis-registry-source')


class ProtectedSourceWrite:
    def __init__(self, value, *, journal, generation, internal, profile_digest, producer_uid):
        sc.fields(value, ('ownerActor', 'ownerName', 'target', 'policyAuthorityDigest', 'interlockDigest',
                          'validatorRevision', 'impactBinding', 'buildPins'))
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
                          generation=generation, expected_digest=value['interlockDigest'])
        self._config = sc.loads_strict(sc.canonical(value))
        self._internal = internal
        self._profile_digest = profile_digest
        self.reservations = InterlockReservations()
        self._check_source()
        # A staged reader can open a verified frozen state. New source
        # effects and the read-only preflight are restricted to NORMAL.
        read_owner_interlock(**self._pins)

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
                'interlockDigest':self._config['interlockDigest']}

    def authorize(self, actor, action, body):
        config = self._config
        if action == 'SOURCE_PREFLIGHT':
            return (actor == self._internal
                    and read_owner_interlock(**self._pins)['phase'] == 'NORMAL')
        if action not in ('SOURCE_REGISTER', 'SOURCE_LOOKUP') or actor != config['ownerActor']:
            return False
        ctx = body['context']
        proposal = body['request']['proposal'] if action == 'SOURCE_REGISTER' else body['proposal']
        return (ctx['owner'] == config['ownerName'] and ctx['target'] == config['target']
                and ctx['policyAuthorityDigest'] == config['policyAuthorityDigest']
                and proposal['repository'] == self._repository
                and proposal['profileDigest'] == self._profile_digest
                and (action == 'SOURCE_LOOKUP'
                     or read_owner_interlock(**self._pins)['phase'] == 'NORMAL'))

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
