"""Acquire exact native Git refs and deliver retained merged-PR evidence."""
from contextlib import contextmanager
from pathlib import Path
import tempfile

from ..integrations.github.publisher_source import decode_source_bundle, import_source_bundle
from ..integrations.registry_contracts import merge_evidence as proof, semantic_contract as sc
from ..workflow.common import Git, branch


class SuccessorSourceDelivery:
    def __init__(self, *, backend, repository, state_root, producer_uid, registry_gid):
        self._backend = backend
        self._repository = repository
        self._short_repo = repository.split('/')[1]
        self._state = state_root
        self._root = proof.MOUNT
        self._identity = dict(uid=producer_uid, gid=registry_gid)
        self.check_mount()

    def check_mount(self):
        proof.check_directory(self._root, readonly=False, **self._identity)

    def _fetch(self, ref, expected):
        response = self._backend.fetch_bundle(self._short_repo, ref, expected)
        return decode_source_bundle(response, repository=self._short_repo, ref=ref, expected=expected)

    @staticmethod
    def _add(git, path, *, target, bundle, expected):
        data = path.parent/(target+'.bundle')
        data.write_bytes(bundle)
        import_source_bundle(git,path,data,expected=expected,target=target)

    @contextmanager
    def review(self, observed):
        sc.need(observed['repository'] == self._repository, 'SOURCE_EVIDENCE_SCOPE_DENIED')
        ref = branch(observed['headBranch'])
        with tempfile.TemporaryDirectory(prefix='successor-source-',dir=self._state) as tmp:
            folder = Path(tmp)
            git = Git(folder/'git')
            repository = folder/'source.git'
            git.run(['init','--bare','--template=',repository])
            for name, current, sha in (
                    ('main', 'main', observed['baseSha']), ('pr', ref, observed['headSha'])):
                self._add(git,repository,target=name,bundle=self._fetch(current,sha),expected=sha)
            yield repository

    @contextmanager
    def merged(self, proposal, observation, body, *, publish):
        self.check_mount()
        sc.need(proposal['repository'] == self._repository, 'SOURCE_EVIDENCE_SCOPE_DENIED')
        merge = observation['mergeSha']
        if publish:
            bundle = self._fetch('main', merge)
            header = proof.make_header(proposal, observation, body, bundle)
        else:
            header, bundle = proof.read_evidence(self._root, merge, **self._identity)
            sc.need(header == proof.make_header(proposal, observation, body, bundle),
                    'SOURCE_EVIDENCE_CONTENT_DENIED')
        with tempfile.TemporaryDirectory(prefix='successor-merge-source-',dir=self._state) as tmp:
            folder = Path(tmp)
            git = Git(folder/'git')
            repository = folder/'source.git'
            git.run(['init','--bare','--template=',repository])
            self._add(git,repository,target='main',bundle=bundle,expected=merge)
            yield repository
        if publish:
            self.check_mount()
            proof.publish_evidence(self._root, header, bundle, **self._identity)
