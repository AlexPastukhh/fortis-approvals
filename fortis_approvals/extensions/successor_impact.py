"""Successor impact verifier, exact reviewed validator and independent Git data.

No fetch, checkout, PR code execution, merge, or policy admission. The
server-composed object stores and validator commit must already be reviewed.
"""
from copy import copy
import hashlib
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from ..core import Denied
from ..workflow.common import Git
from ..integrations.github.publisher_source import private_path, materialize
from ..integrations.github.gateway.retained_impact import _records, _SHIM
from ..integrations.github.post_merge_proof_bindings import _impact_yaml, EvidenceEnvelopeError
from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts import source_lineage_contract as lc
from ..integrations.registry_contracts.release_profile import from_resolved_catalog, resolve_components

# Reuse bounded graph and versioned validation. Return the exact catalog
# so the approved component and maintenance bindings can be verified.
assert _SHIM.count('dependencyGraph=graph)))')==1
_SUCCESSOR_SHIM=_SHIM.replace('dependencyGraph=graph)))',
    'dependencyGraph=graph,catalog=catalog)))')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class SuccessorImpact:
    def __init__(self, *, validator_repository, validator_revision, source_repository,
                 state_root, repository, binding, build_pins, profile_digest):
        self.code=private_path(validator_repository)
        self.source=private_path(source_repository)
        self.state=private_path(state_root)
        sc.hex_id(validator_revision,40);sc.hex_id(profile_digest,64)
        sc.repository(repository)
        sc.need(self.state.is_dir() and self.state.stat().st_uid==os.geteuid()
                and self.state.stat().st_mode & 0o777==0o700,'SUCCESSOR_IMPACT_CONFIG')
        self.revision,self.repository,self.profile_digest=validator_revision,repository,profile_digest
        self.binding=sc.canonical(binding)
        self.build_pins=sc.canonical(build_pins)

    def with_source(self, repository):
        selected = copy(self)
        selected.source = private_path(repository)
        return selected

    def verify_workflows(self,head,workflows):
        """Independent raw Git workflow bytes, not only REST content."""
        sc.hex_id(head,40)
        with tempfile.TemporaryDirectory(dir=self.state,prefix='successor-ci-git-') as tmp:
            git=Git(Path(tmp)/'git',protocols='file')
            for workflow in workflows:
                raw=git.run(['--no-replace-objects','cat-file','blob',head+':'+workflow.path],
                            cwd=self.source)[1]
                sc.need(0<len(raw)<=65536 and _sha(raw)==workflow.sha256,
                        'SUCCESSOR_CI_GIT_WORKFLOW_CHANGED')

    def verify_registered_merge(self, request, *, read_merged_body):
        """Re-derive the accepted impact from independent pinned Git and PR bytes."""
        sc.need(request['kind'] in ('MERGE','EXTERNAL_MERGE'),'SUCCESSOR_MERGE_SOURCE_REQUIRED')
        p=lc.proposal(request['proposal'])
        observed=lc.observation(request['observation'],p)
        self.merged_impact(p,observed['mergeSha'],read_merged_body(p,observed))
        return True

    def merged_impact(self,p,merge_sha,body):
        sc.hex_id(merge_sha,40)
        with tempfile.TemporaryDirectory(dir=self.state,prefix='registry-merge-') as tmp:
            git=Git(Path(tmp)/'git',protocols='file')
            parents=git.text(['--no-replace-objects','rev-list','--parents','-n','1',merge_sha],
                             cwd=self.source).split()
            sc.need(parents==[merge_sha,p['baseSha'],p['headSha']],
                    'SUCCESSOR_MERGE_GIT_OBJECT_CHANGED')
            sc.need(git.text(['--no-replace-objects','rev-parse',merge_sha+'^{tree}'],
                             cwd=self.source)==p['treeSha'],'SUCCESSOR_MERGE_GIT_OBJECT_CHANGED')
            raw=git.run(['--no-replace-objects','cat-file','blob',merge_sha+':release/targets.yaml'],
                        cwd=self.source)[1]
            paths=_records(git,self.source,p['baseSha'],p['headSha'],p['baseSha'])
        impact=self.verify({**p,'body':body,'catalog':raw.decode('utf-8'),
            'catalogBlobSha':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
            'paths':paths})
        sc.need(all(impact[field]==p[field] for field in
                    ('profileDigest','classification','targets','dependencies')),
                'SUCCESSOR_REGISTRY_IMPACT_CHANGED')
        return impact

    def verify(self, observed):
        sc.need(observed['repository']==self.repository)
        base,head=observed['baseSha'],observed['headSha']
        for v in (base,head,observed['treeSha']):sc.hex_id(v,40)
        body=observed['body'];catalog=observed['catalog'];paths=observed['paths']
        sc.need(type(body) is str and 0<len(body.encode())<=20000 and
                type(catalog) is str and 0<len(catalog.encode())<=120000 and
                type(paths) is list and 0<len(paths)<=299)
        try:
            impact=_impact_yaml(body)
        except EvidenceEnvelopeError:
            raise Denied('SUCCESSOR_IMPACT_BODY_INVALID') from None
        sc.need(_sha(body.encode())==observed['bodyDigest'] and
                _sha(impact.encode())==observed['impactDigest'] and
                _sha(catalog.encode())==observed['catalogSha256'] and
                sc.digest(paths)==observed['pathsDigest'],'SUCCESSOR_IMPACT_BYTES_CHANGED')
        with tempfile.TemporaryDirectory(dir=self.state,prefix='successor-impact-') as tmp:
            work=Path(tmp);git=Git(work/'git',protocols='file')
            for repo,rev in ((self.code,self.revision),(self.source,base),(self.source,head)):
                sc.need(git.text(['--no-replace-objects','rev-parse','--verify',rev+'^{commit}'],
                                 cwd=repo)==rev,'SUCCESSOR_IMPACT_COMMIT_CHANGED')
            sc.need(git.text(['--no-replace-objects','rev-parse',head+'^{tree}'],cwd=self.source)
                    ==observed['treeSha'],'SUCCESSOR_IMPACT_TREE_CHANGED')
            sc.need(_records(git,self.source,base,head,base)==paths,'SUCCESSOR_IMPACT_PATHS_CHANGED')
            code,data=work/'code',work/'data'
            materialize(git,self.code,self.revision,code)
            materialize(git,self.source,head,data)
            raw=(data/'release/targets.yaml').read_bytes()
            sc.need(raw==catalog.encode() and hashlib.sha1(b'blob '+str(len(raw)).encode()+
                    b'\0'+raw).hexdigest()==observed['catalogBlobSha'],'SUCCESSOR_IMPACT_CATALOG_CHANGED')
            inputs={'repository':self.repository.split('/')[1],'number':observed['number'],
                    'body':body,'catalog':catalog,'paths':sorted({x for r in paths for x in
                    (r['path'],r['previousPath']) if x is not None})}
            encoded=sc.canonical(inputs).encode()
            sc.need(len(encoded)<=240000)
            env=dict(PATH=os.defpath,HOME=str(git.home),LANG='C.UTF-8',LC_ALL='C.UTF-8')
            with tempfile.TemporaryFile(dir=work) as out,tempfile.TemporaryFile(dir=work) as err:
                p=subprocess.Popen([sys.executable,'-I','-B','-X','pycache_prefix='+str(work/'cache'),
                    '-c',_SUCCESSOR_SHIM,str(code),str(data)],cwd=work,env=env,
                    stdin=subprocess.PIPE,stdout=out,stderr=err,start_new_session=True)
                try:p.communicate(encoded,timeout=40)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid,signal.SIGKILL);p.wait()
                    raise Denied('SUCCESSOR_IMPACT_TIMEOUT') from None
                sc.need(p.returncode==0 and 0<out.tell()<=262144,'SUCCESSOR_IMPACT_VALIDATION_FAILED')
                out.seek(0);result=sc.loads_strict(out.read())
        checked_catalog=result.pop('catalog')
        profile=from_resolved_catalog(checked_catalog,resolve_components(sc.loads_strict(self.binding),checked_catalog),
            repository=self.repository,catalog_sha256=observed['catalogSha256'],
            build_pins=sc.loads_strict(self.build_pins))
        sc.need(sc.digest(profile)==self.profile_digest,'SUCCESSOR_IMPACT_PROFILE_CHANGED')
        graph=result['dependencyGraph']
        # V1 has no pinned external/PR compatibility evidence resolver.
        # Do not silently drop such requirements.
        sc.need(not graph['unresolvedExternalTargets'] and not graph['unresolvedPullRequests'],
                'SUCCESSOR_IMPACT_DEPENDENCY_UNVERIFIED')
        rows={r['subject']['targetId']:r for r in profile['subjects']}
        targets=[]
        for t in result['declaredTargets']:
            row=rows[t['id']]
            sc.need(row['deployable'] and set(t['actions'])<=lc.ACTIONS)
            targets.append({'subject':row['subject'],'actions':sorted(t['actions'])})
        deps=[{'repository':self.repository,'targetId':n} for n in graph['localDependencyTargets']]
        return {'validatorRevision':self.revision,'profileDigest':self.profile_digest,
                'classification':result['classification'],'targets':sorted(targets,key=lambda r:sc.subject_key(r['subject'])),
                'dependencies':sorted(deps,key=sc.canonical),'validatedImpact':result}
