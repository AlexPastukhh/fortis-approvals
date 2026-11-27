"""Exact successor native merge and readback through the existing adapter."""
from contextlib import nullcontext
import hashlib
import os
from pathlib import Path
import tempfile

from ..core import Denied
from ..workflow.common import Git
from ..integrations.github.gateway.adapter import GitHubAdapter
from ..integrations.github.gateway.selected_main_binding import _commit
from ..integrations.github.publisher_source import private_path
from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts import source_lineage_contract as lc
from .composite_executor import StepContext
from .merge_capture import lookup as lookup_capture, validate


class NativeMergeReceiptReader:
    def __init__(self,adapter,*,source_repository,state_root,read_guard,evidence=None):
        from ..workflow.adapters import NativeGitHubAdapter
        sc.need(type(adapter) in (GitHubAdapter,NativeGitHubAdapter) and callable(read_guard))
        self.adapter,self.read_guard=adapter,read_guard
        self.evidence=evidence
        self.source=private_path(source_repository);self.state=private_path(state_root)
        sc.need(self.state.is_dir() and self.state.stat().st_uid==os.geteuid()
                and self.state.stat().st_mode & 0o777==0o700,'SUCCESSOR_MERGE_STATE_ROOT_INVALID')


    def lookup(self,ctx,retained,*,publish=False):
        sc.need(type(ctx) is StepContext and ctx.ordinal==0 and
                ctx.operation=='merge_pull_request' and bool(ctx.owner),
                'SUCCESSOR_MERGE_CONTEXT_REQUIRED')
        p=lc.proposal(ctx.params['proposal'])
        expansion=lc.merge_expansion(ctx.parent_id,p)
        sc.need(ctx.step_id==expansion['steps'][0]['stepId'] and
                ctx.definition_digest==expansion['definitionDigest'] and
                retained['stepId']==ctx.step_id,'SUCCESSOR_MERGE_CONTEXT_CHANGED')
        material=validate(retained['material'],p)
        sc.need(sc.digest(material)==retained['materialDigest'],'SUCCESSOR_MERGE_CAPTURE_CHANGED')
        owner,repo=p['repository'].split('/')
        sc.need(owner==self.adapter.owner and (self.adapter.repositories is None
                or repo in self.adapter.repositories))
        identity={'repository':p['repository'],'number':p['number'],'parentId':ctx.parent_id,
                  'stepId':ctx.step_id,'headSha':p['headSha'],'baseSha':p['baseSha']}
        def guard(kind):
            sc.need(self.read_guard(ctx,kind,identity) is True,'SUCCESSOR_MERGE_READ_DENIED')
        guard('original_receipt')
        original=self.adapter.receipt(ctx.step_id)
        guard('original_receipt')
        if original is None:return None
        sc.fields(original,('requestId','operation','repository','number','merged','sha'))
        sc.need(original['requestId']==ctx.step_id and original['operation']=='merge_pull_request'
                and original['repository']==repo and type(original['number']) is int
                and original['number']==p['number'] and original['merged'] is True,
                'SUCCESSOR_UPSTREAM_RECEIPT_CHANGED')
        merged=original['sha'];sc.hex_id(merged,40)
        def get(kind,suffix):
            guard(kind)
            result=self.adapter._api('GET',self.adapter._path(repo,suffix))
            guard(kind)
            return result
        def remote():
            raw=get('merged_pr','pulls/'+str(p['number']))
            row=self.adapter._project_pull(raw)
            sc.need(row['number']==p['number'] and row['state']=='closed' and row['merged'] is True
                    and row['head']['sha']==p['headSha'] and row['base']['ref']=='main'
                    and raw.get('merge_commit_sha')==merged and
                    raw['head'].get('repo',{}).get('full_name')==p['repository'] and
                    raw['base'].get('repo',{}).get('full_name')==p['repository'] and
                    raw.get('body')==material['body'],'SUCCESSOR_MERGED_PR_CHANGED')
            main=self.adapter._project_branch(get('main','branches/main'))
            sc.need(main['name']=='main' and main['sha']==merged,'SUCCESSOR_MERGED_MAIN_CHANGED')
            commit=get('merge_commit','git/commits/'+merged)
            sc.need(commit.get('sha')==merged and commit.get('tree',{}).get('sha')==p['treeSha']
                    and [r.get('sha') for r in commit.get('parents',[])]==[p['baseSha'],p['headSha']],
                    'SUCCESSOR_MERGE_PARENTS_CHANGED')
            return {'repository':p['repository'],'number':p['number'],'headSha':p['headSha'],
                    'mergeSha':merged,'mainSha':main['sha'],'parents':[p['baseSha'],p['headSha']],
                    **{k:p[k] for k in ('treeSha','catalogSha256','bodyDigest','impactDigest','pathsDigest','ciDigest')}}
        observed=remote()
        selected = (self.evidence.merged(p, observed, material['body'], publish=publish)
                    if self.evidence is not None else nullcontext(self.source))
        with selected as source:
            with tempfile.TemporaryDirectory(dir=self.state,prefix='successor-merge-') as tmp:
                git=Git(Path(tmp)/'git',protocols='file')
                merge=_commit(git,source,merged)
                head=_commit(git,source,p['headSha'])
                _commit(git,source,p['baseSha'])
                sc.need(merge['parents']==observed['parents'] and
                        merge['treeSha']==head['treeSha']==p['treeSha'],
                        'SUCCESSOR_MERGE_GIT_OBJECT_CHANGED')
                raw=git.run(['--no-replace-objects','cat-file','blob',merged+':release/targets.yaml'],
                            cwd=source)[1]
                sc.need(raw==material['catalog'].encode() and hashlib.sha256(raw).hexdigest()==p['catalogSha256'],
                        'SUCCESSOR_MERGE_CATALOG_CHANGED')
            sc.need(remote()==observed,'SUCCESSOR_MERGE_OBSERVATION_CHANGED')
            guard('original_receipt')
            sc.need(self.adapter.receipt(ctx.step_id)==original,'SUCCESSOR_UPSTREAM_RECEIPT_CHANGED')
            guard('original_receipt')
        return {'operationId':ctx.step_id,'parentRequestId':ctx.parent_id,
                'proposalDigest':sc.digest(p),'captureDigest':retained['materialDigest'],
                'observation':lc.observation(observed,p)}



class NativeMergeProvider:
    """Source-installed child of the existing queue, with no public merge route."""
    def __init__(self, discovery, reader):
        from .native_merge_discovery import NativeMergeDiscovery
        from ..workflow.adapters import NativeGitHubAdapter
        sc.need(type(discovery) is NativeMergeDiscovery and type(reader) is NativeMergeReceiptReader
                and type(reader.adapter) is NativeGitHubAdapter
                and discovery.adapter is reader.adapter,'SUCCESSOR_NATIVE_COMPOSITION_REQUIRED')
        self.discovery,self.reader=discovery,reader
        self.binding=None

    def preview(self,actor,proposal):
        return self.discovery.review(actor,proposal)[0]

    def verify_capture(self,ctx,material):
        # The invocation's pre-observation ran independent Git, impact and exact CI.
        # The signed proposal binds each retained byte projection.
        return validate(material,ctx.params['proposal'])==material

    def _retained(self,ctx):
        binding=self.binding
        native=self.reader.adapter
        sc.need(binding is not None and binding.provider is self
                and binding.adapter.core is native.observation_core
                and binding.adapter.core.adapters.get('github') is native,
                'SUCCESSOR_NATIVE_COMPOSITION_REQUIRED')
        with binding.adapter.core._db() as db:
            db.execute('BEGIN')
            return lookup_capture(db,ctx.parent_id)

    def merge(self,ctx,capture_digest):
        from .maintenance_gate import Coordinate
        p=lc.proposal(ctx.params['proposal'])
        retained=self._retained(ctx)
        sc.need(ctx.ordinal==0 and retained is not None
                and retained['stepId']==ctx.step_id and retained['materialDigest']==capture_digest,
                'SUCCESSOR_MERGE_CAPTURE_CHANGED')
        binding=self.binding
        binding._check(ctx)
        request={'requestId':ctx.step_id,'service':'github','operation':'merge_pull_request',
                 'target':p['repository'].split('/')[1],
                 'params':{'number':p['number'],'expectedHeadSha':p['headSha'],'mergeMethod':'merge'}}
        native=self.reader.adapter
        native._access(request['target'])
        # Standalone native prepare binds the submitting Repo actor's task.
        # Here separately enrolled discovery binds the exact branch/PR and CI.
        approved={'operation':'merge_pull_request','repository':request['target'],
                  'number':p['number'],'headSha':p['headSha'],'baseSha':p['baseSha'],
                  'mergeMethod':'merge'}
        with binding.gate.reserve(Coordinate('github','merge_pull_request')) as token:
            def before_write():
                # Native adapter calls this after its own final preflight
                # and immediately before the upstream HEAD-CAS request.
                binding._check(ctx)
                sc.need(binding.effect_guard(ctx) is True,'MERGE_REGISTER_EFFECT_DENIED')
                sc.need(binding.registry.source_preflight(p)==binding.source_expected(p),
                        'MERGE_REGISTER_SOURCE_PREVIEW_CHANGED')
                self.discovery.review(ctx.actor,p,retained=retained['material'])
                binding._check(ctx)
                sc.need(binding.effect_guard(ctx) is True,'MERGE_REGISTER_EFFECT_DENIED')
                binding.gate.check_effect(token)

            with binding.gate.effect(token):
                GitHubAdapter.apply(native,request,approved_preview=approved,
                                    before_reviewed_merge=before_write)
            return self.reader.lookup(ctx,retained,publish=True)

    def lookup(self,ctx):
        retained=self._retained(ctx)
        return None if retained is None else self.reader.lookup(ctx,retained)

    def verify(self,ctx,receipt):
        return self.lookup(ctx)==receipt
