"""Read-only native GitHub observation for successor discovery.

No merge executor, credential provisioning or legacy policy changes.
The independently reviewed successor validator and CI binding are required
inputs to proposal construction; REST observation alone is not evidence GO.
"""
import base64
import hashlib
import uuid

from ..core import Denied, Stale
from ..integrations.github.contract import validate_github_read_projection
from ..integrations.github.gateway.adapter import GitHubAdapter
from ..integrations.github.post_merge_proof_bindings import _impact_yaml, _paths, EvidenceEnvelopeError
from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts import source_lineage_contract as lc


# Only known per-PR eligibility failures may be displayed as a blocked
# row. Scope failure, malformed inventory, uncertain transport, rules/
# authority drift and unknown exceptions still invalidate the whole scan.
BLOCKED_REASONS={
    'SOURCE_DISCOVERY_BASE_CHANGED':'BASE_CHANGED',
    'SOURCE_DISCOVERY_COMPARE_INCOMPLETE':'DIFF_UNVERIFIED',
    'SOURCE_DISCOVERY_IMPACT_INVALID':'IMPACT_INVALID',
    'SUCCESSOR_IMPACT_VALIDATION_FAILED':'IMPACT_INVALID',
    'SUCCESSOR_IMPACT_DEPENDENCY_UNVERIFIED':'DEPENDENCY_UNVERIFIED',
    'GITHUB_RELEASE_CI_MISSING':'CI_NOT_READY',
    'GITHUB_RELEASE_CI_NOT_SUCCESSFUL':'CI_NOT_READY',
    'GITHUB_RELEASE_CI_JOBS_NOT_SUCCESSFUL':'CI_NOT_READY',
}
BLOCKED_CODES=frozenset(BLOCKED_REASONS.values())|{'DRAFT','BASE_NOT_MAIN'}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class NativeMergeDiscovery:
    def __init__(self,adapter,*,repository,read_guard,branch_guard,project):
        from ..workflow.adapters import NativeGitHubAdapter
        sc.need(type(adapter) in (GitHubAdapter,NativeGitHubAdapter) and all(callable(f) for f in
                (read_guard,branch_guard,project)))
        sc.repository(repository)
        owner,repo=repository.split('/')
        sc.need(owner==adapter.owner and (adapter.repositories is None or repo in adapter.repositories),
                'SOURCE_REPOSITORY_NOT_ALLOWLISTED')
        self.adapter,self.repository,self.repo=adapter,repository,repo
        self.read_guard,self.branch_guard,self.project=read_guard,branch_guard,project

    def _guard(self,actor,operation,params):
        sc.need(self.read_guard(actor,self.repository,operation,params) is True,
                'SOURCE_DISCOVERY_READ_DENIED')

    def _list(self,actor):
        result=[]
        for page in (1,2):
            params={'page':page,'perPage':20,'state':'open'}
            self._guard(actor,'list_pull_requests',params)
            query={'requestId':str(uuid.uuid4()),'service':'github','operation':'list_pull_requests',
                   'target':self.repo,'params':params,'reason':'Successor owner discovery'}
            response=self.adapter.read(query)
            validate_github_read_projection('list_pull_requests',response)
            self._guard(actor,'list_pull_requests',params)
            sc.need(response['page']==page and response['perPage']==20
                    and len(response['items'])<=20,'SOURCE_DISCOVERY_INCOMPLETE')
            result.extend(response['items'])
            sc.need(len(result)<=20,'SOURCE_DISCOVERY_INCOMPLETE')
            if len(response['items'])<20:break
        sc.need(len({r['number'] for r in result})==len(result)
                and all(r['state']=='open' and not r['merged'] for r in result),
                'SOURCE_DISCOVERY_INVENTORY_CHANGED')
        return sorted(result,key=lambda r:r['number'])

    def _get(self,actor,kind,identity,suffix,params=None):
        # The exact internal evidence-read operation has its own reviewed
        # scope; list permission is not a grant for raw evidence endpoints.
        guard={'kind':kind,**identity}
        self._guard(actor,'successor_pr_evidence',guard)
        value=self.adapter._api('GET',self.adapter._path(self.repo,suffix),params=params)
        self._guard(actor,'successor_pr_evidence',guard)
        return value

    def observe(self,actor,row,*,retain=False,reviewed=None):
        number=row['number'];head=row['head']['sha'];base=row['base']['sha']
        sc.need(type(number) is int and 0<number<=1000000)
        sc.hex_id(head,40);sc.hex_id(base,40)
        sc.need(head!=base and row['base']['ref']=='main' and row['state']=='open'
                and not row['draft'] and not row['merged'])
        identity={'number':number,'headSha':head,'baseSha':base}
        def get(kind,suffix,params=None):
            return self._get(actor,kind,identity,suffix,params)
        def pr():
            raw=get('pr','pulls/'+str(number))
            sc.need(self.adapter._project_pull(raw)==row and raw.get('merged') is False
                    and raw.get('merged_at') is None and raw.get('draft') is False,
                    'SOURCE_DISCOVERY_PR_CHANGED')
            for ref in ('head','base'):
                sc.need(raw[ref].get('repo',{}).get('full_name')==self.repository,
                        'SOURCE_DISCOVERY_CROSS_REPO_DENIED')
            sc.need(self.branch_guard(actor,self.repository,raw['head']['ref']) is True,
                    'SOURCE_DISCOVERY_BRANCH_DENIED')
            body=raw.get('body')
            sc.need(type(body) is str and 0<len(body.encode('utf-8'))<=20000)
            count=raw.get('changed_files')
            sc.need(type(count) is int and 0<count<=299,'SOURCE_DISCOVERY_FILES_INCOMPLETE')
            return body,count
        def main():
            r=self.adapter._project_branch(get('main','branches/main'))
            sc.need(r['name']=='main' and r['sha']==base,'SOURCE_DISCOVERY_BASE_CHANGED')
        def catalog():
            raw=get('catalog','contents/release/targets.yaml',{'ref':head})
            sc.need(type(raw) is dict and raw.get('type')=='file' and
                    raw.get('path')=='release/targets.yaml' and raw.get('encoding')=='base64'
                    and type(raw.get('size')) is int and 0<raw['size']<=120000
                    and type(raw.get('content')) is str and len(raw['content'])<=240000)
            try:
                data=base64.b64decode(raw['content'].replace('\n',''),validate=True)
                text=data.decode('utf-8')
            except (ValueError,UnicodeError):
                raise Denied('SOURCE_DISCOVERY_CATALOG_ENCODING') from None
            blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            sc.need(len(data)==raw['size'] and blob==raw.get('sha'),'SOURCE_DISCOVERY_CATALOG_HASH')
            return text,blob
        def tree():
            raw=get('head_tree','git/commits/'+head)
            sc.need(type(raw) is dict and raw.get('sha')==head)
            value=raw.get('tree',{}).get('sha')
            sc.hex_id(value,40)
            return value
        def paths(count):
            raw=get('compare','compare/'+base+'...'+head,{'page':1,'per_page':1})
            sc.need(type(raw) is dict and raw.get('base_commit',{}).get('sha')==base
                    and raw.get('merge_base_commit',{}).get('sha')==base
                    and raw.get('status')=='ahead' and type(raw.get('ahead_by')) is int
                    and raw['ahead_by']>0 and type(raw.get('files')) is list
                    and len(raw['files'])==count,'SOURCE_DISCOVERY_COMPARE_INCOMPLETE')
            sc.need(all(type(r) is dict and type(r.get('filename')) is str
                        for r in raw['files']),'SOURCE_DISCOVERY_PATHS_INVALID')
            rows=[{'status':'deleted' if r.get('status')=='removed' else r.get('status'),
                   'path':r.get('filename'),'previousPath':r.get('previous_filename')}
                  for r in raw['files']]
            rows.sort(key=lambda r:r['path'])
            try:
                _paths(rows,{'count':count,'sha256':sc.digest(rows)})
                old=[r['previousPath'] for r in rows if r['previousPath'] is not None]
                sc.need(len(old)==len(set(old)) and not set(old)&{r['path'] for r in rows},
                        'SOURCE_DISCOVERY_PATH_OVERLAP')
            except (EvidenceEnvelopeError,TypeError,ValueError):
                raise Denied('SOURCE_DISCOVERY_PATHS_INVALID') from None
            return rows
        main()
        body,count=pr();catalog_text,blob=catalog();tree_sha=tree();records=paths(count)
        try:
            impact=_impact_yaml(body)
        except EvidenceEnvelopeError:
            raise Denied('SOURCE_DISCOVERY_IMPACT_INVALID') from None
        observed={'repository':self.repository,**identity,'treeSha':tree_sha,
                  'headBranch':row['head']['ref'],'body':body,'bodyDigest':_sha(body.encode()),
                  'catalog':catalog_text,'catalogSha256':_sha(catalog_text.encode()),'catalogBlobSha':blob,
                  'impactDigest':_sha(impact.encode()),'paths':records,'pathsDigest':sc.digest(records)}
        # The reviewed projector must independently verify Git objects,
        # exact successor validator/profile and current CI/rules; it is
        # not supplied by the UI and is not the incumbent P5 authority.
        detached=sc.loads_strict(sc.canonical(observed))
        material=None
        if reviewed is not None:
            from .merge_capture import validate
            p,material=reviewed
            material=validate(material,p)
            sc.need(all(material[k]==observed[k] for k in ('body','catalog','paths')),
                    'SOURCE_DISCOVERY_EVIDENCE_CHANGED')
            ci=material['ci']
            fresh=self.project.refresh_ci(actor,detached,validator_revision=ci['validatorRevision'],
                impact_digest=ci['validatedImpactDigest'],revision=p['expectedSourceRevision'])
            if fresh!=ci:
                raise Stale('SOURCE_DISCOVERY_CI_CHANGED')
            projected=p
        elif retain:
            from .successor_projector import SuccessorProjector
            sc.need(type(self.project) is SuccessorProjector,'SOURCE_REVIEW_PROJECTOR_REQUIRED')
            projected,material=self.project.evidence(actor,detached)
            projected=lc.proposal(projected)
        else:
            projected=lc.proposal(self.project(actor,detached))
        sc.need(all(projected[k]==observed[k] for k in ('repository','number','headSha','baseSha',
                'treeSha','bodyDigest','catalogSha256','impactDigest','pathsDigest')),
                'SOURCE_DISCOVERY_PROJECTION_CHANGED')
        if pr()!=(body,count) or catalog()!=(catalog_text,blob) or tree()!=tree_sha or paths(count)!=records:
            raise Stale('SOURCE_DISCOVERY_EVIDENCE_CHANGED')
        main()
        return (projected,material) if retain else projected

    def external_merge(self,actor,value):
        """Read the exact unaccounted main edge independently of execution receipts."""
        p=lc.proposal(value)
        sc.need(p['repository']==self.repository)
        identity={k:p[k] for k in ('number','headSha','baseSha')}
        suffix='pulls/'+str(p['number'])
        raw=self._get(actor,'pr',identity,suffix)
        row=self.adapter._project_pull(raw)
        if row['state']!='closed' or row['merged'] is not True:
            return None
        sc.need(row['number']==p['number'] and row['head']['sha']==p['headSha']
                and row['base']['ref']=='main'
                and all(raw[edge].get('repo',{}).get('full_name')==self.repository
                        for edge in ('head','base')),
                'SOURCE_EXTERNAL_PR_CHANGED')
        merge_sha=raw.get('merge_commit_sha')
        sc.hex_id(merge_sha,40)
        commit=self._get(actor,'external_merge_commit',identity,'git/commits/'+merge_sha)
        main=self._get(actor,'main',identity,'branches/main')
        # An exact historical edge may be observable after main has advanced.
        # Only the cursor's immediate current successor is actionable here.
        branch=self.adapter._project_branch(main)
        if branch['name']!='main' or branch['sha']!=merge_sha:
            return None
        sc.need(commit.get('sha')==merge_sha and
                [parent.get('sha') for parent in commit.get('parents',[])]==[p['baseSha'],p['headSha']]
                and commit.get('tree',{}).get('sha')==p['treeSha'],
                'SOURCE_EXTERNAL_MERGE_EDGE_CHANGED')
        latest=self._get(actor,'pr',identity,suffix)
        latest_main=self.adapter._project_branch(self._get(actor,'main',identity,'branches/main'))
        if latest!=raw or latest_main['name']!='main' or latest_main['sha']!=merge_sha:
            raise Stale('SOURCE_EXTERNAL_MERGE_CHANGED')
        return merge_sha

    def verify_external(self,actor,p,merge_sha):
        p=lc.proposal(p)
        sc.need(self.external_merge(actor,p)==merge_sha,'SOURCE_EXTERNAL_MERGE_CHANGED')
        raw=self._get(actor,'pr',{k:p[k] for k in ('number','headSha','baseSha')},
                      'pulls/'+str(p['number']))
        branch=raw['head']['ref']
        sc.need(self.branch_guard(actor,self.repository,branch) is True,
                'SOURCE_DISCOVERY_BRANCH_DENIED')
        impact=self.project.impact.merged_impact(p,merge_sha,raw['body'])
        self.project.impact.verify_workflows(p['headSha'],self.project.ci.workflows)
        ci=self.project.refresh_ci(actor,{**p,'headBranch':branch},
                validator_revision=impact['validatorRevision'],
                impact_digest=sc.digest(impact),revision=p['expectedSourceRevision'])
        sc.need(sc.digest(ci)==p['ciDigest'] and self.external_merge(actor,p)==merge_sha,
                'SOURCE_EXTERNAL_MERGE_CHANGED')
        o={k:p[k] for k in ('repository','number','headSha','treeSha','catalogSha256',
                            'bodyDigest','impactDigest','pathsDigest','ciDigest')}
        return lc.observation({**o,'mergeSha':merge_sha,'mainSha':merge_sha,
                               'parents':[p['baseSha'],p['headSha']]},p)

    def _review_row(self,actor,p):
        sc.need(p['repository']==self.repository)
        found=[row for row in self._list(actor) if row['number']==p['number']]
        sc.need(len(found)==1,'SOURCE_REVIEW_PR_NOT_FOUND')
        return found[0]

    def review(self,actor,value,*,retained=None):
        """Exact actor-bound review; re-use only digest-bound retained bytes."""
        p=lc.proposal(value)
        row=self._review_row(actor,p)
        current,material=self.observe(actor,row,retain=True,
                                      reviewed=(p,retained) if retained is not None else None)
        if current!=p:
            raise Stale('SOURCE_REVIEW_PROPOSAL_CHANGED')
        return current,material

    def review_same_head(self,actor,value):
        p=lc.proposal(value)
        row=self._review_row(actor,p)
        sc.need(row['head']['sha']==p['headSha'],'SOURCE_REVIEW_HEAD_CHANGED')
        return self.observe(actor,row)

    def __call__(self,actor,repository):
        sc.need(repository==self.repository,'SOURCE_DISCOVERY_REPOSITORY_DENIED')
        first=self._list(actor)
        proposals=[]
        for row in first:
            reason=None
            if row['draft']:
                reason='DRAFT'
            elif row['base']['ref']!='main':
                reason='BASE_NOT_MAIN'
            else:
                try:
                    proposals.append(self.observe(actor,row))
                except Denied as exc:
                    reason=BLOCKED_REASONS.get(str(exc))
                    if reason is None:raise
            if reason:
                # The PR number came from authorized list READ. Never
                # return partially observed evidence or invent an approval.
                proposals.append({'number':row['number'],'state':'BLOCKED','reason':reason})
        # Never submit part of an unstable/incomplete discovery batch.
        if self._list(actor)!=first:
            raise Stale('SOURCE_DISCOVERY_INVENTORY_CHANGED')
        return proposals
