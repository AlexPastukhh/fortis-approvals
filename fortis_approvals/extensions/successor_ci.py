"""Exact successor CI candidate verification; not historical P5 authority.

Only a reviewed independent policy pin selects workflows/rules. No live
policy provisioning or merge authorization is performed here.
"""
from ..core import Stale
from ..integrations.github.gateway.analysis_adapter import AnalysisGitHubAdapter
from ..integrations.github.release_label_ci import (Workflow,ServerCIReader,
    _collect_workflow_evidence,_inventory,_latest)
from ..integrations.github.gateway.p5_ci_binding import observe_check_witnesses, APP_ID
from ..integrations.registry_contracts import semantic_contract as sc


class _Reader(ServerCIReader):
    max_reads=64
    read_seconds=45
    def __init__(self,adapter,guard):
        super().__init__(adapter)
        self.guard=guard
    def get(self,suffix,params=None):
        sc.need(self.guard(suffix,params) is True,'SUCCESSOR_CI_READ_DENIED')
        result=super().get(suffix,params)
        sc.need(self.guard(suffix,params) is True,'SUCCESSOR_CI_READ_DENIED')
        return result


class SuccessorCI:
    def __init__(self,adapter,*,policy,expected_digest,read_guard):
        sc.need(type(adapter) is AnalysisGitHubAdapter and callable(read_guard))
        sc.fields(policy,('schemaVersion','repository','rulesDigest','workflows'))
        sc.hex_id(expected_digest,64);sc.hex_id(policy['rulesDigest'],64)
        sc.need(type(policy['schemaVersion']) is int and policy['schemaVersion']==1
                and policy['repository']==adapter.owner+'/fortis-approvals'
                and 'fortis-approvals' in adapter.repositories and sc.digest(policy)==expected_digest,
                'SUCCESSOR_CI_POLICY_CHANGED')
        rows=policy['workflows']
        sc.need(type(rows) is list and 2<=len(rows)<=4)
        ids=set();names=set();jobs=set();paths=set()
        workflows=[]
        for row in rows:
            sc.fields(row,('name','id','path','jobs','sha256'))
            sc.hex_id(row['sha256'],64)
            sc.need(type(row['id']) is int and row['id']>0 and row['id'] not in ids
                    and type(row['name']) is str and 0<len(row['name'])<=100
                    and row['name'] not in names and type(row['path']) is str
                    and row['path'].startswith('.github/workflows/')
                    and '/' not in row['path'][len('.github/workflows/'):]
                    and row['path'].endswith(('.yml','.yaml')) and row['path'] not in paths
                    and all(c.isascii() and (c.isalnum() or c in '._-/') for c in row['path']))
            js=row['jobs']
            sc.need(type(js) is list and 0<len(js)<=20 and
                    all(type(j) is str and 0<len(j)<=100 for j in js)
                    and len(set(js))==len(js) and not jobs.intersection(js))
            ids.add(row['id']);names.add(row['name']);paths.add(row['path']);jobs.update(js)
            workflows.append(Workflow(row['name'],row['id'],row['path'],tuple(js),row['sha256']))
        by_name={w.name:set(w.jobs) for w in workflows}
        sc.need({'Source CI','Fortis Release Impact'}<=names and
                {'offline-tests','audit-projections'}<=by_name['Source CI'] and
                'release-impact' in by_name['Fortis Release Impact'],
                'SUCCESSOR_CI_REQUIRED_WORKFLOW_MISSING')
        sc.need(adapter.bindings['fortis-approvals']['workflows']=={str(w.ident):w.path for w in workflows},
                'SUCCESSOR_CI_NATIVE_BINDING_CHANGED')
        self.adapter,self.read_guard=adapter,read_guard
        self.policy=sc.canonical(policy);self.pin=expected_digest;self.workflows=tuple(workflows)

    def _rules(self,reader):
        raw=[]
        for page in (1,2):
            rows=reader.get('rules/branches/main',{'page':page,'per_page':100})
            sc.need(type(rows) is list and len(rows)<=100 and all(type(r) is dict for r in rows))
            raw.extend(rows)
            if len(rows)<100:break
        sc.need(0<len(raw)<200 and sc.digest(sorted(raw,key=sc.canonical))==
                sc.loads_strict(self.policy)['rulesDigest'],'SUCCESSOR_CI_RULES_CHANGED')
        required={}
        for row in raw:
            kind=row.get('type')
            sc.need(type(kind) is str and kind not in ('workflows','required_workflows','required_deployments'),
                    'SUCCESSOR_CI_UNSUPPORTED_RULE')
            if kind=='required_status_checks':
                checks=row['parameters']['required_status_checks']
                sc.need(type(checks) is list)
                for check in checks:
                    name=check['context'];app=check.get('integration_id')
                    sc.need(type(name) is str and (app is None or type(app) is int and app in (-1,APP_ID)) and
                            (name not in required or required[name]==app),'SUCCESSOR_CI_RULE_AMBIGUOUS')
                    required[name]=app
        sc.need(bool(required) and set(required)<={j for w in self.workflows for j in w.jobs},
                'SUCCESSOR_CI_RULE_CONTEXT_UNSUPPORTED')
        return sorted(raw,key=sc.canonical)

    def observe(self,actor,observed):
        policy=sc.loads_strict(self.policy)
        sc.need(observed['repository']==policy['repository'])
        identity={k:observed[k] for k in ('number','baseSha','headSha')}
        reader=_Reader(self.adapter,lambda suffix,params:self.read_guard(actor,
            policy['repository'],'successor_ci_evidence',{**identity,'endpoint':suffix,'params':params}))
        rules=self._rules(reader)
        runs=_collect_workflow_evidence(reader,owner=self.adapter.owner,head=identity['headSha'],
            base=identity['baseSha'],number=identity['number'],branch=observed['headBranch'],
            workflows=self.workflows)
        expected={}
        for w,run in zip(self.workflows,runs):
            sc.need({j['name'] for j in run['jobs']}==set(w.jobs),'SUCCESSOR_CI_JOB_SET_CHANGED')
            for j in run['jobs']:expected[j['name']]=(run,j)
        checks=observe_check_witnesses(reader,owner=self.adapter.owner,head=identity['headSha'],expected=expected)
        if observe_check_witnesses(reader,owner=self.adapter.owner,head=identity['headSha'],expected=expected)!=checks:
            raise Stale('SUCCESSOR_CI_CHECK_CHANGED')
        again=_inventory(reader,identity['headSha'])
        for w,run in zip(self.workflows,runs):
            latest=_latest(again,w)
            sc.need((latest['id'],latest['runAttempt'],latest['runNumber'])==
                    (run['runId'],run['attempt'],run['runNumber']),'SUCCESSOR_CI_ATTEMPT_CHANGED')
        sc.need(self._rules(reader)==rules,'SUCCESSOR_CI_RULES_CHANGED')
        return {'schemaVersion':1,'repository':policy['repository'],**identity,
                'policyDigest':self.pin,'rulesDigest':policy['rulesDigest'],'runs':runs,'checks':checks}
