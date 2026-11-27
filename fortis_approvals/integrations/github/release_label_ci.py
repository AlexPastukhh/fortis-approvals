"""Bounded head-scoped CI admission shared by native preview and pre-WRITE.

No classifier, credential, public-HTTP loopback or repository-history scan.
Readers are trusted typed/provider transports; PR files never select code.
"""
import base64
from dataclasses import dataclass
import hashlib
import re
import time

from ...core import Denied, canonical
from .publisher_profile import REPOSITORY, require

MAX_RUNS = 100
PAGE_SIZE = 20
MAX_READS = 18
READ_SECONDS = 20


@dataclass(frozen=True)
class Workflow:
    name: str
    ident: int
    path: str
    jobs: tuple
    sha256: str


WORKFLOWS = (
    Workflow('Source CI', 408327525, '.github/workflows/source-ci.yml',
        ('offline-tests', 'audit-projections'),
        'f5a5ae93f28673bc9c981ba5702565ba91f115f1fe52d60aca3324a0fbd9fab1'),
    Workflow('Fortis Release Impact', 414303977, '.github/workflows/release-impact.yml',
        ('release-impact',),
        'bf0cf64ee7c576335f1416b02c69ff5eb3c59bf68e031a6b0936dfbca0707d28'),
)


def head_page(get, head, page):
    """One fixed head/event page. Typed method and server collector share it."""
    require(type(head) is str and re.fullmatch(r'[0-9a-f]{40}', head) and
            type(page) is int and 1 <= page <= 5, 'GITHUB_HEAD_RUNS_PARAMS_INVALID')
    raw = get('actions/runs', dict(head_sha=head, event='pull_request',
                                   page=page, per_page=PAGE_SIZE))
    require(type(raw) is dict and type(raw.get('workflow_runs')) is list and
            type(raw.get('total_count')) is int and 0 <= raw['total_count'] <= MAX_RUNS,
            'GITHUB_HEAD_RUNS_INCOMPLETE')
    rows = []
    for x in raw['workflow_runs']:
        require(type(x) is dict, 'GITHUB_HEAD_RUNS_INVALID')
        path = x.get('path')
        require(type(path) is str, 'GITHUB_HEAD_RUNS_INVALID')
        rows.append(dict(id=x.get('id'), name=x.get('name'), event=x.get('event'),
            status=x.get('status'), conclusion=x.get('conclusion'),
            headBranch=x.get('head_branch'), headSha=x.get('head_sha'),
            runNumber=x.get('run_number'), runAttempt=x.get('run_attempt'),
            createdAt=x.get('created_at'), updatedAt=x.get('updated_at'),
            url=x.get('html_url'), workflowId=x.get('workflow_id'),
            workflowPath=path.split('@', 1)[0]))
    offset = (page-1)*PAGE_SIZE
    result = dict(operation='list_head_workflow_runs', headSha=head, items=rows,
        totalCount=raw['total_count'], page=page, perPage=PAGE_SIZE,
        complete=offset+len(rows) >= raw['total_count'])
    from .contract import validate_github_read_projection
    return validate_github_read_projection('list_head_workflow_runs', result)


class ServerCIReader:
    """Fixed provider GETs, at most 18, with a 20s monotonic admission budget.

    The transport's reviewed timeout still bounds an already in-flight GET.
    A budget failure never starts another request or authorizes a WRITE.
    """
    max_reads = MAX_READS
    read_seconds = READ_SECONDS

    def __init__(self, adapter, *, clock=time.monotonic):
        self.adapter = adapter
        self.clock = clock
        self.started = clock()
        self.reads = 0

    def get(self, suffix, params=None):
        require(self.reads < self.max_reads and self.clock()-self.started < self.read_seconds,
                'GITHUB_RELEASE_CI_READ_BUDGET')
        self.reads += 1
        result = self.adapter._api('GET', self.adapter._path(REPOSITORY, suffix), params=params)
        require(self.clock()-self.started < self.read_seconds, 'GITHUB_RELEASE_CI_READ_BUDGET')
        return result

    def head_page(self, head, page):
        return head_page(self.get, head, page)

    def run(self, ident, attempt):
        raw = self.get('actions/runs/'+str(ident)+'/attempts/'+str(attempt))
        return self.adapter._project_run(REPOSITORY, ident, attempt, raw)

    def jobs(self, run):
        raw = self.get('actions/runs/'+str(run['id'])+'/attempts/'+str(run['attempt'])+'/jobs',
                       dict(page=1, per_page=100))
        require(type(raw) is dict and type(raw.get('jobs')) is list and
                type(raw.get('total_count')) is int and 0 < raw['total_count'] <= 100 and
                len(raw['jobs']) == raw['total_count'], 'GITHUB_RELEASE_CI_JOBS_INCOMPLETE')
        jobs = []
        for item in raw['jobs']:
            require(type(item) is dict and item.get('run_id') == run['id'] and
                    item.get('run_attempt') == run['attempt'] and item.get('head_sha') == run['headSha'],
                    'GITHUB_RELEASE_CI_JOB_BINDING_INVALID')
            jobs.append(self.adapter._project_job(item))
        return dict(run=run, items=jobs, total=len(jobs), page=1, perPage=100, complete=True)

    def workflow_hash(self, workflow, head):
        meta = self.get('actions/workflows/'+str(workflow.ident))
        require(type(meta) is dict and meta.get('id') == workflow.ident and
                meta.get('path') == workflow.path and meta.get('name') == workflow.name and
                meta.get('state') == 'active', 'GITHUB_RELEASE_CI_WORKFLOW_CHANGED')
        source = self.get('contents/'+workflow.path, dict(ref=head))
        require(type(source) is dict and source.get('type') == 'file' and
                source.get('path') == workflow.path and source.get('encoding') == 'base64' and
                type(source.get('size')) is int and 0 < source['size'] <= 65536 and
                type(source.get('content')) is str and len(source['content']) <= 90000,
                'GITHUB_RELEASE_CI_WORKFLOW_SOURCE_INVALID')
        try:
            data = base64.b64decode(source['content'].replace('\n','').replace('\r',''), validate=True)
        except (ValueError, UnicodeError):
            raise Denied('GITHUB_RELEASE_CI_WORKFLOW_SOURCE_INVALID') from None
        require(len(data) == source['size'] and hashlib.sha1(
            b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() == source.get('sha'),
            'GITHUB_RELEASE_CI_WORKFLOW_SOURCE_INVALID')
        return hashlib.sha256(data).hexdigest()


def _inventory(reader, head):
    rows = []
    total = None
    ids = set()
    for page in range(1, 6):
        data = reader.head_page(head, page)
        require(data.get('operation') == 'list_head_workflow_runs' and data.get('headSha') == head
                and data.get('page') == page and data.get('perPage') == PAGE_SIZE,
                'GITHUB_RELEASE_CI_PAGE_INVALID')
        count = data.get('totalCount')
        require(type(count) is int and 0 <= count <= MAX_RUNS and
                (total is None or count == total), 'GITHUB_RELEASE_CI_INVENTORY_CHANGED')
        total = count
        batch = data.get('items')
        require(type(batch) is list and len(batch) == min(PAGE_SIZE, max(0, total-len(rows))),
                'GITHUB_RELEASE_CI_INVENTORY_INCOMPLETE')
        for row in batch:
            require(type(row) is dict and type(row.get('id')) is int and row['id'] > 0 and
                    row['id'] not in ids and row.get('headSha') == head and
                    row.get('event') == 'pull_request', 'GITHUB_RELEASE_CI_INVENTORY_INVALID')
            ids.add(row['id'])
            rows.append(row)
        require(data.get('complete') is (len(rows) == total), 'GITHUB_RELEASE_CI_PAGE_INVALID')
        if len(rows) == total:
            return rows
    raise Denied('GITHUB_RELEASE_CI_INVENTORY_INCOMPLETE')


def _latest(rows, workflow):
    matches = [r for r in rows if r.get('workflowId') == workflow.ident]
    require(matches, 'GITHUB_RELEASE_CI_MISSING')
    numbers = [r.get('runNumber') for r in matches]
    require(all(type(n) is int and n > 0 for n in numbers) and len(set(numbers)) == len(numbers),
            'GITHUB_RELEASE_CI_RUN_AMBIGUOUS')
    row = max(matches, key=lambda r:r['runNumber'])
    require(row.get('name') == workflow.name and row.get('workflowPath') == workflow.path and
            type(row.get('runAttempt')) is int and row['runAttempt'] > 0 and
            row.get('status') == 'completed' and row.get('conclusion') == 'success',
            'GITHUB_RELEASE_CI_NOT_SUCCESSFUL')
    return row


def collect_workflow_evidence(reader, *, owner, head, number, branch):
    return _collect_workflow_evidence(reader, owner=owner, head=head, number=number,
                                      branch=branch, workflows=WORKFLOWS)


def _collect_workflow_evidence(reader, *, owner, head, number, branch, workflows, base=None):
    """Shared source observation; no publisher grant or merge authority."""
    rows = _inventory(reader, head)
    full = owner+'/'+REPOSITORY
    evidence = []
    for workflow in workflows:
        selected = _latest(rows, workflow)
        require(reader.workflow_hash(workflow, head) == workflow.sha256,
                'GITHUB_RELEASE_CI_WORKFLOW_CHANGED')
        run = reader.run(selected['id'], selected['runAttempt'])
        require(type(run) is dict and run.get('id') == selected['id'] and
                run.get('attempt') == selected['runAttempt'] and run.get('workflowId') == workflow.ident
                and run.get('workflowPath') == workflow.path and run.get('headSha') == head and
                run.get('headBranch') == branch and run.get('repository') == full and
                run.get('headRepository') == full and run.get('event') == 'pull_request' and
                run.get('status') == 'completed' and run.get('conclusion') == 'success' and
                type(run.get('pullRequests')) is list and
                all(type(p) is dict for p in run['pullRequests']) and any(
                    p.get('number') == number and p.get('headSha') == head and
                    (base is None or p.get('baseSha') == base) for p in run['pullRequests']),
                'GITHUB_RELEASE_CI_RUN_BINDING_INVALID')
        page = reader.jobs(run)
        require(type(page) is dict and page.get('run') == run and page.get('complete') is True
                and page.get('page') == 1 and page.get('perPage') == 100 and
                type(page.get('total')) is int and 0 < page['total'] <= 100 and
                type(page.get('items')) is list and len(page['items']) == page['total'],
                'GITHUB_RELEASE_CI_JOBS_INCOMPLETE')
        jobs = page['items']
        require(all(type(j) is dict for j in jobs), 'GITHUB_RELEASE_CI_JOBS_INVALID')
        names = [j.get('name') for j in jobs]
        ids = [j.get('id') for j in jobs]
        require(all(type(j) is dict and j.get('status') == 'completed' and
                    j.get('conclusion') == 'success' for j in jobs) and
                all(type(n) is str and 0 < len(n) <= 200 for n in names) and
                all(type(n) is int and n > 0 for n in ids) and len(set(names)) == len(names)
                and len(set(ids)) == len(ids) and set(workflow.jobs) <= set(names),
                'GITHUB_RELEASE_CI_JOBS_NOT_SUCCESSFUL')
        evidence.append(dict(name=workflow.name, workflowId=workflow.ident,
            workflowPath=workflow.path, workflowSha256=workflow.sha256,
            runId=run['id'], attempt=run['attempt'], runNumber=selected['runNumber'],
            jobs=sorted([dict(id=j['id'], name=j['name'], status=j['status'], conclusion=j['conclusion'])
                         for j in jobs], key=lambda j:j['name'])))
    # An attempt/run can change while metadata and jobs are being read.
    again = _inventory(reader, head)
    for workflow, entry in zip(workflows, evidence):
        latest = _latest(again, workflow)
        require((latest['id'], latest['runAttempt'], latest['runNumber']) ==
                (entry['runId'], entry['attempt'], entry['runNumber']),
                'GITHUB_RELEASE_CI_LATEST_CHANGED')
    return evidence


def collect_ci(reader, *, profile, registry_actor, owner, head, number, branch):
    """Publisher admission remains gated by its separately composed profile."""
    require(profile.enabled, 'GITHUB_PUBLISHER_DISABLED')
    evidence = collect_workflow_evidence(reader, owner=owner, head=head, number=number, branch=branch)
    return dict(version=1, repository=REPOSITORY, number=number, headSha=head, branch=branch,
        profileSha256=profile.fingerprint(registry_actor), validatorRevision=profile.validator_revision,
        requiredCI=evidence)
