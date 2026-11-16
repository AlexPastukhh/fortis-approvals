"""Owner-invoked one-PR publisher source. No default credentials or background trigger."""
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urlsplit
import uuid

from ...core import Denied, canonical, loads_strict
from ...workflow.common import branch, secure_dir, sha
from .contract import validate_github_action
from .publisher_evidence import own_label_evidence, check_own_record
from .publisher_profile import ACTOR, REPOSITORY, WRITES, require
from .publisher_source import private_path, source_view
from .publisher_validator import PinnedValidator
from .release_label_ci import collect_ci
from .release_label_contract import checked_names, names_hash
from .release_label_evidence import release_label_receipt_matches, read_release_label_evidence

_REASON = 'Fortis publisher v1 admission '


@dataclass(frozen=True)
class RunnerConfig:
    validator_root: Path
    validator_revision: str
    profile_sha256: str
    cache_root: Path
    intent_root: Path
    endpoint: str
    grant_path: Path
    certificate_path: Path
    owner: str = 'AlexPastukhh'
    enabled: bool = False

    def __post_init__(self):
        require(type(self.enabled) is bool, 'PUBLISHER_CONFIG_INVALID')
        sha(self.validator_revision)
        require(type(self.profile_sha256) is str and
                re.fullmatch('[0-9a-f]{64}',self.profile_sha256),
                'PUBLISHER_PROFILE_PIN_REQUIRED')
        require(type(self.owner) is str and
                re.fullmatch('[A-Za-z0-9][A-Za-z0-9-]{0,38}',self.owner),
                'PUBLISHER_OWNER_INVALID')
        for field in ('validator_root','cache_root','intent_root','grant_path','certificate_path'):
            object.__setattr__(self, field, private_path(getattr(self, field)))
        paths = (self.validator_root, self.cache_root, self.intent_root)
        require(all(a != b and a not in b.parents and b not in a.parents
                    for i,a in enumerate(paths) for b in paths[i+1:]),
                'PUBLISHER_ROOTS_MUST_BE_SEPARATE')
        require(type(self.endpoint) is str, 'PUBLISHER_ENDPOINT_INVALID')
        parsed = urlsplit(self.endpoint)
        require(parsed.scheme == 'https' and parsed.hostname and
                parsed.username is None and parsed.password is None and
                not parsed.query and not parsed.fragment and parsed.path in ('','/'),
                'PUBLISHER_ENDPOINT_INVALID')
        try:
            valid_port = parsed.port is None or 0 < parsed.port <= 65535
        except ValueError:
            valid_port = False
        require(valid_port and self.endpoint.isascii() and
                all(32 < ord(c) < 127 for c in self.endpoint), 'PUBLISHER_ENDPOINT_INVALID')
        object.__setattr__(self,'endpoint',self.endpoint.rstrip('/'))

    @classmethod
    def load(cls, path):
        path = private_path(path)
        info = path.stat()
        require(path.is_file() and not info.st_mode & 0o022 and
                info.st_uid in (0,os.geteuid()) and info.st_size <= 16384,
                'PUBLISHER_CONFIG_PERMISSIONS')
        value = loads_strict(path.read_bytes())
        require(type(value) is dict and set(value) == set(cls.__dataclass_fields__),
                'PUBLISHER_CONFIG_FIELDS_INVALID')
        return cls(**value)


@dataclass(frozen=True)
class _AdmittedProfile:
    """A local CI-input adapter after exact live profile-pin validation, no authority."""
    profile_hash: str
    validator_revision: str
    enabled: bool = True

    def fingerprint(self, _registry_actor):
        return self.profile_hash


class TypedCIReader:
    """Existing scoped typed READs; exact workflow hashes come from verified blobs."""
    def __init__(self, github, view, *, clock=time.monotonic):
        self.github, self.view, self.clock = github, view, clock
        self.started, self.reads = clock(), 0

    def _read(self, function, *args, **kwargs):
        require(self.reads < 18 and self.clock()-self.started < 60,
                'PUBLISHER_CI_READ_BUDGET')
        self.reads += 1
        result = function(*args, **kwargs)
        require(self.clock()-self.started < 60, 'PUBLISHER_CI_READ_BUDGET')
        return result

    def head_page(self, head, page):
        return self._read(self.github.list_head_workflow_runs, REPOSITORY, head,
                          page=page, per_page=20)

    def run(self, ident, attempt):
        return self._read(self.github.get_workflow_run, REPOSITORY, ident, attempt)['data']['run']

    def jobs(self, run):
        data = self._read(self.github.list_workflow_jobs, REPOSITORY, run['id'],
                          run['attempt'], page=1, per_page=100)['data']
        keys = ('id','attempt','workflowId','workflowPath','event','status','conclusion',
                'headSha','headBranch','repository','headRepository','pullRequests')
        require(type(data) is dict and type(data.get('run')) is dict and
                all(data['run'].get(k) == run.get(k) for k in keys),
                'PUBLISHER_CI_RUN_CHANGED')
        return {**data,'run':run}

    def workflow_hash(self, workflow, head):
        require(self.view.git.text(['rev-parse','HEAD'], cwd=self.view.data) == head,
                'PUBLISHER_SOURCE_SHA_CHANGED')
        return hashlib.sha256((self.view.data/workflow.path).read_bytes()).hexdigest()


class PublisherRunner:
    def __init__(self, config, client, *, validator_factory=PinnedValidator):
        require(type(config) is RunnerConfig, 'PUBLISHER_CONFIG_REQUIRED')
        require(client.worker is None and client.automatic_recovery is True and
                client.intents.journal.root == config.intent_root and
                getattr(client.gateway,'endpoint',None) == config.endpoint,
                'PUBLISHER_EXPLICIT_PRIVATE_CLIENT_REQUIRED')
        self.config, self.client, self.validator_factory = config, client, validator_factory

    def _capabilities(self):
        require(self.config.enabled, 'PUBLISHER_RUNNER_DISABLED')
        cap = self.client.capabilities(refresh=True)
        require(own_label_evidence(cap) is not None and cap.get('owner') == self.config.owner
                and cap.get('repository') == REPOSITORY and cap.get('workspaceOperations') == [] and
                cap.get('allowGitHub') == [] and set(cap.get('askGitHub',[])) == WRITES and
                cap.get('dynamicRepositories') is False and cap.get('gitHubCredentialInRepo') is False,
                'PUBLISHER_SCOPE_REQUIRED')
        profile, writes, reads = cap.get('publisherProfile'), cap.get('githubReleaseLabelWrites'), cap.get('githubHeadWorkflowReads')
        require(type(profile) is dict and type(profile.get('version')) is int and
                profile['version'] == 1 and profile.get('enabled') is True and
                profile.get('actor') == ACTOR and profile.get('repository') == REPOSITORY and
                profile.get('profileSha256') == self.config.profile_sha256 and
                profile.get('validatorRevision') == self.config.validator_revision and
                profile.get('registryDelegation') is True and
                profile.get('trigger') == 'owner-one-shot' and
                profile.get('ciAdmission') == 'preview-and-before-write-v1' and
                profile.get('activeRequestGuard') == 'repository-wide-v1' and
                type(writes) is dict and writes.get('policy') == 'ASK' and
                writes.get('unknownEffect') == 'STOP' and set(writes.get('commands',[])) == WRITES and
                writes.get('automaticPublisher') == 'OWNER_ONE_SHOT_ASK' and
                writes.get('scope') == 'registered-open-same-repo-task-PR-only' and
                type(reads) is dict and type(reads.get('version')) is int and reads['version'] == 1 and
                reads.get('operation') == 'list_head_workflow_runs' and reads.get('maxRuns') == 100 and
                reads.get('pageSize') == 20, 'PUBLISHER_LIVE_PROFILE_NOT_ADMITTED')
        return cap

    def _snapshot(self, number):
        require(type(number) is int and 0 < number <= 1000000, 'PUBLISHER_PR_INVALID')
        github = self.client.github
        short = github.get_pull_request(REPOSITORY,number)['pullRequest']
        require(short['state'] == 'open' and short['draft'] is False and short['merged'] is False
                and short['base']['ref'] == 'main', 'PUBLISHER_READY_PR_REQUIRED')
        head = sha(short['head']['sha'])
        raw = github.get_pr_release_impact_evidence(REPOSITORY,number,head)
        context = github.get_pr_release_label_context(REPOSITORY,number)
        full = self.config.owner+'/'+REPOSITORY
        require(raw['headRepository'] == raw['baseRepository'] == full and
                raw['state'] == 'open' and raw['draft'] is False and raw['merged'] is False and
                raw['baseBranch'] == 'main' and raw['headSha'] == context['headSha'] == head and
                raw['baseSha'] == context['baseSha'] == short['base']['sha'] and
                raw['headBranch'] == context['branch'] == short['head']['ref'] and
                raw['number'] == context['number'] == number,
                'PUBLISHER_PR_PROVENANCE_CHANGED')
        branch(context['branch'])
        body = raw['body']
        require(type(body) is str and 0 < len(body.encode()) <= 20000 and
                hashlib.sha256(body.encode()).hexdigest() == raw['bodySha256'] == context['bodySha256'],
                'PUBLISHER_BODY_CHANGED')
        labels = checked_names(context['labels'])
        require(names_hash(labels) == context['labelsSha256'], 'PUBLISHER_LABELS_CHANGED')
        pr = dict(number=number,state='open',draft=False,merged=False,merged_at=None,body=body,
                  head=dict(ref=context['branch'],sha=head,repo=dict(full_name=full)),
                  base=dict(ref='main',sha=context['baseSha'],repo=dict(full_name=full)))
        return pr, context

    def _definitions(self):
        names = []
        for page in range(1,7):
            data = self.client.github.list_repository_labels(REPOSITORY,page=page,per_page=50)
            require(data.get('operation') == 'list_repository_labels' and data.get('page') == page
                    and data.get('perPage') == 50 and type(data.get('items')) is list and
                    len(data['items']) <= 50 and type(data.get('hasNextPage')) is bool,
                    'PUBLISHER_LABEL_INVENTORY_INCOMPLETE')
            names.extend(row['name'] for row in data['items'])
            checked_names(names)
            if not data['hasNextPage']:
                return sorted(names)
            require(len(data['items']) == 50, 'PUBLISHER_LABEL_INVENTORY_INCOMPLETE')
        raise Denied('PUBLISHER_LABEL_INVENTORY_LIMIT')

    def _ci(self, view, pr):
        profile = _AdmittedProfile(self.config.profile_sha256,self.config.validator_revision)
        return collect_ci(TypedCIReader(self.client.github,view),profile=profile,
            registry_actor='',owner=self.config.owner,head=pr['head']['sha'],
            number=pr['number'],branch=pr['head']['ref'])

    def _prepare(self, number):
        self._capabilities()
        pr, context = self._snapshot(number)
        main = self.client.github.get_branch(REPOSITORY,'main')['branch']['sha']
        actual = self.client.github.get_branch(REPOSITORY,pr['head']['ref'])['branch']['sha']
        require(actual == pr['head']['sha'], 'PUBLISHER_TASK_REF_CHANGED')
        with source_view(self.client.gateway,self.config.cache_root,main_sha=main,
                head_sha=actual,base_sha=pr['base']['sha'],task_branch=pr['head']['ref']) as (view, source):
            validator = self.validator_factory(self.config.validator_root,self.config.validator_revision,
                                              git=view.git,folder=view.folder/'validator')
            ci = self._ci(view,pr)
            plan = validator.plan(view=view,current_pr=pr,existing_labels=context['labels'],
                                  available_labels=self._definitions(),
                                  repository=self.config.owner+'/'+REPOSITORY)
            fresh_pr, fresh_context = self._snapshot(number)
            require(fresh_pr == pr and fresh_context == context, 'PUBLISHER_PR_CHANGED_DURING_PLAN')
            require(self.client.github.get_branch(REPOSITORY,'main')['branch']['sha'] == main and
                    self.client.github.get_branch(REPOSITORY,pr['head']['ref'])['branch']['sha'] == actual,
                    'PUBLISHER_SOURCE_REF_CHANGED')
            require(canonical(self._ci(view,pr)) == canonical(ci), 'PUBLISHER_CI_CHANGED_DURING_PLAN')
            self._capabilities()
        params = dict(number=number,expectedHeadSha=context['headSha'],expectedBaseSha=context['baseSha'],
                      expectedBodySha256=context['bodySha256'],expectedLabelsSha256=context['labelsSha256'])
        operation = None
        if plan['status'] == 'PREVIEW_ONLY':
            # Delta semantics belong to the pinned public projector. Scheduling
            # one removal before at most five additions belongs to this runner.
            if plan['remove']:
                operation = 'remove_pr_release_label'; params['name'] = sorted(plan['remove'])[0]
            elif plan['add']:
                operation = 'add_pr_release_labels'; params['labels'] = sorted(plan['add'])[:5]
        if operation:
            validate_github_action(operation,REPOSITORY,params)
        admission = dict(version=1,repository=REPOSITORY,pullRequest=number,
            profileSha256=self.config.profile_sha256,validatorRevision=self.config.validator_revision,
            source={key:source[key] for key in ('mainSha','headSha','baseSha','mergeBaseSha')},
            context={key:context[key] for key in ('headSha','baseSha','bodySha256','labelsSha256','branch')},
            requiredCI=ci,plan=plan,operation=operation,params=params if operation else None)
        digest = hashlib.sha256(canonical(admission).encode()).hexdigest()
        return dict(status='BLOCKED_MISSING_LABELS' if plan['missingDefinitions'] else
                    'PREPARED_OWNER_ASK' if operation else 'NO_CHANGES',
                    repository=REPOSITORY,pullRequest=number,headSha=context['headSha'],
                    operation=operation,params=params if operation else None,plan=plan,
                    admissionSha256=digest,admission=admission,sourceReadback=source,
                    ownerApprovalRequired=bool(operation),writeEnabled=False)

    def preview(self, number):
        return self._prepare(number)

    def request(self, number):
        prepared = self._prepare(number)
        if not prepared['operation']:
            return prepared
        evidence = dict(version=1,scope='release-label-publisher',
                        admissionSha256=prepared['admissionSha256'],admission=prepared['admission'])
        result = self.client.intents.github_action(prepared['operation'],REPOSITORY,prepared['params'],
            reason=_REASON+prepared['admissionSha256'],journal_evidence=evidence)
        return dict(status=result['status'],prepared=prepared,intent=result,
                    ownerApprovalRequired=True,writeConfirmed=result['effect']['state'] == 'EXECUTED')

    def _record(self, ident):
        root = secure_dir(self.config.intent_root)
        require(root == self.client.intents.journal.root, 'PUBLISHER_PRIVATE_JOURNAL_REQUIRED')
        record = self.client.intents.journal.load(ident)
        require(type(record) is dict and record.get('endpoint') == self.config.endpoint,
                'PUBLISHER_INTENT_NOT_AVAILABLE')
        intent, evidence = record.get('intent'), record.get('callerEvidence')
        require(type(intent) is dict and intent.get('kind') == 'github' and
                intent.get('repository') == REPOSITORY and intent.get('operation') in WRITES and
                type(evidence) is dict and type(evidence.get('version')) is int and evidence['version'] == 1 and
                evidence.get('scope') == 'release-label-publisher' and type(evidence.get('admission')) is dict,
                'PUBLISHER_INTENT_SCOPE_REQUIRED')
        digest = hashlib.sha256(canonical(evidence['admission']).encode()).hexdigest()
        require(evidence.get('admissionSha256') == digest and intent.get('reason') == _REASON+digest and
                str(uuid.uuid5(uuid.NAMESPACE_URL,self.config.endpoint+'|'+canonical(intent))) == ident,
                'PUBLISHER_INTENT_EVIDENCE_CHANGED')
        validate_github_action(intent['operation'],REPOSITORY,intent['params'])
        require(evidence['admission'].get('params') == intent['params'] and
                evidence['admission'].get('operation') == intent['operation'] and
                evidence['admission'].get('repository') == REPOSITORY and
                0 <= len(record['attempts']) <= 3, 'PUBLISHER_INTENT_EVIDENCE_CHANGED')
        return record

    def inspect(self, ident):
        """Read original journal/receipts and current admission; no retry or reconcile."""
        record = self._record(ident)
        intent = record['intent']; observations = []
        known = any(a.get('observedState') == 'EXECUTED' for a in record['attempts'])
        for attempt in record['attempts']:
            request_id = attempt['requestId']
            item = dict(requestId=request_id,coreState='UNKNOWN',receiptVerified=False,
                        targetReadback=dict(status='UNCONFIRMED'))
            try:
                state = self.client.result(request_id)
                item['coreState'] = state['state']
                known = known or state['state'] == 'EXECUTED'
                details = self.client.details(request_id,event_offset=0,event_limit=100)
                check_own_record(dict(actor=ACTOR),details['request'])
                row = details['request']
                require(row['request']['operation'] == intent['operation'] and
                        row['request']['params'] == intent['params'], 'PUBLISHER_RECEIPT_SCOPE_CHANGED')
                receipt = details.get('receipt')
                receipt = receipt.get('result') if type(receipt) is dict else None
                item['receiptVerified'] = release_label_receipt_matches(intent['operation'],REPOSITORY,
                    intent['params'],request_id,receipt)
                item['targetReadback'] = read_release_label_evidence(self.client.github,REPOSITORY,
                    intent['operation'],intent['params'],receipt)
            except Exception:
                # Optional readback failure never erases a known original effect.
                item['readback'] = 'UNCONFIRMED'
            observations.append(item)
        current = dict(status='UNCONFIRMED')
        try:
            plan = self.preview(intent['params']['number'])
            context = plan['admission']['context']
            matches = all(context[key] == intent['params']['expected'+key[0].upper()+key[1:]]
                          for key in ('headSha','baseSha','bodySha256'))
            current = dict(status='VERIFIED' if matches else 'SOURCE_CHANGED',
                           headSha=plan['headSha'],projectionStatus=plan['status'],
                           remainingAdd=plan['plan']['add'],remainingRemove=plan['plan']['remove'])
        except Exception:
            # No WRITE follows this best-effort current-state observation.
            pass
        return dict(status='READ_ONLY',intentId=ident,attemptIds=[a['requestId'] for a in record['attempts']],
                    effect=dict(state='EXECUTED' if known else 'UNCONFIRMED'),
                    originalRequests=observations,currentAdmission=current,
                    automaticRetryAllowed=False,writeEnabled=False)

    def inspect_pr(self, number):
        require(type(number) is int and 0 < number <= 1000000, 'PUBLISHER_PR_INVALID')
        root = secure_dir(self.config.intent_root)
        files = sorted(root.glob('*.json'))
        require(len(files) <= 256, 'PUBLISHER_INTENT_INVENTORY_LIMIT')
        reports = []
        for path in files:
            record = self._record(path.stem)
            if record['intent']['params']['number'] == number:
                reports.append(self.inspect(path.stem))
        return dict(status='READ_ONLY',pullRequest=number,intents=reports,writeEnabled=False)


def _owner_client(config):
    # Repo-side client modules are imported only by an explicit owner command,
    # never by the Gateway server merely importing its provider package.
    from ...workflow.client import WorkflowClient, WorkflowTransport
    transport = WorkflowTransport(endpoint=config.endpoint,grant_path=str(config.grant_path),
                                  certificate_path=str(config.certificate_path))
    return WorkflowClient.for_release_label_publisher(gateway=transport,intent_root=config.intent_root)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True)
    commands = parser.add_subparsers(dest='mode',required=True)
    for name in ('preview','request'):
        command = commands.add_parser(name); command.add_argument('--pr',type=int,required=True)
    command = commands.add_parser('inspect')
    choice = command.add_mutually_exclusive_group(required=True)
    choice.add_argument('--intent-id'); choice.add_argument('--pr',type=int)
    args = parser.parse_args(argv)
    try:
        config = RunnerConfig.load(args.config)
        require(args.mode == 'inspect' or config.enabled, 'PUBLISHER_RUNNER_DISABLED')
        client = _owner_client(config)
        runner = PublisherRunner(config,client)
        result = (runner.inspect(args.intent_id) if args.intent_id else runner.inspect_pr(args.pr)) if args.mode == 'inspect' else getattr(runner,args.mode)(args.pr)
        print(json.dumps(result,sort_keys=True))
        return 0 if result['status'] not in ('STOP','BLOCKED_MISSING_LABELS','RETRY_EXHAUSTED') else 2
    except Exception as error:
        code = error.args[0] if len(error.args) == 1 else None
        if type(code) is not str or not re.fullmatch('[A-Z][A-Z0-9_]{0,119}',code):
            code = 'PUBLISHER_RUN_FAILED'
        print(json.dumps(dict(status='STOP',code=code,writeEnabled=False)))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
