"""Owner-pinned evidence for the staged #286 transition and one delivery repair."""
import hashlib
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace

import yaml

from ..core import Denied

from ..extensions.successor_impact import SuccessorImpact
from ..integrations.github.publisher_source import import_source_bundle
from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts import source_lineage_contract as lineage
from ..integrations.registry_contracts import transition_contract as transition
from ..r7_registry_reader_mount import _check_owner_readonly_mount
from ..workflow.common import Git, MAX_BUNDLE
from . import source_event_journal as sources
from .local_candidate_read_service import _owner_runtime_bytes
from .release_domain import ReleaseDomain
from .semantic_unix_service import _read_release_profiles

VALIDATOR_MOUNT = Path('/run/fortis-registry-source')
_ACTION = 'AlexPastukhh/fortis-release-impact-action@'



def _reviewed_workflows(ci, proposal, validator_revision):
    sc.fields(ci, ('schemaVersion','repository','number','baseSha','headSha','policyDigest',
                   'rulesDigest','runs','checks','validatorRevision','validatedImpactDigest',
                   'compositionDigest'))
    sc.need(type(ci['schemaVersion']) is int and ci['schemaVersion']==1
            and sc.digest(ci)==proposal['ciDigest']
            and all(ci[k]==proposal[k] for k in ('repository','number','baseSha','headSha'))
            and ci['validatorRevision']==validator_revision, 'SOURCE_TRANSITION_CI_CHANGED')
    for key in ('policyDigest','rulesDigest','compositionDigest','validatedImpactDigest'):
        sc.hex_id(ci[key],64)
    runs, checks = ci['runs'], ci['checks']
    sc.need(type(runs) is list and 2<=len(runs)<=4 and type(checks) is list and 3<=len(checks)<=80
            and all(type(row) is dict for row in (*runs,*checks)), 'SOURCE_TRANSITION_CI_INCOMPLETE')
    check_ids = {(row.get('name'),row.get('checkRunId'),row.get('runId'),
                  row.get('attempt'),row.get('workflowId')) for row in checks
                 if row.get('headSha')==proposal['headSha'] and row.get('conclusion')=='success'}
    sc.need(len(check_ids)==len(checks), 'SOURCE_TRANSITION_CI_INCOMPLETE')
    workflows, jobs = [], set()
    for run in runs:
        path, digest = run.get('workflowPath'), run.get('workflowSha256')
        sc.need(type(path) is str and re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml',path)
                and type(run.get('jobs')) is list and 0<len(run['jobs'])<=20,
                'SOURCE_TRANSITION_CI_INCOMPLETE')
        sc.hex_id(digest,64)
        workflows.append(SimpleNamespace(path=path,sha256=digest))
        for job in run['jobs']:
            sc.need(type(job) is dict and job.get('status')=='completed'
                    and job.get('conclusion')=='success' and type(job.get('name')) is str,
                    'SOURCE_TRANSITION_CI_INCOMPLETE')
            item = (job['name'],job.get('id'),run.get('runId'),run.get('attempt'),run.get('workflowId'))
            sc.need(item in check_ids and job['name'] not in jobs, 'SOURCE_TRANSITION_CI_INCOMPLETE')
            check_ids.remove(item)
            jobs.add(job['name'])
    sc.need(not check_ids and {'offline-tests','audit-projections','release-impact'}<=jobs,
            'SOURCE_TRANSITION_CI_INCOMPLETE')
    return workflows


def _verify_git(*, config, base_catalog, action_revision, proposal, observation,
                body, bundle, workflows, gap=None):
    writer = config['sourceWrite']
    _check_owner_readonly_mount(VALIDATOR_MOUNT)
    with tempfile.TemporaryDirectory(prefix='registry-transition-') as path:
        work = Path(path)
        git = Git(work/'git', protocols='file')
        repo = work/'source.git'
        git.run(['init','--bare','--template=',repo])
        bundle_file = work/'main.bundle'
        bundle_file.write_bytes(bundle)
        merge = observation['mergeSha']
        import_source_bundle(git, repo, bundle_file, expected=merge, target='main')

        old_catalog = git.run(['--no-replace-objects','cat-file','blob',
                               proposal['baseSha']+':release/targets.yaml'],cwd=repo)[1]
        sc.need(hashlib.sha256(old_catalog).hexdigest()==base_catalog,
                'SOURCE_TRANSITION_OLD_CATALOG_CHANGED')

        # Recheck the actual original graph. The pre-publication owner witness
        # separately anchors historical intake and the protected state.
        if gap is not None:
            history = git.text(['--no-replace-objects','rev-list','--first-parent',
                                '--merges','--parents','--reverse','--max-count=32',
                                lineage.BASELINE+'..'+proposal['baseSha']], cwd=repo)
            rows = [row.split() for row in history.splitlines()]
            sc.need(len(rows)==len(gap['merges']) and all(
                len(row)==3 and (row[0],row[2])==(item['mergeSha'],item['headSha'])
                for row,item in zip(rows,gap['merges'])), 'SOURCE_TRANSITION_GIT_GAP_CHANGED')

        workflow = git.run(['--no-replace-objects','cat-file','blob',
                            proposal['headSha']+':.github/workflows/release-impact.yml'],
                           cwd=repo)[1]
        sc.need(0<len(workflow)<=65536, 'SOURCE_TRANSITION_ACTION_PIN_CHANGED')
        try:
            steps = yaml.safe_load(workflow)['jobs']['release-impact']['steps']
        except (KeyError,TypeError,ValueError,yaml.YAMLError):
            raise Denied('SOURCE_TRANSITION_ACTION_PIN_CHANGED') from None
        sc.need(type(steps) is list and all(type(step) is dict for step in steps),
                'SOURCE_TRANSITION_ACTION_PIN_CHANGED')
        uses = [step['uses'] for step in steps if isinstance(step.get('uses'),str)
                and step['uses'].lower().startswith(_ACTION.lower())]
        sc.need(uses==[_ACTION+action_revision],
                'SOURCE_TRANSITION_ACTION_PIN_CHANGED')
        impact = SuccessorImpact(validator_repository=VALIDATOR_MOUNT/'validator.git',
            validator_revision=writer['validatorRevision'], source_repository=repo,
            state_root=work, repository=proposal['repository'], binding=writer['impactBinding'],
            build_pins=writer['buildPins'], profile_digest=proposal['profileDigest'])
        impact.verify_workflows(proposal['headSha'],workflows)
        return impact.merged_impact(proposal, merge, body)


def reviewed_transition(root, config, *, expected_evidence_sha256, expected_source_sha):
    """Build the first event from protected owner input and verified Git."""
    sc.hex_id(expected_evidence_sha256,64)
    sc.hex_id(expected_source_sha,40)
    raw = _owner_runtime_bytes(root/'transition-evidence.json',262144)
    sc.need(hashlib.sha256(raw).hexdigest()==expected_evidence_sha256,
            'SOURCE_TRANSITION_EVIDENCE_PIN_CHANGED')
    envelope = sc.loads_strict(raw)
    sc.fields(envelope,('manifest','oldState','gap','gapObservation','proposal','observation',
                        'ci','body','bundleSha256'))
    sc.need(sc.canonical(envelope).encode()==raw,'SOURCE_TRANSITION_EVIDENCE_INVALID')

    manifest = envelope['manifest']
    pins = config['semantic']
    witness = transition.bind_old_state(manifest,envelope['oldState'],
                                       expected_manifest_digest=pins['transitionDigest'])
    proposal = lineage.proposal(envelope['proposal'])
    observed = lineage.observation(envelope['observation'],proposal)
    gap, gap_observed = envelope['gap'], envelope['gapObservation']
    sc.need(gap_observed=={'baseSha':lineage.BASELINE,'endSha':transition.BASE_SHA,
                          'gapDigest':sc.digest(gap)},'SOURCE_TRANSITION_GAP_READBACK_CHANGED')
    detail = {'manifest':manifest,'gap':gap,'oldStateDigest':witness['oldStateDigest'],
              'gapObservationDigest':sc.digest(gap_observed)}
    lineage.transition(detail,proposal,observed,pins['legacyWitness'],config['scope'],
                       pins['transitionDigest'])
    writer = config['sourceWrite']
    sc.need(observed['mergeSha']==expected_source_sha
            and proposal['profileDigest']==pins['successorProfileDigest']
            and writer['validatorRevision']==manifest['successor']['validatorRevision']
            and writer['policyAuthorityDigest']==manifest['successor']['authorityDigest'],
            'SOURCE_TRANSITION_RUNTIME_PINS_CHANGED')
    ci = envelope['ci']
    workflows = _reviewed_workflows(ci,proposal,writer['validatorRevision'])
    bundle = _owner_runtime_bytes(root/'transition-main.bundle',MAX_BUNDLE)
    sc.need(hashlib.sha256(bundle).hexdigest()==envelope['bundleSha256'],
            'SOURCE_TRANSITION_BUNDLE_CHANGED')
    body = envelope['body']
    sc.need(type(body) is str and 0<len(body.encode())<=20000,'SOURCE_TRANSITION_BODY_INVALID')
    impact = _verify_git(config=config,base_catalog=manifest['old']['catalogSha256'],
                         action_revision=manifest['successor']['actionRevision'],proposal=proposal,
                         observation=observed,body=body,bundle=bundle,gap=gap,workflows=workflows)
    sc.need(ci.get('validatedImpactDigest')==sc.digest(impact),
            'SOURCE_TRANSITION_CI_IMPACT_CHANGED')
    return {'operationId':manifest['transitionId'],'kind':'TRANSITION','parentRequestId':None,
            'proposal':proposal,'observation':observed,'evidenceDigest':expected_evidence_sha256,
            'transition':detail}


def reviewed_delivery_repair(root, config, *, expected_evidence_sha256, expected_source_sha,
                             retained_transition):
    """Verify the same protected scope and CI epoch on the next Git edge."""
    sc.hex_id(expected_evidence_sha256, 64)
    sc.hex_id(expected_source_sha, 40)
    raw = _owner_runtime_bytes(root/'delivery-repair-evidence.json', 262144)
    sc.need(hashlib.sha256(raw).hexdigest() == expected_evidence_sha256,
            'SOURCE_DELIVERY_REPAIR_EVIDENCE_PIN_CHANGED')
    envelope = sc.loads_strict(raw)
    sc.fields(envelope, ('predecessorReceipt', 'proposal', 'observation', 'ci', 'body', 'bundleSha256'))
    sc.need(sc.canonical(envelope).encode() == raw, 'SOURCE_DELIVERY_REPAIR_EVIDENCE_INVALID')

    predecessor, receipt, _ = retained_transition
    sc.need(envelope['predecessorReceipt'] == receipt, 'SOURCE_DELIVERY_REPAIR_PREDECESSOR')
    original_raw = _owner_runtime_bytes(root/'transition-evidence.json', 262144)
    sc.need(hashlib.sha256(original_raw).hexdigest() == predecessor['evidenceDigest'],
            'SOURCE_DELIVERY_REPAIR_ORIGINAL_EVIDENCE_CHANGED')
    original = sc.loads_strict(original_raw)
    sc.need(original['proposal'] == predecessor['proposal']
            and original['observation'] == predecessor['observation']
            and sc.digest(original['ci']) == predecessor['proposal']['ciDigest'],
            'SOURCE_DELIVERY_REPAIR_ORIGINAL_EVIDENCE_CHANGED')

    proposal = lineage.proposal(envelope['proposal'])
    observation = lineage.observation(envelope['observation'], proposal)
    writer = config['sourceWrite']
    manifest = predecessor['transition']['manifest']
    sc.need(proposal['baseSha'] == receipt['sourceCursor'] and proposal['expectedSourceRevision'] == 1
            and proposal['number'] > predecessor['proposal']['number']
            and observation['mergeSha'] == expected_source_sha
            and proposal['catalogSha256'] == predecessor['proposal']['catalogSha256']
            and proposal['profileDigest'] == predecessor['proposal']['profileDigest']
            and proposal['profileDigest'] == config['semantic']['successorProfileDigest']
            and writer['validatorRevision'] == manifest['successor']['validatorRevision'],
            'SOURCE_DELIVERY_REPAIR_RUNTIME_PINS_CHANGED')

    ci, previous_ci = envelope['ci'], original['ci']
    workflows = _reviewed_workflows(ci, proposal, writer['validatorRevision'])

    def workflow_pins(proof):
        return sorted((run['workflowId'], run['workflowPath'], run['workflowSha256'],
                       sorted(job['name'] for job in run['jobs'])) for run in proof['runs'])

    sc.need(all(ci[key] == previous_ci[key] for key in ('policyDigest','rulesDigest','compositionDigest'))
            and workflow_pins(ci) == workflow_pins(previous_ci)
            and all(check.get('appId') == 15368 and check.get('appSlug') == 'github-actions'
                    for check in ci['checks']),
            'SOURCE_DELIVERY_REPAIR_CI_CHANGED')

    bundle = _owner_runtime_bytes(root/'delivery-repair-main.bundle', MAX_BUNDLE)
    sc.need(hashlib.sha256(bundle).hexdigest() == envelope['bundleSha256'],
            'SOURCE_DELIVERY_REPAIR_BUNDLE_CHANGED')
    body = envelope['body']
    sc.need(type(body) is str and 0 < len(body.encode()) <= 20000, 'SOURCE_TRANSITION_BODY_INVALID')
    impact = _verify_git(config=config, base_catalog=proposal['catalogSha256'],
                         action_revision=manifest['successor']['actionRevision'], proposal=proposal,
                         observation=observation, body=body, bundle=bundle, workflows=workflows)
    sc.need(ci['validatedImpactDigest'] == sc.digest(impact), 'SOURCE_TRANSITION_CI_IMPACT_CHANGED')
    return {
        'operationId': sources.delivery_repair_id(receipt['operationId'], expected_source_sha),
        'kind': sources.DELIVERY_REPAIR, 'parentRequestId': None,
        'proposal': proposal, 'observation': observation, 'evidenceDigest': expected_evidence_sha256,
        'transition': {'predecessorOperationId': receipt['operationId'],
                       'predecessorEventDigest': receipt['eventDigest']},
    }


def staged_domain(journal, root, pins):
    legacy, successor = _read_release_profiles(root)
    return ReleaseDomain(journal,legacy,expected_profile_digest=pins['legacyProfileDigest'],
                         successor_profile=successor,
                         expected_successor_profile_digest=pins['successorProfileDigest'])


def account_on_clone(domain, db, request):
    req = sources.request(request,domain.store)
    view = domain._project(db)
    sc.need(req['kind']=='TRANSITION' and view['sourceRevision']==0 and not view['operations'],
            'SOURCE_TRANSITION_STAGED_STATE_CHANGED')
    receipt = sources.append(domain.store,db,req,view['operations'])
    domain._project(db)
    return receipt
