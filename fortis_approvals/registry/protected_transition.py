"""Owner-pinned evidence for the staged #286 transition and bounded initial-delivery repairs."""
from contextlib import contextmanager, closing
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


def _verify_action_pin(git, repo, head, action_revision):
    workflow = git.run(['--no-replace-objects','cat-file','blob',
                        head+':.github/workflows/release-impact.yml'],
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

        _verify_action_pin(git,repo,proposal['headSha'],action_revision)
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


def _repair_material(revision):
    sc.need(revision in (1, 2), 'SOURCE_DELIVERY_REPAIR_SCOPE')
    return 'delivery-repair' if revision == 1 else 'delivery-repair-2'


def _retained_source_evidence(root, name, request):
    raw = _owner_runtime_bytes(root/name,262144)
    sc.need(hashlib.sha256(raw).hexdigest()==request['evidenceDigest'],
            'SOURCE_DELIVERY_REPAIR_ORIGINAL_EVIDENCE_CHANGED')
    evidence = sc.loads_strict(raw)
    sc.need(evidence['proposal']==request['proposal']
            and evidence['observation']==request['observation']
            and sc.digest(evidence['ci'])==request['proposal']['ciDigest'],
            'SOURCE_DELIVERY_REPAIR_ORIGINAL_EVIDENCE_CHANGED')
    return evidence


def _same_delivery_ci(ci, previous_ci, proposal, validator_revision, *, error):
    workflows = _reviewed_workflows(ci,proposal,validator_revision)

    def workflow_pins(proof):
        return sorted((run['workflowId'],run['workflowPath'],run['workflowSha256'],
                       sorted(job['name'] for job in run['jobs'])) for run in proof['runs'])

    sc.need(all(ci[k]==previous_ci[k] for k in ('policyDigest','rulesDigest','compositionDigest'))
            and workflow_pins(ci)==workflow_pins(previous_ci)
            and all(check.get('appId')==15368 and check.get('appSlug')=='github-actions'
                    for check in ci['checks']),error)
    return workflows


def reviewed_delivery_repair(root, config, *, expected_evidence_sha256, expected_source_sha,
                             retained_transition, retained_predecessor):
    """Verify the same protected scope and CI epoch on the next Git edge."""
    sc.hex_id(expected_evidence_sha256, 64)
    sc.hex_id(expected_source_sha, 40)
    predecessor, receipt, _ = retained_predecessor
    material = _repair_material(receipt['sourceRevision'])
    raw = _owner_runtime_bytes(root/(material+'-evidence.json'), 262144)
    sc.need(hashlib.sha256(raw).hexdigest() == expected_evidence_sha256,
            'SOURCE_DELIVERY_REPAIR_EVIDENCE_PIN_CHANGED')
    envelope = sc.loads_strict(raw)
    sc.fields(envelope, ('predecessorReceipt', 'proposal', 'observation', 'ci', 'body', 'bundleSha256'))
    sc.need(sc.canonical(envelope).encode() == raw, 'SOURCE_DELIVERY_REPAIR_EVIDENCE_INVALID')

    sc.need(envelope['predecessorReceipt'] == receipt, 'SOURCE_DELIVERY_REPAIR_PREDECESSOR')
    transition_request, transition_receipt, _ = retained_transition

    original = _retained_source_evidence(root,'transition-evidence.json',transition_request)
    if receipt['sourceRevision'] == 2:
        previous = _retained_source_evidence(root,'delivery-repair-evidence.json',predecessor)
        sc.need(previous['predecessorReceipt'] == transition_receipt,
                'SOURCE_DELIVERY_REPAIR_PREDECESSOR')

    proposal = lineage.proposal(envelope['proposal'])
    observation = lineage.observation(envelope['observation'], proposal)
    writer = config['sourceWrite']
    manifest = transition_request['transition']['manifest']
    sc.need(proposal['baseSha'] == receipt['sourceCursor']
            and proposal['expectedSourceRevision'] == receipt['sourceRevision']
            and proposal['number'] > predecessor['proposal']['number']
            and observation['mergeSha'] == expected_source_sha
            and proposal['catalogSha256'] == predecessor['proposal']['catalogSha256']
            and proposal['profileDigest'] == predecessor['proposal']['profileDigest']
            and proposal['profileDigest'] == config['semantic']['successorProfileDigest']
            and writer['validatorRevision'] == manifest['successor']['validatorRevision'],
            'SOURCE_DELIVERY_REPAIR_RUNTIME_PINS_CHANGED')

    ci, previous_ci = envelope['ci'], original['ci']
    workflows = _same_delivery_ci(ci,previous_ci,proposal,writer['validatorRevision'],
                                  error='SOURCE_DELIVERY_REPAIR_CI_CHANGED')

    bundle = _owner_runtime_bytes(root/(material+'-main.bundle'), MAX_BUNDLE)
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


def bootstrap_prefix(view, store):
    """The exact pre-product prefix, also checked on a readback of its one append."""
    rows = sorted(view['sourceOperations'].values(),key=lambda row:row[1]['sourceRevision'])
    sc.need(view['sourceRevision'] in (3,4) and view['snapshotRevision']==view['sourceRevision']
            and not view['operations'] and not view['sourceTransitionPending']
            and len(rows)==view['sourceRevision'] and all(row[2]==0 for row in rows)
            and all(state['activeAttempt'] is None and state['installed'] is None
                    and state['ownerReported'] is None for state in view['states'].values())
            and (len(rows)==3 or rows[3][0]['kind']==sources.BOOTSTRAP_MIGRATION),
            'SOURCE_BOOTSTRAP_STATE_CHANGED')
    return bootstrap_source_prefix(view,store)


def bootstrap_source_prefix(view,store):
    # Also used to read back the exact first paired begin after ACK loss.
    # This never relaxes bootstrap_prefix's pre-product accounting guard.
    prior=sources.bootstrap_predecessor(view['sourceOperations'])
    rows=sorted(view['sourceOperations'].values(),key=lambda row:row[1]['sourceRevision'])
    sc.need(len(rows) in (3,4) and all(row[2]==0 for row in rows)
            and (len(rows)==3 or rows[3][0]['kind']==sources.BOOTSTRAP_MIGRATION),
            'SOURCE_BOOTSTRAP_STATE_CHANGED')
    return {'instanceId':store.instance_id,'scopeDigest':sc.digest(store.scope),
            'legacyWitnessDigest':sc.digest(store.expected_legacy),
            'transitionDigest':store.transition_digest,'sourcePrefixDigest':sc.digest(rows[:3]),
            'predecessorReceipt':prior[1]}


def _pinned_bootstrap_material(root,name,pin):
    sc.hex_id(pin,64)
    raw=_owner_runtime_bytes(root/name,262144)
    sc.need(hashlib.sha256(raw).hexdigest()==pin,'SOURCE_BOOTSTRAP_EVIDENCE_PIN_CHANGED')
    value=sc.loads_strict(raw)
    sc.need(sc.canonical(value).encode()==raw,'SOURCE_BOOTSTRAP_EVIDENCE_INVALID')
    return value


def read_bootstrap_review(root, expected_review_sha256):
    review=_pinned_bootstrap_material(root,'bootstrap-review.json',expected_review_sha256)
    sc.fields(review,('schemaVersion','prefix','proposal','authorityDigest',
                      'authorityWitnessDigest','primaryRecordDigest','gatewayBackupDigest',
                      'registryBackupDigest','ownerReviewProofDigest'))
    sc.need(type(review['schemaVersion']) is int and review['schemaVersion']==1,
            'SOURCE_BOOTSTRAP_REVIEW_CHANGED')
    for k in ('authorityDigest','authorityWitnessDigest','primaryRecordDigest',
              'gatewayBackupDigest','registryBackupDigest','ownerReviewProofDigest'):
        sc.hex_id(review[k],64)
    return review


def prepare_bootstrap_review_candidate(verifier, observed, ci, *, predecessor, action_revision):
    """Offline candidate projection, before owner review. No source event or merge.

    The caller obtains fresh native typed PR/body/CI evidence and the exact
    local Git objects through the existing reviewed source workflow. The
    owner still independently verifies the current predecessor and rules.
    """
    sc.need(type(verifier) is SuccessorImpact,'SOURCE_BOOTSTRAP_REVIEW_CHANGED')
    old=predecessor['proposal']
    sc.need(observed['baseSha']==predecessor['observation']['mergeSha']==sources._BOOTSTRAP_BASE
            and observed['number']>289 and observed['catalogSha256']==old['catalogSha256']
            and verifier.profile_digest==old['profileDigest']
            and verifier.repository==old['repository'],
            'SOURCE_BOOTSTRAP_REVIEW_CHANGED')
    impact=verifier.verify(observed)
    # This field is the local pinned-validator result, not a reported
    # GitHub check. A supplied value must agree; derive once if omitted.
    impact_digest=sc.digest(impact)
    sc.need(ci.get('validatedImpactDigest') in (None,impact_digest),
            'SOURCE_BOOTSTRAP_CI_IMPACT_CHANGED')
    ci={**ci,'validatedImpactDigest':impact_digest}
    p={k:observed[k] for k in ('repository','number','baseSha','headSha','treeSha',
                              'catalogSha256','bodyDigest','impactDigest','pathsDigest')}
    p.update({k:impact[k] for k in ('profileDigest','classification','targets','dependencies')})
    p= lineage.proposal({**p,'expectedSourceRevision':3,'ciDigest':sc.digest(ci),
                         'dependencyDigest':sc.digest(impact['dependencies'])})
    from ..integrations.registry_contracts.maintenance_contract import paired_subjects
    required=list(paired_subjects(p['repository']).values())
    sc.need(p['classification']=='deployment'
            and all(any(r['subject']==subject and 'image-rebuild' in r['actions']
                        for r in p['targets']) for subject in required)
            and ci['validatedImpactDigest']==sc.digest(impact),
            'SOURCE_BOOTSTRAP_REVIEW_CHANGED')
    workflows=_same_delivery_ci(ci,predecessor['ci'],p,verifier.revision,
                                error='SOURCE_BOOTSTRAP_CI_CHANGED')
    verifier.verify_workflows(p['headSha'],workflows)
    with tempfile.TemporaryDirectory(dir=verifier.state,prefix='bootstrap-review-') as tmp:
        git=Git(Path(tmp)/'git',protocols='file')
        _verify_action_pin(git,verifier.source,p['headSha'],action_revision)
    return {'proposal':p,'ci':ci}


def verify_bootstrap_owner_review(review, raw, *, merged_at):
    # The owner controller reads the original ACL-protected record, never
    # a post-merge reconstruction. merged_at is the independently observed
    # GitHub merge timestamp retained by the owner, not a local clock proof.
    sc.need(type(raw) is bytes and 0<len(raw)<=4096
            and hashlib.sha256(raw).hexdigest()==review['ownerReviewProofDigest'],
            'SOURCE_BOOTSTRAP_OWNER_REVIEW_CHANGED')
    proof=sc.loads_strict(raw)
    sc.fields(proof,('schema','decision','reviewContentDigest','reviewedAt'))
    sc.need(proof['schema']=='fortis-registry-bootstrap-review-v1'
            and proof['decision']=='APPROVE_BOOTSTRAP_MERGE'
            and proof['reviewContentDigest']==sc.digest({k:v for k,v in review.items()
                                                        if k!='ownerReviewProofDigest'})
            and type(proof['reviewedAt']) is int and type(merged_at) is int
            and 0<proof['reviewedAt']<merged_at,
            'SOURCE_BOOTSTRAP_OWNER_REVIEW_ORDER_UNPROVEN')
    return proof


def reviewed_bootstrap_migration(root, config, *, expected_review_sha256,
                                 expected_evidence_sha256, expected_source_sha, view, store):
    """Owner-pinned pre-merge review + independently observed exact merge.

    The controller must authenticate and retain the review and evidence pins,
    actual host backup/authority records, exclusive clone and quiescence. This
    verifier checks their binding, not owner identity or permission to stop.
    No public ingress or generic historical accounting.
    """
    sc.hex_id(expected_source_sha,40)
    review=read_bootstrap_review(root,expected_review_sha256)
    evidence=_pinned_bootstrap_material(root,'bootstrap-evidence.json',expected_evidence_sha256)
    sc.fields(evidence,('reviewDigest','observation','ci','body','bundleSha256','mergedAt'))
    sc.need(type(evidence['mergedAt']) is int and evidence['mergedAt']>0,
            'SOURCE_BOOTSTRAP_OWNER_REVIEW_ORDER_UNPROVEN')
    sc.need(evidence['reviewDigest']==expected_review_sha256
            and review['prefix']==bootstrap_prefix(view,store),'SOURCE_BOOTSTRAP_REVIEW_CHANGED')
    proposal = lineage.proposal(review['proposal'])
    observed = lineage.observation(evidence['observation'],proposal)
    first, first_receipt, _ = sources.delivery_repair_predecessor(view['sourceOperations'])
    second, second_receipt, _ = sources.delivery_repair_predecessor(view['sourceOperations'],2)
    third, third_receipt, _ = sources.bootstrap_predecessor(view['sourceOperations'])
    original = _retained_source_evidence(root,'transition-evidence.json',first)
    prior = _retained_source_evidence(root,'delivery-repair-evidence.json',second)
    last = _retained_source_evidence(root,'delivery-repair-2-evidence.json',third)
    manifest = first['transition']['manifest']
    writer = config['sourceWrite']
    sc.need(prior['predecessorReceipt']==first_receipt and last['predecessorReceipt']==second_receipt
            and proposal['baseSha']==third_receipt['sourceCursor']
            and proposal['expectedSourceRevision']==3 and proposal['number']>289
            and proposal['classification']=='deployment'
            and observed['mergeSha']==expected_source_sha
            and proposal['catalogSha256']==third['proposal']['catalogSha256']
            and proposal['profileDigest']==third['proposal']['profileDigest']==config['semantic']['successorProfileDigest']
            and writer['validatorRevision']==manifest['successor']['validatorRevision']
            and review['authorityDigest']==writer['policyAuthorityDigest']==manifest['successor']['authorityDigest'],
            'SOURCE_BOOTSTRAP_RUNTIME_PINS_CHANGED')
    ci=evidence['ci']
    workflows=_same_delivery_ci(ci,original['ci'],proposal,writer['validatorRevision'],
                                error='SOURCE_BOOTSTRAP_CI_CHANGED')
    bundle=_owner_runtime_bytes(root/'bootstrap-main.bundle',MAX_BUNDLE)
    sc.need(hashlib.sha256(bundle).hexdigest()==evidence['bundleSha256'],'SOURCE_BOOTSTRAP_BUNDLE_CHANGED')
    body=evidence['body']
    sc.need(type(body) is str and 0<len(body.encode())<=20000,'SOURCE_TRANSITION_BODY_INVALID')
    impact=_verify_git(config=config,base_catalog=proposal['catalogSha256'],
        action_revision=manifest['successor']['actionRevision'],proposal=proposal,
        observation=observed,body=body,bundle=bundle,workflows=workflows)
    sc.need(ci['validatedImpactDigest']==sc.digest(impact),'SOURCE_TRANSITION_CI_IMPACT_CHANGED')
    return sources.request({'operationId':sources.bootstrap_migration_id(third_receipt['operationId'],expected_source_sha),
        'kind':sources.BOOTSTRAP_MIGRATION,'parentRequestId':None,'proposal':proposal,
        'observation':observed,'evidenceDigest':expected_evidence_sha256,
        'transition':{'schemaVersion':1,'predecessorOperationId':third_receipt['operationId'],
                      'predecessorEventDigest':third_receipt['eventDigest'],
                      'reviewDigest':expected_review_sha256}},store)


def staged_domain(journal, root, pins):
    legacy, successor = _read_release_profiles(root)
    return ReleaseDomain(journal,legacy,expected_profile_digest=pins['legacyProfileDigest'],
                         successor_profile=successor,
                         expected_successor_profile_digest=pins['successorProfileDigest'])




@contextmanager
def _corrective_snapshot_copy(journal):
    """Private scratch copy of a stable RO-mounted DB and WAL.

    A running but owner-quiescent source may be copied for staging only.
    File identities and full replay must match; this does not establish
    writer exclusion. Admission still requires the later stopped replay.
    """
    import os
    import shutil
    import stat
    from .release_event_journal import ReleaseEventJournal
    from .state_journal import _private

    source = journal.path
    _check_owner_readonly_mount(source.parent)
    journal._paths()

    def identity(path):
        st = path.lstat()
        return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
                st.st_mode, st.st_uid, st.st_gid, st.st_nlink)

    def inputs():
        paths = [source]
        for suffix in ('-wal','-shm','-journal'):
            item = Path(str(source)+suffix)
            if item.exists() or item.is_symlink():
                _private(item)
                sc.need(suffix!='-journal','SOURCE_CORRECTIVE_ROLLBACK_JOURNAL')
                paths.append(item)
        return {item:identity(item) for item in paths}

    before = inputs()
    sc.need(sum(meta[2] for meta in before.values()) <= 536870912,
            'SOURCE_CORRECTIVE_SCRATCH_LIMIT')
    with tempfile.TemporaryDirectory(prefix='registry-frozen-') as scratch:
        dest = Path(scratch)/source.name
        for path, meta in before.items():
            if path.name.endswith('-shm'):
                continue
            fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as stream:
                st = os.fstat(stream.fileno())
                sc.need((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns,
                         st.st_mode,st.st_uid,st.st_gid,st.st_nlink)==meta
                        and stat.S_ISREG(st.st_mode),'SOURCE_CORRECTIVE_FROZEN_CHANGED')
                outfd=os.open(Path(scratch)/path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(outfd,'wb') as out:
                    shutil.copyfileobj(stream,out,length=1048576)
                sc.need((Path(scratch)/path.name).stat().st_size==meta[2],
                        'SOURCE_CORRECTIVE_FROZEN_CHANGED')
        sc.need(inputs()==before,'SOURCE_CORRECTIVE_FROZEN_CHANGED')
        copy = ReleaseEventJournal(dest,instance_id=journal.instance_id,scope=journal.scope,
            expected_legacy=journal.expected_legacy,transition_digest=journal.transition_digest)
        yield copy
        sc.need(inputs()==before,'SOURCE_CORRECTIVE_FROZEN_CHANGED')


def frozen_corrective_checkpoint(journal, root, pins, *, expected_revision, expected_source_sha):
    """Replay a stopped source; the controller establishes writer exclusion."""
    with _corrective_snapshot_copy(journal) as copy:
        return corrective_checkpoint(staged_domain(copy,root,pins),
            expected_revision=expected_revision,expected_source_sha=expected_source_sha)


def frozen_paired_completion_readback(journal, root, pins, *, pair, items, actor):
    """Reuse the confined RO snapshot replay after uncertain completion.

    The controller must establish writer exclusion and authenticate the
    independently retained completion intent. No active restore, journal
    write, startup admission or publication is performed here.
    """
    _check_owner_readonly_mount(root)
    with _corrective_snapshot_copy(journal) as copy:
        return staged_domain(copy,root,pins).protected_pair_completion_readback(pair,items,actor=actor)


def stage_corrective_registry(journal, root, pins, *, target, expected_checkpoint):
    """Clone the pre-product journal onto one fresh private inactive volume.

    The caller pins the independently read original checkpoint and owns
    the exclusive host preparation lock. Original mounts are RO. No
    accounting, source approval, listener start or effect occurs here.
    """
    def checkpoint(domain, view):
        store=domain.store
        return corrective_checkpoint_view(view,instance_id=store.instance_id,scope=store.scope,
            legacy_witness=store.expected_legacy,transition_digest=store.transition_digest,
            expected_revision=2,expected_source_sha=sources._DELIVERY_288)
    return _stage_registry_snapshot(journal,root,pins,target=target,
                                    expected_checkpoint=expected_checkpoint,checkpoint=checkpoint)


def stage_bootstrap_registry(journal, root, pins, *, target, expected_prefix):
    """Use the same confined clone path, restricted to the exact #289 prefix."""
    def checkpoint(domain,view):
        sc.need(view['sourceRevision']==3,'SOURCE_BOOTSTRAP_STATE_CHANGED')
        return bootstrap_prefix(view,domain.store)
    return _stage_registry_snapshot(journal,root,pins,target=target,
                                    expected_checkpoint=expected_prefix,checkpoint=checkpoint)


def _stage_registry_snapshot(journal, root, pins, *, target, expected_checkpoint, checkpoint):
    import os
    import sqlite3
    from ..r7_registry_reader_mount import _exact_mountinfo
    from .release_event_journal import ReleaseEventJournal
    from .state_journal import _private
    target=Path(target)
    _check_owner_readonly_mount(root)
    _private(target.parent,True)
    sc.need(target.is_absolute() and target.parent.resolve()==target.parent
            and target.name==journal.path.name
            and _exact_mountinfo(Path('/proc/self/mountinfo').read_bytes(),target.parent,b'rw')
            and not os.statvfs(target.parent).f_flag & os.ST_RDONLY
            and not list(target.parent.iterdir()), 'SOURCE_CORRECTIVE_TARGET_NOT_FRESH')
    with _corrective_snapshot_copy(journal) as copy:
        domain=staged_domain(copy,root,pins)
        sc.need(checkpoint(domain,domain.snapshot())==expected_checkpoint,
                'SOURCE_CORRECTIVE_STAGE_SOURCE_CHANGED')
        fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        os.close(fd)
        # SQLite backup retains committed WAL pages, not transient SHM.
        with copy._read_only_db() as db, closing(sqlite3.connect(target)) as dst:
            db.backup(dst)
            sc.need(dst.execute('PRAGMA journal_mode=WAL').fetchone()==('wal',),
                    'SOURCE_CORRECTIVE_STAGE_WAL_REQUIRED')
        new=ReleaseEventJournal(target,instance_id=journal.instance_id,scope=journal.scope,
            expected_legacy=journal.expected_legacy,transition_digest=journal.transition_digest)
        target_domain=staged_domain(new,root,pins)
        with new._db() as db:
            result=checkpoint(target_domain,target_domain._project(db))
        sc.need(result==expected_checkpoint,'SOURCE_CORRECTIVE_STAGE_CLONE_CHANGED')
        sc.need(set(p.name for p in target.parent.iterdir())=={target.name},
                'SOURCE_CORRECTIVE_STAGE_UNCHECKPOINTED')
        for path in (target,target.parent):
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
        return result


def corrective_checkpoint(domain, *, expected_revision, expected_source_sha):
    """Read-only pre-product T4 receipt for an original or a staged Registry.

    This proves the exact source-event prefix, not Docker writer exclusion
    or authorization to switch the pair. Both remain controller obligations.
    """
    store = domain.store
    return corrective_checkpoint_view(domain.snapshot(), instance_id=store.instance_id,
        scope=store.scope, legacy_witness=store.expected_legacy,
        transition_digest=store.transition_digest, expected_revision=expected_revision,
        expected_source_sha=expected_source_sha)


def corrective_checkpoint_view(view, *, instance_id, scope, legacy_witness, transition_digest,
                               expected_revision, expected_source_sha):
    # Also consumes the independently replayed snapshot from the exact
    # retained #288 image, which predates the corrective checkpoint helper.
    sc.need(type(expected_revision) is int and expected_revision in (2, 3),
            'SOURCE_CORRECTIVE_REVISION_DENIED')
    sc.hex_id(expected_source_sha, 40)
    sc.uuid_id(instance_id)
    sc.hex_id(transition_digest, 64)
    sc.need(legacy_witness['instanceId']==instance_id
            and legacy_witness['scopeDigest']==sc.digest(scope),'SOURCE_CORRECTIVE_STATE_CHANGED')
    prior = sources.delivery_repair_predecessor(view['sourceOperations'], 2)
    rows = sorted(view['sourceOperations'].values(), key=lambda row: row[1]['sourceRevision'])
    sc.need(view['sourceRevision'] == expected_revision
            and view['snapshotRevision'] == expected_revision
            and view['sourceCursor'] == expected_source_sha
            and not view['operations'] and not view['sourceTransitionPending']
            and len(rows) == expected_revision
            and all(row[2] == 0 and not row[1]['deploymentAuthorized'] for row in rows)
            and all(state['activeAttempt'] is None and state['installed'] is None
                    and state['ownerReported'] is None for state in view['states'].values()),
            'SOURCE_CORRECTIVE_STATE_CHANGED')
    tail = rows[-1]
    sc.need(tail[0]['kind'] == sources.DELIVERY_REPAIR
            and (expected_revision == 2 or tail[0]['transition'] == {
                'predecessorOperationId': prior[1]['operationId'],
                'predecessorEventDigest': prior[1]['eventDigest']}),
            'SOURCE_CORRECTIVE_EDGE_CHANGED')
    return {'instanceId': instance_id, 'scopeDigest': sc.digest(scope),
            'legacyWitnessDigest': sc.digest(legacy_witness),
            'transitionDigest': transition_digest,
            'catalogSha256': view['catalogSha256'], 'profileDigest': view['profileDigest'],
            'sourcePrefixDigest': sc.digest(rows[:2]),
            'sourceRevision': expected_revision, 'sourceCursor': expected_source_sha,
            'eventDigest': view['eventDigest'], 'receipt': tail[1]}


def verify_corrective_pair(source, target, *, expected_source_sha):
    """Pair replayed checkpoints, never a new write or a deployment receipt."""
    sc.hex_id(expected_source_sha, 40)
    keys = ('instanceId', 'scopeDigest', 'legacyWitnessDigest', 'transitionDigest',
            'catalogSha256', 'profileDigest', 'sourcePrefixDigest')
    sc.need(source['sourceRevision'] == 2 and target['sourceRevision'] == 3
            and source['sourceCursor'] == sources._DELIVERY_288
            and source['receipt']['eventDigest'] == sources._DELIVERY_288_EVENT
            and target['sourceCursor'] == expected_source_sha
            and expected_source_sha != source['sourceCursor']
            and all(source[k] == target[k] for k in keys),
            'SOURCE_CORRECTIVE_PAIR_CHANGED')
    return {'source': source, 'target': target}


def account_on_clone(domain, db, request):
    req = sources.request(request,domain.store)
    view = domain._project(db)
    sc.need(req['kind']=='TRANSITION' and view['sourceRevision']==0 and not view['operations'],
            'SOURCE_TRANSITION_STAGED_STATE_CHANGED')
    receipt = sources.append(domain.store,db,req,view['operations'])
    domain._project(db)
    return receipt
