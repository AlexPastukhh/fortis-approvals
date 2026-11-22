"""One offline source-onboarding checkpoint: assess, stage, pause, verify, resume.

Never installs a provider, grants permissions, executes upstream HTTP, runs
arbitrary manual Python, or impersonates owner review. A trusted test/reviewer
must verify all manual code and artifacts before a source candidate can advance.
"""
from contextlib import contextmanager
from copy import deepcopy
import fcntl
import hashlib
import inspect as pyinspect
import os
from pathlib import Path
import re
import shutil
import tempfile
from uuid import uuid4

from ..core import Denied, canonical, loads_strict
from .model import check, ident
from . import source_generator
from .source_strategy import advise_onboarding, next_source_attempt

_STATE='checkpoint.json'
_STAGE='staged_provider'
_MANUAL=('manual.py','tests/test_manual.py')
_VERSIONED_STAGE=re.compile(r'_onboarding_draft_[0-9a-f]{32}\Z')


def _digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def _safe_dir(root):
    root=Path(root).absolute()
    check(root.is_dir() and not root.is_symlink() and root==root.resolve(),
          'ONBOARDING_DIRECTORY_INVALID')
    # Human-editable incomplete drafts must never share the image-packaged
    # provider tree. That tree is reserved for fully reviewed source packages.
    check(not any(path.name=='integrations' and
                  path.parent.name=='fortis_approvals'
                  for path in (root,*root.parents)),
          'ONBOARDING_SESSION_WITHIN_PROVIDER')
    return root


def _stage_dir(root,state):
    name=state.get('activeStage',_STAGE)
    check(type(name) is str and
          (name==_STAGE or _VERSIONED_STAGE.fullmatch(name)),
          'ONBOARDING_STAGE_REFERENCE_INVALID')
    stage=root/name
    check(stage.is_dir() and not stage.is_symlink() and stage.resolve().parent==root,
          'ONBOARDING_STAGE_MISSING')
    return stage


def stage_path(directory):
    """Current human-editable source draft path (read-only lookup)."""
    root=_safe_dir(directory)
    with _locked(root):
        state=_state(root)
        stage=_stage_dir(root,state)
        _verify_stage(stage,state)
        return stage


def _safe_file(file):
    check(file.is_file() and not file.is_symlink(), 'ONBOARDING_FILE_MISSING')
    return file.read_bytes()


def _state(root):
    try:
        data=loads_strict(_safe_file(root/_STATE).decode('utf-8'))
    except (UnicodeError,ValueError):
        raise Denied('ONBOARDING_CHECKPOINT_INVALID') from None
    check(type(data) is dict and data.get('schemaVersion')==1 and
          data.get('phase') in ('STAGING','REVIEW_REQUIRED','MANUAL_REQUIRED',
                               'SOURCE_READY','SOURCE_VERIFIED','SOURCE_PREPARED') and
          type(data.get('provider')) is str and
          type(data.get('sourceDigest')) is str and
          type(data.get('assessmentDigest')) is str and
          type(data.get('generatedHashes')) is dict and
          type(data.get('manualRequirements')) is list and
          type(data.get('expectedOperations')) is list and
          type(data.get('originalDescriptionDigest')) is str,
          'ONBOARDING_CHECKPOINT_INVALID')
    return data


def _reviewer_identity(reviewer):
    """Source-test provenance only, *not* a signed owner authorization.

    The verifier must be in a file under the current Fortis source checkout.
    A caller-controlled callback can still lie about tests; independent PR CI
    and owner code review remain authoritative for actual release.
    """
    check(callable(reviewer), 'ONBOARDING_REVIEWER_REQUIRED')
    file=pyinspect.getsourcefile(reviewer)
    check(type(file) is str and file, 'ONBOARDING_REVIEWER_SOURCE_REQUIRED')
    source=Path(file).absolute()
    root=Path(__file__).resolve().parents[2]
    check(not source.is_symlink() and source.is_file() and
          source==source.resolve() and root in source.parents,
          'ONBOARDING_REVIEWER_OUTSIDE_SOURCE')
    relative=source.relative_to(root)
    check(relative.parts[0]=='fortis_approvals' and
          relative.suffix=='.py', 'ONBOARDING_REVIEWER_OUTSIDE_SOURCE')
    content=source.read_bytes()
    check(len(content)<=4*1024*1024, 'ONBOARDING_REVIEWER_SOURCE_TOO_LARGE')
    name=getattr(reviewer,'__qualname__','')
    check(type(name) is str and 0<len(name)<=512,
          'ONBOARDING_REVIEWER_NAME_INVALID')
    return {'kind':'source-test-only','file':relative.as_posix(),
            'fileSha256':hashlib.sha256(content).hexdigest(),
            'function':name}


def _verify_review_record(state,stage_hashes):
    """Recheck snapshot and reviewer file before copying reviewed source."""
    receipt=state.get('reviewEvidence')
    check(type(receipt) is dict and
          set(receipt)=={'reviewer','stageSha256','assessmentDigest','sourceDigest',
                         'requirementsSha256','operationsSha256'},
          'ONBOARDING_REVIEW_RECORD_MISSING')
    check(receipt['assessmentDigest']==state['assessmentDigest'] and
          receipt['sourceDigest']==state['sourceDigest'] and
          receipt['stageSha256']==_digest(stage_hashes) and
          receipt['requirementsSha256']==_digest(state['manualRequirements']) and
          receipt['operationsSha256']==_digest(state['expectedOperations']),
          'ONBOARDING_REVIEW_SOURCE_MISMATCH')
    reviewer=receipt['reviewer']
    check(type(reviewer) is dict and
          set(reviewer)=={'kind','file','fileSha256','function'} and
          reviewer['kind']=='source-test-only' and
          type(reviewer['file']) is str and
          type(reviewer['fileSha256']) is str,
          'ONBOARDING_REVIEW_RECORD_INVALID')
    project=Path(__file__).resolve().parents[2]
    local=Path(reviewer['file'])
    check(not local.is_absolute() and len(local.parts)>=2 and
          local.parts[0]=='fortis_approvals' and
          all(part not in ('.','..') for part in local.parts),
          'ONBOARDING_REVIEW_RECORD_INVALID')
    file=project/local
    check(not file.is_symlink() and file.is_file() and
          file.resolve().is_relative_to(project) and
          hashlib.sha256(file.read_bytes()).hexdigest()==reviewer['fileSha256'],
          'ONBOARDING_REVIEWER_SOURCE_CHANGED')


def _save(root,data):
    payload=canonical(data).encode('utf-8')
    fd,name=tempfile.mkstemp(prefix='_onboarding_',dir=root)
    path=Path(name)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as file:
            file.write(payload);file.flush();os.fsync(file.fileno())
        os.replace(path,root/_STATE)
    finally:
        path.unlink(missing_ok=True)


@contextmanager
def _locked(root):
    # A local source-only lock, not a cross-host owner release lock.
    lock=root/'.onboarding.lock'
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)


def _stage_hashes(folder):
    result={}
    check(folder.is_dir() and not folder.is_symlink(),'ONBOARDING_STAGE_MISSING')
    for path in folder.rglob('*'):
        check(not path.is_symlink(), 'ONBOARDING_STAGE_SYMLINK_DENIED')
        if path.is_dir():continue
        check(path.is_file(),'ONBOARDING_STAGE_FILE_INVALID')
        relative=path.relative_to(folder).as_posix()
        result[relative]=hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _verify_stage(folder,checkpoint):
    actual=_stage_hashes(folder)
    generated=checkpoint['generatedHashes']
    check(all(actual.get(name)==digest for name,digest in generated.items()),
          'ONBOARDING_GENERATED_SOURCE_CHANGED')
    check(set(actual)==set(generated)|set(_MANUAL),
          'ONBOARDING_UNEXPECTED_STAGE_FILE')
    return actual


def _requirements(plan,evidence):
    """Minimal typed obligations; no ambiguous natural-language acceptance."""
    by_name={row['name']:row for row in evidence['operations']}
    tasks=[]
    for row in plan['operations']:
        name=row['operation'];facts=by_name[name]
        if row['status']=='REVIEW_REQUIRED':continue
        technique=row['selected']
        if technique in ('compiledWithTrustedCheck','prepareDescriptorThenCompile'):
            kind=facts['customization']
            if technique=='compiledWithTrustedCheck' and kind=='none':
                # A narrowly proven additive gap can be handled by a trusted
                # result hook; do not incorrectly report READY with empty hooks.
                kind='resultPostcheck'
            if kind in ('resultPostcheck','contextCheck'):
                tasks.append({'kind':kind,'method':name})
        if technique=='handwrittenOperation':
            tasks.append({'kind':'manualOperation','method':name})
        if technique=='prepareDescriptorThenCompile':
            tasks.append({'kind':'descriptor','method':name})
    if evidence['transport']=='trustedManual' and plan['status']!='REVIEW_REQUIRED':
        tasks.append({'kind':'trustedTransport','method':None})
    return tasks


def _effective_description(description,plan):
    """A handwritten fallback REPLACES the compiled operation, not duplicates it."""
    selected={item['operation']:item['selected'] for item in plan['operations']}
    effective=deepcopy(description)
    effective['methods']=[row for row in description['methods'] if
                          selected.get(row['name'])!='handwrittenOperation']
    return effective


def _pinned_plan(state,evidence,description):
    initial=advise_onboarding(evidence,description)
    check(initial['assessmentDigest']==state['assessmentDigest'] and
          _digest(description)==state['originalDescriptionDigest'],
          'ONBOARDING_EVIDENCE_CHANGED')
    expected=initial
    # Reconstruct every fallback from the verified source-only sequence, so
    # an edited JSON checkpoint cannot arbitrarily choose a weaker technique.
    for event in state['history']:
        if event['event']=='SOURCE_ONLY_FALLBACK':
            expected=next_source_attempt(expected,event['method'],event['failure'])
    check(canonical(expected)==canonical(state['plan']),
          'ONBOARDING_PLAN_TAMPERED')
    return expected


def _stage_source(stage,generated):
    for name,body in generated.items():
        file=stage/name
        file.parent.mkdir(parents=True,exist_ok=True)
        check(not file.is_symlink() and not file.is_dir(),
              'ONBOARDING_STAGE_FILE_INVALID')
        content=body.encode('utf-8')
        # Temporary bytes live next to the staged folder, not *inside* it:
        # a hard exit before replace cannot introduce an unrecognized file in
        # the active provider draft and prevent replay of a pinned STAGING.
        fd,tmp=tempfile.mkstemp(prefix='_onboarding_write_',dir=stage.parent)
        pending=Path(tmp)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'wb') as opened:
                opened.write(content)
                opened.flush();os.fsync(opened.fileno())
            os.replace(pending,file)
        finally:
            pending.unlink(missing_ok=True)


def _complete_begin(root,state,source,files):
    """Recover a partially built draft from a checkpoint pinned to exact bytes.

    STAGING is a written intent; only exact known generated artifacts may be
    completed. Existing unknown files and manual edits are never overwritten.
    """
    check(state['phase']=='STAGING' and state['activeStage']==_STAGE,
          'ONBOARDING_BEGIN_STATE_INVALID')
    check(state['provider']==source['provider'] and
          state['sourceDigest']==_digest(source) and
          state['generatedHashes']==_hashes(files),
          'ONBOARDING_BEGIN_SOURCE_CHANGED')
    stage=root/_STAGE
    check(not stage.is_symlink(),'ONBOARDING_STAGE_SYMLINK_DENIED')
    if not stage.exists():stage.mkdir(mode=0o700)
    check(stage.is_dir(),'ONBOARDING_STAGE_INVALID')
    all_files={**files,'manual.py':source_generator._MANUAL,
               'tests/test_manual.py':source_generator._MANUAL_TEST}
    existing=_stage_hashes(stage)
    check(set(existing)<=set(all_files),'ONBOARDING_BEGIN_UNEXPECTED_FILE')
    for name,body in all_files.items():
        old=existing.get(name)
        if old is not None:
            check(old==hashlib.sha256(body.encode()).hexdigest() or
                  name in _MANUAL,
                  'ONBOARDING_BEGIN_GENERATED_CHANGED')
        else:
            _stage_source(stage,{name:body})
    _verify_stage(stage,state)
    state['phase']=state.pop('pendingPhase')
    _save(root,state)
    return deepcopy(state)


def _hashes(generated):
    return {name:hashlib.sha256(body.encode('utf-8')).hexdigest()
            for name,body in generated.items()}


def begin(directory,evidence,description):
    """Create private, non-discoverable draft and immutable decision checkpoint.

    One session per empty directory. Generated source is placed under the
    session folder, NEVER in `fortis_approvals/integrations` at this stage.
    """
    root=_safe_dir(directory)
    with _locked(root):
        plan=advise_onboarding(evidence,description)
        source,files=source_generator._prepared(
            _effective_description(description,plan))
        check(source['provider']==plan['provider'], 'ONBOARDING_PROVIDER_MISMATCH')
        check(all(x['selected']!='prepareDescriptorThenCompile'
                  for x in plan['operations']), 'ONBOARDING_DESCRIPTOR_REVIEW_REQUIRED')
        if (root/_STATE).exists():
            existing=_state(root)
            check(existing['phase']=='STAGING','ONBOARDING_SESSION_EXISTS')
            _pinned_plan(existing,evidence,description)
            return _complete_begin(root,existing,source,files)
        check(not (root/_STAGE).exists(), 'ONBOARDING_SESSION_EXISTS')
        hashes=_hashes(files)
        requirements=_requirements(plan,evidence)
        expected=sorted(row['operation'] for row in plan['operations'])
        desired=('REVIEW_REQUIRED' if plan['status']=='REVIEW_REQUIRED' else
                 'MANUAL_REQUIRED' if requirements else 'SOURCE_READY')
        state={'schemaVersion':1,'provider':source['provider'],
               'activeStage':_STAGE,'phase':'STAGING','pendingPhase':desired,
               'assessmentDigest':plan['assessmentDigest'],
               'originalDescriptionDigest':_digest(description),
               'sourceDigest':_digest(source),'generatedHashes':hashes,
               'manualRequirements':requirements,'expectedOperations':expected,
               'reviewedHashes':None,'verifiedMethods':[],
               'history':[{'event':'ASSESS_AND_STAGE','phase':desired}],
               'plan':plan}
        _save(root,state)
        return _complete_begin(root,state,source,files)


def fallback(directory,evidence,description,method,failure,*,advance_again=False):
    """Downgrade only after source-only failure; repeat is idempotent by default.

    No external API call is retried. To apply *the same failure classification*
    to a newer technique, explicitly pass advance_again=True after a new test.
    """
    root=_safe_dir(directory)
    with _locked(root):
        state=_state(root)
        check(state['phase'] in ('SOURCE_READY','MANUAL_REQUIRED'),
              'ONBOARDING_FALLBACK_STATE_INVALID')
        _pinned_plan(state,evidence,description)
        original=_stage_dir(root,state)
        actual=_verify_stage(original,state)
        check(type(advance_again) is bool,'ONBOARDING_FALLBACK_FLAG_INVALID')
        if (not advance_again and
                state['history'][-1].get('event')=='SOURCE_ONLY_FALLBACK' and
                state['history'][-1].get('method')==method and
                state['history'][-1].get('failure')==failure):
            # A lost reply after the checkpoint switch must not cause a second
            # downgrade or start an unnecessary fresh handwritten handler.
            return deepcopy(state)
        next_plan=next_source_attempt(state['plan'],method,failure)
        effective=_effective_description(description,next_plan)
        source,generated=source_generator._prepared(effective)
        check(source['provider']==state['provider'],'ONBOARDING_PROVIDER_MISMATCH')
        for name in state['generatedHashes']:
            check(name in generated,'ONBOARDING_GENERATED_FILES_CHANGED')
        # Prepare a complete alternative under a private new directory. A
        # SIGKILL during copy/write leaves an unreferenced, non-discoverable
        # draft, but never corrupts the active version/checkpoint.
        name='_onboarding_draft_'+uuid4().hex
        fresh=root/name
        check(not fresh.exists() and not fresh.is_symlink(),
              'ONBOARDING_DRAFT_CONFLICT')
        shutil.copytree(original,fresh,symlinks=True)
        committed=False
        try:
            _stage_source(fresh,generated)
            proposed=deepcopy(state)
            proposed['sourceDigest']=_digest(source)
            proposed['generatedHashes']=_hashes(generated)
            proposed['plan']=next_plan
            proposed['activeStage']=name
            proposed['manualRequirements']=_requirements(next_plan,evidence)
            proposed['phase']=('REVIEW_REQUIRED' if next_plan['status']=='REVIEW_REQUIRED'
                               else 'MANUAL_REQUIRED' if proposed['manualRequirements']
                               else 'SOURCE_READY')
            proposed['history'].append({'event':'SOURCE_ONLY_FALLBACK',
                                        'method':method,'failure':failure,
                                        'phase':proposed['phase']})
            new_actual=_verify_stage(fresh,proposed)
            check(all(actual.get(rel)==new_actual.get(rel) for rel in _MANUAL),
                  'ONBOARDING_MANUAL_CHANGED_DURING_FALLBACK')
            check(_verify_stage(original,state)==actual,
                  'ONBOARDING_ACTIVE_CHANGED_DURING_FALLBACK')
            _save(root,proposed)
            committed=True
            return deepcopy(proposed)
        finally:
            # Never delete a committed stage. On hard crash, orphan folders
            # remain for explicit inspection instead of automated cleanup.
            if not committed and fresh.exists():
                shutil.rmtree(fresh)


def inspect(directory):
    """Read-only: never repairs partial stage, never executes hand-written code."""
    root=_safe_dir(directory)
    with _locked(root):
        state=_state(root)
        check(state['phase']!='STAGING','ONBOARDING_BEGIN_INCOMPLETE')
        _verify_stage(_stage_dir(root,state),state)
        return deepcopy(state)


def resume(directory,*,verified_methods=None,reviewer=None):
    """Verify a source-owned reviewer/test receipt against staged manual bytes.

    This accepts a *trusted in-process verifier* callback, NOT a Boolean in
    user-controlled JSON. The callback is required to inspect real source,
    validate method/hook/transport contracts, and run agreed negative tests.
    Returning verified method names alone is NOT owner review or a release.
    """
    root=_safe_dir(directory)
    with _locked(root):
        state=_state(root)
        check(state['phase']!='STAGING','ONBOARDING_BEGIN_INCOMPLETE')
        check(state['phase']!='REVIEW_REQUIRED', 'ONBOARDING_REVIEW_STOP')
        if state['phase'] in ('SOURCE_VERIFIED','SOURCE_PREPARED'):
            current=_verify_stage(_stage_dir(root,state),state)
            check(current==state['reviewedHashes'],
                  'ONBOARDING_REVIEWED_SOURCE_CHANGED')
            _verify_review_record(state,current)
            return deepcopy(state)
        hashes=_verify_stage(_stage_dir(root,state),state)
        required=state['manualRequirements']
        check(callable(reviewer), 'ONBOARDING_MANUAL_REVIEW_REQUIRED' if required
              else 'ONBOARDING_SOURCE_TEST_REQUIRED')
        reviewer_before=_reviewer_identity(reviewer)
        if required:
            check(callable(reviewer), 'ONBOARDING_MANUAL_REVIEW_REQUIRED')
            result=reviewer(_stage_dir(root,state),deepcopy(required))
            check(type(result) is dict and set(result)=={'passed','verified','operations'},
                  'ONBOARDING_VERIFICATION_INVALID')
            check(result['passed'] is True and type(result['verified']) is list and
                  len(result['verified'])==len(required) and
                  sorted(result['verified'],key=canonical)==sorted(required,key=canonical),
                  'ONBOARDING_MANUAL_UNVERIFIED')
            check(result['operations']==state['expectedOperations'],
                  'ONBOARDING_UNASSESSED_MANUAL_OPERATION')
        else:
            # Automated source still needs an explicit trusted source test run.
            check(callable(reviewer),'ONBOARDING_SOURCE_TEST_REQUIRED')
            result=reviewer(_stage_dir(root,state),[])
            check(type(result) is dict and
                  result=={'passed':True,'verified':[],
                           'operations':state['expectedOperations']},
                  'ONBOARDING_SOURCE_TEST_FAILED')
        check(_verify_stage(_stage_dir(root,state),state)==hashes,
              'ONBOARDING_STAGE_CHANGED_DURING_REVIEW')
        check(_reviewer_identity(reviewer)==reviewer_before,
              'ONBOARDING_REVIEWER_CHANGED_DURING_TEST')
        state['reviewEvidence']={
            'reviewer':reviewer_before,
            'stageSha256':_digest(hashes),
            'assessmentDigest':state['assessmentDigest'],
            'sourceDigest':state['sourceDigest'],
            'requirementsSha256':_digest(required),
            'operationsSha256':_digest(state['expectedOperations'])}
        state['phase']='SOURCE_VERIFIED'
        state['reviewedHashes']=hashes
        state['verifiedMethods']=[row['method'] for row in required
                                  if row['method'] is not None]
        state['history'].append({'event':'SOURCE_TESTS_ACCEPTED',
                                 'phase':'SOURCE_VERIFIED'})
        _save(root,state)
        return deepcopy(state)


def prepare_source(directory,source_root,description):
    """Explicit source preparation after verification. Still no owner release.

    The trusted staged manual files accompany the ordinary, image-packaged
    generated source; no dynamic runtime install is attempted.
    """
    root=_safe_dir(directory)
    with _locked(root):
        state=_state(root)
        check(state['phase'] in ('SOURCE_VERIFIED','SOURCE_PREPARED'),
              'ONBOARDING_NOT_VERIFIED')
        actual=_verify_stage(_stage_dir(root,state),state)
        check(actual==state['reviewedHashes'], 'ONBOARDING_REVIEWED_SOURCE_CHANGED')
        _verify_review_record(state,actual)
        effective=_effective_description(description,state['plan'])
        source,generated=source_generator._prepared(effective)
        check(state['provider']==source['provider'] and
              state['originalDescriptionDigest']==_digest(description) and
              state['sourceDigest']==_digest(source) and
              state['generatedHashes']==_hashes(generated),
              'ONBOARDING_SOURCE_BINDING_MISMATCH')
        # Normal source permissions and worktree checking remain mandatory.
        source_generator._check_task_worktree(source_root)
        manual={name:(_stage_dir(root,state)/name).read_text(encoding='utf-8')
                for name in _MANUAL}
        target=Path(source_root)/'fortis_approvals'/'integrations'/source['provider']
        if target.exists():
            # The generic generator preserves manual files on updates. Never
            # report an update as accepted if these reviewed bytes would be lost.
            check(all((target/name).is_file() and not (target/name).is_symlink() and
                      (target/name).read_text(encoding='utf-8')==body
                      for name,body in manual.items()),
                  'ONBOARDING_EXISTING_MANUAL_DIFF_REVIEW_REQUIRED')
        outcome=source_generator.source_workspace.apply(source_root,source['provider'],
                                                         generated,manual)
        if state['phase']!='SOURCE_PREPARED':
            state['phase']='SOURCE_PREPARED'
            state['history'].append({'event':'PREPARE_SOURCE',
                                     'phase':'SOURCE_PREPARED'})
            _save(root,state)
        return outcome
