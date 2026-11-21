"""P5 source-only adapter for the separately pinned shared Release Impact code.

Owner-composed repository paths, Git reader and validator commit only. The
retained PR source is materialized as data and never imported or executed.
No live ingress, fetch, grant, installation or Registry write is performed.
"""
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

from ....core import Denied, canonical, loads_strict
from ....workflow.common import Git
from ..publisher_source import materialize, private_path
from ..post_merge_proof_bindings import _impact_yaml, EvidenceEnvelopeError
from .review_capture import _hex, _need, _hash
from .post_merge_reader import PILOT_REPOSITORY

# Run from a fresh raw-blob materialization of the exact reviewed code commit.
# The PR data directory is never a Python import path.
_SHIM = """
import json,resource,sys
from pathlib import Path
resource.setrlimit(resource.RLIMIT_AS,(536870912,536870912))
resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576))
resource.setrlimit(resource.RLIMIT_CPU,(30,30))
code=Path(sys.argv[1]); root=Path(sys.argv[2])
sys.path.insert(0,str(code/'tools/release'))
from validate import load_data,validate_schema,validate_catalog,validate_impact,extract_pr_impact
v=json.load(sys.stdin)
schemas=code/'docs/schemas'
catalog=load_data(v['catalog'],'yaml')
validate_schema(catalog,schemas/'build-target-catalog-v1.schema.json')
validate_catalog(catalog,root,v['repository'])
impact=load_data(extract_pr_impact(v['body']),'yaml')
validate_schema(impact,schemas/'release-impact-v1.schema.json')
result=validate_impact(impact,catalog,v['paths'])
# Do not pass unknown actions or dependency claims as validated closure.
info=impact['releaseImpact']
if any('unknown' in t['actions'] for t in info['targets']):
    raise ValueError('unresolved action')
by_id={t['id']:t for t in catalog['targets']}
dependencies=set()
for t in info['targets']:
    for dep in by_id[t['id']].get('dependsOn',[]):
        dependencies.add((dep['repository'],dep['target']))
for dep in info['dependencies']['targets']:
    dependencies.add((dep['repository'],dep['target']))
if any(r==v['repository'] and t not in by_id for r,t in dependencies):
    raise ValueError('missing local dependency')
if any(d['repository']==v['repository'] and d['number']==v['number'] for d in info['dependencies']['pullRequests']):
    raise ValueError('self PR dependency')
print(json.dumps(dict(classification=result['classification'],affectedTargets=result['affectedTargets'],
    changedFiles=result['changedFiles'],declaredTargets=info['targets'],
    pullRequestDependencies=info['dependencies']['pullRequests'],
    targetDependencies=[dict(repository=r,target=t) for r,t in sorted(dependencies)])))
"""


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _records(git, source, base, head, merge_base):
    # Verify the unique merge base and independently derive exact rename records.
    bases = git.text(['--no-replace-objects','merge-base','--all',base,head], cwd=source)
    _need(bases == merge_base, 'P5_IMPACT_MERGE_BASE_MISMATCH')
    raw = git.run(['--no-replace-objects','-c','diff.renameLimit=1000',
                   'diff','--no-ext-diff','--no-textconv','--name-status','-z','-M',
                   merge_base,head,'--'],cwd=source)[1]
    _need(len(raw) <= 200_000 and raw.endswith(b'\0'), 'P5_IMPACT_GIT_DIFF_INVALID')
    fields = raw[:-1].split(b'\0')
    rows = []
    kinds = {b'A':'added',b'M':'modified',b'D':'deleted'}
    while fields:
        status = fields.pop(0)
        rename = status.startswith(b'R') and status[1:].isdigit()
        _need((rename and len(fields)>=2) or (status in kinds and fields),
              'P5_IMPACT_GIT_DIFF_INVALID')
        try:
            old = fields.pop(0).decode('utf-8')
            path = fields.pop(0).decode('utf-8') if rename else old
        except UnicodeError:
            raise Denied('P5_IMPACT_GIT_DIFF_INVALID') from None
        rows.append({'path':path,'status':'renamed' if rename else kinds[status],
                     'previousPath':old if rename else None})
        _need(len(rows)<=299,'P5_IMPACT_GIT_DIFF_LIMIT')
    return sorted(rows,key=lambda row:row['path'])


class RetainedImpactValidator:
    """No request-supplied executable, code root, object repository or pin."""

    def __init__(self, *, validator_repository, validator_revision, source_repository, state_root):
        self.code = private_path(validator_repository)
        self.source = private_path(source_repository)
        self.state = private_path(state_root)
        _need(_hex(validator_revision,40) and self.state.is_dir()
              and self.state.stat().st_uid == os.geteuid()
              and self.state.stat().st_mode & 0o777 == 0o700,
              'P5_IMPACT_CONFIG_INVALID')
        self.revision = validator_revision

    def validate_retained(self, *, store, operation_id, checkpoint_reader):
        checkpoint = checkpoint_reader()
        retained = store.retained_material(operation_id, expected_checkpoint=checkpoint)
        receipt = store.operation(operation_id)
        _need(receipt is not None and receipt.get('result')=='PRE_MERGE_BUNDLE_RETAINED'
              and receipt.get('bundleDigest') == retained.get('bundleDigest')
              and _hash(retained['bundle']) == receipt['bundleDigest'], 'P5_IMPACT_BUNDLE_REQUIRED')
        bundle = retained['bundle']
        body = retained['body']
        request = retained['request']
        head, base = request['headSha'], request['baseSha']
        _need(_hex(head,40) and _hex(base,40) and _hex(bundle['pathCi']['paths']['mergeBaseSha'],40),
              'P5_IMPACT_PIN_MISMATCH')
        try:
            impact = _impact_yaml(body)
        except EvidenceEnvelopeError:
            raise Denied('P5_IMPACT_BODY_MISMATCH') from None
        _need(request['repository'].split('/')[-1]==PILOT_REPOSITORY
              and _sha256(body.encode('utf-8'))==request['bodySha256']
              and _sha256(impact.encode('utf-8'))==bundle['impactSha256'],
              'P5_IMPACT_BODY_MISMATCH')
        paths = bundle['pathCi']['paths']
        records = paths['records']
        impact_paths = sorted({x for r in records for x in (r['path'],r['previousPath']) if x is not None})
        _need(_hash(records)==paths['sha256'] and len(records)==paths['count']
              and impact_paths==paths['impactPaths'], 'P5_IMPACT_PATH_MISMATCH')
        with tempfile.TemporaryDirectory(dir=self.state,prefix='p5-impact-') as folder:
            work = Path(folder)
            git = Git(work/'git', protocols='file')
            for repo, rev in ((self.code,self.revision),(self.source,head),(self.source,base)):
                _need(git.text(['--no-replace-objects','rev-parse','--verify',rev+'^{commit}'],cwd=repo)==rev,
                      'P5_IMPACT_PIN_MISMATCH')
            # The repository inputs are trusted server-side object stores, not PR-supplied
            # Git dirs. Never fetch or execute a checkout, hooks, filters or attributes.
            _need(_records(git,self.source,base,head,paths['mergeBaseSha'])==records,
                  'P5_IMPACT_GIT_PATH_MISMATCH')
            code, data = work/'code', work/'data'
            materialize(git,self.code,self.revision,code)
            materialize(git,self.source,head,data)
            catalog_path = data/'release/targets.yaml'
            _need(catalog_path.is_file() and catalog_path.stat().st_size<=120_000,
                  'P5_IMPACT_CATALOG_MISMATCH')
            catalog = catalog_path.read_bytes()
            expected = bundle['catalog']
            _need(catalog==expected['text'].encode('utf-8')
                  and _sha256(catalog)==expected['sha256']
                  and hashlib.sha1(b'blob '+str(len(catalog)).encode()+b'\0'+catalog).hexdigest()==expected['gitBlobSha'],
                  'P5_IMPACT_CATALOG_MISMATCH')
            value = {'repository':PILOT_REPOSITORY,'number':request['number'],
                     'body':body,'catalog':expected['text'],'paths':impact_paths}
            raw = canonical(value).encode('utf-8')
            _need(len(raw)<=240_000, 'P5_IMPACT_INPUT_LIMIT')
            env = dict(PATH=os.defpath,HOME=str(git.home),LANG='C.UTF-8',LC_ALL='C.UTF-8')
            with tempfile.TemporaryFile(dir=work) as out, tempfile.TemporaryFile(dir=work) as err:
                p = subprocess.Popen([sys.executable,'-I','-B','-X','pycache_prefix='+str(work/'cache'),
                                      '-c',_SHIM,str(code),str(data)],cwd=work,env=env,
                                     stdin=subprocess.PIPE,stdout=out,stderr=err,start_new_session=True)
                try:
                    p.communicate(raw,timeout=40)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid,signal.SIGKILL)
                    p.wait()
                    raise Denied('P5_IMPACT_VALIDATOR_TIMEOUT') from None
                _need(p.returncode==0 and 0<out.tell()<=65536,'P5_IMPACT_VALIDATION_FAILED')
                out.seek(0)
                try:
                    result=loads_strict(out.read())
                except (ValueError, UnicodeError):
                    raise Denied('P5_IMPACT_OUTPUT_INVALID') from None
        _need(type(result) is dict and set(result)=={'classification','affectedTargets','changedFiles',
                   'declaredTargets','pullRequestDependencies','targetDependencies'}
              and result['classification'] in ('deployment','no-deployment')
              and result['changedFiles']==len(impact_paths)
              and all(type(result[k]) is list for k in ('affectedTargets','declaredTargets',
                  'pullRequestDependencies','targetDependencies')), 'P5_IMPACT_OUTPUT_INVALID')
        _need(checkpoint_reader()==checkpoint and store.checkpoint(expected=checkpoint)==checkpoint,
              'P5_IMPACT_CHECKPOINT_CHANGED')
        observation={'validatorRevision':self.revision,'captureEventDigest':receipt['eventDigest'],
                     'bundleDigest':receipt['bundleDigest'],'repository':request['repository'],
                     'number':request['number'],'headSha':head,'baseSha':base,
                     'catalogSha256':expected['sha256'],'changedPathRecordsSha256':paths['sha256'],
                     'impactSha256':bundle['impactSha256'],'validatedImpact':result}
        return {'result':'RETAINED_IMPACT_VALIDATED','observation':observation,
                'observationDigest':_hash(observation),'dependencyClosureVerified':False,
                'historicalPolicyVerified':False,'evidenceVerified':False,
                'admissionAllowed':False,'deploymentAllowed':False}
