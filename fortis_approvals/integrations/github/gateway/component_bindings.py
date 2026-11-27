"""P5 owner-pinned component/environment mapping candidate, not live topology.

Only host-composed readers and the existing pinned validator/object store.
No caller-selected component/environment or topology assertions are trusted
for admission, actual state, restrictions or deployment.
"""
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

from ....core import Denied, Stale, canonical, loads_strict
from ....workflow.common import Git
from ..publisher_source import materialize
from ...registry_contracts.release_profile import resolve_components as _resolved
from .forward_lineage import _baseline, observe_forward_lineage
from .collector_snapshot import REPOSITORY
from .registry_review_policy import policy_reference
from .selected_main_binding import _commit
from .review_capture import _hash, _hex, _need

_SHIM="""
import json,resource,sys
from pathlib import Path
resource.setrlimit(resource.RLIMIT_AS,(536870912,536870912))
resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576))
resource.setrlimit(resource.RLIMIT_CPU,(30,30))
code=Path(sys.argv[1]); root=Path(sys.argv[2])
sys.path.insert(0,str(code/'tools/release'))
from validate import load_data,validate_schema,validate_catalog
catalog=load_data((root/'release/targets.yaml').read_text(encoding='utf-8'),'yaml')
validate_schema(catalog,code/'docs/schemas/build-target-catalog-v1.schema.json')
validate_catalog(catalog,root,'fortis-approvals')
print(json.dumps(catalog))
"""


def _catalog(validator, sha, expected_digest):
    """Pinned shared semantic validator, raw source materialization only."""
    _need(_hex(sha,40) and _hex(expected_digest,64),'P5_COMPONENT_CATALOG_PIN_INVALID')
    with tempfile.TemporaryDirectory(dir=validator.state,prefix='p5-component-') as folder:
        work=Path(folder);git=Git(work/'git',protocols='file')
        node=_commit(git,validator.source,sha)
        _commit(git,validator.code,validator.revision)
        code,data=work/'code',work/'data'
        materialize(git,validator.code,validator.revision,code)
        materialize(git,validator.source,sha,data)
        p=data/'release/targets.yaml'
        _need(p.is_file() and 0<p.stat().st_size<=120000,'P5_COMPONENT_CATALOG_SIZE')
        raw=p.read_bytes()
        _need(hashlib.sha256(raw).hexdigest()==expected_digest,'P5_COMPONENT_CATALOG_DIGEST')
        env=dict(PATH=os.defpath,HOME=str(git.home),LANG='C.UTF-8',LC_ALL='C.UTF-8')
        with tempfile.TemporaryFile(dir=work) as out,tempfile.TemporaryFile(dir=work) as err:
            proc=subprocess.Popen([sys.executable,'-I','-B','-X','pycache_prefix='+str(work/'cache'),
                                   '-c',_SHIM,str(code),str(data)],cwd=work,env=env,
                                   stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
            try:
                proc.wait(timeout=40)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid,signal.SIGKILL);proc.wait()
                raise Denied('P5_COMPONENT_CATALOG_TIMEOUT') from None
            _need(proc.returncode==0 and 0<out.tell()<=250000,'P5_COMPONENT_CATALOG_INVALID')
            out.seek(0)
            try:
                catalog=loads_strict(out.read())
            except (ValueError,UnicodeError):
                raise Denied('P5_COMPONENT_CATALOG_INVALID') from None
        _need(type(catalog) is dict and catalog.get('repository')=='fortis-approvals'
              and catalog.get('schemaVersion')==1 and type(catalog.get('targets')) is list
              and type(catalog.get('buildUnits')) is list,'P5_COMPONENT_CATALOG_INVALID')
        return catalog,node['treeSha']


def _mapping(reader, baseline):
    try:
        ref=reader()
        _need(type(ref) is dict and set(ref)=={'schemaVersion','repository','enrollmentId',
              'baselineSha','catalogSha256','bindings','components'}
              and type(ref['schemaVersion']) is int and ref['schemaVersion']==1
              and all(ref[k]==baseline[k] for k in ('repository','enrollmentId','baselineSha','catalogSha256'))
              and len(canonical(ref).encode('utf-8'))<=250000
              and _hash(ref)==baseline['bindingDigest'],'P5_COMPONENT_BINDING_PIN_MISMATCH')
        return loads_strict(canonical(ref))
    except Denied:
        raise
    except Exception:
        raise Denied('P5_COMPONENT_BINDING_UNAVAILABLE') from None


def _observe_component_pair(*,adapter,journal,validator,baseline_reader,
                               expected_baseline_digest,selected_main_sha,evidence_ids,
                               policy_reader,expected_policy_digest,binding_reader,
                               cursor_reader=None, cutover_gap=None):
    """Compose full pinned catalog mapping with strict policy-bound lineage."""
    _need(callable(policy_reader) and _hex(expected_policy_digest,64),
          'P5_COMPONENT_POLICY_REQUIRED')
    baseline=_baseline(baseline_reader,expected_baseline_digest)
    ref_policy=policy_reference(policy_reader,expected_policy_digest)
    _need(baseline['repository']==REPOSITORY,'P5_COMPONENT_SCOPE')
    ref=_mapping(binding_reader,baseline)
    catalog,tree=_catalog(validator,selected_main_sha,baseline['catalogSha256'])
    bindings=_resolved(ref,catalog)
    lineage=observe_forward_lineage(adapter=adapter,journal=journal,validator=validator,
        baseline_reader=baseline_reader,expected_baseline_digest=expected_baseline_digest,
        selected_main_sha=selected_main_sha,evidence_ids=evidence_ids,policy_reader=policy_reader,
        expected_policy_digest=expected_policy_digest,cursor_reader=cursor_reader,
        cutover_gap=cutover_gap)
    o=lineage['observation']
    _need(o['baselineDigest']==expected_baseline_digest and o['selectedMainSha']==selected_main_sha
          and o['catalogSha256']==baseline['catalogSha256']
          and o['policyReferenceDigest']==expected_policy_digest
          and (o['merges'][-1]['treeSha'] if o['merges'] else
               o.get('startCursorTreeSha',o['baselineTreeSha']))==tree,
          'P5_COMPONENT_LINEAGE_MISMATCH')
    if (_mapping(binding_reader,baseline)!=ref or _baseline(baseline_reader,expected_baseline_digest)!=baseline
        or policy_reference(policy_reader,expected_policy_digest)!=ref_policy
        or journal.anchored_batch(evidence_ids)['checkpoint']!=o['collectorCheckpoint']):
        raise Stale('P5_COMPONENT_BINDING_CHANGED')
    branch=adapter._project_branch(adapter._api('GET',adapter._path('fortis-approvals','branches/main')))
    if branch['name']!='main' or branch['sha']!=selected_main_sha:
        raise Stale('P5_COMPONENT_MAIN_CHANGED')
    observation={'repository':REPOSITORY,'enrollmentId':baseline['enrollmentId'],
                 'baselineDigest':expected_baseline_digest,'bindingDigest':baseline['bindingDigest'],
                 'policyReferenceDigest':expected_policy_digest,'selectedMainSha':selected_main_sha,
                 'treeSha':tree,'catalogSha256':baseline['catalogSha256'],
                 'validatorRevision':validator.revision,'catalogProjectionSha256':_hash(catalog),
                 'lineageDigest':lineage['observationDigest'],
                 'collectorCheckpoint':o['collectorCheckpoint'],'bindings':bindings,
                 'components':ref['components']}
    return ({'result':'COMPONENT_ENVIRONMENT_MATCH_CANDIDATE',
            'observation':observation,'observationDigest':_hash(observation),
            'componentBindingsVerified':False,'resourceTopologyVerified':False,
            'baselineAcceptanceVerified':False,'evidenceVerified':False,
            'admissionAllowed':False,'deploymentAllowed':False},lineage,catalog,baseline)


def observe_component_bindings(**kwargs):
    return _observe_component_pair(**kwargs)[0]
