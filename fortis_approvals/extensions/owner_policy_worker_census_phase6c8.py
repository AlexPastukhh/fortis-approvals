"""Phase 6C.8 offline owner-host worker inventory consistency classifier.

SOURCE ONLY: no OS discovery, network, PID introspection, deployment, policy
change or runtime selector. Supplied records are NOT authenticated evidence.
A passing comparison can NEVER authorize installation or policy activation.
"""
import re

from ..core import Denied

_DIGEST=re.compile(r'[0-9a-f]{64}\Z')
_ROLE=frozenset(('owner-http','machine-ingress','native-broker',
                 'native-worker','extension-ingress','extension-worker'))
_EXPECTED=frozenset(('schemaVersion','observedAt','maxAgeSeconds',
    'requiredRoles','expectedProcesses','sourceDigest','credentialGenerationDigest',
    'grantDigest','policyVersion','revision','database','enumerationComplete'))
_PROCESS=frozenset(('pid','startTicks','roles'))
_RECORD=frozenset(('pid','startTicks','roles','coreType','sourceDigest',
    'credentialGenerationDigest','grantDigest','policyVersion','revision',
    'database','observedAt'))
_DB=frozenset(('path','device','inode'))


def _require(condition, code):
    if not condition:
        raise Denied(code)


def _digest(value):
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _roles(value):
    return (type(value) is list and bool(value) and
            all(type(x) is str and x in _ROLE for x in value) and
            len(set(value)) == len(value) and value == sorted(value))


def _db(value):
    if type(value) is not dict or set(value) != _DB:
        return False
    path=value['path']
    return (type(path) is str and len(path)<=4096 and path.startswith('/')
        and not path.startswith('//') and
        not any(ch in path for ch in ('\0','\n','\r','\t')) and
        all(part not in ('','.','..') for part in path.split('/')[1:])
        and type(value['device']) is int and value['device']>=0
        and type(value['inode']) is int and value['inode']>0)


def _process(value):
    return (type(value) is dict and set(value)==_PROCESS
        and type(value['pid']) is int and value['pid']>0
        and type(value['startTicks']) is int and value['startTicks']>0
        and _roles(value['roles']))


def _record(value):
    return (type(value) is dict and set(value)==_RECORD
        and _process({k:value[k] for k in _PROCESS})
        and type(value['coreType']) is str and len(value['coreType'])<=100
        and all(_digest(value[k]) for k in (
            'sourceDigest','credentialGenerationDigest','grantDigest'))
        and type(value['policyVersion']) is str
        and 0<len(value['policyVersion'])<=256
        and type(value['revision']) is int and value['revision']>=0
        and type(value['observedAt']) is int and value['observedAt']>=0
        and _db(value['database']))


def assess_owner_worker_census(expected, observations):
    """Compare one CLOSED owner-supplied expected layout to claimed samples.

    *Never* returns canDeploy=True, even for a consistent declaration.
    Only an independent trusted owner-host collector can attest completeness,
    installed image/credentials, mount identity and absence of old processes.
    """
    _require(type(expected) is dict and set(expected)==_EXPECTED,
             'OWNER_WORKER_CENSUS_EXPECTED_SCHEMA')
    _require(type(expected['schemaVersion']) is int and
             expected['schemaVersion']==1,
             'OWNER_WORKER_CENSUS_VERSION')
    _require(type(expected['observedAt']) is int and
             expected['observedAt']>=0 and
             type(expected['maxAgeSeconds']) is int and
             0<expected['maxAgeSeconds']<=60,
             'OWNER_WORKER_CENSUS_CLOCK')
    _require(_roles(expected['requiredRoles']) and
             {'owner-http','machine-ingress'} <= set(expected['requiredRoles']),
             'OWNER_WORKER_CENSUS_ROLES')
    _require(type(expected['expectedProcesses']) is list and
             0<len(expected['expectedProcesses'])<=128 and
             all(_process(x) for x in expected['expectedProcesses']),
             'OWNER_WORKER_CENSUS_PROCESS_SCHEMA')
    processes=expected['expectedProcesses']
    pids=[x['pid'] for x in processes]
    roles=[role for x in processes for role in x['roles']]
    # Multiple independent replicas may legitimately serve the same role;
    # every role must be covered, but the process identities must be unique.
    _require(len(set(pids))==len(pids) and
             set(roles)==set(expected['requiredRoles']),
             'OWNER_WORKER_CENSUS_PROCESS_COVERAGE')
    _require(all(_digest(expected[k]) for k in (
        'sourceDigest','credentialGenerationDigest','grantDigest')),
        'OWNER_WORKER_CENSUS_DIGEST')
    _require(type(expected['policyVersion']) is str and
             0<len(expected['policyVersion'])<=256 and
             type(expected['revision']) is int and expected['revision']>=0 and
             expected['policyVersion'].endswith(
                 '|owner-local-deny:'+str(expected['revision'])) and
             _db(expected['database']) and
             type(expected['enumerationComplete']) is bool,
             'OWNER_WORKER_CENSUS_BASELINE')
    _require(type(observations) is list and len(observations)<=128 and
             all(_record(x) for x in observations),
             'OWNER_WORKER_CENSUS_OBSERVATIONS_SCHEMA')
    _require(len(set(x['pid'] for x in observations))==len(observations),
             'OWNER_WORKER_CENSUS_DUPLICATE_PID')

    found={x['pid']:x for x in observations}
    declared={x['pid']:x for x in processes}
    blockers=[]
    if not expected['enumerationComplete']:
        blockers.append('EXTERNAL_ENUMERATION_NOT_CONFIRMED')
    if set(found)!=set(declared):
        blockers.append('PROCESS_SET_MISMATCH')
    for pid,item in sorted(found.items()):
        wanted=declared.get(pid)
        if wanted is None:
            blockers.append('UNKNOWN_RUNNING_PROCESS')
            continue
        if (item['startTicks']!=wanted['startTicks'] or
                item['roles']!=wanted['roles']):
            blockers.append('PROCESS_IDENTITY_OR_ROLE_MISMATCH')
        if item['coreType']!='LocalDenyCore':
            blockers.append('UNGUARDED_CORE_DETECTED')
        if (item['database']!=expected['database']):
            blockers.append('SQLITE_STATE_IDENTITY_MISMATCH')
        if item['sourceDigest']!=expected['sourceDigest']:
            blockers.append('INSTALLED_SOURCE_MISMATCH')
        if item['credentialGenerationDigest']!=expected['credentialGenerationDigest']:
            blockers.append('CREDENTIAL_GENERATION_MISMATCH')
        if item['grantDigest']!=expected['grantDigest']:
            blockers.append('ACTOR_GRANTS_MISMATCH')
        if (item['policyVersion']!=expected['policyVersion'] or
                item['revision']!=expected['revision']):
            blockers.append('POLICY_REVISION_MISMATCH')
        if not (expected['observedAt']-expected['maxAgeSeconds']
                <= item['observedAt'] <= expected['observedAt']):
            blockers.append('STALE_OR_FUTURE_PROCESS_SAMPLE')
    if set(declared)-set(found):
        blockers.append('MISSING_EXPECTED_PROCESS')
    blockers=sorted(set(blockers))
    return {'kind':'OWNER_WORKER_CENSUS_OFFLINE_COMPARISON_V1',
            'consistentDeclaredSamples':not blockers,
            'blockers':blockers,'observedProcesses':len(observations),
            'expectedProcesses':len(processes),'ownerHostAttested':False,
            'processEnumerationIndependentlyVerified':False,
            'rollbackProtected':False,'runtimeIntegrated':False,
            'canDeploy':False,'canApplyPolicy':False}
