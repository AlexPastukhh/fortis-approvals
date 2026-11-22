"""P5 closed typed boundary, for owner-composed offline tests only.

No live authentication transport, collector persistence, Registry writer,
or anchor is installed. No caller-provided observation or actor is trusted.
Current preview can only be blocked; no authoritative receipt or queue read
is possible until the protected store and original-operation reader exist.
"""
import hashlib
import re
import uuid

from ..core import Denied, canonical, loads_strict
from ..integrations.registry.read_contract import (
    REPOSITORY, READS, MISSING, GATEWAY_TARGET, GATEWAY_READ_OPERATIONS,
    validate_gateway_read_query, validate_gateway_read_projection,
)

COLLECTOR = 'release-registry-collector-v1'
PLANNER = 'release-registry-planner-v1'
READER = 'release-registry-reader-v1'
MAX_REQUEST = 4096
MAX_EVIDENCE = 2_000_000

INGEST = 'registry.ingest_merged'
FIELDS = {**READS, INGEST: ('repository','operationId','evidenceId','evidenceDigest','expectedRevision')}
FLAGS = ('historicalPolicyVerified','historicalMergeCutoffVerified',
         'dependencyClosureVerified','componentBindingsVerified',
         'evidenceVerified','admissionAllowed','deploymentAllowed')


def _need(value, code):
    if not value:
        raise Denied(code)


def _hex(value, width):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(width)+'}',value) is not None


def _uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _bytes(value, limit, code):
    try:
        result=canonical(value).encode('utf-8')
        _need(len(result)<=limit,code)
        return result
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise Denied(code) from None


def _digest(value):
    return hashlib.sha256(_bytes(value,MAX_EVIDENCE,'REGISTRY_EVIDENCE_INVALID')).hexdigest()


def parse_request(raw):
    """Exact typed JSON; no operation authority is conveyed by parsing."""
    _need(type(raw) is bytes and 0<len(raw)<=MAX_REQUEST,'REGISTRY_REQUEST_INVALID')
    try:
        request=loads_strict(raw)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Denied('REGISTRY_REQUEST_INVALID') from None
    _need(type(request) is dict and set(request)=={'operation','params'}
          and type(request['operation']) is str
          and request['operation'] in FIELDS,'REGISTRY_OPERATION_UNSUPPORTED')
    op,p=request['operation'],request['params']
    _need(type(p) is dict and set(p)==set(FIELDS[op]),'REGISTRY_PARAMS_INVALID')
    _need(p['repository']==REPOSITORY,'REGISTRY_SCOPE_DENIED')
    # Registry source and Gateway READ are separate enforcement boundaries:
    # shared method shapes, but each validates its own untrusted ingress.
    for field in ('operationId','evidenceId'):
        if field in p:
            _need(_uuid(p[field]),'REGISTRY_PARAMS_INVALID')
    for field in ('evidenceDigest','recordId'):
        if field in p:
            _need(_hex(p[field],64),'REGISTRY_PARAMS_INVALID')
    if 'expectedRevision' in p:
        _need(type(p['expectedRevision']) is int and 0<=p['expectedRevision']<=2**63-1,
              'REGISTRY_PARAMS_INVALID')
    if op=='registry.list_records':
        _need(type(p['limit']) is int and 1<=p['limit']<=100 and
              (p['cursor'] is None or type(p['cursor']) is str and
               re.fullmatch('[A-Za-z0-9_-]{1,256}',p['cursor']) is not None),
              'REGISTRY_PARAMS_INVALID')
    return op,p


def _preview(snapshot, params):
    """Inspect only the exact current source observation, never admit it."""
    fields={'schemaVersion','issuer','repository','evidenceId','result'}
    _need(type(snapshot) is dict and type(snapshot.get('schemaVersion')) is int
          and snapshot['schemaVersion'] in (1,2),'REGISTRY_EVIDENCE_IDENTITY_MISMATCH')
    bound=snapshot['schemaVersion']==2
    if bound: fields|={'registryPolicy','registryReview'}
    _need(set(snapshot)==fields
        and snapshot['issuer']==COLLECTOR and snapshot['repository']==REPOSITORY
        and snapshot['evidenceId']==params['evidenceId'],
        'REGISTRY_EVIDENCE_IDENTITY_MISMATCH')
    _need(_digest(snapshot)==params['evidenceDigest'],'REGISTRY_EVIDENCE_DIGEST_MISMATCH')
    result=snapshot['result']
    _need(type(result) is dict and set(result)=={
        'result','observation','observationDigest','missingProofs',*FLAGS}
        and result['result']=='SELECTED_MAIN_LOCAL_SOURCE_BOUND'
        and all(result[k] is False for k in FLAGS)
        and type(result['missingProofs']) is list
        and all(type(x) is str for x in result['missingProofs']),'REGISTRY_EVIDENCE_UNSUPPORTED')
    o=result['observation']
    _need(type(o) is dict and _digest(o)==result['observationDigest']
          and o.get('repository')==REPOSITORY and _hex(o.get('selectedMainSha'),40)
          and type(o.get('number')) is int and 0<o['number']<=1_000_000
          and type(o.get('unresolvedExternalTargets')) is list
          and type(o.get('unresolvedPullRequests')) is list,
          'REGISTRY_EVIDENCE_INVALID')
    impact=o.get('retainedImpact')
    _need(type(impact) is dict and _digest(impact)==o.get('retainedImpactSha256')
          and impact.get('repository')==REPOSITORY and impact.get('number')==o['number']
          and type(impact.get('validatedImpact')) is dict
          and impact['validatedImpact'].get('classification') in ('deployment','no-deployment'),
          'REGISTRY_EVIDENCE_INVALID')
    gaps=list(MISSING)
    if bound:
        # Only a candidate consistency projection. The owning collector
        # validates the full retained policy/reference under its checkpoint.
        ref=snapshot['registryPolicy'];rr=snapshot['registryReview']
        flags={'registryReviewPolicyVerified','registryReviewCutoffVerified',
               'historicalPolicyVerified','historicalMergeCutoffVerified',
               'evidenceVerified','admissionAllowed','deploymentAllowed'}
        _need(type(ref) is dict and ref.get('repository')==REPOSITORY
              and type(rr) is dict and set(rr)=={'result','observation','observationDigest',*flags}
              and rr['result']=='REGISTRY_REVIEW_POLICY_MATCH_CANDIDATE'
              and all(rr[k] is False for k in flags),'REGISTRY_REVIEW_POLICY_UNSUPPORTED')
        r=rr['observation']
        _need(type(r) is dict and _digest(r)==rr['observationDigest']
              and r.get('repository')==REPOSITORY and r.get('selectedMainSha')==o['selectedMainSha']
              and r.get('selectedMainObservationDigest')==result['observationDigest']
              and type(r.get('policyBinding')) is dict
              and r['policyBinding'].get('policyReferenceDigest')==_digest(ref),
              'REGISTRY_REVIEW_POLICY_MISMATCH')
        gaps.append('PROTECTED_REGISTRY_REVIEW_POLICY_ACCEPTANCE')
    if o['unresolvedExternalTargets']:
        gaps.append('EXTERNAL_TARGET_DEPENDENCY_UNRESOLVED')
    if o['unresolvedPullRequests']:
        gaps.append('PR_DEPENDENCY_UNRESOLVED')
    # Even a no-deployment classification needs admitted evidence. No empty
    # records array, count, or authoritative no-deployment result is returned.
    return {'result':'BLOCKED_EVIDENCE_GAP','evidenceClass':'SOURCE_CANDIDATE_ONLY',
            'repository':REPOSITORY,
            'evidenceId':params['evidenceId'],'evidenceDigest':params['evidenceDigest'],
            'selectedMainSha':o['selectedMainSha'],'number':o['number'],
            'observedClassification':impact['validatedImpact']['classification'],
            'missingProofs':sorted(gaps),'evidenceVerified':False,
            'admissionAllowed':False,'deploymentAllowed':False}


class RegistryBoundary:
    """Offline dispatch with an injected host authenticator and source reader.

    The dependency is trusted host code, not a request selector. The reader
    may return a synthetic snapshot in tests; the issuer field and hashes are
    not authenticated provenance. No production composition exists.
    """
    def __init__(self, *, authenticator, evidence_reader=None):
        self.authenticator=authenticator
        self.evidence_reader=evidence_reader

    def _active(self, actor):
        _need(actor in (PLANNER,READER) and self.authenticator.active(actor),
              'REGISTRY_ACTOR_DENIED')

    def dispatch(self, credential, raw):
        _need(type(credential) is str and bool(credential),'REGISTRY_ACTOR_DENIED')
        try:
            actor=self.authenticator.authenticate(credential)
        except Exception:
            raise Denied('REGISTRY_ACTOR_DENIED') from None
        self._active(actor)
        op,p=parse_request(raw)
        if op==INGEST:
            # A known future schema is not a permitted WRITE.
            _need(actor==PLANNER,'REGISTRY_ACTOR_DENIED')
            raise Denied('REGISTRY_WRITE_DISABLED')
        if op=='registry.capabilities':
            return {'schemaVersion':1,'repository':REPOSITORY,
                    'activationState':'SOURCE_ONLY','liveOperations':[],
                    'candidateReadOperations':sorted(READS),
                    'writeEnabled':False,'storeAvailable':False,
                    'authenticatedCollectorAvailable':False}
        if op=='registry.preview_merged':
            _need(self.evidence_reader is not None,'REGISTRY_EVIDENCE_UNAVAILABLE')
            try:
                snapshot=self.evidence_reader(p['evidenceId'])
            except Exception:
                # Do not expose the provider/reader error or turn it into
                # an empty/no-deployment result.
                raise Denied('REGISTRY_EVIDENCE_UNAVAILABLE') from None
            _need(snapshot is not None,'REGISTRY_EVIDENCE_UNAVAILABLE')
            result=_preview(snapshot,p)
            self._active(actor)
            return result
        # No original receipt or canonical store exists. In particular a
        # lookup cannot fabricate NOT_FOUND, UNKNOWN_OUTCOME resolution or
        # an empty queue; no readback is inferred from a preview.
        raise Denied('REGISTRY_STORAGE_UNAVAILABLE')


class GatewayRegistryReadCandidate:
    """Explicit opt-in source-only adapter for the existing Repo READ Broker.

    A future trusted Gateway release must supply the source boundary and its
    pinned private reader identity, configure Core's native registry policy and
    exact actor read grants, then separately prove a real runtime. This class
    never installs itself into R7, binds a listener, or exposes Registry WRITE.
    """

    def __init__(self, *, boundary, reader_credential):
        _need(type(boundary) is RegistryBoundary
              and type(reader_credential) is str and bool(reader_credential),
              'REGISTRY_GATEWAY_BINDING_DENIED')
        try:
            principal = boundary.authenticator.authenticate(reader_credential)
        except Exception:
            raise Denied('REGISTRY_GATEWAY_BINDING_DENIED') from None
        _need(principal == READER and boundary.authenticator.active(READER),
              'REGISTRY_GATEWAY_BINDING_DENIED')
        self._boundary = boundary
        self._reader_credential = reader_credential

    def read(self, request):
        _need(type(request) is dict and request.get('service') == 'registry',
              'REGISTRY_GATEWAY_SCOPE_DENIED')
        operation = request.get('operation')
        _name, params = validate_gateway_read_query(
            operation, request.get('target'), request.get('params'))
        raw = canonical({'operation': _name, 'params': params}).encode('utf-8')
        result = self._boundary.dispatch(self._reader_credential, raw)
        return validate_gateway_read_projection(operation, result)
