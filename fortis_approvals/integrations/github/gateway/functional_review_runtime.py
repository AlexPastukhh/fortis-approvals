"""Functional V1 Gateway-side original review and retention.

Trusted composition only. Use existing Core ASK, original GitHub adapter and
existing journals. No caller-supplied evidence, owner proof, Git credentials,
path, actor, policy or Registry plan. No live writer or deployment permission.
A local checkpoint pin in the protected Gateway domain is not an independent
monotonic witness; the owner must separately accept V1 enrollment and storage.
"""
import os
from pathlib import Path
import stat
import threading
from contextlib import contextmanager
import uuid

from ....core import Denied, Stale, canonical, loads_strict
from ....incidents import IncidentCore
from .adapter import GitHubAdapter
from .collector_snapshot import CollectorSnapshotStore, REPOSITORY
from .registry_review_policy import RegistryPolicyReviewAdapter, policy_reference
from .retained_impact import RetainedImpactValidator
from .review_attestation import ACTOR, BUNDLE_OPERATION, SERVICE, read_bound_owner_decision, review_policy
from .review_capture import ReviewCaptureStore, _hash, _hex, _need, _private, _uuid

PILOT = 'fortis-approvals'


class LocalPin:
    """Existing private file, changed by one trusted Gateway writer only.

    This is deliberately a separate retained reference, NOT a read of the
    journal's current head and NOT protected against joint rollback. A lost
    commit/ACK or pin mismatch stops; never recreate the pin from the DB.
    """
    def __init__(self, path, *, instance_id=None):
        self.path = Path(path)
        self.instance_id = instance_id
        _need(self.path.is_absolute() and self.path.parent.resolve() == self.path.parent,
              'P5_RUNTIME_PIN_PATH')
        _private(self.path.parent, directory=True)
        self.assert_clear()
        self.read()

    def assert_clear(self):
        pending = self.path.with_name(self.path.name+'.next')
        _need(not pending.exists() and not pending.is_symlink(), 'P5_RUNTIME_PIN_OUTCOME_UNKNOWN')

    def read(self):
        self.assert_clear()
        return self._read()

    def _read(self):
        try:
            _need(self.path.parent.resolve() == self.path.parent, 'P5_RUNTIME_PIN_PATH')
            _private(self.path.parent, directory=True)
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, 'rb') as f:
                st = os.fstat(f.fileno())
                _need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid()
                      and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1
                      and 0 < st.st_size <= 1024, 'P5_RUNTIME_PIN_FILE')
                raw = f.read(1025)
                _need(len(raw) == st.st_size, 'P5_RUNTIME_PIN_FILE')
            value = loads_strict(raw)
            fields = {'revision','eventDigest'}
            if self.instance_id is not None:
                fields |= {'schemaVersion','instanceId'}
            _need(type(value) is dict and set(value) == fields
                  and type(value['revision']) is int and 0 <= value['revision'] <= 128
                  and _hex(value['eventDigest'],64) and canonical(value).encode() == raw
                  and (self.instance_id is None or type(value['schemaVersion']) is int
                       and value['schemaVersion'] == 1 and value['instanceId'] == self.instance_id),
                  'P5_RUNTIME_PIN_INVALID')
            return value
        except (OSError, ValueError, TypeError, KeyError):
            raise Denied('P5_RUNTIME_PIN_UNAVAILABLE') from None

    def advance(self, before, after):
        # All callers run under one runtime lock in the admitted Gateway.
        self.assert_clear()
        _need(self.read() == before and after['revision'] == before['revision'] + 1
              and after['revision'] <= 128
              and _hex(after['eventDigest'],64)
              and {k:v for k,v in after.items() if k not in ('revision','eventDigest')}
                  == {k:v for k,v in before.items() if k not in ('revision','eventDigest')},
              'P5_RUNTIME_PIN_CHANGED')
        temp = self.path.with_name(self.path.name+'.next')
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        # Retain a partial .next on any failure; do not silently recover.
        with os.fdopen(fd, 'wb') as f:
            f.write(canonical(after).encode()); f.flush(); os.fsync(f.fileno())
        _need(self._read() == before, 'P5_RUNTIME_PIN_CHANGED')
        os.replace(temp,self.path)
        fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
        _need(self.read() == after, 'P5_RUNTIME_PIN_READBACK')


class FunctionalReviewRuntime:
    """Bind actual existing protected Gateway objects, not a fixture DTO.

    Source composition requires pre-provisioned private journals and matching
    retained pins. No implicit init/reset, new grant or owner approval. The
    caller must have independently bound ACTOR to an internal-only identity.
    """
    def __init__(self, *, core, provider, capture, capture_pin, collector,
                 collector_pin, validator, owner, policy_reader, policy_digest):
        _need(isinstance(core,IncidentCore) and isinstance(provider,GitHubAdapter) and provider.owner+'/'+provider._repo(PILOT)==REPOSITORY
              and type(capture) is ReviewCaptureStore and type(collector) is CollectorSnapshotStore
              and type(capture_pin) is LocalPin and type(collector_pin) is LocalPin
              and capture_pin.instance_id is None and collector_pin.instance_id==collector.instance_id
              and collector.anchor_reader==collector_pin.read
              and getattr(collector.anchor_reader,'__self__',None) is collector_pin
              and type(validator) is RetainedImpactValidator and type(owner) is str and bool(owner)
              and core.auth.active(ACTOR), 'P5_RUNTIME_COMPOSITION_REQUIRED')
        self.core,self.provider,self.capture,self.collector,self.validator=core,provider,capture,collector,validator
        self.capture_pin,self.collector_pin=capture_pin,collector_pin
        self.owner,self.policy_reader,self.policy_digest=owner,policy_reader,policy_digest
        self.lock=threading.RLock()
        self.planner=None
        self.native_backend=None
        self.policy=policy_reference(policy_reader,policy_digest)
        self.capture.checkpoint(expected=self.capture_pin.read())
        _need(self.collector.anchored_batch([])['checkpoint']==self.collector_pin.read(),
              'P5_RUNTIME_COLLECTOR_PIN_MISMATCH')
        self.adapter=RegistryPolicyReviewAdapter(store=capture,provider=provider,
                    checkpoint_reader=capture_pin.read,policy_reader=policy_reader,
                    expected_policy_digest=policy_digest)

    def install(self, portal):
        _need(portal.core is self.core and portal.auth is self.core.owner_verifier
              and SERVICE not in self.core.adapters
              and not any(SERVICE in k for k in self.core.policies)
              and getattr(portal,'_registry_review_runtime',None) is None,
              'P5_RUNTIME_ALREADY_BOUND')
        # Internal-only actor; no broker/extension operation or machine grant
        # is added here. Existing owner Portal performs the real WebAuthn.
        self.core.adapters[SERVICE]=self.adapter
        self.core.policies[(ACTOR,SERVICE,BUNDLE_OPERATION,PILOT)]=review_policy
        portal.strong_operations |= {(SERVICE,BUNDLE_OPERATION)}
        portal._registry_review_runtime=self

    def _policy(self):
        _need(policy_reference(self.policy_reader,self.policy_digest)==self.policy,
              'P5_RUNTIME_POLICY_CHANGED')

    def _original(self, request_id):
        try: return self.core._read(request_id)
        except Denied as e:
            if str(e) != 'REQUEST_NOT_AVAILABLE': raise
            return None

    def _bound(self, row, number=None, head=None):
        p=row['request']; args=p['params']
        _need(row['actor']==ACTOR and p['service']==SERVICE and p['operation']==BUNDLE_OPERATION
              and p['target']==PILOT and row['requestId']==p['requestId']
              and (number is None or args['number']==number and args['headSha']==head),
              'P5_RUNTIME_ORIGINAL_REQUEST_CONFLICT')
        return {'requestId':row['requestId'],'state':row['state'],
                'number':args['number'],'headSha':args['headSha'],
                'captureOperationId':args['captureOperationId'],
                'bundleDigest':args['bundleDigest'],'mergeAuthorized':False,
                'admissionAllowed':False,'deploymentAllowed':False}

    def _main(self):
        repo=self.provider._repo(PILOT)
        branch=self.provider._project_branch(self.provider._api('GET',self.provider._path(repo,'branches/main')))
        _need(branch['name']=='main' and _hex(branch['sha'],40),'P5_RUNTIME_MAIN_UNAVAILABLE')
        return branch['sha']

    def prepare_review(self, *, request_id, number, expected_head_sha):
        """Retain exact open PR and create a real PENDING Core ASK once.

        The caller is an authenticated owner session, NOT a supplied approval.
        Owner still reviews the PENDING request using existing strong WebAuthn.
        After a crash, original request/capture is read, never recaptured.
        """
        _need(_uuid(request_id) and type(number) is int and 0<number<=1_000_000
              and _hex(expected_head_sha,40),'P5_RUNTIME_REVIEW_INPUT')
        with self.lock:
            self._policy()
            self.capture_pin.assert_clear(); self.collector_pin.assert_clear()
            old=self._original(request_id)
            if old is not None: return self._bound(old,number,expected_head_sha)
            cp=self.capture_pin.read();self.capture.checkpoint(expected=cp)
            # No concurrent outstanding reviews; no new capture can invalidate
            # the previous approval before its post-merge evidence is retained.
            with self.core._db() as db:
                rows=db.execute('SELECT id FROM requests WHERE actor=? ORDER BY created_at,id',(ACTOR,)).fetchall()
            for (rid,) in rows:
                row=self.core._read(rid); self._bound(row)
                state=row['state']
                _need(state not in ('PENDING','APPROVED','DISPATCHED','UNCERTAIN'),
                      'P5_RUNTIME_REVIEW_IN_FLIGHT')
                if state=='EXECUTED':
                    retained=self.collector.receipt(str(uuid.uuid5(uuid.UUID(rid),'p5-functional-collector-v1')))
                    if self.planner is not None:
                        self.planner.require_consumed(retained)
            capture_id=str(uuid.uuid5(uuid.UUID(request_id),'p5-functional-capture-v1'))
            receipt=self.capture.operation(capture_id)
            if receipt is not None:
                _need(cp['revision']==len(rows)+1 and receipt['number']==number and receipt['headSha']==expected_head_sha
                      and receipt['revision']==cp['revision'] and receipt['eventDigest']==cp['eventDigest'],
                      'P5_RUNTIME_CAPTURE_REPLAY_MISMATCH')
            else:
                _need(cp['revision']==len(rows) and cp['revision']<128, 'P5_RUNTIME_UNRESOLVED_CAPTURE_OR_LIMIT')
                pr=self.provider._release_impact_pr_evidence(PILOT,number,expected_head_sha)
                current_main=self._main()
                _need(pr['baseSha']==current_main,'P5_RUNTIME_PR_BASE_CHANGED')
                if self.planner is not None:
                    self.planner.check_capture_base(current_main)
                receipt=self.capture.capture_bundle(self.provider,operation_id=capture_id,
                    expected_revision=cp['revision'],number=number,expected_head_sha=expected_head_sha,
                    expected_base_sha=pr['baseSha'],expected_body_sha256=pr['bodySha256'],policy_bound=True)
                fresh={'revision':receipt['revision'],'eventDigest':receipt['eventDigest']}
                self.capture.checkpoint(expected=fresh); self.capture_pin.advance(cp,fresh);cp=fresh
            _need(receipt['result']=='PRE_MERGE_BUNDLE_RETAINED' and _hex(receipt['bundleDigest'],64),
                  'P5_RUNTIME_CAPTURE_UNBOUND')
            self._policy()
            payload={'requestId':request_id,'service':SERVICE,
                'operation':BUNDLE_OPERATION,'target':PILOT,'expectedVersion':cp['revision'],
                'params':{'captureOperationId':capture_id,'captureEventDigest':receipt['eventDigest'],
                    'headSha':expected_head_sha,'bodySha256':receipt['bodySha256'],'number':number,
                    'checkpointDigest':cp['eventDigest'],'bundleDigest':receipt['bundleDigest']},
                'reason':'Owner review of exact retained Registry pre-merge bundle; no merge or deployment'}
            _need(self.core._policy(ACTOR,payload)=='ASK','P5_RUNTIME_REVIEW_ASK_REQUIRED')
            row=self.core.submit(ACTOR,payload)
            _need(row['state']=='PENDING','P5_RUNTIME_REVIEW_NOT_PENDING')
            return self._bound(row,number,expected_head_sha)

    def retain_merge(self, *, request_id):
        """Retain post-merge evidence from the ORIGINAL Core decision only.

        Owner does not supply a merge SHA, plan, evidence bytes, or proof.
        Select the actual remote main, validate exact merge, persist evidence,
        and advance the separately retained *local* collector reference.
        No Registry DB write or accepted enrollment follows from this result.
        """
        _need(_uuid(request_id),'P5_RUNTIME_RETAIN_INPUT')
        with self.lock:
            self._policy()
            self.capture_pin.assert_clear(); self.collector_pin.assert_clear()
            row=self.core._read(request_id); self._bound(row)
            _need(row['state']=='EXECUTED','P5_RUNTIME_REVIEW_NOT_EXECUTED')
            decision=read_bound_owner_decision(self.core,request_id,owner=self.owner)
            _need(decision['result']=='OWNER_BUNDLE_DECISION_BOUND','P5_RUNTIME_REVIEW_NOT_BOUND')
            eid=str(uuid.uuid5(uuid.UUID(request_id),'p5-functional-collector-v1'))
            cp=self.collector_pin.read()
            batch=self.collector.anchored_batch([])
            _need(batch['checkpoint']==cp,'P5_RUNTIME_COLLECTOR_PIN_MISMATCH')
            # Exact original replay: lookup first; no re-read of mutable PR.
            try: old=self.collector.receipt(eid)
            except Denied as e:
                if str(e)!='P5_SNAPSHOT_NOT_FOUND':raise
                old=None
            if old is not None:
                _need(old['ownerRequestId']==request_id,'P5_RUNTIME_RETAIN_REPLAY_MISMATCH')
                return old
            merge=self._main()
            if self.native_backend is not None:
                _refresh_private_objects(self.native_backend,self.validator,merge)
            result=self.collector.retain(evidence_id=eid,expected_revision=cp['revision'],
                owner_request_id=request_id,selected_main_sha=merge,adapter=self.provider,
                store=self.capture,core=self.core,checkpoint_reader=self.capture_pin.read,
                owner=self.owner,validator=self.validator,policy_reader=self.policy_reader,
                expected_policy_digest=self.policy_digest)
            _need(result['result']=='LOCAL_EVIDENCE_PENDING_ANCHOR'
                  and result['previousCheckpoint']==cp and result['ownerRequestId']==request_id,
                  'P5_RUNTIME_RETAIN_RECEIPT')
            self.collector_pin.advance(cp,result['checkpoint'])
            final=self.collector.receipt(eid)
            _need(final['evidenceDigest']==result['evidenceDigest'] and final['ownerRequestId']==request_id,
                  'P5_RUNTIME_RETAIN_READBACK')
            return final


class FunctionalRegistryPlanner:
    """One exact retained merge -> reviewed Core ASK -> private Registry CAS.

    Keep the reader's original Core extension adapter; no Repo WRITE grant.
    The authenticated internal planner sends derived evidence, not client DTOs.
    The existing local candidate receipt is never labeled installed/admitted.
    """
    service = 'registry'
    operation = 'ingest_merged'

    def __init__(self, *, review, writer, baseline, binding, cutover_gap=None):
        from ...registry.candidate_gateway import GatewayRegistryUnixPlanner, PinnedRegistryCursor
        from ...registry.read_contract import PLANNER_ACTOR
        from .forward_lineage import _baseline
        from .component_bindings import _mapping
        _need(type(review) is FunctionalReviewRuntime and
              type(writer) is GatewayRegistryUnixPlanner and
              review.core.auth.active(PLANNER_ACTOR), 'P5_PLANNER_COMPOSITION_REQUIRED')
        self.review, self.writer, self.core = review, writer, review.core
        self._baseline_raw = canonical(baseline)
        self._binding_raw = canonical(binding)
        self.baseline_digest = _hash(baseline)
        ref = _baseline(self.baseline, self.baseline_digest)
        _need(all(ref[k]==review.policy[k] for k in (
            'repository','enrollmentId','baselineSha','acceptanceReceiptDigest')),
            'P5_PLANNER_BASELINE_POLICY_MISMATCH')
        _mapping(self.binding,ref)
        scope = {k:ref[k] for k in (
            'repository','enrollmentId','baselineSha','catalogSha256','bindingDigest')}
        scope.update(baselineDigest=self.baseline_digest,policyReferenceDigest=review.policy_digest)
        self.cursor= PinnedRegistryCursor(writer.reader,scope)
        self._cutover_gap = None if cutover_gap is None else canonical(cutover_gap)
        self.actor=PLANNER_ACTOR
        self.delegate=None

    def baseline(self):
        return loads_strict(self._baseline_raw)

    def binding(self):
        return loads_strict(self._binding_raw)

    def install(self, portal):
        _need(portal.core is self.core and portal.auth is self.core.owner_verifier
              and getattr(portal,'_registry_review_runtime',None) is self.review
              and getattr(portal,'_registry_planner_runtime',None) is None
              and self.service in self.core.adapters
              and not any(self.service in k and self.operation in k for k in self.core.policies),
              'P5_PLANNER_ALREADY_BOUND')
        from ....extensions.runtime import ExtensionAdapter
        self.delegate=self.core.adapters[self.service]
        _need(type(self.delegate) is ExtensionAdapter
              and self.delegate.provider.api is self.writer.reader
              and self.review.planner is None, 'P5_PLANNER_READER_BINDING')
        self.review.planner=self
        self.core.adapters[self.service]=self
        self.core.policies[(self.actor,self.service,self.operation,PILOT)]=self.inner_policy
        portal.strong_operations |= {(self.service,self.operation)}
        portal._registry_planner_runtime=self

    def check_capture_base(self, current_main):
        from tempfile import TemporaryDirectory
        from ....workflow.common import Git
        from .forward_lineage import cutover_start, verify_cutover_commits

        head = self.cursor.checkpoint()
        if head['localCheckpoint']['revision'] == 0 and self._cutover_gap is not None:
            gap = loads_strict(self._cutover_gap)
            baseline = self.baseline()
            _need(head['candidateCursor'] == baseline['baselineSha']
                  and current_main == cutover_start(gap, baseline['baselineSha'])
                  and self.review.native_backend is not None,
                  'P5_RUNTIME_CUTOVER_OR_CURSOR_MAIN_CHANGED')
            validator = self.review.validator
            _refresh_private_objects(self.review.native_backend, validator, current_main)
            with TemporaryDirectory(dir=validator.state, prefix='p5-cutover-') as folder:
                verify_cutover_commits(gap, baseline, Git(Path(folder)/'git'), validator.source)
        else:
            _need(head['candidateCursor'] == current_main,
                  'P5_RUNTIME_CUTOVER_OR_CURSOR_MAIN_CHANGED')

    def require_consumed(self, retained):
        # Serial functional pilot: don't accept another PR for review until
        # the preceding merged source has an exact executed Registry receipt.
        with self.core._db() as db:
            rows=db.execute('SELECT id FROM requests WHERE actor=? AND state=?',
                            (self.actor,'EXECUTED')).fetchall()
        for (rid,) in rows:
            row=self.core._read(rid)
            params=self._params(row['request'])
            if (params['evidenceId']==retained['evidenceId']
                    and params['evidenceDigest']==retained['evidenceDigest']):
                _need(self.receipt(rid)==row['result'], 'P5_PLANNER_PRIOR_RECEIPT_CHANGED')
                return
        raise Denied('P5_PLANNER_PRIOR_MERGE_NOT_INGESTED')

    @contextmanager
    def _prepare_lock(self):
        # Core.prepare runs with the Core DB write reservation. Review
        # submission holds the review lock before entering Core. Refuse
        # contention rather than deadlock in inverted lock order.
        if not self.review.lock.acquire(blocking=False):
            raise Stale('P5_PLANNER_REVIEW_BUSY')
        try:
            yield
        finally:
            self.review.lock.release()

    def _params(self, payload):
        from ...registry.read_contract import planner_params
        _need(payload['service']==self.service and payload['operation']==self.operation
              and payload['target']==PILOT, 'P5_PLANNER_SCOPE_DENIED')
        params=planner_params(payload['params'])
        _need(payload['requestId']==params['operationId']
              and payload['expectedVersion']==params['expectedRevision'],
              'P5_PLANNER_OPERATION_ID_DENIED')
        return params

    def inner_policy(self, actor, payload):
        if payload.get('operation')!=self.operation:
            check=getattr(self.delegate,'inner_policy',None)
            return check(actor,payload) if callable(check) else 'DENY'
        # Unified owner policy may further deny, never convert this mandatory
        # owner ASK to ALLOW. No public ingress registers this internal actor.
        try:
            self._params(payload)
            return 'ASK' if actor==self.actor and self.core.auth.active(actor) else 'DENY'
        except (Denied,KeyError,TypeError):
            return 'DENY'

    def submit(self, params):
        from ...registry.read_contract import planner_params
        params=planner_params(params)
        payload={'requestId':params['operationId'],'service':self.service,
            'operation':self.operation,'target':PILOT,'params':params,
            'expectedVersion':params['expectedRevision'],
            'reason':'Owner ASK for one retained merge into isolated Functional V1 Registry; no deployment'}
        _need(self.core._policy(self.actor,payload)=='ASK','P5_PLANNER_ASK_REQUIRED')
        row=self.core.submit(self.actor,payload)
        return {'requestId':row['requestId'],'state':row['state'],
                'deploymentAllowed':False,'admissionAllowed':False}

    def prepare(self, payload):
        if payload.get('operation')!=self.operation:
            return self.delegate.prepare(payload)
        from . import admission_plan
        from ...registry.read_contract import PLANNER_FRAME_LIMIT
        params=self._params(payload)
        with self._prepare_lock():
            self.review._policy()
            head=self.cursor.checkpoint()
            if head['localCheckpoint']['revision']!=params['expectedRevision']:
                raise Stale('P5_PLANNER_REVISION_CHANGED')
            cp=self.review.collector_pin.read()
            original=self.review.collector.receipt(params['evidenceId'])
            _need(original['evidenceDigest']==params['evidenceDigest']
                  and original['policyReferenceDigest']==self.review.policy_digest
                  and original['checkpoint']==cp,
                  'P5_PLANNER_ORIGINAL_EVIDENCE_CHANGED')
            decision=read_bound_owner_decision(self.core,original['ownerRequestId'],owner=self.review.owner)
            _need(decision['result']=='OWNER_BUNDLE_DECISION_BOUND',
                  'P5_PLANNER_ORIGINAL_OWNER_REQUIRED')
            kwargs=dict(adapter=self.review.provider,journal=self.review.collector,
                validator=self.review.validator,baseline_reader=self.baseline,
                expected_baseline_digest=self.baseline_digest,policy_reader=self.review.policy_reader,
                expected_policy_digest=self.review.policy_digest,binding_reader=self.binding,
                selected_main_sha=original['selectedMainSha'],evidence_ids=[params['evidenceId']])
            if params['expectedRevision']==0:
                _need(head['candidateCursor']==self.baseline()['baselineSha'],
                      'P5_PLANNER_GENESIS_CURSOR')
                gap = None if self._cutover_gap is None else loads_strict(self._cutover_gap)
                plan=admission_plan.observe_initial_plan(cutover_gap=gap, **kwargs)
            else:
                plan=admission_plan.observe_suffix_plan(cursor_reader=self.cursor.checkpoint,**kwargs)
            evidence={'schemaVersion':1,'issuer':'release-registry-collector-v1',
                'repository':REPOSITORY,'evidenceId':params['evidenceId'],'plan':plan}
            _need(len(canonical(evidence).encode())<=PLANNER_FRAME_LIMIT-4096
                  and self.cursor.checkpoint()==head
                  and self.review.collector_pin.read()==cp
                  and self.review.collector.receipt(params['evidenceId'])==original,
                  'P5_PLANNER_PREVIEW_CHANGED')
            return {'purpose':'FUNCTIONAL_V1_LOCAL_CANDIDATE_INGEST',
                    'before':head,'collectorCheckpoint':cp,'evidence':evidence,
                    'deploymentAllowed':False,'admissionAllowed':False}

    def apply(self, payload):
        if payload.get('operation')!=self.operation:
            return self.delegate.apply(payload)
        params=self._params(payload)
        with self.review.lock:
            row=self.core._read(payload['requestId'])
            _need(row['request']==payload and row['actor']==self.actor
                  and row['state']=='DISPATCHED' and row['decision']=='approve'
                  and row['owner']==self.review.owner,'P5_PLANNER_CORE_DISPATCH_REQUIRED')
            preview=row['preview']
            # Core already recomputed the complete preview before dispatch.
            # Recheck only mutable edges, never recompute or substitute a plan
            # AFTER owner approval. The Registry independently checks CAS.
            self.review._policy()
            if (self.cursor.checkpoint()!=preview['before']
                    or self.review.collector_pin.read()!=preview['collectorCheckpoint']
                    or self.review._main()!=preview['evidence']['plan']['observation']['selectedMainSha']):
                raise Stale('P5_PLANNER_DISPATCH_STALE')
            return self.writer.ingest(params,preview['evidence'])

    def confirm(self, request_id, result):
        row=self.core._read(request_id)
        if row['request'].get('operation')!=self.operation:
            return self.delegate.confirm(request_id,result)
        return self.receipt(request_id)==result and result is not None

    def receipt(self, request_id):
        row=self.core._read(request_id)
        if row['request'].get('operation')!=self.operation:
            return self.delegate.receipt(request_id)
        _need(row['actor']==self.actor and row['decision']=='approve'
              and row['owner']==self.review.owner, 'P5_PLANNER_CORE_RECEIPT_REQUIRED')
        return self.writer.lookup(self._params(row['request']),row['preview']['evidence'])


_CUTOVER_254_CONFIG_SHA256 = '581381a958f9d2736810c657524582497eea71db13fa478971e136d8c822059b'
_CUTOVER_259_CONFIG_SHA256 = '41d27088b48ab14887ab99602f6d86dd3ebcaf7e8e4d30b9c5b409cf6f337bb4'
_CUTOVER_262_CONFIG_SHA256 = 'c907b51c43397e14b44a9bed29d72dde99cf30e7ceaa39eed3cdc97f2ddd0d8e'
_CUTOVER_265_CONFIG_SHA256 = '31aedf27462df2bcae21a993216ccc2b1283bd34ff4b3e6829f156d7a0d2cb70'


def _reviewed_functional_predecessor_digests(value):
    """Reconstruct the exact retained functional policy epochs for this successor."""
    from .forward_lineage import (
        _POST_255_GAP, _POST_260_GAP_SIZE, _POST_261_GAP_SIZE, _POST_263_GAP_SIZE, _POST_264_GAP_SIZE,
        _POST_266_GAP_SIZE, _POST_267_GAP_SIZE,
    )
    recovery = value.get('cutoverRecovery')
    if recovery is None or recovery['gap']['disposition'] != _POST_255_GAP:
        return ()

    merges = recovery['gap']['merges']
    digests = []
    if len(merges) in (_POST_266_GAP_SIZE, _POST_267_GAP_SIZE):
        previous = {**value, 'cutoverRecovery': {
            'gap': {'disposition': _POST_255_GAP, 'merges': merges[:_POST_264_GAP_SIZE]},
            'release': {
                'releaseNonce': '8afe6cf9-acc6-4c24-897a-dcde0143e2ff',
                'validatorRevision': value['validatorRevision'],
                'registryImageId': 'sha256:2c48c667215c85086a7fb1358b7be3d816e56ee6f4bcb0a4e3cc85ee5dc10081',
                'gatewayImageId': 'sha256:6334d9d1c75b3dff7d42c9dfef3cf730227e2ad9bf3399caa817dd00b5ad2af6',
                'gatewaySourceDigest': 'e5d23744bcdb5028d8872aaaae6dc267873a7ddf6406a5e2e40032a80a1c268e',
            },
        }}
        digest = _hash(previous)
        _need(digest == _CUTOVER_265_CONFIG_SHA256, 'P5_CUTOVER_POLICY_PREDECESSOR_NOT_REVIEWED')
        if len(merges) == _POST_267_GAP_SIZE:
            # The promoted #265 retry resealed the same config with its exact new nonce.
            previous['cutoverRecovery']['release']['releaseNonce'] = '2471add6-079b-42ae-9e1d-a22adf821a0d'
            digest = _hash(previous)
        digests.append(digest)
    if len(merges) in (_POST_263_GAP_SIZE, _POST_264_GAP_SIZE, _POST_266_GAP_SIZE, _POST_267_GAP_SIZE):
        previous = {**value, 'cutoverRecovery': {
            'gap': {'disposition': _POST_255_GAP, 'merges': merges[:_POST_261_GAP_SIZE]},
            'release': {
                'releaseNonce': '370079a2-d23e-4c55-a97f-cd8cdf305600',
                'validatorRevision': value['validatorRevision'],
                'registryImageId': 'sha256:a535c91943341e8ae04705c458012e3e4c03226efd513efda86cfea644a7992b',
                'gatewayImageId': 'sha256:07450e0f5c362290d3fecce5f5d7cdb7abc5295dbb828f22f6e4321168068966',
                'gatewaySourceDigest': 'c71eebc342f3e4cd45f1cdd502d0c0854088af66c0a0a5fa988fc76ff6182bb4',
            },
        }}
        digest = _hash(previous)
        _need(digest == _CUTOVER_262_CONFIG_SHA256, 'P5_CUTOVER_POLICY_PREDECESSOR_NOT_REVIEWED')
        digests.append(digest)
    if len(merges) in (_POST_260_GAP_SIZE, _POST_261_GAP_SIZE, _POST_263_GAP_SIZE,
                       _POST_264_GAP_SIZE, _POST_266_GAP_SIZE, _POST_267_GAP_SIZE):
        previous = {**value, 'cutoverRecovery': {
            'gap': {'disposition': _POST_255_GAP, 'merges': merges[:7]},
            'release': {
                'releaseNonce': '92836269-9f83-47c4-aa0c-c352249f5fa8',
                'validatorRevision': value['validatorRevision'],
                'registryImageId': 'sha256:32794e660626d4d173861d019261d202aabf5fdcbf092ecd489715d711b73ada',
                'gatewayImageId': 'sha256:ecf412817a0595e66aea867c0f6744a7313b0b33a81f14bfcf590e735f9cf72e',
                'gatewaySourceDigest': 'fe607625bd79e2ad45fbb7065e2fef2da45d077af6ce8c085325aac988e4ab57',
            },
        }}
        digest = _hash(previous)
        _need(digest == _CUTOVER_259_CONFIG_SHA256, 'P5_CUTOVER_POLICY_PREDECESSOR_NOT_REVIEWED')
        digests.append(digest)

    previous = {**value, 'cutoverRecovery': {
        'gap': {
            'disposition': 'OWNER_REVIEWED_PRE_CAPTURE_GAP',
            'merges': recovery['gap']['merges'][:2],
        },
        'release': {
            'releaseNonce': 'e43f890f-fe66-4139-b397-4bb20be82e80',
            'validatorRevision': value['validatorRevision'],
            'registryImageId': 'sha256:6d41a635d71392a2397df7f470a1b0b0a8a779943a0c21e0185faf9885589060',
            'gatewayImageId': 'sha256:22de6d321559c70d3e7c788dc1e77a77cde7dea078cdd7c67cbe59aa93930963',
            'gatewaySourceDigest': 'ece8ada947e53301fa3cc6d9bd6b645bbc02c6b122de851e7780a07bd3b66b61',
        },
    }}
    digest = _hash(previous)
    _need(digest == _CUTOVER_254_CONFIG_SHA256, 'P5_CUTOVER_POLICY_PREDECESSOR_NOT_REVIEWED')
    return (*digests,digest)


class FunctionalRegistryConfiguration:
    """Owner-sealed configuration for the explicit local-candidate mode.

    Not enrollment approval. No path, key or topology can be selected by an
    HTTP caller. The release controller pins the outer immutable profile.
    """
    def __init__(self, value, key, *, scope_digest):
        from .forward_lineage import _baseline, cutover_start
        from .component_bindings import _mapping
        fields={'schemaVersion','collectorInstanceId','baseline','binding','policyReference','validatorRevision'}
        if type(value) is dict and value.get('schemaVersion')==2:
            fields |= {'boundaryDecision','bootstrapReceipt'}
            if 'cutoverRecovery' in value:
                fields.add('cutoverRecovery')
        _need(type(value) is dict and set(value)==fields
              and type(value['schemaVersion']) is int and value['schemaVersion'] in (1,2)
              and _uuid(value['collectorInstanceId']) and _hex(value['validatorRevision'],40)
              and type(key) is bytes and len(key)==32, 'P5_FUNCTIONAL_CONFIG_INVALID')
        baseline=_baseline(lambda:value['baseline'],_hash(value['baseline']))
        policy=policy_reference(lambda:value['policyReference'],_hash(value['policyReference']))
        _mapping(lambda:value['binding'],baseline)
        _need(all(baseline[k]==policy[k] for k in (
            'repository','enrollmentId','baselineSha','acceptanceReceiptDigest')),
            'P5_FUNCTIONAL_CONFIG_SCOPE')
        scope={k:baseline[k] for k in (
            'repository','enrollmentId','baselineSha','catalogSha256','bindingDigest')}
        scope.update(baselineDigest=_hash(baseline),policyReferenceDigest=_hash(policy))
        _need(_hash(scope)==scope_digest,'P5_FUNCTIONAL_CONFIG_SCOPE')
        if value['schemaVersion']==2:
            decision=value['boundaryDecision'];receipt=value['bootstrapReceipt']
            _need(type(decision) is dict and set(decision)=={'schemaVersion','decision',
                'approvedAt','proposalDigest','enrollmentAccepted','admissionAllowed','activationRequired',
                'instanceId','enrollmentId','baselineSha','catalogSha256','bindingDigest','cutover'}
                and decision['schemaVersion']==1
                and decision['decision']=='OWNER_FUNCTIONAL_V1_BOUNDARY_APPROVED'
                and _uuid(decision['instanceId']) and _hex(decision['proposalDigest'],64)
                and decision['activationRequired'] is True
                and decision['enrollmentAccepted'] is False and decision['admissionAllowed'] is False
                and _hash(decision)==baseline['acceptanceReceiptDigest']
                and all(decision[k]==baseline[k] for k in ('enrollmentId','baselineSha','catalogSha256','bindingDigest'))
                and decision['approvedAt']==policy['effectiveAt'],
                'P5_FUNCTIONAL_BOUNDARY_DECISION_REQUIRED')
            cutover=decision['cutover']
            _need(type(cutover) is dict and set(cutover)=={
                'releaseNonce','validatorRevision','registryImageId','gatewayImageId','gatewaySourceDigest'}
                and _uuid(cutover['releaseNonce']) and uuid.UUID(cutover['releaseNonce']).version==4
                and cutover['validatorRevision']==value['validatorRevision']
                and _hex(cutover['gatewaySourceDigest'],64)
                and all(type(cutover[k]) is str and cutover[k].startswith('sha256:') and
                        _hex(cutover[k][7:],64) for k in ('registryImageId','gatewayImageId')),
                'P5_FUNCTIONAL_CUTOVER_PLAN_INVALID')
            _need(type(receipt) is dict and set(receipt)=={'result','instanceId','scopeDigest',
                'specSha256','sourceSha','backupId','fileDigests','hostAccepted','enrollmentAccepted',
                'admissionAllowed','registryServiceStarted','rollbackProtected'}
                and receipt['result']=='PILOT_SCHEMA3_GENESIS_BACKUP_RESTORE_PASS'
                and receipt['instanceId']==decision['instanceId'] and receipt['scopeDigest']==scope_digest
                and receipt['sourceSha']==baseline['baselineSha'] and _uuid(receipt['backupId'])
                and _hex(receipt['specSha256'],64)
                and type(receipt['fileDigests']) is dict and set(receipt['fileDigests'])=={'sqlite','manifest','config'}
                and all(_hex(v,64) for v in receipt['fileDigests'].values())
                and all(receipt[k] is False for k in ('hostAccepted','enrollmentAccepted','admissionAllowed','registryServiceStarted','rollbackProtected')),
                'P5_FUNCTIONAL_BOOTSTRAP_RECEIPT_REQUIRED')

        if 'cutoverRecovery' in value:
            recovery = value['cutoverRecovery']
            _need(type(recovery) is dict and set(recovery) == {'gap', 'release'},
                  'P5_CUTOVER_RECOVERY_CONFIG')
            cutover_start(recovery['gap'], baseline['baselineSha'])
            release = recovery['release']
            _need(type(release) is dict and set(release) == set(cutover)
                  and release['validatorRevision'] == value['validatorRevision']
                  and _uuid(release['releaseNonce'])
                  and uuid.UUID(release['releaseNonce']).version == 4
                  and release['releaseNonce'] != cutover['releaseNonce']
                  and _hex(release['gatewaySourceDigest'], 64)
                  and all(type(release[k]) is str and release[k].startswith('sha256:')
                          and _hex(release[k][7:], 64) and release[k] != cutover[k]
                          for k in ('registryImageId', 'gatewayImageId')),
                  'P5_CUTOVER_RECOVERY_RELEASE')
        self._raw=canonical(value)
        self._key=key
        self.digest=_hash(value)

    @property
    def value(self):
        return loads_strict(self._raw)

    def reviewed_authority_predecessor_digests(self):
        return _reviewed_functional_predecessor_digests(self.value)

    def install(self, *, core, portal, reader, native, root):
        from ....workflow.adapters import NativeGitHubAdapter
        from ....workflow.git_backend import GitHubGitBackend
        from ...registry.candidate_gateway import GatewayRegistryUnixPlanner
        value=self.value
        _need(value['schemaVersion']==2 and value['boundaryDecision']['instanceId']==reader._instance,
              'P5_FUNCTIONAL_FINAL_CUTOVER_REQUIRED')
        provider=native['adapter']
        _need(type(provider) is NativeGitHubAdapter and
              type(provider.backend) is GitHubGitBackend and provider.observation_core is core,
              'P5_FUNCTIONAL_NATIVE_REQUIRED')
        # Startup opens only the previously owner-provisioned private state.
        state=Path(root)/'registry-functional-v1'
        _private(state,directory=True)
        capture=ReviewCaptureStore(state/'capture.sqlite')
        capture_pin=LocalPin(state/'capture.json')
        cid=value['collectorInstanceId']
        collector_pin=LocalPin(state/'collector.json',instance_id=cid)
        collector=CollectorSnapshotStore(state/'collector.sqlite',instance_id=cid,
                                         anchor_reader=collector_pin.read)
        validator=RetainedImpactValidator(validator_repository=state/'validator.git',
            validator_revision=value['validatorRevision'],source_repository=state/'source.git',
            state_root=state)
        review=FunctionalReviewRuntime(core=core,provider=provider,capture=capture,
            capture_pin=capture_pin,collector=collector,collector_pin=collector_pin,
            validator=validator,owner=portal.auth.owner,
            policy_reader=lambda:self.value['policyReference'],
            policy_digest=_hash(value['policyReference']))
        review.native_backend=provider.backend
        review.install(portal)
        planner=FunctionalRegistryPlanner(review=review,
            writer=GatewayRegistryUnixPlanner(reader,self._key),
            baseline=value['baseline'],binding=value['binding'],
            cutover_gap=value.get('cutoverRecovery', {}).get('gap'))
        planner.install(portal)


def initialize_functional_state(root, collector_instance):
    """Explicit owner-only fresh state initialization, never invoked on startup."""
    from ....workflow.common import Git
    from .collector_snapshot import genesis
    _need(_uuid(collector_instance),'P5_FUNCTIONAL_COLLECTOR_ID')
    parent=Path(root)
    _need(parent.is_absolute() and parent.resolve()==parent,'P5_FUNCTIONAL_STATE_PATH')
    _private(parent,directory=True)
    state=parent/'registry-functional-v1'
    state.mkdir(mode=0o700,exist_ok=False)
    def put(name,value):
        fd=os.open(state/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical(value).encode());stream.flush();os.fsync(stream.fileno())
    capture=ReviewCaptureStore.initialize(state/'capture.sqlite')
    put('capture.json',capture.checkpoint())
    put('collector.json',genesis(collector_instance))
    cp=LocalPin(state/'collector.json',instance_id=collector_instance)
    CollectorSnapshotStore.initialize(state/'collector.sqlite',instance_id=collector_instance,
                                     anchor_reader=cp.read)
    git=Git(state/'git-initialize')
    for name in ('source.git','validator.git'):
        git.run(['init','--bare','--template=',state/name])
        (state/name).chmod(0o700)
    fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return {'result':'P5_FUNCTIONAL_LOCAL_COLLECTOR_GENESIS','collectorInstanceId':collector_instance,
            'enrollmentAccepted':False,'admissionAllowed':False,'deploymentAllowed':False}


def prepare_staged_functional_state(reader, root):
    """Only UC-GW-005's exclusive, freshly cloned candidate state.

    The exact owner-sealed reader profile decides whether initialization is
    allowed. The old running state and previous release are never mounted RW.
    For a later release retain the original journals, don't recreate genesis.
    """
    from ...registry.candidate_gateway import GatewayRegistryUnixCandidateRead
    _need(type(reader) is GatewayRegistryUnixCandidateRead,'P5_FUNCTIONAL_READER_REQUIRED')
    root=Path(root)
    _private(root,directory=True)
    state=root/'registry-functional-v1'
    cfg=getattr(reader,'_functional_config',None)
    if cfg is None:
        _need(not state.exists() and not state.is_symlink(),'P5_FUNCTIONAL_DOWNGRADE_DENIED')
        return {'result':'P5_FUNCTIONAL_STATE_NOT_SELECTED'}
    _need(type(cfg) is FunctionalRegistryConfiguration and cfg.value['schemaVersion']==2
          and cfg.value['boundaryDecision']['instanceId']==reader._instance,
          'P5_FUNCTIONAL_FINAL_CUTOVER_REQUIRED')
    cid=cfg.value['collectorInstanceId']
    if not state.exists() and not state.is_symlink():
        value = cfg.value
        cutover = (value['cutoverRecovery']['release'] if 'cutoverRecovery' in value
                   else value['boundaryDecision']['cutover'])
        _need(getattr(reader,'_release_nonce',None)==cutover['releaseNonce']
              and getattr(reader,'_gateway_source_digest',None)==cutover['gatewaySourceDigest'],
              'P5_FUNCTIONAL_FIRST_CUTOVER_SEAL_MISMATCH')
        return initialize_functional_state(root,cid)
    _private(state,directory=True)
    capture=ReviewCaptureStore(state/'capture.sqlite')
    capture.checkpoint(expected=LocalPin(state/'capture.json').read())
    pin=LocalPin(state/'collector.json',instance_id=cid)
    collector=CollectorSnapshotStore(state/'collector.sqlite',instance_id=cid,anchor_reader=pin.read)
    _need(collector.anchored_batch([])['checkpoint']==pin.read(),'P5_RUNTIME_COLLECTOR_PIN_MISMATCH')
    for path in (state/'source.git',state/'validator.git'):
        _private(path,directory=True)
    return {'result':'P5_FUNCTIONAL_LOCAL_COLLECTOR_RETAINED','collectorInstanceId':cid,
            'enrollmentAccepted':False,'admissionAllowed':False,'deploymentAllowed':False}


def _refresh_private_objects(backend, validator, selected_main):
    """Reuse Gateway's native authenticated fixed-repo Git backend, raw Git only."""
    from ....workflow.git_backend import GitHubGitBackend
    _need(type(backend) is GitHubGitBackend and backend.owner+'/'+PILOT==REPOSITORY,
          'P5_FUNCTIONAL_GIT_BACKEND_REQUIRED')
    with backend.lock:
        for name,path,pin,exact in (
            (PILOT,validator.source,selected_main,True),
            ('fortis-container',validator.code,validator.revision,False),
        ):
            _private(path,directory=True)
            git=backend.git
            _need(git.text(['rev-parse','--is-bare-repository'],cwd=path)=='true'
                  and not (path/'shallow').exists()
                  and not (path/'objects/info/alternates').exists()
                  and not git.text(['for-each-ref','refs/replace'],cwd=path),
                  'P5_FUNCTIONAL_GIT_OBJECT_STORE')
            ref='refs/heads/verified-main'
            code,raw=git.run(['rev-parse','--verify',ref],cwd=path,ok=(0,128))
            current=raw.decode('ascii').strip() if code==0 else None
            def present():
                if current is None:return False
                if exact:return current==pin
                return git.run(['--no-replace-objects','merge-base','--is-ancestor',pin,current],
                               cwd=path,ok=(0,1,128))[0]==0
            if not present():
                with backend.credentials(name) as config:
                    backend._fetch(name,path,'main',ref,config)
                current=git.text(['rev-parse','--verify',ref],cwd=path)
            _need(present() and git.text(['--no-replace-objects','cat-file','-t',pin],
                                       cwd=path)=='commit','P5_FUNCTIONAL_GIT_PIN_MISMATCH')


if __name__=='__main__':
    # Owner may run this once in the reviewed Gateway image and exclusively
    # attached private state volume. Never a default server/startup action.
    import argparse
    parser=argparse.ArgumentParser(description='Initialize fresh owner-scoped local collector journals only')
    parser.add_argument('--initialize-collector-instance',required=True)
    args=parser.parse_args()
    _need(os.geteuid()==10001 and os.getegid()==10001,'P5_FUNCTIONAL_OWNER_RUNTIME_IDENTITY')
    print(canonical(initialize_functional_state('/state/private',args.initialize_collector_instance)))
