"""Optional owner-only incident lifecycle extension for the pinned R7 components.

The persistence-compatible Core, WebAuthn and base OwnerPortal source bytes are
immutable release guards. This module subclasses those components for new
owner-facing operations, never mutating legacy tables or machine routes.
"""
import hashlib
import json
import re

from .core import Core, Denied, ApprovalError, canonical
from .owner_auth import OwnerWebAuthn, _hash
from .owner_shell_portal import OwnerShellPortal
from .extensions.owner_inventory import owner_policy_inventory
from .extensions.owner_policy_preview import preview_policy_change


class IncidentCore(Core):
    STATES = Core.STATES | {'CLOSED_UNCONFIRMED', 'CANCELLED_BEFORE_DISPATCH'}

    def owner_incident_closure(self, request_id):
        # Owner portal only. Preserve the operator attestation and audit event,
        # not a synthetic successful remote result.
        row=self._read(request_id)
        if row['state']!='CLOSED_UNCONFIRMED':
            return None
        with self._db() as db:
            evidence=db.execute(
                "SELECT detail FROM events WHERE request_id=? AND state='CLOSED_UNCONFIRMED' "
                "ORDER BY seq DESC LIMIT 1",(request_id,)).fetchone()
            if not evidence:
                raise Denied('INCIDENT_CLOSURE_AUDIT_MISSING')
            return json.loads(evidence['detail'])

    def owner_unresolved(self, *, limit=100):
        """Owner-only inventory, separate from pending approvals and history.

        Keep the exact Core state: an UNCERTAIN operation is not proof of
        failure or success. Never expire, replay, or relabel it on read.
        """
        if type(limit) is not int or not 0 < limit <= 100:
            raise Denied('LIST_INVALID')
        states=('APPROVED','DISPATCHED','UNCERTAIN')
        with self._db() as db:
            total=db.execute(
                'SELECT COUNT(*) FROM requests WHERE state IN (?,?,?)',states
            ).fetchone()[0]
            rows=db.execute(
                'SELECT * FROM requests WHERE state IN (?,?,?) '
                'ORDER BY created_at DESC,id DESC LIMIT ?',(*states,limit)
            ).fetchall()
            return {'items':[self._view(row) for row in rows],
                    'total':total,'truncated':total>len(rows)}

    def machine_request_details(self, credential, request_id, *, event_offset=0, event_limit=100):
        """Read-only request/audit/receipt for any authenticated machine actor.

        The authenticated machine grant authorizes investigation globally.
        No decision, dispatch, claim, retry, session, or machine credential
        is exposed or performed. In particular, WorkspaceAdapter.receipt()
        is never called: it may register tasks after dispatch.
        """
        if (type(event_offset) is not int or event_offset < 0 or event_offset > 1000000 or
            type(event_limit) is not int or not 1 <= event_limit <= 100):
            raise Denied('INCIDENT_READ_PAGINATION_DENIED')
        if (type(request_id) is not str or not re.fullmatch(
                r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',request_id)):
            raise Denied('INCIDENT_READ_UUID_INVALID')
        self.auth.authenticate(credential)
        # Machine-only global read: no Core.client(status), whose actor
        # equality is still required for result/reconcile/execute/owner paths.
        row=self._read(request_id)
        with self._db() as db:
            count=db.execute('SELECT COUNT(*) FROM events WHERE request_id=?',
                             (request_id,)).fetchone()[0]
            events=[dict(seq=r['seq'],at=r['at'],state=r['state'],
                        detail=json.loads(r['detail'])) for r in db.execute(
                'SELECT seq,at,state,detail FROM events WHERE request_id=? '
                'ORDER BY seq LIMIT ? OFFSET ?', (request_id,event_limit,event_offset))]
        adapter=self.adapters.get(row['request']['service'])
        job=None
        evidence=None
        if adapter is not None:
            store=getattr(adapter,'store',None)
            if callable(getattr(store,'job',None)):
                saved=store.job(request_id)
                if saved is not None:
                    if saved['actor']!=row['actor']:
                        raise Denied('INCIDENT_WORKER_ACTOR_MISMATCH')
                    job=dict(state=saved['state'],actor=saved['actor'],
                             error=saved['error'],hasClaim=bool(saved['claim']),
                             result=json.loads(saved['result']) if saved['result'] else None)
                    # Preserve the exact legacy machine details schema for old
                    # jobs; new evidence is present only when it truly exists.
                    if saved.get('diagnostic') is not None:
                        job['diagnostic']=json.loads(saved['diagnostic'])
                    # Additive evidence: timestamps may be NULL on legacy jobs.
                    # A heartbeat is never proof of worker quiescence.
                    if saved.get('claimed_at') is not None:
                        job['claimedAt']=saved['claimed_at']
                    if saved.get('heartbeat_at') is not None:
                        job['lastHeartbeatAt']=saved['heartbeat_at']
                    if job['state']=='DONE' and type(job['result']) is dict:
                        evidence={'source':'native-worker-job','result':job['result']}
            elif row['request']['service']=='github':
                # GitHub receipt lookup is a local read; no upstream dispatch.
                receipt=adapter.receipt(request_id)
                if receipt is not None:
                    evidence={'source':'github-receipts','result':receipt}
        return {'schemaVersion':1,'request':row,'events':events,
                'eventOffset':event_offset,'eventTotal':count,
                'eventsTruncated':event_offset+len(events)<count,
                'worker':job,'receipt':evidence,
                'incidentClosure':self.owner_incident_closure(request_id)
                    if row['state']=='CLOSED_UNCONFIRMED' else None}

    def owner_close_simple(self, request_id, expected_fingerprint, owner):
        """Owner-authenticated administrative dismissal; not a result assertion.

        One click after existing WebAuthn login + CSRF. Never calls any
        adapter, never writes worker jobs/receipts, and never redispatches.
        """
        if (type(request_id) is not str or not re.fullmatch(
                r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',request_id) or
            type(expected_fingerprint) is not str or not re.fullmatch(
                r'[0-9a-f]{64}',expected_fingerprint) or
            type(owner) is not str or not owner):
            raise Denied('INCIDENT_SIMPLE_CLOSE_INPUT_INVALID')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            record=db.execute('SELECT * FROM requests WHERE id=?',(request_id,)).fetchone()
            if record is None or record['state']!='UNCERTAIN' or (
                    record['fingerprint']!=expected_fingerprint):
                raise Denied('INCIDENT_NOT_UNCERTAIN_OR_CHANGED')
            row=self._view(record)
            changed=db.execute(
                "UPDATE requests SET state='CLOSED_UNCONFIRMED' "
                "WHERE id=? AND state='UNCERTAIN' AND fingerprint=?",
                (request_id,expected_fingerprint)).rowcount
            if changed!=1:raise Denied('INCIDENT_CONCURRENT_CHANGE')
            self._event(db,request_id,'CLOSED_UNCONFIRMED',{
                'owner':owner,'closeMethod':'authenticated_owner_session',
                'originalFailure':row['failure'],
                'originalFingerprint':row['fingerprint'],
                'outcome':'UNCONFIRMED',
                'remoteEffectVerified':False,'workerStateUnchanged':True})
            return self._view(db.execute(
                'SELECT * FROM requests WHERE id=?',(request_id,)).fetchone())

    def owner_cancel_approved(self, request_id, expected_fingerprint, owner):
        """Owner-only, transactionally prevent first dispatch of an APPROVED intent.

        Core.execute() serializes its preflight and DISPATCHED marker with the
        same approvals database writer lock. This transition wins *only* before
        the durable DISPATCHED marker, and never rewrites an executed request.
        """
        if (type(request_id) is not str or not re.fullmatch(
                r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', request_id) or
            type(expected_fingerprint) is not str or not re.fullmatch(
                r'[0-9a-f]{64}', expected_fingerprint) or
            type(owner) is not str or not owner):
            raise Denied('INCIDENT_CANCEL_APPROVED_INPUT_INVALID')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            record=db.execute('SELECT * FROM requests WHERE id=?',(request_id,)).fetchone()
            if (record is None or record['state']!='APPROVED' or
                    record['fingerprint']!=expected_fingerprint):
                raise Denied('INCIDENT_NOT_APPROVED_OR_CHANGED')
            ever_dispatched=db.execute(
                "SELECT 1 FROM events WHERE request_id=? AND state='DISPATCHED' LIMIT 1",
                (request_id,)).fetchone()
            if ever_dispatched or record['result'] is not None:
                raise Denied('INCIDENT_DISPATCH_ALREADY_POSSIBLE')
            # Defense in depth against an inconsistent or partly migrated
            # worker store: do not cancel if a native job already exists.
            request=json.loads(record['payload'])
            adapter=self.adapters.get(request['service'])
            store=getattr(adapter,'store',None)
            if callable(getattr(store,'job',None)) and store.job(request_id) is not None:
                raise Denied('INCIDENT_WORKER_JOB_PRESENT')
            if request['service'] in ('github','sonar') and adapter is not None:
                if adapter.receipt(request_id) is not None:
                    raise Denied('INCIDENT_RECEIPT_PRESENT')
            changed=db.execute(
                "UPDATE requests SET state='CANCELLED_BEFORE_DISPATCH', "
                "failure='OWNER_CANCELLED_BEFORE_DISPATCH' "
                "WHERE id=? AND state='APPROVED' AND fingerprint=?",
                (request_id,expected_fingerprint)).rowcount
            if changed!=1:
                raise Denied('INCIDENT_CONCURRENT_CHANGE')
            self._event(db,request_id,'CANCELLED_BEFORE_DISPATCH',{
                'owner':owner,'cancelMethod':'authenticated_owner_session',
                'originalFingerprint':expected_fingerprint,
                'dispatchRecorded':False,'effectNotDispatchedByGateway':True,
                'workerStateUnchanged':True})
            return self._view(db.execute(
                'SELECT * FROM requests WHERE id=?',(request_id,)).fetchone())

    def owner_assess(self, request_id):
        """Passive evidence inventory, not a retry, reconciliation or provider probe.

        A durable local receipt is an automatic signal for owner reconciliation,
        but absence of a receipt never proves non-execution after DISPATCHED.
        """
        if type(request_id) is not str or not re.fullmatch(
                r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',request_id):
            raise Denied('INCIDENT_ASSESS_REQUEST_INVALID')
        with self._db() as db:
            db.execute('BEGIN')
            record=db.execute('SELECT * FROM requests WHERE id=?',(request_id,)).fetchone()
            if record is None:
                raise Denied('REQUEST_NOT_AVAILABLE')
            state=record['state']
            dispatched=bool(db.execute(
                "SELECT 1 FROM events WHERE request_id=? AND state='DISPATCHED' LIMIT 1",
                (request_id,)).fetchone())
            cancelled=bool(db.execute(
                "SELECT 1 FROM events WHERE request_id=? AND state='CANCELLED_BEFORE_DISPATCH' LIMIT 1",
                (request_id,)).fetchone())
            payload=json.loads(record['payload'])
        adapter=self.adapters.get(payload['service'])
        worker=None
        receipt=False
        evidence_unavailable=False
        # Existing job/receipt stores only: no upstream calls or provider
        # mutation, no WorkspaceAdapter.receipt (can register a task).
        try:
            if adapter is not None:
                store=getattr(adapter,'store',None)
                if callable(getattr(store,'job',None)):
                    saved=store.job(request_id)
                    if saved is not None:
                        if saved.get('actor')!=record['actor']:
                            raise Denied('INCIDENT_WORKER_ACTOR_MISMATCH')
                        worker=saved['state']
                        receipt=(worker=='DONE' and saved.get('result') is not None)
                elif payload['service'] in ('github','sonar'):
                    receipt=adapter.receipt(request_id) is not None
        except Exception:
            # Missing evidence is never a positive non-execution or receipt
            # proof; do not surface raw provider/storage exception strings.
            evidence_unavailable=True
        if evidence_unavailable:
            verdict='OUTCOME_UNCONFIRMED'
        elif state=='CANCELLED_BEFORE_DISPATCH' and cancelled and not dispatched and worker is None and not receipt:
            verdict='VERIFIED_NOT_DISPATCHED'
        elif state=='APPROVED' and not dispatched and worker is None and not receipt:
            verdict='CANCELLABLE_IF_STILL_APPROVED'
        elif state=='EXECUTED':
            verdict='CORE_EXECUTION_CONFIRMED'
        elif receipt and state in ('UNCERTAIN','DISPATCHED'):
            verdict='RECEIPT_PRESENT_RECONCILE_REQUIRED'
        elif receipt and state=='CLOSED_UNCONFIRMED':
            verdict='RECEIPT_AFTER_CLOSURE_REVIEW_REQUIRED'
        else:
            verdict='OUTCOME_UNCONFIRMED'
        return {
            'requestId':request_id,'state':state,'verdict':verdict,
            'dispatchedRecorded':dispatched,'workerState':worker,
            'receiptRecorded':receipt,'evidenceUnavailable':evidence_unavailable,
            'canCancelNow':verdict=='CANCELLABLE_IF_STILL_APPROVED',
            'freshRequestEligibleAfterPreflight':verdict=='VERIFIED_NOT_DISPATCHED',
            'readOnly':True,
            'note':'Only durable Gateway evidence; external effect unknown after dispatch without independent verification.'
        }

    @staticmethod
    def _closure_fingerprint(row, backup_volume, explanation):
        # Owner attestation of an operator-verified backup, NOT a backup
        # verification performed by the Gateway itself.
        if (type(backup_volume) is not str or not re.fullmatch(
                r'fortis-gateway-backup-[0-9a-f]{32}',backup_volume) or
            type(explanation) is not str or
                not 20 <= len(explanation.strip()) <= 1000):
            raise Denied('INCIDENT_BACKUP_ATTESTATION_REQUIRED')
        return hashlib.sha256(canonical({
            'purpose':'CLOSE_UNCONFIRMED_V1',
            'requestId':row['requestId'],
            'originalFingerprint':row['fingerprint'],
            'state':'UNCERTAIN',
            'backupVolume':backup_volume,
            'explanation':explanation,
        }).encode()).hexdigest()

    def owner_incident_fingerprint(self, request_id, backup_volume, explanation):
        row=self._read(request_id)
        if row['state']!='UNCERTAIN':
            raise Denied('INCIDENT_NOT_UNCERTAIN')
        return self._closure_fingerprint(row,backup_volume,explanation)

    def owner_close_uncertain(self, request_id, backup_volume, explanation, proof):
        """Archive a resolved *investigation*, never assert remote effect success.

        Requires a separately signed WebAuthn ceremony and operator-attested
        verified cold backup. The backup identity is recorded but cannot be
        validated against host Docker from this isolated owner process.
        """
        if (self.owner_verifier is None or type(proof) is not dict or
                set(proof)!={'session','ceremonyId','response'}):
            raise Denied('INCIDENT_WEBAUTHN_REQUIRED')
        fingerprint=self.owner_incident_fingerprint(
            request_id,backup_volume,explanation)
        # Fail closed when a durable receipt exists or a worker has not
        # conclusively reached FAILED. Never infer a failure from a timeout.
        def check_receipt(row):
            adapter=self.adapters.get(row['request']['service'])
            if adapter is None:
                raise Denied('INCIDENT_ADAPTER_UNAVAILABLE')
            receipt=adapter.receipt(request_id)
            if receipt is not None:
                raise Denied('INCIDENT_RECEIPT_AVAILABLE_RECONCILE_FIRST')
            store=getattr(adapter,'store',None)
            if callable(getattr(store,'job',None)):
                # Workspace's Store has jobs; GitHubAdapter.store is only
                # the Path to github-receipts.sqlite, with no worker queue.
                job=store.job(request_id)
                if not job or job.get('state')!='FAILED':
                    raise Denied('INCIDENT_WORKER_NOT_TERMINAL')
        prior=self._read(request_id)
        check_receipt(prior)
        owner=self.owner_verifier.verify(
            request_id,fingerprint,'close_uncertain',proof)
        if type(owner) is not str or not owner:
            raise Denied('INCIDENT_OWNER_PROOF_REQUIRED')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            record=db.execute('SELECT * FROM requests WHERE id=?',(request_id,)).fetchone()
            if record is None or record['state']!='UNCERTAIN':
                raise Denied('INCIDENT_STATE_CHANGED')
            current=self._view(record)
            if self._closure_fingerprint(current,backup_volume,explanation)!=fingerprint:
                raise Denied('INCIDENT_DETAILS_CHANGED')
            check_receipt(current)
            updated=db.execute(
                "UPDATE requests SET state='CLOSED_UNCONFIRMED' WHERE id=? AND state='UNCERTAIN'",
                (request_id,)).rowcount
            if updated!=1:
                raise Denied('INCIDENT_CONCURRENT_CHANGE')
            self._event(db,request_id,'CLOSED_UNCONFIRMED',{
                'owner':owner,
                'backupVolumeOwnerAttested':backup_volume,
                'explanation':explanation,
                'originalFailure':current['failure'],
                'proofSha256':hashlib.sha256(canonical(proof).encode()).hexdigest(),
                'remoteEffectVerified':False,
            })
            return self._view(db.execute(
                'SELECT * FROM requests WHERE id=?',(request_id,)).fetchone())



class IncidentOwnerWebAuthn(OwnerWebAuthn):
    def begin_decision(self, session, request_id, fingerprint, decision):
        if decision != 'close_uncertain':
            return super().begin_decision(session, request_id, fingerprint, decision)
        self.session(session)
        return self._begin_assertion(
            'decision', session_hash=_hash(session),
            request_id=request_id, fingerprint=fingerprint, decision=decision)


class IncidentOwnerPortal(OwnerShellPortal):
    # The historic approvals, WebAuthn, PowerShell and static routes remain
    # delegated through OwnerShellPortal -> protected OwnerPortal.
    def _owner_view(self, row):
        action = (row['request']['service'], row['request']['operation'])
        return {**row, 'requiresStrongProof': self._strong(row),
                'approvalAllowed': (action not in self.blocked_approvals and
                                    self._approval_policy_current(row)),
                'incidentClosure': self.core.owner_incident_closure(row['requestId'])
                        if row['state']=='CLOSED_UNCONFIRMED' else None}

    def __call__(self, env, start):
        method=env.get('REQUEST_METHOD')
        path=env.get('PATH_INFO','')
        get_inventory=method=='GET' and path=='/v1/owner/provider-inventory'
        post_policy_preview=method=='POST' and path=='/v1/owner/policy/preview'
        get_unresolved=method=='GET' and path=='/v1/owner/unresolved'
        post_incident=method=='POST' and path in (
            '/v1/owner/reconcile',
            '/v1/owner/incidents/close/simple',
            '/v1/owner/incidents/cancel/approved',
            '/v1/owner/incidents/assess',
            '/v1/owner/incidents/close/begin',
            '/v1/owner/incidents/close/finish')
        if not (get_inventory or post_policy_preview or get_unresolved or post_incident):
            return super().__call__(env,start)
        try:
            if (env.get('HTTP_HOST') != self.host or env.get('QUERY_STRING') or
                    any(env.get(x) for x in (
                        'HTTP_X_FORWARDED_HOST','HTTP_FORWARDED',
                        'HTTP_PROXY_AUTHORIZATION','HTTP_AUTHORIZATION'))):
                raise Denied('HOST_DENIED')
            token=self._cookie(env)
            if get_inventory:
                self.auth.session(token)
                return self._reply(start,200,owner_policy_inventory(
                    self.core,getattr(self,'_extension_runtime',None)))
            if get_unresolved:
                self.auth.session(token)
                rows=self.core.owner_unresolved()
                return self._reply(start,200,{
                    **rows,'items':[self._owner_view(x) for x in rows['items']]})
            if env.get('HTTP_ORIGIN') != self.origin:
                raise Denied('ORIGIN_DENIED')
            body=self._json(env)
            csrf=env.get('HTTP_X_FORTIS_CSRF')
            if not csrf:raise Denied('CSRF_REQUIRED')
            self.auth.session(token,csrf)
            if post_policy_preview:
                return self._reply(start,200,preview_policy_change(
                    self.core,getattr(self,'_extension_runtime',None),body))
            if self.read_only_banner and path!='/v1/owner/incidents/assess':
                raise Denied('INCIDENT_OWNER_WRITE_NOT_ENABLED')
            if path=='/v1/owner/incidents/assess' and set(body)=={'requestId'}:
                return self._reply(start,200,self.core.owner_assess(body['requestId']))
            if path=='/v1/owner/incidents/cancel/approved' and set(body)=={
                    'requestId','fingerprint'}:
                owner_session=self.auth.session(token,csrf)
                return self._reply(start,200,self._owner_view(
                    self.core.owner_cancel_approved(
                        body['requestId'],body['fingerprint'],owner_session['owner'])))
            if path=='/v1/owner/incidents/close/simple' and set(body)=={
                    'requestId','fingerprint'}:
                owner_session=self.auth.session(token,csrf)
                return self._reply(start,200,self._owner_view(
                    self.core.owner_close_simple(
                        body['requestId'],body['fingerprint'],owner_session['owner'])))
            if path=='/v1/owner/reconcile' and set(body)=={'requestId'}:
                if (type(body['requestId']) is not str or not
                        re.fullmatch(
                            r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',
                            body['requestId'])):
                    raise Denied('REQUEST_ID_INVALID')
                return self._reply(start,200,self._owner_view(
                    self.core.reconcile(body['requestId'])))
            if path=='/v1/owner/incidents/close/begin' and set(body)=={
                    'requestId','backupVolume','explanation','acknowledgeUnknown'}:
                if body['acknowledgeUnknown'] is not True:
                    raise Denied('INCIDENT_UNKNOWN_OUTCOME_ACK_REQUIRED')
                fingerprint=self.core.owner_incident_fingerprint(
                    body['requestId'],body['backupVolume'],body['explanation'])
                return self._reply(start,200,self.auth.begin_decision(
                    token,body['requestId'],fingerprint,'close_uncertain'))
            if path=='/v1/owner/incidents/close/finish' and set(body)=={
                    'requestId','backupVolume','explanation','acknowledgeUnknown',
                    'ceremonyId','response'}:
                if body['acknowledgeUnknown'] is not True:
                    raise Denied('INCIDENT_UNKNOWN_OUTCOME_ACK_REQUIRED')
                proof={'session':token,'ceremonyId':body['ceremonyId'],
                       'response':body['response']}
                return self._reply(start,200,self._owner_view(
                    self.core.owner_close_uncertain(
                        body['requestId'],body['backupVolume'],body['explanation'],proof)))
            return self._reply(start,404,{'error':'ROUTE_NOT_FOUND'})
        except Denied as exc:
            return self._reply(start,403,{'error':str(exc)})
        except (ApprovalError,ValueError,TypeError,KeyError,UnicodeError):
            return self._reply(start,400,{'error':'REQUEST_INVALID'})
        except (OSError,RuntimeError):
            return self._reply(start,500,{'error':'OUTCOME_UNCONFIRMED'})
