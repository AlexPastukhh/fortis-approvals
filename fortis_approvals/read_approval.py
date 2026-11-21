"""One-use owner ASK for registered native synchronous READ methods.

No provider effect runs in the approval request. Only a subsequent matching
machine READ consumes the committed approval atomically under Core's SQLite
lock, before the actual provider GET. Lost responses are not replayed.
"""
import hashlib
import uuid

from .core import Denied, Stale, canonical, loads_strict
from .repo_action_contract import validate_read_query

_SERVICE = "read-authorization"
_OPERATION = "approve"


def _assert_spent_schema(db):
    """Never treat a pre-existing table without a one-use primary key as safe."""
    columns = tuple((row[1], row[2], row[3], row[5]) for row in
                    db.execute('PRAGMA table_info(owner_read_approval_spent)'))
    primary_keys = tuple((row[2], row[3]) for row in
                         db.execute('PRAGMA index_list(owner_read_approval_spent)')
                         if row[3] == 'pk')
    if (columns != (('request_id', 'TEXT', 0, 1),
                    ('actor', 'TEXT', 1, 0),
                    ('used_at', 'INTEGER', 1, 0)) or
            primary_keys != ((1, 'pk'),)):
        raise Denied('OWNER_READ_SPEND_SCHEMA_INVALID')


class OwnerReadApprovalAdapter:
    def __init__(self, core, broker):
        self.core, self.broker = core, broker

    def _query(self, actor, payload):
        if (type(payload) is not dict or payload.get('service') != _SERVICE or
                payload.get('operation') != _OPERATION or
                payload.get('expectedVersion') != 0 or
                type(payload.get('params')) is not dict or
                set(payload['params']) != {'actor','query'} or
                payload['params']['actor'] != actor):
            raise Denied("OWNER_READ_APPROVAL_SCOPE_DENIED")
        query = validate_read_query(payload['params']['query'])
        if (payload.get('requestId') != query['requestId'] or
                payload.get('target') != query['target'] or
                payload.get('reason') != query['reason'] or
                (query['service'],query['operation']) not in
                self.broker.actor_read_operations.get(actor,()) or
                query['service'] not in self.broker.read_adapters):
            raise Denied("OWNER_READ_APPROVAL_GRANT_DENIED")
        guard = self.broker.actor_authorizers.get(actor)
        if guard is not None:
            guard(actor,query,'read')
        return query

    def policy(self, actor, payload):
        try:
            query = self._query(actor,payload)
            if self.core._policy(actor,query) != 'ASK':
                return 'DENY'
        except (Denied,TypeError,KeyError):
            return 'DENY'
        return 'ASK'

    def prepare(self,payload):
        # Core authenticates the actor before it calls this adapter. It is
        # read again from the persisted row at the actual consume boundary.
        actor=payload['params']['actor']
        query=self._query(actor,payload)
        if self.core._policy(actor,query) != 'ASK':
            raise Denied("OWNER_READ_POLICY_CHANGED")
        return {'kind':'OWNER_READ_ONE_SHOT_V1','service':query['service'],
                'operation':query['operation'],'target':query['target'],
                'querySha256':hashlib.sha256(canonical(query).encode()).hexdigest()}

    def apply(self,payload):
        # Pure durable approval receipt: NEVER contact the external reader.
        preview=self.prepare(payload)
        row=self.core._read(payload['requestId'])
        if (row['state']!='DISPATCHED' or row['decision']!='approve'
                or type(row['owner']) is not str or not row['owner']
                or row['request']!=payload or row['preview']!=preview):
            raise Stale("OWNER_READ_PROOF_STALE")
        return {'requestId':payload['requestId'],'readApproved':True,
                'querySha256':preview['querySha256']}

    def confirm(self,request_id,result):
        return (type(result) is dict and set(result)==
                {'requestId','readApproved','querySha256'} and
                result['requestId']==request_id and result['readApproved'] is True and
                type(result['querySha256']) is str and
                len(result['querySha256'])==64)

    def receipt(self,request_id):
        row=self.core._read(request_id)
        if row['request']['service'] != _SERVICE:
            raise Denied("OWNER_READ_RECEIPT_SCOPE_DENIED")
        return {'requestId':request_id,'readApproved':True,
                'querySha256':row['preview']['querySha256']}

    def request(self, actor, query):
        return {'requestId':query['requestId'],'service':_SERVICE,
                'operation':_OPERATION,'target':query['target'],
                'params':{'actor':actor,'query':query},
                'expectedVersion':0,'reason':query['reason']}

    def begin_or_consume(self, credential, actor, query):
        with self.core._db() as db:
            _assert_spent_schema(db)
        payload=self.request(actor,query)
        row=self.core.client(credential,'submit',payload)
        if row['state'] != 'EXECUTED':
            return row['state']
        with self.core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            _assert_spent_schema(db)
            persisted=db.execute('SELECT * FROM requests WHERE id=?',
                                 (query['requestId'],)).fetchone()
            if persisted is None:
                raise Stale("OWNER_READ_APPROVAL_NOT_FOUND")
            saved=loads_strict(persisted['payload'])
            rev,overlay,legacy=self.core._snapshot(db)
            coord=(actor,query['service'],query['operation'],query['target'])
            if (persisted['state'] != 'EXECUTED' or
                    persisted['actor'] != actor or saved != payload or
                    persisted['decision'] != 'approve' or
                    type(persisted['owner']) is not str or not persisted['owner'] or
                    int(self.core.clock()) >= persisted['expires_at'] or
                    persisted['policy_version'] != self.core._version(rev) or
                    self.core.authority.decision(coord,overlay,legacy) != 'ASK'):
                raise Stale("OWNER_READ_APPROVAL_STALE")
            result=loads_strict(persisted['result'])
            if (type(result) is not dict or
                    result.get('querySha256') != hashlib.sha256(
                        canonical(query).encode()).hexdigest() or
                    not self.confirm(query['requestId'],result)):
                raise Stale("OWNER_READ_APPROVAL_RECEIPT_CHANGED")
            try:
                db.execute("INSERT INTO owner_read_approval_spent VALUES(?,?,?)",
                    (query['requestId'],actor,int(self.core.clock())))
            except Exception as exc:
                # A repeated requestId cannot read again on the previous
                # authorization. This is not a retryable Core effect.
                import sqlite3
                if isinstance(exc,sqlite3.IntegrityError):
                    raise Denied("OWNER_READ_APPROVAL_ALREADY_USED") from None
                raise
        return "CONSUMED"


def install_owner_read_approval(core,broker,portal):
    if (getattr(broker,'read_approval',None) is not None or
            _SERVICE in core.adapters):
        raise Denied("OWNER_READ_ALREADY_INSTALLED")
    with core._db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS owner_read_approval_spent(
            request_id TEXT PRIMARY KEY,actor TEXT NOT NULL,used_at INTEGER NOT NULL)""")
        _assert_spent_schema(db)
    adapter=OwnerReadApprovalAdapter(core,broker)
    core.adapters[_SERVICE]=adapter
    core._owner_read_approval=adapter
    broker.read_approval=adapter
    portal.strong_operations |= {(_SERVICE,_OPERATION)}
    return adapter
