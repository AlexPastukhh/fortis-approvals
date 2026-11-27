"""Opt-in successor private Unix service using the established peer checks.

The existing Registry entrypoint loads reviewed profiles. The host must
independently seal keys, socket ACL, generation, grants, sole writer,
maintenance and recovery. No legacy planner operation is accepted.
"""
from contextlib import contextmanager, nullcontext
import fcntl
import os
import re
from ..core import Denied
from ..integrations.registry_contracts import semantic_contract as sc, semantic_wire as wire
from .semantic_service import SemanticRegistry
from .local_candidate_read_service import (PrivateCandidateReadService,_absolute_path,
    _private_socket_dir,_canonical_frame,_real_peer,_TIMEOUT)


class SemanticFrameService:
    def __init__(self,service,*,frame_key,generation,authorize,provenance,internal_actor,
                 source_authorize=None,external_source_authorize=None,source_reservation=None,source_delivery=None):
        sc.need(type(service) is SemanticRegistry and type(frame_key) is bytes and len(frame_key)==32
                and callable(authorize) and callable(provenance) and type(internal_actor) is str)
        sc.hex_id(generation,64)
        self.service,self.key,self.generation=service,frame_key,generation
        self.authorize,self.provenance,self.internal_actor=authorize,provenance,internal_actor
        sc.need(source_authorize is None or callable(source_authorize))
        self.source_authorize=source_authorize
        sc.need(external_source_authorize is None or callable(external_source_authorize))
        self.external_source_authorize=external_source_authorize
        sc.need(source_reservation is None or callable(source_reservation))
        self.source_reservation = source_reservation
        sc.need(source_delivery is None or callable(source_delivery))
        self.source_delivery = source_delivery
        self.store=service.domain.store
        self.pins={'instance':self.store.instance_id,'scope':self.store.expected_legacy['scopeDigest'],
                   'generation':generation}

    def dispatch(self,frame):
        req=wire.open_request(self.key,frame,**self.pins)
        actor,act,b=req['actor'],req['action'],req['body']
        sc.need(self.authorize(actor,act,b) is True,'SEMANTIC_WIRE_SCOPE_DENIED')
        if act=='READ':
            result=self.service.read(actor,b['operation'],b['params'])
            sc.need(self.authorize(actor,act,b) is True,'SEMANTIC_WIRE_SCOPE_DENIED')
        elif act=='WRITE':
            sc.need(self.provenance(actor)==b['assertionSource'],'SEMANTIC_WIRE_PROVENANCE')
            result=self.service.owner_write(actor,b['operation'],b['params'],
                operation_id=b['operationId'],assertion_source=b['assertionSource'],parent_id=b['parentRequestId'])
        elif act=='BEGIN_GROUP':
            sc.need(self.provenance(actor)==b['assertionSource'],'SEMANTIC_WIRE_PROVENANCE')
            result=self.service.begin_group(actor,b['params'],operation_ids=b['operationIds'],
                parent_id=b['parentRequestId'],assertion_source=b['assertionSource'])
        elif act in ('SOURCE_REGISTER_EXTERNAL','SOURCE_LOOKUP_EXTERNAL'):
            from ..integrations.registry_contracts.source_lineage_contract import external_operation
            sc.need(actor!=self.internal_actor and self.provenance(actor)=='OWNER_DIRECT'
                    and self.external_source_authorize is not None
                    and self.external_source_authorize(actor,act,b) is True,
                    'SEMANTIC_EXTERNAL_SOURCE_SCOPE_DENIED')
            domain=self.service.domain
            p=b['request']['proposal'] if act=='SOURCE_REGISTER_EXTERNAL' else b['proposal']
            sc.need(p['repository']==self.store.scope['repository'],'SEMANTIC_SOURCE_SCOPE_DENIED')
            if act=='SOURCE_REGISTER_EXTERNAL':
                result=domain.register_source(b['request'],effect_guard=lambda:
                    self.authorize(actor,act,b) is True and
                    self.external_source_authorize(actor,act,b) is True)
            else:
                ident=external_operation(b['parentRequestId'])
                row=domain.snapshot()['sourceOperations'].get(ident)
                if row is not None:
                    sc.need(row[0]['kind']=='EXTERNAL_MERGE'
                            and row[0]['parentRequestId']==b['parentRequestId']
                            and row[0]['proposal']==b['proposal'],'SEMANTIC_SOURCE_RECEIPT_CHANGED')
                result=row[1] if row is not None else None
            sc.need(self.external_source_authorize(actor,act,b) is True,
                    'SEMANTIC_EXTERNAL_SOURCE_SCOPE_DENIED')
        elif act in ('SOURCE_PREFLIGHT','SOURCE_REGISTER','SOURCE_LOOKUP'):
            # Separate reviewed source admission, not inherited from the
            # ordinary frame grant. Domain source verification still required.
            sc.need(self.source_authorize is not None and
                    self.source_authorize(actor,act,b) is True,'SEMANTIC_SOURCE_SCOPE_DENIED')
            domain=self.service.domain
            p=b['request']['proposal'] if act=='SOURCE_REGISTER' else b['proposal']
            sc.need(p['repository']==self.store.scope['repository'],'SEMANTIC_SOURCE_SCOPE_DENIED')
            if act=='SOURCE_PREFLIGHT':
                sc.need(actor==self.internal_actor,'SEMANTIC_WIRE_INTERNAL_ONLY')
                result=domain.source_preflight(p)
            elif act=='SOURCE_REGISTER':
                sc.need(actor!=self.internal_actor,'SEMANTIC_SOURCE_ACTOR_DENIED')
                reservation = self.source_reservation() if self.source_reservation is not None else nullcontext()
                with reservation:
                    result=domain.register_source(b['request'],effect_guard=lambda:
                        self.authorize(actor,act,b) is True and self.source_authorize(actor,act,b) is True)
            else:
                sc.need(actor!=self.internal_actor,'SEMANTIC_SOURCE_ACTOR_DENIED')
                ctx=b['context']
                row=domain.snapshot()['sourceOperations'].get(ctx['stepId'])
                if row is not None:
                    sc.need(row[0]['kind']=='MERGE' and row[0]['parentRequestId']==ctx['parentId']
                            and row[0]['proposal']==p,'SEMANTIC_SOURCE_RECEIPT_CHANGED')
                result=row[1] if row is not None else None
            sc.need(self.source_authorize(actor,act,b) is True,'SEMANTIC_SOURCE_SCOPE_DENIED')
        else:
            sc.need(actor==self.internal_actor,'SEMANTIC_WIRE_INTERNAL_ONLY')
            if act == 'HOLD_SNAPSHOT':
                result = self.service.domain.maintenance_snapshot()
            else:
                sc.need(act == 'PROFILE', 'SEMANTIC_WIRE_BINDING')
                view = self.service.domain.snapshot()
                result = {k: view[k] for k in ('profileDigest', 'sourceRevision')}
                if self.source_delivery is not None:
                    result['sourceDelivery'] = self.source_delivery()
        return wire.reply(self.key,req,result)


class PrivateSemanticUnixService(PrivateCandidateReadService):
    def __init__(self,*,frames,socket_path,reader_uid,reader_gid,peer_key):
        sc.need(type(frames) is SemanticFrameService and type(peer_key) is bytes and len(peer_key)==32
                and peer_key!=frames.key and os.geteuid()>0 and os.getegid()>0
                and type(reader_uid) is int and type(reader_gid) is int
                and 0<reader_uid<2**31 and 0<reader_gid<2**31
                and reader_uid!=os.geteuid() and reader_gid!=os.getegid(),
                'SEMANTIC_UNIX_CONFIG_DENIED')
        self.frames,self._store=frames,frames.store
        self._path=_absolute_path(socket_path,socket_name=True)
        sc.need(not self._path.parent.is_relative_to(self._store.path.parent))
        self._uid,self._gid=reader_uid,reader_gid
        self._planner_key=peer_key # Existing peer proof helper only; no planner dispatch.
        self._managed_startup=True
        self._endpoint=None
        _private_socket_dir(self._path,self._gid)
        self._head()

    def _head(self):
        return self.frames.service.domain.snapshot()

    @contextmanager
    def _managed_socket(self):
        if self.frames.source_reservation is None:
            with super()._managed_socket() as listener:
                yield listener
            return
        descriptor = os.open(self._store.path.parent,
                             os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Denied('REGISTRY_SOURCE_WRITER_BUSY') from None
            with super()._managed_socket() as listener:
                yield listener
        finally:
            os.close(descriptor)

    def handle(self,connection):
        before=self._check_endpoint()
        sc.need(connection.getsockname()==str(self._path))
        peer=_real_peer(connection,reader_uid=self._uid,reader_gid=self._gid)
        # Mandatory managed peer challenge: never accept a raw legacy frame.
        self._prove_identity(connection)
        req=_canonical_frame(connection,wire.MAX_REQUEST)
        sc.need(self._check_endpoint()==before and
                _real_peer(connection,reader_uid=self._uid,reader_gid=self._gid)==peer)
        try:
            out=self.frames.dispatch(req)
        except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):
            raise Denied('SEMANTIC_WIRE_INVALID') from None
        sc.need(self._check_endpoint()==before and
                _real_peer(connection,reader_uid=self._uid,reader_gid=self._gid)==peer)
        raw=sc.canonical(out).encode()+b'\n'
        sc.need(len(raw)<=wire.MAX_REPLY+1)
        connection.settimeout(_TIMEOUT)
        connection.sendall(raw)
        import socket
        connection.shutdown(socket.SHUT_WR)


def _read_release_profiles(root):
    from .local_candidate_read_service import _owner_runtime_bytes

    def load_profile(name):
        raw = _owner_runtime_bytes(root/name,262144)
        profile = sc.loads_strict(raw)
        sc.need(sc.canonical(profile).encode()==raw,'SEMANTIC_STARTUP_PROFILE_INVALID')
        return profile

    return load_profile('legacy-release-profile.json'), load_profile('successor-release-profile.json')


def owner_semantic_reader(config,root):
    """Open the transitioned Registry with the exact protected runtime profile."""
    from .release_domain import ReleaseDomain, key
    from .release_event_journal import ReleaseEventJournal
    from ..integrations.registry.read_contract import private_planner_key

    pins=config['semantic']
    sc.fields(pins,('legacyWitness','transitionDigest','legacyProfileDigest',
                    'successorProfileDigest','generation','internalActor',
                    'peerKeyDigest','frameKeyDigest','readGrants'))
    for field in ('peerKeyDigest','frameKeyDigest'):
        sc.hex_id(pins[field],64)
    internal=pins['internalActor']
    sc.need(type(internal) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}',internal),
            'SEMANTIC_STARTUP_INTERNAL_ACTOR')
    repo=config['scope']['repository']
    reads=pins['readGrants']
    sc.need(type(reads) is list and 0<len(reads)<=64,'SEMANTIC_STARTUP_READ_GRANTS')
    grants={}
    for row in reads:
        sc.fields(row,('actor','operation','subject'))
        actor,op,subject=row['actor'],row['operation'],row['subject']
        sc.need(type(actor) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}',actor)
                and actor!=internal and op in sc.READ_METHODS,'SEMANTIC_STARTUP_READ_GRANTS')
        sc.subject(subject)
        sc.need(subject['repository']==repo,'SEMANTIC_STARTUP_READ_GRANTS')
        choices=grants.setdefault((actor,op),set())
        ident=key(subject)
        sc.need(ident not in choices,'SEMANTIC_STARTUP_READ_GRANTS')
        choices.add(ident)

    legacy, successor = _read_release_profiles(root)
    journal=ReleaseEventJournal(config['registryStatePath'],instance_id=config['instanceId'],
        scope=config['scope'],expected_legacy=pins['legacyWitness'],
        transition_digest=pins['transitionDigest'])
    source_writer = None
    if config['schemaVersion'] == 3:
        from .protected_source_write import ProtectedSourceWrite
        source_writer = ProtectedSourceWrite(
            config['sourceWrite'], journal=journal, generation=pins['generation'],
            internal=internal, profile_digest=pins['successorProfileDigest'], producer_uid=config['readerUid'])
    domain=ReleaseDomain(journal,legacy,expected_profile_digest=pins['legacyProfileDigest'],
        successor_profile=successor,expected_successor_profile_digest=pins['successorProfileDigest'],
        source_verify=source_writer.verify if source_writer is not None else None)
    current=domain.snapshot()
    sc.need(current['sourceTransitionPending'] is False
            and current['profileDigest']==pins['successorProfileDigest']
            and all(scope<=set(current['states']) for scope in grants.values()),
            'SEMANTIC_STARTUP_STATE_NOT_ACCEPTED')
    peer_key=private_planner_key(root/'semantic-peer.key',pins['peerKeyDigest'])
    frame_key=private_planner_key(root/'semantic-frame.key',pins['frameKeyDigest'])

    def can_read(actor,operation,subject):
        allowed=grants.get((actor,operation))
        return bool(allowed and subject['repository']==repo
                    and ('targetId' not in subject or key(subject) in allowed))

    def admit(actor,action,body):
        if action=='READ':
            return (actor,body['operation']) in grants
        if action in ('PROFILE','HOLD_SNAPSHOT'):
            return actor==internal
        return source_writer is not None and action in ('SOURCE_PREFLIGHT','SOURCE_REGISTER','SOURCE_LOOKUP')

    service=SemanticRegistry(domain,authorize=can_read,clock=lambda:0)
    frames=SemanticFrameService(service,frame_key=frame_key,generation=pins['generation'],
        authorize=admit,provenance=lambda _:None,internal_actor=internal,
        source_authorize=source_writer.authorize if source_writer is not None else None,
        source_reservation=source_writer.reservations.reserve if source_writer is not None else None,
        source_delivery=source_writer.delivery_binding if source_writer is not None else None)
    return PrivateSemanticUnixService(frames=frames,socket_path=config['socketPath'],
        reader_uid=config['readerUid'],reader_gid=config['readerGid'],peer_key=peer_key)
