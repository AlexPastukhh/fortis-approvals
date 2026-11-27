"""New typed private semantic client on reviewed managed Registry peer.

Constructed only in trusted Gateway composition, not by public callers.
No direct DB mount, no raw proxy/legacy fallback, no automatic retry.
"""
import uuid
import socket
from ..core import Denied
from ..integrations.registry_contracts import semantic_contract as sc, semantic_wire as wire
from ..integrations.registry.candidate_gateway import GatewayRegistryUnixCandidateRead


class GatewayRegistrySemanticTransport:
    def __init__(self,peer,*,frame_key,generation,internal_actor):
        sc.need(type(peer) is GatewayRegistryUnixCandidateRead and
                type(peer._peer_key) is bytes and type(frame_key) is bytes and len(frame_key)==32
                and frame_key!=peer._peer_key and type(internal_actor) is str,
                'SEMANTIC_UNIX_PEER_REQUIRED')
        sc.hex_id(generation,64)
        self.peer,self.key,self.generation=peer,frame_key,generation
        self.internal_actor=internal_actor

    def _exchange(self, wire_request, *, limit, timeout, reply_limit):
        sc.need(type(reply_limit) is int and reply_limit==wire.MAX_REPLY+1)
        self.peer._check_identity()
        endpoint = self.peer._check_socket()
        raw = sc.canonical(wire_request).encode('utf-8') + b'\n'
        sc.need(len(raw) <= limit + 1, 'REGISTRY_CANDIDATE_REQUEST_TOO_LARGE')
        reply = bytearray()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(str(self.peer._path))
                peer = self.peer._authenticate_peer(sock)
                sock.sendall(raw)
                sock.shutdown(socket.SHUT_WR)
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    reply.extend(chunk)
                    sc.need(len(reply) <= reply_limit,
                          'REGISTRY_CANDIDATE_RESPONSE_TOO_LARGE')
                sc.need(self.peer._peer(sock) == peer,
                      'REGISTRY_CANDIDATE_SERVER_CHANGED')
        except (OSError, TimeoutError):
            raise Denied('REGISTRY_CANDIDATE_TRANSPORT_UNAVAILABLE') from None
        self.peer._check_identity()
        sc.need(self.peer._check_socket() == endpoint
              and 2 <= len(reply) <= reply_limit
              and reply[-1:] == b'\n' and reply.count(b'\n') == 1,
              'REGISTRY_CANDIDATE_RESPONSE_DENIED')
        return reply

    def _call(self,actor,action,body):
        pins={'instance':self.peer._instance,'scope':self.peer._scope,'generation':self.generation}
        req=wire.request({'schemaVersion':2,'requestId':str(uuid.uuid4()),
                  'instanceId':pins['instance'],'scopeDigest':pins['scope'],
                  'generation':pins['generation'],'actor':actor,'action':action,'body':body},**pins)
        # Independent source validation runs a bounded validator (40 seconds)
        # before accounting. Keep the ordinary healthy peer latency bound.
        timeout=50 if action in ('SOURCE_REGISTER','SOURCE_REGISTER_EXTERNAL') else 2.5
        raw=self._exchange(wire.seal(self.key,req),limit=wire.MAX_REQUEST,
                           timeout=timeout,reply_limit=wire.MAX_REPLY+1)
        frame=sc.loads_strict(bytes(raw[:-1]))
        sc.need(sc.canonical(frame).encode()==bytes(raw[:-1]),'SEMANTIC_WIRE_RESPONSE_DENIED')
        return wire.open_reply(self.key,req,frame)

    def read(self,actor,operation,params):
        return self._call(actor,'READ',{'operation':operation,'params':params})

    def owner_write(self,actor,operation,params,*,operation_id,assertion_source,parent_id=None):
        return self._call(actor,'WRITE',{'operation':operation,'params':params,'operationId':operation_id,
                     'assertionSource':assertion_source,'parentRequestId':parent_id})

    def begin_group(self,actor,params,*,operation_ids,parent_id,assertion_source):
        return self._call(actor,'BEGIN_GROUP',{'params':params,'operationIds':operation_ids,
                      'parentRequestId':parent_id,'assertionSource':assertion_source})

    def maintenance_snapshot(self):
        return self._call(self.internal_actor,'HOLD_SNAPSHOT',{})

    def profile(self):
        result = self._call(self.internal_actor, 'PROFILE', {})
        fields = {'profileDigest', 'sourceRevision'}
        if type(result) is dict and 'sourceDelivery' in result:
            sc.fields(result['sourceDelivery'], ('device','inode','policyAuthorityDigest','interlockDigest'))
            for pin in ('policyAuthorityDigest','interlockDigest'):
                sc.hex_id(result['sourceDelivery'][pin],64)
            for coordinate in ('device','inode'):
                number = result['sourceDelivery'][coordinate]
                sc.need(type(number) is int and 0 < number < 2**64)
            fields.add('sourceDelivery')
        sc.fields(result, fields)
        sc.hex_id(result['profileDigest'], 64)
        sc.revision(result['sourceRevision'])
        return result

    def profile_digest(self):
        return self.profile()['profileDigest']

    def source_preflight(self,p):
        return self._call(self.internal_actor,'SOURCE_PREFLIGHT',{'proposal':p})

    def register_source(self,actor,context,req,merge_receipt):
        return self._call(actor,'SOURCE_REGISTER',{'context':context,'request':req,
                                                  'mergeReceipt':merge_receipt})

    def source_operation(self,actor,context,proposal):
        return self._call(actor,'SOURCE_LOOKUP',{'context':context,'proposal':proposal})


    def register_external_source(self,actor,body):
        return self._call(actor,'SOURCE_REGISTER_EXTERNAL',body)

    def external_source_operation(self,actor,parent_id,proposal):
        return self._call(actor,'SOURCE_LOOKUP_EXTERNAL',
                          {'parentRequestId':parent_id,'proposal':proposal})
