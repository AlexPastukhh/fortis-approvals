"""Private versioned authenticated Registry frame; no public ingress.

Frame key is separately provisioned by trusted owner composition and
distinct from the peer challenge key. No legacy fallback, no caller key,
no arbitrary method/path/actor selection from public DTOs.
"""
import hashlib
import hmac
import re
from . import semantic_contract as sc
from . import source_lineage_contract as lc

MAX_REQUEST=65536
MAX_REPLY=270000
ACTIONS=('READ','WRITE','BEGIN_GROUP','HOLD_SNAPSHOT','PROFILE','SOURCE_PREFLIGHT',
         'SOURCE_REGISTER','SOURCE_LOOKUP','SOURCE_REGISTER_EXTERNAL','SOURCE_LOOKUP_EXTERNAL','CONTROLLER_PAIRED_BEGIN')


def _tag(key,label,value):
    sc.need(type(key) is bytes and len(key)==32,'SEMANTIC_WIRE_KEY_REQUIRED')
    return hmac.new(key,label.encode()+b'\0'+sc.canonical(value).encode(),hashlib.sha256).hexdigest()


def request(value,*,instance,scope,generation):
    sc.fields(value,('schemaVersion','requestId','instanceId','scopeDigest','generation','actor','action','body'))
    sc.need(type(value['schemaVersion']) is int and value['schemaVersion']==2
            and value['instanceId']==instance and value['scopeDigest']==scope
            and value['generation']==generation and value['action'] in ACTIONS,'SEMANTIC_WIRE_BINDING')
    sc.uuid_id(value['requestId']);sc.uuid_id(instance);sc.hex_id(scope,64);sc.hex_id(generation,64)
    sc.need(type(value['actor']) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}',value['actor']))
    body=value['body'];act=value['action']
    if act=='READ':
        sc.fields(body,('operation','params'))
        sc.need(type(body['operation']) is str and body['operation'] in sc.READ_METHODS)
        sc.validate_params(body['operation'],body['params'])
    elif act=='WRITE':
        sc.fields(body,('operation','params','operationId','assertionSource','parentRequestId'))
        sc.need(body['operation'] in ('begin_release','report_release_result'))
        sc.validate_params(body['operation'],body['params'])
        sc.uuid_id(body['operationId'])
        if body['parentRequestId'] is not None:sc.uuid_id(body['parentRequestId'])
        sc.need(body['assertionSource'] in ('OWNER_DIRECT','OWNER_TRANSCRIBED'))
    elif act=='BEGIN_GROUP':
        sc.fields(body,('params','operationIds','parentRequestId','assertionSource'))
        sc.validate_params('begin_release_group',body['params'])
        ids=body['operationIds']
        sc.need(type(ids) is list and len(ids)==len(body['params']['items']))
        for ident in ids:sc.uuid_id(ident)
        sc.need(len(set(ids))==len(ids))
        sc.uuid_id(body['parentRequestId'])
        sc.need(body['assertionSource'] in ('OWNER_DIRECT','OWNER_TRANSCRIBED'))
    elif act=='CONTROLLER_PAIRED_BEGIN':
        sc.fields(body,('intentDigest','readback'))
        sc.hex_id(body['intentDigest'],64)
        sc.need(type(body['readback']) is bool)
    elif act=='SOURCE_PREFLIGHT':
        sc.fields(body,('proposal',))
        lc.proposal(body['proposal'])
    elif act=='SOURCE_REGISTER':
        lc.merge_registration(body)
    elif act=='SOURCE_REGISTER_EXTERNAL':
        lc.external_registration(body)
    elif act=='SOURCE_LOOKUP_EXTERNAL':
        sc.fields(body,('parentRequestId','proposal'))
        lc.external_operation(body['parentRequestId'])
        lc.proposal(body['proposal'])
    elif act=='SOURCE_LOOKUP':
        sc.fields(body,('context','proposal'))
        lc.source_context(body['context'],body['proposal'])
    elif act=='PROFILE' and body!={}:
        sc.fields(body,('sourceCheckpoint',))
        sc.need(body['sourceCheckpoint'] is True,'SEMANTIC_WIRE_BINDING')
    else:
        sc.need(body=={})
    sc.need(len(sc.canonical(value).encode())<=MAX_REQUEST-128,'SEMANTIC_WIRE_LIMIT')
    return sc.loads_strict(sc.canonical(value))


def seal(key,value):
    return {'request':value,'mac':_tag(key,'registry-semantic-request-v2',value)}


def open_request(key,frame,**pins):
    sc.fields(frame,('request','mac'))
    sc.hex_id(frame['mac'],64)
    value=request(frame['request'],**pins)
    sc.need(hmac.compare_digest(frame['mac'],_tag(key,'registry-semantic-request-v2',value)),
            'SEMANTIC_WIRE_AUTH_DENIED')
    return value


def reply(key,req,result):
    body={'schemaVersion':2,'requestId':req['requestId'],'requestDigest':sc.digest(req),
          'result':result}
    out={'response':body,'mac':_tag(key,'registry-semantic-response-v2',body)}
    sc.need(len(sc.canonical(out).encode())<=MAX_REPLY,'SEMANTIC_WIRE_LIMIT')
    return out


def open_reply(key,req,frame):
    sc.fields(frame,('response','mac'))
    sc.hex_id(frame['mac'],64)
    body=frame['response']
    sc.fields(body,('schemaVersion','requestId','requestDigest','result'))
    sc.need(type(body['schemaVersion']) is int and body['schemaVersion']==2
            and body['requestId']==req['requestId'] and body['requestDigest']==sc.digest(req)
            and hmac.compare_digest(frame['mac'],_tag(key,'registry-semantic-response-v2',body)),
            'SEMANTIC_WIRE_RESPONSE_DENIED')
    return body['result']
